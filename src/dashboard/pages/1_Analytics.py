"""Analytics page: KPIs, threat volume, layer distribution, risk, latency, top threats.

Flow (one Streamlit run):
    sidebar -> time-range selector -> [fragment, re-runs every refresh interval]
        load_datasets()  ->  KPI cards, charts, tables

Where the numbers come from
    * KPIs, threat volume and layer distribution: the getters in
      src/database/storage.py. Beyond 48 hours the volume series is read from
      the pre-aggregated system_metrics table (hourly rows), not threat_logs.
    * Latency, risk histogram, top patterns, top client IPs and output-scanner
      flags: storage.py has no getters for these yet, so the read-only
      aggregate queries live in the "Queries" section below. Latency beyond
      48 hours is also metrics-backed. Move them into storage.py whenever
      convenient; nothing else in this file depends on where they live.

Behaviour rules
    * Every dataset is fetched in parallel with one run_sync() call and cached
      for the sidebar's refresh interval. A failed dataset is never cached.
    * Every section copes with "no data" and with a failed query. A database
      outage shows one friendly message; no traceback ever reaches the page.
    * The page never shows prompt text, only counts, rule IDs and client IPs.
"""

from __future__ import annotations

import asyncio
import importlib
import logging
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# Streamlit runs this file with src/dashboard on sys.path, not the repo root.
_ROOT = Path(__file__).resolve().parents[3]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pandas as pd  # noqa: E402
import plotly.graph_objects as go  # noqa: E402
import streamlit as st  # noqa: E402
from sqlalchemy import and_, case, func, literal_column, select, true  # noqa: E402

from src.dashboard.components.metrics_cards import render_kpi_cards  # noqa: E402
from src.database.connection import AsyncSessionLocal, check_database_connection, engine  # noqa: E402
from src.database.models import SystemMetric, ThreatLog  # noqa: E402
from src.database.storage import (  # noqa: E402
    RECENT_HOURS_LIMIT,
    get_kpi_summary,
    get_layer_distribution,
    get_timeseries,
    run_sync,
)

logger = logging.getLogger("firewall.dashboard.analytics")

# ----------------------------------------------------------------------
# Settings
# ----------------------------------------------------------------------
RANGES = {"24h": 24, "7d": 24 * 7, "30d": 24 * 30, "90d": 24 * 90}
DEFAULT_RANGE = "24h"
RISK_BINS = 10                    # 0.0-0.1, 0.1-0.2, ... 0.9-1.0
TOP_N = 10                        # rows in "top ..." lists
FETCH_TIMEOUT_SECONDS = 20.0      # one database round for all datasets
CHART_HEIGHT = 320

LAYER_LABELS = {
    "LAYER_1": "Layer 1 · rules",
    "LAYER_2": "Layer 2 · classifier",
    "LAYER_3": "Layer 3 · judge",
    "OUTPUT_SCANNER": "Output scanner",
    "NONE": "Pipeline error (fail-closed)",
}
COLOR_ALLOWED = "#4fc3f7"
COLOR_BLOCKED = "#ef5350"
COLOR_GOLD = "#e8b75b"            # the theme's primary colour
COLOR_TEXT = "#edf3ff"

EMPTY_MESSAGE = "No data in this period yet."
SECTION_ERROR = "This section could not be loaded. It will retry on the next refresh."
DB_ERROR_MESSAGE = (
    "The analytics database could not be reached. Check that the database is "
    "running, then press Retry. This page keeps trying on every refresh."
)

# Fixed constants, never built from user input (same reason as storage.py:
# a bound parameter inside both SELECT and GROUP BY is not seen as the same expression).
_UNIT = {"hour": literal_column("'hour'"), "day": literal_column("'day'")}
_BINS_SQL = literal_column(str(int(RISK_BINS)))
_LAST_BIN_SQL = literal_column(str(int(RISK_BINS) - 1))
_EMPTY_JSON_ARRAY = literal_column("'[]'::jsonb")


# ----------------------------------------------------------------------
# Pure helpers (no Streamlit, no database)
# ----------------------------------------------------------------------
def bucket_for(hours: int) -> str:
    """Hourly points up to a week, daily points beyond that."""
    return "hour" if hours <= 24 * 7 else "day"


def range_label(hours: int) -> str:
    for label, value in RANGES.items():
        if value == hours:
            return label
    return f"{hours}h"


def _frame(rows: Any, columns: list[str]) -> pd.DataFrame:
    """List of dicts -> DataFrame with a stable set of columns (even when empty)."""
    frame = pd.DataFrame(list(rows or []))
    for column in columns:
        if column not in frame.columns:
            frame[column] = pd.Series(dtype="float64")
    return frame[columns]


def _style(fig: go.Figure, *, x_title: str | None = None, y_title: str | None = None) -> go.Figure:
    """One look for every chart: transparent background, theme colours."""
    fig.update_layout(
        height=CHART_HEIGHT,
        margin={"l": 8, "r": 8, "t": 28, "b": 8},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": COLOR_TEXT},
        legend={"orientation": "h", "yanchor": "bottom", "y": 1.0, "x": 0},
        hoverlabel={"namelength": -1},
    )
    fig.update_xaxes(title=x_title, gridcolor="rgba(255,255,255,0.06)", zeroline=False)
    fig.update_yaxes(title=y_title, gridcolor="rgba(255,255,255,0.08)", zeroline=False)
    return fig


def build_volume_figure(rows: Any) -> go.Figure | None:
    """Stacked bars per bucket: allowed vs blocked. None when there is no data.

    Bars (not a line) so a quiet hour with no row is simply absent instead of
    being drawn as a misleading slope between its neighbours.
    """
    frame = _frame(rows, ["bucket_start", "total_requests", "blocked_requests"])
    if frame.empty or float(frame["total_requests"].sum()) == 0:
        return None
    frame["bucket_start"] = pd.to_datetime(frame["bucket_start"], utc=True)
    frame["allowed"] = (frame["total_requests"] - frame["blocked_requests"]).clip(lower=0)

    fig = go.Figure()
    fig.add_bar(x=frame["bucket_start"], y=frame["allowed"], name="Allowed", marker_color=COLOR_ALLOWED)
    fig.add_bar(x=frame["bucket_start"], y=frame["blocked_requests"], name="Blocked", marker_color=COLOR_BLOCKED)
    fig.update_layout(barmode="stack", bargap=0.15)
    return _style(fig, x_title="Time (UTC)", y_title="Requests")


def build_layer_figure(distribution: Any) -> go.Figure | None:
    """Horizontal bars: blocked requests per layer. None when nothing was blocked."""
    data = {k: int(v) for k, v in dict(distribution or {}).items() if v is not None}
    if sum(data.values()) == 0:
        return None
    order = [k for k in ("LAYER_1", "LAYER_2", "LAYER_3", "OUTPUT_SCANNER") if k in data]
    order += [k for k in data if k not in order and data[k] > 0]     # e.g. NONE (fail-closed errors)
    fig = go.Figure(go.Bar(
        x=[data[k] for k in order],
        y=[LAYER_LABELS.get(k, k) for k in order],
        orientation="h",
        marker_color=COLOR_GOLD,
        hovertemplate="%{y}: %{x} blocked<extra></extra>",
    ))
    fig.update_yaxes(autorange="reversed")
    return _style(fig, x_title="Blocked requests")


def risk_bin_labels() -> list[str]:
    step = 1 / RISK_BINS
    return [f"{i * step:.1f}–{(i + 1) * step:.1f}" for i in range(RISK_BINS)]


def build_risk_figure(rows: Any) -> go.Figure | None:
    """Histogram of risk scores (all bins always shown), allowed vs blocked."""
    frame = _frame(rows, ["bin", "is_blocked", "count"])
    if frame.empty or float(frame["count"].sum()) == 0:
        return None
    allowed = [0] * RISK_BINS
    blocked = [0] * RISK_BINS
    for _, row in frame.iterrows():
        index = min(max(int(row["bin"]), 0), RISK_BINS - 1)
        (blocked if bool(row["is_blocked"]) else allowed)[index] += int(row["count"])

    labels = risk_bin_labels()
    fig = go.Figure()
    fig.add_bar(x=labels, y=allowed, name="Allowed", marker_color=COLOR_ALLOWED)
    fig.add_bar(x=labels, y=blocked, name="Blocked", marker_color=COLOR_BLOCKED)
    fig.update_layout(barmode="stack", bargap=0.1)
    return _style(fig, x_title="Risk score", y_title="Requests")


def build_latency_figure(rows: Any, *, p95_label: str) -> go.Figure | None:
    """Average and p95 latency per bucket. None when there is no data."""
    frame = _frame(rows, ["bucket_start", "avg_ms", "p95_ms"]).dropna(subset=["avg_ms"])
    if frame.empty:
        return None
    frame["bucket_start"] = pd.to_datetime(frame["bucket_start"], utc=True)
    fig = go.Figure()
    fig.add_scatter(x=frame["bucket_start"], y=frame["avg_ms"], name="Average", mode="lines+markers",
                    line={"color": COLOR_GOLD})
    fig.add_scatter(x=frame["bucket_start"], y=frame["p95_ms"], name=p95_label, mode="lines+markers",
                    line={"color": COLOR_BLOCKED, "dash": "dot"})
    return _style(fig, x_title="Time (UTC)", y_title="Milliseconds")


def build_patterns_figure(rows: Any) -> go.Figure | None:
    """Horizontal bars: the most-hit rule IDs among blocked requests."""
    frame = _frame(rows, ["pattern", "hits"])
    if frame.empty:
        return None
    fig = go.Figure(go.Bar(
        x=frame["hits"], y=frame["pattern"], orientation="h", marker_color=COLOR_GOLD,
        hovertemplate="%{y}: %{x} hits<extra></extra>",
    ))
    fig.update_yaxes(autorange="reversed")
    return _style(fig, x_title="Blocked requests that matched")


def clients_table(rows: Any) -> pd.DataFrame:
    frame = _frame(rows, ["client_ip", "requests", "blocked"])
    if frame.empty:
        return frame
    frame["block_rate"] = (frame["blocked"] / frame["requests"].where(frame["requests"] > 0)) * 100
    return frame.rename(columns={
        "client_ip": "Client IP", "requests": "Requests", "blocked": "Blocked", "block_rate": "Block rate (%)",
    })


# ----------------------------------------------------------------------
# Queries (read-only aggregates; every value is a bound parameter or a
# fixed constant; none of them selects prompt text)
# ----------------------------------------------------------------------
def _expand(array_expr, label: str):
    """One row per element of a JSON array, as a LATERAL join against threat_logs."""
    return func.jsonb_array_elements_text(array_expr).table_valued(label).lateral()


def _since(hours: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(hours=max(1, int(hours)))


async def _query_latency(hours: int, bucket: str) -> list[dict]:
    """Average and p95 execution time per bucket. > 48h reads system_metrics."""
    start = _since(hours)
    unit = _UNIT[bucket]
    if hours <= RECENT_HOURS_LIMIT:
        bucket_expr = func.date_trunc(unit, ThreatLog.created_at)
        stmt = (
            select(
                bucket_expr.label("bucket_start"),
                func.avg(ThreatLog.execution_time_ms).label("avg_ms"),
                func.percentile_cont(0.95).within_group(ThreatLog.execution_time_ms).label("p95_ms"),
            )
            .where(ThreatLog.created_at >= start)
            .group_by(bucket_expr)
            .order_by(bucket_expr)
        )
    else:
        bucket_expr = func.date_trunc(unit, SystemMetric.bucket_start)
        weight = func.sum(SystemMetric.total_requests)
        stmt = (
            select(
                bucket_expr.label("bucket_start"),
                # Request-weighted mean of the hourly means = the exact mean.
                (func.sum(SystemMetric.avg_latency_ms * SystemMetric.total_requests)
                 / func.nullif(weight, 0)).label("avg_ms"),
                # Percentiles cannot be merged; the worst hourly p95 is the honest summary.
                func.max(SystemMetric.p95_latency_ms).label("p95_ms"),
            )
            .where(SystemMetric.bucket_start >= start, SystemMetric.total_requests > 0)
            .group_by(bucket_expr)
            .order_by(bucket_expr)
        )
    async with AsyncSessionLocal() as session:
        rows = (await session.execute(stmt)).all()
    return [
        {"bucket_start": r.bucket_start,
         "avg_ms": None if r.avg_ms is None else float(r.avg_ms),
         "p95_ms": None if r.p95_ms is None else float(r.p95_ms)}
        for r in rows
    ]


async def _query_risk_histogram(hours: int) -> list[dict]:
    """Request counts per risk-score bin and blocked/allowed."""
    index = func.greatest(func.least(func.floor(ThreatLog.risk_score * _BINS_SQL), _LAST_BIN_SQL), 0)
    stmt = (
        select(index.label("bin"), ThreatLog.is_blocked, func.count().label("count"))
        .where(ThreatLog.created_at >= _since(hours))
        .group_by(index, ThreatLog.is_blocked)
    )
    async with AsyncSessionLocal() as session:
        rows = (await session.execute(stmt)).all()
    return [{"bin": int(r.bin), "is_blocked": bool(r.is_blocked), "count": int(r.count)} for r in rows]


async def _query_top_patterns(hours: int) -> list[dict]:
    """Rule IDs most often matched by blocked requests (detected_patterns is a JSON array)."""
    as_array = case(
        (func.jsonb_typeof(ThreatLog.detected_patterns) == "array", ThreatLog.detected_patterns),
        else_=_EMPTY_JSON_ARRAY,
    )
    pattern = _expand(as_array, "value")
    stmt = (
        select(pattern.c.value.label("pattern"), func.count().label("hits"))
        .select_from(ThreatLog)
        .join(pattern, true())
        .where(ThreatLog.created_at >= _since(hours), ThreatLog.is_blocked.is_(True))
        .group_by(pattern.c.value)
        .order_by(func.count().desc(), pattern.c.value)
        .limit(TOP_N)
    )
    async with AsyncSessionLocal() as session:
        rows = (await session.execute(stmt)).all()
    return [{"pattern": r.pattern, "hits": int(r.hits)} for r in rows]


async def _query_top_clients(hours: int) -> list[dict]:
    """Client IPs ranked by blocked requests, then by volume."""
    blocked = func.count().filter(ThreatLog.is_blocked.is_(True))
    stmt = (
        select(ThreatLog.client_ip, func.count().label("requests"), blocked.label("blocked"))
        .where(ThreatLog.created_at >= _since(hours))
        .group_by(ThreatLog.client_ip)
        .order_by(blocked.desc(), func.count().desc(), ThreatLog.client_ip)
        .limit(TOP_N)
    )
    async with AsyncSessionLocal() as session:
        rows = (await session.execute(stmt)).all()
    return [{"client_ip": r.client_ip, "requests": int(r.requests), "blocked": int(r.blocked)} for r in rows]


async def _query_scanner_flags(hours: int) -> dict:
    """Completions flagged by the output scanner, by action taken and by category."""
    scanner = ThreatLog.layer_details["output_scanner"]
    action = scanner["action"].astext
    as_array = case(
        (func.jsonb_typeof(scanner["categories"]) == "array", scanner["categories"]),
        else_=_EMPTY_JSON_ARRAY,
    )
    category = _expand(as_array, "value")
    flagged = and_(ThreatLog.created_at >= _since(hours), ThreatLog.output_flagged.is_(True))

    by_action = select(action.label("action"), func.count().label("flags")).where(flagged).group_by(action)
    by_category = (
        select(category.c.value.label("category"), func.count().label("flags"))
        .select_from(ThreatLog).join(category, true())
        .where(flagged).group_by(category.c.value)
        .order_by(func.count().desc(), category.c.value)
    )
    total = select(func.count()).select_from(ThreatLog).where(flagged)

    async with AsyncSessionLocal() as session:
        actions = (await session.execute(by_action)).all()
        categories = (await session.execute(by_category)).all()
        flagged_total = (await session.execute(total)).scalar_one()
    return {
        "total": int(flagged_total),
        "by_action": [{"Action": r.action or "unknown", "Flags": int(r.flags)} for r in actions],
        "by_category": [{"Category": r.category, "Flags": int(r.flags)} for r in categories],
    }


# ----------------------------------------------------------------------
# Loading: one parallel database round, cached for the refresh interval
# ----------------------------------------------------------------------
DATASETS = ("kpis", "kpis_previous", "volume", "layers", "latency", "risk", "patterns", "clients", "flags")


@dataclass(frozen=True)
class Loaded:
    """One dataset: either `value` or `error`, plus when it was fetched."""

    value: Any = None
    error: str | None = None
    fetched_at: float | None = None


def _dataset_call(name: str, hours: int, bucket: str):
    """The coroutine that fetches one dataset."""
    return {
        "kpis": lambda: get_kpi_summary(hours),
        "kpis_previous": lambda: get_kpi_summary(hours, offset_hours=hours),   # the period before
        "volume": lambda: get_timeseries(hours, bucket),                       # > 48h: system_metrics
        "layers": lambda: get_layer_distribution(hours),
        "latency": lambda: _query_latency(hours, bucket),
        "risk": lambda: _query_risk_histogram(hours),
        "patterns": lambda: _query_top_patterns(hours),
        "clients": lambda: _query_top_clients(hours),
        "flags": lambda: _query_scanner_flags(hours),
    }[name]()


async def _gather(names: list[str], hours: int, bucket: str) -> dict[str, Any]:
    results = await asyncio.gather(
        *(_dataset_call(n, hours, bucket) for n in names), return_exceptions=True
    )
    return dict(zip(names, results))


@st.cache_resource
def _ttl_store() -> dict:
    """Process-wide cache shared by every session (a plain dict, so editing this
    file never leaves an old class definition behind)."""
    return {"lock": threading.Lock(), "items": {}}


def _cache_get(key: tuple, ttl: float) -> Loaded | None:
    store = _ttl_store()
    with store["lock"]:
        hit = store["items"].get(key)
    if hit is not None and time.time() - hit.fetched_at < ttl:
        return hit
    return None


def _cache_put(key: tuple, item: Loaded) -> None:
    store = _ttl_store()
    with store["lock"]:
        items = store["items"]
        if len(items) > 256:                                   # keep memory bounded
            for stale in sorted(items, key=lambda k: items[k].fetched_at)[:64]:
                items.pop(stale, None)
        items[key] = item


def clear_cache() -> None:
    """Forget cached datasets and the storage getters' own caches ("Refresh now")."""
    store = _ttl_store()
    with store["lock"]:
        store["items"].clear()
    for getter in (get_kpi_summary, get_timeseries, get_layer_distribution):
        getter.cache_clear()


def _fetch_round(names: list[str], hours: int, bucket: str) -> dict[str, Any]:
    """One parallel database round. Returns name -> value, or name -> the exception."""
    try:
        return run_sync(_gather(names, hours, bucket), timeout=FETCH_TIMEOUT_SECONDS)
    except Exception as exc:                                   # timeout, or the loop itself failed
        return {name: exc for name in names}


def reset_connection_pool() -> None:
    """Discard every pooled connection without closing it (close=False).

    Needed because a connection created on a different, already-closed event
    loop cannot be used or even closed safely; see render_shared_sidebar().
    """
    try:
        run_sync(engine.dispose(close=False), timeout=5)
    except Exception:
        logger.debug("Could not reset the connection pool", exc_info=True)


def load_datasets(hours: int, bucket: str, ttl: float) -> dict[str, Loaded]:
    """Fetch every dataset. A dataset younger than `ttl` seconds is reused; a
    failed one is reported but never cached, so the next run retries it."""
    out: dict[str, Loaded] = {}
    missing: list[str] = []
    for name in DATASETS:
        hit = _cache_get((name, hours, bucket), ttl)
        if hit is not None:
            out[name] = hit
        else:
            missing.append(name)

    if missing:
        fetched = _fetch_round(missing, hours, bucket)

        # One retry for datasets that failed for any reason except a timeout:
        # reset the pool first, so a connection left over from another event
        # loop cannot fail the retry too. A timeout is not retried (it would
        # just double the wait when the database is unreachable).
        failed = [n for n, r in fetched.items()
                  if isinstance(r, BaseException) and not isinstance(r, TimeoutError)]
        if failed:
            reset_connection_pool()
            fetched.update(_fetch_round(failed, hours, bucket))

        now = time.time()
        for name, result in fetched.items():
            if isinstance(result, BaseException):
                logger.warning("Analytics dataset %r failed", name, exc_info=result)
                out[name] = Loaded(error=SECTION_ERROR)
            else:
                item = Loaded(value=result, fetched_at=now)
                _cache_put((name, hours, bucket), item)
                out[name] = item
    return out


# ----------------------------------------------------------------------
# Page chrome
# ----------------------------------------------------------------------
def _database_is_available() -> bool:
    """app.py's sidebar status check, run on the same event loop as every query."""
    try:
        return bool(run_sync(check_database_connection(), timeout=5))
    except Exception:
        return False


def render_shared_sidebar() -> dict:
    """The dashboard's common sidebar, made safe to use from this page.

    Two things in app.py need working around (both are bugs there; the proper
    fix is in app.py, after which this function just calls render_sidebar()):

    1. app.py draws its whole overview page, and its own sidebar, at module
       level. The FIRST import in a server process would therefore render the
       overview inside this page and fail on a duplicate widget key. We
       detect that, and restart this page once; the module is cached after.
    2. Its database status check uses asyncio.run() on the shared connection
       pool, i.e. a throwaway event loop. That makes the status flip between
       "connected" and "unreachable" on a healthy database, and leaves
       connections behind that crash later queries (storage.run_sync uses one
       long-lived loop). We replace it with a check on that same loop, and
       drop any connections the original left in the pool.
    """
    first_import = "src.dashboard.app" not in sys.modules
    app = importlib.import_module("src.dashboard.app")
    app.database_is_available = _database_is_available
    try:
        st.set_page_config(page_title="Sheba Shield | Analytics", page_icon="📊", layout="wide",
                           initial_sidebar_state="expanded")
    except Exception:                                          # app.py already set it on that import
        pass
    if first_import and hasattr(app, "settings"):
        reset_connection_pool()          # the import's own check left a bad connection behind
        st.rerun()
    return app.render_sidebar()


def _fmt_time(epoch: float | None) -> str:
    if epoch is None:
        return "n/a"
    return datetime.fromtimestamp(epoch).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")


# ----------------------------------------------------------------------
# Sections
# ----------------------------------------------------------------------
def _section(title: str) -> None:
    st.markdown(f"#### {title}")


def _chart_or_message(ds: Loaded, build, key: str, empty: str = EMPTY_MESSAGE) -> None:
    """Draw a chart, or the right message when it failed or has nothing to show."""
    if ds.error:
        st.warning(ds.error)
        return
    figure = build(ds.value)
    if figure is None:
        st.caption(empty)
    else:
        st.plotly_chart(figure, width="stretch", key=key)


def _render_clients(ds: Loaded) -> None:
    if ds.error:
        st.warning(ds.error)
        return
    table = clients_table(ds.value)
    if table.empty:
        st.caption(EMPTY_MESSAGE)
        return
    st.dataframe(
        table, hide_index=True, width="stretch",
        column_config={"Block rate (%)": st.column_config.NumberColumn(format="%.1f")},
    )


def _render_flags(ds: Loaded) -> None:
    if ds.error:
        st.warning(ds.error)
        return
    data = ds.value or {}
    if not data.get("total"):
        st.caption("No completions were flagged in this period.")
        return
    st.metric("Flagged completions", f"{data['total']:,}")
    left, right = st.columns(2)
    with left:
        st.caption("By action")
        st.dataframe(pd.DataFrame(data["by_action"]), hide_index=True, width="stretch")
    with right:
        st.caption("By category")
        st.dataframe(pd.DataFrame(data["by_category"]), hide_index=True, width="stretch")


def render_report(hours: int, refresh_seconds: int, auto_refresh: bool) -> None:
    """Everything below the controls. Runs as a fragment, so with auto-refresh on
    only this block re-runs every `refresh_seconds`, not the whole page."""
    bucket = bucket_for(hours)
    data = load_datasets(hours, bucket, ttl=refresh_seconds)

    # A total outage: every dataset failed. One friendly message, nothing else.
    if all(item.error for item in data.values()):
        st.error(DB_ERROR_MESSAGE)
        st.button("Retry", key="analytics_retry")
        return

    fetched = [item.fetched_at for item in data.values() if item.fetched_at]
    refresh_note = f"auto-refresh every {refresh_seconds} s" if auto_refresh else "auto-refresh off"
    st.caption(f"Last updated {_fmt_time(min(fetched) if fetched else None)} · {refresh_note}")

    # --- KPIs -----------------------------------------------------------
    kpis, previous = data["kpis"], data["kpis_previous"]
    if kpis.error:
        st.warning(kpis.error)
    else:
        render_kpi_cards(kpis.value, None if previous.error else previous.value)
        if not (kpis.value or {}).get("total_requests"):
            st.info(f"No requests were recorded in the last {range_label(hours)}. "
                    "Send traffic through the gateway and this page fills in.")

    # --- Volume + layers --------------------------------------------------
    left, right = st.columns([2, 1])
    with left:
        _section("Threat volume")
        _chart_or_message(data["volume"], build_volume_figure, "analytics_volume")
        total = (kpis.value or {}).get("total_requests") if not kpis.error else 0
        if (hours > RECENT_HOURS_LIMIT and total and not data["volume"].error
                and not data["volume"].value):
            st.info("Hourly metrics for this range have not been rolled up yet. The gateway writes "
                    "them every few minutes for recent hours; see the README for loading older data.")
    with right:
        _section("Blocked by layer")
        _chart_or_message(data["layers"], build_layer_figure, "analytics_layers",
                          empty="Nothing was blocked in this period.")

    # --- Risk + latency ---------------------------------------------------
    left, right = st.columns(2)
    with left:
        _section("Risk scores")
        _chart_or_message(data["risk"], build_risk_figure, "analytics_risk")
    with right:
        _section("Latency")
        p95_label = "p95" if hours <= RECENT_HOURS_LIMIT else f"p95 (worst hour per {bucket})"
        _chart_or_message(data["latency"], lambda rows: build_latency_figure(rows, p95_label=p95_label),
                          "analytics_latency")

    # --- Top threats --------------------------------------------------------
    left, right = st.columns(2)
    with left:
        _section("Top matched rules")
        _chart_or_message(data["patterns"], build_patterns_figure, "analytics_patterns",
                          empty="No blocked request matched a rule in this period.")
    with right:
        _section("Top client IPs")
        _render_clients(data["clients"])

    _section("Output scanner flags")
    _render_flags(data["flags"])


# ----------------------------------------------------------------------
# Page
# ----------------------------------------------------------------------
settings = render_shared_sidebar()

st.title("📊 Analytics")
st.caption("Real-time view of what the firewall inspected, blocked and how fast it did it.")

control_left, control_right = st.columns([3, 1])
with control_left:
    selected = st.radio("Time range", list(RANGES), index=list(RANGES).index(DEFAULT_RANGE),
                        horizontal=True, key="analytics_range")
with control_right:
    auto_refresh = st.toggle("Auto-refresh", value=True, key="analytics_auto_refresh")
    if st.button("Refresh now", key="analytics_refresh_now"):
        clear_cache()

_refresh_seconds = int(settings.get("refresh_seconds", 30))
_report = st.fragment(run_every=_refresh_seconds if auto_refresh else None)(render_report)
_report(RANGES[selected], _refresh_seconds, auto_refresh)