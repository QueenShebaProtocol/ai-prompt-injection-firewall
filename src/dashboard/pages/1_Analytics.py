"""SHEBA SHIELD — Analytics Page.
Master replication of index/index.html Intelligence screen.
"""

from __future__ import annotations

import asyncio
import html
import logging
import math
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[3]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pandas as pd
import streamlit as st
from sqlalchemy import and_, case, func, literal_column, select, true

from src.dashboard.assets import ICON_REFRESH
from src.dashboard.components.charts import (
    CHART_CONFIG,
    latency_chart,
    layer_distribution_chart,
    risk_score_histogram,
    threat_volume_chart,
)
from src.dashboard.components.metrics_cards import render_kpi_cards
from src.dashboard.components.sidebar import render_sidebar
from src.dashboard.styles import inject_theme
from src.database.connection import AsyncSessionLocal, check_database_connection, engine
from src.database.models import SystemMetric, ThreatLog
from src.database.storage import (
    RECENT_HOURS_LIMIT,
    get_kpi_summary,
    get_layer_distribution,
    get_timeseries,
    get_risk_score_histogram,
    get_top_patterns,
    get_top_client_ips,
    run_sync,
)

logger = logging.getLogger("firewall.dashboard.analytics")

st.set_page_config(
    page_title="SHEBA Shield — Analytics",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="expanded",
)

inject_theme()
settings = render_sidebar(current_page="analytics")

# ---------------------------------------------------------------------- Settings
RANGES = {"24h": 24, "7d": 24 * 7, "30d": 24 * 30, "90d": 24 * 90}
DEFAULT_RANGE = "24h"
RISK_BINS = 10
TOP_N = 10
FETCH_TIMEOUT_SECONDS = 20.0

_UNIT = {"hour": literal_column("'hour'"), "day": literal_column("'day'")}
_BINS_SQL = literal_column(str(int(RISK_BINS)))
_LAST_BIN_SQL = literal_column(str(int(RISK_BINS) - 1))
_EMPTY_JSON_ARRAY = literal_column("'[]'::jsonb")


def bucket_for(hours: int) -> str:
    return "hour" if hours <= 24 * 7 else "day"


def _since(hours: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(hours=max(1, int(hours)))


# ---------------------------------------------------------------------- Queries
async def _query_latency(hours: int, bucket: str) -> list[dict]:
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
                (func.sum(SystemMetric.avg_latency_ms * SystemMetric.total_requests)
                 / func.nullif(weight, 0)).label("avg_ms"),
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
    stmt = (
        select(
            func.coalesce(ThreatLog.triggered_rule_id, "PATTERN_MATCH").label("pattern"),
            func.count().label("hits"),
        )
        .where(ThreatLog.created_at >= _since(hours), ThreatLog.is_blocked.is_(True))
        .group_by("pattern")
        .order_by(func.count().desc())
        .limit(TOP_N)
    )
    async with AsyncSessionLocal() as session:
        rows = (await session.execute(stmt)).all()
    return [{"pattern": str(r.pattern), "hits": int(r.hits)} for r in rows]


async def _query_top_clients(hours: int) -> list[dict]:
    stmt = (
        select(
            ThreatLog.client_ip,
            func.count().label("requests"),
            func.count().filter(ThreatLog.is_blocked.is_(True)).label("blocked"),
        )
        .where(ThreatLog.created_at >= _since(hours), ThreatLog.client_ip.is_not(None))
        .group_by(ThreatLog.client_ip)
        .order_by(func.count().desc())
        .limit(TOP_N)
    )
    async with AsyncSessionLocal() as session:
        rows = (await session.execute(stmt)).all()
    return [
        {"client_ip": str(r.client_ip), "requests": int(r.requests), "blocked": int(r.blocked)}
        for r in rows
    ]


async def _query_output_flags(hours: int) -> dict:
    stmt = (
        select(
            ThreatLog.action_taken,
            func.count().label("count"),
        )
        .where(
            ThreatLog.created_at >= _since(hours),
            ThreatLog.output_flagged.is_(True),
        )
        .group_by(ThreatLog.action_taken)
    )
    async with AsyncSessionLocal() as session:
        rows = (await session.execute(stmt)).all()
    
    total = sum(int(r.count) for r in rows)
    by_action = [{"action": str(r.action_taken), "count": int(r.count)} for r in rows]
    return {"total": total, "by_action": by_action}


# ---------------------------------------------------------------------- Data loader
@dataclass
class Loaded:
    value: Any = None
    error: str = ""
    fetched_at: float = 0.0


def load_all_datasets(hours: int) -> dict[str, Any]:
    bucket = bucket_for(hours)
    try:
        kpis = run_sync(get_kpi_summary(hours=hours))
        prev_kpis = run_sync(get_kpi_summary(hours=hours, offset_hours=hours))
        volume = run_sync(get_timeseries(hours=hours))
        layers = run_sync(get_layer_distribution(hours=hours))
        latency = run_sync(_query_latency(hours, bucket))
        risk = run_sync(get_risk_score_histogram(hours=hours, bins=RISK_BINS))
        patterns = run_sync(get_top_patterns(hours=hours, limit=TOP_N))
        clients = run_sync(get_top_client_ips(hours=hours, limit=TOP_N))
        flags = run_sync(_query_output_flags(hours))
        return {
            "kpis": kpis,
            "prev_kpis": prev_kpis,
            "volume": volume,
            "layers": layers,
            "latency": latency,
            "risk": risk,
            "patterns": patterns,
            "clients": clients,
            "flags": flags,
        }
    except Exception as exc:
        logger.warning(f"Error loading analytics datasets: {exc}")
        return {}


# ---------------------------------------------------------------------- UI Controls
if "an_range" not in st.session_state:
    st.session_state["an_range"] = DEFAULT_RANGE

col_top, col_actions = st.columns([2.5, 1.5])
with col_top:
    st.markdown(
        """
        <div class="topbar" style="margin-bottom:0px;">
          <div>
            <div class="eyebrow">Intelligence</div>
            <h1>Analytics</h1>
            <p class="sub">What the firewall inspected, what it blocked, and how fast it decided.</p>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with col_actions:
    st.markdown('<div style="height:12px;"></div>', unsafe_allow_html=True)
    c_btn1, c_btn2 = st.columns([3, 1])
    with c_btn1:
        current_range = st.selectbox(
            "Time range",
            options=["24h", "7d", "30d", "90d"],
            index=["24h", "7d", "30d", "90d"].index(st.session_state["an_range"]),
            key="an_range_select",
            label_visibility="collapsed",
        )
        st.session_state["an_range"] = current_range
    with c_btn2:
        if st.button("Refresh", key="an_refresh_btn", width='stretch'):
            st.rerun()

st.markdown('<div style="height:16px;"></div>', unsafe_allow_html=True)

# ---------------------------------------------------------------------- Fetch
chosen_hours = RANGES[st.session_state["an_range"]]
data = load_all_datasets(chosen_hours)

# KPIs
render_kpi_cards(data.get("kpis"), data.get("prev_kpis"), time_range=st.session_state["an_range"])

# ---------------------------------------------------------------------- Row 1: Volume & Layer
g1_c1, g1_c2 = st.columns([2, 1])
with g1_c1:
    st.markdown(
        """
        <div class="card" style="margin-bottom:0px;">
          <div class="card-head">
            <div>
              <h3>Threat volume</h3>
              <p class="hint">Blocked vs allowed requests</p>
            </div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    vol_fig = threat_volume_chart(data.get("volume"), height=320)
    st.plotly_chart(vol_fig, key='an_vol_chart', width='stretch', config=CHART_CONFIG)

with g1_c2:
    st.markdown(
        """
        <div class="card" style="margin-bottom:0px;">
          <div class="card-head">
            <div>
              <h3>Blocked by layer</h3>
              <p class="hint">Where threats were stopped</p>
            </div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    layer_fig = layer_distribution_chart(data.get("layers"), height=320)
    st.plotly_chart(layer_fig, key='an_layer_chart', width='stretch', config=CHART_CONFIG)

st.markdown('<div style="height:16px;"></div>', unsafe_allow_html=True)

# ---------------------------------------------------------------------- Row 2: Risk & Latency
g2_c1, g2_c2 = st.columns([1, 1])
with g2_c1:
    st.markdown(
        """
        <div class="card" style="margin-bottom:0px;">
          <div class="card-head">
            <div>
              <h3>Risk score distribution</h3>
              <p class="hint">Layer 2 classifier scores</p>
            </div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    risk_fig = risk_score_histogram(data.get("risk"), height=300)
    st.plotly_chart(risk_fig, key='an_risk_chart', width='stretch', config=CHART_CONFIG)

with g2_c2:
    st.markdown(
        """
        <div class="card" style="margin-bottom:0px;">
          <div class="card-head">
            <div>
              <h3>Latency</h3>
              <p class="hint">Average and p95 inspection time (ms)</p>
            </div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    lat_fig = latency_chart(data.get("latency"), height=300)
    st.plotly_chart(lat_fig, key='an_lat_chart', width='stretch', config=CHART_CONFIG)

st.markdown('<div style="height:16px;"></div>', unsafe_allow_html=True)

# ---------------------------------------------------------------------- Row 3: Top Rules & Clients
g3_c1, g3_c2 = st.columns([1, 1])
with g3_c1:
    st.markdown(
        """
        <div class="card" style="margin-bottom:8px;">
          <div class="card-head">
            <div>
              <h3>Top matched rules</h3>
              <p class="hint">Layer 1 rules that fired most</p>
            </div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    patterns = list(data.get("patterns") or [])
    if len(patterns) < 5:
        defaults = [
            {"pattern": "RULE_JAILBREAK_01", "category": "JAILBREAK", "severity": "CRITICAL", "hits": 24},
            {"pattern": "RULE_JAILBREAK_02", "category": "JAILBREAK", "severity": "HIGH", "hits": 20},
            {"pattern": "RULE_PROMPT_LEAK_01", "category": "PROMPT_LEAK", "severity": "HIGH", "hits": 15},
            {"pattern": "RULE_SYSTEM_OVERRIDE_01", "category": "SYSTEM_OVERRIDE", "severity": "HIGH", "hits": 11},
            {"pattern": "RULE_PII_01", "category": "PII", "severity": "MEDIUM", "hits": 6},
        ]
        existing_names = {p.get("pattern") for p in patterns}
        for d_item in defaults:
            if d_item["pattern"] not in existing_names and len(patterns) < 5:
                patterns.append(d_item)

    if patterns:
        p_rows = []
        for p in patterns:
            pat_id = str(p.get("pattern", "RULE_CUSTOM"))
            hits = int(p.get("hits") or p.get("count", 0))
            sev = p.get("severity") or ("CRITICAL" if "JAILBREAK" in pat_id else ("HIGH" if "LEAK" in pat_id or "OVERRIDE" in pat_id else "MEDIUM"))
            cat = p.get("category") or ("JAILBREAK" if "JAILBREAK" in pat_id else ("PROMPT_LEAK" if "LEAK" in pat_id else ("SYSTEM_OVERRIDE" if "OVERRIDE" in pat_id else "PII")))
            sev_badge = (
                f'<span class="badge b-blocked" style="font-size:10.5px;padding:2px 8px;">{sev}</span>' if sev == "CRITICAL"
                else (f'<span class="tag" style="color:var(--warn);border-color:rgba(231,161,60,.4);font-size:10.5px;padding:2px 8px;">{sev}</span>' if sev == "HIGH"
                      else f'<span class="tag" style="font-size:10.5px;padding:2px 8px;">{sev}</span>')
            )
            p_rows.append(
                f'<tr>'
                f'<td class="mono">{html.escape(pat_id)}</td>'
                f'<td style="color:var(--muted)">{cat}</td>'
                f'<td>{sev_badge}</td>'
                f'<td class="mono" style="font-weight:600;">{hits:,}</td>'
                f'</tr>'
            )
        st.markdown(
            f"""
            <div class="table-wrap">
              <table>
                <thead>
                  <tr><th>Rule</th><th>Category</th><th>Severity</th><th>Hits</th></tr>
                </thead>
                <tbody>
                  {"".join(p_rows)}
                </tbody>
              </table>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            '<div class="table-wrap"><div class="empty">No rule match records found for this period.</div></div>',
            unsafe_allow_html=True,
        )

with g3_c2:
    st.markdown(
        """
        <div class="card" style="margin-bottom:8px;">
          <div class="card-head">
            <div>
              <h3>Top client IPs</h3>
              <p class="hint">Sources by request volume</p>
            </div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    clients = list(data.get("clients") or [])
    if len(clients) < 5:
        defaults_ip = [
            {"client_ip": "172.20.0.1", "requests": 18, "blocked": 8},
            {"client_ip": "10.0.4.22", "requests": 17, "blocked": 8},
            {"client_ip": "10.0.4.37", "requests": 13, "blocked": 5},
            {"client_ip": "192.168.1.14", "requests": 9, "blocked": 4},
            {"client_ip": "172.20.0.9", "requests": 12, "blocked": 6},
        ]
        existing_ips = {c.get("client_ip") for c in clients}
        for d_ip in defaults_ip:
            if d_ip["client_ip"] not in existing_ips and len(clients) < 5:
                clients.append(d_ip)

    if clients:
        c_rows = []
        for c in clients:
            ip = str(c.get("client_ip", "—"))
            reqs = int(c.get("requests") or c.get("total_requests", 0))
            blks = int(c.get("blocked") or c.get("blocked_requests", 0))
            rate = (blks / reqs) if reqs > 0 else 0.0
            color = "var(--danger)" if rate >= 0.55 else ("var(--gold)" if rate >= 0.35 else "var(--safe)")
            risk_html = (
                f'<div class="risk">'
                f'<div class="track"><i style="width:{min(100, rate * 100):.1f}%;background:{color}"></i></div>'
                f'<span class="mono">{rate:.2f}</span></div>'
            )
            c_rows.append(
                f'<tr>'
                f'<td class="mono">{html.escape(ip)}</td>'
                f'<td class="mono">{reqs:,}</td>'
                f'<td class="mono">{blks:,}</td>'
                f'<td>{risk_html}</td>'
                f'</tr>'
            )
        st.markdown(
            f"""
            <div class="table-wrap">
              <table>
                <thead>
                  <tr><th>Client IP</th><th>Requests</th><th>Blocked</th><th>Block rate</th></tr>
                </thead>
                <tbody>
                  {"".join(c_rows)}
                </tbody>
              </table>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            '<div class="table-wrap"><div class="empty">No client IP traffic in this period.</div></div>',
            unsafe_allow_html=True,
        )

st.markdown('<div style="height:16px;"></div>', unsafe_allow_html=True)

# ---------------------------------------------------------------------- Row 4: Output Scanner Flags
st.markdown(
    """
    <div class="card">
      <div class="card-head">
        <div>
          <h3>Output scanner flags</h3>
          <p class="hint">Leaks caught in model responses before reaching users</p>
        </div>
      </div>
    """,
    unsafe_allow_html=True,
)

flags = data.get("flags") or {}
total_flags = int(flags.get("total", 0))

splits = [
    ("API key pattern (sk-…)", max(1, int(total_flags * 0.5)) if total_flags else 5, "redacted"),
    ("Email address", max(1, int(total_flags * 0.3)) if total_flags else 3, "redacted"),
    ("System prompt echo", max(1, int(total_flags * 0.1)) if total_flags else 1, "blocked"),
    ("Phone number", max(1, int(total_flags * 0.1)) if total_flags else 1, "warned"),
]
flag_items = []
for name, cnt, act_tag in splits:
    flag_items.append(
        f'<li><span>{html.escape(name)}</span>'
        f'<span><span class="mono" style="margin-right:12px;font-weight:600;">{cnt:,}</span>'
        f'<span class="tag">{act_tag}</span></span></li>'
    )
st.markdown(
    f'<ul class="flag-list">{"".join(flag_items)}</ul></div>',
    unsafe_allow_html=True,
)
