"""Plotly chart builders faithfully styled to match index/index.html.

Pure functions (no database, no Streamlit calls). Every function returns a go.Figure.
"""

from __future__ import annotations

import html
import math
from collections.abc import Mapping
from datetime import date, datetime, timezone
from typing import Any, Iterable

import plotly.graph_objects as go

__all__ = [
    "CHART_CONFIG",
    "EMPTY_MESSAGE",
    "latency_chart",
    "layer_distribution_chart",
    "overview_categories_chart",
    "overview_traffic_chart",
    "risk_score_histogram",
    "threat_volume_chart",
    "top_patterns_chart",
]

EMPTY_MESSAGE = "No data for this period"
DEFAULT_HEIGHT = 260
MAX_POINTS = 1500

CHART_CONFIG = {
    "displaylogo": False,
    "displayModeBar": False,
    "responsive": True,
}

# Design system colors from index/index.html
BG = "#070B16"
SURFACE = "#0E1424"
SURFACE_2 = "#131B30"
LINE = "#1F2942"
LINE_SOFT = "#182136"
GOLD = "#D9AE5B"
GOLD_2 = "#F1D08C"
IVORY = "#ECE6D6"
MUTED = "#8C95AB"
FAINT = "#5E6782"
DANGER = "#E5554F"
SAFE = "#3DBE8B"
WARN = "#E7A13C"
FONT_FAMILY = "Geist, system-ui, -apple-system, sans-serif"

_TIME_KEYS = ("bucket_start", "bucket", "timestamp", "ts", "time", "hour", "created_at", "date")
_TOTAL_KEYS = ("total", "total_requests", "requests", "request_count", "count")
_BLOCKED_KEYS = ("blocked", "blocked_requests", "blocked_count", "threats", "blocks", "blocked_threats")
_SAFE_KEYS = ("safe", "safe_prompts", "passed", "allowed", "passed_count", "allowed_count")
_LOW_KEYS = ("bin_start", "start", "low", "lower", "min", "bucket_start")
_HIGH_KEYS = ("bin_end", "end", "high", "upper", "max", "bucket_end")
_LABEL_KEYS = ("range", "label", "bin")
_COUNT_KEYS = ("count", "n", "hits", "total", "requests", "occurrences")
_PATTERN_KEYS = ("pattern", "rule_id", "name", "label", "detected_pattern", "category")
_NAME_KEYS = ("metric", "metric_name", "name", "layer", "series")


def _esc(text: Any, limit: int | None = None) -> str:
    val = str(text or "")
    if limit is not None and len(val) > limit:
        val = val[: limit - 1] + "…"
    return html.escape(val, quote=False)


def _as_mapping(row: Any) -> Mapping | None:
    if isinstance(row, Mapping):
        return row
    inner = getattr(row, "_mapping", None)
    return inner if isinstance(inner, Mapping) else None


def _pick(row: Mapping, names: Iterable[str]) -> Any:
    for name in names:
        if row.get(name) is not None:
            return row[name]
    return None


def _num(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        n = float(value)
        return n if math.isfinite(n) else None
    except (TypeError, ValueError):
        return None


def _to_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, date):
        dt = datetime(value.year, value.month, value.day)
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        sec = value / 1000 if abs(value) > 1e11 else value
        try:
            dt = datetime.fromtimestamp(sec, tz=timezone.utc)
        except Exception:
            return None
    elif isinstance(value, str):
        txt = value.strip()
        if not txt:
            return None
        try:
            dt = datetime.fromisoformat(txt.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _rows(data: Any) -> list[Mapping]:
    if data is None or isinstance(data, (str, bytes, Mapping)):
        return []
    try:
        return [r for r in (_as_mapping(item) for item in list(data)) if r is not None]
    except TypeError:
        return []


def _apply_layout(
    fig: go.Figure,
    *,
    height: int,
    x_title: str | None = None,
    y_title: str | None = None,
    legend: bool = False,
    legend_pos: str = "top",
    hovermode: str | None = None,
) -> None:
    legend_cfg = (
        dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1, font=dict(color=MUTED, size=11))
        if legend_pos == "top"
        else dict(orientation="h", yanchor="top", y=-0.2, xanchor="center", x=0.5, font=dict(color=MUTED, size=11))
    )
    fig.update_layout(
        height=height,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=IVORY, family=FONT_FAMILY, size=12),
        margin=dict(l=10, r=10, t=10, b=10),
        showlegend=legend,
        legend=legend_cfg,
        hoverlabel=dict(bgcolor=SURFACE_2, bordercolor=LINE, font=dict(color=IVORY, family=FONT_FAMILY)),
        **({"hovermode": hovermode} if hovermode else {}),
    )
    axis_cfg = dict(
        gridcolor="rgba(31,41,66,0.6)",
        zerolinecolor="rgba(31,41,66,0.6)",
        linecolor=LINE,
        tickfont=dict(color=MUTED, size=11),
        automargin=True,
    )
    fig.update_xaxes(**axis_cfg, **({"title": dict(text=x_title, font=dict(color=MUTED))} if x_title else {}))
    fig.update_yaxes(**axis_cfg, **({"title": dict(text=y_title, font=dict(color=MUTED))} if y_title else {}))


def _empty_figure(*, height: int = DEFAULT_HEIGHT, text: str = EMPTY_MESSAGE) -> go.Figure:
    fig = go.Figure()
    _apply_layout(fig, height=height)
    fig.update_xaxes(visible=False)
    fig.update_yaxes(visible=False)
    fig.add_annotation(
        text=text, x=0.5, y=0.5, xref="paper", yref="paper",
        showarrow=False, font=dict(color=MUTED, size=14, family=FONT_FAMILY),
    )
    return fig


# ------------------------------------------------------------------ Overview Charts
def overview_traffic_chart(series: Any, *, height: int = 240) -> go.Figure:
    """Traffic overview (Passed vs Blocked) over the last 24 hours."""
    points: list[tuple[datetime, float, float]] = []
    for r in _rows(series):
        when = _to_datetime(_pick(r, _TIME_KEYS))
        if when is None:
            continue
        total = _num(_pick(r, _TOTAL_KEYS)) or 0.0
        blocked = _num(_pick(r, _BLOCKED_KEYS)) or 0.0
        safe = _num(_pick(r, _SAFE_KEYS))
        if safe is None:
            safe = max(0.0, total - blocked)
        points.append((when, safe, blocked))
    points.sort(key=lambda x: x[0])

    if not points:
        return _empty_figure(height=height, text="Awaiting 24h traffic telemetry")

    xs = [p[0].strftime("%H:00") for p in points]
    safe_ys = [p[1] for p in points]
    blocked_ys = [p[2] for p in points]

    fig = go.Figure()
    # Passed line
    fig.add_trace(go.Scatter(
        x=xs,
        y=safe_ys,
        mode="lines",
        name="Passed",
        line=dict(color=SAFE, width=2, shape="spline"),
        fill="tozeroy",
        fillcolor="rgba(61,190,139,0.12)",
        hovertemplate="Passed: %{y:,}<extra></extra>",
    ))
    # Blocked line
    fig.add_trace(go.Scatter(
        x=xs,
        y=blocked_ys,
        mode="lines",
        name="Blocked",
        line=dict(color=DANGER, width=2, shape="spline"),
        fill="tozeroy",
        fillcolor="rgba(229,85,79,0.15)",
        hovertemplate="Blocked: %{y:,}<extra></extra>",
    ))

    _apply_layout(fig, height=height, hovermode="x unified")
    fig.update_xaxes(nticks=8)
    fig.update_yaxes(rangemode="tozero")
    return fig


def overview_categories_chart(dist: dict[str, int | float] | None, *, height: int = 240) -> go.Figure:
    """Threat categories doughnut chart with cutout 68%."""
    counts = dist or {}
    total = sum(counts.values()) if counts else 0
    if not counts or total <= 0:
        counts = {"Jailbreak": 0, "Prompt leak": 0, "System override": 0, "PII": 0}
        return _empty_figure(height=height, text="No threat incidents recorded")

    labels = list(counts.keys())
    values = list(counts.values())
    colors = [DANGER, GOLD, WARN, "#6C7A9C", "#9B7BFF", "#4B5F7E"]

    fig = go.Figure()
    fig.add_trace(go.Pie(
        labels=labels,
        values=values,
        hole=0.68,
        direction="clockwise",
        sort=False,
        textinfo="percent",
        textfont=dict(color=IVORY, family=FONT_FAMILY, size=11),
        marker=dict(colors=colors, line=dict(color=SURFACE, width=3)),
        hovertemplate="%{label}<br>%{value:,} blocked (%{percent})<extra></extra>",
    ))
    _apply_layout(fig, height=height, legend=True, legend_pos="bottom")
    return fig


# ------------------------------------------------------------------ Analytics Charts
def threat_volume_chart(series: Any, *, height: int = 240) -> go.Figure:
    """Stacked Threat volume: Allowed + Blocked."""
    points: list[tuple[datetime, float, float]] = []
    for r in _rows(series):
        when = _to_datetime(_pick(r, _TIME_KEYS))
        if when is None:
            continue
        total = _num(_pick(r, _TOTAL_KEYS)) or 0.0
        blocked = _num(_pick(r, _BLOCKED_KEYS)) or 0.0
        safe = _num(_pick(r, _SAFE_KEYS))
        if safe is None:
            safe = max(0.0, total - blocked)
        points.append((when, safe, blocked))
    points.sort(key=lambda x: x[0])

    if not points:
        return _empty_figure(height=height)

    xs = [p[0].strftime("%H:00" if len(points) <= 24 else "%b %d") for p in points]
    safe_ys = [p[1] for p in points]
    blocked_ys = [p[2] for p in points]

    fig = go.Figure()
    fig.add_trace(go.Bar(
        x=xs,
        y=safe_ys,
        name="Allowed",
        marker=dict(color="rgba(61,190,139,0.55)", line=dict(width=0)),
        hovertemplate="Allowed: %{y:,}<extra></extra>",
    ))
    fig.add_trace(go.Bar(
        x=xs,
        y=blocked_ys,
        name="Blocked",
        marker=dict(color=DANGER, line=dict(width=0)),
        hovertemplate="Blocked: %{y:,}<extra></extra>",
    ))

    fig.update_layout(barmode="stack")
    _apply_layout(fig, height=height, legend=True, hovermode="x unified")
    fig.update_xaxes(nticks=10)
    fig.update_yaxes(rangemode="tozero")
    return fig


def layer_distribution_chart(dist: Any, *, height: int = 240) -> go.Figure:
    """Horizontal bar chart: Where threats were stopped."""
    labels = ["Layer 1 · rules", "Layer 2 · classifier", "Layer 3 · judge", "Output scanner"]
    counts = {
        "LAYER_1": 0,
        "LAYER_2": 0,
        "LAYER_3": 0,
        "OUTPUT_SCANNER": 0,
    }
    if isinstance(dist, Mapping):
        for k, v in dist.items():
            k_clean = str(k).upper().replace("-", "_").replace(" ", "_")
            if k_clean in counts:
                counts[k_clean] = int(v or 0)
    else:
        for r in _rows(dist):
            k = _pick(r, ("layer", "triggered_layer", "name"))
            v = _num(_pick(r, ("count", "blocked", "total"))) or 0
            k_clean = str(k).upper().replace("-", "_").replace(" ", "_")
            if k_clean in counts:
                counts[k_clean] += int(v)

    ys = [
        "Layer 1 · rules",
        "Layer 2 · classifier",
        "Layer 3 · judge",
        "Output scanner",
    ]
    xs = [
        counts["LAYER_1"],
        counts["LAYER_2"],
        counts["LAYER_3"],
        counts["OUTPUT_SCANNER"],
    ]
    colors = [GOLD, GOLD, "rgba(217,174,91,0.55)", WARN]

    if sum(xs) == 0:
        return _empty_figure(height=height)

    fig = go.Figure()
    fig.add_trace(go.Bar(
        x=xs,
        y=ys,
        orientation="h",
        marker=dict(color=colors, line=dict(width=0)),
        hovertemplate="%{y}: %{x:,} blocked<extra></extra>",
    ))
    _apply_layout(fig, height=height)
    fig.update_yaxes(autorange="reversed")
    fig.update_xaxes(rangemode="tozero")
    return fig


def risk_score_histogram(bins: Any, *, height: int = 220) -> go.Figure:
    """10-bin Risk score distribution (0.0 to 0.9) matching index.html."""
    bin_labels = ["0.0", "0.1", "0.2", "0.3", "0.4", "0.5", "0.6", "0.7", "0.8", "0.9"]
    counts = [0] * 10

    for r in _rows(bins):
        cnt = int(_num(_pick(r, _COUNT_KEYS)) or 0)
        low = _num(_pick(r, _LOW_KEYS))
        idx = None
        if low is not None:
            idx = min(9, max(0, int(low * 10)))
        else:
            lbl = str(_pick(r, _LABEL_KEYS) or "")
            for i, b in enumerate(bin_labels):
                if b in lbl:
                    idx = i
                    break
        if idx is not None and cnt > 0:
            counts[idx] += cnt

    if sum(counts) == 0:
        return _empty_figure(height=height)

    colors = [
        DANGER if float(b) >= 0.75 else (GOLD if float(b) >= 0.3 else SAFE)
        for b in bin_labels
    ]

    fig = go.Figure()
    fig.add_trace(go.Bar(
        x=bin_labels,
        y=counts,
        marker=dict(color=colors, line=dict(width=0), opacity=0.9),
        hovertemplate="Risk %{x}: %{y:,} requests<extra></extra>",
    ))
    _apply_layout(fig, height=height, x_title="Risk score")
    fig.update_xaxes(tickmode="array", tickvals=bin_labels, ticktext=bin_labels)
    fig.update_yaxes(rangemode="tozero")
    return fig


def latency_chart(series: Any, *, height: int = 220) -> go.Figure:
    """Average and p95 latency over time matching index.html."""
    points: list[tuple[datetime, float, float]] = []
    for r in _rows(series):
        when = _to_datetime(_pick(r, _TIME_KEYS))
        if when is None:
            continue
        avg = _num(_pick(r, ("avg_ms", "avg_latency_ms", "avg", "mean", "latency_ms")))
        p95 = _num(_pick(r, ("p95_ms", "p95_latency_ms", "p95", "max_latency_ms")))
        if avg is None and p95 is None:
            continue
        avg_val = avg if avg is not None else (p95 / 1.8 if p95 else 0.0)
        p95_val = p95 if p95 is not None else (avg_val * 1.8)
        points.append((when, avg_val, p95_val))
    points.sort(key=lambda x: x[0])

    if not points:
        return _empty_figure(height=height, text="Awaiting latency telemetry")

    xs = [p[0].strftime("%H:00" if len(points) <= 24 else "%b %d %H:00") for p in points]
    avg_ys = [p[1] for p in points]
    p95_ys = [p[2] for p in points]

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=xs,
        y=avg_ys,
        mode="lines",
        name="Average",
        line=dict(color=GOLD_2, width=2.2, shape="spline"),
        hovertemplate="Average: %{y:.1f} ms<extra></extra>",
    ))
    fig.add_trace(go.Scatter(
        x=xs,
        y=p95_ys,
        mode="lines",
        name="p95",
        line=dict(color=DANGER, width=2.2, dash="dash", shape="spline"),
        hovertemplate="p95: %{y:.1f} ms<extra></extra>",
    ))
    _apply_layout(fig, height=height, legend=True, legend_pos="top", hovermode="x unified")
    fig.update_yaxes(rangemode="tozero")
    return fig


def top_patterns_chart(rows: Any, *, height: int = DEFAULT_HEIGHT) -> go.Figure:
    """Top patterns / rules as horizontal bars."""
    items = []
    for r in _rows(rows):
        lbl = _pick(r, _PATTERN_KEYS)
        cnt = _num(_pick(r, _COUNT_KEYS))
        if lbl and cnt and cnt > 0:
            items.append((str(lbl), cnt))
    if not items:
        return _empty_figure(height=height)
    items.sort(key=lambda x: x[1], reverse=True)
    items = items[:10]

    fig = go.Figure()
    fig.add_trace(go.Bar(
        x=[it[1] for it in items],
        y=[_esc(it[0], 25) for it in items],
        orientation="h",
        marker=dict(color=GOLD, line=dict(width=0)),
        hovertemplate="%{y}: %{x:,} matches<extra></extra>",
    ))
    _apply_layout(fig, height=height)
    fig.update_yaxes(autorange="reversed")
    fig.update_xaxes(rangemode="tozero")
    return fig
