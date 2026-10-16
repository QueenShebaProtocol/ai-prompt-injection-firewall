"""Plotly chart builders for the analytics page (pure functions, no database, no Streamlit).

Every function takes plain data and returns a plotly Figure. Empty or unusable
input gives a readable "No data for this period" figure, never an exception.
All text is bundled with Plotly: no CDN links, no remote fonts, no images.

Data shapes the functions accept (the first matching key name wins, so the
exact column names from src/database/storage.py can differ a little):

  threat_volume_chart(series)         list of rows, one per time bucket
      time:    bucket_start | bucket | timestamp | ts | time | hour | created_at | date
      total:   total | total_requests | requests | request_count | count
      blocked: blocked | blocked_requests | blocked_count | threats | blocks | blocked_threats
      safe:    safe | safe_prompts | passed | allowed | passed_count | allowed_count
      (a missing total or safe value is worked out from the other two)
  layer_distribution_chart(dist)      blocked requests per layer, as returned by
                                      storage.get_layer_distribution:
                                      {"LAYER_1": 12, "LAYER_2": 5, "LAYER_3": 2,
                                       "OUTPUT_SCANNER": 1}. An optional "NONE" key means
                                      blocked by a pipeline error (fail-closed). A list of
                                      {"layer": ..., "count": ...} rows also works.
  risk_score_histogram(bins)          rows with count and either bounds
      (bin_start | start | low | lower | min, bin_end | end | high | upper | max)
      or a text label (range | label | bin), e.g. {"bin_start": 0.0, "bin_end": 0.1, "count": 40}
  latency_chart(series)               rows with a time key plus numeric columns whose name
      contains "latency" or ends in "_ms" (avg_latency_ms, p95_latency_ms, ...),
      or long rows {"time": ..., "metric": "avg", "value": 12.3}
  top_patterns_chart(rows)            rows {"pattern" | "rule_id" | "name" | "label": ..., "count": ...}

Large series are downsampled to MAX_POINTS points: counts are summed, latency
averages are averaged, p95/max values keep the maximum. The x-axis title says
how many original intervals each point covers. Naive times are treated as UTC.
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
    "MAX_POINTS",
    "latency_chart",
    "layer_distribution_chart",
    "risk_score_histogram",
    "threat_volume_chart",
    "top_patterns_chart",
]

# ------------------------------------------------------------------ constants
EMPTY_MESSAGE = "No data for this period"
DEFAULT_HEIGHT = 320
MAX_POINTS = 1500          # line series above this are downsampled
MAX_TOP_PATTERNS = 20
MAX_LABEL_CHARS = 40

# Pass to st.plotly_chart(fig, config=CHART_CONFIG): no Plotly logo, bar on hover only.
CHART_CONFIG = {"displaylogo": False, "displayModeBar": "hover"}

# Same palette as the dashboard shell.
PANEL = "#091A30"
GOLD = "#E8B75B"
BLUE = "#3985FF"
GREEN = "#25D6A0"
RED = "#F05268"
PURPLE = "#9B7BFF"
MUTED = "#91A7C7"
TEXT = "#EDF3FF"
GRID = "#203C60"
FONT_FAMILY = "system-ui, -apple-system, 'Segoe UI', Roboto, Arial, sans-serif"
LINE_COLORS = [BLUE, GOLD, GREEN, RED, PURPLE]

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

_LAYER_ORDER = ["LAYER_1", "LAYER_2", "LAYER_3", "OUTPUT_SCANNER", "NONE"]
_LAYER_LABELS = {
    "LAYER_1": "Layer 1 · rules",
    "LAYER_2": "Layer 2 · classifier",
    "LAYER_3": "Layer 3 · LLM",
    "OUTPUT_SCANNER": "Output scanner",
    "NONE": "Pipeline error (fail-closed)",
}
_LAYER_COLORS = {
    "LAYER_1": GOLD, "LAYER_2": BLUE, "LAYER_3": PURPLE, "OUTPUT_SCANNER": RED, "NONE": "#4B5F7E",
}


# -------------------------------------------------------------- small helpers
def _esc(text: Any, limit: int | None = None) -> str:
    """Make text safe for Plotly labels and hover text (Plotly reads a few HTML tags)."""
    value = str(text)
    if limit is not None and len(value) > limit:
        value = value[: limit - 1] + "…"
    return html.escape(value, quote=False)


def _as_mapping(row: Any) -> Mapping | None:
    if isinstance(row, Mapping):
        return row
    inner = getattr(row, "_mapping", None)  # SQLAlchemy rows
    return inner if isinstance(inner, Mapping) else None


def _pick(row: Mapping, names: Iterable[str]) -> Any:
    for name in names:
        if row.get(name) is not None:
            return row[name]
    return None


def _num(value: Any) -> float | None:
    """A finite float, or None for anything that is not a usable number."""
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _tidy(number: float) -> int | float:
    return int(number) if number == int(number) else number


def _to_datetime(value: Any) -> datetime | None:
    """Parse a datetime, date, ISO string or epoch number. Result is naive UTC."""
    if isinstance(value, datetime):
        moment = value
    elif isinstance(value, date):
        moment = datetime(value.year, value.month, value.day)
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        seconds = value / 1000 if abs(value) > 1e11 else value
        try:
            moment = datetime.fromtimestamp(seconds, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if moment.tzinfo is not None:
        moment = moment.astimezone(timezone.utc).replace(tzinfo=None)
    return moment


def _rows(data: Any) -> list[Mapping]:
    if data is None or isinstance(data, (str, bytes, Mapping)):
        return []
    try:
        items = list(data)
    except TypeError:
        return []
    return [row for row in (_as_mapping(item) for item in items) if row is not None]


def _downsample(xs: list, columns: list[list], modes: list[str]) -> tuple[list, list[list], int]:
    """Shrink to at most MAX_POINTS points. Returns (xs, columns, points per group)."""
    n = len(xs)
    if n <= MAX_POINTS:
        return xs, columns, 1
    group = -(-n // MAX_POINTS)  # ceil division
    new_xs = [xs[i] for i in range(0, n, group)]
    new_columns: list[list] = [[] for _ in columns]
    for start in range(0, n, group):
        for index, column in enumerate(columns):
            chunk = [v for v in column[start:start + group] if v is not None]
            if not chunk:
                new_columns[index].append(None)
            elif modes[index] == "sum":
                new_columns[index].append(sum(chunk))
            elif modes[index] == "max":
                new_columns[index].append(max(chunk))
            else:
                new_columns[index].append(sum(chunk) / len(chunk))
    return new_xs, new_columns, group


def _apply_layout(fig: go.Figure, *, height: int, x_title: str | None = None,
                  y_title: str | None = None, legend: bool = False,
                  hovermode: str | None = None) -> None:
    """The one shared look: transparent background, dashboard colours, system fonts."""
    fig.update_layout(
        height=height,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=TEXT, family=FONT_FAMILY, size=12),
        margin=dict(l=10, r=10, t=30, b=10),
        showlegend=legend,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0, font=dict(color=MUTED)),
        hoverlabel=dict(bgcolor=PANEL, bordercolor=GRID, font=dict(color=TEXT)),
        **({"hovermode": hovermode} if hovermode else {}),
    )
    axis = dict(gridcolor=GRID, zerolinecolor=GRID, linecolor=GRID, tickfont=dict(color=MUTED), automargin=True)
    fig.update_xaxes(**axis, **({"title": dict(text=x_title, font=dict(color=MUTED))} if x_title else {}))
    fig.update_yaxes(**axis, **({"title": dict(text=y_title, font=dict(color=MUTED))} if y_title else {}))


def _empty_figure(*, height: int = DEFAULT_HEIGHT) -> go.Figure:
    fig = go.Figure()
    _apply_layout(fig, height=height)
    fig.update_xaxes(visible=False)
    fig.update_yaxes(visible=False)
    fig.add_annotation(
        text=EMPTY_MESSAGE, x=0.5, y=0.5, xref="paper", yref="paper",
        showarrow=False, font=dict(color=MUTED, size=15),
    )
    return fig


def _lerp_hex(start: str, end: str, t: float) -> str:
    a = [int(start[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(end[i:i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{round(x + (y - x) * t):02X}" for x, y in zip(a, b))


def _risk_color(score: float) -> str:
    """Green (safe) -> gold -> red (risky) for a 0..1 score."""
    t = min(max(score, 0.0), 1.0)
    return _lerp_hex(GREEN, GOLD, t * 2) if t < 0.5 else _lerp_hex(GOLD, RED, (t - 0.5) * 2)


def _line_mode(points: int) -> str:
    return "lines+markers" if points <= 60 else "lines"  # a single point still shows


def _x_title(group: int) -> str:
    return "Time (UTC)" if group == 1 else f"Time (UTC) · each point = {group} intervals"


# ------------------------------------------------------------- threat volume
def threat_volume_chart(series: Any, *, height: int = DEFAULT_HEIGHT) -> go.Figure:
    """Requests over time: total, safe and blocked."""
    points: list[tuple[datetime, float | None, float | None, float | None]] = []
    for row in _rows(series):
        when = _to_datetime(_pick(row, _TIME_KEYS))
        if when is None:
            continue
        total = _num(_pick(row, _TOTAL_KEYS))
        blocked = _num(_pick(row, _BLOCKED_KEYS))
        safe = _num(_pick(row, _SAFE_KEYS))
        if total is None and blocked is not None and safe is not None:
            total = blocked + safe
        if safe is None and total is not None and blocked is not None:
            safe = max(total - blocked, 0.0)
        points.append((when, total, safe, blocked))
    points.sort(key=lambda p: p[0])

    lines = [
        ("Total", BLUE, [p[1] for p in points]),
        ("Safe", GREEN, [p[2] for p in points]),
        ("Blocked", RED, [p[3] for p in points]),
    ]
    lines = [line for line in lines if any(v is not None for v in line[2])]
    if not points or not lines:
        return _empty_figure(height=height)

    xs, columns, group = _downsample([p[0] for p in points], [line[2] for line in lines], ["sum"] * len(lines))
    mode = _line_mode(len(xs))
    fig = go.Figure()
    for (name, color, _), values in zip(lines, columns):
        fig.add_trace(go.Scatter(
            x=xs, y=[None if v is None else _tidy(v) for v in values], mode=mode, name=name,
            line=dict(color=color, width=2), marker=dict(size=6, color=color),
            fill="tozeroy" if name == "Blocked" else "none",
            fillcolor="rgba(240,82,104,0.12)" if name == "Blocked" else None,
            connectgaps=False,
            hovertemplate=name + ": %{y:,}<extra></extra>",
        ))
    _apply_layout(fig, height=height, x_title=_x_title(group), y_title="Requests", legend=True, hovermode="x unified")
    fig.update_xaxes(hoverformat="%Y-%m-%d %H:%M")
    fig.update_yaxes(rangemode="tozero", separatethousands=True)
    return fig


# ---------------------------------------------------------- layer distribution
def _layer_key(raw: Any) -> str:
    return "NONE" if raw is None else str(raw).strip().upper().replace(" ", "_").replace("-", "_") or "NONE"


def _count_of(value: Any) -> float | None:
    if isinstance(value, Mapping):
        return _num(_pick(value, ("count", "blocked", "total", "value")))
    return _num(value)


def layer_distribution_chart(dist: Any, *, height: int = DEFAULT_HEIGHT) -> go.Figure:
    """Which layer stopped each blocked request, as a donut."""
    counts: dict[str, float] = {}
    if isinstance(dist, Mapping):
        pairs = list(dist.items())
    else:
        pairs = [(_pick(row, ("layer", "triggered_layer", "name", "label")), _count_of(row))
                 for row in _rows(dist)]
    for raw_key, raw_value in pairs:
        value = _count_of(raw_value)
        if value is None or value <= 0:
            continue
        key = _layer_key(raw_key)
        counts[key] = counts.get(key, 0.0) + value
    if not counts:
        return _empty_figure(height=height)

    known = [k for k in _LAYER_ORDER if k in counts]
    other = sorted(k for k in counts if k not in _LAYER_ORDER)
    keys = known + other
    palette = iter(LINE_COLORS[::-1] + [MUTED])
    colors = [_LAYER_COLORS.get(k) or next(palette, MUTED) for k in keys]

    fig = go.Figure()
    fig.add_trace(go.Pie(
        labels=[_esc(_LAYER_LABELS.get(k, k.replace("_", " ").title()), MAX_LABEL_CHARS) for k in keys],
        values=[_tidy(counts[k]) for k in keys],
        hole=0.55, sort=False, direction="clockwise", textinfo="percent",
        textfont=dict(color=TEXT),
        marker=dict(colors=colors, line=dict(color=PANEL, width=2)),
        hovertemplate="%{label}<br>%{value:,} blocked (%{percent})<extra></extra>",
    ))
    _apply_layout(fig, height=height, legend=True)
    return fig


# ------------------------------------------------------------ risk histogram
def risk_score_histogram(bins: Any, *, height: int = DEFAULT_HEIGHT) -> go.Figure:
    """How many requests fall into each risk-score range."""
    items = []  # (low, high, label, count)
    for row in _rows(bins):
        count = _num(_pick(row, _COUNT_KEYS))
        if count is None or count < 0:
            continue
        low, high = _num(_pick(row, _LOW_KEYS)), _num(_pick(row, _HIGH_KEYS))
        label = _pick(row, _LABEL_KEYS)
        if low is None and high is None and label is None:
            continue
        items.append((low, high, label, count))
    if not items or sum(item[3] for item in items) <= 0:
        return _empty_figure(height=height)

    fig = go.Figure()
    if all(item[0] is not None and item[1] is not None and item[1] > item[0] for item in items):
        items.sort(key=lambda item: item[0])
        centers = [(lo + hi) / 2 for lo, hi, _, _ in items]
        widths = [hi - lo for lo, hi, _, _ in items]
        fig.add_trace(go.Bar(
            x=centers, y=[_tidy(item[3]) for item in items], width=widths,
            marker=dict(color=[_risk_color(c) for c in centers], line=dict(width=0)),
            customdata=[f"{lo:.2f} – {hi:.2f}" for lo, hi, _, _ in items],
            hovertemplate="Risk score %{customdata}<br>%{y:,} requests<extra></extra>",
        ))
        _apply_layout(fig, height=height, x_title="Risk score", y_title="Requests")
        highs = [item[1] for item in items]
        if min(item[0] for item in items) >= 0 and max(highs) <= 1:
            fig.update_xaxes(range=[0, 1])
    else:  # text labels only
        labels = [_esc(item[2] if item[2] is not None else "?", MAX_LABEL_CHARS) for item in items]
        fig.add_trace(go.Bar(
            x=labels, y=[_tidy(item[3]) for item in items],
            marker=dict(color=GOLD, line=dict(width=0)),
            hovertemplate="%{x}<br>%{y:,} requests<extra></extra>",
        ))
        _apply_layout(fig, height=height, x_title="Risk score", y_title="Requests")
        fig.update_xaxes(type="category")
    fig.update_yaxes(rangemode="tozero", separatethousands=True)
    return fig


# --------------------------------------------------------------------- latency
_LATENCY_NAMES = {"avg": "Average", "mean": "Average", "p50": "Median (p50)", "p95": "p95", "p99": "p99", "max": "Max"}


def _latency_label(key: str) -> str:
    base = key.lower()
    for cut in ("_latency_ms", "_latency", "_ms", "latency_"):
        base = base.replace(cut, "")
    base = base.strip("_") or key
    return _LATENCY_NAMES.get(base, base.replace("_", " ").title())


def _is_latency_key(key: str) -> bool:
    lowered = key.lower()
    return "latency" in lowered or lowered.endswith("_ms") or lowered in _LATENCY_NAMES


def latency_chart(series: Any, *, height: int = DEFAULT_HEIGHT) -> go.Figure:
    """Response time over time, one line per measure (average, p95, ...)."""
    points: dict[str, dict[datetime, float]] = {}
    for row in _rows(series):
        when = _to_datetime(_pick(row, _TIME_KEYS))
        if when is None:
            continue
        name_raw = _pick(row, _NAME_KEYS)
        if name_raw is not None and "value" in row:  # long format
            value = _num(row.get("value"))
            if value is not None:
                points.setdefault(_latency_label(str(name_raw)), {})[when] = value
            continue
        for key, raw in row.items():  # wide format
            if key in _TIME_KEYS or not isinstance(key, str) or not _is_latency_key(key):
                continue
            value = _num(raw)
            if value is not None:
                points.setdefault(_latency_label(key), {}).setdefault(when, value)
    if not points:
        return _empty_figure(height=height)

    names = list(points)
    xs = sorted({when for per_name in points.values() for when in per_name})
    columns = [[points[name].get(when) for when in xs] for name in names]
    modes = ["max" if name.lower().startswith("p9") or "max" in name.lower() else "mean" for name in names]
    xs, columns, group = _downsample(xs, columns, modes)

    fig = go.Figure()
    for index, (name, values) in enumerate(zip(names, columns)):
        color = LINE_COLORS[index % len(LINE_COLORS)]
        fig.add_trace(go.Scatter(
            x=xs, y=values, mode=_line_mode(len(xs)), name=_esc(name, MAX_LABEL_CHARS),
            line=dict(color=color, width=2), marker=dict(size=6, color=color),
            connectgaps=False,
            hovertemplate=_esc(name, MAX_LABEL_CHARS) + ": %{y:,.1f} ms<extra></extra>",
        ))
    _apply_layout(fig, height=height, x_title=_x_title(group), y_title="Latency (ms)", legend=True, hovermode="x unified")
    fig.update_xaxes(hoverformat="%Y-%m-%d %H:%M")
    fig.update_yaxes(rangemode="tozero", separatethousands=True)
    return fig


# ---------------------------------------------------------------- top patterns
def top_patterns_chart(rows: Any, *, height: int = DEFAULT_HEIGHT) -> go.Figure:
    """The most often detected patterns, as horizontal bars (largest on top)."""
    items = []
    for row in _rows(rows):
        label = _pick(row, _PATTERN_KEYS)
        count = _num(_pick(row, _COUNT_KEYS))
        if label is None or count is None or count <= 0:
            continue
        items.append((str(label), count))
    if not items:
        return _empty_figure(height=height)
    items.sort(key=lambda item: item[1], reverse=True)
    items = items[:MAX_TOP_PATTERNS]

    fig = go.Figure()
    fig.add_trace(go.Bar(
        x=[_tidy(count) for _, count in items],
        y=[_esc(label, MAX_LABEL_CHARS) for label, _ in items],
        orientation="h",
        marker=dict(color=GOLD, line=dict(width=0)),
        customdata=[_esc(label, 300) for label, _ in items],
        hovertemplate="%{customdata}<br>%{x:,} detections<extra></extra>",
    ))
    _apply_layout(fig, height=max(height, 40 * len(items) + 60), x_title="Detections")
    fig.update_yaxes(autorange="reversed", automargin=True)
    fig.update_xaxes(rangemode="tozero", separatethousands=True)
    return fig
