"""KPI metric cards matching index/index.html faithfully.

Supports both the Security Overview and Analytics layouts with the exact
design system: icon boxes, delta highlights, accent backgrounds and typography.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any

import streamlit as st

from src.dashboard.assets import (
    ICON_BLOCK,
    ICON_LAT,
    ICON_RATE,
    ICON_REQ,
    ICON_SAFE,
)

NOT_AVAILABLE = "—"


def _to_float(value: Any) -> float | None:
    try:
        n = float(value)
        return n if math.isfinite(n) else None
    except (TypeError, ValueError):
        return None


def format_count(value: Any) -> str:
    n = _to_float(value)
    return NOT_AVAILABLE if n is None else f"{round(n):,}"


def format_rate(rate: Any) -> str:
    n = _to_float(rate)
    if n is None:
        return NOT_AVAILABLE
    if n > 1.0:
        n /= 100.0
    return f"{n * 100.0:.1f}%"


def format_latency(ms: Any) -> str:
    n = _to_float(ms)
    if n is None:
        return NOT_AVAILABLE
    if n >= 1000.0:
        return f"{n / 1000.0:.2f} s"
    return f"{n:.1f} ms"


def _kpi_card_html(label: str, val: str, delta: str, icon_svg: str, accent: bool = False) -> str:
    accent_cls = "accent" if accent else ""
    return (
        f'<div class="card kpi {accent_cls}">'
        f'  <div class="label"><span class="ico">{icon_svg}</span>{label}</div>'
        f'  <div class="val">{val}</div>'
        f'  <div class="delta">{delta}</div>'
        f'</div>'
    )


def render_overview_kpis(kpis: Mapping[str, Any] | None, previous: Mapping[str, Any] | None = None) -> None:
    """Render the 4 KPI cards for the Security Overview page."""
    data = kpis or {}
    prev = previous or {}

    total = int(_to_float(data.get("total_requests")) or 0)
    blocked = int(_to_float(data.get("blocked_requests")) or 0)
    bypassed = int(_to_float(data.get("bypassed_requests")) or 0)
    if "safe_requests" in data and data.get("safe_requests") is not None:
        safe = int(_to_float(data.get("safe_requests")) or 0)
    else:
        safe = max(0, total - blocked - bypassed)
    inspected = max(0, total - bypassed)
    rate = (blocked / inspected * 100.0) if inspected > 0 else 0.0

    prev_total = int(_to_float(prev.get("total_requests")) or 0)
    if prev_total > 0:
        pct_change = ((total - prev_total) / prev_total) * 100.0
        cls = "up" if pct_change >= 0 else "down"
        sign = "+" if pct_change >= 0 else ""
        total_delta = f'<b class="{cls}">{sign}{pct_change:.1f}%</b> vs previous 24h'
    else:
        total_delta = 'Last 24 hours'

    cards = [
        _kpi_card_html("Total requests", f"{total:,}", total_delta, ICON_REQ),
        _kpi_card_html("Safe prompts", f"{safe:,}", "Passed inspection", ICON_SAFE),
        _kpi_card_html("Blocked threats", f"{blocked:,}", f'<b class="up">{blocked}</b> in this period', ICON_BLOCK),
        _kpi_card_html("Threat rate", f"{rate:.1f}%", "Of all inspected traffic", ICON_RATE, accent=True),
    ]

    st.markdown(
        f'<div class="grid kpis" style="margin-bottom:16px;">{"".join(cards)}</div>',
        unsafe_allow_html=True,
    )


def render_kpi_cards(
    kpis: Mapping[str, Any] | None,
    previous: Mapping[str, Any] | None = None,
    time_range: str = "24h",
) -> None:
    """Render the 4 KPI cards for the Analytics page."""
    data = kpis or {}
    prev = previous or {}

    total = int(_to_float(data.get("total_requests")) or 0)
    blocked = int(_to_float(data.get("blocked_requests")) or 0)
    bypassed = int(_to_float(data.get("bypassed_requests")) or 0)
    inspected = max(0, total - bypassed)
    rate = (blocked / inspected * 100.0) if inspected > 0 else 0.0
    latency = _to_float(data.get("avg_latency_ms"))
    lat_str = f"{latency:.1f} ms" if latency is not None else NOT_AVAILABLE

    p95 = _to_float(data.get("p95_latency_ms"))
    p95_str = f"p95 · {p95:.1f} ms" if p95 is not None else "p95 · — ms"

    # Delta for block rate
    prev_total = int(_to_float(prev.get("total_requests")) or 0)
    prev_blocked = int(_to_float(prev.get("blocked_requests")) or 0)
    prev_bypassed = int(_to_float(prev.get("bypassed_requests")) or 0)
    prev_inspected = max(0, prev_total - prev_bypassed)
    prev_rate = (prev_blocked / prev_inspected * 100.0) if prev_inspected > 0 else 0.0
    diff_rate = rate - prev_rate
    diff_cls = "up" if diff_rate > 0 else "down"
    diff_sign = "+" if diff_rate > 0 else ""
    rate_delta = (
        f'<b class="{diff_cls}">{diff_sign}{diff_rate:.1f}%</b> vs previous'
        if prev_total > 0 else "Baseline established"
    )

    req_sub = f"{inspected:,} inspected in {time_range}" if bypassed > 0 else f"Inspected in {time_range}"
    cards = [
        _kpi_card_html("Total requests", f"{total:,}", req_sub, ICON_REQ),
        _kpi_card_html("Blocked requests", f"{blocked:,}", "Stopped before the model", ICON_BLOCK),
        _kpi_card_html("Block rate", f"{rate:.1f}%", rate_delta, ICON_RATE, accent=True),
        _kpi_card_html("Avg latency", lat_str, p95_str, ICON_LAT),
    ]

    st.markdown(
        f'<div class="grid kpis" style="margin-bottom:16px;">{"".join(cards)}</div>',
        unsafe_allow_html=True,
    )
