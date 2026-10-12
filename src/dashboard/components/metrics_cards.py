"""KPI metric cards for the analytics page (src/dashboard/pages/1_Analytics.py).

Pure render functions: they receive plain dictionaries and draw four
st.metric cards. This module never touches the database - the page fetches
the data (storage.get_kpi_summary) and passes it in.

Expected input, one dict per period:
    {"total_requests": int, "blocked_requests": int,
     "avg_latency_ms": float, "block_rate": float}

Rules the cards follow:
- A missing key, None, NaN or a non-number shows as "n/a".
- Zero requests never divides by zero: the block rate and the average
  latency have no meaning for an empty period, so they show "n/a".
- The block rate is worked out from the two counts. The "block_rate" key is
  only a fallback when a count is missing, and is read as a 0-1 fraction
  (a value above 1 is read as an already-computed percentage).
- Each delta compares this period with `previous`. No `previous`, or a
  previous value that cannot be compared, shows no delta.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any

NOT_AVAILABLE = "n/a"


# ----------------------------------------------------------------------
# Formatting helpers (pure functions, no Streamlit needed)
# ----------------------------------------------------------------------
def _to_float(value: Any) -> float | None:
    """Return `value` as a finite float, or None if it is missing or not a number."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def format_count(value: Any) -> str:
    """1234567 -> "1,234,567"; missing -> "n/a"."""
    number = _to_float(value)
    return NOT_AVAILABLE if number is None else f"{round(number):,}"


def format_rate(rate: Any) -> str:
    """Format a 0-1 fraction as a percentage: 0.125 -> "12.5%"; missing -> "n/a"."""
    number = _to_float(rate)
    return NOT_AVAILABLE if number is None else f"{number * 100:.1f}%"


def format_latency(milliseconds: Any) -> str:
    """0.04 -> "0.04 ms", 12.34 -> "12.3 ms", 1500 -> "1.50 s"; missing -> "n/a"."""
    ms = _to_float(milliseconds)
    if ms is None:
        return NOT_AVAILABLE
    if ms >= 1000:
        return f"{ms / 1000:.2f} s"
    if ms >= 10:
        return f"{ms:.1f} ms"
    return f"{ms:.2f} ms"


def _signed(value: float, decimals: int, suffix: str) -> str:
    """Format a change with an explicit sign; a change that rounds to zero has no sign."""
    rounded = round(value, decimals)
    if rounded == 0:
        return f"{0:.{decimals}f}{suffix}"
    return f"{rounded:+,.{decimals}f}{suffix}"


def delta_text(current: Any, previous: Any, mode: str = "percent") -> str | None:
    """Describe the change from `previous` to `current`, or None if it cannot be computed.

    mode "percent": relative change of a count        120 vs 100  -> "+20.0%"
                    (no value when previous is 0, as the change is undefined)
    mode "points":  difference of two 0-1 fractions    0.15 vs 0.10 -> "+5.0 pp"
    mode "ms":      difference of two latencies        12.5 vs 10   -> "+2.50 ms"

    The sign is always ASCII "+" / "-": Streamlit reads a leading "-" as a fall.
    """
    now, before = _to_float(current), _to_float(previous)
    if now is None or before is None:
        return None

    if mode == "percent":
        if before == 0:
            return None
        return _signed((now - before) / abs(before) * 100, 1, "%")

    if mode == "points":
        return _signed((now - before) * 100, 1, " pp")

    if mode == "ms":
        diff = now - before
        if abs(diff) >= 1000:
            return _signed(diff / 1000, 2, " s")
        return _signed(diff, 2 if abs(diff) < 10 else 1, " ms")

    raise ValueError(f"Unknown delta mode: {mode!r}")


def _is_zero_delta(text: str) -> bool:
    """True for "0.0%", "0.0 pp", "0.00 ms": a delta with no non-zero digit."""
    return not any(char in "123456789" for char in text)


# ----------------------------------------------------------------------
# Turning a KPI dict into the four values the cards show
# ----------------------------------------------------------------------
def _block_rate(total: float | None, blocked: float | None, raw_rate: Any) -> float | None:
    """Block rate as a 0-1 fraction, or None when it has no meaning."""
    if total is not None and total <= 0:
        return None  # no requests, so no rate

    if total is not None and blocked is not None:
        return min(max(blocked / total, 0.0), 1.0)

    # Fallback: a count is missing, so trust the "block_rate" key.
    rate = _to_float(raw_rate)
    if rate is None:
        return None
    if rate > 1:  # already a percentage
        rate /= 100
    return min(max(rate, 0.0), 1.0)


def _snapshot(kpis: Mapping[str, Any] | None) -> dict[str, float | None]:
    """Normalize one KPI dict. Every value is a float or None (= n/a)."""
    data = kpis if isinstance(kpis, Mapping) else {}

    total = _to_float(data.get("total_requests"))
    blocked = _to_float(data.get("blocked_requests"))
    latency = _to_float(data.get("avg_latency_ms"))

    if total is not None and total <= 0:
        latency = None  # an average over zero requests is meaningless

    return {
        "total": total,
        "blocked": blocked,
        "rate": _block_rate(total, blocked, data.get("block_rate")),
        "latency": latency,
    }


# label, snapshot key, value formatter, delta mode, delta colour, tooltip
# Colour: "inverse" = a rise is bad (red up / green down), "off" = neutral grey.
_CARDS = (
    ("Total requests", "total", format_count, "percent", "off",
     "All requests inspected in this period."),
    ("Blocked requests", "blocked", format_count, "percent", "inverse",
     "Requests stopped by any layer."),
    ("Block rate", "rate", format_rate, "points", "inverse",
     "Blocked requests as a share of all requests."),
    ("Avg latency", "latency", format_latency, "ms", "inverse",
     "Average proxy processing time per request."),
)


# ----------------------------------------------------------------------
# Rendering
# ----------------------------------------------------------------------
def render_kpi_cards(
    kpis: Mapping[str, Any] | None,
    previous: Mapping[str, Any] | None = None,
) -> None:
    """Draw four KPI cards, each with a delta against the previous period.

    kpis:     KPI dict for the period being viewed.
    previous: KPI dict for the period before it, or None for no deltas.
    """
    # Imported here so the formatting helpers above can be imported and
    # tested without Streamlit installed.
    import streamlit as st

    current = _snapshot(kpis)
    earlier = _snapshot(previous) if previous is not None else None

    columns = st.columns(len(_CARDS))
    for column, (label, key, formatter, mode, colour, tooltip) in zip(columns, _CARDS):
        delta = delta_text(current[key], earlier[key], mode) if earlier is not None else None
        if delta is None or _is_zero_delta(delta):
            colour = "off"  # nothing to judge: no change, or no delta at all

        column.metric(
            label=label,
            value=formatter(current[key]),
            delta=delta,
            delta_color=colour,
            help=tooltip,
        )