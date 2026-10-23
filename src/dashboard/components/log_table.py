"""Threat Logs UI components: filters, table and detail dialog.

Pure presentation. No database calls: the page (2_Threat_Logs.py) fetches the
data and passes it in.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

import pandas as pd
import streamlit as st

from src.database.storage import LogFilters, Page


LAYERS = ["LAYER_1", "LAYER_2", "LAYER_3", "OUTPUT_SCANNER", "NONE"]
TIME_RANGES: dict[str, timedelta | None] = {
    "Last hour": timedelta(hours=1),
    "Last 24 hours": timedelta(hours=24),
    "Last 7 days": timedelta(days=7),
    "Last 30 days": timedelta(days=30),
    "All time": None,
}
DEFAULT_RANGE = "Last 24 hours"
STATUS_OPTIONS = ["All", "Blocked", "Passed"]
STATUS_TO_BLOCKED = {"All": None, "Blocked": True, "Passed": False}
ACTION_LABELS = {
    "PASSED": "🟢 PASSED",
    "BLOCKED": "🔴 BLOCKED",
    "REDACTED": "🟠 REDACTED",
}
PREVIEW_LEN = 80

K_RANGE = "lf_range"
K_ANCHOR = "lf_time_anchor"


def _preview(text: str | None) -> str:
    """One-line, truncated prompt preview for the table."""
    text = (text or "").replace("\n", " ").replace("\r", " ")
    return text if len(text) <= PREVIEW_LEN else text[:PREVIEW_LEN] + "…"


def _action_label(action: str | None) -> str:
    return ACTION_LABELS.get(action or "", action or "")


def _time_window(range_label: str) -> datetime | None:
    """Start of the chosen window, held steady across reruns.

    The page treats any change in the filters as 'new search' (it resets the
    page number and closes the dialog). A fresh datetime.now() on every rerun
    would look like a change every time, so the anchor is stored in session
    state and only recomputed when the range changes or Refresh is clicked.
    """
    delta = TIME_RANGES[range_label]
    if delta is None:
        return None
    anchor = st.session_state.get(K_ANCHOR)
    if anchor is None or anchor[0] != range_label:
        anchor = (range_label, datetime.now(timezone.utc))
        st.session_state[K_ANCHOR] = anchor
    return anchor[1] - delta


def _refresh_window() -> None:
    st.session_state.pop(K_ANCHOR, None)


def render_filters(defaults: LogFilters | None = None) -> LogFilters:
    """Draw the filter widgets and return the chosen LogFilters."""
    d = defaults or LogFilters()

    status_index = {None: 0, True: 1, False: 2}.get(d.is_blocked, 0)
    layer_options = ["Any"] + LAYERS
    layer_index = layer_options.index(d.triggered_layer) if d.triggered_layer in layer_options else 0

    c1, c2, c3 = st.columns(3)
    with c1:
        range_label = st.selectbox(
            "Time range", list(TIME_RANGES),
            index=list(TIME_RANGES).index(DEFAULT_RANGE), key=K_RANGE,
        )
        st.button("↻ Refresh time window", key="lf_refresh", on_click=_refresh_window)
        status = st.radio("Status", STATUS_OPTIONS, index=status_index,
                          horizontal=True, key="lf_status")
    with c2:
        layer = st.selectbox("Triggering layer", layer_options,
                             index=layer_index, key="lf_layer")
        client_ip = st.text_input("Client IP", value=d.client_ip or "", key="lf_ip")
    with c3:
        min_risk = st.slider("Minimum risk score", 0.0, 1.0,
                             float(d.min_risk or 0.0), 0.05, key="lf_risk")
        text = st.text_input("Search prompt text", value=d.text or "", key="lf_text")

    return LogFilters(
        start=_time_window(range_label),
        end=None,
        is_blocked=STATUS_TO_BLOCKED[status],
        triggered_layer=None if layer == "Any" else layer,
        client_ip=client_ip.strip() or None,
        min_risk=min_risk if min_risk > 0 else None,
        text=text.strip() or None,
    )



def render_log_table(page: Page) -> str | None:
    """Show one page of logs. Returns the selected row's request_id, or None."""
    rows = list(page.items)
    if not rows:
        st.info("No threat logs match these filters. Try a wider time range "
                "or clear some filters.")
        return None

    df = pd.DataFrame([{
        "created_at": r.get("created_at"),
        "request_id": r.get("request_id"),
        "client_ip": r.get("client_ip"),
        "application_id": r.get("application_id"),
        "target_model": r.get("target_model"),
        "action_taken": _action_label(r.get("action_taken")),
        "triggered_layer": r.get("triggered_layer"),
        "risk_score": r.get("risk_score"),
        "prompt_preview": _preview(r.get("raw_prompt") or r.get("prompt_preview")),
    } for r in rows])

    options: dict[str, Any] = dict(
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row",
        key="log_table",
        column_config={
            "created_at": st.column_config.DatetimeColumn(
                "created_at (UTC)", format="YYYY-MM-DD HH:mm:ss"),
            "risk_score": st.column_config.ProgressColumn(
                "risk_score", min_value=0.0, max_value=1.0, format="%.2f"),
        },
    )
    try:
        event = st.dataframe(df, width="stretch", **options)
    except TypeError: 
        event = st.dataframe(df, use_container_width=True, **options)

    selected = event.selection.rows
    if not selected or selected[0] >= len(rows):
        return None
    return rows[selected[0]].get("request_id")


def _json_block(label: str, value: Any) -> None:
    """Pretty-print JSON as a code block (rendered literally, never as HTML)."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            pass
    st.markdown(f"**{label}**")
    st.code(json.dumps(value if value is not None else {}, indent=2, default=str),
            language="json")


def _plain_text_box(label: str, value: str | None, empty: str) -> None:
    """Show untrusted text exactly as written. st.text never parses HTML/markdown."""
    st.markdown(f"**{label}**")
    with st.container(height=220, border=True):
        st.text(value if value else empty)


def _detail_body(detail: dict) -> None:
    action = detail.get("action_taken")
    st.caption(f"Request {detail.get('request_id')} · {detail.get('created_at')}")

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Action", _action_label(action))
    c2.metric("Layer", detail.get("triggered_layer") or "—")
    risk = detail.get("risk_score")
    c3.metric("Risk", f"{risk:.2f}" if isinstance(risk, (int, float)) else "—")
    ms = detail.get("execution_time_ms")
    c4.metric("Time (ms)", f"{ms:.1f}" if isinstance(ms, (int, float)) else "—")

    if detail.get("output_flagged"):
        st.warning("Output scanner flagged this completion.")

    _plain_text_box("Prompt", detail.get("raw_prompt"), "(empty)")
    _plain_text_box("System instruction", detail.get("system_instruction"), "(none)")
    _plain_text_box("Completion", detail.get("output_completion"), "(not stored)")

    _json_block("Layer details", detail.get("layer_details"))
    _json_block("Detected patterns", detail.get("detected_patterns"))


if hasattr(st, "dialog"):
    @st.dialog("Request details", width="large")
    def render_detail_modal(detail: dict) -> None:
        """Open a modal with the full record of one request."""
        _detail_body(detail)
else: 
    def render_detail_modal(detail: dict) -> None:
        with st.expander("Request details", expanded=True):
            _detail_body(detail)