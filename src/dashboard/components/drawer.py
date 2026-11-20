"""SHEBA SHIELD — Decision Evidence Drawer & Dialog Component.
Replicates the forensics slide-out drawer from index/index.html.
"""

from __future__ import annotations

import html
import json
from typing import Any

import streamlit as st


def _esc(val: Any) -> str:
    return html.escape(str(val or ""))


def _badge(action: str | None) -> str:
    a = (action or "PASSED").upper()
    cls = "b-blocked" if a == "BLOCKED" else ("b-redacted" if a == "REDACTED" else "b-passed")
    return f'<span class="badge {cls}">{a}</span>'


def _risk_bar(score: float | int | None) -> str:
    val = float(score) if isinstance(score, (int, float)) else 0.0
    val = max(0.0, min(1.0, val))
    color = "var(--danger)" if val >= 0.85 else ("var(--gold)" if val >= 0.35 else "var(--safe)")
    return (
        f'<div class="risk">'
        f'<div class="track"><i style="width:{val * 100:.1f}%;background:{color}"></i></div>'
        f'<span class="mono">{val:.2f}</span>'
        f'</div>'
    )


def _render_layer_trace(detail: dict) -> str:
    action = (detail.get("action_taken") or "PASSED").upper()
    triggered = (detail.get("triggered_layer") or "NONE").upper()
    layer_details = detail.get("layer_details") or {}
    if isinstance(layer_details, str):
        try:
            layer_details = json.loads(layer_details)
        except Exception:
            layer_details = {}

    order = ["LAYER_1", "LAYER_2", "LAYER_3"]
    stop_at = order.index(triggered) if triggered in order else -1

    traces_html = []
    for i, layer_name in enumerate(order):
        if stop_at == -1 or i < stop_at:
            res_text = "Clear"
            res_cls = "down"
        elif i == stop_at:
            if layer_name == "LAYER_1":
                rule_id = (layer_details.get("layer_1", {}) or {}).get("rule_id") or "Rule match"
                res_text = f"{action} · {rule_id}"
            elif layer_name == "LAYER_2":
                score = detail.get("risk_score", 0.0)
                res_text = f"{action} · score {score:.2f}"
            else:
                res_text = f"{action} · judge verdict"
            res_cls = "up"
        else:
            res_text = "Not reached"
            res_cls = ""
        
        traces_html.append(
            f'<div class="trace"><span class="tag mono">{layer_name}</span>'
            f'<span class="t-res {res_cls}">{res_text}</span></div>'
        )

    # Output scanner trace
    if action == "REDACTED" or detail.get("output_flagged"):
        traces_html.append(
            '<div class="trace"><span class="tag mono">OUTPUT_SCANNER</span>'
            '<span class="t-res up">Redacted sensitive leak</span></div>'
        )
    elif action != "BLOCKED":
        traces_html.append(
            '<div class="trace"><span class="tag mono">OUTPUT_SCANNER</span>'
            '<span class="t-res down">Clean</span></div>'
        )

    return f'<div class="layer-trace">{"".join(traces_html)}</div>'


def _render_matched_rule(detail: dict) -> str:
    layer_details = detail.get("layer_details") or {}
    if isinstance(layer_details, str):
        try:
            layer_details = json.loads(layer_details)
        except Exception:
            layer_details = {}

    l1 = layer_details.get("layer_1") or {}
    rule_id = l1.get("rule_id")
    category = l1.get("category")
    severity = l1.get("severity")
    pattern = l1.get("pattern") or detail.get("detected_patterns") or ""

    if not rule_id:
        return ""

    return (
        '<h3 style="margin-top:22px;font-size:13px">Matched rule</h3>'
        f'<div class="prompt-box mono" style="color:var(--ivory)">'
        f'{_esc(rule_id)}  ·  {_esc(category)}  ·  {_esc(severity)}\n'
        f'{_esc(pattern)}</div>'
    )


def render_evidence_dialog(detail: dict) -> None:
    """Render the full decision evidence drawer modal inside Streamlit."""
    action = (detail.get("action_taken") or "PASSED").upper()
    title = (
        "Blocked request" if action == "BLOCKED"
        else ("Redacted response" if action == "REDACTED" else "Passed request")
    )
    req_id = detail.get("request_id") or "—"
    created = detail.get("created_at") or "—"
    if hasattr(created, "strftime"):
        created = created.strftime("%Y-%m-%d %H:%M:%S UTC")
    else:
        created = str(created).replace("T", " ")[:19]
    ip = detail.get("client_ip") or "—"
    app = detail.get("application_id") or "—"
    model = detail.get("target_model") or "—"
    risk = detail.get("risk_score", 0.0)
    time_ms = detail.get("execution_time_ms")
    time_str = f"{time_ms:.1f} ms" if isinstance(time_ms, (int, float)) else "—"
    prompt = detail.get("raw_prompt") or detail.get("prompt_preview") or "(empty prompt)"

    st.markdown(
        f"""
        <div style="padding: 10px 0;">
          <div class="eyebrow">Decision evidence</div>
          <h2 class="serif" style="font-size:20px;margin-top:4px;color:var(--ivory);">{title}</h2>
          
          <div style="margin-top:14px">{_badge(action)}</div>

          <dl class="kv">
            <dt>Request ID</dt><dd class="mono">{_esc(req_id)}</dd>
            <dt>Created (UTC)</dt><dd class="mono">{_esc(created)}</dd>
            <dt>Client IP</dt><dd class="mono">{_esc(ip)}</dd>
            <dt>Application</dt><dd>{_esc(app)}</dd>
            <dt>Target model</dt><dd class="mono">{_esc(model)}</dd>
            <dt>Risk score</dt><dd>{_risk_bar(risk)}</dd>
            <dt>Inspection time</dt><dd class="mono">{_esc(time_str)}</dd>
          </dl>

          <h3 style="margin-top:22px;font-size:13px">Prompt (raw)</h3>
          <div class="prompt-box mono">{_esc(prompt)}</div>

          <h3 style="margin-top:22px;font-size:13px">Layer trace</h3>
          {_render_layer_trace(detail)}

          {_render_matched_rule(detail)}
        </div>
        """,
        unsafe_allow_html=True,
    )


if hasattr(st, "dialog"):
    @st.dialog("Decision Evidence", width="large")
    def open_evidence_modal(detail: dict) -> None:
        render_evidence_dialog(detail)
else:
    def open_evidence_modal(detail: dict) -> None:
        with st.expander("Decision Evidence", expanded=True):
            render_evidence_dialog(detail)
