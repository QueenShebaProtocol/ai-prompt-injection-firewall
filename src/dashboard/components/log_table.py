"""
Threat Logs UI components faithfully reproducing index/index.html.

Pure presentation components: filters, table with badges and the slide-out
Decision Evidence drawer that opens instantly when clicking ANY row in the table.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timedelta, timezone
from typing import Any

import streamlit as st
import streamlit.components.v1 as components

from src.database.storage import LogFilters, Page

LAYERS = ["LAYER_1", "LAYER_2", "LAYER_3", "OUTPUT_SCANNER", "NONE"]

# Map triggered_layer → inspection direction shown in table
_DIRECTION_MAP = {
    "LAYER_1": "INPUT",
    "LAYER_2": "INPUT",
    "LAYER_3": "INPUT",
    "OUTPUT_SCANNER": "OUTPUT",
    "NONE": "INPUT",  # bypassed or clean pass
}
TIME_RANGES: dict[str, timedelta | None] = {
    "Last hour": timedelta(hours=1),
    "Last 24 hours": timedelta(hours=24),
    "Last 7 days": timedelta(days=7),
    "Last 30 days": timedelta(days=30),
    "All time": None,
}
DEFAULT_RANGE = "Last 24 hours"
STATUS_OPTIONS = ["All", "Blocked", "Redacted", "Passed", "Bypassed"]
PREVIEW_LEN = 80

K_RANGE = "lf_range"
K_ANCHOR = "lf_time_anchor"


def _preview(text: str | None) -> str:
    txt = (text or "").replace("\n", " ").replace("\r", " ")
    return txt if len(txt) <= PREVIEW_LEN else txt[:PREVIEW_LEN] + "…"


def _time_window(range_label: str) -> datetime | None:
    delta = TIME_RANGES.get(range_label)
    if delta is None:
        return None
    anchor = st.session_state.get(K_ANCHOR)
    if anchor is None or anchor[0] != range_label:
        anchor = (range_label, datetime.now(timezone.utc))
        st.session_state[K_ANCHOR] = anchor
    return anchor[1] - delta


def get_active_filters() -> LogFilters:
    """Read currently selected filter values from session state without rendering."""
    range_label = st.session_state.get(K_RANGE, DEFAULT_RANGE)
    layer = st.session_state.get("lf_layer", "Any")
    client_ip = (st.session_state.get("lf_ip") or "").strip() or None
    text = (st.session_state.get("lf_text") or "").strip() or None
    min_risk = float(st.session_state.get("lf_risk") or 0.0)
    status_choice = st.session_state.get("lf_status_choice", "All")
    is_blocked = True if status_choice == "Blocked" else (False if status_choice == "Passed" else None)
    bypassed_only = True if status_choice == "Bypassed" else None
    return LogFilters(
        start=_time_window(range_label),
        end=None,
        is_blocked=is_blocked,
        triggered_layer=None if layer == "Any" else layer,
        client_ip=client_ip,
        min_risk=min_risk if min_risk > 0 else None,
        text=text,
        bypassed_only=bypassed_only,
    )
def render_filters(defaults: LogFilters | None = None, matching_count: int | None = None) -> LogFilters:
    """Draw the filters card matching the target UI design exactly."""
    d = defaults or LogFilters()

    # Time range
    range_options = list(TIME_RANGES)
    range_idx = range_options.index(DEFAULT_RANGE) if DEFAULT_RANGE in range_options else 0

    # Layer options
    layer_options = ["Any"] + LAYERS
    layer_idx = layer_options.index(d.triggered_layer) if d.triggered_layer in layer_options else 0

    # Status index
    status_val = st.session_state.get("lf_status_choice", "All")

    # Read current risk for the dynamic label "MIN RISK - 0.00"
    curr_risk = float(st.session_state.get("lf_risk", d.min_risk or 0.0))

    with st.container(border=True):
        # First row of filters (5 columns with proportions matching screenshot)
        f1, f2, f3, f4, f5 = st.columns([1.3, 1.3, 1.3, 2.4, 1.7])
        with f1:
            range_label = st.selectbox("TIME RANGE", range_options, index=range_idx, key=K_RANGE)
        with f2:
            layer = st.selectbox("TRIGGERING LAYER", layer_options, index=layer_idx, key="lf_layer")
        with f3:
            client_ip = st.text_input("CLIENT IP", value=d.client_ip or "", placeholder="e.g. 172.20.0.1", key="lf_ip")
        with f4:
            text = st.text_input("SEARCH PROMPT TEXT", value=d.text or "", placeholder="Search prompts...", key="lf_text")
        with f5:
            min_risk = st.slider(f"MIN RISK - {curr_risk:.2f}", 0.0, 1.0, float(d.min_risk or 0.0), 0.05, key="lf_risk", format="%.2f")

        # Second row: Status segmented pill choices + matching count aligned horizontally
        s_col, count_col = st.columns([3, 1.5])
        with s_col:
            status_choice = st.radio(
                "STATUS FILTER",
                options=STATUS_OPTIONS,
                index=STATUS_OPTIONS.index(status_val) if status_val in STATUS_OPTIONS else 0,
                horizontal=True,
                key="lf_status_choice",
                label_visibility="collapsed",
            )
        with count_col:
            count_str = f"{matching_count:,} matching log entries" if matching_count is not None else ""
            st.markdown(
                f'<div class="filter-count-label">{count_str}</div>',
                unsafe_allow_html=True,
            )

    # Determine is_blocked and action filter
    is_blocked = True if status_choice == "Blocked" else (False if status_choice == "Passed" else None)
    bypassed_only = True if status_choice == "Bypassed" else None
    return LogFilters(
        start=_time_window(range_label),
        end=None,
        is_blocked=is_blocked,
        triggered_layer=None if layer == "Any" else layer,
        client_ip=(client_ip or "").strip() or None,
        min_risk=min_risk if min_risk > 0 else None,
        text=(text or "").strip() or None,
        bypassed_only=bypassed_only,
    )


def render_log_table(page: Page) -> str | None:
    """Show the table of threat logs matching index/index.html.

    Clicking ANY row in the table instantly slides out the Decision Evidence
    drawer from the right side, displaying full evidence matching index.html.
    """
    rows = list(page.items) if page else []

    if not rows:
        st.markdown(
            '<div class="table-wrap"><div class="empty">No log entries match these filters.</div></div>',
            unsafe_allow_html=True,
        )
        return None

    # Prepare rows data for client-side slide-out drawer
    rows_data = []
    rows_html = []
    for r in rows:
        rid = str(r.get("request_id") or "")
        t = r.get("created_at") or ""
        t_str = t.strftime("%Y-%m-%d %H:%M:%S") if hasattr(t, "strftime") else str(t).replace("T", " ")[:19]
        ip = str(r.get("client_ip") or "—")
        app = str(r.get("application_id") or "—")
        model = str(r.get("target_model") or "—")
        act = str(r.get("action_taken") or "PASSED").upper()
        layer = str(r.get("triggered_layer") or "NONE")
        risk = float(r.get("risk_score") or 0.0)
        ms = float(r.get("execution_time_ms") or 0.0)
        prompt = str(r.get("raw_prompt") or r.get("prompt_preview") or "")

        # Extract rule details if matched
        layer_details = r.get("layer_details") or {}
        if isinstance(layer_details, str):
            try:
                layer_details = json.loads(layer_details)
            except Exception:
                layer_details = {}

        rule_info = None
        if isinstance(layer_details, dict):
            l1 = layer_details.get("layer_1")
            if isinstance(l1, dict) and l1.get("rule_id"):
                rule_info = {
                    "id": str(l1.get("rule_id")),
                    "cat": str(l1.get("category") or "GENERAL"),
                    "sev": str(l1.get("severity") or "CRITICAL"),
                    "pat": str(l1.get("pattern") or l1.get("rule_id")),
                }

        if not rule_info:
            patterns = r.get("detected_patterns")
            if isinstance(patterns, list) and patterns:
                rule_info = {
                    "id": str(patterns[0]),
                    "cat": "DETECTION_RULE",
                    "sev": "HIGH",
                    "pat": str(patterns[0]),
                }

        # Determine BYPASSED from layer_details master field
        is_bypassed = isinstance(layer_details, dict) and layer_details.get("firewall_master") == "OFF"
        display_act = "BYPASSED" if is_bypassed else act

        # Inspection direction: OUTPUT_SCANNER operates on responses; all input layers on the prompt
        direction = _DIRECTION_MAP.get(layer, "INPUT")
        if is_bypassed:
            direction = "BYPASSED"

        # Layer 3 details for the drawer
        l3_details = layer_details.get("layer_3") if isinstance(layer_details, dict) else None
        l3_decision = l3_details.get("decision", "") if isinstance(l3_details, dict) else ""
        l3_rationale = l3_details.get("rationale", "") if isinstance(l3_details, dict) else ""
        l2_details = layer_details.get("layer_2") if isinstance(layer_details, dict) else None
        l2_score_val = float(l2_details.get("score", risk)) if isinstance(l2_details, dict) else risk
        output_scanner_details = layer_details.get("output_scanner") if isinstance(layer_details, dict) else None
        output_cats = output_scanner_details.get("categories", []) if isinstance(output_scanner_details, dict) else []

        rows_data.append({
            "id": rid,
            "t": t_str,
            "ip": ip,
            "app": app,
            "model": model,
            "action": display_act,
            "layer": layer,
            "risk": risk,
            "l2score": l2_score_val,
            "ms": ms,
            "prompt": prompt,
            "rule": rule_info,
            "bypassed": is_bypassed,
            "direction": direction,
            "l3decision": l3_decision,
            "l3rationale": l3_rationale,
            "outputcats": output_cats,
        })

        if display_act == "BLOCKED":
            act_badge = '<span class="badge b-blocked">BLOCKED</span>'
        elif display_act == "REDACTED":
            act_badge = '<span class="badge b-redacted">REDACTED</span>'
        elif display_act == "BYPASSED":
            act_badge = '<span class="badge" style="background:rgba(255,180,0,.18);color:#FFB400;border:1px solid rgba(255,180,0,.4);">BYPASSED</span>'
        else:
            act_badge = '<span class="badge b-passed">PASSED</span>'

        risk_color = "var(--danger)" if risk >= 0.85 else ("var(--gold)" if risk >= 0.35 else "var(--safe)")
        risk_html = (
            f'<div class="risk">'
            f'<div class="track"><i style="width:{min(100, risk * 100):.1f}%;background:{risk_color}"></i></div>'
            f'<span class="mono">{risk:.2f}</span></div>'
        )
        dir_tag = (
            f'<span class="tag mono" style="font-size:10px;padding:1px 5px;opacity:.7">{html.escape(direction)}</span>'
        )
        prompt_preview = _preview(prompt)
        rid_safe = html.escape(rid)

        rows_html.append(
            f'<tr class="clickable" data-id="{rid_safe}" tabindex="0" title="Click to view decision evidence" '
            f'onclick="if(window.parent&&window.parent.shebaOpenDrawer){{window.parent.shebaOpenDrawer(\'{rid_safe}\');}}else if(window.shebaOpenDrawer){{window.shebaOpenDrawer(\'{rid_safe}\')}}">'
            f'<td class="mono">{html.escape(t_str)}</td>'
            f'<td class="mono" style="color:var(--muted)">{html.escape(rid[:13])}…</td>'
            f'<td class="mono">{html.escape(ip)}</td>'
            f'<td>{html.escape(app)}</td>'
            f'<td class="mono" style="color:var(--muted)">{html.escape(model)}</td>'
            f'<td>{act_badge}</td>'
            f'<td><span class="tag mono">{html.escape(layer)}</span> {dir_tag}</td>'
            f'<td>{risk_html}</td>'
            f'<td class="trunc">{html.escape(prompt_preview)}</td>'
            f'</tr>'
        )

    logs_json = json.dumps(rows_data)

    # Full table with Wazuh-style Expand/Fullscreen Toolbar + Slide-out Drawer
    table_and_drawer_html = f"""
    <div class="table-wrap">
      <div style="display:flex;justify-content:space-between;align-items:center;padding:10px 14px;border-bottom:1px solid var(--line);background:var(--surface);">
        <span style="font-size:12px;color:var(--muted);font-weight:500;">Forensics log stream · Click any row to inspect decision evidence</span>
        <button id="btnFullscreenTable" type="button" class="btn" style="padding:4px 10px;font-size:12px;cursor:pointer;display:inline-flex;align-items:center;gap:6px;background:var(--surface-2);border:1px solid var(--line);border-radius:6px;color:var(--ivory);"
                onclick="if(window.parent&&window.parent.shebaToggleFullscreenTable){{window.parent.shebaToggleFullscreenTable();}}else if(window.shebaToggleFullscreenTable){{window.shebaToggleFullscreenTable();}}">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M8 3H5a2 2 0 0 0-2 2v3m18 0V5a2 2 0 0 0-2-2h-3m0 18h3a2 2 0 0 0 2-2v-3M3 16v3a2 2 0 0 0 2 2h3"/></svg>
          <span>Fullscreen</span>
        </button>
      </div>
      <table>
        <thead>
          <tr>
            <th>Created (UTC)</th>
            <th>Request ID</th>
            <th>Client IP</th>
            <th>Application</th>
            <th>Model</th>
            <th>Action</th>
            <th>Layer / Direction</th>
            <th>Risk</th>
            <th>Prompt preview</th>
          </tr>
        </thead>
        <tbody>
          {"".join(rows_html)}
        </tbody>
      </table>
    </div>

    <!-- Slide-out Drawer & Scrim matching index.html -->
    <div class="scrim" id="scrim" onclick="if(window.parent&&window.parent.shebaCloseDrawer){{window.parent.shebaCloseDrawer();}}else if(window.shebaCloseDrawer){{window.shebaCloseDrawer();}}"></div>
    <aside class="drawer" id="drawer" role="dialog" aria-modal="true" aria-labelledby="dTitle" tabindex="-1">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <div>
          <div class="eyebrow">Decision evidence</div>
          <h2 id="dTitle" class="serif" style="font-size:18px;margin-top:4px">Request</h2>
        </div>
        <button class="btn" id="dClose" type="button" aria-label="Close details"
                onclick="if(window.parent&&window.parent.shebaCloseDrawer){{window.parent.shebaCloseDrawer();}}else if(window.shebaCloseDrawer){{window.shebaCloseDrawer();}}">Close</button>
      </div>
      <div id="dBody"></div>
    </aside>
    """

    st.markdown(table_and_drawer_html, unsafe_allow_html=True)

    # Inject controller via Streamlit iframe component to ensure execution in parent window
    controller_js = f"""
    <script>
    (function() {{
      try {{
        const pwin = window.parent || window;
        const pdoc = (window.parent && window.parent.document) || document;
        const LOGS = {logs_json};

        pwin.__SHEBA_LOGS__ = LOGS;

        // Keep sensitive banner hidden across reruns if dismissed in this browser session
        if ((pwin.sessionStorage && pwin.sessionStorage.getItem('sheba_hide_banner') === '1') ||
            (window.sessionStorage && window.sessionStorage.getItem('sheba_hide_banner') === '1')) {{
          const sb = pdoc.getElementById('sensitiveBanner');
          if (sb) sb.style.display = 'none';
        }}

        pwin.shebaCloseDrawer = function() {{
          const d = pdoc.getElementById('drawer');
          const s = pdoc.getElementById('scrim');
          if (d) d.classList.remove('open');
          if (s) s.classList.remove('open');
        }};

        pwin.shebaOpenDrawer = function(id) {{
          const logs = pwin.__SHEBA_LOGS__ || [];
          const l = logs.find(x => String(x.id) === String(id));
          if (!l) return;
          const d = pdoc.getElementById('drawer');
          const s = pdoc.getElementById('scrim');
          const dTitle = pdoc.getElementById('dTitle');
          const dBody = pdoc.getElementById('dBody');
          if (!d || !s || !dBody) return;

          const esc = s => String(s || '').replace(/[&<>"']/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]));
          const badge = a => {{
            const act = (a || 'PASSED').toUpperCase();
            if (act === 'BLOCKED') return `<span class="badge b-blocked">BLOCKED</span>`;
            if (act === 'REDACTED') return `<span class="badge b-redacted">REDACTED</span>`;
            if (act === 'BYPASSED') return `<span class="badge" style="background:rgba(255,180,0,.18);color:#FFB400;border:1px solid rgba(255,180,0,.4);">BYPASSED</span>`;
            return `<span class="badge b-passed">PASSED</span>`;
          }};
          const riskCol = v => v >= .85 ? 'var(--danger)' : (v >= .35 ? 'var(--gold)' : 'var(--safe)');
          const riskBar = v => {{
            const val = Number(v) || 0;
            return `<div class="risk"><div class="track"><i style="width:${{Math.min(100, val * 100).toFixed(1)}}%;background:${{riskCol(val)}}"></i></div><span class="mono">${{val.toFixed(2)}}</span></div>`;
          }};

          const rule = l.rule;
          // Build layer trace from actual layer_details-based data
          const tr = (name, res, cls, detail) => {{
            const detailHtml = detail ? `<span style="font-size:11px;color:var(--muted);margin-left:6px;">${{esc(detail)}}</span>` : '';
            return `<div class="trace"><span class="tag mono">${{name}}</span><span class="t-res ${{cls}}">${{res}}</span>${{detailHtml}}</div>`;
          }};

          let trace = '';
          if (l.bypassed) {{
            // BYPASSED: no layers ran
            trace = tr('LAYER_1','NOT EXECUTED','','firewall OFF') +
                    tr('LAYER_2','NOT EXECUTED','','firewall OFF') +
                    tr('LAYER_3','NOT EXECUTED','','firewall OFF') +
                    tr('OUTPUT_SCANNER','NOT EXECUTED','','firewall OFF');
          }} else {{
            const layer = l.layer;
            const act = l.action;
            const l2s = (typeof l.l2score === 'number') ? l.l2score : l.risk;

            // LAYER_1
            if (layer === 'LAYER_1') {{
              const ruleLabel = rule ? rule.id : 'pattern match';
              trace += tr('LAYER_1', 'BLOCKED', 'up', ruleLabel);
              trace += tr('LAYER_2','NOT EXECUTED','','stopped at L1');
              trace += tr('LAYER_3','NOT EXECUTED','','stopped at L1');
              trace += tr('OUTPUT_SCANNER','NOT EXECUTED','','stopped at L1');
            }} else if (layer === 'LAYER_2') {{
              trace += tr('LAYER_1','CLEAR','down','no pattern match');
              trace += tr('LAYER_2','BLOCKED','up', 'score ' + l2s.toFixed(4));
              trace += tr('LAYER_3','NOT EXECUTED','','stopped at L2');
              trace += tr('OUTPUT_SCANNER','NOT EXECUTED','','stopped at L2');
            }} else if (layer === 'LAYER_3') {{
              const l3dec = (l.l3decision || '').toUpperCase();
              const l3rat = l.l3rationale || '';
              const l3cls = l3dec === 'BLOCK' ? 'up' : (l3dec === 'REDACT' ? 'up' : 'down');
              trace += tr('LAYER_1','CLEAR','down','no pattern match');
              trace += tr('LAYER_2','ESCALATED','','score ' + l2s.toFixed(4) + ' — in uncertainty band');
              trace += tr('LAYER_3', l3dec || act, l3cls, l3rat);
              if (l3dec !== 'BLOCK') {{
                const oCats = (l.outputcats || []).join(', ');
                if (act === 'REDACTED') {{
                  trace += tr('OUTPUT_SCANNER','REDACTED','up', oCats || 'sensitive data detected');
                }} else {{
                  trace += tr('OUTPUT_SCANNER','CLEAN','down','no sensitive data');
                }}
              }} else {{
                trace += tr('OUTPUT_SCANNER','NOT EXECUTED','','stopped at L3');
              }}
            }} else if (layer === 'OUTPUT_SCANNER') {{
              trace += tr('LAYER_1','CLEAR','down','no pattern match');
              trace += tr('LAYER_2', l2s <= 0.35 ? 'PASS' : 'ESCALATED', l2s > 0.35 ? '' : 'down', 'score ' + l2s.toFixed(4));
              if (l2s > 0.35 && l2s < 0.85) {{
                const l3dec = (l.l3decision || 'ALLOW').toUpperCase();
                trace += tr('LAYER_3', l3dec, l3dec === 'ALLOW' ? 'down' : 'up', l.l3rationale || '');
              }} else {{
                trace += tr('LAYER_3','SKIPPED','','score outside escalation band');
              }}
              const oCats = (l.outputcats || []).join(', ');
              if (act === 'BLOCKED') {{
                trace += tr('OUTPUT_SCANNER','BLOCKED','up', oCats || 'secret/PII detected');
              }} else if (act === 'REDACTED') {{
                trace += tr('OUTPUT_SCANNER','REDACTED','up', oCats || 'secret/PII detected');
              }}
            }} else {{
              // NONE — clean pass through all layers
              trace += tr('LAYER_1','CLEAR','down','no pattern match');
              trace += tr('LAYER_2', l2s <= 0.35 ? 'PASS' : (l2s >= 0.85 ? 'PASS' : 'PASS'), 'down', 'score ' + l2s.toFixed(4));
              trace += tr('LAYER_3','SKIPPED','','score outside escalation band');
              const oCats = (l.outputcats || []).join(', ');
              if (act === 'REDACTED') {{
                trace += tr('OUTPUT_SCANNER','REDACTED','up', oCats || 'sensitive data detected');
              }} else {{
                trace += tr('OUTPUT_SCANNER','CLEAN','down','no sensitive data');
              }}
            }}
          }}

          if (dTitle) {{
            const titles = {{'BLOCKED':'Blocked request','REDACTED':'Redacted response','BYPASSED':'Bypassed — no inspection','PASSED':'Passed request'}};
            dTitle.textContent = titles[l.action] || 'Passed request';
          }}

          const directionPill = l.bypassed
            ? `<span style="font-size:11px;background:rgba(255,180,0,.12);color:#FFB400;border:1px solid rgba(255,180,0,.35);border-radius:4px;padding:2px 7px;margin-left:8px;">BYPASSED — no inspection</span>`
            : `<span style="font-size:11px;background:rgba(100,100,120,.18);color:var(--muted);border:1px solid var(--line);border-radius:4px;padding:2px 7px;margin-left:8px;">${{esc(l.direction)}} inspection</span>`;

          dBody.innerHTML = `
            <div style="margin-top:14px;display:flex;align-items:center;gap:0;">${{badge(l.action)}}${{directionPill}}</div>
            <dl class="kv">
              <dt>Request ID</dt><dd class="mono">${{esc(l.id)}}</dd>
              <dt>Created (UTC)</dt><dd class="mono">${{esc(l.t)}}</dd>
              <dt>Client IP</dt><dd class="mono">${{esc(l.ip)}}</dd>
              <dt>Application</dt><dd>${{esc(l.app)}}</dd>
              <dt>Target model</dt><dd class="mono">${{esc(l.model)}}</dd>
              <dt>Risk score</dt><dd>${{riskBar(l.risk)}}</dd>
              <dt>Inspection time</dt><dd class="mono">${{l.ms.toFixed(1)}} ms</dd>
            </dl>
            <h3 style="margin-top:22px;font-size:13px">Prompt (raw)</h3>
            <div class="prompt-box mono" style="white-space:pre-wrap;word-break:break-word;">${{esc(l.prompt)}}</div>
            <h3 style="margin-top:22px;font-size:13px">Layer trace</h3>
            <div class="layer-trace">${{trace}}</div>
            ${{rule ? `<h3 style="margin-top:22px;font-size:13px">Matched rule</h3><div class="prompt-box mono" style="color:var(--ivory);white-space:pre-wrap;word-break:break-all;">${{esc(rule.id)}}  ·  ${{esc(rule.cat)}}  ·  ${{esc(rule.sev)}}<br>${{esc(rule.pat)}}</div>` : ''}}
          `;

          d.classList.add('open');
          s.classList.add('open');
          d.focus();
        }};

        pwin.shebaToggleFullscreenTable = function() {{
          const wrap = pdoc.querySelector('.table-wrap');
          const btn = pdoc.getElementById('btnFullscreenTable');
          if (!wrap) return;
          const isFull = wrap.classList.toggle('fullscreen');
          if (btn) {{
            const textSpan = btn.querySelector('span');
            if (textSpan) textSpan.textContent = isFull ? 'Exit fullscreen' : 'Fullscreen';
          }}
        }};

        if (!pwin.__SHEBA_EVENTS_ATTACHED__) {{
          pwin.__SHEBA_EVENTS_ATTACHED__ = true;
          pdoc.addEventListener('click', function(e) {{
            const tr = e.target.closest('tr[data-id]');
            if (tr && tr.dataset && tr.dataset.id) {{
              pwin.shebaOpenDrawer(tr.dataset.id);
              return;
            }}
            if (e.target.closest('#dClose') || e.target.closest('#scrim')) {{
              pwin.shebaCloseDrawer();
              return;
            }}
            if (e.target.closest('#btnFullscreenTable')) {{
              pwin.shebaToggleFullscreenTable();
              return;
            }}
            const bClose = e.target.closest && (e.target.closest('#closeSensitiveBannerBtn') || e.target.closest('.banner-close'));
            if (bClose) {{
              e.preventDefault();
              e.stopPropagation();
              const b = pdoc.getElementById('sensitiveBanner') || bClose.closest('.banner');
              if (b) {{
                b.style.display = 'none';
                const c = b.closest('[data-testid="stElementContainer"]');
                if (c) c.style.display = 'none';
              }}
              try {{
                if (pwin.sessionStorage) pwin.sessionStorage.setItem('sheba_hide_banner', '1');
                if (window.sessionStorage) window.sessionStorage.setItem('sheba_hide_banner', '1');
              }} catch (err) {{}}
              return;
            }}
          }});
          pdoc.addEventListener('keydown', function(e) {{
            if (e.key === 'Escape') {{
              pwin.shebaCloseDrawer();
              const wrap = pdoc.querySelector('.table-wrap.fullscreen');
              if (wrap) pwin.shebaToggleFullscreenTable();
            }}
            const tr = e.target.closest && e.target.closest('tr[data-id]');
            if (tr && e.key === 'Enter') {{
              pwin.shebaOpenDrawer(tr.dataset.id);
            }}
          }});
        }}
      }} catch (err) {{
        console.error('Sheba table controller error:', err);
      }}
    }})();
    </script>
    """

    components.html(controller_js, height=0)
    return None

def render_detail_modal(detail: dict) -> None:
    from src.dashboard.components.drawer import open_evidence_modal
    open_evidence_modal(detail)
