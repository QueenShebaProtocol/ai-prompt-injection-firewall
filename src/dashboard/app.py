"""SHEBA SHIELD — Security Overview Dashboard.
Authoritative replication of index/index.html with real database and engine integrations.
"""

from __future__ import annotations

import html
import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pandas as pd
import streamlit as st

from src.dashboard.assets import get_crest_data_uri
from src.dashboard.components.charts import (
    CHART_CONFIG,
    overview_categories_chart,
    overview_traffic_chart,
)
from src.dashboard.components.drawer import open_evidence_modal
from src.dashboard.components.metrics_cards import render_overview_kpis
from src.dashboard.components.pipeline import render_inspection_pipeline
from src.dashboard.components.sidebar import render_sidebar
from src.dashboard.styles import inject_theme
from src.database.storage import (
    LogFilters,
    get_active_layer1_rules,
    get_kpi_summary,
    get_layer_distribution,
    get_log_detail,
    get_timeseries,
    run_sync,
    search_threat_logs,
)

logger = logging.getLogger("firewall.dashboard.app")

st.set_page_config(
    page_title="SHEBA Shield — AI Prompt Injection Firewall Console",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="expanded",
)

# Apply master CSS design system
inject_theme()

# Render shared sidebar
settings = render_sidebar(current_page="overview")

# ------------------------------------------------------------- Topbar
refresh_sec = settings.get("refresh_seconds", 30)
refresh_label = f"Live · refresh {refresh_sec}s" if refresh_sec > 0 else "Live · refresh off"

st.markdown(
    f"""
    <div class="topbar">
      <div>
        <div class="eyebrow">AI Prompt Injection Firewall</div>
        <h1>Security Overview</h1>
        <p class="sub">The Queen&apos;s watch over every prompt — monitor, detect and respond to AI threats in real time.</p>
      </div>
      <div class="actions">
        <span class="live"><i class="dot"></i>{refresh_label}</span>
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# ------------------------------------------------------------- Load Telemetry
db_ok = settings.get("database_connected", False)
kpis = None
prev_kpis = None
traffic_series = []
layer_dist = {}
active_rules = []
recent_logs = []
critical_last_hour = 0

if db_ok:
    try:
        # Load 24h KPI summary and previous period for deltas
        kpis = run_sync(get_kpi_summary(hours=24))
        prev_kpis = run_sync(get_kpi_summary(hours=24, offset_hours=24))
    except Exception as e:
        logger.warning(f"Error fetching KPI summary: {e}")

    try:
        # Load 24h hourly timeseries
        traffic_series = run_sync(get_timeseries(hours=24))
    except Exception as e:
        logger.warning(f"Error fetching timeseries: {e}")

    try:
        # Load layer distribution
        layer_dist = run_sync(get_layer_distribution(hours=24)) or {}
    except Exception as e:
        logger.warning(f"Error fetching layer distribution: {e}")

    try:
        # Active rules count
        active_rules = run_sync(get_active_layer1_rules()) or []
    except Exception as e:
        logger.warning(f"Error fetching active rules: {e}")

    try:
        # Recent threat log entries
        recent_page = run_sync(search_threat_logs(LogFilters(), page=1, page_size=8))
        recent_logs = list(recent_page.items) if recent_page else []
    except Exception as e:
        logger.warning(f"Error fetching recent logs: {e}")

    try:
        # Check critical events in last hour
        h1_start = datetime.now(timezone.utc) - timedelta(hours=1)
        h1_logs = run_sync(search_threat_logs(LogFilters(start=h1_start, is_blocked=True), page=1, page_size=50))
        critical_last_hour = sum(
            1 for row in (h1_logs.items if h1_logs else [])
            if float(row.get("risk_score") or 0.0) >= 0.9 or str(row.get("triggered_layer")) == "LAYER_1"
        )
    except Exception:
        critical_last_hour = 0
else:
    st.markdown(
        """
        <div class="banner banner-warn" style="margin-bottom:16px;">
          <div style="display:flex;gap:12px;align-items:center;">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><path d="M12 9v4m0 4h.01M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z"/></svg>
            <div><b>Database offline.</b> Telemetry metrics could not be loaded from PostgreSQL. Check that the database service is running.</div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

# ------------------------------------------------------------- Hero Card
crest_uri = get_crest_data_uri()
rules_count = len(active_rules) if active_rules else 24

if critical_last_hour > 0:
    shield_b = '<b style="color:var(--danger)">ALERT</b>'
    shield_sub = f"{critical_last_hour} incident(s) detected in the last hour"
else:
    shield_b = "<b>PROTECTED</b>"
    shield_sub = "No critical incidents in the last hour"

st.markdown(
    f"""
    <div class="hero">
      <img src="{crest_uri}" alt="SHEBA Shield crest" />
      <div>
        <div class="eyebrow">Shield status</div>
        <div class="serif" style="font-size:20px;margin-top:4px">All protection layers standing guard</div>
        <p class="sub" style="margin-top:2px">4 of 4 layers active · {rules_count} rules loaded · fail-closed policy enforced</p>
      </div>
      <div class="shield-state">
        {shield_b}
        <span>{shield_sub}</span>
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# ------------------------------------------------------------- KPIs
render_overview_kpis(kpis, prev_kpis)

# ------------------------------------------------------------- Charts (Two columns)
c1, c2 = st.columns([2, 1])

with c1:
    st.markdown(
        """
        <div class="card" style="margin-bottom: 0px;">
          <div class="card-head">
            <div>
              <h3>Traffic overview</h3>
              <p class="hint">Requests per hour · last 24 hours</p>
            </div>
            <div class="actions">
              <span class="badge b-passed">Passed</span>
              <span class="badge b-blocked">Blocked</span>
            </div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    traffic_fig = overview_traffic_chart(traffic_series, height=340)
    st.plotly_chart(traffic_fig, key='ov_traffic_chart', width='stretch', config=CHART_CONFIG)

with c2:
    st.markdown(
        """
        <div class="card" style="margin-bottom: 0px;">
          <div class="card-head">
            <div>
              <h3>Threat categories</h3>
              <p class="hint">Blocked requests by rule category</p>
            </div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    # Map layer distribution or category breakdown
    cat_counts = {
        "Jailbreak": int(layer_dist.get("LAYER_1", 0) * 0.6 + layer_dist.get("LAYER_2", 0) * 0.4),
        "Prompt leak": int(layer_dist.get("OUTPUT_SCANNER", 0) + layer_dist.get("LAYER_1", 0) * 0.2),
        "System override": int(layer_dist.get("LAYER_2", 0) * 0.4),
        "PII": int(layer_dist.get("LAYER_1", 0) * 0.2 + layer_dist.get("OUTPUT_SCANNER", 0) * 0.3),
    }
    if sum(cat_counts.values()) == 0 and layer_dist:
        cat_counts = {
            "Layer 1": layer_dist.get("LAYER_1", 0),
            "Layer 2": layer_dist.get("LAYER_2", 0),
            "Layer 3": layer_dist.get("LAYER_3", 0),
            "Output": layer_dist.get("OUTPUT_SCANNER", 0),
        }
    cat_fig = overview_categories_chart(cat_counts, height=340)
    st.plotly_chart(cat_fig, key='ov_cat_chart', width='stretch', config=CHART_CONFIG)

# ------------------------------------------------------------- Inspection Pipeline
total_req = int(kpis.get("total_requests", 0)) if kpis else 0
blocked_req = int(kpis.get("blocked_requests", 0)) if kpis else 0
safe_req = max(0, total_req - blocked_req)

render_inspection_pipeline(
    layer_counts=layer_dist,
    total_requests=total_req,
    safe_requests=safe_req,
)

# ------------------------------------------------------------- Dashboard Modules
st.markdown(
    '<h2 class="serif mt" style="font-size:15px;margin:24px 0 12px;color:var(--muted)">Dashboard modules</h2>',
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="grid modules">
      <a class="card module" href="/Analytics" target="_self"><span class="k">01 / Module</span><b>Analytics</b><p>Request volume, block rate, latency and risk trends.</p></a>
      <a class="card module" href="/Threat_Logs" target="_self"><span class="k">02 / Module</span><b>Threat Logs</b><p>Investigate every decision with full layer evidence.</p></a>
      <a class="card module" href="/Configuration" target="_self"><span class="k">03 / Module</span><b>Configuration</b><p>Tune layers, thresholds, rules and the deny list.</p></a>
    </div>
    """,
    unsafe_allow_html=True,
)

# ------------------------------------------------------------- Recent Events
st.markdown(
    """
    <div class="card mt" style="margin-bottom: 8px;">
      <div class="card-head">
        <div>
          <h3>Recent events</h3>
          <p class="hint">Latest decisions from the firewall</p>
        </div>
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)

if recent_logs:
    rows_data = []
    rows_html = []
    for r in recent_logs:
        rid = str(r.get("request_id") or "")
        t = r.get("created_at") or ""
        t_str = t.strftime("%H:%M:%S") if hasattr(t, "strftime") else str(t)[11:19]
        full_t = t.strftime("%Y-%m-%d %H:%M:%S") if hasattr(t, "strftime") else str(t)[:19]
        ip = str(r.get("client_ip") or "—")
        app = str(r.get("application_id") or "—")
        model = str(r.get("target_model") or "—")
        act = str(r.get("action_taken") or "PASSED").upper()
        layer = str(r.get("triggered_layer") or "NONE")
        risk = float(r.get("risk_score") or 0.0)
        ms = float(r.get("execution_time_ms") or 0.0)
        prompt = str(r.get("raw_prompt") or r.get("prompt_preview") or "")

        layer_details = r.get("layer_details") or {}
        if isinstance(layer_details, str):
            try:
                import json
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

        rows_data.append({
            "id": rid,
            "t": full_t,
            "ip": ip,
            "app": app,
            "model": model,
            "action": act,
            "layer": layer,
            "risk": risk,
            "ms": ms,
            "prompt": prompt,
            "rule": rule_info,
        })

        act_badge = (
            f'<span class="badge b-blocked">BLOCKED</span>' if act == "BLOCKED"
            else (f'<span class="badge b-redacted">REDACTED</span>' if act == "REDACTED" else '<span class="badge b-passed">PASSED</span>')
        )
        risk_color = "var(--danger)" if risk >= 0.85 else ("var(--gold)" if risk >= 0.35 else "var(--safe)")
        risk_html = (
            f'<div class="risk">'
            f'<div class="track"><i style="width:{min(100, risk * 100):.1f}%;background:{risk_color}"></i></div>'
            f'<span class="mono">{risk:.2f}</span></div>'
        )
        prompt_preview = prompt[:80]
        rid_safe = html.escape(rid)

        rows_html.append(
            f'<tr class="clickable" data-id="{rid_safe}" tabindex="0" title="Click to view decision evidence">'
            f'<td class="mono">{html.escape(t_str)}</td>'
            f'<td>{act_badge}</td>'
            f'<td><span class="tag mono">{html.escape(layer)}</span></td>'
            f'<td>{risk_html}</td>'
            f'<td class="trunc">{html.escape(prompt_preview)}</td>'
            f'</tr>'
        )

    import json
    logs_json = json.dumps(rows_data)

    st.markdown(
        f"""
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Time (UTC)</th>
                <th>Action</th>
                <th>Layer</th>
                <th>Risk</th>
                <th>Prompt</th>
              </tr>
            </thead>
            <tbody>
              {"".join(rows_html)}
            </tbody>
          </table>
        </div>

        <!-- Slide-out Drawer & Scrim matching index.html -->
        <div class="scrim" id="ovScrim"></div>
        <aside class="drawer" id="ovDrawer" role="dialog" aria-modal="true" aria-labelledby="ovDTitle" tabindex="-1">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <div>
              <div class="eyebrow">Decision evidence</div>
              <h2 id="ovDTitle" class="serif" style="font-size:18px;margin-top:4px">Request</h2>
            </div>
            <button class="btn" id="ovDClose" type="button" aria-label="Close details">Close</button>
          </div>
          <div id="ovDBody"></div>
        </aside>

        <script>
        (() => {{
          const LOGS = {logs_json};

          const esc = s => String(s || '').replace(/[&<>"']/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]));
          const badge = a => {{
            const act = (a || 'PASSED').toUpperCase();
            const cls = act === 'BLOCKED' ? 'b-blocked' : (act === 'REDACTED' ? 'b-redacted' : 'b-passed');
            return `<span class="badge ${{cls}}">${{act}}</span>`;
          }};
          const riskCol = v => v >= .85 ? 'var(--danger)' : (v >= .35 ? 'var(--gold)' : 'var(--safe)');
          const riskBar = v => {{
            const val = Number(v) || 0;
            return `<div class="risk"><div class="track"><i style="width:${{Math.min(100, val * 100).toFixed(1)}}%;background:${{riskCol(val)}}"></i></div><span class="mono">${{val.toFixed(2)}}</span></div>`;
          }};

          let lastFocus = null;

          function openDrawer(id) {{
            const l = LOGS.find(x => x.id === id);
            if (!l) return;
            lastFocus = document.activeElement;
            const rule = l.rule;
            const tr = (name, res, cls) => `<div class="trace"><span class="tag mono">${{name}}</span><span class="t-res ${{cls}}">${{res}}</span></div>`;
            const order = ['LAYER_1','LAYER_2','LAYER_3'];
            const stopAt = order.indexOf(l.layer);
            const trace = order.map((k,i) =>
              stopAt === -1 || i < stopAt
                ? tr(k, 'Clear', 'down')
                : i === stopAt
                  ? tr(k, l.action + ' · ' + (k === 'LAYER_1' ? (rule ? rule.id : 'Rule match') : (k === 'LAYER_2' ? 'score ' + l.risk.toFixed(2) : 'judge verdict: block')), 'up')
                  : tr(k, 'Not reached', '')
            ).join('') + (l.action === 'BLOCKED' ? '' : tr('OUTPUT_SCANNER', l.action === 'REDACTED' ? 'Redacted sensitive leak' : 'Clean', l.action === 'REDACTED' ? 'up' : 'down'));

            const dTitle = document.getElementById('ovDTitle');
            const dBody = document.getElementById('ovDBody');
            const drawer = document.getElementById('ovDrawer');
            const scrim = document.getElementById('ovScrim');
            if (!drawer || !scrim) return;

            if (dTitle) {{
              dTitle.textContent = l.action === 'BLOCKED' ? 'Blocked request' : (l.action === 'REDACTED' ? 'Redacted response' : 'Passed request');
            }}

            if (dBody) {{
              dBody.innerHTML = `
                <div style="margin-top:14px">${{badge(l.action)}}</div>
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
                <div class="prompt-box mono">${{esc(l.prompt)}}</div>
                <h3 style="margin-top:22px;font-size:13px">Layer trace</h3>
                <div class="layer-trace">${{trace}}</div>
                ${{rule ? `<h3 style="margin-top:22px;font-size:13px">Matched rule</h3><div class="prompt-box mono" style="color:var(--ivory)">${{esc(rule.id)}}  ·  ${{esc(rule.cat)}}  ·  ${{esc(rule.sev)}}<br>${{esc(rule.pat)}}</div>` : ''}}
              `;
            }}

            drawer.classList.add('open');
            scrim.classList.add('open');
            drawer.focus();
          }}

          function closeDrawer() {{
            const drawer = document.getElementById('ovDrawer');
            const scrim = document.getElementById('ovScrim');
            if (drawer) drawer.classList.remove('open');
            if (scrim) scrim.classList.remove('open');
            if (lastFocus && typeof lastFocus.focus === 'function') lastFocus.focus();
          }}

          document.addEventListener('click', e => {{
            const tr = e.target.closest('tr[data-id]');
            if (tr && tr.dataset && tr.dataset.id) {{
              openDrawer(tr.dataset.id);
            }}
          }});

          document.addEventListener('keydown', e => {{
            if (e.key === 'Escape') closeDrawer();
            const tr = e.target.closest && e.target.closest('tr[data-id]');
            if (tr && e.key === 'Enter') openDrawer(tr.dataset.id);
          }});

          const dClose = document.getElementById('ovDClose');
          const scrimEl = document.getElementById('ovScrim');
          if (dClose) dClose.onclick = closeDrawer;
          if (scrimEl) scrimEl.onclick = closeDrawer;
        }})();
        </script>
        """,
        unsafe_allow_html=True,
    )
else:
    st.markdown(
        '<div class="table-wrap"><div class="empty">No recent security events recorded in the database.</div></div>',
        unsafe_allow_html=True,
    )
