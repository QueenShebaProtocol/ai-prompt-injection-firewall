"""SHEBA SHIELD — Inspection Pipeline Component.
Renders the 5-stage waterfall cascade visualizer matching index/index.html.
"""

from __future__ import annotations

from typing import Any

import streamlit as st


def render_inspection_pipeline(
    layer_counts: dict[str, int] | None = None,
    total_requests: int = 0,
    safe_requests: int = 0,
) -> None:
    """Render the 5-stage inspection pipeline waterfall."""
    counts = layer_counts or {}
    total = max(1, total_requests)

    l1_count = counts.get("LAYER_1", 0)
    l2_count = counts.get("LAYER_2", 0)
    l3_count = counts.get("LAYER_3", 0)
    os_count = counts.get("OUTPUT_SCANNER", 0)

    l1_pct = round((l1_count / total) * 100) if total_requests > 0 else 0
    l2_pct = round((l2_count / total) * 100) if total_requests > 0 else 0
    l3_pct = round((l3_count / total) * 100) if total_requests > 0 else 0
    os_pct = round((os_count / total) * 100) if total_requests > 0 else 0
    safe_pct = round((safe_requests / total) * 100) if total_requests > 0 else 0

    stages = [
        {"k": "Layer 1", "n": "Deterministic rules", "time": "0.4 ms", "share": f"{l1_pct}% decided", "w": max(2, min(100, l1_pct))},
        {"k": "Layer 2", "n": "ONNX classifier", "time": "24 ms", "share": f"{l2_pct}% decided", "w": max(2, min(100, l2_pct))},
        {"k": "Layer 3", "n": "LLM judge", "time": "1.2 s", "share": f"{l3_pct}% decided", "w": max(2, min(100, l3_pct))},
        {"k": "Output", "n": "Output scanner", "time": "3 ms", "share": f"{os_pct}% redacted", "w": max(2, min(100, os_pct))},
    ]

    stages_html = "".join([
        f'<div class="stage">'
        f'  <div class="k">{s["k"]}</div>'
        f'  <div class="n">{s["n"]}</div>'
        f'  <div class="m"><span class="mono">{s["time"]}</span><span>{s["share"]}</span></div>'
        f'  <div class="bar"><i style="width:{s["w"]}%;"></i></div>'
        f'</div>'
        for s in stages
    ])

    delivered_html = (
        f'<div class="stage end">'
        f'  <div class="k">Delivered</div>'
        f'  <div class="n">Safe response</div>'
        f'  <div class="m"><span>to your users</span><span>{safe_requests:,} today</span></div>'
        f'  <div class="bar"><i style="width:{max(2, min(100, safe_pct))}%;background:var(--safe)"></i></div>'
        f'</div>'
    )

    st.markdown(
        f"""
        <div class="card mt">
          <div class="card-head">
            <div>
              <h3>Inspection pipeline</h3>
              <p class="hint">Cascade stops at the first decision — share of traffic decided at each stage</p>
            </div>
          </div>
          <div class="pipeline">
            {stages_html}
            {delivered_html}
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
