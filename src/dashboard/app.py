"""Sheba Shield — AI Prompt Injection Firewall dashboard shell."""

import asyncio
import logging
from datetime import datetime
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[2]
st.set_page_config(
    page_title="Sheba Shield | Security Overview",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

NAVY = "#061225"
PANEL = "#091a30"
GOLD = "#e8b75b"
BLUE = "#3985ff"
GREEN = "#25d6a0"
RED = "#f05268"
MUTED = "#91a7c7"

st.markdown(
    f"""
    <style>
    .stApp {{
        background: {NAVY};
        color: #edf3ff;
    }}
    [data-testid="stSidebar"] {{
        background: #07172b;
        border-right: 1px solid #203b5d;
    }}
    [data-testid="stSidebar"] * {{
        color: #e7edfa;
    }}
    .brand {{
        padding: 8px 0 24px;
        border-bottom: 1px solid #263b56;
        margin-bottom: 20px;
    }}
    .brand-title {{
        color: {GOLD};
        font-family: Georgia, serif;
        font-size: 29px;
        letter-spacing: 2px;
        font-weight: bold;
    }}
    .brand-sub {{
        color: {MUTED};
        font-size: 10px;
        letter-spacing: 2px;
    }}
    .eyebrow {{
        color: {GOLD};
        font-size: 12px;
        letter-spacing: 2px;
        text-transform: uppercase;
    }}
    .subtitle {{
        color: {MUTED};
        font-size: 14px;
    }}
    .metric-card, .panel {{
        background: linear-gradient(145deg, #0b1c32, #071427);
        border: 1px solid #203c60;
        border-radius: 11px;
        padding: 16px;
        margin-bottom: 12px;
    }}
    .metric-label {{
        color: #b5c4dd;
        font-size: 13px;
    }}
    .metric-value {{
        color: #f3f6ff;
        font-size: 28px;
        font-weight: 700;
        padding-top: 6px;
    }}
    .metric-note {{
        color: {MUTED};
        font-size: 11px;
        margin-top: 5px;
    }}
    .panel-title {{
        color: #e9f0ff;
        font-size: 17px;
        font-weight: 600;
        margin-bottom: 10px;
    }}
    .status-dot {{
        color: {GREEN};
        font-size: 13px;
    }}
    div[data-testid="stMetric"] {{
        background: linear-gradient(145deg, #0b1c32, #071427);
        border: 1px solid #203c60;
        border-radius: 11px;
        padding: 15px;
    }}
    div[data-testid="stMetricLabel"] {{
        color: #b5c4dd;
    }}
    div[data-testid="stMetricValue"] {{
        color: #f3f6ff;
    }}
    .stButton > button {{
        border: 1px solid {GOLD};
        color: {GOLD};
        background: #102039;
        border-radius: 8px;
    }}
    hr {{
        border-color: #203c60;
    }}
    footer {{
        visibility: hidden;
    }}
    </style>
    """,
    unsafe_allow_html=True,
)


def database_is_available() -> bool:
    """Check PostgreSQL without allowing database errors to crash the UI."""
    try:
        import sys

        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))

        from src.database.connection import check_database_connection

        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return bool(asyncio.run(check_database_connection()))

        # Streamlit normally has no running event loop. If one exists,
        # avoid nested-loop errors and report an unknown/unreachable state.
        return False
    except Exception:
        logger.warning("Dashboard database health check failed.", exc_info=True)
        return False


def render_sidebar() -> dict:
    """Render shared dashboard controls and return their settings."""
    with st.sidebar:
        st.markdown(
            """
            <div class="brand">
                <div class="brand-title">♕ SHEBA<br>SHIELD</div>
                <div class="brand-sub">AI PROTECTION · SOVEREIGNTY · TRUST</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("### ◈ Security Console")
        st.caption("Navigate using the pages in this dashboard.")

        refresh_seconds = st.selectbox(
            "Refresh interval",
            options=[15, 30, 60, 120],
            index=1,
            format_func=lambda value: f"{value} seconds",
            key="refresh_seconds",
        )

        st.markdown("---")
        st.caption("LAST UPDATED")
        st.text(datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"))

        st.markdown("---")
        st.markdown("**SYSTEM STATUS**")

        db_ok = database_is_available()
        if db_ok:
            st.success("Database connected")
        else:
            st.warning("Database unreachable")

        st.caption("Sheba Shield · Dashboard Shell")
        st.caption("P1 · Initial dashboard")

    return {
        "refresh_seconds": refresh_seconds,
        "database_available": db_ok,
    }


settings = render_sidebar()

# Header
header_left, header_right = st.columns([3, 1])
with header_left:
    st.markdown('<div class="eyebrow">AI PROMPT INJECTION FIREWALL</div>',
                unsafe_allow_html=True)
    st.title("🛡️ Security Overview")
    st.markdown(
        '<div class="subtitle">Monitor, detect and respond to AI security threats.</div>',
        unsafe_allow_html=True,
    )
with header_right:
    st.markdown("")
    st.markdown(
        f'<div class="subtitle">REFRESH · {settings["refresh_seconds"]}s</div>',
        unsafe_allow_html=True,
    )

st.markdown("---")

# Empty-state metrics: don't present invented numbers as real telemetry.
st.markdown("### Security Metrics")
st.caption(
    "Live metrics will appear here when dashboard analytics are connected "
    "to stored firewall events."
)

metric_columns = st.columns(4)
metric_specs = [
    ("TOTAL REQUESTS", "—", "Awaiting telemetry", BLUE),
    ("SAFE PROMPTS", "—", "Awaiting telemetry", GREEN),
    ("BLOCKED THREATS", "—", "Awaiting telemetry", RED),
    ("THREAT RATE", "—", "Awaiting telemetry", GOLD),
]
for column, (label, value, note, accent) in zip(metric_columns, metric_specs):
    with column:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-label">{label}</div>
                <div class="metric-value" style="color:{accent}">{value}</div>
                <div class="metric-note">{note}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

left, right = st.columns([2.2, 1])

with left:
    st.markdown(
        '<div class="panel-title">↗ Traffic Overview</div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="subtitle">Request trends will be shown after telemetry integration.</div>',
        unsafe_allow_html=True,
    )

    # Empty chart: deliberately no fabricated traffic values.
    chart = go.Figure()
    chart.update_layout(
        height=260,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=10, r=10, t=15, b=10),
        xaxis=dict(visible=False),
        yaxis=dict(visible=False),
        annotations=[
            dict(
                text="Traffic data will appear here",
                x=0.5, y=0.5, xref="paper", yref="paper",
                showarrow=False,
                font=dict(color=MUTED, size=15),
            )
        ],
    )
    st.plotly_chart(chart, width="stretch")

with right:
    st.markdown(
        '<div class="panel-title">◉ System Status</div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        f'<div class="subtitle">● Dashboard UI — <span style="color:{GREEN}">Online</span></div>',
        unsafe_allow_html=True,
    )
    db_label = "Connected" if settings["database_available"] else "Unreachable"
    db_color = GREEN if settings["database_available"] else RED
    st.markdown(
        f'<div class="subtitle">● Database — <span style="color:{db_color}">{db_label}</span></div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="subtitle">○ Firewall metrics — Pending integration</div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="subtitle">○ Model evaluator — Pending integration</div>',
        unsafe_allow_html=True,
    )

st.markdown("---")
st.markdown("### Dashboard Modules")

module_columns = st.columns(3)
modules = [
    ("01", "Analytics", "Request volume, safe prompts, blocked threats and trends."),
    ("02", "Threat Logs", "Review detected threats and investigation evidence."),
    ("03", "Configuration", "Review firewall settings and protection controls."),
]
for column, (number, title, description) in zip(module_columns, modules):
    with column:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="eyebrow">{number} / MODULE</div>
                <div class="panel-title">{title}</div>
                <div class="subtitle">{description}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

st.markdown("---")
st.markdown("### Recent Events")
st.caption(
    "No event records are displayed until the threat-log data source is connected."
)
st.dataframe(
    pd.DataFrame(columns=["Time", "Event Type", "Risk Level", "Status", "Details"]),
    width="stretch",
    hide_index=True,
)

st.caption(
    "Sheba Shield · Security dashboard shell · "
    "Live analytics and event integration are planned follow-up work."
)
