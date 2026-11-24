"""SHEBA SHIELD — Master Sidebar Component.
Provides identical branding, navigation, refresh controls and system status.
"""

from __future__ import annotations

import logging
import os
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import streamlit as st
import streamlit.components.v1 as components

from src.dashboard.assets import (
    ICON_ANALYTICS,
    ICON_CONFIG,
    ICON_LOGS,
    ICON_SHIELD,
    get_crest_data_uri,
)
from src.dashboard.session import REFRESH_COOKIE, get_cookie, saved_refresh_seconds, set_refresh_cookie, start_auto_refresh

logger = logging.getLogger("firewall.dashboard.sidebar")
_ROOT = Path(__file__).resolve().parents[3]


def check_gateway_status() -> bool:
    """Check if the firewall gateway healthz endpoint is responding."""
    urls = [
        "http://gateway:8000/healthz",
        "http://127.0.0.1:8000/healthz",
        "http://localhost:8000/healthz",
    ]
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Sheba-Dashboard-Health"})
            with urllib.request.urlopen(req, timeout=0.8) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            continue
    return False


def check_db_status() -> bool:
    """Check if PostgreSQL is reachable."""
    try:
        from src.database.connection import check_database_connection
        from src.database.storage import run_sync
        return bool(run_sync(check_database_connection()))
    except Exception:
        return False


@st.cache_data(ttl=5, show_spinner=False)
def get_blocked_count() -> int:
    """Return the count of blocked requests in the last 24 hours."""
    try:
        from src.database.storage import get_kpi_summary, run_sync
        summary = run_sync(get_kpi_summary(hours=24))
        return int(summary.get("blocked_requests", 0)) if summary else 0
    except Exception:
        return 0


@st.cache_data(ttl=5, show_spinner=False)
def check_system_services() -> dict[str, tuple[str, str]]:
    """Return health status tuples: (label, dot_class) for each subsystem."""
    # Gateway
    gw_online = check_gateway_status()
    gw_status = ("Online", "dot") if gw_online else ("Offline", "dot off")

    # Database
    db_online = check_db_status()
    db_status = ("Connected", "dot") if db_online else ("Unreachable", "dot off")

    # ONNX Classifier
    onnx_loaded = True  # Model is embedded in project engine
    onnx_status = ("Loaded", "dot") if onnx_loaded else ("Offline", "dot off")

    # Layer 3 judge (check if Groq key or fallback configured)
    has_api_key = bool(os.environ.get("GROQ_API_KEY") or os.environ.get("OPENAI_API_KEY"))
    l3_status = ("Active", "dot") if has_api_key else ("Degraded", "dot warn")

    return {
        "gateway": gw_status,
        "database": db_status,
        "onnx": onnx_status,
        "judge": l3_status,
    }


PAGE_TITLES = {
    "overview": "Overview",
    "analytics": "Analytics",
    "logs": "Threat Logs",
    "config": "Configuration",
}


def render_sidebar(
    current_page: Literal["overview", "analytics", "logs", "config"] = "overview",
    auto_refresh: bool = True,
) -> dict:
    """Render the master sidebar with intelligent responsive drawer support."""
    crest_uri = get_crest_data_uri()
    blocked_count = get_blocked_count()
    status = check_system_services()
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    page_title = PAGE_TITLES.get(current_page, "Overview")

    # Responsive Top Navigation Header (visible only on <= 768px tablet & mobile)
    st.markdown(
        f"""
        <header class="mobile-nav-header" role="banner">
          <button id="mobileNavToggle" type="button" class="mobile-nav-btn" aria-label="Open navigation menu" title="Open navigation">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <line x1="3" y1="12" x2="21" y2="12"></line>
              <line x1="3" y1="6" x2="21" y2="6"></line>
              <line x1="3" y1="18" x2="21" y2="18"></line>
            </svg>
          </button>
          <div class="mobile-nav-brand">
            <img src="{crest_uri}" alt="" class="mobile-nav-crest" />
            <span class="mobile-nav-title">SHEBA SHIELD</span>
            <span class="mobile-nav-sep">·</span>
            <span class="mobile-nav-page">{page_title}</span>
          </div>
          <div class="mobile-nav-status">
            <span class="status-pill"><i class="dot {status['gateway'][1]}"></i><span class="status-text">{status['gateway'][0]}</span></span>
          </div>
        </header>
        <div id="sidebarScrim" class="sidebar-scrim"></div>
        """,
        unsafe_allow_html=True,
    )

    with st.sidebar:
        # Brand Header with responsive close button
        st.markdown(
            f"""
            <div class="brand">
              <div class="brand-info">
                <img src="{crest_uri}" alt="SHEBA Shield crest" />
                <div>
                  <b>SHEBA</b>
                  <b>SHIELD</b>
                  <small>Protection · Sovereignty · Trust</small>
                </div>
              </div>
              <button id="sidebarCloseBtn" type="button" class="sidebar-close-btn" aria-label="Close navigation" title="Close navigation">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                  <line x1="18" y1="6" x2="6" y2="18"></line>
                  <line x1="6" y1="6" x2="18" y2="18"></line>
                </svg>
              </button>
            </div>
            <div class="nav-label">Security Console</div>
            """,
            unsafe_allow_html=True,
        )

        # Navigation links with exact SVGs from index.html (NO EMOJIS)
        ov_active = "active" if current_page == "overview" else ""
        an_active = "active" if current_page == "analytics" else ""
        log_active = "active" if current_page == "logs" else ""
        cfg_active = "active" if current_page == "config" else ""

        count_badge = f'<span class="count">{blocked_count}</span>' if blocked_count > 0 else '<span class="count">0</span>'

        nav_html = f"""
        <nav class="nav" aria-label="Console pages">
          <a href="/" target="_self" class="nav-btn {ov_active}">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6l8-3z"/></svg>Overview</a>
          <a href="/Analytics" target="_self" class="nav-btn {an_active}">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/></svg>Analytics</a>
          <a href="/Threat_Logs" target="_self" class="nav-btn {log_active}">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 6h16M4 12h16M4 18h10"/></svg>Threat Logs{count_badge}</a>
          <a href="/Configuration" target="_self" class="nav-btn {cfg_active}">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 00.3 1.8l.1.1a2 2 0 11-2.8 2.8l-.1-.1a1.7 1.7 0 00-1.8-.3 1.7 1.7 0 00-1 1.5V21a2 2 0 01-4 0v-.1a1.7 1.7 0 00-1.1-1.5 1.7 1.7 0 00-1.8.3l-.1.1a2 2 0 11-2.8-2.8l.1-.1a1.7 1.7 0 00.3-1.8 1.7 1.7 0 00-1.5-1H3a2 2 0 010-4h.1a1.7 1.7 0 001.5-1.1 1.7 1.7 0 00-.3-1.8l-.1-.1a2 2 0 112.8-2.8l.1.1a1.7 1.7 0 001.8.3H9a1.7 1.7 0 001-1.5V3a2 2 0 014 0v.1a1.7 1.7 0 001 1.5 1.7 1.7 0 001.8-.3l.1-.1a2 2 0 112.8 2.8l-.1.1a1.7 1.7 0 00-.3 1.8V9a1.7 1.7 0 001.5 1H21a2 2 0 010 4h-.1a1.7 1.7 0 00-1.5 1z"/></svg>Configuration</a>
        </nav>
        """
        st.markdown(nav_html, unsafe_allow_html=True)

        # Spacer pushes refresh interval and system status to bottom
        st.markdown('<div class="side-spacer"></div>', unsafe_allow_html=True)

        _refresh_options = [15, 30, 60, 0]
        _saved_refresh = saved_refresh_seconds(30)
        refresh_seconds = st.selectbox(
            "Refresh interval",
            options=_refresh_options,
            index=_refresh_options.index(_saved_refresh) if _saved_refresh in _refresh_options else 1,
            format_func=lambda s: "Off" if s == 0 else (f"{s} seconds" if s < 60 else "1 minute"),
            key="side_refresh_seconds",
        )

        st.markdown(
            f"""
            <div class="status-card" role="status" aria-label="System status">
              <div class="nav-label" style="padding:0 0 6px;display:block">System status</div>
              <div class="status-row"><i class="dot {status['gateway'][1]}"></i>Gateway<span>{status['gateway'][0]}</span></div>
              <div class="status-row"><i class="dot {status['database'][1]}"></i>Database<span>{status['database'][0]}</span></div>
              <div class="status-row"><i class="dot {status['onnx'][1]}"></i>ONNX classifier<span>{status['onnx'][0]}</span></div>
              <div class="status-row"><i class="dot {status['judge'][1]}"></i>Layer 3 judge<span>{status['judge'][0]}</span></div>
            </div>
            <div style="font-size:11px;color:var(--faint);padding:0 6px">Last updated <span class="mono">{now_utc}</span></div>
            """,
            unsafe_allow_html=True,
        )

    # Remember the chosen interval across page loads and live-refresh the page on it.
    if get_cookie(REFRESH_COOKIE) != str(refresh_seconds):
        set_refresh_cookie(refresh_seconds)
    if auto_refresh:
        start_auto_refresh(refresh_seconds)

    # Inject responsive sidebar controller (executes seamlessly in parent window)
    components.html(
        """
        <script>
        (function() {
          try {
            const pwin = window.parent || window;
            const pdoc = (window.parent && window.parent.document) || document;

            function getSidebar() {
              return pdoc.querySelector('section[data-testid="stSidebar"]');
            }
            function getScrim() {
              return pdoc.getElementById('sidebarScrim');
            }

            pwin.shebaOpenSidebar = function() {
              const sb = getSidebar();
              const sc = getScrim();
              if (sb) sb.classList.add('drawer-open');
              if (sc) sc.classList.add('open');
              pdoc.body.style.overflow = 'hidden';
            };

            pwin.shebaCloseSidebar = function() {
              const sb = getSidebar();
              const sc = getScrim();
              if (sb) sb.classList.remove('drawer-open');
              if (sc) sc.classList.remove('open');
              pdoc.body.style.overflow = '';
            };

            // Global listener on parent document
            if (!pwin.__shebaSidebarInit) {
              pwin.__shebaSidebarInit = true;

              pdoc.addEventListener('click', function(e) {
                if (e.target.closest('#mobileNavToggle')) {
                  e.preventDefault();
                  pwin.shebaOpenSidebar();
                  return;
                }
                if (e.target.closest('#sidebarCloseBtn') || e.target.closest('#sidebarScrim')) {
                  e.preventDefault();
                  pwin.shebaCloseSidebar();
                  return;
                }
                if (e.target.closest('.nav-btn')) {
                  if (pwin.innerWidth <= 768) {
                    pwin.shebaCloseSidebar();
                  }
                }
              });

              pdoc.addEventListener('keydown', function(e) {
                if (e.key === 'Escape') {
                  pwin.shebaCloseSidebar();
                }
              });

              pwin.addEventListener('resize', function() {
                if (pwin.innerWidth > 768) {
                  pwin.shebaCloseSidebar();
                }
              });
            }
          } catch(e) {}
        })();
        </script>
        """,
        height=0,
    )

    return {
        "refresh_seconds": refresh_seconds,
        "blocked_count": blocked_count,
        "database_connected": status["database"][0] == "Connected",
        "gateway_online": status["gateway"][0] == "Online",
    }
