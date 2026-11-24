"""SHEBA SHIELD — Threat Logs Page.
Master replication of index/index.html Forensics screen.
"""

from __future__ import annotations

import csv
import html
import io
import json
import logging
import math
import sys
from collections.abc import Mapping
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[3]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import streamlit as st
import streamlit.components.v1 as components

from src.dashboard.assets import ICON_EXPORT, ICON_WARNING
from src.dashboard.components.drawer import open_evidence_modal
from src.dashboard.components.log_table import (
    get_active_filters,
    render_detail_modal,
    render_filters,
    render_log_table,
)
from src.dashboard.components.sidebar import render_sidebar
from src.dashboard.session import restore_admin_session, sync_session_cookie
from src.dashboard.styles import inject_theme
from src.database.storage import (
    LogFilters,
    delete_threat_log,
    export_threat_logs,
    get_log_detail,
    run_sync,
    search_threat_logs,
)

logger = logging.getLogger("firewall.dashboard.threat_logs")

# ---------------------------------------------------------------------- Settings
FIRST_PAGE = 1
PAGE_SIZE_OPTIONS = (10, 15, 25, 50)
DEFAULT_PAGE_SIZE = 15
MAX_PAGE_SIZE = max(PAGE_SIZE_OPTIONS)
EXPORT_MAX_ROWS = 10_000

K_FILTERS = "logs_filters"
K_SIGNATURE = "logs_filters_signature"
K_PAGE = "logs_page"
K_PAGE_SIZE = "logs_page_size"
K_SHOWN = "logs_modal_shown"
K_EXPORT = "logs_export"

DB_ERROR_MESSAGE = (
    "The log database could not be reached. Check that the database is "
    "running, then press Retry. Your filters and page position are kept."
)

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def neutralize_formula(value: Any) -> Any:
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def _csv_cell(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple)):
        value = json.dumps(value, ensure_ascii=False, default=str)
    elif isinstance(value, (datetime, date)):
        value = value.isoformat()
    elif not isinstance(value, (str, int, float, bool)):
        value = str(value)
    return neutralize_formula(value)


def _columns(rows: list[Mapping[str, Any]]) -> list[str]:
    seen: dict[str, None] = {}
    for row in rows:
        for key in row:
            seen.setdefault(key, None)
    return list(seen)


def rows_to_csv(rows: list[Mapping[str, Any]]) -> bytes:
    buffer = io.StringIO()
    cols = _columns(rows)
    writer = csv.writer(buffer)
    writer.writerow([neutralize_formula(c) for c in cols])
    for row in rows:
        writer.writerow([_csv_cell(row.get(c)) for c in cols])
    return buffer.getvalue().encode("utf-8-sig")


def page_total(page: Any) -> int:
    try:
        return max(0, int(getattr(page, "total", 0)))
    except Exception:
        return 0


def total_pages(total: int, page_size: int) -> int:
    return max(1, math.ceil(total / max(1, page_size)))


# ---------------------------------------------------------------------- Session
def _init_state() -> None:
    st.session_state.setdefault(K_PAGE, FIRST_PAGE)
    st.session_state.setdefault(K_PAGE_SIZE, DEFAULT_PAGE_SIZE)
    st.session_state.setdefault(K_SHOWN, None)


def _step_page(delta: int) -> None:
    st.session_state[K_PAGE] = max(FIRST_PAGE, int(st.session_state[K_PAGE]) + delta)


def _safe_page_size() -> int:
    try:
        size = int(st.session_state.get(K_PAGE_SIZE, DEFAULT_PAGE_SIZE))
    except (TypeError, ValueError):
        size = DEFAULT_PAGE_SIZE
    return min(max(1, size), MAX_PAGE_SIZE)


# ---------------------------------------------------------------------- Delete a log entry
def _clear_delete_param() -> None:
    try:
        del st.query_params["delete_log"]
    except Exception:
        pass


def _handle_delete_request(admin_user: str) -> None:
    """Confirm and carry out a delete started by the trash icon (``?delete_log=<request id>``).

    Nothing is deleted by the link itself: the administrator must press the
    confirmation button, and the signed-in check is repeated here on the server.
    """
    flash = st.session_state.pop("_log_delete_flash", None)
    if flash:
        getattr(st, flash[0])(flash[1])

    raw = st.query_params.get("delete_log")
    target = str(raw)[:128].strip() if raw else ""
    if not target:
        return
    if not admin_user:
        _clear_delete_param()
        st.warning("Only a signed-in administrator can delete log entries. Sign in on the Configuration page, then try again.")
        return

    try:
        detail = run_sync(get_log_detail(target))
    except Exception:
        logger.error("Could not load log entry for deletion", exc_info=True)
        _clear_delete_param()
        st.error(DB_ERROR_MESSAGE)
        return
    if detail is None:
        _clear_delete_param()
        st.info("That log entry no longer exists.")
        return

    when = detail.get("created_at")
    when_txt = when.strftime("%Y-%m-%d %H:%M:%S UTC") if hasattr(when, "strftime") else str(when)
    with st.container(border=True):
        st.markdown(
            f"**Delete this log entry permanently?**  \n"
            f"`{html.escape(target)}` · {html.escape(str(detail.get('client_ip', '')))} · "
            f"{html.escape(str(detail.get('action_taken', '')))} · {html.escape(when_txt)}"
        )
        st.code(str(detail.get("raw_prompt") or "")[:300], language=None)
        st.caption(
            "The prompt, system instruction and model output are removed from the database and cannot be recovered. "
            "The deletion is recorded in the audit log. Dashboard totals for the period will drop by one request."
        )
        c_ok, c_cancel = st.columns(2)
        with c_ok:
            confirmed = st.button("Delete permanently", type="primary", key="btn_confirm_delete_log", width="stretch")
        with c_cancel:
            cancelled = st.button("Cancel", key="btn_cancel_delete_log", width="stretch")
    if confirmed:
        try:
            removed = run_sync(delete_threat_log(target, admin_user))
            st.session_state["_log_delete_flash"] = (
                ("success", "Log entry deleted.") if removed else ("info", "That log entry no longer exists.")
            )
        except Exception:
            logger.error("Deleting log entry failed", exc_info=True)
            st.session_state["_log_delete_flash"] = ("error", "Could not delete the log entry. Check the database connection.")
        _clear_delete_param()
        st.rerun()
    if cancelled:
        _clear_delete_param()
        st.rerun()


# ---------------------------------------------------------------------- Page Runner
def main() -> None:
    st.set_page_config(
        page_title="SHEBA Shield — Threat Logs",
        page_icon=None,
        layout="wide",
        initial_sidebar_state="expanded",
    )

    inject_theme()
    render_sidebar(current_page="logs")
    _init_state()

    # Topbar
    col_h, col_act = st.columns([3, 1])
    with col_h:
        st.markdown(
            """
            <div class="topbar" style="margin-bottom:0px;">
              <div>
                <div class="eyebrow">Forensics</div>
                <h1>Threat Logs</h1>
                <p class="sub">Every decision the firewall made, with the evidence behind it.</p>
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col_act:
        st.markdown('<div style="height:14px;"></div>', unsafe_allow_html=True)
        active_filters = get_active_filters()

        def _generate_csv() -> bytes:
            try:
                export_rows = run_sync(export_threat_logs(active_filters, EXPORT_MAX_ROWS))
                return rows_to_csv(list(export_rows or []))
            except Exception as exc:
                logger.warning(f"Error generating CSV export: {exc}")
                return b""

        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        st.download_button(
            label="Export CSV",
            data=_generate_csv,
            file_name=f"sheba-shield-threat-logs_{stamp}.csv",
            mime="text/csv",
            key="btn_quick_export",
            width='stretch',
        )

    # Sensitive Banner (dismissible with small "x" icon)
    st.markdown(
        f"""
        <div id="sensitiveBanner" class="banner" role="note" style="margin-top:14px;">
          <div style="display:flex; gap:12px; align-items:flex-start; flex:1;">
            {ICON_WARNING}
            <div><b>Sensitive data.</b> This page shows raw prompts exactly as received. They can contain personal data, credentials or confidential text. Open only what you need and do not share screenshots or exports with unauthorised people.</div>
          </div>
          <button id="closeSensitiveBannerBtn" type="button" class="banner-close" aria-label="Dismiss message" title="Dismiss">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
              <line x1="18" y1="6" x2="6" y2="18"></line>
              <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg>
          </button>
        </div>
        """,
        unsafe_allow_html=True,
    )
    components.html(
        """
        <script>
        (function() {
          try {
            const pwin = window.parent || window;
            const pdoc = (window.parent && window.parent.document) || document;

            function hideBanner() {
              const b = pdoc.getElementById('sensitiveBanner');
              if (b) {
                b.style.display = 'none';
                const c = b.closest('[data-testid="stElementContainer"]');
                if (c) c.style.display = 'none';
              }
            }

            if (pwin.sessionStorage && pwin.sessionStorage.getItem('sheba_hide_banner') === '1') {
              hideBanner();
            }

            pdoc.addEventListener('click', function(e) {
              const btn = e.target.closest && (e.target.closest('#closeSensitiveBannerBtn') || e.target.closest('.banner-close'));
              if (btn) {
                e.preventDefault();
                e.stopPropagation();
                hideBanner();
                try {
                  if (pwin.sessionStorage) pwin.sessionStorage.setItem('sheba_hide_banner', '1');
                  if (window.sessionStorage) window.sessionStorage.setItem('sheba_hide_banner', '1');
                } catch(err) {}
              }
            });
          } catch(e) {}
        })();
        </script>
        """,
        height=0,
    )

    admin_user = restore_admin_session()
    sync_session_cookie(bool(admin_user))
    _handle_delete_request(admin_user)

    # Filters & Query
    filters = render_filters(
        defaults=st.session_state.get(K_FILTERS),
        matching_count=st.session_state.get("logs_last_total"),
    )

    sig = repr(filters)
    if sig != st.session_state.get(K_SIGNATURE):
        st.session_state[K_SIGNATURE] = sig
        st.session_state[K_PAGE] = FIRST_PAGE
        st.session_state.pop(K_EXPORT, None)
    st.session_state[K_FILTERS] = filters

    page_size = _safe_page_size()
    page_no = max(FIRST_PAGE, int(st.session_state[K_PAGE]))

    page = None
    try:
        page = run_sync(search_threat_logs(filters, page_no, page_size))
    except Exception as exc:
        logger.error("Failed to query threat logs", exc_info=True)
        st.error(DB_ERROR_MESSAGE)
        st.stop()

    total = page_total(page)
    st.session_state["logs_last_total"] = total
    last_page = total_pages(total, page_size)
    if page_no > last_page and last_page >= FIRST_PAGE:
        st.session_state[K_PAGE] = last_page
        page = run_sync(search_threat_logs(filters, last_page, page_size))
        total = page_total(page)
        st.session_state["logs_last_total"] = total

    # Render Table
    selected_id = render_log_table(page, can_delete=bool(admin_user))

    # Pager bar matching index.html
    first_row = 0 if total == 0 else (st.session_state[K_PAGE] - FIRST_PAGE) * page_size + 1
    last_row = min(total, st.session_state[K_PAGE] * page_size) if total else 0

    p_c1, p_c2, p_c3 = st.columns([1, 2.5, 1.5])
    with p_c1:
        st.button(
            "Previous",
            key="btn_pg_prev",
            disabled=st.session_state[K_PAGE] <= FIRST_PAGE,
            on_click=_step_page,
            args=(-1,),
            width='stretch',
        )
    with p_c2:
        st.markdown(
            f'<div style="text-align:center;padding-top:8px;color:var(--muted);font-size:12.5px;">'
            f'Page {st.session_state[K_PAGE]} of {last_page} · rows {first_row}–{last_row} of {total}'
            f'</div>',
            unsafe_allow_html=True,
        )
    with p_c3:
        ps_c1, ps_c2 = st.columns([1.2, 1])
        with ps_c1:
            st.selectbox(
                "Rows",
                PAGE_SIZE_OPTIONS,
                index=PAGE_SIZE_OPTIONS.index(page_size) if page_size in PAGE_SIZE_OPTIONS else 1,
                key=K_PAGE_SIZE,
                label_visibility="collapsed",
            )
        with ps_c2:
            st.button(
                "Next",
                key="btn_pg_next",
                disabled=st.session_state[K_PAGE] >= last_page,
                on_click=_step_page,
                args=(1,),
                width='stretch',
            )

    # Hold the live refresh while an evidence dialog is open so it is not closed under the reader.
    st.session_state["_pause_refresh"] = bool(selected_id)

    # Handle Evidence Drawer
    if selected_id:
        try:
            detail = run_sync(get_log_detail(selected_id))
            if detail:
                open_evidence_modal(detail)
        except Exception as exc:
            st.error(f"Could not load log detail: {exc}")



if __name__ == "__main__":
    main()
