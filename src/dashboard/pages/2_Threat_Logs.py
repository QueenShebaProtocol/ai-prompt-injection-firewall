"""Threat Logs page: search, filter, inspect and export the firewall's logs.

Flow (one Streamlit run):
    render_sidebar() -> render_filters() -> run_sync(search_threat_logs(...))
    -> render_log_table(page) -> if a row is selected:
       render_detail_modal(run_sync(get_log_detail(request_id)))

This page only renders. All queries live in src/database/storage.py and all
widgets live in src/dashboard/components/log_table.py.

SENSITIVE: the log rows contain raw prompts and model output. The page says
so at the top, and exports are built only when the user asks for them.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import math
import sys
from collections.abc import Mapping
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

# Streamlit runs this file with src/dashboard on sys.path, not the repo root.
_ROOT = Path(__file__).resolve().parents[3]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import streamlit as st  # noqa: E402

from src.dashboard.app import render_sidebar  # noqa: E402
from src.dashboard.components.log_table import (  # noqa: E402
    render_detail_modal,
    render_filters,
    render_log_table,
)
from src.database.storage import (  # noqa: E402
    export_threat_logs,
    get_log_detail,
    run_sync,
    search_threat_logs,
)

logger = logging.getLogger("firewall.dashboard.threat_logs")

# ----------------------------------------------------------------------
# Settings
# ----------------------------------------------------------------------
FIRST_PAGE = 1  # search_threat_logs(page=...) is 1-based; change here if P5's is 0-based
PAGE_SIZE_OPTIONS = (25, 50, 100)
DEFAULT_PAGE_SIZE = 25
MAX_PAGE_SIZE = max(PAGE_SIZE_OPTIONS)  # hard ceiling for the page size
EXPORT_MAX_ROWS = 10_000  # matches export_threat_logs' own default cap

# Session-state keys. Everything the page remembers lives under these.
K_FILTERS = "logs_filters"
K_SIGNATURE = "logs_filters_signature"
K_PAGE = "logs_page"
K_PAGE_SIZE = "logs_page_size"
K_SHOWN = "logs_modal_shown"
K_EXPORT = "logs_export"

SENSITIVE_NOTICE = (
    "**Sensitive data.** This page shows raw prompts and model output exactly "
    "as received. They can contain personal data, credentials or confidential "
    "business text. Open only what you need, and do not share screenshots or "
    "exports with anyone who is not authorised to see them."
)
DB_ERROR_MESSAGE = (
    "The log database could not be reached. Check that the database is "
    "running, then press Retry. Your filters and page position are kept."
)


# ----------------------------------------------------------------------
# Pure helpers (no Streamlit calls)
# ----------------------------------------------------------------------
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def neutralize_formula(value: Any) -> Any:
    """Stop spreadsheets from running a text cell as a formula.

    A string starting with = + - @ (or a tab / carriage return, which Excel
    also treats as a formula start) gets a leading apostrophe, so
    "=cmd|' /C calc'!A0" is shown as text. Non-strings are returned as is.
    """
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def _csv_cell(value: Any) -> Any:
    """Turn any value from a log row into a safe CSV cell."""
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
    """Column names in first-seen order across every row."""
    seen: dict[str, None] = {}
    for row in rows:
        for key in row:
            seen.setdefault(key, None)
    return list(seen)


def rows_to_csv(rows: list[Mapping[str, Any]]) -> bytes:
    """CSV bytes (UTF-8 with BOM, so Excel reads accents correctly).

    Every cell passes through neutralize_formula(), so a prompt such as
    "=cmd" is exported as the text "'=cmd".
    """
    buffer = io.StringIO()
    columns = _columns(rows)
    writer = csv.writer(buffer)
    writer.writerow([neutralize_formula(c) for c in columns])
    for row in rows:
        writer.writerow([_csv_cell(row.get(c)) for c in columns])
    return buffer.getvalue().encode("utf-8-sig")


def rows_to_json(rows: list[Mapping[str, Any]]) -> bytes:
    """JSON bytes. JSON is not opened by spreadsheets, so values stay unchanged."""
    return json.dumps(rows, indent=2, ensure_ascii=False, default=str).encode("utf-8")


def _field(obj: Any, *names: str, default: Any = None) -> Any:
    """Read the first available attribute / key from a dataclass or a dict."""
    for name in names:
        if isinstance(obj, Mapping):
            if name in obj:
                return obj[name]
        elif hasattr(obj, name):
            return getattr(obj, name)
    return default


def page_total(page: Any) -> int:
    """Total matching rows reported by search_threat_logs()."""
    try:
        return max(0, int(_field(page, "total", "total_count", "total_rows", default=0)))
    except (TypeError, ValueError):
        return 0


def page_row_count(page: Any) -> int:
    rows = _field(page, "items", "rows", "results", default=None) or []
    return len(rows)


def total_pages(total: int, page_size: int) -> int:
    return max(1, math.ceil(total / max(1, page_size)))


# ----------------------------------------------------------------------
# Session state
# ----------------------------------------------------------------------
def _init_state() -> None:
    st.session_state.setdefault(K_PAGE, FIRST_PAGE)
    st.session_state.setdefault(K_PAGE_SIZE, DEFAULT_PAGE_SIZE)
    st.session_state.setdefault(K_SHOWN, None)


def _first_page() -> None:
    st.session_state[K_PAGE] = FIRST_PAGE


def _step_page(delta: int) -> None:
    st.session_state[K_PAGE] = st.session_state[K_PAGE] + delta


def _safe_page_size() -> int:
    """The chosen page size, never above MAX_PAGE_SIZE."""
    try:
        size = int(st.session_state.get(K_PAGE_SIZE, DEFAULT_PAGE_SIZE))
    except (TypeError, ValueError):
        size = DEFAULT_PAGE_SIZE
    return min(max(1, size), MAX_PAGE_SIZE)


def _show_db_error(action: str) -> None:
    logger.error("Threat Logs page: %s failed", action, exc_info=True)
    st.error(DB_ERROR_MESSAGE)


# ----------------------------------------------------------------------
# Page sections
# ----------------------------------------------------------------------
def _sync_filters(filters: Any) -> None:
    """Remember the filters; a change sends the table back to page one."""
    signature = repr(filters)
    if signature != st.session_state.get(K_SIGNATURE):
        st.session_state[K_SIGNATURE] = signature
        _first_page()
        st.session_state.pop(K_EXPORT, None)  # an old export no longer matches
        st.session_state[K_SHOWN] = None
    st.session_state[K_FILTERS] = filters


def _load_page(filters: Any, page_size: int) -> Any:
    """Query one page. Returns None (after showing the error) if the database fails."""
    try:
        page_no = max(FIRST_PAGE, int(st.session_state[K_PAGE]))
        page = run_sync(search_threat_logs(filters, page_no, page_size))

        # Filters or page size shrank the result set: jump back to the last real page.
        last_page = total_pages(page_total(page), page_size)
        if page_no > last_page:
            st.session_state[K_PAGE] = last_page
            page = run_sync(search_threat_logs(filters, last_page, page_size))
        return page
    except Exception:  # noqa: BLE001 - the page must never show a traceback
        _show_db_error("search_threat_logs")
        return None


def _render_pagination(total: int, page_size: int) -> None:
    current = st.session_state[K_PAGE]
    last_page = total_pages(total, page_size)
    first_row = 0 if total == 0 else (current - FIRST_PAGE) * page_size + 1
    last_row = min(total, current * page_size) if total else 0

    prev_col, info_col, next_col = st.columns([1, 3, 1])
    prev_col.button(
        "Previous",
        key="logs_prev",
        disabled=current <= FIRST_PAGE,
        on_click=_step_page,
        args=(-1,),
        use_container_width=True,
    )
    info_col.markdown(
        f"<div style='text-align:center'>Page {current:,} of {last_page:,} "
        f"&middot; rows {first_row:,}-{last_row:,} of {total:,}</div>",
        unsafe_allow_html=True,
    )
    next_col.button(
        "Next",
        key="logs_next",
        disabled=current >= last_page,
        on_click=_step_page,
        args=(1,),
        use_container_width=True,
    )


def _render_detail(selected: str | None) -> None:
    """Open the detail modal once per selected row (not on every rerun)."""
    if not selected:
        st.session_state[K_SHOWN] = None
        return
    if selected == st.session_state.get(K_SHOWN):
        return  # already shown; a closed dialog must not pop up again

    try:
        detail = run_sync(get_log_detail(selected))
    except Exception:  # noqa: BLE001
        _show_db_error("get_log_detail")
        return

    st.session_state[K_SHOWN] = selected
    if detail is None:
        st.warning("That log entry is no longer available.")
        return
    render_detail_modal(detail)


def _prepare_export(filters: Any, total: int) -> None:
    """Fetch the capped export and keep the CSV/JSON bytes in session state."""
    try:
        with st.spinner("Preparing export..."):
            rows = run_sync(export_threat_logs(filters, EXPORT_MAX_ROWS))
    except Exception:  # noqa: BLE001
        _show_db_error("export_threat_logs")
        return

    rows = list(rows or [])[:EXPORT_MAX_ROWS]  # enforce the cap even if the getter did not
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    st.session_state[K_EXPORT] = {
        "csv": rows_to_csv(rows),
        "json": rows_to_json(rows),
        "count": len(rows),
        "matching": max(total, len(rows)),
        "stamp": stamp,
    }


def _render_export(filters: Any, total: int) -> None:
    st.subheader("Export")
    st.caption(
        f"Exports every entry matching the current filters, up to "
        f"{EXPORT_MAX_ROWS:,} rows. CSV cells that start with = + - or @ are "
        f"prefixed with an apostrophe so spreadsheets show them as text."
    )

    if st.button("Prepare export", key="logs_prepare_export", disabled=total == 0):
        _prepare_export(filters, total)

    export = st.session_state.get(K_EXPORT)
    if not export:
        return

    if export["matching"] > export["count"]:
        st.warning(
            f"Export capped: {export['count']:,} of {export['matching']:,} matching "
            f"entries are included. Narrow the filters to export the rest."
        )
    else:
        st.success(f"Export ready: {export['count']:,} entries.")

    csv_col, json_col = st.columns(2)
    csv_col.download_button(
        "Download CSV",
        data=export["csv"],
        file_name=f"threat_logs_{export['stamp']}.csv",
        mime="text/csv",
        key="logs_download_csv",
        use_container_width=True,
    )
    json_col.download_button(
        "Download JSON",
        data=export["json"],
        file_name=f"threat_logs_{export['stamp']}.json",
        mime="application/json",
        key="logs_download_json",
        use_container_width=True,
    )


# ----------------------------------------------------------------------
# Page
# ----------------------------------------------------------------------
def main() -> None:
    render_sidebar()
    _init_state()

    st.title("Threat Logs")
    st.warning(SENSITIVE_NOTICE)

    filters = render_filters(defaults=st.session_state.get(K_FILTERS))
    _sync_filters(filters)

    st.selectbox(
        "Rows per page",
        PAGE_SIZE_OPTIONS,
        key=K_PAGE_SIZE,
        on_change=_first_page,
    )
    page_size = _safe_page_size()

    page = _load_page(filters, page_size)
    if page is None:
        st.button("Retry", key="logs_retry")  # any click reruns the script
        st.stop()

    total = page_total(page)
    if total == 0 and page_row_count(page) == 0:
        st.info("No log entries match the current filters.")
    st.caption(f"{total:,} matching log entries")

    selected = render_log_table(page)
    _render_pagination(total, page_size)
    _render_detail(selected)

    st.divider()
    _render_export(filters, total)


if __name__ == "__main__":
    main()