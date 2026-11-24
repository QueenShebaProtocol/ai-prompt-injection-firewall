"""SHEBA SHIELD — "Block a client IP" panel for the Analytics page.

An administrator types a client IP and presses **Block client IP**. The IP is stored
in ``blocked_clients``; the gateway reads that list (cached ~5 s) and answers every
request from a blocked IP with HTTP 403 before any inspection or forwarding.

Only a signed-in administrator (the Configuration-page login) can block or unblock.
Everyone else sees the list read-only. Each change is written to the audit log.
"""

from __future__ import annotations

import html
import logging

import streamlit as st

from src.dashboard.session import restore_admin_session, sync_session_cookie
from src.database.storage import (
    block_client_ip,
    list_blocked_clients,
    normalize_client_ip,
    run_sync,
    unblock_client_ip,
)

logger = logging.getLogger("firewall.dashboard.ip_block")


def _fmt_time(value) -> str:
    return value.strftime("%Y-%m-%d %H:%M") if hasattr(value, "strftime") else str(value)[:16]


def render_ip_block_panel() -> None:
    admin_user = restore_admin_session()
    sync_session_cookie(bool(admin_user))

    st.markdown('<div style="height:12px;"></div>', unsafe_allow_html=True)
    st.markdown(
        """
        <div class="card" style="margin-bottom:8px;">
          <div class="card-head">
            <div>
              <h3>Block a client IP</h3>
              <p class="hint">Blocked clients get HTTP 403 from the gateway (within about 5 seconds).</p>
            </div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    flash = st.session_state.pop("_ip_block_flash", None)
    if flash:
        getattr(st, flash[0])(flash[1])

    try:
        blocked = run_sync(list_blocked_clients())
    except Exception:
        logger.error("Could not load the blocked client list", exc_info=True)
        st.error("The blocked client list could not be loaded. Check the database connection.")
        return

    if not admin_user:
        st.info("Sign in on the Configuration page to block or unblock client IPs.")
    else:
        with st.form("form_block_client_ip", clear_on_submit=True, border=True):
            ip_in = st.text_input("Client IP address", placeholder="e.g. 172.20.0.1", key="block_ip_input")
            reason_in = st.text_input(
                "Reason (optional)", placeholder="e.g. repeated injection attempts", max_chars=200, key="block_ip_reason"
            )
            submitted = st.form_submit_button("Block client IP", type="primary", width="stretch")
        if submitted:
            try:
                ip = normalize_client_ip(ip_in)
            except ValueError as exc:
                st.error(str(exc))
            else:
                try:
                    added = run_sync(block_client_ip(ip, admin_user, reason_in))
                except Exception:
                    logger.error("Blocking client IP failed", exc_info=True)
                    st.error("Could not block that IP. Check the database connection and try again.")
                else:
                    st.session_state["_ip_block_flash"] = (
                        ("success", f"{ip} is now blocked.") if added else ("warning", f"{ip} is already blocked.")
                    )
                    st.rerun()

    if blocked:
        rows = "".join(
            f'<tr><td class="mono">{html.escape(b["client_ip"])}</td>'
            f'<td>{html.escape(b["reason"] or "—")}</td>'
            f'<td>{html.escape(b["blocked_by"])}</td>'
            f'<td class="mono">{html.escape(_fmt_time(b["created_at"]))}</td></tr>'
            for b in blocked
        )
        st.markdown(
            f"""
            <div class="table-wrap">
              <table>
                <thead><tr><th>Blocked IP</th><th>Reason</th><th>By</th><th>Since (UTC)</th></tr></thead>
                <tbody>{rows}</tbody>
              </table>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if admin_user:
            pick = st.selectbox("Unblock a client", [b["client_ip"] for b in blocked], key="unblock_ip_pick")
            if st.button("Unblock client IP", key="btn_unblock_ip"):
                try:
                    removed = run_sync(unblock_client_ip(pick, admin_user))
                except Exception:
                    logger.error("Unblocking client IP failed", exc_info=True)
                    st.error("Could not unblock that IP. Check the database connection and try again.")
                else:
                    st.session_state["_ip_block_flash"] = (
                        ("success", f"{pick} is unblocked.") if removed else ("warning", f"{pick} was not blocked.")
                    )
                    st.rerun()
    else:
        st.markdown('<div class="table-wrap"><div class="empty">No client IPs are blocked.</div></div>', unsafe_allow_html=True)
