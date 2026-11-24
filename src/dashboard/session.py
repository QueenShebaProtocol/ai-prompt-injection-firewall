"""SHEBA SHIELD — persistent administrator session and live auto-refresh helpers.

Streamlit keeps ``st.session_state`` per browser connection, so reloading the page
(or following a plain ``<a href>`` link between pages) used to sign the administrator
out. This module keeps the login alive across reloads:

* On login a random token is created and stored **server-side** in a process-wide
  registry (``st.cache_resource``). The browser only holds the opaque token, in a
  ``SameSite=Lax`` cookie. No password or user data is stored in the cookie.
* On every new connection the cookie is looked up in the registry. A valid, unexpired
  token restores the administrator.
* The registry lives in the dashboard server's memory, so stopping or restarting the
  dashboard server invalidates every session. That is the only way a reload signs
  the administrator out, apart from an explicit sign-out or the idle timeout.
"""

from __future__ import annotations

import json
import secrets
import threading
import time

import streamlit as st
import streamlit.components.v1 as components

SESSION_COOKIE = "sheba_admin_session"
REFRESH_COOKIE = "sheba_refresh_seconds"
SESSION_IDLE_SECONDS = 8 * 60 * 60  # signed out after 8 hours without any page run
COOKIE_MAX_AGE = SESSION_IDLE_SECONDS


@st.cache_resource
def _registry() -> dict:
    """Process-wide ``{token: {"user": str, "expires": float}}`` (lost when the server stops)."""
    return {"lock": threading.Lock(), "tokens": {}}


def get_cookie(name: str) -> str:
    try:
        return str(st.context.cookies.get(name, "") or "")
    except Exception:
        return ""


def _cookie_js(name: str, value: str, max_age: int) -> None:
    """Write a cookie on the parent page (the component iframe is same-origin)."""
    components.html(
        f"""
        <script>
          try {{
            const d = window.parent.document;
            d.cookie = {json.dumps(name)} + "=" + encodeURIComponent({json.dumps(value)}) +
              "; path=/; max-age={int(max_age)}; SameSite=Lax";
          }} catch (e) {{}}
        </script>
        """,
        height=0,
    )


def set_refresh_cookie(seconds: int) -> None:
    _cookie_js(REFRESH_COOKIE, str(int(seconds)), 365 * 24 * 3600)


def saved_refresh_seconds(default: int = 30) -> int:
    raw = get_cookie(REFRESH_COOKIE)
    return int(raw) if raw in ("0", "15", "30", "60") else default


def create_admin_session(user: str) -> str:
    token = secrets.token_urlsafe(32)
    reg = _registry()
    with reg["lock"]:
        reg["tokens"][token] = {"user": user, "expires": time.time() + SESSION_IDLE_SECONDS}
    st.session_state["admin_token"] = token
    return token


def restore_admin_session() -> str:
    """Return the signed-in administrator name (restoring it from the cookie), or ''."""
    user = st.session_state.get("admin_user", "")
    token = st.session_state.get("admin_token") or get_cookie(SESSION_COOKIE)
    reg = _registry()
    now = time.time()
    with reg["lock"]:
        for t in [t for t, v in reg["tokens"].items() if v["expires"] < now]:
            reg["tokens"].pop(t, None)
        entry = reg["tokens"].get(token) if token else None
        if entry is None:
            if user:  # session token vanished (e.g. server restarted): sign out
                st.session_state.pop("admin_user", None)
                st.session_state.pop("admin_token", None)
            return ""
        entry["expires"] = now + SESSION_IDLE_SECONDS  # sliding expiry
        st.session_state["admin_user"] = entry["user"]
        st.session_state["admin_token"] = token
        return entry["user"]


def end_admin_session() -> None:
    token = st.session_state.pop("admin_token", None) or get_cookie(SESSION_COOKIE)
    if token:
        reg = _registry()
        with reg["lock"]:
            reg["tokens"].pop(token, None)
    st.session_state.pop("admin_user", None)


def sync_session_cookie(signed_in: bool) -> None:
    """Keep the browser cookie in step with the server-side session (call on every run)."""
    token = st.session_state.get("admin_token", "")
    if signed_in and token:
        if get_cookie(SESSION_COOKIE) != token:
            _cookie_js(SESSION_COOKIE, token, COOKIE_MAX_AGE)
    elif get_cookie(SESSION_COOKIE):
        _cookie_js(SESSION_COOKIE, "", 0)


def start_auto_refresh(seconds: int) -> None:
    """Re-run the whole page every ``seconds`` seconds without a browser reload.

    Filters, page number and the signed-in user live in ``st.session_state`` and are kept.
    Set ``st.session_state["_pause_refresh"] = True`` to hold the refresh (e.g. while an
    evidence dialog is open).
    """
    if not seconds or seconds <= 0:
        return
    st.session_state["_ar_armed"] = False  # the fragment's first run in each full run only arms it

    @st.fragment(run_every=int(seconds))
    def _tick() -> None:
        if st.session_state.get("_ar_armed") and not st.session_state.get("_pause_refresh"):
            st.rerun(scope="app")
        st.session_state["_ar_armed"] = True

    _tick()
