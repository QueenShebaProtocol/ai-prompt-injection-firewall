"""SHEBA SHIELD — Administrator Configuration & Royal Chamber.
Master replication of index/index.html Administration screen.
"""

from __future__ import annotations

import copy
import hmac
import html
import logging
import os
import re
import sys
import tempfile
import time
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import streamlit as st
import streamlit.components.v1 as components
import yaml
from sqlalchemy import select

from src.dashboard.assets import get_crest_data_uri
from src.dashboard.components.sidebar import render_sidebar
from src.dashboard.session import (
    create_admin_session,
    end_admin_session,
    restore_admin_session,
    sync_session_cookie,
)
from src.dashboard.styles import inject_theme
from src.database.models import AdminAuditLog
from src.database.storage import (
    AsyncSessionLocal,
    create_rule,
    delete_rule,
    list_rules,
    run_sync,
    update_rule,
    write_audit_log,
)

logger = logging.getLogger("firewall.dashboard.config")

# ------------------------------------------------------------------ Constants
ADMIN_PASSWORD_ENV = "DASHBOARD_ADMIN_PASSWORD"
MAX_NAME_LENGTH = 64
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 30

RULE_TYPES = ("REGEX", "KEYWORD", "EXCLUSION")
CATEGORIES = ("JAILBREAK", "PROMPT_LEAK", "SYSTEM_OVERRIDE", "PII")
SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
OUTPUT_ACTIONS = ("block", "redact", "warn")

MAX_PATTERN_LENGTH = 500
MAX_DESCRIPTION_LENGTH = 200
RULE_ID_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")
EDITABLE_FIELDS = ("rule_type", "category", "pattern", "description", "severity", "is_active")

LAYER_FLAGS = (
    ("layer_1_enabled", "Layer 1 — Deterministic rules", "Regex and keyword matching · sub-millisecond"),
    ("layer_2_enabled", "Layer 2 — ONNX classifier", "DeBERTa v3 prompt-injection model · local CPU"),
    ("layer_3_enabled", "Layer 3 — LLM evaluator", "phi4-mini judge for uncertain prompts · fails closed"),
    ("output_scanner_enabled", "Output scanner", "Detects leaked system prompt, PII and secrets"),
)

RUNTIME_CONFIG_ENV = "FIREWALL_RUNTIME_CONFIG_PATH"
PACKAGED_CONFIG_PATH = _REPO_ROOT / "config" / "firewall.yaml"
OVERLAY_KEYS: dict[str, tuple[str, ...]] = {
    "pipeline": ("firewall_enabled",) + tuple(flag for flag, _, _ in LAYER_FLAGS),
    "layer_2": ("high_confidence_threshold", "low_confidence_threshold"),
    "output_scanner": ("on_detect",),
}

DEFAULT_SETTINGS: dict[str, dict[str, Any]] = {
    "pipeline": {
        "firewall_enabled": True,
        "layer_1_enabled": True,
        "layer_2_enabled": True,
        "layer_3_enabled": True,
        "output_scanner_enabled": True,
    },
    "layer_2": {"high_confidence_threshold": 0.85, "low_confidence_threshold": 0.35},
    "output_scanner": {"on_detect": "redact"},
}


# ------------------------------------------------------------------ Admin Auth
def _read_dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return values
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip("'\"")
    return values


def _admin_password() -> str:
    value = os.environ.get(ADMIN_PASSWORD_ENV)
    if value is None:
        value = _read_dotenv(_REPO_ROOT / ".env").get(ADMIN_PASSWORD_ENV, "")
    return value or ""


def _password_matches(entered: str, expected: str) -> bool:
    return hmac.compare_digest(entered.encode("utf-8"), expected.encode("utf-8"))


def _clean_name(raw: str) -> str:
    name = " ".join(str(raw).split())
    if not name or len(name) > MAX_NAME_LENGTH or any(ord(c) < 32 for c in name):
        return ""
    return name


def _lockout_remaining() -> int:
    until = st.session_state.get("_login_locked_until", 0.0)
    return max(0, int(until - time.time() + 0.999))


def _register_failure() -> None:
    failures = st.session_state.get("_login_failures", 0) + 1
    if failures >= MAX_LOGIN_ATTEMPTS:
        st.session_state["_login_locked_until"] = time.time() + LOCKOUT_SECONDS
        failures = 0
    st.session_state["_login_failures"] = failures


# ------------------------------------------------------------------ Validation
def validate_rule(rule: dict, existing_ids: Iterable[str] = (), is_new: bool = True) -> list[str]:
    errors: list[str] = []
    rule_id = str(rule.get("rule_id", "")).strip()
    rule_type = rule.get("rule_type")
    category = rule.get("category")
    severity = rule.get("severity")
    pattern = str(rule.get("pattern", ""))
    description = str(rule.get("description", ""))

    if not rule_id:
        errors.append("Rule ID is required.")
    elif not RULE_ID_RE.match(rule_id):
        errors.append("Rule ID must start with a capital letter and use only capital letters, digits and underscores (3 to 64 characters).")
    elif is_new and rule_id in set(existing_ids):
        errors.append(f"A rule with ID {rule_id} already exists.")

    if rule_type not in RULE_TYPES:
        errors.append(f"Type must be one of: {', '.join(RULE_TYPES)}.")
    if category not in CATEGORIES:
        errors.append(f"Category must be one of: {', '.join(CATEGORIES)}.")
    if severity not in SEVERITIES:
        errors.append(f"Severity must be one of: {', '.join(SEVERITIES)}.")

    if not pattern.strip():
        errors.append("Pattern is required.")
    elif len(pattern) > MAX_PATTERN_LENGTH:
        errors.append(f"Pattern is {len(pattern)} characters long. The limit is {MAX_PATTERN_LENGTH}.")
    elif rule_type == "REGEX":
        try:
            compiled = re.compile(pattern)
            if compiled.search(""):
                errors.append("Pattern matches empty text, so it would block every prompt.")
        except re.error as exc:
            errors.append(f"Pattern is not a valid regular expression: {exc}.")

    if len(description) > MAX_DESCRIPTION_LENGTH:
        errors.append(f"Description is {len(description)} characters long. The limit is {MAX_DESCRIPTION_LENGTH}.")
    return errors


def validate_settings(settings: dict) -> list[str]:
    errors: list[str] = []
    pipeline = settings.get("pipeline", {})
    if "firewall_enabled" in pipeline and not isinstance(pipeline.get("firewall_enabled"), bool):
        errors.append("firewall_enabled must be on or off.")
    for flag, _, _ in LAYER_FLAGS:
        if not isinstance(pipeline.get(flag), bool):
            errors.append(f"{flag} must be on or off.")
    layer_2 = settings.get("layer_2", {})
    low = layer_2.get("low_confidence_threshold")
    high = layer_2.get("high_confidence_threshold")
    numbers_ok = True
    for label, value in (("Low", low), ("High", high)):
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0.0 <= value <= 1.0:
            errors.append(f"{label} threshold must be a number from 0.00 to 1.00.")
            numbers_ok = False
    if numbers_ok and not low < high:
        errors.append("The low threshold must be smaller than the high threshold.")
    if settings.get("output_scanner", {}).get("on_detect") not in OUTPUT_ACTIONS:
        errors.append(f"Output scanner action must be one of: {', '.join(OUTPUT_ACTIONS)}.")
    return errors


# ------------------------------------------------------------------ Data access
def _runtime_config_path() -> str:
    val = os.environ.get(RUNTIME_CONFIG_ENV)
    if val is None:
        val = _read_dotenv(_REPO_ROOT / ".env").get(RUNTIME_CONFIG_ENV, "")
    return val or ""


def _read_yaml(path: Any) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    return raw if isinstance(raw, dict) else {}


def _overlay_keys(raw: dict) -> dict:
    kept: dict[str, dict] = {}
    for section, keys in OVERLAY_KEYS.items():
        values = raw.get(section)
        if isinstance(values, dict):
            picked = {k: values[k] for k in keys if k in values}
            if picked:
                kept[section] = picked
    return kept


def _load_settings() -> dict:
    settings = copy.deepcopy(DEFAULT_SETTINGS)
    sources = [("packaged config", PACKAGED_CONFIG_PATH)]
    runtime = _runtime_config_path()
    if runtime and os.path.exists(runtime):
        sources.append(("runtime config", runtime))
    for label, path in sources:
        try:
            overlay = _overlay_keys(_read_yaml(path))
        except Exception:
            continue
        candidate = copy.deepcopy(settings)
        for section, values in overlay.items():
            candidate[section].update(values)
        if not validate_settings(candidate):
            settings = candidate
    return settings


def _write_runtime_file(path: str, settings: dict) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    text = (
        "# Written by Sheba Shield dashboard.\n"
        + yaml.safe_dump(settings, sort_keys=True, default_flow_style=False)
    )
    tmp_name = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=target.parent, prefix=".firewall-", suffix=".tmp", delete=False) as tmp:
            tmp_name = tmp.name
            tmp.write(text)
            tmp.flush()
            os.fsync(tmp.fileno())
        os.chmod(tmp_name, 0o644)
        os.replace(tmp_name, target)
    except Exception:
        if tmp_name and os.path.exists(tmp_name):
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
        raise


def _save_settings(settings: dict, admin_user: str) -> None:
    new = _overlay_keys(settings)
    path = _runtime_config_path()
    if not path:
        raise RuntimeError(f"{RUNTIME_CONFIG_ENV} is not set, so settings cannot be saved.")
    old = _overlay_keys(_load_settings())
    _write_runtime_file(path, new)
    try:
        run_sync(write_audit_log(admin_user=admin_user, action="THRESHOLD_CHANGED", before=old, after=new))
    except Exception as exc:
        logger.warning(f"Settings saved but audit log failed: {exc}")


def _save_master_setting(settings: dict, new_state: bool, admin_user: str, reason: str = "") -> None:
    settings["pipeline"]["firewall_enabled"] = new_state
    new = _overlay_keys(settings)
    path = _runtime_config_path()
    if not path:
        raise RuntimeError(f"{RUNTIME_CONFIG_ENV} is not set, so settings cannot be saved.")
    old = _overlay_keys(_load_settings())
    _write_runtime_file(path, new)
    try:
        run_sync(write_audit_log(
            admin_user=admin_user,
            action="THRESHOLD_CHANGED",
            before=old,
            after={
                **new,
                "master_control": {
                    "previous": old.get("pipeline", {}).get("firewall_enabled", True),
                    "current": new_state,
                },
                "reason": reason,
            },
        ))
    except Exception as exc:
        logger.warning(f"Master setting saved but audit log failed: {exc}")


async def _last_master_change() -> dict | None:
    async with AsyncSessionLocal() as session:
        stmt = (
            select(AdminAuditLog)
            .where(AdminAuditLog.action == "THRESHOLD_CHANGED")
            .order_by(AdminAuditLog.timestamp.desc())
            .limit(50)
        )
        rows = (await session.execute(stmt)).scalars().all()
        for r in rows:
            details = r.change_details or {}
            after = details.get("after", {})
            if "master_control" in details or "master_control" in after or "firewall_enabled" in str(details):
                mc = details.get("master_control") or after.get("master_control") or {}
                return {
                    "timestamp": r.timestamp,
                    "admin_user": r.admin_user,
                    "new_state": mc.get("current", after.get("pipeline", {}).get("firewall_enabled")),
                    "reason": details.get("reason") or after.get("reason", ""),
                }
    return None


async def _fetch_audit_logs(limit: int = 50) -> list[dict]:
    async with AsyncSessionLocal() as session:
        stmt = select(AdminAuditLog).order_by(AdminAuditLog.timestamp.desc()).limit(limit)
        rows = (await session.execute(stmt)).scalars().all()
        return [
            {
                "timestamp": r.timestamp,
                "admin_user": r.admin_user,
                "action": r.action,
                "target_rule_id": r.target_rule_id,
                "change_details": r.change_details,
            }
            for r in rows
        ]


# ------------------------------------------------------------------ Page Main Runner
def main() -> None:
    st.set_page_config(
        page_title="SHEBA Shield — Configuration",
        page_icon=None,
        layout="wide",
        initial_sidebar_state="expanded",
    )

    inject_theme()
    # No auto-refresh here: a rerun mid-edit would discard half-typed rule and setting changes.
    render_sidebar(current_page="config", auto_refresh=False)

    # Handle signout query param
    if st.query_params.get("signout") in ("1", "true") or st.query_params.get("action") == "signout":
        end_admin_session()
        try:
            del st.query_params["signout"]
        except Exception:
            pass
        try:
            del st.query_params["action"]
        except Exception:
            pass
        st.rerun()

    # Restore the login from the server-side session after a page reload.
    admin_user = restore_admin_session()
    sync_session_cookie(bool(admin_user))
    crest_uri = get_crest_data_uri()

    # Topbar
    top_c1, top_c2 = st.columns([3, 1.5])
    with top_c1:
        st.markdown(
            """
            <div class="topbar" style="margin-bottom:0px;">
              <div>
                <div class="eyebrow">Administration</div>
                <h1>Configuration</h1>
                <p class="sub">Protection layers, Layer 2 thresholds, detection rules and the keyword deny list.</p>
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with top_c2:
        if admin_user:
            initial = html.escape((admin_user or "A")[:1].upper())
            user_display = html.escape(admin_user)
            user_label = html.escape(admin_user.capitalize() if admin_user.islower() else admin_user)

            st.markdown(
                f"""
                <div class="sheba-profile-menu" id="shebaProfileMenu">
                  <div class="sheba-profile-pill" id="shebaProfilePill" tabindex="0" role="button" aria-haspopup="true" aria-expanded="false" title="Account options">
                    <div class="sheba-profile-avatar">{initial}</div>
                    <span class="sheba-profile-name">{user_label}</span>
                    <svg class="sheba-profile-chevron" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                      <path d="M6 9l6 6 6-6"/>
                    </svg>
                  </div>
                  <div class="sheba-profile-dropdown" id="shebaProfileDropdown">
                    <div class="sheba-profile-dropdown-header">
                      <div class="sheba-profile-dropdown-user">{user_display}</div>
                      <div class="sheba-profile-dropdown-role">Administrator</div>
                    </div>
                    <a href="?signout=1" target="_self" class="sheba-profile-item logout" id="shebaDropdownLogout">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path>
                        <polyline points="16 17 21 12 16 7"></polyline>
                        <line x1="21" y1="12" x2="9" y2="12"></line>
                      </svg>
                      <span>Logout</span>
                    </a>
                  </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            # Native Streamlit button bridge
            if st.button("Sign out", key="btn_sign_out", width="content"):
                end_admin_session()
                st.rerun()

            # Parent-window interactive controller for dropdown click/escape & logout bridge
            components.html(
                """
                <script>
                  (function() {
                    const pdoc = window.parent.document;
                    const pwin = window.parent;

                    function initMenu() {
                      const menu = pdoc.getElementById('shebaProfileMenu');
                      const pill = pdoc.getElementById('shebaProfilePill');
                      if (!menu || !pill) return;

                      if (!pwin.__shebaProfileInit) {
                        pwin.__shebaProfileInit = true;

                        pdoc.addEventListener('click', function(e) {
                          const clickedLogout = e.target.closest('#shebaDropdownLogout') || e.target.closest('.sheba-profile-item.logout');
                          const clickedPill = e.target.closest('#shebaProfilePill');
                          const activeMenu = pdoc.getElementById('shebaProfileMenu');

                          if (clickedLogout) {
                            e.preventDefault();
                            if (activeMenu) activeMenu.classList.remove('open');
                            // Trigger native Streamlit button if present
                            const btn = pdoc.querySelector('.st-key-btn_sign_out button') ||
                                        pdoc.querySelector('button[key="btn_sign_out"]') ||
                                        Array.from(pdoc.querySelectorAll('button')).find(b => b.textContent && b.textContent.trim() === 'Sign out');
                            if (btn) {
                              btn.click();
                            } else {
                              pwin.location.search = '?signout=1';
                            }
                            return;
                          }

                          if (clickedPill) {
                            e.preventDefault();
                            e.stopPropagation();
                            if (activeMenu) {
                              const isOpen = activeMenu.classList.toggle('open');
                              clickedPill.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
                            }
                            return;
                          }

                          // Click outside closes menu
                          if (activeMenu && !activeMenu.contains(e.target)) {
                            activeMenu.classList.remove('open');
                            const p = pdoc.getElementById('shebaProfilePill');
                            if (p) p.setAttribute('aria-expanded', 'false');
                          }
                        });

                        pdoc.addEventListener('keydown', function(e) {
                          if (e.key === 'Escape') {
                            const activeMenu = pdoc.getElementById('shebaProfileMenu');
                            if (activeMenu && activeMenu.classList.contains('open')) {
                              activeMenu.classList.remove('open');
                              const p = pdoc.getElementById('shebaProfilePill');
                              if (p) {
                                p.setAttribute('aria-expanded', 'false');
                                p.focus();
                              }
                            }
                          }
                        });
                      }
                    }

                    initMenu();
                    setTimeout(initMenu, 150);
                    setTimeout(initMenu, 500);
                  })();
                </script>
                """,
                height=0,
                width=0,
            )

    st.markdown('<div style="height:16px;"></div>', unsafe_allow_html=True)

    # ------------------------------------------------------------------ Royal Chamber Login View
    expected_pass = _admin_password()

    if not admin_user:
        st.markdown('<div style="height:28px;"></div>', unsafe_allow_html=True)
        log_col1, log_col2, log_col3 = st.columns([1, 1.25, 1])
        with log_col2:
            with st.form("royal_chamber_login", border=True):
                st.markdown(
                    f"""
                    <div style="text-align:center;padding-top:4px;margin-bottom:18px;">
                      <img src="{crest_uri}" alt="SHEBA Shield crest" style="width:76px;height:76px;border-radius:16px;margin:0 auto 14px;display:block;border:1px solid var(--gold-dim);object-fit:cover;" />
                      <h2 class="serif" style="font-size:21px;color:var(--gold-2);margin:0 0 6px;letter-spacing:.04em;text-align:center;">Royal Chamber Access</h2>
                      <p style="color:var(--muted);font-size:13.5px;line-height:1.5;margin:0 auto;text-align:center;max-width:32ch;">Sign in as an administrator to view and change the firewall configuration.</p>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                entered_name = st.text_input("Admin name", placeholder="e.g. admin", key="login_name")
                entered_pass = st.text_input("Password", type="password", placeholder="Enter admin password", key="login_pass")
                st.markdown('<div style="height:6px;"></div>', unsafe_allow_html=True)
                submitted = st.form_submit_button("Sign in", type="primary", width='stretch')
                st.markdown(
                    '<p style="font-size:11.5px;color:var(--faint);text-align:center;margin-top:14px;margin-bottom:0;">Demo: any name and password. All changes are written to the audit log.</p>',
                    unsafe_allow_html=True,
                )

            if submitted:
                clean = _clean_name(entered_name)
                remaining = _lockout_remaining()
                if remaining > 0:
                    st.error(f"Too many wrong attempts. Locked out for {remaining}s.")
                elif not clean:
                    st.error("Please enter a valid admin name.")
                elif expected_pass and not _password_matches(entered_pass, expected_pass):
                    _register_failure()
                    st.error("Invalid administrator password.")
                else:
                    st.session_state["admin_user"] = clean
                    create_admin_session(clean)
                    st.session_state["_login_failures"] = 0
                    st.success("Access granted.")
                    st.rerun()

        st.stop()

    # ------------------------------------------------------------------ Signed In View (4 Tabs)
    if "cfg_state" not in st.session_state:
        st.session_state["cfg_state"] = _load_settings()
    saved_settings = _load_settings()
    state = st.session_state["cfg_state"]

    master_on = bool(state.get("pipeline", {}).get("firewall_enabled", True))

    # ------------------------------------------------------------------ FIREWALL MASTER CONTROL
    if master_on:
        st.markdown(
            """
            <div class="banner banner-safe" style="margin-top:8px;margin-bottom:16px;">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6l8-3z"/></svg>
              <div><b>FIREWALL ACTIVE</b> — Incoming prompts are inspected by all configured and enabled security layers.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            """
            <div class="banner banner-danger" style="margin-top:8px;margin-bottom:16px;background:rgba(235,94,85,.14);border:1px solid rgba(235,94,85,.5);">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--danger)" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0zM12 9v4m0 4h.01"/></svg>
              <div><b style="color:var(--danger)">FIREWALL DISABLED</b> — Incoming prompts are being forwarded directly to the downstream LLM without security inspection.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Fetch last state change info
    try:
        last_change = run_sync(_last_master_change())
    except Exception:
        last_change = None

    if last_change and last_change.get("timestamp"):
        t = last_change["timestamp"]
        t_str = t.strftime("%Y-%m-%d %H:%M:%S UTC") if hasattr(t, "strftime") else str(t)[:19] + " UTC"
        who = last_change.get("admin_user", "admin")
        reason_txt = f" · Reason: {last_change['reason']}" if last_change.get("reason") else ""
        meta_html = f"Last state change: <b class='mono' style='color:var(--ivory)'>{html.escape(t_str)}</b> by <b style='color:var(--gold-2)'>{html.escape(who)}</b>{html.escape(reason_txt)}"
    else:
        meta_html = "Protection State: <b style='color:var(--gold-2)'>Default configuration active (Initial boot)</b>"

    # Master Control Card
    st.markdown(
        f"""
        <div class="card" style="margin-bottom:18px;border:1px solid {('rgba(235,94,85,.5)' if not master_on else 'var(--line)')};background:{('rgba(235,94,85,.05)' if not master_on else 'var(--surface)')};">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:16px;">
            <div style="flex:1;min-width:300px;">
              <div class="eyebrow" style="color:{('var(--danger)' if not master_on else 'var(--gold-2)')};margin-bottom:4px;">Global System Override</div>
              <h2 class="serif" style="font-size:20px;margin:0 0 6px;">FIREWALL MASTER CONTROL</h2>
              <p class="hint" style="max-width:700px;font-size:13.5px;line-height:1.5;">
                {('Bypasses the entire firewall inspection pipeline when switched OFF. User prompts and completion outputs are forwarded directly to the downstream LLM without Layer 1, Layer 2, Layer 3, or Output Scanner inspection.' if not master_on else 'When switched ON, all configured and enabled detection layers inspect incoming and outgoing traffic according to their individual policies.')}
              </p>
              <div style="margin-top:12px;font-size:12px;color:var(--muted);">
                {meta_html}
              </div>
            </div>
            <div style="text-align:right;">
              <div style="margin-bottom:12px;">
                {('<span class="badge b-blocked" style="font-size:13px;padding:4px 14px;background:rgba(235,94,85,.2);color:var(--danger);border:1px solid rgba(235,94,85,.5);">● DISABLED (BYPASS ACTIVE)</span>' if not master_on else '<span class="badge b-passed" style="font-size:13px;padding:4px 14px;background:rgba(62,207,142,.15);color:var(--safe);border:1px solid rgba(62,207,142,.4);">● ACTIVE (PROTECTED)</span>')}
              </div>
            </div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Master Switch Actions and Confirmation Modal
    if master_on:
        if not st.session_state.get("show_disable_confirm", False):
            if st.button("Disable Firewall (Emergency Bypass)", type="secondary", key="btn_trigger_master_off"):
                st.session_state["show_disable_confirm"] = True
                st.rerun()
        else:
            with st.container(border=True):
                st.markdown(
                    """
                    <div style="padding:4px 0 10px;">
                      <b style="color:var(--danger);font-size:16px;">⚠️ Confirm Disabling Firewall Protection</b>
                      <p style="color:var(--ivory);font-size:13.5px;margin-top:6px;line-height:1.5;">
                        Are you sure you want to disable the master firewall? While disabled:
                        <br>• <b>All security layers (Layer 1, Layer 2, Layer 3, Output Scanner) will be bypassed.</b>
                        <br>• Malicious prompt injections and data leakage attacks will <b>not be blocked</b>.
                        <br>• Prompts will be delivered straight to the downstream LLM.
                      </p>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                disable_reason = st.text_input(
                    "Reason for disabling (optional):",
                    placeholder="e.g. Debugging downstream service or routine maintenance",
                    key="input_disable_reason",
                )
                dc1, dc2, _ = st.columns([1.6, 1.2, 3])
                with dc1:
                    if st.button("Confirm: Switch Firewall OFF", type="primary", key="btn_confirm_master_off", width='stretch'):
                        state["pipeline"]["firewall_enabled"] = False
                        _save_master_setting(state, False, admin_user, disable_reason or "Admin bypass")
                        st.session_state["show_disable_confirm"] = False
                        st.session_state["cfg_state"] = _load_settings()
                        st.success("Firewall has been DISABLED. Incoming requests are now bypassing inspection.")
                        st.rerun()
                with dc2:
                    if st.button("Cancel", key="btn_cancel_master_off", width='stretch'):
                        st.session_state["show_disable_confirm"] = False
                        st.rerun()
    else:
        if st.button("Activate Firewall (Enable Protection)", type="primary", key="btn_trigger_master_on"):
            state["pipeline"]["firewall_enabled"] = True
            _save_master_setting(state, True, admin_user, "Restored firewall protection")
            st.session_state["cfg_state"] = _load_settings()
            st.success("Firewall has been ACTIVATED. All enabled detection layers are now standing guard.")
            st.rerun()

    st.markdown('<div style="height:12px;"></div>', unsafe_allow_html=True)

    tab_layers, tab_rules, tab_deny, tab_audit = st.tabs([
        "Layers & thresholds",
        "Rules",
        "Keyword deny list",
        "Audit log",
    ])

    # ------------------------------------------------------------------ TAB 1: Layers & Thresholds
    with tab_layers:
        l_c1, l_c2 = st.columns([1, 1])
        with l_c1:
            st.markdown(
                """
                <div class="card" style="margin-bottom:0px;">
                  <h3>Protection layers</h3>
                  <p class="hint">Turn individual inspection stages on or off.</p>
                </div>
                """,
                unsafe_allow_html=True,
            )
            if not master_on:
                st.markdown(
                    """
                    <div style="background:rgba(235,94,85,.1);border:1px solid rgba(235,94,85,.35);border-radius:8px;padding:8px 12px;margin:10px 0 14px;font-size:12.5px;color:var(--warn);">
                      ⚠️ <b>Master Firewall is currently OFF.</b> Individual layer settings are preserved below, but all traffic is currently bypassing inspection.
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            st.markdown('<div style="height:10px;"></div>', unsafe_allow_html=True)
            l1_on = st.toggle(
                "Layer 1 — Deterministic rules (Regex and keywords · sub-millisecond)",
                value=bool(state["pipeline"].get("layer_1_enabled", True)),
                key="cfg_l1_toggle",
            )
            l2_on = st.toggle(
                "Layer 2 — ONNX classifier (DeBERTa v3 prompt-injection model · local CPU)",
                value=bool(state["pipeline"].get("layer_2_enabled", True)),
                key="cfg_l2_toggle",
            )
            l3_on = st.toggle(
                "Layer 3 — LLM evaluator (phi4-mini judge for uncertain prompts · fails closed)",
                value=bool(state["pipeline"].get("layer_3_enabled", True)),
                key="cfg_l3_toggle",
            )
            os_on = st.toggle(
                "Output scanner (Detects leaked system prompt, PII and secrets)",
                value=bool(state["pipeline"].get("output_scanner_enabled", True)),
                key="cfg_os_toggle",
            )

            state["pipeline"]["layer_1_enabled"] = l1_on
            state["pipeline"]["layer_2_enabled"] = l2_on
            state["pipeline"]["layer_3_enabled"] = l3_on
            state["pipeline"]["output_scanner_enabled"] = os_on

        with l_c2:
            st.markdown(
                """
                <div class="card" style="margin-bottom:0px;">
                  <h3>Layer 2 thresholds</h3>
                  <p class="hint">At or above high → blocked. Below low → passed. In between → sent to Layer 3 judge.</p>
                </div>
                """,
                unsafe_allow_html=True,
            )
            cur_low = float(state["layer_2"].get("low_confidence_threshold", 0.35))
            cur_high = float(state["layer_2"].get("high_confidence_threshold", 0.85))

            pass_w = max(5, int(cur_low * 100))
            judge_w = max(5, int((cur_high - cur_low) * 100))
            block_w = max(5, int((1.0 - cur_high) * 100))

            st.markdown(
                f"""
                <div class="zone" aria-hidden="true" style="margin-top:16px;">
                  <div class="z-pass" style="width:{pass_w}%">Pass</div>
                  <div class="z-judge" style="width:{judge_w}%">Layer 3</div>
                  <div class="z-block" style="width:{block_w}%">Block</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            th_c1, th_c2 = st.columns(2)
            with th_c1:
                new_low = st.slider(
                    "Low-confidence threshold",
                    0.0, 1.0, cur_low, 0.01,
                    format="%.2f",
                    key="cfg_slider_low",
                )
            with th_c2:
                new_high = st.slider(
                    "High-confidence threshold",
                    0.0, 1.0, cur_high, 0.01,
                    format="%.2f",
                    key="cfg_slider_high",
                )

            state["layer_2"]["low_confidence_threshold"] = round(min(new_low, new_high - 0.01), 2)
            state["layer_2"]["high_confidence_threshold"] = round(max(new_high, new_low + 0.01), 2)

            st.markdown(
                """
                <div style="margin-top:16px;">
                  <h3>Output scanner action</h3>
                  <p class="hint">What to do when a leak is found in a model response.</p>
                </div>
                """,
                unsafe_allow_html=True,
            )
            cur_act = state["output_scanner"].get("on_detect", "redact")
            act_choice = st.radio(
                "Action on detect",
                options=["block", "redact", "warn"],
                index=["block", "redact", "warn"].index(cur_act) if cur_act in ("block", "redact", "warn") else 1,
                horizontal=True,
                key="cfg_act_radio",
                label_visibility="collapsed",
            )
            state["output_scanner"]["on_detect"] = act_choice

        # Savebar
        dirty = (
            state["pipeline"] != saved_settings["pipeline"]
            or state["layer_2"] != saved_settings["layer_2"]
            or state["output_scanner"] != saved_settings["output_scanner"]
        )
        if dirty:
            st.markdown(
                """
                <div class="savebar">
                  <span><b style="color:var(--gold-2)">Unsaved changes</b> <span style="color:var(--muted)">— review before applying to the gateway.</span></span>
                </div>
                """,
                unsafe_allow_html=True,
            )
            sb_col1, sb_col2 = st.columns([1, 1])
            with sb_col1:
                if st.button("Discard changes", key="btn_discard_settings", width='stretch'):
                    st.session_state["cfg_state"] = _load_settings()
                    st.rerun()
            with sb_col2:
                if st.button("Save settings", type="primary", key="btn_save_settings", width='stretch'):
                    try:
                        _save_settings(state, admin_user)
                        st.success("Settings saved successfully and persisted.")
                        st.session_state["cfg_state"] = _load_settings()
                        st.rerun()
                    except Exception as exc:
                        st.error(f"Save failed: {exc}")

    # ------------------------------------------------------------------ TAB 2: Rules
    with tab_rules:
        st.markdown(
            """
            <div class="card" style="margin-bottom:12px;">
              <div class="card-head">
                <div>
                  <h3>Layer 1 detection rules</h3>
                  <p class="hint">Regex and keyword rules — hot-reloaded within 5 seconds.</p>
                </div>
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        try:
            rules_list = run_sync(list_rules()) or []
        except Exception as exc:
            rules_list = []
            st.error(f"Could not load rules: {exc}")

        if rules_list:
            r_rows = []
            for r in rules_list:
                rid = r.get("rule_id", "")
                rtype = r.get("rule_type", "REGEX")
                cat = r.get("category", "JAILBREAK")
                sev = r.get("severity", "HIGH")
                pat = r.get("pattern", "")
                active = "Active" if r.get("is_active") else "Disabled"
                active_badge = f'<span class="badge b-passed">{active}</span>' if r.get("is_active") else f'<span class="badge b-redacted">{active}</span>'
                r_rows.append(
                    f'<tr>'
                    f'<td>{active_badge}</td>'
                    f'<td class="mono">{html.escape(rid)}</td>'
                    f'<td><span class="tag">{html.escape(rtype)}</span></td>'
                    f'<td>{html.escape(cat)}</td>'
                    f'<td><span class="tag sev-{sev}">{sev}</span></td>'
                    f'<td class="mono trunc">{html.escape(pat)}</td>'
                    f'</tr>'
                )
            st.markdown(
                f"""
                <div class="table-wrap">
                  <table>
                    <thead>
                      <tr><th>Status</th><th>Rule ID</th><th>Type</th><th>Category</th><th>Severity</th><th>Pattern</th></tr>
                    </thead>
                    <tbody>{"".join(r_rows)}</tbody>
                  </table>
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown('<h3 style="margin-top:24px;">Manage rules</h3>', unsafe_allow_html=True)
        rule_action = st.radio("Rule action", ["Add rule", "Enable / disable", "Delete rule"], horizontal=True, key="rule_action_choice")

        all_ids = [r["rule_id"] for r in rules_list]

        if rule_action == "Add rule":
            with st.form("form_add_rule"):
                new_id = st.text_input("Rule ID", placeholder="e.g. RULE_CUSTOM_01")
                new_type = st.selectbox("Type", RULE_TYPES)
                new_cat = st.selectbox("Category", CATEGORIES)
                new_sev = st.selectbox("Severity", SEVERITIES, index=2)
                new_pat = st.text_area("Pattern", placeholder="Regex pattern or keyword phrase")
                new_desc = st.text_input("Description", placeholder="Rule purpose")
                add_sub = st.form_submit_button("Add rule", type="primary")

            if add_sub:
                candidate = {
                    "rule_id": new_id.strip(),
                    "rule_type": new_type,
                    "category": new_cat,
                    "severity": new_sev,
                    "pattern": new_pat.strip(),
                    "description": new_desc.strip(),
                    "is_active": True,
                }
                errs = validate_rule(candidate, all_ids, is_new=True)
                if errs:
                    st.error("Validation errors:\n" + "\n".join(f"- {e}" for e in errs))
                else:
                    try:
                        run_sync(create_rule(candidate, admin_user))
                        st.success(f"Rule {new_id} added successfully.")
                        st.rerun()
                    except Exception as exc:
                        st.error(f"Failed to create rule: {exc}")

        elif rule_action == "Enable / disable":
            if all_ids:
                target_id = st.selectbox("Select rule", all_ids, key="toggle_rule_select")
                curr_rule = next(r for r in rules_list if r["rule_id"] == target_id)
                is_act = bool(curr_rule.get("is_active", True))
                st.write(f"Rule `{target_id}` is currently **{'Active' if is_act else 'Disabled'}**.")
                if st.button("Disable rule" if is_act else "Enable rule", key="btn_toggle_act"):
                    try:
                        run_sync(update_rule(target_id, {"is_active": not is_act}, admin_user))
                        st.success(f"Rule {target_id} updated.")
                        st.rerun()
                    except Exception as exc:
                        st.error(f"Failed to update rule: {exc}")

        elif rule_action == "Delete rule":
            if all_ids:
                del_id = st.selectbox("Select rule to delete", all_ids, key="del_rule_select")
                confirm_del = st.checkbox(f"Yes, permanently delete {del_id}", key="confirm_del_chk")
                if st.button("Delete rule", disabled=not confirm_del, key="btn_del_exec"):
                    try:
                        run_sync(delete_rule(del_id, admin_user))
                        st.success(f"Rule {del_id} deleted.")
                        st.rerun()
                    except Exception as exc:
                        st.error(f"Delete failed: {exc}")

    # ------------------------------------------------------------------ TAB 3: Keyword Deny List
    with tab_deny:
        st.markdown(
            """
            <div class="card">
              <h3>Keyword deny list</h3>
              <p class="hint">Exact phrases that are always blocked at Layer 1.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        try:
            keywords = run_sync(list_rules(rule_type="KEYWORD")) or []
        except Exception as exc:
            keywords = []
            st.error(f"Could not load deny list: {exc}")

        with st.form("form_add_deny_phrase"):
            d_c1, d_c2 = st.columns([3, 1])
            with d_c1:
                phrase_in = st.text_input("New phrase", placeholder="e.g. reveal your system prompt", label_visibility="collapsed")
            with d_c2:
                add_phrase_sub = st.form_submit_button("Add phrase", type="primary", width='stretch')

        if add_phrase_sub and phrase_in.strip():
            clean_phrase = phrase_in.strip()
            existing_phrases = [r.get("pattern", "").strip().lower() for r in keywords]
            if clean_phrase.lower() in existing_phrases:
                st.warning("That phrase is already in the keyword deny list.")
            else:
                all_kw_ids = [r["rule_id"] for r in (run_sync(list_rules()) or [])]
                idx = 1
                while f"RULE_DENY_{idx:02d}" in all_kw_ids:
                    idx += 1
                rule_id = f"RULE_DENY_{idx:02d}"
                rule_dict = {
                    "rule_id": rule_id,
                    "rule_type": "KEYWORD",
                    "category": "JAILBREAK",
                    "severity": "CRITICAL",
                    "pattern": clean_phrase,
                    "description": "Added via Dashboard Keyword Deny List",
                    "is_active": True,
                }
                try:
                    run_sync(create_rule(rule_dict, admin_user))
                    st.success(f"Added \"{clean_phrase}\" as {rule_id}.")
                    st.rerun()
                except Exception as exc:
                    st.error(f"Failed to add keyword: {exc}")

        st.markdown('<div class="chips" style="margin-top:16px;">', unsafe_allow_html=True)
        chips_html = []
        for k in keywords:
            pat = k.get("pattern") or ""
            rid = k.get("rule_id") or ""
            chips_html.append(
                f'<span class="chip">{html.escape(pat)} <small style="color:var(--faint);font-size:10px;">({rid})</small></span>'
            )
        st.markdown("".join(chips_html) or '<span class="hint">No deny list phrases configured.</span>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

        if keywords:
            st.markdown('<div style="height:20px;"></div>', unsafe_allow_html=True)
            rem_opts = {k["rule_id"]: f"{k.get('pattern')}  ({k['rule_id']})" for k in keywords}
            picked_rem = st.selectbox("Select phrase to remove:", list(rem_opts.keys()), format_func=lambda x: rem_opts.get(x, x))
            if st.button("Remove phrase", key="btn_remove_deny_phrase"):
                try:
                    run_sync(delete_rule(picked_rem, admin_user))
                    st.success(f"Removed phrase {picked_rem}.")
                    st.rerun()
                except Exception as exc:
                    st.error(f"Failed to remove phrase: {exc}")

    # ------------------------------------------------------------------ TAB 4: Audit Log
    with tab_audit:
        st.markdown(
            """
            <div class="card">
              <h3>Admin audit log</h3>
              <p class="hint">Every configuration change, who made it and when.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        try:
            audit_records = run_sync(_fetch_audit_logs(limit=50))
        except Exception as exc:
            audit_records = []
            logger.warning(f"Could not fetch audit logs: {exc}")

        if audit_records:
            audit_html = []
            for r in audit_records:
                t = r.get("timestamp")
                t_str = t.strftime("%Y-%m-%d %H:%M") if hasattr(t, "strftime") else str(t)[:16]
                who = r.get("admin_user") or "admin"
                act = r.get("action") or "CHANGE"
                details = r.get("change_details") or {}
                target = r.get("target_rule_id") or ""
                msg = f"{act} {target}".strip()
                if act == "THRESHOLD_CHANGED":
                    mc = details.get("master_control")
                    if mc is not None:
                        state_lbl = "ON" if mc.get("current") else "OFF (Bypassed)"
                        reason_lbl = f" — Reason: {details.get('reason')}" if details.get("reason") else ""
                        msg = f"Switched Firewall Master Control to {state_lbl}{reason_lbl}"
                    elif "firewall_enabled" in str(details):
                        after_fe = details.get("after", {}).get("pipeline", {}).get("firewall_enabled")
                        state_lbl = "ON" if after_fe else "OFF (Bypassed)"
                        msg = f"Switched Firewall Master Control to {state_lbl}"
                    else:
                        msg = "Updated firewall runtime settings / thresholds"
                elif act == "RULE_CREATED":
                    msg = f"Created rule {target}"
                elif act == "RULE_UPDATED":
                    msg = f"Updated rule {target}"
                elif act == "RULE_DELETED":
                    msg = f"Deleted rule {target}"
                audit_html.append(
                    f'<li>'
                    f'<time class="mono">{html.escape(t_str)}</time>'
                    f'<span><b style="color:var(--gold-2)">{html.escape(who)}</b> — {html.escape(msg)}</span>'
                    f'</li>'
                )
            st.markdown(
                f'<ul class="audit mt">{"".join(audit_html)}</ul>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                '<div class="empty">No audit logs recorded yet.</div>',
                unsafe_allow_html=True,
            )


if __name__ == "__main__":
    main()
