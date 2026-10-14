"""Configuration page: layer toggles, Layer 2 thresholds, rule CRUD (UI first).

Who can do what
- DASHBOARD_ADMIN_PASSWORD not set  -> the page is read-only and nothing can be saved.
- It is set, nobody signed in       -> only the sign-in form is shown.
- Signed in (admin name + password) -> everything below can be changed.
The password check is a shared password per browser session. It is not a user
system, and the failed-attempt lockout is per browser session only.

Data
Today all data lives in st.session_state through the small "seam" functions
(_load_rules, _create_rule, _update_rule, _delete_rule, _load_settings,
_save_settings). Each is marked TODO(P3, Wed): the real database and the
runtime config file are connected there. Nothing in this file touches the
network.

The page code runs inside main() so tests can import this file safely.
"""

from __future__ import annotations

import copy
import hmac
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterable

import streamlit as st

_DASHBOARD_DIR = Path(__file__).resolve().parents[1]
_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_DASHBOARD_DIR) not in sys.path:
    sys.path.insert(0, str(_DASHBOARD_DIR))

try:  # the shared dashboard shell (app.py); the page still works without it
    import app as _shell
except Exception:
    _shell = None

# ------------------------------------------------------------------ constants
ADMIN_PASSWORD_ENV = "DASHBOARD_ADMIN_PASSWORD"
MAX_NAME_LENGTH = 64
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 30

# TODO(P3, Wed): confirm these against the database enums in src/database/models.py.
RULE_TYPES = ("REGEX", "KEYWORD")
CATEGORIES = ("JAILBREAK", "PROMPT_LEAK", "SYSTEM_OVERRIDE", "PII", "SECRET")
SEVERITIES = ("LOW", "MEDIUM", "HIGH")
OUTPUT_ACTIONS = ("block", "redact", "warn")

MAX_PATTERN_LENGTH = 500
MAX_DESCRIPTION_LENGTH = 200
RULE_ID_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")
EDITABLE_FIELDS = ("rule_type", "category", "pattern", "description", "severity", "is_active")

LAYER_FLAGS = (
    ("layer_1_enabled", "Layer 1: deterministic rules (regex and keywords)"),
    ("layer_2_enabled", "Layer 2: ONNX classifier"),
    ("layer_3_enabled", "Layer 3: LLM evaluator"),
    ("output_scanner_enabled", "Output scanner"),
)

# Same keys as the runtime config overlay in the Week 3 contracts.
# TODO(P3, Wed): the real starting values come from the runtime config file.
DEFAULT_SETTINGS: dict[str, dict[str, Any]] = {
    "pipeline": {
        "layer_1_enabled": True,
        "layer_2_enabled": True,
        "layer_3_enabled": True,
        "output_scanner_enabled": True,
    },
    "layer_2": {"high_confidence_threshold": 0.90, "low_confidence_threshold": 0.50},
    "output_scanner": {"on_detect": "block"},
}


def _seed_rules() -> list[dict[str, Any]]:
    return [
        {"rule_id": "RULE_SYSTEM_OVERRIDE_01", "rule_type": "REGEX", "category": "SYSTEM_OVERRIDE",
         "pattern": r"ignore\s+(all\s+)?previous\s+instructions",
         "description": "Attempt to override earlier instructions", "severity": "HIGH", "is_active": True},
        {"rule_id": "RULE_DENY_01", "rule_type": "KEYWORD", "category": "JAILBREAK",
         "pattern": "disable your safety filters",
         "description": "Explicit request to turn off safety filtering", "severity": "HIGH", "is_active": True},
        {"rule_id": "RULE_DENY_02", "rule_type": "KEYWORD", "category": "PROMPT_LEAK",
         "pattern": "print your hidden instructions",
         "description": "Explicit request to dump hidden instructions", "severity": "HIGH", "is_active": True},
        {"rule_id": "RULE_DENY_03", "rule_type": "KEYWORD", "category": "SYSTEM_OVERRIDE",
         "pattern": "override system prompt",
         "description": "Explicit request to replace the system prompt", "severity": "HIGH", "is_active": True},
    ]


# --------------------------------------------------------- shell (app.py) glue
def _configure_page(title: str) -> None:
    fn = getattr(_shell, "configure_page", None)
    if fn:
        fn(title)
    else:
        st.set_page_config(page_title=title, layout="wide")


def _render_sidebar() -> dict:
    fn = getattr(_shell, "render_sidebar", None)
    return fn() if fn else {}


# -------------------------------------------------------------- admin sign-in
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
    """The shared admin password, or "" when it is not set. Never shown anywhere."""
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


def require_admin() -> str:
    """Return the signed-in admin's name, or "" when nobody is signed in."""
    expected = _admin_password()
    if not expected:
        st.warning(
            f"Read-only: {ADMIN_PASSWORD_ENV} is not set, so nothing can be saved. "
            "Set it and restart the dashboard to turn editing on."
        )
        return ""

    name = st.session_state.get("admin_user", "")
    if name:
        st.success(f"Signed in as {name}")
        if st.button("Sign out", key="cfg_sign_out"):
            st.session_state.pop("admin_user", None)
            st.rerun()
        return name

    remaining = _lockout_remaining()
    if remaining > 0:
        st.error(f"Too many wrong passwords. Try again in {remaining} seconds.")
        return ""

    st.info("Sign in to view and change the configuration.")
    with st.form("admin_login"):
        entered_name = st.text_input("Admin name")
        entered_password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Sign in")
    if submitted:
        clean = _clean_name(entered_name)
        if not clean:
            st.error(f"Enter your admin name (up to {MAX_NAME_LENGTH} characters).")
        elif _password_matches(entered_password, expected):
            st.session_state["_login_failures"] = 0
            st.session_state["admin_user"] = clean
            st.rerun()
        else:
            _register_failure()
            st.error("Wrong password.")
    return ""


# ----------------------------------------------------------------- validation
def validate_rule(rule: dict, existing_ids: Iterable[str] = (), is_new: bool = True) -> list[str]:
    """Return a list of clear problems. An empty list means the rule is valid."""
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
        except re.error as exc:
            errors.append(f"Pattern is not a valid regular expression: {exc}.")
        else:
            if compiled.search(""):
                errors.append("Pattern matches empty text, so it would block every prompt.")

    if len(description) > MAX_DESCRIPTION_LENGTH:
        errors.append(f"Description is {len(description)} characters long. The limit is {MAX_DESCRIPTION_LENGTH}.")
    if not isinstance(rule.get("is_active", True), bool):
        errors.append("Active must be true or false.")
    return errors


def validate_settings(settings: dict) -> list[str]:
    errors: list[str] = []
    pipeline = settings.get("pipeline", {})
    for flag, _label in LAYER_FLAGS:
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


def _describe_changes(old: dict, new: dict) -> list[str]:
    changes = []
    for section, values in new.items():
        for key, value in values.items():
            before = old.get(section, {}).get(key)
            if before != value:
                show = (lambda v: f"{v:.2f}" if isinstance(v, float) else str(v))
                changes.append(f"{section}.{key}: {show(before)} -> {show(value)}")
    return changes


def _next_deny_id(existing_ids: Iterable[str]) -> str:
    numbers = [int(m.group(1)) for rid in existing_ids if (m := re.match(r"^RULE_DENY_(\d+)$", rid))]
    return f"RULE_DENY_{(max(numbers) + 1 if numbers else 1):02d}"


# ---------------------------------------------------------- data seam (temp)
def _store(key: str, default_factory: Callable[[], Any]) -> Any:
    if key not in st.session_state:
        st.session_state[key] = default_factory()
    return st.session_state[key]


def _require_admin_user(admin_user: str) -> None:
    if not admin_user:
        raise PermissionError("Sign in as an admin to make changes.")


def _audit(admin_user: str, action: str, detail: str) -> None:
    # TODO(P3, Wed): the real audit row is written by storage.write_audit_log in the same transaction.
    _store("_cfg_audit", list).append(
        (datetime.now().strftime("%H:%M:%S"), admin_user, action, detail)
    )


def _load_rules(category: str | None = None, rule_type: str | None = None) -> list[dict]:
    # TODO(P3, Wed): wire to DB (storage.list_rules)
    rules = _store("_cfg_rules", _seed_rules)
    return [
        copy.deepcopy(r) for r in rules
        if (category is None or r["category"] == category)
        and (rule_type is None or r["rule_type"] == rule_type)
    ]


def _create_rule(rule: dict, admin_user: str) -> dict:
    # TODO(P3, Wed): wire to DB (storage.create_rule)
    _require_admin_user(admin_user)
    rules = _store("_cfg_rules", _seed_rules)
    errors = validate_rule(rule, [r["rule_id"] for r in rules], is_new=True)
    if errors:
        raise ValueError(" ".join(errors))
    created = {"rule_id": str(rule["rule_id"]).strip(), **{k: rule[k] for k in EDITABLE_FIELDS if k in rule}}
    created.setdefault("description", "")
    created.setdefault("is_active", True)
    rules.append(created)
    _audit(admin_user, "CREATE_RULE", created["rule_id"])
    return copy.deepcopy(created)


def _update_rule(rule_id: str, changes: dict, admin_user: str) -> dict:
    # TODO(P3, Wed): wire to DB (storage.update_rule)
    _require_admin_user(admin_user)
    rules = _store("_cfg_rules", _seed_rules)
    rule = next((r for r in rules if r["rule_id"] == rule_id), None)
    if rule is None:
        raise ValueError(f"Rule {rule_id} was not found.")
    allowed = {k: v for k, v in changes.items() if k in EDITABLE_FIELDS}
    errors = validate_rule({**rule, **allowed}, is_new=False)
    if errors:
        raise ValueError(" ".join(errors))
    rule.update(allowed)
    _audit(admin_user, "UPDATE_RULE", f"{rule_id}: {', '.join(sorted(allowed))}")
    return copy.deepcopy(rule)


def _delete_rule(rule_id: str, admin_user: str) -> None:
    # TODO(P3, Wed): wire to DB (storage.delete_rule)
    _require_admin_user(admin_user)
    rules = _store("_cfg_rules", _seed_rules)
    for index, rule in enumerate(rules):
        if rule["rule_id"] == rule_id:
            del rules[index]
            _audit(admin_user, "DELETE_RULE", rule_id)
            return
    raise ValueError(f"Rule {rule_id} was not found.")


def _load_settings() -> dict:
    # TODO(P3, Wed): wire to runtime config (the runtime copy of firewall.yaml)
    return copy.deepcopy(_store("_cfg_settings", lambda: copy.deepcopy(DEFAULT_SETTINGS)))


def _save_settings(settings: dict, admin_user: str) -> None:
    # TODO(P3, Wed): wire to runtime config (write the overlay keys, then write_audit_log)
    _require_admin_user(admin_user)
    errors = validate_settings(settings)
    if errors:
        raise ValueError(" ".join(errors))
    old = _load_settings()
    st.session_state["_cfg_settings"] = copy.deepcopy(settings)
    _audit(admin_user, "UPDATE_SETTINGS", "; ".join(_describe_changes(old, settings)) or "no changes")


# --------------------------------------------------------------- UI helpers
def _flash(level: str, text: str) -> None:
    _store("_cfg_flash", list).append((level, text))


def _show_flash() -> None:
    shown = {"success": st.success, "error": st.error, "warning": st.warning}
    for level, text in st.session_state.pop("_cfg_flash", []):
        shown.get(level, st.info)(text)


def _epoch() -> int:
    return int(st.session_state.get("_cfg_epoch", 0))


def _bump_epoch() -> None:
    """New widget keys after a save, so forms and confirm boxes start fresh."""
    st.session_state["_cfg_epoch"] = _epoch() + 1


def _attempt(action: str, func: Callable[..., Any], *args: Any) -> tuple[bool, str]:
    """Run a seam function. Never raises: returns (ok, error text)."""
    try:
        func(*args)
        return True, ""
    except (PermissionError, ValueError) as exc:
        return False, f"{action} failed: {exc}"
    except Exception as exc:
        return False, f"{action} failed: {type(exc).__name__}: {exc}"


def _show_errors(title: str, errors: list[str]) -> None:
    st.error(title + "\n\n" + "\n".join(f"- {e}" for e in errors))


def _index(options: tuple, value: Any, fallback: int = 0) -> int:
    return options.index(value) if value in options else fallback


def _rules_table(rules: list[dict]) -> None:
    if not rules:
        st.info("No rules match.")
        return
    st.dataframe(
        [
            {
                "Rule ID": r["rule_id"],
                "Type": r["rule_type"],
                "Category": r["category"],
                "Severity": r["severity"],
                "Active": "Yes" if r["is_active"] else "No",
                "Pattern": r["pattern"] if len(r["pattern"]) <= 80 else r["pattern"][:77] + "...",
                "Description": r["description"],
            }
            for r in rules
        ],
        hide_index=True,
    )


# ----------------------------------------------------- tab 1: layers + limits
def _discard_setting_edits() -> None:
    for key in [k for k in st.session_state if str(k).startswith("cfg_set_")]:
        del st.session_state[key]


def render_layers_tab(admin: str) -> None:
    can_edit = bool(admin)
    try:
        saved = _load_settings()
    except Exception as exc:
        st.error(f"Could not load the settings: {type(exc).__name__}: {exc}")
        return

    st.subheader("Protection layers")
    pipeline = {
        flag: st.toggle(label, value=bool(saved["pipeline"][flag]), key=f"cfg_set_{flag}", disabled=not can_edit)
        for flag, label in LAYER_FLAGS
    }

    st.subheader("Layer 2 thresholds")
    st.caption(
        "At or above the high threshold a prompt is blocked. Below the low threshold it passes. "
        "In between it goes to Layer 3."
    )
    low = st.slider("Low-confidence threshold", 0.0, 1.0,
                    value=float(saved["layer_2"]["low_confidence_threshold"]), step=0.01,
                    format="%.2f", key="cfg_set_low", disabled=not can_edit)
    high = st.slider("High-confidence threshold", 0.0, 1.0,
                     value=float(saved["layer_2"]["high_confidence_threshold"]), step=0.01,
                     format="%.2f", key="cfg_set_high", disabled=not can_edit)

    st.subheader("Output scanner")
    on_detect = st.selectbox(
        "When the scanner finds a leak",
        OUTPUT_ACTIONS,
        index=_index(OUTPUT_ACTIONS, saved["output_scanner"]["on_detect"]),
        key="cfg_set_on_detect",
        disabled=not can_edit,
        help="block: refuse the reply. redact: replace the leaked part. warn: let it through and log it.",
    )

    new = {
        "pipeline": pipeline,
        "layer_2": {"high_confidence_threshold": round(high, 2), "low_confidence_threshold": round(low, 2)},
        "output_scanner": {"on_detect": on_detect},
    }
    errors = validate_settings(new)
    if errors:
        _show_errors("These settings cannot be saved yet:", errors)

    needs_confirm = bool(saved["pipeline"]["layer_1_enabled"]) and not pipeline["layer_1_enabled"]
    confirmed = True
    if needs_confirm:
        st.warning("Layer 1 is the first line of defence. Turning it off removes all fixed regex and keyword rules.")
        confirmed = st.checkbox(
            "I understand and want to turn Layer 1 off",
            key=f"cfg_set_confirm_l1_{_epoch()}",
            disabled=not can_edit,
        )

    changes = _describe_changes(saved, new)
    blocked = (not can_edit) or bool(errors) or not confirmed
    save_col, discard_col = st.columns([1, 1])
    with save_col:
        save_pressed = st.button("Save settings", type="primary", disabled=blocked, key="cfg_set_save")
    with discard_col:
        st.button("Discard changes", disabled=not can_edit, key="cfg_set_discard", on_click=_discard_setting_edits)

    if save_pressed:
        if not changes:
            st.info("Nothing to save: the settings are unchanged.")
        else:
            ok, error = _attempt("Save settings", _save_settings, new, admin)
            if ok:
                _flash("success", "Saved " + str(len(changes)) + " change(s):\n\n" + "\n".join(f"- {c}" for c in changes))
                _bump_epoch()
                st.rerun()
            else:
                st.error(error)


# -------------------------------------------------------------- tab 2: rules
def _rule_fields(prefix: str, defaults: dict, lock_id: bool) -> dict:
    return {
        "rule_id": st.text_input("Rule ID", value=str(defaults.get("rule_id", "")), key=f"{prefix}_id",
                                 disabled=lock_id, help="Capital letters, digits and underscores, e.g. RULE_DENY_10"),
        "rule_type": st.selectbox("Type", RULE_TYPES, index=_index(RULE_TYPES, defaults.get("rule_type")), key=f"{prefix}_type"),
        "category": st.selectbox("Category", CATEGORIES, index=_index(CATEGORIES, defaults.get("category")), key=f"{prefix}_cat"),
        "severity": st.selectbox("Severity", SEVERITIES, index=_index(SEVERITIES, defaults.get("severity"), 2), key=f"{prefix}_sev"),
        "pattern": st.text_area("Pattern", value=str(defaults.get("pattern", "")), key=f"{prefix}_pat",
                                help=f"Up to {MAX_PATTERN_LENGTH} characters. A REGEX pattern must compile."),
        "description": st.text_input("Description", value=str(defaults.get("description", "")), key=f"{prefix}_desc"),
        "is_active": st.checkbox("Active", value=bool(defaults.get("is_active", True)), key=f"{prefix}_act"),
    }


def render_rules_tab(admin: str) -> None:
    can_edit = bool(admin)
    left, right = st.columns(2)
    with left:
        category = st.selectbox("Filter by category", ("All",) + CATEGORIES, key="cfg_rules_cat")
    with right:
        rule_type = st.selectbox("Filter by type", ("All",) + RULE_TYPES, key="cfg_rules_type")

    try:
        all_rules = _load_rules()
        shown = _load_rules(None if category == "All" else category, None if rule_type == "All" else rule_type)
    except Exception as exc:
        st.error(f"Could not load the rules: {type(exc).__name__}: {exc}")
        return
    _rules_table(shown)

    if not can_edit:
        st.info("Read-only. Sign in as an admin to add, edit, enable, disable or delete rules.")
        return

    ids = [r["rule_id"] for r in all_rules]
    epoch = _epoch()
    st.subheader("Manage rules")
    action = st.radio("Action", ("Add", "Edit", "Enable / disable", "Delete"), horizontal=True, key="cfg_rules_action")

    if action == "Add":
        with st.form(f"cfg_add_form_{epoch}"):
            values = _rule_fields(f"cfg_add_{epoch}", {"is_active": True, "rule_type": "KEYWORD", "category": CATEGORIES[0]}, False)
            submitted = st.form_submit_button("Add rule")
        if submitted:
            errors = validate_rule(values, ids, is_new=True)
            if errors:
                _show_errors("Rule not added:", errors)
            else:
                ok, error = _attempt("Add rule", _create_rule, values, admin)
                if ok:
                    _flash("success", f"Rule {values['rule_id'].strip()} was added.")
                    _bump_epoch()
                    st.rerun()
                else:
                    st.error(error)
        return

    if not ids:
        st.info("There are no rules yet.")
        return
    rule_id = st.selectbox("Rule", ids, key="cfg_rules_pick")
    rule = next(r for r in all_rules if r["rule_id"] == rule_id)

    if action == "Edit":
        with st.form(f"cfg_edit_form_{rule_id}_{epoch}"):
            values = _rule_fields(f"cfg_edit_{rule_id}_{epoch}", rule, True)
            submitted = st.form_submit_button("Save changes")
        if submitted:
            changes = {k: values[k] for k in EDITABLE_FIELDS if values[k] != rule[k]}
            if not changes:
                st.info("Nothing to save: the rule is unchanged.")
            else:
                errors = validate_rule({**rule, **changes}, is_new=False)
                if errors:
                    _show_errors(f"Rule {rule_id} not saved:", errors)
                else:
                    ok, error = _attempt("Save rule", _update_rule, rule_id, changes, admin)
                    if ok:
                        _flash("success", f"Rule {rule_id} was saved. Changed: {', '.join(sorted(changes))}.")
                        _bump_epoch()
                        st.rerun()
                    else:
                        st.error(error)

    elif action == "Enable / disable":
        now_active = bool(rule["is_active"])
        st.write(f"{rule_id} is currently **{'enabled' if now_active else 'disabled'}**.")
        if st.button("Disable rule" if now_active else "Enable rule", key=f"cfg_toggle_{rule_id}_{epoch}"):
            ok, error = _attempt("Update rule", _update_rule, rule_id, {"is_active": not now_active}, admin)
            if ok:
                _flash("success", f"Rule {rule_id} is now {'disabled' if now_active else 'enabled'}.")
                _bump_epoch()
                st.rerun()
            else:
                st.error(error)

    else:  # Delete
        st.warning(f"Deleting {rule_id} cannot be undone.")
        confirmed = st.checkbox(f"Yes, delete {rule_id}", key=f"cfg_del_confirm_{rule_id}_{epoch}")
        if st.button("Delete rule", disabled=not confirmed, key=f"cfg_delete_{rule_id}_{epoch}"):
            ok, error = _attempt("Delete rule", _delete_rule, rule_id, admin)
            if ok:
                _flash("success", f"Rule {rule_id} was deleted.")
                _bump_epoch()
                st.rerun()
            else:
                st.error(error)


# ----------------------------------------------------- tab 3: keyword deny list
def render_deny_list_tab(admin: str) -> None:
    can_edit = bool(admin)
    try:
        keywords = _load_rules(rule_type="KEYWORD")
        all_ids = [r["rule_id"] for r in _load_rules()]
    except Exception as exc:
        st.error(f"Could not load the deny list: {type(exc).__name__}: {exc}")
        return

    st.caption("Phrases that are always blocked. These are the KEYWORD rules, so they also appear on the Rules tab.")
    _rules_table(keywords)
    if not can_edit:
        st.info("Read-only. Sign in as an admin to add or remove phrases.")
        return

    epoch = _epoch()
    st.subheader("Add a phrase")
    with st.form(f"cfg_deny_add_{epoch}"):
        phrase = st.text_input("Phrase", key=f"cfg_deny_phrase_{epoch}")
        category = st.selectbox("Category", CATEGORIES, key=f"cfg_deny_cat_{epoch}")
        severity = st.selectbox("Severity", SEVERITIES, index=2, key=f"cfg_deny_sev_{epoch}")
        submitted = st.form_submit_button("Add to deny list")
    if submitted:
        clean = phrase.strip()
        rule = {
            "rule_id": _next_deny_id(all_ids), "rule_type": "KEYWORD", "category": category,
            "pattern": clean, "description": "Added from the dashboard deny list",
            "severity": severity, "is_active": True,
        }
        errors = validate_rule(rule, all_ids, is_new=True)
        if any(r["pattern"].strip().lower() == clean.lower() for r in keywords) and clean:
            errors.append("That phrase is already in the deny list.")
        if errors:
            _show_errors("Phrase not added:", errors)
        else:
            ok, error = _attempt("Add phrase", _create_rule, rule, admin)
            if ok:
                _flash("success", f"Added \"{clean}\" as {rule['rule_id']}.")
                _bump_epoch()
                st.rerun()
            else:
                st.error(error)

    st.subheader("Remove phrases")
    if not keywords:
        st.info("The deny list is empty.")
        return
    labels = {r["rule_id"]: f"{r['pattern']}  ({r['rule_id']})" for r in keywords}
    picked = st.multiselect("Phrases to remove", list(labels), format_func=labels.get, key=f"cfg_deny_pick_{epoch}")
    confirmed = st.checkbox("Yes, remove the selected phrases", key=f"cfg_deny_confirm_{epoch}")
    if st.button("Remove selected", disabled=not (picked and confirmed), key=f"cfg_deny_remove_{epoch}"):
        done, failed = [], []
        for rule_id in picked:
            ok, error = _attempt("Remove phrase", _delete_rule, rule_id, admin)
            (done if ok else failed).append(rule_id if ok else error)
        if done:
            _flash("success", "Removed: " + ", ".join(done) + ".")
        for error in failed:
            _flash("error", error)
        _bump_epoch()
        st.rerun()


# ----------------------------------------------------------------------- main
def _draw_tab(draw: Callable[[str], None], admin: str, name: str) -> None:
    """Draw one tab. A bug in one tab must not take the whole page down."""
    try:
        draw(admin)
    except Exception as exc:
        if type(exc).__name__ in ("RerunException", "StopException"):
            raise  # Streamlit's own control flow
        st.error(f"The {name} tab could not be shown: {type(exc).__name__}: {exc}")


def main() -> None:
    _configure_page("Configuration")
    _render_sidebar()

    st.title("Configuration")
    st.caption("Protection layers, Layer 2 thresholds, detection rules and the keyword deny list.")
    st.info(
        "Temporary data: changes are kept in this browser session only and do not reach the "
        "firewall yet. They are connected to the database and the runtime config on Wednesday."
    )

    admin = require_admin()
    if _admin_password() and not admin:
        return  # password is set and nobody is signed in: no access
    _show_flash()

    layers_tab, rules_tab, deny_tab = st.tabs(["Layers and thresholds", "Rules", "Keyword deny list"])
    with layers_tab:
        _draw_tab(render_layers_tab, admin, "layers")
    with rules_tab:
        _draw_tab(render_rules_tab, admin, "rules")
    with deny_tab:
        _draw_tab(render_deny_list_tab, admin, "deny list")

    audit = st.session_state.get("_cfg_audit", [])
    if audit:
        with st.expander(f"Changes made in this session ({len(audit)})"):
            st.dataframe(
                [{"Time": t, "Admin": a, "Action": act, "Detail": d} for t, a, act, d in reversed(audit)],
                hide_index=True,
            )


if __name__ == "__main__":
    main()
