"""
Inspection pipeline orchestrator - Week 2 scope.

Input side, run_pipeline():
    Layer 1 (deterministic) -> Layer 2 (ONNX classifier) -> threshold decision.
    Prompts in the ambiguous Layer 2 band are escalated to Layer 3 (local
    reasoning judge), which returns ALLOW, BLOCK or REDACT.

Output side, scan_output():
    Checks the LLM completion for system-prompt leakage and PII/secrets
    before it goes back to the client.

Exceptions: neither function swallows unexpected errors. handler.py owns the
fail-open / fail-closed policy (FIREWALL_FAIL_OPEN).

Note on scan_output: the Week 2 contract defines it here, but handler.py calls
it as `output_scanner.scan_output(...)`. The bottom of this module publishes it
under both names so each caller finds it.
"""

import inspect
import logging
import os
import time
import uuid
from dataclasses import dataclass, field

import yaml

from src.engine.layer_1_deterministic import layer1_engine
from src.engine import output_scanner as _output_scanner_module
from src.engine.layer_2_classifier import ClassifierUnavailable, get_classifier
from src.engine.layer_3_evaluator import Layer3Result, evaluate_layer3
from src.engine.output_scanner import (
    OutputScanResult,
    detect_pii,
    detect_system_prompt_leak,
)
import threading
...
from dataclasses import dataclass, field, fields

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = os.getenv("FIREWALL_CONFIG_PATH", "config/firewall.yaml")


class PipelineConfigError(ValueError):
    """firewall.yaml is invalid. Startup must abort."""


OUTPUT_ON_DETECT_CHOICES = frozenset({"block", "redact", "warn"})


@dataclass(frozen=True)
class PipelineConfig:
    layer_1_enabled: bool = True
    layer_2_enabled: bool = True
    layer_3_enabled: bool = True          
    high_confidence_threshold: float = 0.85
    low_confidence_threshold: float = 0.30
    max_context_turns: int = 5
    max_context_chars: int = 2000        
    output_scanner_enabled: bool = True
    output_on_detect: str = "redact"      # block | redact | warn

    def __post_init__(self):
        for name in ("high_confidence_threshold", "low_confidence_threshold"):
            value = getattr(self, name)
            if not 0.0 <= value <= 1.0:
                raise PipelineConfigError(f"{name} must be between 0.0 and 1.0, got {value}")
        if self.low_confidence_threshold >= self.high_confidence_threshold:
            raise PipelineConfigError(
                f"Invalid thresholds: low_confidence_threshold "
                f"({self.low_confidence_threshold}) must be strictly less than "
                f"high_confidence_threshold ({self.high_confidence_threshold})."
            )
        if self.max_context_turns < 0 or self.max_context_chars < 1:
            raise PipelineConfigError("max_context_turns must be >= 0 and max_context_chars >= 1")
        if self.output_on_detect not in OUTPUT_ON_DETECT_CHOICES:
            raise PipelineConfigError(
                f"output_scanner.on_detect must be one of "
                f"{sorted(OUTPUT_ON_DETECT_CHOICES)}, got {self.output_on_detect!r}"
            )


def _get_bool(section: dict, key: str, default: bool) -> bool:
    value = section.get(key, default)
    if not isinstance(value, bool):
        raise PipelineConfigError(f"'{key}' must be true or false, got {value!r}")
    return value


def _get_choice(section: dict, key: str, default: str, choices) -> str:
    value = section.get(key, default)
    if not isinstance(value, str) or value.strip().lower() not in choices:
        raise PipelineConfigError(f"'{key}' must be one of {sorted(choices)}, got {value!r}")
    return value.strip().lower()


def _get_number(section: dict, key: str, default, kind=float):
    value = section.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PipelineConfigError(f"'{key}' must be a number, got {value!r}")
    return kind(value)


# ----------------------------------------------------------------------
# Runtime config overlay (Week 3)
# ----------------------------------------------------------------------
# The dashboard writes a runtime copy of firewall.yaml (path in
# FIREWALL_RUNTIME_CONFIG_PATH). Only the keys below are honoured from it;
# everything else in that file is ignored.
RUNTIME_CONFIG_ENV = "FIREWALL_RUNTIME_CONFIG_PATH"
RUNTIME_POLL_SECONDS = 1.0
RUNTIME_OVERLAY_KEYS: dict[str, tuple[str, ...]] = {
    "pipeline": (
        "layer_1_enabled",
        "layer_2_enabled",
        "layer_3_enabled",
        "output_scanner_enabled",
    ),
    "layer_2": ("high_confidence_threshold", "low_confidence_threshold"),
    "output_scanner": ("on_detect",),
}


def _read_yaml_mapping(path, label: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
    except FileNotFoundError as exc:
        raise PipelineConfigError(f"{label} not found: {path}") from exc
    except UnicodeDecodeError as exc:
        raise PipelineConfigError(f"{label} is not valid UTF-8: {exc}") from exc
    except OSError as exc:
        raise PipelineConfigError(f"{label} could not be read: {exc}") from exc
    except yaml.YAMLError as exc:
        raise PipelineConfigError(f"{label} is not valid YAML: {exc}") from exc

    if not isinstance(raw, dict):
        raise PipelineConfigError(f"{label} root must be a mapping")
    return raw


def _read_runtime_overlay(path) -> dict:
    """Read the runtime file and keep only the whitelisted keys."""
    raw = _read_yaml_mapping(path, "Runtime config file")
    overlay: dict[str, dict] = {}
    ignored: list[str] = []

    for section, values in raw.items():
        allowed = RUNTIME_OVERLAY_KEYS.get(section)
        if allowed is None:
            ignored.append(str(section))
            continue
        if values is None:
            continue
        if not isinstance(values, dict):
            raise PipelineConfigError(f"Runtime config section '{section}' must be a mapping")
        kept = {k: v for k, v in values.items() if k in allowed}
        ignored.extend(f"{section}.{k}" for k in values if k not in allowed)
        if kept:
            overlay[section] = kept

    if ignored:  # the runtime file is a full copy of firewall.yaml, so this is normal
        logger.debug("Runtime config: ignoring keys that are not runtime-editable: %s",
                     sorted(ignored))
    return overlay


def _merge_overlay(raw: dict, overlay: dict) -> dict:
    merged = dict(raw)
    for section, values in overlay.items():
        base = merged.get(section) or {}
        if not isinstance(base, dict):
            raise PipelineConfigError(f"Config section '{section}' must be a mapping")
        merged[section] = {**base, **values}
    return merged


def load_pipeline_config(path, runtime_path=None) -> PipelineConfig:
    """Read firewall.yaml and overlay the runtime config file on top of it.

    runtime_path: None  -> use FIREWALL_RUNTIME_CONFIG_PATH if it is set;
                  ""    -> no overlay (packaged file only);
                  other -> that file. A missing overlay file is simply skipped.
    Raises PipelineConfigError for an invalid packaged OR runtime file.
    """
    raw = _read_yaml_mapping(path, "Config file")

    if runtime_path is None:
        runtime_path = os.getenv(RUNTIME_CONFIG_ENV, "")
    if runtime_path and os.path.exists(runtime_path):
        raw = _merge_overlay(raw, _read_runtime_overlay(runtime_path))

    pipeline = raw.get("pipeline") or {}
    layer2 = raw.get("layer_2") or {}
    scanner = raw.get("output_scanner") or {}
    d = PipelineConfig()

    return PipelineConfig(
        layer_1_enabled=_get_bool(pipeline, "layer_1_enabled", d.layer_1_enabled),
        layer_2_enabled=_get_bool(pipeline, "layer_2_enabled", d.layer_2_enabled),
        layer_3_enabled=_get_bool(pipeline, "layer_3_enabled", d.layer_3_enabled),
        high_confidence_threshold=_get_number(layer2, "high_confidence_threshold", d.high_confidence_threshold),
        low_confidence_threshold=_get_number(layer2, "low_confidence_threshold", d.low_confidence_threshold),
        max_context_turns=_get_number(layer2, "max_context_turns", d.max_context_turns, int),
        max_context_chars=_get_number(layer2, "max_context_chars", d.max_context_chars, int),
        output_scanner_enabled=_get_bool(pipeline, "output_scanner_enabled", d.output_scanner_enabled),
        output_on_detect=_get_choice(scanner, "on_detect", d.output_on_detect, OUTPUT_ON_DETECT_CHOICES),
    )


_config: PipelineConfig | None = None

# Runtime-file polling state
_runtime_lock = threading.Lock()
_runtime_signature: tuple | None = None   # (path, mtime_ns, size) of the last version we looked at
_runtime_next_check: float = 0.0          # time.monotonic() before which we do not look again


def _config_diff(old: PipelineConfig | None, new: PipelineConfig) -> str:
    if old is None:
        return "initial load"
    changes = [
        f"{f.name}: {getattr(old, f.name)!r} -> {getattr(new, f.name)!r}"
        for f in fields(PipelineConfig)
        if getattr(old, f.name) != getattr(new, f.name)
    ]
    return "; ".join(changes) or "no effective change"


def _refresh_runtime_config(force: bool = False) -> None:
    """Pick up changes to the runtime config file.

    Cheap: one os.stat, and at most once per RUNTIME_POLL_SECONDS. An invalid
    file is logged ONCE and ignored; the last good config stays in force. Never
    raises, because this runs on the request path.
    """
    global _config, _runtime_signature, _runtime_next_check

    path = os.getenv(RUNTIME_CONFIG_ENV, "")
    if not path:
        return
    if not force and time.monotonic() < _runtime_next_check:
        return

    with _runtime_lock:
        now = time.monotonic()
        if not force and now < _runtime_next_check:
            return
        _runtime_next_check = now + RUNTIME_POLL_SECONDS

        try:
            st = os.stat(path)
        except OSError:
            return  # no runtime file (yet): keep the current config

        signature = (path, st.st_mtime_ns, st.st_size)
        if signature == _runtime_signature:
            return
        _runtime_signature = signature  # remembered even if invalid, so it is logged once

        try:
            new_cfg = load_pipeline_config(DEFAULT_CONFIG_PATH, runtime_path=path)
        except Exception as exc:
            logger.error(
                "Runtime config %s was ignored; keeping the last good config. Reason: %s",
                path, exc,
            )
            return

        if new_cfg != _config:
            logger.info("Runtime config reloaded from %s (%s)", path, _config_diff(_config, new_cfg))
        _config = new_cfg  # one assignment: requests see the old or the new config, never a mix


def set_pipeline_config(cfg: PipelineConfig) -> None:
    global _config
    _config = cfg


def get_pipeline_config() -> PipelineConfig:
    global _config
    if _config is None:
        # Packaged file only first: if it is invalid, startup must abort.
        _config = load_pipeline_config(DEFAULT_CONFIG_PATH, runtime_path="")
        _refresh_runtime_config(force=True)
    else:
        _refresh_runtime_config()
    return _config


@dataclass
class PipelineResult:
    request_id: str
    is_blocked: bool
    action_taken: str          
    triggered_layer: str       
    risk_score: float | None
    detected_patterns: list = field(default_factory=list)
    execution_time_ms: float = 0.0
    layer_details: dict | None = None
    # --- Week 2 ---
    layer2_score: float | None = None
    sanitized_prompt: str | None = None   
    decision: str = "PASS"              # final decision: PASS | BLOCK | REDACT (ESCALATE only inside layer_details)


def new_request_id() -> str:
    return str(uuid.uuid4())


def _ms_since(t0: float) -> float:
    return (time.perf_counter() - t0) * 1000


def _capped_turns(context, cfg: PipelineConfig) -> list[str]:
    """Earlier user turns, cleaned and capped by count and length."""
    turns = [t.strip() for t in (context or []) if isinstance(t, str) and t.strip()]
    if cfg.max_context_turns:
        turns = turns[-cfg.max_context_turns:]  
    else:
        turns = []
    return [t[: cfg.max_context_chars] for t in turns]


def _build_layer2_text(prompt: str, context, cfg: PipelineConfig) -> tuple[str, int]:
    """Earlier user turns (capped) + current prompt LAST. Returns (text, turns_used)."""
    turns = _capped_turns(context, cfg)
    return "\n".join(turns + [prompt]), len(turns)


def _decide(score: float, cfg: PipelineConfig) -> str:
    if score >= cfg.high_confidence_threshold:
        return "BLOCK"
    if score <= cfg.low_confidence_threshold:
        return "PASS"
    return "ESCALATE"


async def _run_layer2(prompt, context, cfg, layer_details) -> float | None:
    """Return the score, or None if Layer 2 could not run (degraded mode)."""
    clf = get_classifier()
    if not clf.is_loaded:
        logger.warning("Layer 2 is enabled but the classifier is not loaded; "
                       "continuing with Layer 1 only.")
        layer_details["layer_2"] = {"status": "unavailable", "reason": "model_not_loaded"}
        return None

    text, turns_used = _build_layer2_text(prompt, context, cfg)
    try:
        res = await clf.predict_async(text)
    except ClassifierUnavailable as exc:
        logger.warning("Layer 2 failed (%s); continuing with Layer 1 only.", exc)
        layer_details["layer_2"] = {"status": "error", "reason": str(exc)}
        return None
    except Exception:
        logger.exception("Unexpected Layer 2 error; continuing with Layer 1 only.")
        layer_details["layer_2"] = {"status": "error", "reason": "unexpected_error"}
        return None

    layer_details["layer_2"] = {
        "status": "ok",
        "score": round(res.score, 4),
        "time_ms": round(res.latency_ms, 4),
        "context_turns": turns_used,
    }
    return res.score


_RATIONALE_MAX_CHARS = 300
_LAYER3_DECISIONS = frozenset({"ALLOW", "BLOCK", "REDACT"})


async def _escalate_to_layer3(
    prompt: str,
    system_instruction: str,
    context,
    cfg: PipelineConfig,
    score: float,
    request_id: str,
    start: float,
    layer_details: dict,
) -> PipelineResult:
    """Layer 2 was unsure: let the Layer 3 judge decide (or skip it if disabled).

    Fails closed: a REDACT with nothing to forward, or a decision we do not
    recognise, becomes a BLOCK.
    """
    if not cfg.layer_3_enabled:
        layer_details["layer_3"] = {"status": "disabled"}
        return PipelineResult(
            request_id=request_id, is_blocked=False, action_taken="PASSED",
            triggered_layer="NONE", risk_score=score, layer2_score=score,
            execution_time_ms=_ms_since(start), layer_details=layer_details,
            decision="PASS",
        )

    l3: Layer3Result = await evaluate_layer3(prompt, system_instruction, _capped_turns(context, cfg))
    decision = (l3.decision or "").strip().upper()

    details = {
        "status": "degraded" if l3.degraded else "ok",
        "decision": decision,                     # what Layer 3 actually answered
        "time_ms": round(l3.latency_ms, 4),
        "degraded": l3.degraded,
        "rationale": (l3.rationale or "")[:_RATIONALE_MAX_CHARS],
    }
    layer_details["layer_3"] = details
    if l3.degraded:
        logger.warning("Layer 3 degraded for request %s; fallback decision was %s.",
                       request_id, decision or "<empty>")

    if decision not in _LAYER3_DECISIONS:
        details["downgraded"] = "unknown_decision"
        decision = "BLOCK"
    elif decision == "REDACT" and not (l3.sanitized_prompt or "").strip():
        details["downgraded"] = "redact_without_sanitized_prompt"
        decision = "BLOCK"

    if decision == "BLOCK":
        return PipelineResult(
            request_id=request_id, is_blocked=True, action_taken="BLOCKED",
            triggered_layer="LAYER_3", risk_score=score, layer2_score=score,
            execution_time_ms=_ms_since(start), layer_details=layer_details,
            decision="BLOCK",
        )

    if decision == "REDACT":
        return PipelineResult(
            request_id=request_id, is_blocked=False, action_taken="REDACTED",
            triggered_layer="LAYER_3", risk_score=score, layer2_score=score,
            sanitized_prompt=l3.sanitized_prompt,
            execution_time_ms=_ms_since(start), layer_details=layer_details,
            decision="REDACT",
        )

    return PipelineResult(                        # ALLOW
        request_id=request_id, is_blocked=False, action_taken="PASSED",
        triggered_layer="LAYER_3", risk_score=score, layer2_score=score,
        execution_time_ms=_ms_since(start), layer_details=layer_details,
        decision="PASS",
    )


async def run_pipeline(
    prompt: str,
    system_instruction: str = "",
    context: list[str] | None = None,
    request_id: str | None = None,
) -> PipelineResult:
    request_id = request_id or new_request_id()
    cfg = get_pipeline_config()
    start = time.perf_counter()
    layer_details: dict = {}

    # ---------------- Layer 1 ----------------
    if cfg.layer_1_enabled:
        l1_start = time.perf_counter()
        l1 = layer1_engine.evaluate(prompt, system_instruction)
        layer_details["layer_1"] = {
            "matched": l1.matched,
            "rule_id": l1.rule_id,
            "category": l1.category,
            "severity": l1.severity,
            "time_ms": round(_ms_since(l1_start), 4),
        }
        if l1.matched:                      
            return PipelineResult(
                request_id=request_id, is_blocked=True, action_taken="BLOCKED",
                triggered_layer="LAYER_1", risk_score=1.0,
                detected_patterns=l1.patterns, execution_time_ms=_ms_since(start),
                layer_details=layer_details, decision="BLOCK",
            )

    # ---------------- Layer 2 ----------------
    score = None
    if cfg.layer_2_enabled:
        score = await _run_layer2(prompt, context, cfg, layer_details)

    if score is None:                       
        return PipelineResult(
            request_id=request_id, is_blocked=False, action_taken="PASSED",
            triggered_layer="NONE", risk_score=0.0, execution_time_ms=_ms_since(start),
            layer_details=layer_details, decision="PASS",
        )

    decision = _decide(score, cfg)
    layer_details["layer_2"]["decision"] = decision

    if decision == "BLOCK":
        return PipelineResult(
            request_id=request_id, is_blocked=True, action_taken="BLOCKED",
            triggered_layer="LAYER_2", risk_score=score, layer2_score=score,
            execution_time_ms=_ms_since(start), layer_details=layer_details,
            decision="BLOCK",
        )

    if decision == "ESCALATE":
        return await _escalate_to_layer3(
            prompt, system_instruction, context, cfg, score, request_id, start, layer_details,
        )

    return PipelineResult(
        request_id=request_id, is_blocked=False, action_taken="PASSED",
        triggered_layer="NONE", risk_score=score, layer2_score=score,
        execution_time_ms=_ms_since(start), layer_details=layer_details,
        decision=decision,
    )


# ======================================================================
# Output side
# ======================================================================
async def scan_output(
    completion_text: str,
    system_instruction: str,
    request_id: str,
) -> OutputScanResult:
    """Scan an LLM completion for system-prompt leakage and PII/secrets.

    Returns OutputScanResult(flagged, categories, spans, action) where action
    is PASS when nothing was found, otherwise the configured
    output_scanner.on_detect policy (BLOCK | REDACT | WARN).

    Never logs the completion or the matched text, only counts and categories.
    Errors from the detectors are not swallowed; handler.py applies the
    FIREWALL_FAIL_OPEN policy.
    """
    cfg = get_pipeline_config()
    if not cfg.output_scanner_enabled:
        return OutputScanResult(flagged=False, action="PASS")

    spans = list(detect_system_prompt_leak(completion_text, system_instruction))

    # detect_pii loads its rules from the database, so it is async. Accept a
    # plain list too, so a sync detector (or a test double) keeps working.
    pii_spans = detect_pii(completion_text)
    if inspect.isawaitable(pii_spans):
        pii_spans = await pii_spans
    spans.extend(pii_spans)

    spans.sort(key=lambda sp: (sp.start, sp.end))
    flagged = bool(spans)
    categories = sorted({sp.category for sp in spans})
    action = cfg.output_on_detect.upper() if flagged else "PASS"

    if flagged:
        logger.warning(
            "Output scanner flagged request %s: %d span(s), categories=%s, action=%s",
            request_id, len(spans), categories, action,
        )

    return OutputScanResult(flagged=flagged, categories=categories, spans=spans, action=action)


# handler.py calls output_scanner.scan_output(...); the contract defines the
# function in this module. Publish it on the scanner module too.
_output_scanner_module.scan_output = scan_output




