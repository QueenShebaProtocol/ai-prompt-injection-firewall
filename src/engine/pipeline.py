"""
Inspection pipeline orchestrator - Week 2 scope.

Cascade: Layer 1 (deterministic) -> Layer 2 (ONNX classifier) -> threshold
decision. Layer 3 and the output scanner are integrated later; Layer 3 is a
stub for now.
"""

import logging
import os
import time
import uuid
from dataclasses import dataclass, field

import yaml

from src.engine.layer_1_deterministic import layer1_engine
from src.engine.layer_2_classifier import ClassifierUnavailable, get_classifier

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = os.getenv("FIREWALL_CONFIG_PATH", "config/firewall.yaml")


class PipelineConfigError(ValueError):
    """firewall.yaml is invalid. Startup must abort."""


@dataclass(frozen=True)
class PipelineConfig:
    layer_1_enabled: bool = True
    layer_2_enabled: bool = True
    layer_3_enabled: bool = True          
    high_confidence_threshold: float = 0.85
    low_confidence_threshold: float = 0.30
    max_context_turns: int = 5
    max_context_chars: int = 2000        

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


def _get_bool(section: dict, key: str, default: bool) -> bool:
    value = section.get(key, default)
    if not isinstance(value, bool):
        raise PipelineConfigError(f"'{key}' must be true or false, got {value!r}")
    return value


def _get_number(section: dict, key: str, default, kind=float):
    value = section.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PipelineConfigError(f"'{key}' must be a number, got {value!r}")
    return kind(value)


def load_pipeline_config(path) -> PipelineConfig:
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
    except FileNotFoundError as exc:
        raise PipelineConfigError(f"Config file not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise PipelineConfigError(f"Config file is not valid YAML: {exc}") from exc

    if not isinstance(raw, dict):
        raise PipelineConfigError("Config root must be a mapping")

    pipeline = raw.get("pipeline") or {}
    layer2 = raw.get("layer_2") or {}
    d = PipelineConfig()

    return PipelineConfig(
        layer_1_enabled=_get_bool(pipeline, "layer_1_enabled", d.layer_1_enabled),
        layer_2_enabled=_get_bool(pipeline, "layer_2_enabled", d.layer_2_enabled),
        layer_3_enabled=_get_bool(pipeline, "layer_3_enabled", d.layer_3_enabled),
        high_confidence_threshold=_get_number(layer2, "high_confidence_threshold", d.high_confidence_threshold),
        low_confidence_threshold=_get_number(layer2, "low_confidence_threshold", d.low_confidence_threshold),
        max_context_turns=_get_number(layer2, "max_context_turns", d.max_context_turns, int),
        max_context_chars=_get_number(layer2, "max_context_chars", d.max_context_chars, int),
    )


_config: PipelineConfig | None = None


def set_pipeline_config(cfg: PipelineConfig) -> None:
    global _config
    _config = cfg


def get_pipeline_config() -> PipelineConfig:
    global _config
    if _config is None:
        _config = load_pipeline_config(DEFAULT_CONFIG_PATH)
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
    decision: str = "PASS"              


def new_request_id() -> str:
    return str(uuid.uuid4())


def _ms_since(t0: float) -> float:
    return (time.perf_counter() - t0) * 1000


def _build_layer2_text(prompt: str, context, cfg: PipelineConfig) -> tuple[str, int]:
    """Earlier user turns (capped) + current prompt LAST. Returns (text, turns_used)."""
    turns = [t.strip() for t in (context or []) if isinstance(t, str) and t.strip()]
    if cfg.max_context_turns:
        turns = turns[-cfg.max_context_turns:]  
    else:
        turns = []
    turns = [t[: cfg.max_context_chars] for t in turns]
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
        # TEMPORARY: P4 replaces this with the real Layer 3 call on Wednesday.
        layer_details["layer_3"] = {"status": "pending_integration"}

    return PipelineResult(
        request_id=request_id, is_blocked=False, action_taken="PASSED",
        triggered_layer="NONE", risk_score=score, layer2_score=score,
        execution_time_ms=_ms_since(start), layer_details=layer_details,
        decision=decision,
    )