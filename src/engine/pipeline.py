"""
Inspection pipeline orchestrator — Week 1 scope.

Only Layer 1 (deterministic engine) runs this week. Layer 2, Layer 3,
and the output scanner are added in Week 2 — do not import them here.
"""

import time
import uuid
from dataclasses import dataclass, field

from src.engine.layer_1_deterministic import layer1_engine


@dataclass
class PipelineResult:
    request_id: str
    is_blocked: bool
    action_taken: str          # "PASSED" or "BLOCKED"
    triggered_layer: str       # "NONE" or "LAYER_1"
    risk_score: float | None
    detected_patterns: list = field(default_factory=list)
    execution_time_ms: float = 0.0
    layer_details: dict | None = None


def new_request_id() -> str:
    return str(uuid.uuid4())


async def run_pipeline(
    prompt: str,
    system_instruction: str = "",
    request_id: str | None = None,
) -> PipelineResult:
    """
    Run the Week 1 pipeline (Layer 1 only) and return the decision,
    along with timing and rule-match details for logging.
    """
    request_id = request_id or new_request_id()
    start = time.perf_counter()

    result = layer1_engine.evaluate(prompt, system_instruction)

    elapsed_ms = (time.perf_counter() - start) * 1000

    layer_details = {
        "layer_1": {
            "matched": result.matched,
            "rule_id": result.rule_id,
            "category": result.category,
            "severity": result.severity,
            "time_ms": round(elapsed_ms, 4),
        }
    }

    if result.matched:
        return PipelineResult(
            request_id=request_id,
            is_blocked=True,
            action_taken="BLOCKED",
            triggered_layer="LAYER_1",
            risk_score=1.0,
            detected_patterns=result.patterns,
            execution_time_ms=elapsed_ms,
            layer_details=layer_details,
        )

    return PipelineResult(
        request_id=request_id,
        is_blocked=False,
        action_taken="PASSED",
        triggered_layer="NONE",
        risk_score=0.0,
        detected_patterns=[],
        execution_time_ms=elapsed_ms,
        layer_details=layer_details,
    )