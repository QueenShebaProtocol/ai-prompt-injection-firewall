import time
import uuid
from dataclasses import dataclass, field

from fastapi import APIRouter, BackgroundTasks, Request
from fastapi.responses import JSONResponse

from src.database.storage import write_threat_log
from src.engine.layer_1_deterministic import layer1_engine
from src.proxy.forwarder import forward_to_llm

router = APIRouter()


@dataclass
class InspectionOutcome:
    blocked: bool
    matched_rule_ids: list[str] = field(default_factory=list)
    execution_time_ms: float = 0.0
    detected_patterns: list[str] = field(default_factory=list)


def _content_to_text(content) -> str:
    """Convert OpenAI message content to plain text."""
    if content is None:
        return ""

    if isinstance(content, str):
        return content

    if isinstance(content, list):
        parts = []

        for part in content:
            if isinstance(part, dict) and part.get("type") == "text":
                text = part.get("text")
                if isinstance(text, str):
                    parts.append(text)

        return "\n".join(parts)

    return ""


def _extract_prompt_and_system(body: dict) -> tuple[str, str]:
    """Extract the latest user prompt and all system instructions."""
    messages = body.get("messages") or []

    prompt = ""
    system_parts: list[str] = []

    # Collect all system messages.
    for message in messages:
        if isinstance(message, dict) and message.get("role") == "system":
            text = _content_to_text(message.get("content"))

            if text:
                system_parts.append(text)

    # Find the latest user message.
    for message in reversed(messages):
        if isinstance(message, dict) and message.get("role") == "user":
            prompt = _content_to_text(message.get("content"))
            break

    return prompt, "\n".join(system_parts)


def _inspect(prompt: str, system_instruction: str) -> InspectionOutcome:
    # TODO(P5, Fri): replace with run_pipeline

    start = time.perf_counter()

    result = layer1_engine.evaluate(
        prompt,
        system_instruction,
    )

    elapsed_ms = (time.perf_counter() - start) * 1000.0

    matched = bool(result.matched)

    return InspectionOutcome(
        blocked=matched,
        matched_rule_ids=(
            [result.rule_id]
            if matched and result.rule_id
            else []
        ),
        execution_time_ms=elapsed_ms,
        detected_patterns=(
            list(result.patterns or [])
            if matched
            else []
        ),
    )


@router.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok"}


@router.post("/v1/chat/completions")
async def chat_completions(
    request: Request,
    background_tasks: BackgroundTasks,
):
    body = await request.json()

    request_id = str(uuid.uuid4())

    client_ip = (
        request.client.host
        if request.client
        else "unknown"
    )

    application_id = request.headers.get(
        "X-Application-Id",
        "unknown",
    )

    target_model = body.get("model") or "unknown"

    prompt, system_instruction = _extract_prompt_and_system(body)

    outcome = _inspect(
        prompt,
        system_instruction,
    )

    log_entry = {
        "request_id": request_id,
        "client_ip": client_ip,
        "application_id": application_id,
        "target_model": target_model,
        "raw_prompt": prompt,
        "system_instruction": system_instruction,
        "is_blocked": outcome.blocked,
        "action_taken": (
            "blocked"
            if outcome.blocked
            else "allowed"
        ),
        "triggered_layer": (
            "layer_1"
            if outcome.blocked
            else None
        ),

        # TODO(P5, Fri): replace temporary risk score
        # with PipelineResult.risk_score.
        "risk_score": (
            1.0
            if outcome.blocked
            else 0.0
        ),

        "execution_time_ms": outcome.execution_time_ms,
        "detected_patterns": outcome.detected_patterns,
    }

    background_tasks.add_task(
        write_threat_log,
        log_entry,
    )

    if outcome.blocked:
        return JSONResponse(
            status_code=403,
            content={
                "detail": "Request blocked by security policy"
            },
        )

    return await forward_to_llm(body)
