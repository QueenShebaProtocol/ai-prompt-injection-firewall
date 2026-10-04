"""OpenAI-compatible proxy endpoint.

Flow: validate -> inspect (pipeline) -> block or forward -> respond.

Every response from the chat endpoint, success or error, carries the header
X-Firewall-Request-Id. Errors always have one shape:

    {"error": {"type": ..., "code": ..., "message": ..., "request_id": ...}}

Error bodies are deliberately generic: they never contain rule IDs, patterns,
stack traces or downstream details. Those stay in the server log and in
`threat_logs`.
"""

import logging
import os
import time

import httpx
from fastapi import APIRouter, BackgroundTasks, Request
from fastapi.responses import JSONResponse

from src.database.storage import write_threat_log
from src.engine.pipeline import PipelineResult, new_request_id, run_pipeline
from src.proxy.forwarder import forward_to_llm

logger = logging.getLogger("firewall.handler")

router = APIRouter()

REQUEST_ID_HEADER = "X-Firewall-Request-Id"


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

    # Collect all system messages
    for message in messages:
        if isinstance(message, dict) and message.get("role") == "system":
            text = _content_to_text(message.get("content"))

            if text:
                system_parts.append(text)

    # Find the latest user message
    for message in reversed(messages):
        if isinstance(message, dict) and message.get("role") == "user":
            prompt = _content_to_text(message.get("content"))
            break

    return prompt, "\n".join(system_parts)



                   # Response helpers
# ---------------------------------------------------------------------------
def _fail_open_enabled() -> bool:
    """FIREWALL_FAIL_OPEN=true lets requests through if inspection crashes.

    Read on every request (not at import time) so it can be changed in tests.
    The default is fail-closed.
    """
    return os.environ.get("FIREWALL_FAIL_OPEN", "false").strip().lower() == "true"


def _respond(status_code: int, content, request_id: str) -> JSONResponse:
    """Every response goes through here so the request-id header is never missed."""
    return JSONResponse(
        status_code=status_code,
        content=content,
        headers={REQUEST_ID_HEADER: request_id},
    )


def _error(
    status_code: int,
    err_type: str,
    code: str,
    message: str,
    request_id: str,
    **extra,
) -> JSONResponse:
    error = {
        "type": err_type,
        "code": code,
        "message": message,
        "request_id": request_id,
    }
    error.update(extra)
    return _respond(status_code, {"error": error}, request_id)


def _validate_body(body) -> tuple[str, str] | None:
    """Return (code, message) for the first problem found, or None if valid."""
    if not isinstance(body, dict):
        return "invalid_request", "Request body must be a JSON object."

    messages = body.get("messages")
    if not isinstance(messages, list) or not messages:
        return "invalid_request", "'messages' must be a non-empty list."

    if body.get("stream") is True:
        return (
            "streaming_not_supported",
            "Streaming responses are not supported yet. "
            'Send the request without "stream": true.',
        )

    return None


              # Log entry helpers (columns of the threat_logs table)
# ---------------------------------------------------------------------------
def _log_entry_from_result(base: dict, result: PipelineResult) -> dict:
    return {
        **base,
        "is_blocked": result.is_blocked,
        "action_taken": result.action_taken,
        "triggered_layer": result.triggered_layer,
        # threat_logs.risk_score is NOT NULL, but PipelineResult allows None.
        "risk_score": result.risk_score if result.risk_score is not None else 0.0,
        "execution_time_ms": result.execution_time_ms,
        "layer_details": result.layer_details,
        "detected_patterns": list(result.detected_patterns or []),
    }


def _log_entry_pipeline_failure(base: dict, *, blocked: bool, elapsed_ms: float) -> dict:
    return {
        **base,
        "is_blocked": blocked,
        "action_taken": "BLOCKED" if blocked else "PASSED",
        "triggered_layer": "NONE",
        "risk_score": 0.0,
        "execution_time_ms": elapsed_ms,
        "layer_details": {
            "error": (
                "pipeline_failure_fail_closed"
                if blocked
                else "pipeline_failure_fail_open"
            )
        },
        "detected_patterns": [],
    }



                          # Endpoints
# ---------------------------------------------------------------------------
@router.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok"}


@router.post("/v1/chat/completions")
async def chat_completions(
    request: Request,
    background_tasks: BackgroundTasks,
):
    # The id exists before anything can fail, so even a successful request carries one.
    request_id = new_request_id()

    # 1. First the  request is validated .
    try:
        body = await request.json()
    except ValueError:  # includes json.JSONDecodeError and UnicodeDecodeError
        return _error(
            400,
            "invalid_request_error",
            "invalid_json",
            "Request body must be valid JSON.",
            request_id,
        )

    problem = _validate_body(body)
    if problem is not None:
        code, message = problem
        return _error(400, "invalid_request_error", code, message, request_id)

    client_ip = request.client.host if request.client else "unknown"
    application_id = request.headers.get("X-Application-Id", "unknown")
    target_model = body.get("model") or "unknown"

    prompt, system_instruction = _extract_prompt_and_system(body)

    base_log = {
        "request_id": request_id,
        "client_ip": client_ip,
        "application_id": application_id,
        "target_model": target_model,
        "raw_prompt": prompt,
        "system_instruction": system_instruction,
    }

    # 2. Inspect - If the pipeline itself crashes,fail closed unless the operator explicitly chose fail-open.

    start = time.perf_counter()
    try:
        result = await run_pipeline(
            prompt,
            system_instruction,
            request_id=request_id,
        )
    except Exception:
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        logger.exception("Pipeline failure for request_id=%s", request_id)

        if not _fail_open_enabled():
            background_tasks.add_task(
                write_threat_log,
                _log_entry_pipeline_failure(base_log, blocked=True, elapsed_ms=elapsed_ms),
            )
            return _error(
                503,
                "firewall_error",
                "inspection_unavailable",
                "The request could not be inspected. Please try again later.",
                request_id,
            )

        logger.error(
            "FIREWALL_FAIL_OPEN is on: forwarding request_id=%s without inspection",
            request_id,
        )
        background_tasks.add_task(
            write_threat_log,
            _log_entry_pipeline_failure(base_log, blocked=False, elapsed_ms=elapsed_ms),
        )
    else:
        # Logged in the background so the client never waits for the database
        background_tasks.add_task(
            write_threat_log,
            _log_entry_from_result(base_log, result),
        )

        # 3. Blocked, Rule IDs and patterns stay in threat_logs.
        if result.is_blocked:
            return _error(
                403,
                "prompt_injection_blocked",
                "prompt_injection_blocked",
                "Request blocked by security policy.", #generic messages only
                request_id,
                triggered_layer=result.triggered_layer,
            )

    # 4. Forward. httpx.TimeoutException is a kind of httpx.RequestError, so it
    #   MUST be caught first, otherwise a timeout would be reported as a 502.
    try:
        completion = await forward_to_llm(body)
    except httpx.HTTPStatusError as exc:
        logger.warning(
            "Downstream returned HTTP %s for request_id=%s",
            exc.response.status_code,
            request_id,
        )
        return _error(
            502,
            "downstream_error",
            "downstream_llm_error",
            "The downstream model returned an error.",
            request_id,
        )
    except httpx.TimeoutException:
        logger.warning("Downstream timeout for request_id=%s", request_id)
        return _error(
            504,
            "downstream_error",
            "downstream_timeout",
            "The downstream model did not respond in time.",
            request_id,
        )
    except httpx.RequestError:
        logger.warning("Downstream unreachable for request_id=%s", request_id)
        return _error(
            502,
            "downstream_error",
            "downstream_unreachable",
            "The downstream model could not be reached.",
            request_id,
        )
    except Exception:
        # Anything unexpected (for example a non-JSON reply) - no details to the client.
        logger.exception("Unexpected forwarding error for request_id=%s", request_id)
        return _error(
            500,
            "firewall_error",
            "internal_error",
            "An unexpected error occurred.",
            request_id,
        )

    return _respond(200, completion, request_id)
