# """OpenAI-compatible proxy endpoint.

# Flow: validate -> inspect (pipeline) -> block or forward -> respond.

# Every response from the chat endpoint, success or error, carries the header
# X-Firewall-Request-Id. Errors always have one shape:

#     {"error": {"type": ..., "code": ..., "message": ..., "request_id": ...}}

# Error bodies are deliberately generic: they never contain rule IDs, patterns,
# stack traces or downstream details. Those stay in the server log and in
# `threat_logs`.
# """

# import logging
# import os
# import time

# import httpx
# from fastapi import APIRouter, BackgroundTasks, Request
# from fastapi.responses import JSONResponse

# from src.database.storage import write_threat_log
# from src.engine.pipeline import PipelineResult, new_request_id, run_pipeline
# from src.proxy.forwarder import forward_to_llm

# logger = logging.getLogger("firewall.handler")

# router = APIRouter()

# REQUEST_ID_HEADER = "X-Firewall-Request-Id"


# def _content_to_text(content) -> str:
#     """Convert OpenAI message content to plain text."""
#     if content is None:
#         return ""

#     if isinstance(content, str):
#         return content

#     if isinstance(content, list):
#         parts = []

#         for part in content:
#             if isinstance(part, dict) and part.get("type") == "text":
#                 text = part.get("text")
#                 if isinstance(text, str):
#                     parts.append(text)

#         return "\n".join(parts)

#     return ""


# def _extract_prompt_and_system(body: dict) -> tuple[str, str]:
#     """Extract the latest user prompt and all system instructions."""
#     messages = body.get("messages") or []

#     prompt = ""
#     system_parts: list[str] = []

#     # Collect all system messages
#     for message in messages:
#         if isinstance(message, dict) and message.get("role") == "system":
#             text = _content_to_text(message.get("content"))

#             if text:
#                 system_parts.append(text)

#     # Find the latest user message
#     for message in reversed(messages):
#         if isinstance(message, dict) and message.get("role") == "user":
#             prompt = _content_to_text(message.get("content"))
#             break

#     return prompt, "\n".join(system_parts)



#                    # Response helpers
# # ---------------------------------------------------------------------------
# def _fail_open_enabled() -> bool:
#     """FIREWALL_FAIL_OPEN=true lets requests through if inspection crashes.

#     Read on every request (not at import time) so it can be changed in tests.
#     The default is fail-closed.
#     """
#     return os.environ.get("FIREWALL_FAIL_OPEN", "false").strip().lower() == "true"


# def _respond(status_code: int, content, request_id: str) -> JSONResponse:
#     """Every response goes through here so the request-id header is never missed."""
#     return JSONResponse(
#         status_code=status_code,
#         content=content,
#         headers={REQUEST_ID_HEADER: request_id},
#     )


# def _error(
#     status_code: int,
#     err_type: str,
#     code: str,
#     message: str,
#     request_id: str,
#     **extra,
# ) -> JSONResponse:
#     error = {
#         "type": err_type,
#         "code": code,
#         "message": message,
#         "request_id": request_id,
#     }
#     error.update(extra)
#     return _respond(status_code, {"error": error}, request_id)


# def _validate_body(body) -> tuple[str, str] | None:
#     """Return (code, message) for the first problem found, or None if valid."""
#     if not isinstance(body, dict):
#         return "invalid_request", "Request body must be a JSON object."

#     messages = body.get("messages")
#     if not isinstance(messages, list) or not messages:
#         return "invalid_request", "'messages' must be a non-empty list."

#     if body.get("stream") is True:
#         return (
#             "streaming_not_supported",
#             "Streaming responses are not supported yet. "
#             'Send the request without "stream": true.',
#         )

#     return None


#               # Log entry helpers (columns of the threat_logs table)
# # ---------------------------------------------------------------------------
# def _log_entry_from_result(base: dict, result: PipelineResult) -> dict:
#     return {
#         **base,
#         "is_blocked": result.is_blocked,
#         "action_taken": result.action_taken,
#         "triggered_layer": result.triggered_layer,
#         # threat_logs.risk_score is NOT NULL, but PipelineResult allows None.
#         "risk_score": result.risk_score if result.risk_score is not None else 0.0,
#         "execution_time_ms": result.execution_time_ms,
#         "layer_details": result.layer_details,
#         "detected_patterns": list(result.detected_patterns or []),
#     }


# def _log_entry_pipeline_failure(base: dict, *, blocked: bool, elapsed_ms: float) -> dict:
#     return {
#         **base,
#         "is_blocked": blocked,
#         "action_taken": "BLOCKED" if blocked else "PASSED",
#         "triggered_layer": "NONE",
#         "risk_score": 0.0,
#         "execution_time_ms": elapsed_ms,
#         "layer_details": {
#             "error": (
#                 "pipeline_failure_fail_closed"
#                 if blocked
#                 else "pipeline_failure_fail_open"
#             )
#         },
#         "detected_patterns": [],
#     }



#                           # Endpoints
# # ---------------------------------------------------------------------------
# @router.get("/healthz")
# async def healthz() -> dict:
#     return {"status": "ok"}


# @router.post("/v1/chat/completions")
# async def chat_completions(
#     request: Request,
#     background_tasks: BackgroundTasks,
# ):
#     # The id exists before anything can fail, so even a successful request carries one.
#     request_id = new_request_id()

#     # 1. First the  request is validated .
#     try:
#         body = await request.json()
#     except ValueError:  # includes json.JSONDecodeError and UnicodeDecodeError
#         return _error(
#             400,
#             "invalid_request_error",
#             "invalid_json",
#             "Request body must be valid JSON.",
#             request_id,
#         )

#     problem = _validate_body(body)
#     if problem is not None:
#         code, message = problem
#         return _error(400, "invalid_request_error", code, message, request_id)

#     client_ip = request.client.host if request.client else "unknown"
#     application_id = request.headers.get("X-Application-Id", "unknown")
#     target_model = body.get("model") or "unknown"

#     prompt, system_instruction = _extract_prompt_and_system(body)

#     base_log = {
#         "request_id": request_id,
#         "client_ip": client_ip,
#         "application_id": application_id,
#         "target_model": target_model,
#         "raw_prompt": prompt,
#         "system_instruction": system_instruction,
#     }

#     # 2. Inspect - If the pipeline itself crashes,fail closed unless the operator explicitly chose fail-open.

#     start = time.perf_counter()
#     try:
#         result = await run_pipeline(
#             prompt,
#             system_instruction,
#             request_id=request_id,
#         )
#     except Exception:
#         elapsed_ms = (time.perf_counter() - start) * 1000.0
#         logger.exception("Pipeline failure for request_id=%s", request_id)

#         if not _fail_open_enabled():
#             background_tasks.add_task(
#                 write_threat_log,
#                 _log_entry_pipeline_failure(base_log, blocked=True, elapsed_ms=elapsed_ms),
#             )
#             return _error(
#                 503,
#                 "firewall_error",
#                 "inspection_unavailable",
#                 "The request could not be inspected. Please try again later.",
#                 request_id,
#             )

#         logger.error(
#             "FIREWALL_FAIL_OPEN is on: forwarding request_id=%s without inspection",
#             request_id,
#         )
#         background_tasks.add_task(
#             write_threat_log,
#             _log_entry_pipeline_failure(base_log, blocked=False, elapsed_ms=elapsed_ms),
#         )
#     else:
#         # Logged in the background so the client never waits for the database
#         background_tasks.add_task(
#             write_threat_log,
#             _log_entry_from_result(base_log, result),
#         )

#         # 3. Blocked, Rule IDs and patterns stay in threat_logs.
#         if result.is_blocked:
#             return _error(
#                 403,
#                 "prompt_injection_blocked",
#                 "prompt_injection_blocked",
#                 "Request blocked by security policy.", #generic messages only
#                 request_id,
#                 triggered_layer=result.triggered_layer,
#             )

#     # 4. Forward. httpx.TimeoutException is a kind of httpx.RequestError, so it
#     #   MUST be caught first, otherwise a timeout would be reported as a 502.
#     try:
#         completion = await forward_to_llm(body)
#     except httpx.HTTPStatusError as exc:
#         logger.warning(
#             "Downstream returned HTTP %s for request_id=%s",
#             exc.response.status_code,
#             request_id,
#         )
#         return _error(
#             502,
#             "downstream_error",
#             "downstream_llm_error",
#             "The downstream model returned an error.",
#             request_id,
#         )
#     except httpx.TimeoutException:
#         logger.warning("Downstream timeout for request_id=%s", request_id)
#         return _error(
#             504,
#             "downstream_error",
#             "downstream_timeout",
#             "The downstream model did not respond in time.",
#             request_id,
#         )
#     except httpx.RequestError:
#         logger.warning("Downstream unreachable for request_id=%s", request_id)
#         return _error(
#             502,
#             "downstream_error",
#             "downstream_unreachable",
#             "The downstream model could not be reached.",
#             request_id,
#         )
#     except Exception:
#         # Anything unexpected (for example a non-JSON reply) - no details to the client.
#         logger.exception("Unexpected forwarding error for request_id=%s", request_id)
#         return _error(
#             500,
#             "firewall_error",
#             "internal_error",
#             "An unexpected error occurred.",
#             request_id,
#         )

#     return _respond(200, completion, request_id)





















"""OpenAI-compatible proxy endpoint.

Flow: validate -> inspect (pipeline) -> block or forward (the sanitized request
if Layer 3 redacted the prompt) -> scan the completion -> apply the output
policy -> respond.

Every response from the chat endpoint, success or error, carries the header
X-Firewall-Request-Id. Errors always have one shape:

    {"error": {"type": ..., "code": ..., "message": ..., "request_id": ...}}

Error bodies are deliberately generic: they never contain rule IDs, patterns,
stack traces, downstream details or any text from a completion. Those stay in
the server log and in `threat_logs`.
"""

import copy
import inspect
import logging
import os
import time

import httpx
from fastapi import APIRouter, BackgroundTasks, Request
from fastapi.responses import JSONResponse

from src.database.storage import write_threat_log
from src.engine import output_scanner
from src.engine.output_scanner import OutputScanResult, redact_completion_payload
from src.engine.pipeline import PipelineResult, new_request_id, run_pipeline
from src.proxy.forwarder import forward_to_llm

logger = logging.getLogger("firewall.handler")

router = APIRouter()

REQUEST_ID_HEADER = "X-Firewall-Request-Id"
ACTION_HEADER = "X-Firewall-Action"


# ---------------------------------------------------------------------------
# Request helpers
# ---------------------------------------------------------------------------
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

   
    for message in reversed(messages):
        if isinstance(message, dict) and message.get("role") == "user":
            prompt = _content_to_text(message.get("content"))
            break

    return prompt, "\n".join(system_parts)


def _replace_text_content(content, new_text: str):
    """String content -> the new string. List of parts -> the first text part
    carries the new text, other text parts are dropped (the sanitized prompt
    already covers them), and non-text parts (images...) are kept untouched."""
    if not isinstance(content, list):
        return new_text

    new_parts = []
    placed = False
    for part in content:
        if isinstance(part, dict) and part.get("type") == "text":
            if not placed:
                new_parts.append({**part, "text": new_text})
                placed = True
        else:
            new_parts.append(part)
    if not placed:
        new_parts.insert(0, {"type": "text", "text": new_text})
    return new_parts


def _build_sanitized_body(body: dict, sanitized_prompt: str) -> dict:
    """Copy of the request with the LAST user message replaced. The original
    body is never changed: the log still needs the raw prompt."""
    new_body = copy.deepcopy(body)
    for message in reversed(new_body.get("messages") or []):
        if isinstance(message, dict) and message.get("role") == "user":
            message["content"] = _replace_text_content(
                message.get("content"), sanitized_prompt
            )
            break
    return new_body


def _completion_text(completion) -> str:
    """Text of choices[0].message.content, or "" when there is none."""
    if not isinstance(completion, dict):
        return ""
    choices = completion.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    first = choices[0]
    message = first.get("message") if isinstance(first, dict) else None
    content = message.get("content") if isinstance(message, dict) else None
    return content if isinstance(content, str) else ""


async def _scan_completion(
    completion: dict, system_instruction: str, request_id: str
) -> OutputScanResult:
    text = _completion_text(completion)
    if not text:
        return OutputScanResult()  
    scan = output_scanner.scan_output(text, system_instruction, request_id)
    if inspect.isawaitable(scan): 
        scan = await scan
    return scan



def _fail_open_enabled() -> bool:
    """FIREWALL_FAIL_OPEN=true lets requests through if inspection crashes.

    Read on every request (not at import time) so it can be changed in tests.
    The default is fail-closed.
    """
    return os.environ.get("FIREWALL_FAIL_OPEN", "false").strip().lower() == "true"


def _respond(
    status_code: int, content, request_id: str, action: str | None = None
) -> JSONResponse:
    """Every response goes through here so the request-id header is never missed."""
    headers = {REQUEST_ID_HEADER: request_id}
    if action:
        headers[ACTION_HEADER] = action
    return JSONResponse(status_code=status_code, content=content, headers=headers)


def _error(
    status_code: int,
    err_type: str,
    code: str,
    message: str,
    request_id: str,
    *,
    action: str | None = None,
    **extra,
) -> JSONResponse:
    error = {
        "type": err_type,
        "code": code,
        "message": message,
        "request_id": request_id,
    }
    error.update(extra)
    return _respond(status_code, {"error": error}, request_id, action)


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


def _log_entry_with_output(
    entry: dict, scan: OutputScanResult, *, input_redacted: bool
) -> dict:
    """Final threat_logs row: input stage + output stage in one."""
    out = dict(entry)
    details = dict(out.get("layer_details") or {})
    details["output_scanner"] = {
        "action": scan.action,
        "categories": list(scan.categories),  
    }
    out["layer_details"] = details
    out["output_flagged"] = bool(scan.flagged)

    if scan.action == "BLOCK":
        out["is_blocked"] = True
        out["action_taken"] = "BLOCKED"
        out["triggered_layer"] = "OUTPUT_SCANNER"
    elif scan.action == "REDACT":
        out["action_taken"] = "REDACTED"
        out["triggered_layer"] = "OUTPUT_SCANNER"
    elif input_redacted:
        out["action_taken"] = "REDACTED"
    return out


def _log_entry_scanner_failure(
    entry: dict, *, blocked: bool, input_redacted: bool
) -> dict:
    out = dict(entry)
    details = dict(out.get("layer_details") or {})
    details["output_scanner"] = {
        "error": "scanner_failure_fail_closed" if blocked else "scanner_failure_fail_open"
    }
    out["layer_details"] = details
    if blocked:
        out["is_blocked"] = True
        out["action_taken"] = "BLOCKED"
        out["triggered_layer"] = "OUTPUT_SCANNER"
    elif input_redacted:
        out["action_taken"] = "REDACTED"
    return out


@router.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok"}


@router.post("/v1/chat/completions")
async def chat_completions(
    request: Request,
    background_tasks: BackgroundTasks,
):
 
    request_id = new_request_id()

   
    try:
        body = await request.json()
    except ValueError: 
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

 
    start = time.perf_counter()
    result = None
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
                action="BLOCKED",
            )

        logger.error(
            "FIREWALL_FAIL_OPEN is on: forwarding request_id=%s without inspection",
            request_id,
        )
        log_entry = _log_entry_pipeline_failure(
            base_log, blocked=False, elapsed_ms=elapsed_ms
        )
    else:
        log_entry = _log_entry_from_result(base_log, result)

 
        if result.is_blocked:
            background_tasks.add_task(write_threat_log, log_entry)
            return _error(
                403,
                "prompt_injection_blocked",
                "prompt_injection_blocked",
                "Request blocked by security policy.", 
                request_id,
                action="BLOCKED",
                triggered_layer=result.triggered_layer,
            )

    input_redacted = bool(result is not None and result.sanitized_prompt)
    forward_body = body
    if input_redacted:
        forward_body = _build_sanitized_body(body, result.sanitized_prompt)


    try:
        completion = await forward_to_llm(forward_body)
    except httpx.HTTPStatusError as exc:
        background_tasks.add_task(write_threat_log, log_entry)
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
        background_tasks.add_task(write_threat_log, log_entry)
        logger.warning("Downstream timeout for request_id=%s", request_id)
        return _error(
            504,
            "downstream_error",
            "downstream_timeout",
            "The downstream model did not respond in time.",
            request_id,
        )
    except httpx.RequestError:
        background_tasks.add_task(write_threat_log, log_entry)
        logger.warning("Downstream unreachable for request_id=%s", request_id)
        return _error(
            502,
            "downstream_error",
            "downstream_unreachable",
            "The downstream model could not be reached.",
            request_id,
        )
    except Exception:
  
        background_tasks.add_task(write_threat_log, log_entry)
        logger.exception("Unexpected forwarding error for request_id=%s", request_id)
        return _error(
            500,
            "firewall_error",
            "internal_error",
            "An unexpected error occurred.",
            request_id,
        )


    try:
        scan = await _scan_completion(completion, system_instruction, request_id)
        if scan.action == "REDACT":
            completion = redact_completion_payload(completion, {0: scan.spans})
    except Exception:
        logger.exception("Output scanner failure for request_id=%s", request_id)

        if not _fail_open_enabled():
            background_tasks.add_task(
                write_threat_log,
                _log_entry_scanner_failure(
                    log_entry, blocked=True, input_redacted=input_redacted
                ),
            )
            return _error(
                503,
                "firewall_error",
                "output_inspection_unavailable",
                "The response could not be inspected. Please try again later.",
                request_id,
                action="BLOCKED",
            )

        logger.error(
            "FIREWALL_FAIL_OPEN is on: returning request_id=%s without output inspection",
            request_id,
        )
        final_entry = _log_entry_scanner_failure(
            log_entry, blocked=False, input_redacted=input_redacted
        )
        background_tasks.add_task(write_threat_log, final_entry)
        return _respond(200, completion, request_id, final_entry["action_taken"])


    final_entry = _log_entry_with_output(log_entry, scan, input_redacted=input_redacted)
    background_tasks.add_task(write_threat_log, final_entry)

    if scan.action == "BLOCK":

        return _error(
            403,
            "output_blocked",
            "output_blocked",
            "Response blocked by security policy.",
            request_id,
            action="BLOCKED",
        )


    return _respond(200, completion, request_id, final_entry["action_taken"])