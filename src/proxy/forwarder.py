"""Transparent forwarding to the downstream LLM provider.

This module owns the single outbound network call in the firewall: once a
request has been cleared by the inspection pipeline, `handler.py` calls
`forward_to_llm` to relay it to the real LLM provider (OpenAI, Gemini, a
local model, etc.) and get its completion back.

Design notes
------------
- One shared `httpx.AsyncClient` per process (see `get_http_client`) so
  connections are pooled and reused instead of re-negotiated per request.
- This module never catches exceptions. `forward_to_llm` can raise:
    * httpx.HTTPStatusError  - downstream returned a 4xx/5xx
      (because `raise_for_status()` is called on the response)
    * httpx.TimeoutException - the request did not complete within
      DOWNSTREAM_TIMEOUT_SECONDS
    * httpx.RequestError     - any other transport-level failure
      (DNS failure, connection refused, etc.)
  `handler.py` is responsible for catching these and translating them into
  HTTP responses for the client.
- Never log the API key or the request payload. The payload may contain
  the end user's prompt; the key is a secret credential. Neither belongs
  in application logs (SRS 8.2: secrets must never be logged in plaintext).
"""

import os

import httpx

# --- Environment configuration (read once, at import time) -----------------
#
# A trailing slash on TARGET_LLM_BASE_URL is stripped so that building the
# request URL below never produces a double slash, regardless of how the
# operator wrote it in .env.
TARGET_LLM_BASE_URL: str = os.environ.get(
    "TARGET_LLM_BASE_URL", "https://api.openai.com/v1"
).rstrip("/")
TARGET_LLM_API_KEY: str = os.environ.get("TARGET_LLM_API_KEY", "")
DOWNSTREAM_TIMEOUT_SECONDS: float = float(
    os.environ.get("DOWNSTREAM_TIMEOUT_SECONDS", "30")
)

# --- Shared client -----------------------------------------------------------

_client: httpx.AsyncClient | None = None


def get_http_client() -> httpx.AsyncClient:
    """Return the process-wide `httpx.AsyncClient`, creating it on first use.

    A single client is reused across requests so that TCP/TLS connections
    to the downstream provider are pooled instead of re-established on
    every call.
    """
    global _client
    if _client is None:
        _client = httpx.AsyncClient(timeout=DOWNSTREAM_TIMEOUT_SECONDS)
    return _client


async def close_http_client() -> None:
    """Close the shared client. Call this once, on application shutdown."""
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


# --- Forwarding ---------------------------------------------------------------


async def forward_to_llm(payload: dict) -> dict:
    """Send a cleared request to the downstream LLM and return its JSON reply.

    Args:
        payload: The request body to forward as-is (e.g. an OpenAI-compatible
            chat completion request).

    Returns:
        The downstream provider's JSON response, decoded into a dict.

    Raises:
        httpx.HTTPStatusError: the downstream provider returned a 4xx/5xx
            status code.
        httpx.TimeoutException: the request did not complete within
            DOWNSTREAM_TIMEOUT_SECONDS.
        httpx.RequestError: any other transport-level failure (DNS
            resolution, connection refused, etc.).

    This function does not catch any of the above - callers (`handler.py`)
    are expected to catch them and translate them into client-facing HTTP
    responses.
    """
    client = get_http_client()
    response = await client.post(
        f"{TARGET_LLM_BASE_URL}/chat/completions",
        json=payload,
        headers={
            "Authorization": f"Bearer {TARGET_LLM_API_KEY}",
            "Content-Type": "application/json",
        },
    )
    response.raise_for_status()
    return response.json()