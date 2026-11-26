import asyncio
import json

import httpx
from fastapi import FastAPI

from src.proxy import handler
from src.proxy.admission import RequestAdmissionController


def test_token_bucket_enforces_burst_refill_and_separate_clients():
    limiter = RequestAdmissionController(
        requests_per_minute=60,
        burst=2,
        max_in_flight=1,
    )

    assert limiter.consume_token("192.0.2.1", now=10.0) is None
    assert limiter.consume_token("192.0.2.1", now=10.0) is None
    assert limiter.consume_token("192.0.2.1", now=10.0) == 1
    assert limiter.consume_token("192.0.2.2", now=10.0) is None
    assert limiter.consume_token("192.0.2.1", now=11.0) is None


def test_request_route_returns_429_and_retry_after(monkeypatch):
    limiter = RequestAdmissionController(
        requests_per_minute=60,
        burst=1,
        max_in_flight=1,
    )
    monkeypatch.setattr(handler, "admission_controller", limiter)
    app = FastAPI()
    app.include_router(handler.router)

    async def send_requests():
        transport = httpx.ASGITransport(
            app=app,
            client=("192.0.2.10", 50000),
        )
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://firewall.test",
        ) as client:
            first = await client.post("/v1/chat/completions", json={})
            second = await client.post("/v1/chat/completions", json={})
        return first, second

    first, second = asyncio.run(send_requests())

    assert first.status_code == 400
    assert second.status_code == 429
    assert second.headers["retry-after"] == "1"
    assert json.loads(second.content)["error"]["code"] == "rate_limit_exceeded"


def test_request_route_returns_503_when_capacity_is_full(monkeypatch):
    limiter = RequestAdmissionController(
        requests_per_minute=60,
        burst=1,
        max_in_flight=1,
    )
    assert limiter.try_acquire()
    monkeypatch.setattr(handler, "admission_controller", limiter)
    app = FastAPI()
    app.include_router(handler.router)

    async def send_request():
        transport = httpx.ASGITransport(
            app=app,
            client=("192.0.2.11", 50001),
        )
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://firewall.test",
        ) as client:
            return await client.post("/v1/chat/completions", json={})

    try:
        response = asyncio.run(send_request())
    finally:
        limiter.release()

    assert response.status_code == 503
    assert response.headers["retry-after"] == "1"
    assert json.loads(response.content)["error"]["code"] == "server_overloaded"


def test_request_route_releases_capacity_after_early_response(monkeypatch):
    limiter = RequestAdmissionController(
        requests_per_minute=60,
        burst=1,
        max_in_flight=1,
    )
    monkeypatch.setattr(handler, "admission_controller", limiter)
    app = FastAPI()
    app.include_router(handler.router)

    async def send_requests():
        responses = []
        for ip in ("192.0.2.12", "192.0.2.13"):
            transport = httpx.ASGITransport(app=app, client=(ip, 50002))
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://firewall.test",
            ) as client:
                responses.append(
                    await client.post("/v1/chat/completions", json={})
                )
        return responses

    first, second = asyncio.run(send_requests())

    assert first.status_code == 400
    assert second.status_code == 400


def test_invalid_admission_environment_is_rejected(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_REQUESTS_PER_MINUTE", "0")

    try:
        RequestAdmissionController.from_environment()
    except ValueError as exc:
        assert "RATE_LIMIT_REQUESTS_PER_MINUTE" in str(exc)
    else:
        raise AssertionError("invalid rate limit should fail configuration")
