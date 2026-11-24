"""Client-IP blocklist: address normalisation and the gateway's refusal path.

Needs no database: the blocklist lookup and the log writer are replaced by fakes.
"""
import asyncio
import json
from types import SimpleNamespace

import pytest

from src.database.storage import normalize_client_ip
from src.proxy import handler


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("172.20.0.1", "172.20.0.1"),
        ("  10.0.4.22 ", "10.0.4.22"),
        ("::ffff:10.0.0.5", "10.0.0.5"),
        ("2001:DB8::1", "2001:db8::1"),
    ],
)
def test_normalize_accepts_single_addresses(raw, expected):
    assert normalize_client_ip(raw) == expected


@pytest.mark.parametrize("raw", ["", "unknown", "1.2.3", "1.2.3.4/24", "999.1.1.1", "a b"])
def test_normalize_rejects_everything_else(raw):
    with pytest.raises(ValueError):
        normalize_client_ip(raw)


class _FakeTasks:
    def __init__(self):
        self.added = []

    def add_task(self, fn, *args, **kwargs):
        self.added.append((fn, args, kwargs))


def _request():
    return SimpleNamespace(headers={"X-Application-Id": "shop"})


def _run(client_ip, blocked, monkeypatch, tasks=None):
    async def fake_blocked():
        if isinstance(blocked, Exception):
            raise blocked
        return set(blocked)

    monkeypatch.setattr(handler, "get_blocked_ips", fake_blocked)
    handler._blocked_last_logged.clear()
    tasks = tasks or _FakeTasks()
    resp = asyncio.run(handler._refuse_if_ip_blocked(client_ip, "req-1", _request(), tasks))
    return resp, tasks


def test_blocked_ip_gets_generic_403_and_one_log_row(monkeypatch):
    resp, tasks = _run("172.20.0.1", {"172.20.0.1"}, monkeypatch)
    assert resp.status_code == 403
    body = json.loads(resp.body)
    assert body["error"]["code"] == "client_blocked"
    assert "172.20.0.1" not in resp.body.decode()  # generic: no IP echoed back
    assert len(tasks.added) == 1
    entry = tasks.added[0][1][0]
    assert entry["is_blocked"] is True and entry["action_taken"] == "BLOCKED"
    assert "[not stored" in entry["raw_prompt"]  # the prompt text is never stored


def test_repeat_requests_do_not_flood_the_log(monkeypatch):
    resp, tasks = _run("172.20.0.1", {"172.20.0.1"}, monkeypatch)
    for _ in range(5):
        asyncio.run(handler._refuse_if_ip_blocked("172.20.0.1", "req-n", _request(), tasks))
    assert len(tasks.added) == 1


def test_unlisted_ip_passes_through(monkeypatch):
    resp, tasks = _run("10.0.4.22", {"172.20.0.1"}, monkeypatch)
    assert resp is None and tasks.added == []


def test_unknown_client_address_is_not_blockable(monkeypatch):
    resp, _ = _run("unknown", {"unknown"}, monkeypatch)
    assert resp is None


def test_lookup_failure_never_stops_traffic(monkeypatch):
    resp, _ = _run("172.20.0.1", RuntimeError("db down"), monkeypatch)
    assert resp is None
