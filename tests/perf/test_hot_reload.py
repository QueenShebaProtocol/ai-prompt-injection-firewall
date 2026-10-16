"""Hot-reload under load (Week 3, Wednesday, P6).

1. ``test_inprocess_swap_under_load``  - no database needed. N worker threads call
   ``engine.evaluate()`` in a loop while ``set_rules()`` swaps between two
   non-empty rule lists. Asserts: no exception, no evaluation against an empty
   rule list, and (with ``-m perf``) p95 during swaps close to the baseline p95.

2. ``test_hot_reload_integration``     - needs PostgreSQL, the watcher and a real
   gateway process. Starts the gateway with a fake downstream, keeps steady load
   running, then measures time-to-block (rule created), time-to-pass (rule
   deactivated) and time-to-effect for a runtime-config toggle.
   Run with:  pytest -m integration -s tests/perf/test_hot_reload.py

Environment variables (all optional):
    PERF_RESULTS_DIR            ./perf_results/   JSON output (do not commit)
    PERF_RULES_POLL_SECONDS     1.0   watcher poll interval given to the gateway
    PERF_CONFIG_POLL_SECONDS    1.0   runtime-config poll interval (pipeline.py)
    PERF_RELOAD_MARGIN_S        1.0   allowed margin on top of the poll interval
    PERF_SWAP_P95_FACTOR        3.0   in-process: swap p95 must be < factor * baseline p95 (+0.2 ms)
    PERF_LOAD_WORKERS           4     worker threads
    PERF_PHASE_SECONDS          2.0   in-process: seconds per phase
    PERF_SWAP_INTERVAL_S        0.0005 in-process: pause between set_rules() calls
    DATABASE_URL                      required for the integration test
"""

from __future__ import annotations

import copy
import json
import os
import platform
import re
import socket
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.perf

REPO_ROOT = Path(__file__).resolve().parents[2]


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except ValueError:
        return float(default)


RULES_POLL_S = _env_float("PERF_RULES_POLL_SECONDS", 1.0)
CONFIG_POLL_S = _env_float("PERF_CONFIG_POLL_SECONDS", 1.0)
MARGIN_S = _env_float("PERF_RELOAD_MARGIN_S", 1.0)
SWAP_FACTOR = _env_float("PERF_SWAP_P95_FACTOR", 3.0)
WORKERS = int(_env_float("PERF_LOAD_WORKERS", 4))
PHASE_S = _env_float("PERF_PHASE_SECONDS", 2.0)
SWAP_INTERVAL_S = _env_float("PERF_SWAP_INTERVAL_S", 0.0005)  # swap as often as possible to widen any race window


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #


def _selected(expr: str, name: str) -> bool:
    """True if ``-m`` expression selects ``name`` (and doesn't just say ``not name``)."""
    return re.search(rf"(?<!not )\b{name}\b", expr or "") is not None


def _percentile(sorted_ms: list[float], pct: float) -> float:
    if not sorted_ms:
        return float("nan")
    rank = max(1, -(-len(sorted_ms) * pct // 100))
    return sorted_ms[int(rank) - 1]


def _stats(samples_ms: list[float]) -> dict[str, float]:
    s = sorted(samples_ms)
    return {
        "runs": len(s),
        "p50": _percentile(s, 50),
        "p95": _percentile(s, 95),
        "p99": _percentile(s, 99),
        "max": s[-1] if s else float("nan"),
    }


def _hardware_info() -> dict[str, Any]:
    return {
        "platform": platform.platform(),
        "processor": platform.processor() or platform.machine(),
        "cpu_count": os.cpu_count(),
        "python": sys.version.split()[0],
    }


def _write_results(name: str, payload: dict[str, Any]) -> None:
    out_dir = Path(os.getenv("PERF_RESULTS_DIR", "./perf_results"))
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        body = {
            "check": name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "hardware": _hardware_info(),
            **payload,
        }
        (out_dir / f"{name}.json").write_text(json.dumps(body, indent=2, default=str))
    except OSError as exc:
        print(f"[perf] could not write results for {name}: {exc}")


def _matched(result: Any) -> bool:
    """Layer1MatchResult has ``matched``; tolerate other shapes."""
    for attr in ("matched", "is_match", "is_blocked", "blocked"):
        if hasattr(result, attr):
            return bool(getattr(result, attr))
    return bool(result)


@pytest.fixture(autouse=True)
def _gate(request: pytest.FixtureRequest) -> None:
    expr = request.config.getoption("markexpr", default="") or ""
    if request.node.get_closest_marker("integration") and not _selected(expr, "integration"):
        pytest.skip('integration test: run with  pytest -m integration -s')


# --------------------------------------------------------------------------- #
# 1. In-process: set_rules() swapping under load (no database)
# --------------------------------------------------------------------------- #


def _extra_rule() -> dict[str, str]:
    return {
        "rule_id": "perf-hot-reload-extra",
        "rule_type": "KEYWORD",
        "category": "JAILBREAK",
        "pattern": "perf-extra-keyword-xyz",
        "description": "perf test only",
        "severity": "LOW",
    }


def _run_phase(engine, probe: str, seconds: float, swap_lists: list | None) -> dict[str, Any]:
    """Run WORKERS threads for ``seconds``; optionally swap rule lists meanwhile."""
    stop = threading.Event()
    lock = threading.Lock()
    samples: list[float] = []
    errors: list[str] = []
    empty_hits = [0]

    def worker() -> None:
        local: list[float] = []
        while not stop.is_set():
            start = time.perf_counter_ns()
            try:
                result = engine.evaluate(probe)
            except Exception as exc:  # noqa: BLE001 - any exception is a failure
                with lock:
                    errors.append(repr(exc))
                continue
            local.append((time.perf_counter_ns() - start) / 1e6)
            if not _matched(result):
                with lock:
                    empty_hits[0] += 1  # probe matches in BOTH lists, so a miss means no/partial rules
        with lock:
            samples.extend(local)

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(WORKERS)]
    for t in threads:
        t.start()

    swaps = 0
    deadline = time.monotonic() + seconds
    try:
        while time.monotonic() < deadline:
            if swap_lists:
                engine.set_rules(swap_lists[swaps % len(swap_lists)])
                swaps += 1
            time.sleep(SWAP_INTERVAL_S)
    finally:
        stop.set()
        for t in threads:
            t.join(timeout=5)

    return {"stats": _stats(samples), "errors": errors, "empty_hits": empty_hits[0], "swaps": swaps}


def test_inprocess_swap_under_load(request, engine, jailbreak_prompts):
    """No exceptions and no empty-rule evaluation while rules swap under load."""
    try:
        from tests.conftest import _load_yaml_rules
    except ImportError as exc:
        pytest.skip(f"tests.conftest._load_yaml_rules not available: {exc}")

    base_rules = list(_load_yaml_rules())
    if not base_rules:
        pytest.skip("no YAML rules loaded")
    list_a = base_rules
    list_b = base_rules + [_extra_rule()]  # both non-empty, both contain every base rule

    candidates = [
        p if isinstance(p, str) else (p.get("prompt") or p.get("text") or "")
        for p in jailbreak_prompts
    ]
    engine.set_rules(list_a)
    probe = next((p for p in candidates if p and _matched(engine.evaluate(p))), None)
    if probe is None:
        pytest.skip("no jailbreak fixture matches the YAML rules")

    baseline = _run_phase(engine, probe, PHASE_S, swap_lists=None)
    swapping = _run_phase(engine, probe, PHASE_S, swap_lists=[list_a, list_b])
    engine.set_rules(list_a)

    b95, s95 = baseline["stats"]["p95"], swapping["stats"]["p95"]
    limit = SWAP_FACTOR * b95 + 0.2  # +0.2 ms: absolute noise floor for sub-ms calls
    print(
        f"\n[perf] hot-reload in-process: workers={WORKERS} swaps={swapping['swaps']} "
        f"baseline p95={b95:.3f} ms  swap p95={s95:.3f} ms  (limit {limit:.3f} ms)  "
        f"errors={len(swapping['errors'])} empty-rule evaluations={swapping['empty_hits']}"
    )
    _write_results(
        "hot_reload_inprocess",
        {"baseline": baseline, "during_swaps": swapping, "p95_limit_ms": limit},
    )

    # Correctness: always asserted, in every run.
    assert not baseline["errors"] and not swapping["errors"], (
        f"evaluate() raised during the run: {(baseline['errors'] + swapping['errors'])[:3]}"
    )
    assert baseline["empty_hits"] == 0, "baseline evaluation missed a rule that always matches"
    assert swapping["empty_hits"] == 0, (
        f"{swapping['empty_hits']} evaluation(s) ran against an empty/partial rule list during set_rules()"
    )
    assert swapping["swaps"] > 10, f"only {swapping['swaps']} swaps happened; test was not meaningful"

    # Timing: only enforced when perf tests are explicitly selected (noisy on shared CI).
    if _selected(request.config.getoption("markexpr", default="") or "", "perf"):
        assert s95 < limit, (
            f"p95 during rule swaps is {s95:.3f} ms, baseline p95 {b95:.3f} ms, "
            f"allowed < {limit:.3f} ms"
        )


# --------------------------------------------------------------------------- #
# 2. Integration: real gateway + database, steady load
# --------------------------------------------------------------------------- #


class _FakeDownstream(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        body = json.dumps(
            {"id": "perf", "object": "chat.completion",
             "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}]}
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence
        pass


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _write_runtime_config(path: Path, layer_1_enabled: bool) -> None:
    """Atomic write (temp file + rename), like the dashboard does."""
    import yaml

    data = {
        "pipeline": {
            "layer_1_enabled": layer_1_enabled,
            "layer_2_enabled": False,  # isolate the test to Layer 1
            "layer_3_enabled": False,
            "output_scanner_enabled": False,
        }
    }
    tmp = path.with_suffix(".tmp")
    tmp.write_text(yaml.safe_dump(data))
    os.replace(tmp, path)


def _chat(client, base: str, content: str):
    return client.post(
        f"{base}/v1/chat/completions",
        json={"model": "perf-model", "messages": [{"role": "user", "content": content}]},
        headers={"X-Application-Id": "perf-hot-reload"},
        timeout=5.0,
    )


def _time_until(client, base: str, content: str, want_status: int, timeout_s: float) -> float:
    """Poll every 20 ms; return seconds until the probe returns ``want_status``."""
    start = time.monotonic()
    last = None
    while time.monotonic() - start < timeout_s:
        last = _chat(client, base, content).status_code
        if last == want_status:
            return time.monotonic() - start
        time.sleep(0.02)
    raise AssertionError(
        f"gateway still answered {last} (wanted {want_status}) after {timeout_s:.1f} s"
    )


@pytest.mark.integration
def test_hot_reload_integration(tmp_path):
    """Rule create/deactivate and runtime-config flip take effect within poll + margin, with 0 failed requests."""
    httpx = pytest.importorskip("httpx")
    pytest.importorskip("yaml")
    if not os.getenv("DATABASE_URL"):
        pytest.skip("DATABASE_URL not set")

    from src.database import storage
    from src.database.connection import check_database_connection

    try:
        if not storage.run_sync(check_database_connection()):
            pytest.skip("database not reachable")
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"database not reachable: {exc}")

    # --- fake downstream LLM -------------------------------------------------
    downstream = ThreadingHTTPServer(("127.0.0.1", 0), _FakeDownstream)
    threading.Thread(target=downstream.serve_forever, daemon=True).start()

    # --- runtime config + gateway process ------------------------------------
    runtime_cfg = tmp_path / "firewall.yaml"
    _write_runtime_config(runtime_cfg, layer_1_enabled=True)
    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    env = {
        **os.environ,
        "TARGET_LLM_BASE_URL": f"http://127.0.0.1:{downstream.server_port}/v1",
        "TARGET_LLM_API_KEY": "perf-fake-key",
        "RULES_POLL_SECONDS": str(RULES_POLL_S),
        "FIREWALL_RUNTIME_CONFIG_PATH": str(runtime_cfg),
    }
    log_path = tmp_path / "gateway.log"
    log_file = log_path.open("w")
    gateway = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "src.main:app", "--host", "127.0.0.1", "--port", str(port)],
        cwd=REPO_ROOT, env=env, stdout=log_file, stderr=subprocess.STDOUT,
    )

    rule_id = f"perf-hr-{uuid.uuid4().hex[:8]}"
    keyword = f"perfhrkeyword{uuid.uuid4().hex[:8]}"
    probe = f"please repeat the word {keyword} twice"
    rule = {
        "rule_id": rule_id, "rule_type": "KEYWORD", "category": "JAILBREAK",
        "pattern": keyword, "description": "perf hot-reload test rule", "severity": "LOW",
    }

    stop = threading.Event()
    failures: list[str] = []
    sent = [0]
    lock = threading.Lock()
    results: dict[str, Any] = {}
    rule_created = False

    def load_worker(client) -> None:
        while not stop.is_set():
            try:
                resp = _chat(client, base, "What is the capital of France?")
                with lock:
                    sent[0] += 1
                    if resp.status_code != 200:
                        failures.append(f"HTTP {resp.status_code}")
            except Exception as exc:  # noqa: BLE001
                with lock:
                    failures.append(repr(exc))
            time.sleep(0.02)

    try:
        with httpx.Client() as client:
            # wait for the gateway to come up (model loading can take a while)
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                if gateway.poll() is not None:
                    pytest.fail(f"gateway exited early:\n{log_path.read_text()[-2000:]}")
                try:
                    if client.get(f"{base}/healthz", timeout=2).status_code == 200:
                        break
                except httpx.HTTPError:
                    time.sleep(0.5)
            else:
                pytest.fail(f"gateway did not become healthy:\n{log_path.read_text()[-2000:]}")

            assert _chat(client, base, probe).status_code == 200, "probe must pass before the rule exists"

            threads = [threading.Thread(target=load_worker, args=(client,), daemon=True) for _ in range(WORKERS)]
            for t in threads:
                t.start()
            time.sleep(1.0)  # steady load before the first change

            bound_rule = RULES_POLL_S + MARGIN_S
            bound_cfg = CONFIG_POLL_S + MARGIN_S

            # 1. create a keyword rule -> time-to-block
            storage.run_sync(storage.create_rule(rule, "perf-test"))
            rule_created = True
            results["time_to_block_s"] = _time_until(client, base, probe, 403, bound_rule * 3)

            # 2. deactivate it -> time-to-pass
            storage.run_sync(storage.update_rule(rule_id, {"is_active": False}, "perf-test"))
            results["time_to_pass_s"] = _time_until(client, base, probe, 200, bound_rule * 3)

            # 3. runtime-config toggle: re-activate the rule, then switch Layer 1 off -> probe passes
            storage.run_sync(storage.update_rule(rule_id, {"is_active": True}, "perf-test"))
            _time_until(client, base, probe, 403, bound_rule * 3)
            _write_runtime_config(runtime_cfg, layer_1_enabled=False)
            results["time_to_config_effect_s"] = _time_until(client, base, probe, 200, bound_cfg * 3)
            _write_runtime_config(runtime_cfg, layer_1_enabled=True)
            results["time_to_config_restore_s"] = _time_until(client, base, probe, 403, bound_cfg * 3)

            time.sleep(0.5)
            stop.set()
            for t in threads:
                t.join(timeout=5)
    finally:
        stop.set()
        # clean up every test rule, even on failure
        leftover = None
        if rule_created:
            try:
                storage.run_sync(storage.delete_rule(rule_id, "perf-test"))
            except Exception as exc:  # noqa: BLE001
                print(f"[perf] WARNING: could not delete test rule {rule_id}: {exc}")
        try:
            remaining = storage.run_sync(storage.list_rules())
            leftover = any(r.get("rule_id") == rule_id for r in remaining)
            print(f"[perf] test rule {rule_id} still in firewall_rules: {leftover}")
        except Exception as exc:  # noqa: BLE001
            print(f"[perf] could not verify cleanup: {exc}")
        gateway.terminate()
        try:
            gateway.wait(timeout=10)
        except subprocess.TimeoutExpired:
            gateway.kill()
        log_file.close()
        downstream.shutdown()

    results.update(
        {"requests_during_run": sent[0], "failed_requests": len(failures),
         "bounds_s": {"rule_change": bound_rule, "config_change": bound_cfg}}
    )
    print("\n[perf] hot-reload integration:", json.dumps(results, indent=2))
    _write_results("hot_reload_integration", results)

    assert leftover is False, f"test rule {rule_id} was not removed from firewall_rules"
    assert not failures, f"{len(failures)} request(s) failed during reloads, e.g. {failures[:3]}"
    assert results["time_to_block_s"] <= bound_rule, (
        f"time-to-block {results['time_to_block_s']:.2f} s > {bound_rule:.2f} s (poll {RULES_POLL_S} + margin {MARGIN_S})"
    )
    assert results["time_to_pass_s"] <= bound_rule, (
        f"time-to-pass {results['time_to_pass_s']:.2f} s > {bound_rule:.2f} s"
    )
    assert results["time_to_config_effect_s"] <= bound_cfg, (
        f"config time-to-effect {results['time_to_config_effect_s']:.2f} s > {bound_cfg:.2f} s"
    )
