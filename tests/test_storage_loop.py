"""run_sync() keeps every database call on ONE event loop.

No database needed: LoopBound behaves like an asyncpg pool. It belongs to the
first loop that uses it and refuses to be used from any other loop.
"""

import asyncio
import threading
import time

import pytest

from src.database import storage


class LoopBound:
    def __init__(self):
        self.loop = None

    async def use(self):
        current = asyncio.get_running_loop()
        if self.loop is None:
            self.loop = current
        elif self.loop is not current:
            raise RuntimeError("Future attached to a different loop")
        await asyncio.sleep(0.01)  # yield, so calls really interleave
        return threading.current_thread().name


def _in_threads(fn, n=20):
    """Run fn in n threads that all start at the same moment."""
    barrier = threading.Barrier(n)
    results, errors = [], []

    def worker():
        try:
            barrier.wait(timeout=5)
            results.append(fn())
        except Exception as exc:  # noqa: BLE001 - collected for the assertions
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)
    return results, errors


def _kill_loop():
    old = storage._get_background_loop()
    old.call_soon_threadsafe(old.stop)
    deadline = time.monotonic() + 5
    while old.is_running() and time.monotonic() < deadline:
        time.sleep(0.01)
    return old


def test_concurrent_calls_share_one_loop():
    resource = LoopBound()
    results, errors = _in_threads(lambda: storage.run_sync(resource.use()))
    assert errors == []
    assert len(results) == 20
    assert set(results) == {"storage-event-loop"}


def test_first_use_race_creates_only_one_loop(monkeypatch):
    monkeypatch.setattr(
        storage, "_loop", None
    )  # fresh process; restored after the test
    resource = LoopBound()
    results, errors = _in_threads(lambda: storage.run_sync(resource.use()))
    assert errors == []  # two loops would make LoopBound raise
    assert len(results) == 20


def test_naive_asyncio_run_breaks_a_loop_bound_resource():
    """Documents the bug that run_sync() prevents."""
    resource = LoopBound()
    asyncio.run(resource.use())
    with pytest.raises(RuntimeError, match="different loop"):
        asyncio.run(resource.use())


def test_run_sync_refuses_to_run_inside_a_running_loop():
    async def outer():
        with pytest.raises(RuntimeError, match="cannot be called"):
            storage.run_sync(asyncio.sleep(0))

    asyncio.run(outer())


def test_run_sync_times_out_instead_of_hanging():
    with pytest.raises(TimeoutError):
        storage.run_sync(asyncio.sleep(5), timeout=0.2)


def test_run_sync_rejects_non_coroutines():
    with pytest.raises(TypeError):
        storage.run_sync(lambda: 1)


def test_exceptions_reach_the_caller():
    async def boom():
        raise ValueError("boom")

    with pytest.raises(ValueError, match="boom"):
        storage.run_sync(boom())


def test_dead_loop_is_replaced_when_the_old_pool_is_discarded(monkeypatch):
    discarded = []
    monkeypatch.setattr(
        storage, "_discard_stale_pool", lambda: discarded.append(1) or True
    )

    old = _kill_loop()
    new = storage._get_background_loop()
    assert new is not old and new.is_running()
    assert discarded == [1]
    assert storage.run_sync(asyncio.sleep(0, result="ok")) == "ok"


def test_dead_loop_with_unresettable_pool_fails_loudly(monkeypatch):
    monkeypatch.setattr(storage, "_discard_stale_pool", lambda: False)
    _kill_loop()
    with pytest.raises(RuntimeError, match="Restart the dashboard"):
        storage.run_sync(asyncio.sleep(0))


def test_shutdown_stops_the_loop_and_a_later_call_starts_a_new_one():
    first = storage._get_background_loop()
    storage.shutdown_storage()
    assert not first.is_running()
    assert storage.run_sync(asyncio.sleep(0, result="again")) == "again"


def test_default_timeout_is_below_the_sqlalchemy_pool_timeout():
    assert 0 < storage.DEFAULT_RUN_SYNC_TIMEOUT_S < 30
