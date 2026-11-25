"""In-process per-client rate limiting and gateway concurrency control."""

from __future__ import annotations

import math
import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass

_MAX_TRACKED_CLIENTS = 10_000


@dataclass
class _TokenBucket:
    tokens: float
    updated_at: float


def _positive_env_int(name: str, default: int) -> int:
    raw_value = os.getenv(name, str(default))
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive integer") from exc
    if value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value


class RequestAdmissionController:
    """Token bucket per client IP plus a non-queuing global in-flight cap."""

    def __init__(
        self,
        requests_per_minute: int,
        burst: int,
        max_in_flight: int,
        *,
        max_clients: int = _MAX_TRACKED_CLIENTS,
    ) -> None:
        for name, value in (
            ("requests_per_minute", requests_per_minute),
            ("burst", burst),
            ("max_in_flight", max_in_flight),
            ("max_clients", max_clients),
        ):
            if value < 1:
                raise ValueError(f"{name} must be positive")

        self._rate_per_second = requests_per_minute / 60.0
        self._burst = burst
        self._refill_seconds = burst / self._rate_per_second
        self._max_clients = max_clients
        self._clients: OrderedDict[str, _TokenBucket] = OrderedDict()
        self._lock = threading.Lock()
        self._in_flight = threading.BoundedSemaphore(max_in_flight)

    @classmethod
    def from_environment(cls) -> RequestAdmissionController:
        return cls(
            requests_per_minute=_positive_env_int(
                "RATE_LIMIT_REQUESTS_PER_MINUTE", 60
            ),
            burst=_positive_env_int("RATE_LIMIT_BURST", 20),
            max_in_flight=_positive_env_int("MAX_IN_FLIGHT_REQUESTS", 16),
        )

    def consume_token(self, client_ip: str, now: float | None = None) -> int | None:
        """Return Retry-After seconds when limited; otherwise consume one token."""
        now = time.monotonic() if now is None else now
        with self._lock:
            while self._clients:
                oldest_ip, oldest = next(iter(self._clients.items()))
                if now - oldest.updated_at < self._refill_seconds:
                    break
                self._clients.pop(oldest_ip)

            bucket = self._clients.get(client_ip)
            if bucket is None:
                if len(self._clients) >= self._max_clients:
                    self._clients.popitem(last=False)
                bucket = _TokenBucket(tokens=float(self._burst), updated_at=now)
                self._clients[client_ip] = bucket
            else:
                elapsed = max(0.0, now - bucket.updated_at)
                bucket.tokens = min(
                    float(self._burst),
                    bucket.tokens + elapsed * self._rate_per_second,
                )
                bucket.updated_at = now
                self._clients.move_to_end(client_ip)

            if bucket.tokens >= 1.0:
                bucket.tokens -= 1.0
                return None

            retry_after = math.ceil((1.0 - bucket.tokens) / self._rate_per_second)
            return max(1, retry_after)

    def try_acquire(self) -> bool:
        """Acquire an in-flight slot without waiting for capacity."""
        return self._in_flight.acquire(blocking=False)

    def release(self) -> None:
        self._in_flight.release()
