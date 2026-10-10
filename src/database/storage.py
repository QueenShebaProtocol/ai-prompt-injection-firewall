"""Async storage layer for the AI Prompt Injection Firewall.

Functions in this file:
- write_threat_log
    Week 1 Wednesday, P4
- get_active_layer1_rules
- get_rules_fingerprint
    Week 1 Friday, P3
- compute_bucket
- upsert_bucket
- rollup_recent_hours
- backfill
- run_rollup_loop
    Week 2 Monday, P4
- write_audit_log
    Week 2 Wednesday, P2
- run_sync, ttl_cache, LogFilters, Page
- get_kpi_summary, get_timeseries, get_layer_distribution
- search_threat_logs, get_log_detail
- get_active_output_scanner_rules
    Week 2 Friday, P5
"""

import asyncio
import copy
import functools
import logging
import threading
import time
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from sqlalchemy import and_, func, literal_column, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from src.database.connection import AsyncSessionLocal
from src.database.models import (
    AdminAuditLog,
    FirewallRule,
    SystemMetric,
    ThreatLog,
)

logger = logging.getLogger("firewall.storage")


# =============================================================================
# Threat log storage
# =============================================================================


async def write_threat_log(entry: dict) -> None:
    """Insert one row into `threat_logs`.

    This function is intentionally non-raising because it is called from
    the request/response path as a background task.

    A database failure must never propagate back to the client response.

    Args:
        entry: Dictionary containing values matching the ThreatLog model.
    """
    try:
        async with AsyncSessionLocal() as session:
            session.add(ThreatLog(**entry))
            await session.commit()

    except Exception:
        request_id = entry.get("request_id", "unknown")

        logger.error(
            "write_threat_log failed for request_id=%s",
            request_id,
            exc_info=True,
        )


# =============================================================================
# Layer 1 rule storage
# =============================================================================


async def get_active_layer1_rules() -> list[FirewallRule]:
    """Return all active Layer 1 firewall rules.

    Layer 1 uses REGEX, KEYWORD and EXCLUSION rules.

    The rules are loaded from PostgreSQL so that the firewall can support
    dynamic rule updates without requiring a source-code change.
    """
    async with AsyncSessionLocal() as session:
        stmt = (
            select(FirewallRule)
            .where(FirewallRule.is_active.is_(True))
            .where(
                FirewallRule.rule_type.in_(
                    ["REGEX", "KEYWORD", "EXCLUSION"]
                )
            )
            .order_by(FirewallRule.rule_id)
        )

        result = await session.execute(stmt)

        return list(result.scalars().all())


async def get_rules_fingerprint() -> str:
    """Return a deterministic fingerprint for the active firewall rules.

    The fingerprint can be used by the Layer 1 hot-reload mechanism to
    determine whether the database rules changed.

    The implementation intentionally uses only stable rule fields so that
    unrelated database state does not cause unnecessary reloads.
    """
    import hashlib

    rules = await get_active_layer1_rules()

    canonical = "\n".join(
        "|".join(
            [
                str(rule.rule_id or ""),
                str(rule.rule_type or ""),
                str(rule.category or ""),
                str(rule.pattern or ""),
                str(rule.severity or ""),
                str(rule.is_active),
            ]
        )
        for rule in rules
    )

    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# =============================================================================
# Hourly system_metrics rollup
# =============================================================================


def _floor_to_hour(dt: datetime) -> datetime:
    """Normalize a datetime to the beginning of its UTC hour."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)

    return dt.replace(
        minute=0,
        second=0,
        microsecond=0,
    )


async def compute_bucket(bucket_start: datetime) -> dict:
    """Aggregate `threat_logs` for one hourly bucket.

    The aggregation range is:

        [bucket_start, bucket_start + 1 hour)

    The function is read-only and does not write to `system_metrics`.

    Args:
        bucket_start: Beginning of the UTC hour.

    Returns:
        Dictionary matching the SystemMetric model fields.
    """
    bucket_start = _floor_to_hour(bucket_start)
    bucket_end = bucket_start + timedelta(hours=1)

    async with AsyncSessionLocal() as session:
        stmt = select(
            func.count().label("total_requests"),

            func.count()
            .filter(
                ThreatLog.is_blocked.is_(True)
            )
            .label("blocked_requests"),

            func.count()
            .filter(
                and_(
                    ThreatLog.triggered_layer == "LAYER_1",
                    ThreatLog.is_blocked.is_(True),
                )
            )
            .label("layer_1_blocks"),

            func.count()
            .filter(
                and_(
                    ThreatLog.triggered_layer == "LAYER_2",
                    ThreatLog.is_blocked.is_(True),
                )
            )
            .label("layer_2_blocks"),

            func.count()
            .filter(
                and_(
                    ThreatLog.triggered_layer == "LAYER_3",
                    ThreatLog.is_blocked.is_(True),
                )
            )
            .label("layer_3_blocks"),

            func.count()
            .filter(
                and_(
                    ThreatLog.triggered_layer == "OUTPUT_SCANNER",
                    ThreatLog.is_blocked.is_(True),
                )
            )
            .label("output_blocks"),

            func.coalesce(
                func.avg(ThreatLog.execution_time_ms),
                0.0,
            ).label("avg_latency_ms"),

            func.coalesce(
                func.percentile_cont(0.95).within_group(
                    ThreatLog.execution_time_ms
                ),
                0.0,
            ).label("p95_latency_ms"),

        ).where(
            ThreatLog.created_at >= bucket_start,
            ThreatLog.created_at < bucket_end,
        )

        row = (await session.execute(stmt)).one()

    return {
        "bucket_start": bucket_start,
        "total_requests": row.total_requests,
        "blocked_requests": row.blocked_requests,
        "layer_1_blocks": row.layer_1_blocks,
        "layer_2_blocks": row.layer_2_blocks,
        "layer_3_blocks": row.layer_3_blocks,
        "output_blocks": row.output_blocks,
        "avg_latency_ms": float(row.avg_latency_ms or 0.0),
        "p95_latency_ms": float(row.p95_latency_ms or 0.0),
    }


async def upsert_bucket(row: dict) -> None:
    """Insert or update one `system_metrics` row.

    `bucket_start` is the logical unique key for the hourly metric.
    """
    async with AsyncSessionLocal() as session:
        stmt = pg_insert(SystemMetric).values(**row)

        update_cols = {
            column: stmt.excluded[column]
            for column in row
            if column != "bucket_start"
        }

        stmt = stmt.on_conflict_do_update(
            index_elements=["bucket_start"],
            set_=update_cols,
        )

        await session.execute(stmt)
        await session.commit()


async def rollup_recent_hours(hours: int = 3) -> int:
    """Recompute and upsert the most recent hourly buckets.

    The current partial hour is included.

    Args:
        hours: Number of hourly buckets to process.

    Returns:
        Number of buckets written.
    """
    if hours <= 0:
        return 0

    current_bucket = _floor_to_hour(
        datetime.now(timezone.utc)
    )

    written = 0

    for i in range(hours):
        bucket_start = current_bucket - timedelta(hours=i)

        row = await compute_bucket(bucket_start)

        await upsert_bucket(row)

        written += 1

    return written


async def backfill(since: datetime) -> int:
    """Backfill hourly metrics from `since` through the current hour.

    Args:
        since: Starting timestamp.

    Returns:
        Number of hourly buckets written.
    """
    bucket_start = _floor_to_hour(since)

    current_bucket = _floor_to_hour(
        datetime.now(timezone.utc)
    )

    written = 0

    while bucket_start <= current_bucket:
        row = await compute_bucket(bucket_start)

        await upsert_bucket(row)

        written += 1

        bucket_start += timedelta(hours=1)

    return written


async def run_rollup_loop(interval_seconds: int = 300) -> None:
    """Continuously maintain the recent hourly metrics.

    Database errors are logged and do not terminate the background loop.

    The loop exits cleanly only when cancelled by the application.
    """
    if interval_seconds <= 0:
        raise ValueError("interval_seconds must be greater than zero")

    while True:
        try:
            await rollup_recent_hours()

        except asyncio.CancelledError:
            raise

        except Exception:
            logger.error(
                "rollup_recent_hours failed",
                exc_info=True,
            )

        try:
            await asyncio.sleep(interval_seconds)

        except asyncio.CancelledError:
            raise


# =============================================================================
# Week 2 Wednesday - Administrative audit logging
# =============================================================================


_VALID_AUDIT_ACTIONS = {
    "RULE_CREATED",
    "RULE_UPDATED",
    "RULE_DELETED",
    "THRESHOLD_CHANGED",
}


def _json_safe(value: Any) -> Any:
    """Convert common Python/SQLAlchemy values into JSON-safe values.

    `change_details` is stored as PostgreSQL JSONB. Audit snapshots can
    therefore contain dictionaries/lists, but datetime values and other
    Python objects need to be converted before being persisted.

    This helper deliberately does not expose or transform secret values;
    callers are responsible for deciding what belongs in an audit snapshot.
    """
    if value is None:
        return None

    if isinstance(value, (str, int, float, bool)):
        return value

    if isinstance(value, datetime):
        return value.isoformat()

    if isinstance(value, Mapping):
        return {
            str(key): _json_safe(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple, set)):
        return [
            _json_safe(item)
            for item in value
        ]

    # SQLAlchemy/other model objects should not be serialized blindly.
    # Convert unknown values to their string representation rather than
    # allowing JSON serialization to fail.
    return str(value)


def _build_change_details(
    before: Any = None,
    after: Any = None,
    details: Mapping[str, Any] | None = None,
) -> dict:
    """Build the JSONB audit payload.

    The standard audit format is:

        {
            "before": {...},
            "after": {...}
        }

    Optional additional metadata can be supplied through `details`.
    """
    change_details: dict[str, Any] = {
        "before": _json_safe(before),
        "after": _json_safe(after),
    }

    if details:
        for key, value in details.items():
            change_details[str(key)] = _json_safe(value)

    return change_details


async def write_audit_log(
    *,
    admin_user: str,
    action: str,
    target_rule_id: str | None = None,
    before: Any = None,
    after: Any = None,
    details: Mapping[str, Any] | None = None,
) -> None:
    """Write one administrative action to `admin_audit_logs`.

    This function is intended to be called by dashboard/configuration
    operations whenever an administrator changes firewall policy.

    Supported actions are:

        RULE_CREATED
        RULE_UPDATED
        RULE_DELETED
        THRESHOLD_CHANGED

    The database table stores:

        timestamp
        admin_user
        action
        target_rule_id
        change_details

    `change_details` contains the pre-change and post-change snapshots.

    Args:
        admin_user:
            Username or identifier of the administrator performing the
            operation.

        action:
            Administrative operation type.

        target_rule_id:
            Firewall rule affected by the operation, when applicable.
            Threshold changes may leave this as None.

        before:
            State before the change.

        after:
            State after the change.

        details:
            Optional additional JSON-serializable metadata.

    Raises:
        ValueError:
            If the administrator or action is invalid.

        Exception:
            Database exceptions are allowed to propagate so the caller can
            decide whether the administrative operation itself should be
            considered successful.
    """
    if not isinstance(admin_user, str) or not admin_user.strip():
        raise ValueError("admin_user must be a non-empty string")

    normalized_action = str(action).strip().upper()

    if normalized_action not in _VALID_AUDIT_ACTIONS:
        raise ValueError(
            f"Unsupported audit action: {normalized_action}. "
            f"Expected one of: "
            f"{', '.join(sorted(_VALID_AUDIT_ACTIONS))}"
        )

    normalized_rule_id = None

    if target_rule_id is not None:
        normalized_rule_id = str(target_rule_id).strip()

        if not normalized_rule_id:
            normalized_rule_id = None

    change_details = _build_change_details(
        before=before,
        after=after,
        details=details,
    )

    audit_entry = {
        "admin_user": admin_user.strip(),
        "action": normalized_action,
        "target_rule_id": normalized_rule_id,
        "change_details": change_details,
    }

    async with AsyncSessionLocal() as session:
        audit_log = AdminAuditLog(**audit_entry)

        session.add(audit_log)

        await session.commit()

    logger.info(
        "Administrative audit event recorded: "
        "admin_user=%s action=%s target_rule_id=%s",
        admin_user,
        normalized_action,
        normalized_rule_id,
    )



# --- Dashboard data layer (Week 2 Fri, P5) ----------------------------
#
# The Streamlit dashboard is synchronous, but the database code is async.
# run_sync() lets the dashboard call async getters safely, and ttl_cache()
# stops the dashboard from hitting the database on every page refresh.

MAX_PAGE_SIZE = 200
DEFAULT_PAGE_SIZE = 50
RECENT_HOURS_LIMIT = 48          # <= 48h: read threat_logs, > 48h: read system_metrics
PROMPT_PREVIEW_CHARS = 200

_VALID_LAYERS = {"NONE", "LAYER_1", "LAYER_2", "LAYER_3", "OUTPUT_SCANNER"}
_VALID_RULE_CATEGORIES = {"JAILBREAK", "PROMPT_LEAK", "PII", "SYSTEM_OVERRIDE"}

# Fixed constants, never built from user input. They are literal_column objects
# (not bind parameters) so that date_trunc('hour', col) is written identically in
# SELECT and GROUP BY, which PostgreSQL requires.
_BUCKET_SQL = {
    "minute": literal_column("'minute'"),
    "hour": literal_column("'hour'"),
    "day": literal_column("'day'"),
}


# --- 1. run_sync: one long-lived background event loop ----------------
_loop: asyncio.AbstractEventLoop | None = None
_loop_lock = threading.Lock()


def _get_background_loop() -> asyncio.AbstractEventLoop:
    """Start (once) a dedicated thread that runs one event loop forever.

    asyncpg connections belong to the loop they were created on, so every
    dashboard query must run on this same loop.
    """
    global _loop
    with _loop_lock:
        if _loop is not None and _loop.is_running():
            return _loop

        loop = asyncio.new_event_loop()
        started = threading.Event()

        def _run() -> None:
            asyncio.set_event_loop(loop)
            loop.call_soon(started.set)
            loop.run_forever()

        threading.Thread(target=_run, name="storage-event-loop", daemon=True).start()
        started.wait()
        _loop = loop
        return _loop


def run_sync(coro, timeout: float = 30.0) -> Any:
    """Run an async coroutine from synchronous code (Streamlit) and return its result.

    Usage:  kpis = run_sync(get_kpi_summary(24))
    Do not call this from inside async code; use `await` there.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        pass  # no loop running in this thread: the normal Streamlit case
    else:
        coro.close()
        raise RuntimeError(
            "run_sync() cannot be called from a running event loop; use await instead."
        )

    loop = _get_background_loop()
    future = asyncio.run_coroutine_threadsafe(coro, loop)
    try:
        return future.result(timeout=timeout)
    except FutureTimeout:
        future.cancel()
        raise TimeoutError(f"Database call did not finish within {timeout} seconds")


# --- 2. ttl_cache: remember results for a few seconds -----------------
def ttl_cache(seconds: float, maxsize: int = 128):
    """Cache an async function's result for `seconds`, keyed by its arguments.

    - A second identical call inside the TTL returns the stored result and
      runs no query.
    - Errors are never cached.
    - Callers get a deep copy, so changing the result cannot corrupt the cache.
    - Call fn.cache_clear() in tests.
    """

    def decorator(fn):
        store: dict = {}
        lock = threading.Lock()

        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            try:
                key = (args, tuple(sorted(kwargs.items())))
                hash(key)
            except TypeError:
                return await fn(*args, **kwargs)  # unhashable arguments: skip caching

            now = time.monotonic()
            with lock:
                entry = store.get(key)
                if entry is not None and entry[0] > now:
                    return copy.deepcopy(entry[1])

            result = await fn(*args, **kwargs)

            with lock:
                if len(store) >= maxsize:
                    for expired in [k for k, (exp, _) in store.items() if exp <= now]:
                        del store[expired]
                    if len(store) >= maxsize:
                        store.pop(next(iter(store)))  # drop the oldest entry
                store[key] = (time.monotonic() + seconds, result)
            return copy.deepcopy(result)

        def cache_clear() -> None:
            with lock:
                store.clear()

        wrapper.cache_clear = cache_clear
        return wrapper

    return decorator


# --- 3. Filters and pages ---------------------------------------------
@dataclass(frozen=True)
class LogFilters:
    """Search filters for threat_logs. Every field is optional (None = no filter)."""

    start: datetime | None = None          # created_at >= start
    end: datetime | None = None            # created_at <  end
    is_blocked: bool | None = None
    triggered_layer: str | None = None     # NONE | LAYER_1 | LAYER_2 | LAYER_3 | OUTPUT_SCANNER
    client_ip: str | None = None
    min_risk: float | None = None          # risk_score >= min_risk
    text: str | None = None                # case-insensitive "contains" on raw_prompt


@dataclass
class Page:
    items: list[dict]
    total: int
    page: int
    page_size: int


def _window(hours: int, offset_hours: int = 0) -> tuple[datetime, datetime]:
    """Return (start, end) for 'the last `hours` hours', optionally shifted back."""
    hours = max(1, int(hours))
    offset_hours = max(0, int(offset_hours))
    end = datetime.now(timezone.utc) - timedelta(hours=offset_hours)
    return end - timedelta(hours=hours), end


def _escape_like(text: str) -> str:
    """Make % and _ in the user's search text match literally."""
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _apply_filters(stmt, f: LogFilters | None):
    """Add WHERE clauses for each filter that is set. Every value is a bound parameter."""
    if f is None:
        return stmt
    if f.start is not None:
        stmt = stmt.where(ThreatLog.created_at >= f.start)
    if f.end is not None:
        stmt = stmt.where(ThreatLog.created_at < f.end)
    if f.is_blocked is not None:
        stmt = stmt.where(ThreatLog.is_blocked.is_(bool(f.is_blocked)))
    if f.triggered_layer:
        if f.triggered_layer not in _VALID_LAYERS:
            raise ValueError(f"Unknown triggered_layer: {f.triggered_layer!r}")
        stmt = stmt.where(ThreatLog.triggered_layer == f.triggered_layer)
    if f.client_ip:
        stmt = stmt.where(ThreatLog.client_ip == f.client_ip)
    if f.min_risk is not None:
        stmt = stmt.where(ThreatLog.risk_score >= float(f.min_risk))
    if f.text:
        stmt = stmt.where(
            ThreatLog.raw_prompt.ilike(f"%{_escape_like(f.text)}%", escape="\\")
        )
    return stmt


# --- 4. Getters --------------------------------------------------------
@ttl_cache(15)
async def get_kpi_summary(hours: int = 24, offset_hours: int = 0) -> dict:
    """Headline numbers for the last `hours` hours.

    offset_hours=hours gives the PREVIOUS period (for the delta on the KPI cards).
    """
    start, end = _window(hours, offset_hours)
    stmt = select(
        func.count().label("total"),
        func.count().filter(ThreatLog.is_blocked.is_(True)).label("blocked"),
        func.coalesce(func.avg(ThreatLog.execution_time_ms), 0.0).label("avg_latency"),
        func.coalesce(
            func.percentile_cont(0.95).within_group(ThreatLog.execution_time_ms), 0.0
        ).label("p95_latency"),
    ).where(ThreatLog.created_at >= start, ThreatLog.created_at < end)

    async with AsyncSessionLocal() as session:
        row = (await session.execute(stmt)).one()

    total = int(row.total)
    blocked = int(row.blocked)
    return {
        "total_requests": total,
        "blocked_requests": blocked,
        "block_rate": (blocked / total) if total else 0.0,   # 0.0 - 1.0
        "avg_latency_ms": float(row.avg_latency or 0.0),
        "p95_latency_ms": float(row.p95_latency or 0.0),
        "hours": max(1, int(hours)),
    }


@ttl_cache(30)
async def get_timeseries(hours: int = 24, bucket: str = "hour") -> list[dict]:
    """Requests and blocks per time bucket, oldest first.

    <= 48 hours: counted live from threat_logs.
    >  48 hours: summed from the pre-aggregated system_metrics table
                 (hourly rows, so 'minute' falls back to 'hour').
    """
    if bucket not in _BUCKET_SQL:
        raise ValueError(f"bucket must be one of {sorted(_BUCKET_SQL)}, got {bucket!r}")

    hours = max(1, int(hours))
    start = datetime.now(timezone.utc) - timedelta(hours=hours)

    if hours <= RECENT_HOURS_LIMIT:
        bucket_expr = func.date_trunc(_BUCKET_SQL[bucket], ThreatLog.created_at)
        stmt = (
            select(
                bucket_expr.label("bucket_start"),
                func.count().label("total_requests"),
                func.count().filter(ThreatLog.is_blocked.is_(True)).label("blocked_requests"),
            )
            .where(ThreatLog.created_at >= start)
            .group_by(bucket_expr)
            .order_by(bucket_expr)
        )
    else:
        unit = _BUCKET_SQL["day" if bucket == "day" else "hour"]
        bucket_expr = func.date_trunc(unit, SystemMetric.bucket_start)
        stmt = (
            select(
                bucket_expr.label("bucket_start"),
                func.coalesce(func.sum(SystemMetric.total_requests), 0).label("total_requests"),
                func.coalesce(func.sum(SystemMetric.blocked_requests), 0).label("blocked_requests"),
            )
            .where(SystemMetric.bucket_start >= start)
            .group_by(bucket_expr)
            .order_by(bucket_expr)
        )

    async with AsyncSessionLocal() as session:
        rows = (await session.execute(stmt)).all()

    return [
        {
            "bucket_start": r.bucket_start,
            "total_requests": int(r.total_requests),
            "blocked_requests": int(r.blocked_requests),
        }
        for r in rows
    ]


@ttl_cache(30)
async def get_layer_distribution(hours: int = 24) -> dict:
    """How many BLOCKED requests each layer stopped, e.g. {"LAYER_1": 12, ...}."""
    start, end = _window(hours)
    stmt = (
        select(ThreatLog.triggered_layer, func.count())
        .where(ThreatLog.created_at >= start, ThreatLog.is_blocked.is_(True))
        .group_by(ThreatLog.triggered_layer)
    )
    async with AsyncSessionLocal() as session:
        rows = (await session.execute(stmt)).all()

    distribution = {"LAYER_1": 0, "LAYER_2": 0, "LAYER_3": 0, "OUTPUT_SCANNER": 0}
    for layer, count in rows:
        # A fail-closed pipeline error is logged as blocked with layer "NONE";
        # it shows up here under its own key instead of being hidden.
        distribution[layer] = int(count)
    return distribution


@ttl_cache(10)
async def search_threat_logs(
    filters: LogFilters | None = None,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> Page:
    """One page of log rows (newest first) plus the total number of matches."""
    page = max(1, int(page))
    page_size = min(max(1, int(page_size)), MAX_PAGE_SIZE)

    count_stmt = _apply_filters(select(func.count()).select_from(ThreatLog), filters)
    rows_stmt = _apply_filters(
        select(
            ThreatLog.created_at,
            ThreatLog.request_id,
            ThreatLog.client_ip,
            ThreatLog.application_id,
            ThreatLog.target_model,
            ThreatLog.is_blocked,
            ThreatLog.action_taken,
            ThreatLog.triggered_layer,
            ThreatLog.risk_score,
            ThreatLog.output_flagged,
            # only the first characters, so huge prompts are not loaded for the table
            func.left(ThreatLog.raw_prompt, PROMPT_PREVIEW_CHARS).label("prompt_preview"),
        ),
        filters,
    )
    rows_stmt = (
        rows_stmt.order_by(ThreatLog.created_at.desc(), ThreatLog.id.desc())
        .limit(page_size)
        .offset((page - 1) * page_size)
    )

    async with AsyncSessionLocal() as session:
        total = (await session.execute(count_stmt)).scalar_one()
        rows = (await session.execute(rows_stmt)).mappings().all()

    return Page(
        items=[dict(r) for r in rows],
        total=int(total),
        page=page,
        page_size=page_size,
    )


@ttl_cache(10)
async def get_log_detail(request_id: str) -> dict | None:
    """Every column of one threat_logs row, or None if the request_id is unknown."""
    stmt = select(ThreatLog).where(ThreatLog.request_id == request_id)
    async with AsyncSessionLocal() as session:
        obj = (await session.execute(stmt)).scalar_one_or_none()

    if obj is None:
        return None
    detail = {c.name: getattr(obj, c.name) for c in ThreatLog.__table__.columns}
    detail["id"] = str(detail["id"])
    return detail


# --- 5. Rule reader for the output scanner (used by P2's detect_pii) ---
async def get_active_output_scanner_rules(category: str = "PII") -> list[dict]:
    """Active rules of one category, as rule dictionaries (not cached on purpose,
    so detect_pii sees rule changes; it caches its own compiled patterns)."""
    if category not in _VALID_RULE_CATEGORIES:
        raise ValueError(f"Unknown rule category: {category!r}")

    stmt = (
        select(FirewallRule)
        .where(
            FirewallRule.is_active.is_(True),
            FirewallRule.category == category,
            FirewallRule.rule_type.in_(("REGEX", "KEYWORD")),
        )
        .order_by(FirewallRule.rule_id)
    )
    async with AsyncSessionLocal() as session:
        rules = (await session.execute(stmt)).scalars().all()

    return [
        {
            "rule_id": r.rule_id,
            "rule_type": r.rule_type,
            "category": r.category,
            "pattern": r.pattern,
            "description": r.description,
            "severity": r.severity,
        }
        for r in rules
    ]