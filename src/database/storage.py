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
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from sqlalchemy import and_, func, select
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