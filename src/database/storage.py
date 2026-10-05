"""Async write path for threat logs, plus the hourly system_metrics rollup.

Only the log writer and the rollup live here today - P2's Wednesday task
adds the admin audit log functions, and P5's Friday task adds the
dashboard getters, both to this same file.
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from src.database.connection import AsyncSessionLocal
from src.database.models import SystemMetric, ThreatLog

logger = logging.getLogger("firewall.storage")


async def write_threat_log(entry: dict) -> None:
    """Insert one row into `threat_logs`. Never raises.

    Called as a FastAPI background task from `handler.py`, so a failure
    here must never propagate back into the client's response path - it is
    logged (with the request_id, so it can be correlated) and swallowed.
    """
    try:
        async with AsyncSessionLocal() as session:
            session.add(ThreatLog(**entry))
            await session.commit()
    except Exception:
        request_id = entry.get("request_id", "unknown")
        logger.error(
            "write_threat_log failed for request_id=%s", request_id, exc_info=True
        )


# --- Hourly system_metrics rollup -------------------------------------------


def _floor_to_hour(dt: datetime) -> datetime:
    """Normalize a datetime to the top of its hour, in UTC."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.replace(minute=0, second=0, microsecond=0)


async def compute_bucket(bucket_start: datetime) -> dict:
    """Aggregate `threat_logs` over [bucket_start, bucket_start + 1h) into
    one row matching the `system_metrics` columns. Read-only - does not
    write anything itself."""
    bucket_end = bucket_start + timedelta(hours=1)

    async with AsyncSessionLocal() as session:
        stmt = select(
            func.count().label("total_requests"),
            func.count()
            .filter(ThreatLog.is_blocked.is_(True))
            .label("blocked_requests"),
            func.count()
            .filter(and_(ThreatLog.triggered_layer == "LAYER_1", ThreatLog.is_blocked.is_(True)))
            .label("layer_1_blocks"),
            func.count()
            .filter(and_(ThreatLog.triggered_layer == "LAYER_2", ThreatLog.is_blocked.is_(True)))
            .label("layer_2_blocks"),
            func.count()
            .filter(and_(ThreatLog.triggered_layer == "LAYER_3", ThreatLog.is_blocked.is_(True)))
            .label("layer_3_blocks"),
            func.count()
            .filter(and_(ThreatLog.triggered_layer == "OUTPUT_SCANNER", ThreatLog.is_blocked.is_(True)))
            .label("output_blocks"),
            func.coalesce(func.avg(ThreatLog.execution_time_ms), 0.0).label(
                "avg_latency_ms"
            ),
            func.coalesce(
                func.percentile_cont(0.95).within_group(ThreatLog.execution_time_ms),
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
    """Insert or update one `system_metrics` row, keyed on `bucket_start`."""
    async with AsyncSessionLocal() as session:
        stmt = pg_insert(SystemMetric).values(**row)
        update_cols = {
            col: stmt.excluded[col] for col in row if col != "bucket_start"
        }
        stmt = stmt.on_conflict_do_update(
            index_elements=["bucket_start"], set_=update_cols
        )
        await session.execute(stmt)
        await session.commit()


async def rollup_recent_hours(hours: int = 3) -> int:
    """Recompute and upsert the last `hours` hourly buckets, including the
    current (partial) hour. Returns the number of buckets written."""
    current_bucket = _floor_to_hour(datetime.now(timezone.utc))
    written = 0
    for i in range(hours):
        bucket_start = current_bucket - timedelta(hours=i)
        row = await compute_bucket(bucket_start)
        await upsert_bucket(row)
        written += 1
    return written


async def backfill(since: datetime) -> int:
    """First-time setup: compute and upsert every hourly bucket from
    `since` (normalized to the top of its hour) through the current hour,
    inclusive. Returns the number of buckets written."""
    bucket_start = _floor_to_hour(since)
    current_bucket = _floor_to_hour(datetime.now(timezone.utc))
    written = 0
    while bucket_start <= current_bucket:
        row = await compute_bucket(bucket_start)
        await upsert_bucket(row)
        written += 1
        bucket_start += timedelta(hours=1)
    return written


async def run_rollup_loop(interval_seconds: int = 300) -> None:
    """Run `rollup_recent_hours` forever on a fixed interval. Never exits on
    a database error - logs it and keeps going. Only exits on cancellation
    (so `main.py` can `task.cancel()` it cleanly at shutdown)."""
    while True:
        try:
            await rollup_recent_hours()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.error("rollup_recent_hours failed", exc_info=True)

        try:
            await asyncio.sleep(interval_seconds)
        except asyncio.CancelledError:
            raise