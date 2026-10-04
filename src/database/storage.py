# """Async write path for threat logs.

# Only the log writer lives here today - P3's Friday task adds the rule
# reader and the hot-reload fingerprint query to this same file.
# """

# import logging

# from src.database.connection import AsyncSessionLocal
# from src.database.models import ThreatLog

# logger = logging.getLogger("firewall.storage")

"""Async storage layer: threat-log writer, rule reader, and rules fingerprint."""

import logging

from sqlalchemy import func, select

from src.database.connection import AsyncSessionLocal
from src.database.models import FirewallRule, ThreatLog

logger = logging.getLogger("firewall.storage")

LAYER1_RULE_TYPES = ("REGEX", "KEYWORD")


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


async def get_active_layer1_rules() -> list[dict]:
    """Return active REGEX/KEYWORD rules as dicts for Layer1Engine.set_rules().

    The WHERE clause matches the (is_active, rule_type) index. Ordered by id
    so rule order is stable (Layer 1 stops at the first match). Errors are
    NOT swallowed: the caller decides whether to keep the old rule set.
    """
    stmt = (
        select(
            FirewallRule.rule_id,
            FirewallRule.rule_type,
            FirewallRule.category,
            FirewallRule.pattern,
            FirewallRule.severity,
            FirewallRule.description,
        )
        .where(
            FirewallRule.is_active.is_(True),
            FirewallRule.rule_type.in_(LAYER1_RULE_TYPES),
        )
        .order_by(FirewallRule.id)
    )
    async with AsyncSessionLocal() as session:
        result = await session.execute(stmt)
        return [dict(row) for row in result.mappings().all()]


async def get_rules_fingerprint() -> tuple:
    """Return (row_count, max(updated_at)) in a single aggregate query.

    Used by the hot-reload watcher: if the tuple changes, rules changed.
    An empty table gives (0, None).
    """
    stmt = select(func.count(FirewallRule.id), func.max(FirewallRule.updated_at))
    async with AsyncSessionLocal() as session:
        result = await session.execute(stmt)
        count, latest = result.one()
    return (count, latest)