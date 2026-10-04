"""Async write path for threat logs.

Only the log writer lives here today - P3's Friday task adds the rule
reader and the hot-reload fingerprint query to this same file.
"""

import logging

from src.database.connection import AsyncSessionLocal
from src.database.models import ThreatLog

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