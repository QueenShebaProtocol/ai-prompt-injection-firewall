"""Architecture guards for database access (run offline, no database)."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "src" / "dashboard"
STORAGE = ROOT / "src" / "database" / "storage.py"

# The dashboard may only use src.database.storage, always through run_sync().
FORBIDDEN_IN_DASHBOARD = [
    r"asyncio\.run\(",
    r"run_until_complete",
    r"new_event_loop",
    r"get_event_loop",
    r"AsyncSessionLocal",
    r"AsyncSession\b",
    r"create_async_engine",
    r"src\.database\.connection",
    r"from src\.database import connection",
    r"import asyncpg",
    r"from sqlalchemy",
    r"import sqlalchemy",
]


def test_dashboard_never_bypasses_storage():
    offenders = []
    for path in DASHBOARD.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for pattern in FORBIDDEN_IN_DASHBOARD:
            if re.search(pattern, text):
                offenders.append(f"{path.relative_to(ROOT)}: {pattern}")
    assert (
        not offenders
    ), "Dashboard code must use storage.run_sync only:\n" + "\n".join(offenders)


def test_storage_opens_every_session_in_its_own_async_with():
    """Sessions are never shared: each use is `async with AsyncSessionLocal() as ...`."""
    src = STORAGE.read_text(encoding="utf-8")
    uses = re.findall(r"AsyncSessionLocal\(\)", src)
    scoped = re.findall(r"async with AsyncSessionLocal\(\)", src)
    assert uses and len(uses) == len(scoped)
