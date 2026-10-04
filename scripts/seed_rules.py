"""Load the YAML rule files into the firewall_rules table.

load_rules_from_yaml() has no database imports so tests can reuse it.
Run from the repo root:  python scripts/seed_rules.py
"""

import asyncio
import logging
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGEX_PATH = ROOT / "config" / "rules_regex.yaml"
DEFAULT_DENY_PATH = ROOT / "config" / "deny_list.yaml"

REQUIRED_KEYS = ("rule_id", "rule_type", "category", "pattern", "severity")
UPDATABLE_FIELDS = (
    "rule_type", "category", "pattern", "description", "severity", "is_active",
)

logger = logging.getLogger("firewall.seed")


def _read_rules(path: Path, top_key: str) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    rules = []
    for entry in data.get(top_key) or []:
        missing = [k for k in REQUIRED_KEYS if k not in entry]
        if missing:
            raise ValueError(
                f"{path.name}: rule {entry.get('rule_id', '<no rule_id>')} "
                f"is missing {missing}"
            )
        rules.append({
            "rule_id": entry["rule_id"],
            "rule_type": entry["rule_type"],
            "category": entry["category"],
            "pattern": entry["pattern"],
            "description": entry.get("description"),
            "severity": entry["severity"],
            "is_active": entry.get("is_active", True),
        })
    return rules


def load_rules_from_yaml(
    regex_path=DEFAULT_REGEX_PATH, deny_path=DEFAULT_DENY_PATH
) -> list[dict]:
    """Read both YAML files and return every rule (inactive ones included)."""
    rules = _read_rules(Path(regex_path), "rules") + _read_rules(
        Path(deny_path), "deny_list"
    )
    seen: set[str] = set()
    for rule in rules:
        if rule["rule_id"] in seen:
            raise ValueError(f"Duplicate rule_id in YAML files: {rule['rule_id']}")
        seen.add(rule["rule_id"])
    return rules


async def seed() -> None:
    """Upsert every YAML rule into firewall_rules, keyed by rule_id."""
    
    from sqlalchemy import select

    from src.database.connection import AsyncSessionLocal, engine, init_schema
    from src.database.models import FirewallRule

    rules = load_rules_from_yaml()
    inserted = updated = unchanged = 0

    try:
        await init_schema()  
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(FirewallRule).where(
                    FirewallRule.rule_id.in_([r["rule_id"] for r in rules])
                )
            )
            existing = {row.rule_id: row for row in result.scalars()}

            for rule in rules:
                row = existing.get(rule["rule_id"])
                if row is None:
                    session.add(FirewallRule(**rule))
                    inserted += 1
                    continue

                changed = False
                for field in UPDATABLE_FIELDS:
                    if getattr(row, field) != rule[field]:
                        setattr(row, field, rule[field])
                        changed = True
                if changed:
                    updated += 1
                else:
                    unchanged += 1

            await session.commit()
    finally:
        await engine.dispose()

    logger.info(
        "Seed complete: %d inserted, %d updated, %d unchanged",
        inserted, updated, unchanged,
    )


if __name__ == "__main__":
    sys.path.insert(0, str(ROOT)) 
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    asyncio.run(seed())