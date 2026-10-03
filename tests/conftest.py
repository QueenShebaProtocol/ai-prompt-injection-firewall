"""Shared pytest fixtures. Needs no database, network, or model files."""
import json
from pathlib import Path

import pytest
import yaml

from src.engine.layer_1_deterministic import Layer1Engine

ROOT = Path(__file__).resolve().parents[1]
CONFIG_DIR = ROOT / "config"
FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"


def _load_yaml_rules() -> list[dict]:
    """Read rules_regex.yaml + deny_list.yaml directly (no database).

    TEMPORARY duplicate of the loader in Friday's seed_rules.py,
    tracked in an Issue #31 - remove once that loader can be shared.
    """

    with open(CONFIG_DIR / "rules_regex.yaml", encoding="utf-8") as f:
        regex_rules = (yaml.safe_load(f) or {}).get("rules", [])
    with open(CONFIG_DIR / "deny_list.yaml", encoding="utf-8") as f:
        deny_rules = (yaml.safe_load(f) or {}).get("deny_list", [])


    return [r for r in (regex_rules + deny_rules) if r.get("is_active", True)]


def _load_json(filename: str) -> list[dict]:
    with open(FIXTURE_DIR / filename, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def jailbreak_prompts() -> list[dict]:
    return _load_json("jailbreak_prompts.json")


@pytest.fixture
def benign_prompts() -> list[dict]:
    return _load_json("benign_prompts.json")


@pytest.fixture
def engine() -> Layer1Engine:
    eng = Layer1Engine()
    eng.set_rules(_load_yaml_rules())
    return eng