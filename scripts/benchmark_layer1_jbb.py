"""Measure Layer 1 lexical matching against a pinned JailbreakBench PAIR artifact.

The public artifact is MIT-licensed. This measures rule matches, not
end-to-end model jailbreak success or overall firewall effectiveness.
"""

import json
import sys
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.seed_rules import load_rules_from_yaml
from src.engine.layer_1_deterministic import Layer1Engine

DATASET_REF = "909e68c01d94222b8ad2e397a017e2e12e2adb73"
DATASET_URL = (
    "https://raw.githubusercontent.com/JailbreakBench/artifacts/"
    f"{DATASET_REF}/attack-artifacts/PAIR/black_box/vicuna-13b-v1.5.json"
)


def main() -> None:
    request = Request(
        DATASET_URL,
        headers={"User-Agent": "ai-prompt-injection-firewall-benchmark"},
    )
    with urlopen(request, timeout=30) as response:
        artifact = json.load(response)

    rows = artifact.get("jailbreaks")
    if not isinstance(rows, list):
        raise ValueError("Pinned JailbreakBench artifact has no jailbreaks list")

    prompts = [
        row["prompt"]
        for row in rows
        if isinstance(row, dict)
        and isinstance(row.get("prompt"), str)
        and row["prompt"].strip()
    ]
    if not prompts:
        raise ValueError("Pinned JailbreakBench artifact contains no prompt records")

    engine = Layer1Engine()
    engine.set_rules(load_rules_from_yaml())
    matched_by_rule: dict[str, int] = {}
    for prompt in prompts:
        result = engine.evaluate(prompt)
        if result.matched:
            rule_id = result.rule_id or "UNKNOWN"
            matched_by_rule[rule_id] = matched_by_rule.get(rule_id, 0) + 1

    benign_path = ROOT / "tests" / "fixtures" / "benign_prompts.json"
    with benign_path.open(encoding="utf-8") as file:
        benign_prompts = json.load(file)
    benign_matches = sum(
        engine.evaluate(row["text"]).matched for row in benign_prompts
    )

    detected = sum(matched_by_rule.values())
    print(f"dataset=JailbreakBench PAIR/vicuna-13b-v1.5@{DATASET_REF}")
    print(
        f"artifact_rows={len(rows)} prompts={len(prompts)} "
        f"detected={detected} detection_rate={detected / len(prompts):.1%}"
    )
    print(
        f"local_benign_fixtures={len(benign_prompts)} "
        f"false_positives={benign_matches}"
    )
    print(f"matched_rules={dict(sorted(matched_by_rule.items()))}")


if __name__ == "__main__":
    main()
