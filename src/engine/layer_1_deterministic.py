"""
Layer 1 - Deterministic Engine.

Sub-millisecond regex / keyword matching against the active rule set,
held fully compiled in memory so evaluation never touches the database
on the hot path (SRS FR-L1-01, FR-L1-03, FR-L1-04).

Note: the hot-reload watcher (start_watcher / stop_watcher) is added to
this same file on Friday by P6. It is not part of this Wednesday task.
"""

import logging
import re
import unicodedata
from dataclasses import dataclass, field

logger = logging.getLogger("firewall.layer1")


@dataclass
class Layer1MatchResult:
    """Outcome of evaluating one prompt against the active rule set."""
    matched: bool
    rule_id: str | None = None
    category: str | None = None
    severity: str | None = None
    patterns: list[str] = field(default_factory=list)


class Layer1Engine:
    """
    Holds a compiled, in-memory copy of the active Layer 1 rules and
    evaluates prompts against them.
    """

    def __init__(self) -> None:
        self._rules: list[dict] = []

    # ------------------------------------------------------------------
    # Rule loading
    # ------------------------------------------------------------------
    def set_rules(self, rules: list[dict]) -> None:
        """
        Compile and install a rule list. Each rule dict must have:
        rule_id, rule_type ("REGEX" or "KEYWORD"), category, pattern,
        severity. Invalid regexes are skipped and logged rather than
        breaking the whole rule set.

        The new list is installed with a single assignment at the end,
        so a request in flight always sees either the old or the new
        complete rule set, never a half-built one.
        """
        compiled_rules: list[dict] = []

        for rule in rules:
            entry = dict(rule)

            if rule["rule_type"] == "REGEX":
                try:
                    entry["compiled"] = re.compile(rule["pattern"])
                except re.error as exc:
                    logger.error(
                        "Skipping rule %s: invalid regex (%s)",
                        rule.get("rule_id", "<unknown>"),
                        exc,
                    )
                    continue
            elif rule["rule_type"] == "KEYWORD":
                entry["compiled"] = None
                entry["keyword_lower"] = rule["pattern"].lower()
            else:
                # EXCLUSION and any future rule_type are not evaluated
                # by Layer 1; skip them here rather than error.
                continue

            compiled_rules.append(entry)

        self._rules = compiled_rules

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    async def load_rules(self) -> None:
        """
        Load active REGEX/KEYWORD rules from the database and install
        them. Imported lazily so this module (and set_rules/evaluate)
        can be used and tested with no database available.
        """
        from src.database.storage import get_active_layer1_rules

        rules = await get_active_layer1_rules()
        self.set_rules(rules)
        logger.info("Layer 1: %d rules active", self.rule_count)

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------
    @staticmethod
    def _normalize(text: str) -> str:
        """
        NFKC-normalize (folds full-width and many homoglyph forms to
        their plain equivalents) and collapse repeated whitespace, so
        simple obfuscation doesn't slip past the rules.
        """
        if not text:
            return ""
        normalized = unicodedata.normalize("NFKC", text)
        return re.sub(r"\s+", " ", normalized).strip()

    def evaluate(self, prompt: str, system_instruction: str = "") -> Layer1MatchResult:
        """
        Evaluate a prompt (and optional system instruction) against all
        active Layer 1 rules. Returns on the first match — short-circuit,
        per FR-L1-03 — rather than collecting every match.
        """
        text = self._normalize(f"{prompt or ''} {system_instruction or ''}")
        text_lower = text.lower()

        for rule in self._rules:
            if rule["rule_type"] == "REGEX":
                hit = rule["compiled"].search(text) is not None
            else:  # KEYWORD
                hit = rule["keyword_lower"] in text_lower

            if hit:
                return Layer1MatchResult(
                    matched=True,
                    rule_id=rule["rule_id"],
                    category=rule["category"],
                    severity=rule["severity"],
                    patterns=[rule["rule_id"]],
                )

        return Layer1MatchResult(matched=False)


# Process-wide singleton shared by the proxy handler and the pipeline.
layer1_engine = Layer1Engine()