"""
Layer 1 - Deterministic Engine.

Sub-millisecond regex / keyword matching against the active rule set,
held fully compiled in memory so evaluation never touches the database
on the hot path (SRS FR-L1-01, FR-L1-03, FR-L1-04).

Note: the hot-reload watcher (start_watcher / stop_watcher) is added to
this same file on Friday by P6. It is not part of this Wednesday task.
"""

import asyncio
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
        self._fingerprint: tuple | None = None
        self._watcher_task: asyncio.Task | None = None

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
        from src.database.storage import (
            get_active_layer1_rules,
            get_rules_fingerprint,
        )

        # Fingerprint first: if a rule changes between the two queries,
        # the next poll sees a newer fingerprint and reloads (never misses).
        fingerprint = await get_rules_fingerprint()
        rules = await get_active_layer1_rules()
        self.set_rules(rules)
        self._fingerprint = fingerprint
        logger.info("Layer 1: %d rules active", self.rule_count)

    # ------------------------------------------------------------------
    # Hot-reload watcher
    # ------------------------------------------------------------------
    def start_watcher(self, interval_seconds: float = 5.0) -> None:
        """
        Start one background task that polls the rule fingerprint and
        reloads rules when it changes. Does nothing if already running.
        Must be called while an event loop is running (e.g. FastAPI lifespan).
        """
        if self._watcher_task is not None and not self._watcher_task.done():
            return
        self._watcher_task = asyncio.create_task(
            self._watch_rules(interval_seconds), name="layer1-rule-watcher"
        )
        logger.info("Layer 1 watcher started (every %.1fs)", interval_seconds)

    async def stop_watcher(self) -> None:
        """Cancel the watcher task and wait until it has finished."""
        task, self._watcher_task = self._watcher_task, None
        if task is None:
            return
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        logger.info("Layer 1 watcher stopped")

    async def _watch_rules(self, interval_seconds: float) -> None:
        while True:
            await asyncio.sleep(interval_seconds)
            try:
                # Imported here so the engine imports without a database.
                from src.database.storage import get_rules_fingerprint

                current = await get_rules_fingerprint()
                if current != self._fingerprint:
                    logger.info("Layer 1: rule change detected, reloading")
                    await self.load_rules()  # swaps rules in one assignment
            except Exception as exc:  # cancellation is not an Exception
                # Keep serving the last good rules; retry on next tick.
                logger.error("Layer 1 watcher error (keeping current rules): %s", exc)

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