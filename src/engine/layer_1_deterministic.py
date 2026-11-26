"""
Layer 1 - Deterministic Engine.

Sub-millisecond regex / keyword matching against the active rule set,
held fully compiled in memory so evaluation never touches the database
on the hot path (SRS FR-L1-01, FR-L1-03, FR-L1-04).

Note: the hot-reload watcher (start_watcher / stop_watcher) is added to
this same file on Friday by P6. It is not part of this Wednesday task.
"""

import asyncio
import base64
import binascii
import logging
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import unquote, unquote_plus

logger = logging.getLogger("firewall.layer1")

_BASE64_RE = re.compile(r"(?<![\w+/_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![\w+/_=-])")
_HEX_RE = re.compile(r"(?<![A-Fa-f0-9])(?:[A-Fa-f0-9]{2}){8,}(?![A-Fa-f0-9])")
_LEET_TRANSLATION = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t"})
_ROT13_TRANSLATION = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)
_LOOKALIKE_TRANSLATION = str.maketrans({
    "\u0430": "a", "\u0410": "A", "\u0435": "e", "\u0415": "E",
    "\u043e": "o", "\u041e": "O", "\u0440": "p", "\u0420": "P",
    "\u0441": "c", "\u0421": "C", "\u0445": "x", "\u0425": "X",
    "\u0443": "y", "\u0423": "Y", "\u0456": "i", "\u0406": "I",
    "\u0458": "j", "\u0408": "J", "\u03b1": "a", "\u0391": "A",
    "\u03b5": "e", "\u0395": "E", "\u03bf": "o", "\u039f": "O",
    "\u03c1": "p", "\u03a1": "P", "\u03b9": "i", "\u0399": "I",
    "\u03ba": "k", "\u039a": "K", "\u03bd": "v", "\u039d": "N",
    "\u03c4": "t", "\u03a4": "T", "\u03c7": "x", "\u03a7": "X",
})


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
            if (rule.get("category") or "").upper() == "PII":
                continue
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
        database_rules = await get_active_layer1_rules()
        rules = [
            {
                "rule_id": rule["rule_id"],
                "rule_type": rule["rule_type"],
                "category": rule["category"],
                "pattern": rule["pattern"],
                "severity": rule["severity"],
            }
            for rule in database_rules
        ]
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
        their plain equivalents), remove invisible format characters,
        and collapse repeated whitespace.
        """
        if not text:
            return ""
        normalized = unicodedata.normalize("NFKC", text)
        normalized = "".join(
            char for char in normalized
            if unicodedata.category(char) != "Cf"
        )
        return re.sub(r"\s+", " ", normalized).strip()

    @classmethod
    def _inspection_variants(cls, text: str) -> tuple[list[str], bool]:
        """Return bounded decoded/normalized views and whether a large blob was found."""
        normalized = cls._normalize(text)
        variants = [text]
        seen = {text}
        large_encoded_blob = False

        def add(value: str) -> None:
            value = cls._normalize(value)
            if value and value not in seen:
                seen.add(value)
                variants.append(value)

        add(normalized)
        spaced_invisibles = cls._normalize("".join(
            " " if unicodedata.category(char) == "Cf" else char
            for char in unicodedata.normalize("NFKC", text)
        ))
        add(spaced_invisibles)
        add(normalized.translate(_LOOKALIKE_TRANSLATION))

        for decoder in (unquote, unquote_plus):
            decoded_url = normalized
            for _ in range(2):
                next_url = decoder(decoded_url)
                if next_url == decoded_url:
                    break
                decoded_url = next_url
                add(decoded_url)

        primary_variants = tuple(variants)
        for source in primary_variants:
            for match in _BASE64_RE.finditer(source):
                token = match.group()
                if len(token) >= 256:
                    large_encoded_blob = True
                padded = token + "=" * (-len(token) % 4)
                try:
                    raw = base64.b64decode(padded, altchars=b"-_", validate=True)
                    decoded = raw.decode("utf-8")
                except (binascii.Error, UnicodeDecodeError, ValueError):
                    continue
                if decoded and all(char.isprintable() or char.isspace() for char in decoded):
                    add(decoded)

            for match in _HEX_RE.finditer(source):
                token = match.group()
                if len(token) >= 256:
                    large_encoded_blob = True
                try:
                    decoded = bytes.fromhex(token).decode("utf-8")
                except (ValueError, UnicodeDecodeError):
                    continue
                if decoded and all(char.isprintable() or char.isspace() for char in decoded):
                    add(decoded)

            add(source.translate(_ROT13_TRANSLATION))
            add(source.translate(_LEET_TRANSLATION))
        return variants, large_encoded_blob

    def evaluate(self, prompt: str, system_instruction: str = "") -> Layer1MatchResult:
        """
        Evaluate a prompt (and optional system instruction) against all
        active Layer 1 rules. Returns on the first match — short-circuit,
        per FR-L1-03 — rather than collecting every match.
        """
        text = f"{prompt or ''} {system_instruction or ''}"
        variants, large_encoded_blob = self._inspection_variants(text)

        if large_encoded_blob:
            return Layer1MatchResult(
                matched=True,
                rule_id="RULE_ENCODED_BLOB_01",
                category="ENCODED_CONTENT",
                severity="HIGH",
                patterns=["RULE_ENCODED_BLOB_01"],
            )

        for variant in variants:
            variant_lower = variant.lower()
            for rule in self._rules:
                if rule["rule_type"] == "REGEX":
                    hit = rule["compiled"].search(variant) is not None
                else:  # KEYWORD
                    hit = rule["keyword_lower"] in variant_lower

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