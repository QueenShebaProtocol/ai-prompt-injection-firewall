
"""Output scanner: inspects LLM completions before they reach the client.
"""

from __future__ import annotations

import copy
import logging
import re
import unicodedata
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Mapping, Sequence


logger = logging.getLogger("firewall.output_scanner")

# Rule-ID convention agreed for this implementation:
# IDs beginning with SECRET_ or SECRET- produce SECRET_LEAK spans.
# Other rules loaded from the PII category produce PII_LEAK spans.
_SECRET_RULE_PREFIXES = ("SECRET_", "SECRET-")

# Accepted field names allow the scanner to work with dictionaries or
# ORM-like rule objects. Align these with the actual P5 rule model.
_PATTERN_FIELDS = ("pattern", "regex", "expression", "regex_pattern")
_RULE_ID_FIELDS = ("rule_id", "id", "name")
_FLAGS_FIELDS = ("flags", "regex_flags")


class OutputScannerRuleError(ValueError):
    """Raised when an output-scanner rule is missing required data or invalid."""


@dataclass
class Span:
    """A half-open character range [start, end), tagged with a category."""

    start: int
    end: int
    category: str


@dataclass
class OutputScanResult:
    flagged: bool = False
    categories: list[str] = field(default_factory=list)
    spans: list[Span] = field(default_factory=list)
    action: str = "PASS"  # PASS | BLOCK | REDACT | WARN


# ---------------------------------------------------------------------------
# Span utilities
# ---------------------------------------------------------------------------

def merge_spans(spans: list[Span], text_len: int) -> list[Span]:
    """Clip, sort, and merge overlapping or touching spans.

    The first span's category wins when spans overlap.
    Returns new Span objects without mutating the input.
    """
    limit = max(0, text_len)
    clipped: list[Span] = []

    for span in spans:
        start = max(0, min(span.start, limit))
        end = max(0, min(span.end, limit))

        if end > start:
            clipped.append(Span(start, end, span.category))

    clipped.sort(key=lambda span: (span.start, span.end))

    merged: list[Span] = []
    for span in clipped:
        if merged and span.start <= merged[-1].end:
            merged[-1].end = max(merged[-1].end, span.end)
        else:
            merged.append(Span(span.start, span.end, span.category))

    return merged


def redact_spans(
    text: str,
    spans: list[Span],
    placeholder: str = "[REDACTED:{category}]",
) -> str:
    """Redact spans without including the original matched text."""
    merged = merge_spans(spans, len(text))
    result = text

    for span in reversed(merged):
        replacement = placeholder.replace("{category}", span.category)
        result = result[:span.start] + replacement + result[span.end:]

    return result


def redact_completion_payload(
    completion: dict,
    spans_by_choice: dict[int, list[Span]],
) -> dict:
    """Return a redacted deep copy of an OpenAI-style completion."""
    result = copy.deepcopy(completion)
    choices = result.get("choices")

    if not isinstance(choices, list):
        return result

    for index, spans in spans_by_choice.items():
        if (
            not spans
            or not isinstance(index, int)
            or not 0 <= index < len(choices)
        ):
            continue

        choice = choices[index]
        message = choice.get("message") if isinstance(choice, dict) else None

        if not isinstance(message, dict):
            continue

        content = message.get("content")
        if isinstance(content, str):
            message["content"] = redact_spans(content, spans)

    return result


# ---------------------------------------------------------------------------
# P1 Wednesday: preserve the real implementation from your existing branch.
# ---------------------------------------------------------------------------

_WORD_RE = re.compile(r"\w+")

SYSTEM_PROMPT_LEAK = "SYSTEM_PROMPT_LEAK"

# Scan limits (keeps the detector fast and its cost predictable).
# Only the first MAX_COMPLETION_CHARS characters of a completion are scanned,
# so a leak that starts after that point is not detected.
# Only the first MAX_SYSTEM_CHARS characters of the system instruction are used.
MAX_COMPLETION_CHARS = 20_000
MAX_SYSTEM_CHARS = 50_000


def normalize_with_offsets(text: str) -> tuple[str, list[int], list[int]]:
    """Normalize `text` and return (normalized, starts, ends).

    Normalization: NFKC, lowercase, invisible format characters (zero-width
    spaces, soft hyphens, ...) removed, runs of whitespace collapsed to one
    space, leading/trailing whitespace removed.

    `starts[j]` / `ends[j]` give the [start, end) range in the ORIGINAL text
    that produced normalized character j, so matches can be mapped back.
    """
    out: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    prev_space = True  # also strips leading whitespace
    n = len(text)
    i = 0
    while i < n:
        # Keep a base character together with its combining marks, so NFKC
        # composes them the same way it would for the whole string.
        j = i + 1
        while j < n and unicodedata.combining(text[j]):
            j += 1
        for ch in unicodedata.normalize("NFKC", text[i:j]).lower():
            if ch.isspace():
                if not prev_space:
                    out.append(" ")
                    starts.append(i)
                    ends.append(j)
                    prev_space = True
            elif unicodedata.category(ch) == "Cf":
                continue  # invisible format character
            else:
                out.append(ch)
                starts.append(i)
                ends.append(j)
                prev_space = False
        i = j

    if out and out[-1] == " ":  # strip trailing whitespace
        out.pop()
        starts.pop()
        ends.pop()
    return "".join(out), starts, ends


def normalize(text: str) -> str:
    """NFKC, lowercase, collapse whitespace. See `normalize_with_offsets`."""
    if text.isascii():  # fast path: same result, no offset map needed
        return " ".join(text.lower().split())
    return normalize_with_offsets(text)[0]


def _tokenize(text: str) -> list[tuple[str, int, int]]:
    """Split `text` into normalized words, as (word, start, end) where
    start/end are offsets in the ORIGINAL text."""
    if text.isascii():
        # Lowercasing ASCII keeps every offset identical to the original.
        return [(m.group(), m.start(), m.end()) for m in _WORD_RE.finditer(text.lower())]

    normalized, starts, ends = normalize_with_offsets(text)
    return [
        (m.group(), starts[m.start()], ends[m.end() - 1])
        for m in _WORD_RE.finditer(normalized)
    ]


def detect_system_prompt_leak(
    completion: str,
    system_instruction: str,
    min_words: int = 8,
) -> list[Span]:
    """Find places where `completion` repeats the system instruction.

    A leak is `min_words` or more consecutive words that appear in the same
    order in the system instruction. Comparison ignores case, punctuation,
    spacing and Unicode width/compatibility differences. Overlapping or
    adjacent matches are merged into one span (category SYSTEM_PROMPT_LEAK)
    with offsets in the original `completion`.

    Cost: one pass over each text plus one hash lookup per completion word.
    Returns [] when either input is empty or the system instruction has fewer
    than `min_words` words.
    """
    if not completion or not system_instruction:
        return []
    k = max(1, int(min_words))

    sys_words = [w for w, _, _ in _tokenize(system_instruction[:MAX_SYSTEM_CHARS])]
    if len(sys_words) < k:
        return []
    shingles = {tuple(sys_words[i : i + k]) for i in range(len(sys_words) - k + 1)}

    tokens = _tokenize(completion[:MAX_COMPLETION_CHARS])
    words = [w for w, _, _ in tokens]

    spans: list[Span] = []
    run_start = -1  # first word index of the current leaked run
    run_end = -1    # last word index of the current leaked run
    for i in range(len(words) - k + 1):
        if tuple(words[i : i + k]) not in shingles:
            continue
        if run_start >= 0 and i <= run_end + 1:  # overlaps or touches the run
            run_end = i + k - 1
        else:
            if run_start >= 0:
                spans.append(Span(start=tokens[run_start][1], end=tokens[run_end][2], category=SYSTEM_PROMPT_LEAK))
            run_start, run_end = i, i + k - 1
    if run_start >= 0:
        spans.append(Span(start=tokens[run_start][1], end=tokens[run_end][2], category=SYSTEM_PROMPT_LEAK))
    return spans


# ---------------------------------------------------------------------------
# Rule loading and regex compilation
# ---------------------------------------------------------------------------

def _get_field(rule: Any, field_names: Sequence[str]) -> Any:
    """Read a rule field from either a mapping or an object."""
    for name in field_names:
        if isinstance(rule, Mapping):
            if name in rule:
                return rule[name]
        elif hasattr(rule, name):
            return getattr(rule, name)

    return None


def _normalize_flags(flags: Any) -> int:
    """Convert supported flag representations into Python regex flags."""
    if flags is None or flags == "":
        return 0

    if isinstance(flags, int):
        return flags

    if isinstance(flags, str):
        result = 0
        known_flags = {
            "IGNORECASE": re.IGNORECASE,
            "I": re.IGNORECASE,
            "MULTILINE": re.MULTILINE,
            "M": re.MULTILINE,
            "DOTALL": re.DOTALL,
            "S": re.DOTALL,
            "ASCII": re.ASCII,
            "A": re.ASCII,
        }

        for item in re.split(r"[\s,|]+", flags.strip().upper()):
            if not item:
                continue
            if item not in known_flags:
                raise OutputScannerRuleError(
                    f"Unsupported regex flag {item!r} in output-scanner rule."
                )
            result |= known_flags[item]

        return result

    if isinstance(flags, (list, tuple, set)):
        result = 0
        for item in flags:
            result |= _normalize_flags(item)
        return result

    raise OutputScannerRuleError(
        f"Unsupported regex flags type: {type(flags).__name__}."
    )


def _rule_signature(rule: Any) -> tuple[str, str, int]:
    """Extract and validate a rule's ID, pattern, and regex flags."""
    rule_id = _get_field(rule, _RULE_ID_FIELDS)
    pattern = _get_field(rule, _PATTERN_FIELDS)
    flags = _get_field(rule, _FLAGS_FIELDS)

    if not isinstance(rule_id, str) or not rule_id.strip():
        raise OutputScannerRuleError(
            "Output-scanner rule is missing a non-empty rule_id."
        )

    if not isinstance(pattern, str) or not pattern:
        raise OutputScannerRuleError(
            f"Output-scanner rule {rule_id!r} is missing a regex pattern."
        )

    normalized_flags = _normalize_flags(flags)

    # Validate immediately, so a malformed rule fails during loading rather
    # than during a later request scan.
    try:
        re.compile(pattern, normalized_flags)
    except re.error as exc:
        raise OutputScannerRuleError(
            f"Invalid regex in output-scanner rule {rule_id!r}: {exc}"
        ) from exc

    return rule_id.strip(), pattern, normalized_flags


@lru_cache(maxsize=512)
def _compile_regex(rule_id: str, pattern: str, flags: int) -> re.Pattern[str]:
    """Compile a rule once and reuse its compiled regex."""
    try:
        return re.compile(pattern, flags)
    except re.error as exc:
        # Defensive validation in case this helper is called directly.
        raise OutputScannerRuleError(
            f"Invalid regex in output-scanner rule {rule_id!r}: {exc}"
        ) from exc


async def _load_active_pii_rules() -> list[Any]:
    """Load PII-category rules from the storage layer.

    P5 should expose:
        async def get_active_output_scanner_rules(category: str) -> list[...]
    """
    try:
        from src.database.storage import get_active_output_scanner_rules
    except ImportError as exc:
        raise RuntimeError(
            "Cannot import get_active_output_scanner_rules from "
            "src.database.storage. Confirm the P5 implementation and "
            "update this import if the function lives elsewhere."
        ) from exc

    rules = await get_active_output_scanner_rules("PII")

    if rules is None:
        return []

    if isinstance(rules, (str, bytes, Mapping)):
        raise OutputScannerRuleError(
            "get_active_output_scanner_rules('PII') must return a sequence "
            "of rule objects, not a single string or mapping."
        )

    if not isinstance(rules, Sequence):
        try:
            rules = list(rules)
        except TypeError as exc:
            raise OutputScannerRuleError(
                "The PII rule loader did not return an iterable of rules."
            ) from exc

    return list(rules)


async def _compiled_pii_rules() -> list[tuple[str, re.Pattern[str]]]:
    """Load current active rules and reuse cached compiled patterns."""
    rules = await _load_active_pii_rules()
    compiled: list[tuple[str, re.Pattern[str]]] = []

    for rule in rules:
        rule_id, pattern, flags = _rule_signature(rule)
        compiled.append((rule_id, _compile_regex(rule_id, pattern, flags)))

    return compiled


# ---------------------------------------------------------------------------
# Card validation and secret helpers
# ---------------------------------------------------------------------------

def luhn_ok(digits: str) -> bool:
    """Return whether a digit string passes the Luhn checksum.

    Non-digit characters are rejected. This validates the checksum only;
    it does not prove that a payment card exists or is active.
    """
    if not digits or not digits.isascii() or not digits.isdigit():
        return False

    total = 0
    parity = len(digits) % 2

    for index, char in enumerate(digits):
        value = ord(char) - ord("0")

        if index % 2 == parity:
            value *= 2
            if value > 9:
                value -= 9

        total += value

    return total % 10 == 0


def has_secret(spans: list[Span]) -> bool:
    """Return True if any span represents a detected secret."""
    return any(span.category == "SECRET_LEAK" for span in spans)


def _is_ascii_digit(char: str) -> bool:
    """Use ASCII digit boundaries for identifiers and card numbers."""
    return "0" <= char <= "9"


def _violates_digit_boundary(text: str, start: int, end: int) -> bool:
    """Reject a match embedded inside a longer digit sequence."""
    if start > 0 and _is_ascii_digit(text[start - 1]):
        return True

    if end < len(text) and _is_ascii_digit(text[end]):
        return True

    return False


def _candidate_digits(match_text: str) -> str:
    """Remove common separators from a matched card-number candidate."""
    return "".join(char for char in match_text if char.isascii() and char.isdigit())


# ---------------------------------------------------------------------------
# P2 Friday: PII and API-key / secret detection
# ---------------------------------------------------------------------------

async def detect_pii(text: str) -> list[Span]:
    """Detect PII and secrets using active PII-category regex rules.

    Rule IDs starting with SECRET_ or SECRET- are tagged SECRET_LEAK.
    Other rules are tagged PII_LEAK.

    For rules whose ID contains CARD (case-insensitive), the match must:
      1. Not be embedded inside a longer digit sequence.
      2. Pass the Luhn checksum after common separators are removed.

    Only category/count metadata is logged; matched values are never logged.
    """
    if not isinstance(text, str):
        raise TypeError("detect_pii(text) expects text to be a string.")

    if not text:
        return []

    compiled_rules = await _compiled_pii_rules()
    spans: list[Span] = []

    for rule_id, regex in compiled_rules:
        category = (
            "SECRET_LEAK"
            if rule_id.upper().startswith(_SECRET_RULE_PREFIXES)
            else "PII_LEAK"
        )
        is_card_rule = "CARD" in rule_id.upper()

        try:
            for match in regex.finditer(text):
                start, end = match.span()

                if start == end:
                    continue

                # Avoid false positives for numbers embedded in longer
                # digit strings (for example, a 16-digit card within 17 digits).
                if _violates_digit_boundary(text, start, end):
                    continue

                if is_card_rule:
                    digits = _candidate_digits(match.group(0))
                    if not luhn_ok(digits):
                        continue

                spans.append(Span(start=start, end=end, category=category))

        except re.error as exc:
            # Compiled regexes should not fail during finditer. Keep the
            # exception clear if an unusual runtime regex failure occurs.
            raise OutputScannerRuleError(
                f"Regex scan failed for output-scanner rule {rule_id!r}: {exc}"
            ) from exc

    # Log only aggregate metadata. Never log text, match.group(0), or digits.
    if spans:
        category_counts: dict[str, int] = {}
        for span in spans:
            category_counts[span.category] = (
                category_counts.get(span.category, 0) + 1
            )

        logger.info(
            "Output scanner detected matches: total=%d categories=%s",
            len(spans),
            category_counts,
        )

    return merge_spans(spans, len(text))
