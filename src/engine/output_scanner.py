"""Output scanner: inspects LLM completions before they reach the client.

This file is built up over Week 2 by different people:
  - P1 Mon : Span, merge_spans, redact_spans, redact_completion_payload,
             OutputScanResult, and stubs for the two detectors (this version)
  - P1 Wed : detect_system_prompt_leak (real implementation)
  - P2 Fri : detect_pii (real implementation, replaces the stub body only)

Rules for everything in this file:
  - Redaction placeholders never contain the original text.
  - Input objects (text, spans, completion dicts) are never mutated.
  - No network access, no heavy imports.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field


@dataclass
class Span:
    """A half-open character range [start, end) in a text, tagged with a category."""

    start: int
    end: int
    category: str


@dataclass
class OutputScanResult:
    flagged: bool = False
    categories: list[str] = field(default_factory=list)
    spans: list[Span] = field(default_factory=list)
    action: str = "PASS"  # PASS | BLOCK | REDACT | WARN


# --------------------------------------------------------------------- spans
def merge_spans(spans: list[Span], text_len: int) -> list[Span]:
    """Clip spans to [0, text_len], drop empty ones, sort, and merge overlapping
    or touching spans. The first span's category wins in a merge.

    Returns new Span objects; the input list and its spans are not changed.
    """
    limit = max(0, text_len)
    clipped: list[Span] = []
    for s in spans:
        start = max(0, min(s.start, limit))
        end = max(0, min(s.end, limit))
        if end > start:
            clipped.append(Span(start, end, s.category))

    clipped.sort(key=lambda s: (s.start, s.end))

    merged: list[Span] = []
    for s in clipped:
        if merged and s.start <= merged[-1].end:  # overlapping or touching
            merged[-1].end = max(merged[-1].end, s.end)
        else:
            merged.append(s)
    return merged


def redact_spans(
    text: str,
    spans: list[Span],
    placeholder: str = "[REDACTED:{category}]",
) -> str:
    """Replace each span in `text` with a placeholder.

    Spans are merged first, then replaced from the end to the start so the
    offsets of the remaining spans stay valid. The placeholder only uses the
    category name, never the original text.
    """
    merged = merge_spans(spans, len(text))
    result = text
    for s in reversed(merged):
        replacement = placeholder.replace("{category}", s.category)
        result = result[: s.start] + replacement + result[s.end :]
    return result


def redact_completion_payload(
    completion: dict,
    spans_by_choice: dict[int, list[Span]],
) -> dict:
    """Return a deep copy of an OpenAI-style completion with
    choices[i].message.content redacted for every choice that has spans.

    The input completion is never mutated. Unknown choice indexes and
    non-string content are left alone.
    """
    result = copy.deepcopy(completion)
    choices = result.get("choices")
    if not isinstance(choices, list):
        return result

    for index, spans in spans_by_choice.items():
        if not spans or not isinstance(index, int) or not 0 <= index < len(choices):
            continue
        choice = choices[index]
        message = choice.get("message") if isinstance(choice, dict) else None
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if isinstance(content, str):
            message["content"] = redact_spans(content, spans)
    return result


# ---------------------------------------------------------------- detectors
def detect_system_prompt_leak(
    completion: str, system_instruction: str, min_words: int = 8
) -> list[Span]:
    # TODO(P1, Wed): implement the text-overlap leak detector
    return []


def detect_pii(text: str) -> list[Span]:
    # TODO(P2, Fri): implement PII / secret detection
    return []
