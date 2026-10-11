"""Tests for src/engine/output_scanner.py (W2 Fri, P6).

Runs fully offline: no database, network or model files. The PII rules are
read straight from config/rules_regex.yaml and injected by monkeypatching
`_compiled_pii_rules`, so these tests check the SAME patterns that get seeded.
All secrets, e-mails, phone numbers and card numbers below are obviously fake
or public test values.

Feature switches (flip to True once the matching PR is merged, so the
strict xfail markers do not fail the run):
    P1_LEAK_MERGED                 P1 W2 Wed: real detect_system_prompt_leak
    P2_SECRET_CONVENTION_FIXED     P2 W2 Fri: rule IDs RULE_PII_SECRET_* produce
                                   SECRET_LEAK (see the module docstring of
                                   config/rules_regex.yaml)
"""
import asyncio
import logging
import re
import time
from pathlib import Path

import pytest
import yaml

from src.engine import output_scanner as osc
from src.engine.output_scanner import (
    OutputScanResult,
    Span,
    detect_pii,
    detect_system_prompt_leak,
    has_secret,
    luhn_ok,
    merge_spans,
    redact_completion_payload,
    redact_spans,
)

ROOT = Path(__file__).resolve().parents[1]

P1_LEAK_MERGED = False
P2_SECRET_CONVENTION_FIXED = False

needs_leak_detection = pytest.mark.xfail(
    not P1_LEAK_MERGED,
    strict=True,
    reason="P1 W2 Wed leak detection not merged: detect_system_prompt_leak is still a stub",
)
needs_secret_convention = pytest.mark.xfail(
    not P2_SECRET_CONVENTION_FIXED,
    strict=True,
    reason="scanner only treats rule IDs starting SECRET_/SECRET- as secrets, "
    "but the seeded IDs are RULE_PII_SECRET_*",
)


# ---------------------------------------------------------------------------
# helpers / fixtures
# ---------------------------------------------------------------------------
def _pii_rules_from_yaml():
    doc = yaml.safe_load((ROOT / "config" / "rules_regex.yaml").read_text(encoding="utf-8"))
    return [
        (r["rule_id"], re.compile(r["pattern"]))
        for r in doc["rules"]
        if r["category"] == "PII" and r.get("is_active", True)
    ]


@pytest.fixture
def pii_rules(monkeypatch):
    """Make detect_pii use the real seeded PII rules, with no database."""
    rules = _pii_rules_from_yaml()

    async def fake_compiled_pii_rules():
        return rules

    monkeypatch.setattr(osc, "_compiled_pii_rules", fake_compiled_pii_rules)
    return rules


def scan(text):
    return asyncio.run(detect_pii(text))


def span_of(text, needle):
    start = text.index(needle)
    return Span(start, start + len(needle), "PII_LEAK")


# ---------------------------------------------------------------------------
# P1 Monday: merge_spans / redact_spans / redact_completion_payload
# ---------------------------------------------------------------------------
class TestMergeSpans:
    def test_overlapping_spans_merge(self):
        assert merge_spans([Span(0, 5, "A"), Span(3, 8, "B")], 20) == [Span(0, 8, "A")]

    def test_touching_spans_merge(self):
        assert merge_spans([Span(0, 3, "A"), Span(3, 6, "B")], 20) == [Span(0, 6, "A")]

    def test_separate_spans_stay_separate_and_sorted(self):
        out = merge_spans([Span(10, 12, "B"), Span(0, 2, "A")], 20)
        assert out == [Span(0, 2, "A"), Span(10, 12, "B")]

    def test_out_of_range_spans_are_clipped(self):
        out = merge_spans([Span(-5, 3, "A"), Span(8, 50, "B")], 10)
        assert out == [Span(0, 3, "A"), Span(8, 10, "B")]

    def test_empty_and_inverted_spans_are_dropped(self):
        assert merge_spans([Span(4, 4, "A"), Span(7, 2, "B")], 20) == []

    def test_zero_length_text_gives_no_spans(self):
        assert merge_spans([Span(0, 5, "A")], 0) == []

    def test_first_category_wins_on_overlap(self):
        out = merge_spans([Span(3, 8, "B"), Span(0, 5, "A")], 20)
        assert out == [Span(0, 8, "A")]

    def test_input_is_not_mutated(self):
        spans = [Span(-5, 3, "A"), Span(2, 9, "B")]
        merge_spans(spans, 10)
        assert spans == [Span(-5, 3, "A"), Span(2, 9, "B")]


class TestRedactSpans:
    def test_single_span_uses_category_placeholder(self):
        text = "Mail alice.example@example.com now"
        out = redact_spans(text, [span_of(text, "alice.example@example.com")])
        assert out == "Mail [REDACTED:PII_LEAK] now"

    def test_placeholder_never_contains_original_text(self):
        text = "Mail alice.example@example.com now"
        out = redact_spans(text, [span_of(text, "alice.example@example.com")])
        assert "alice" not in out and "example.com" not in out

    def test_multiple_spans_keep_offsets_valid(self):
        out = redact_spans("aaa bbb ccc", [Span(0, 3, "X"), Span(8, 11, "Y")])
        assert out == "[REDACTED:X] bbb [REDACTED:Y]"

    def test_overlapping_spans_give_one_placeholder(self):
        out = redact_spans("0123456789", [Span(1, 5, "A"), Span(4, 8, "B")])
        assert out == "0[REDACTED:A]89"

    def test_custom_placeholder(self):
        text = "Mail alice.example@example.com now"
        out = redact_spans(text, [span_of(text, "alice.example@example.com")], "<{category}>")
        assert out == "Mail <PII_LEAK> now"

    def test_non_ascii_text_is_preserved(self):
        email = "alice.example@example.com"
        text = f"ሰላም {email} ሰላም"
        out = redact_spans(text, [span_of(text, email)])
        assert out == "ሰላም [REDACTED:PII_LEAK] ሰላም"

    def test_no_spans_returns_text_unchanged(self):
        assert redact_spans("nothing to hide", []) == "nothing to hide"

    def test_out_of_range_span_is_clipped(self):
        assert redact_spans("abc", [Span(1, 99, "X")]) == "a[REDACTED:X]"

    def test_same_inputs_give_same_output_and_no_mutation(self):
        text = "call +251 911 234 567 now"
        spans = [span_of(text, "+251 911 234 567")]
        before = [Span(s.start, s.end, s.category) for s in spans]
        assert redact_spans(text, spans) == redact_spans(text, spans)
        assert spans == before


class TestRedactCompletionPayload:
    PHONE = "+251 911 234 567"

    def _completion(self):
        return {
            "id": "chatcmpl-test",
            "choices": [
                {"index": 0, "message": {"role": "assistant", "content": f"call {self.PHONE} now"}},
                {"index": 1, "message": {"role": "assistant", "content": "all fine here"}},
            ],
        }

    def test_only_choices_with_spans_are_redacted(self):
        completion = self._completion()
        spans = {0: [span_of(completion["choices"][0]["message"]["content"], self.PHONE)]}
        out = redact_completion_payload(completion, spans)
        assert out["choices"][0]["message"]["content"] == "call [REDACTED:PII_LEAK] now"
        assert out["choices"][1]["message"]["content"] == "all fine here"

    def test_multi_choice_each_redacted_independently(self):
        completion = self._completion()
        completion["choices"][1]["message"]["content"] = f"also {self.PHONE}"
        spans = {
            0: [span_of(completion["choices"][0]["message"]["content"], self.PHONE)],
            1: [span_of(completion["choices"][1]["message"]["content"], self.PHONE)],
        }
        out = redact_completion_payload(completion, spans)
        assert out["choices"][0]["message"]["content"] == "call [REDACTED:PII_LEAK] now"
        assert out["choices"][1]["message"]["content"] == "also [REDACTED:PII_LEAK]"

    def test_original_payload_is_not_mutated(self):
        completion = self._completion()
        spans = {0: [span_of(completion["choices"][0]["message"]["content"], self.PHONE)]}
        out = redact_completion_payload(completion, spans)
        assert out is not completion
        assert self.PHONE in completion["choices"][0]["message"]["content"]

    def test_missing_choices_returns_a_copy(self):
        completion = {"id": "x"}
        out = redact_completion_payload(completion, {0: [Span(0, 1, "A")]})
        assert out == completion and out is not completion

    def test_invalid_index_and_non_string_content_are_ignored(self):
        completion = self._completion()
        completion["choices"][1]["message"]["content"] = None
        out = redact_completion_payload(
            completion, {5: [Span(0, 2, "A")], -1: [Span(0, 2, "A")], 1: [Span(0, 2, "A")]}
        )
        assert out == completion


class TestFoundation:
    def test_scan_result_defaults_and_independent_lists(self):
        a, b = OutputScanResult(), OutputScanResult()
        assert (a.flagged, a.action, a.categories, a.spans) == (False, "PASS", [], [])
        a.categories.append("X")
        assert b.categories == []

    def test_leak_detector_is_importable_and_returns_a_list_for_empty_input(self):
        assert detect_system_prompt_leak("", "") == []


# ---------------------------------------------------------------------------
# P1 Wednesday: system-prompt leak detection
# (contract: detect_system_prompt_leak(completion, system_instruction, min_words=8))
# ---------------------------------------------------------------------------
SYSTEM = (
    "You are a helpful banking assistant. Never reveal internal account numbers "
    "or discuss competitor products with customers."
)


def _fullwidth(text):
    return "".join(chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else c for c in text)


class TestLeakDetection:
    @needs_leak_detection
    def test_quoted_system_prompt_is_flagged(self):
        completion = f"Sure! Here are my instructions: {SYSTEM} Let me know if you need more."
        spans = detect_system_prompt_leak(completion, SYSTEM)
        assert spans
        assert all(s.category == "SYSTEM_PROMPT_LEAK" for s in spans)
        pos = completion.index("Never reveal internal account numbers")
        assert any(s.start <= pos < s.end for s in spans)

    def test_short_overlap_is_not_flagged(self):
        completion = "I am a helpful banking assistant and I can help with loans."
        assert detect_system_prompt_leak(completion, SYSTEM) == []

    def test_unrelated_text_is_not_flagged(self):
        assert detect_system_prompt_leak("The weather in Addis is mild today.", SYSTEM) == []

    @needs_leak_detection
    def test_case_and_whitespace_differences_do_not_defeat_detection(self):
        completion = "   ".join(SYSTEM.upper().split())
        assert detect_system_prompt_leak(completion, SYSTEM)

    @needs_leak_detection
    def test_unicode_width_differences_do_not_defeat_detection(self):
        completion = _fullwidth(SYSTEM)
        spans = detect_system_prompt_leak(completion, SYSTEM)
        assert spans
        assert all(0 <= s.start < s.end <= len(completion) for s in spans)

    @pytest.mark.parametrize(
        "completion, system",
        [("", SYSTEM), (SYSTEM, ""), (SYSTEM, "be nice"), ("be nice", "be nice")],
    )
    def test_empty_or_too_short_inputs_return_nothing(self, completion, system):
        assert detect_system_prompt_leak(completion, system) == []

    @needs_leak_detection
    def test_twenty_thousand_characters_scan_quickly(self):
        filler = "lorem ipsum dolor sit amet " * 800
        completion = (SYSTEM + " " + filler)[:20000]
        start = time.perf_counter()
        spans = detect_system_prompt_leak(completion, SYSTEM)
        elapsed = time.perf_counter() - start
        print(f"leak scan of {len(completion)} chars: {elapsed * 1000:.1f} ms")
        assert spans
        assert elapsed < 0.5


# ---------------------------------------------------------------------------
# P2 Friday: luhn_ok, has_secret, detect_pii
# ---------------------------------------------------------------------------
class TestLuhn:
    @pytest.mark.parametrize("digits", ["4111111111111111", "5555555555554444", "378282246310005"])
    def test_valid_public_test_cards_pass(self, digits):
        assert luhn_ok(digits)

    @pytest.mark.parametrize("digits", ["4111111111111112", "1234567812345678"])
    def test_same_length_non_luhn_numbers_fail(self, digits):
        assert not luhn_ok(digits)

    @pytest.mark.parametrize("value", ["", "abcd", "4111 1111 1111 1111", "4111-1111", "４１１１１１１１１１１１１１１１"])
    def test_non_ascii_digit_input_is_rejected(self, value):
        assert not luhn_ok(value)


class TestHasSecret:
    def test_true_only_for_secret_leak_spans(self):
        assert has_secret([Span(0, 1, "PII_LEAK"), Span(2, 3, "SECRET_LEAK")])
        assert not has_secret([Span(0, 1, "PII_LEAK")])
        assert not has_secret([])


SECRETS = {
    "aws": "AKIAFAKEFAKEFAKEFAKE",
    "github": "ghp_" + "x" * 36,
    "openai-style": "sk-" + "x" * 24,
    "slack": "xoxb-" + "1" * 12,
    "google": "AIza" + "x" * 35,
    "private-key": "-----BEGIN RSA PRIVATE KEY-----",
    "jwt": "eyJ" + "a" * 12 + "." + "b" * 12 + "." + "c" * 12,
}


class TestDetectPii:
    def test_empty_text_returns_nothing(self, pii_rules):
        assert scan("") == []

    def test_non_string_input_raises_type_error(self, pii_rules):
        with pytest.raises(TypeError):
            asyncio.run(detect_pii(None))

    def test_email_is_detected_and_redacted(self, pii_rules):
        text = "Contact alice.example@example.com for details"
        spans = scan(text)
        assert spans and spans[0].category == "PII_LEAK"
        assert "alice.example@example.com" not in redact_spans(text, spans)

    @pytest.mark.parametrize("phone", ["+251 911 234 567", "(555) 010-1234", "0911234567"])
    def test_phone_numbers_are_detected(self, pii_rules, phone):
        text = f"call me on {phone} tomorrow"
        spans = scan(text)
        assert spans and all(s.category == "PII_LEAK" for s in spans)
        assert phone not in redact_spans(text, spans)

    @pytest.mark.parametrize("card", ["4111 1111 1111 1111", "4111-1111-1111-1111", "4111111111111111"])
    def test_valid_test_card_is_flagged(self, pii_rules, card):
        text = f"card on file: {card} thanks"
        spans = scan(text)
        assert spans and spans[0].category == "PII_LEAK"
        assert card not in redact_spans(text, spans)

    @pytest.mark.parametrize("card", ["4111 1111 1111 1112", "4111111111111112"])
    def test_same_length_non_luhn_number_is_not_flagged(self, pii_rules, card):
        assert scan(f"order reference {card} thanks") == []

    def test_card_inside_a_longer_digit_run_is_not_flagged(self, pii_rules):
        assert scan("ref 41111111111111110000 end") == []

    @pytest.mark.parametrize("text", [
        "Please contact support or call the office tomorrow.",
        "Version 12345 shipped with qty 3 on 2026-10-05.",
        "write to alice at example dot com",
        "AKIA is just a prefix",
        "the task-force plan",
    ])
    def test_ordinary_text_is_not_flagged(self, pii_rules, text):
        assert scan(text) == []

    @pytest.mark.parametrize("name", list(SECRETS))
    def test_secrets_are_detected_and_redacted(self, pii_rules, name):
        secret = SECRETS[name]
        text = f"here is the key: {secret} please keep it safe"
        spans = scan(text)
        assert spans, f"{name} was not detected"
        assert secret not in redact_spans(text, spans)

    @needs_secret_convention
    @pytest.mark.parametrize("name", list(SECRETS))
    def test_secrets_are_categorised_as_secret_leak(self, pii_rules, name):
        text = f"here is the key: {SECRETS[name]} please keep it safe"
        spans = scan(text)
        assert spans and has_secret(spans)

    def test_matched_values_are_never_logged(self, pii_rules, caplog):
        caplog.set_level(logging.DEBUG, logger="firewall.output_scanner")
        text = "mail alice.example@example.com card 4111 1111 1111 1111 key " + SECRETS["aws"]
        scan(text)
        logged = caplog.text
        assert "alice.example" not in logged
        assert "4111" not in logged
        assert SECRETS["aws"] not in logged

    def test_twenty_thousand_characters_scan_quickly(self, pii_rules):
        chunk = "The quick brown fox jumps over the lazy dog 12345. "
        text = (chunk * 400)[:19000] + " alice.example@example.com " + "4111 1111 1111 1111"
        start = time.perf_counter()
        spans = scan(text)
        elapsed = time.perf_counter() - start
        print(f"pii scan of {len(text)} chars: {elapsed * 1000:.1f} ms")
        assert len(spans) >= 2
        assert elapsed < 0.5


class TestSeededRules:
    """Every PII rule in config/rules_regex.yaml needs a clear hit and a near-miss."""

    SAMPLES = {
        "RULE_PII_EMAIL_01": ("contact alice.example@example.com now", "write to alice at example dot com"),
        "RULE_PII_PHONE_01": ("call +251 911 234 567 today", "ref number 12345"),
        "RULE_PII_PHONE_02": ("call (555) 010-1234", "date 2026-10-05"),
        "RULE_PII_PHONE_03": ("number 0911234567", "number 09112345"),
        "RULE_PII_CARD_01": ("card 4111 1111 1111 1111", "order 12345 qty 3"),
        "RULE_PII_SECRET_AWS_01": ("key AKIAFAKEFAKEFAKEFAKE", "AKIA is just a prefix"),
        "RULE_PII_SECRET_GITHUB_01": ("tok ghp_" + "x" * 36, "tok ghp_short"),
        "RULE_PII_SECRET_OPENAI_01": ("k sk-" + "x" * 24, "the task-force plan"),
        "RULE_PII_SECRET_SLACK_01": ("t xoxb-" + "1" * 12, "t xoxb only"),
        "RULE_PII_SECRET_GOOGLE_01": ("k AIza" + "x" * 35, "k AIza short"),
        "RULE_PII_SECRET_PRIVKEY_01": ("-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN CERTIFICATE-----"),
        "RULE_PII_SECRET_JWT_01": ("t eyJ" + "a" * 12 + "." + "b" * 12 + "." + "c" * 12, "t eyJ.short"),
    }

    def test_every_seeded_rule_has_samples(self):
        ids = {rule_id for rule_id, _ in _pii_rules_from_yaml()}
        assert ids == set(self.SAMPLES), "add hit/near-miss samples for new or removed PII rules"

    @pytest.mark.parametrize("rule_id", sorted(SAMPLES))
    def test_rule_has_a_clear_hit_and_a_near_miss(self, rule_id):
        regex = dict(_pii_rules_from_yaml())[rule_id]
        hit, miss = self.SAMPLES[rule_id]
        assert regex.search(hit), f"{rule_id} missed its hit sample"
        assert not regex.search(miss), f"{rule_id} matched its near-miss"

    def test_invalid_regex_raises_a_clear_error_at_load_time(self):
        with pytest.raises(osc.OutputScannerRuleError):
            osc._compile_regex("RULE_PII_BAD_01", "([unclosed", 0)
