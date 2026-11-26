import asyncio
import json

from src.engine.layer_2_classifier import ClassifierUnavailable
from src.engine.output_scanner import OutputScanResult, Span, redact_completion_payload
from src.proxy import handler


def test_prompt_token_limit_rejects_oversized_user_prompt(monkeypatch):
    monkeypatch.setenv("L2_MAX_LENGTH", "512")
    monkeypatch.setenv("MAX_PROMPT_TOKENS", "256")
    monkeypatch.setattr(handler, "count_prompt_tokens", lambda text: 257)

    response = asyncio.run(
        handler._check_prompt_token_limit(
            {"messages": [{"role": "user", "content": "too long"}]},
            "request-1",
        )
    )

    assert response.status_code == 413
    body = json.loads(response.body)
    assert body["error"]["code"] == "prompt_too_long"
    assert body["error"]["max_tokens"] == 256
    assert body["error"]["actual_tokens"] == 257


def test_prompt_token_limit_ignores_system_context_and_history(monkeypatch):
    observed = []
    monkeypatch.setenv("L2_MAX_LENGTH", "512")
    monkeypatch.setenv("MAX_PROMPT_TOKENS", "256")

    def count_tokens(text):
        observed.append(text)
        return 256

    monkeypatch.setattr(handler, "count_prompt_tokens", count_tokens)
    body = {
        "messages": [
            {"role": "system", "content": "system context " * 1000},
            {"role": "user", "content": "earlier user turn"},
            {"role": "assistant", "content": "assistant response"},
            {
                "role": "user",
                "content": [{"type": "text", "text": "latest user prompt"}],
            },
        ]
    }

    response = asyncio.run(handler._check_prompt_token_limit(body, "request-boundary"))

    assert response is None
    assert observed == ["latest user prompt"]


def test_prompt_token_limit_fails_closed_when_tokenizer_is_unavailable(monkeypatch):
    def tokenizer_unavailable(text):
        raise ClassifierUnavailable("missing")

    monkeypatch.setattr(
        handler,
        "count_prompt_tokens",
        tokenizer_unavailable,
    )

    response = asyncio.run(
        handler._check_prompt_token_limit(
            {"messages": [{"role": "user", "content": "prompt"}]},
            "request-2",
        )
    )

    assert response.status_code == 503
    assert json.loads(response.body)["error"]["code"] == "prompt_limit_unavailable"


def test_request_validation_accepts_up_to_four_choices():
    assert handler._validate_body({
        "messages": [{"role": "user", "content": "hello"}],
        "n": 4,
    }) is None


def test_request_validation_rejects_more_than_four_choices():
    error = handler._validate_body({
        "messages": [{"role": "user", "content": "hello"}],
        "n": 5,
    })

    assert error == ("too_many_choices", "'n' cannot exceed 4.")


def test_request_validation_rejects_non_positive_or_non_integer_choice_count():
    for choice_count in (0, -1, 1.5, True, "2"):
        error = handler._validate_body({
            "messages": [{"role": "user", "content": "hello"}],
            "n": choice_count,
        })
        assert error == ("invalid_n", "'n' must be a positive integer.")


def test_output_scan_covers_and_redacts_every_choice(monkeypatch):
    scanned = []

    async def fake_scan(text, system_instruction, request_id):
        scanned.append(text)
        if "@" not in text:
            return OutputScanResult()
        start = text.index("@")
        start = text.rfind(" ", 0, start) + 1
        end = text.find(" ", start)
        if end == -1:
            end = len(text)
        return OutputScanResult(
            flagged=True,
            categories=["PII_LEAK"],
            spans=[Span(start, end, "PII_LEAK")],
            action="REDACT",
        )

    monkeypatch.setattr(handler.output_scanner, "scan_output", fake_scan)
    completion = {
        "choices": [
            {"message": {"content": "contact alice@example.com"}},
            {"message": {"content": "contact bob@example.com"}},
        ]
    }

    scan, spans_by_choice = asyncio.run(
        handler._scan_completion(completion, "", "request-3")
    )
    redacted = redact_completion_payload(completion, spans_by_choice)

    assert scanned == [
        "contact alice@example.com",
        "contact bob@example.com",
    ]
    assert scan.flagged
    assert set(spans_by_choice) == {0, 1}
    assert redacted["choices"][0]["message"]["content"] == "contact [REDACTED:PII_LEAK]"
    assert redacted["choices"][1]["message"]["content"] == "contact [REDACTED:PII_LEAK]"
