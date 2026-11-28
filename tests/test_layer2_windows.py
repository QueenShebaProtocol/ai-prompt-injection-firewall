"""Layer 2 long-prompt handling: every part of a long prompt is classified.

The old head+tail truncation dropped the middle of long prompts, so an
injection placed there was never seen. These tests use a fake model that
"detects" a marker token id, to prove that a marker in the head, the middle or
the tail is found, and that the legacy mode still misses the middle.
"""
import numpy as np
import pytest

from src.engine.layer_2_classifier import Layer2Classifier

MARKER = 777
CLS, SEP = 1, 2


class FakeInput:
    def __init__(self, name):
        self.name = name


class MarkerSession:
    """Scores high (class 1) when the marker token is inside the window."""

    def __init__(self):
        self.calls = []

    def get_inputs(self):
        return [FakeInput("input_ids"), FakeInput("attention_mask")]

    def run(self, output_names, feeds):
        ids = feeds["input_ids"][0].tolist()
        self.calls.append(ids)
        return [np.array([[0.0, 8.0]]) if MARKER in ids else np.array([[8.0, 0.0]])]


class Tok:
    """Encodes 'n:<count>@<position>' as <count> body tokens with the marker at <position>."""

    def encode(self, text, add_special_tokens=True):
        count, pos = (int(x) for x in text.split(":")[1].split("@"))
        body = [10 + (i % 500) for i in range(count)]
        if pos >= 0:
            body[pos] = MARKER

        class Enc:
            ids = ([CLS] + body + [SEP]) if add_special_tokens else body
            attention_mask = [1] * len(ids)
            special_tokens_mask = [1] + [0] * count + [1]

        return Enc()


def make(max_length=64, overlap=16, max_windows=30, mode="windows"):
    clf = Layer2Classifier()
    clf.max_length = max_length
    clf.window_overlap = overlap
    clf.max_windows = max_windows
    clf.long_prompt_mode = mode
    clf._tokenizer = Tok()
    clf._session = MarkerSession()
    clf._input_names = {"input_ids", "attention_mask"}
    return clf


@pytest.mark.parametrize("pos", [5, 150, 300, 440, 590])  # head, middle (x3), tail of a 600-token prompt
def test_injection_anywhere_in_a_long_prompt_is_detected(pos):
    clf = make()
    res = clf.predict(f"n:600@{pos}")
    assert res.score > 0.9
    assert res.windows > 1 and res.windows_skipped is False


def test_benign_long_prompt_scores_low():
    res = make().predict("n:600@-1")
    assert res.score < 0.1


def test_every_window_is_at_most_max_length_and_keeps_special_tokens():
    clf = make()
    clf.predict("n:600@-1")
    for ids in clf._session.calls:
        assert len(ids) <= 64
        assert ids[0] == CLS and ids[-1] == SEP


def test_windows_cover_the_whole_body_with_overlap():
    clf = make()
    clf.predict("n:600@-1")
    covered = set()
    for ids in clf._session.calls:
        covered.update(ids[1:-1])
    # body tokens are 10 + (i % 500): all 500 distinct values must be seen
    assert covered >= set(range(10, 510))


def test_short_prompt_is_a_single_window():
    clf = make()
    res = clf.predict("n:30@10")
    assert res.windows == 1 and len(clf._session.calls) == 1


def test_window_cap_is_reported_not_silent():
    clf = make(max_windows=3)
    res = clf.predict("n:600@-1")
    assert res.windows == 3 and res.windows_skipped is True


def test_legacy_truncate_mode_still_misses_the_middle():
    """Documents the old weakness: this is why 'windows' is the default."""
    clf = make(mode="truncate")
    assert clf.predict("n:600@300").score < 0.1
    assert clf.predict("n:600@5").score > 0.9


def test_count_tokens_uses_the_tokenizer():
    clf = make()
    assert clf.count_tokens("n:123@-1") == 123
    assert clf.count_tokens("") == 0
