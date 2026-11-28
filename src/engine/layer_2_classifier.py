"""Layer 2: local ONNX prompt-injection classifier.

Week 1 (P1, first version): load() + predict() only, not wired into the
pipeline yet.

Week 2 (P2, this file): module-level singleton, warm-up, rolling-window
latency statistics, an async wrapper so inference never blocks the event
loop, hardened score validation (NaN/inf), and head+tail truncation for
prompts longer than max_length (an injection attempt is often appended
at the end of an otherwise long, benign prompt, so keeping only the head
could miss it).

Usage:
    clf = get_classifier()          # module-level singleton
    clf.load()                      # raises ClassifierUnavailable if files are missing
    clf.warm_up()                   # a few throwaway predictions, not counted in stats()
    result = await clf.predict_async("ignore all previous instructions")
    print(result.score, result.latency_ms)
    print(clf.stats())              # {"count": ..., "p50_ms": ..., "p95_ms": ..., "max_ms": ...}

Heavy libraries (onnxruntime, tokenizers, numpy) are imported inside functions,
so the rest of the app still imports when they are not installed.
No network access is used at any point.
"""

from __future__ import annotations

import asyncio
import os
import threading
import time
from collections import deque
from dataclasses import dataclass

_LATENCY_WINDOW_SIZE = 1000


class ClassifierUnavailable(RuntimeError):
    """Raised when the model or tokenizer cannot be used, or produces a bad score."""


@dataclass
class Layer2Result:
    score: float        # probability of the injection class, 0.0 - 1.0
    latency_ms: float   # time spent in predict()
    windows: int = 1                 # how many token windows were classified
    windows_skipped: bool = False    # True if the window cap left part of the prompt unscanned


def _settings() -> dict:
    return {
        "model_path": os.getenv("L2_MODEL_PATH", "src/models/classifier.onnx"),
        "tokenizer_dir": os.getenv("L2_TOKENIZER_DIR", "src/models/tokenizer"),
        "max_length": int(os.getenv("L2_MAX_LENGTH", "512")),
        "label_index": int(os.getenv("L2_INJECTION_LABEL_INDEX", "1")),
        # "windows": classify every part of a long prompt (default);
        # "truncate": legacy head+tail only (the middle is NOT scanned).
        "long_prompt_mode": os.getenv("L2_LONG_PROMPT_MODE", "windows").strip().lower(),
        "window_overlap": int(os.getenv("L2_WINDOW_OVERLAP", "128")),
        "max_windows": int(os.getenv("L2_MAX_WINDOWS", "8")),
    }


class Layer2Classifier:
    def __init__(self) -> None:
        cfg = _settings()
        self.model_path: str = cfg["model_path"]
        self.tokenizer_dir: str = cfg["tokenizer_dir"]
        self.max_length: int = cfg["max_length"]
        self.label_index: int = cfg["label_index"]
        self.long_prompt_mode: str = cfg["long_prompt_mode"] if cfg["long_prompt_mode"] in ("windows", "truncate") else "windows"
        self.window_overlap: int = max(0, cfg["window_overlap"])
        self.max_windows: int = max(1, cfg["max_windows"])

        self._tokenizer = None
        self._session = None
        self._input_names: set[str] = set()
        self._warmed_up: bool = False

        self._latencies: deque[float] = deque(maxlen=_LATENCY_WINDOW_SIZE)
        self._stats_lock = threading.Lock()

    # ------------------------------------------------------------------ load
    def load(self) -> None:
        tokenizer_file = os.path.join(self.tokenizer_dir, "tokenizer.json")

        if not os.path.isfile(self.model_path):
            raise ClassifierUnavailable(f"Model file not found: {self.model_path}")
        if not os.path.isfile(tokenizer_file):
            raise ClassifierUnavailable(f"Tokenizer file not found: {tokenizer_file}")

        try:
            import onnxruntime as ort
            from tokenizers import Tokenizer
        except ImportError as exc:
            raise ClassifierUnavailable(f"Missing dependency: {exc}") from exc

        try:
            tokenizer = Tokenizer.from_file(tokenizer_file)
            # No enable_truncation() here: automatic truncation only keeps
            # the head of the sequence. Week 2 needs head+tail truncation
            # (see _truncate below), so it is done manually in predict().

            session = ort.InferenceSession(
                self.model_path, providers=["CPUExecutionProvider"]
            )
        except Exception as exc:  # corrupt file, wrong format, etc.
            raise ClassifierUnavailable(f"Could not load classifier: {exc}") from exc

        self._tokenizer = tokenizer
        self._session = session
        self._input_names = {i.name for i in session.get_inputs()}

    @property
    def is_loaded(self) -> bool:
        return self._session is not None and self._tokenizer is not None

    # --------------------------------------------------------------- warm-up
    def warm_up(self, runs: int = 3) -> None:
        """
        Run a few throwaway predictions so the first real request doesn't
        pay the cold-start cost (first-call allocations, lazy init inside
        onnxruntime, etc). These are not counted in stats().
        """
        if not self.is_loaded:
            raise ClassifierUnavailable("Classifier not loaded: call load() first")

        sample_text = "This is a short warm-up prompt used to prime the model."
        for _ in range(runs):
            self.predict(sample_text, _record_stats=False)

        self._warmed_up = True

    # --------------------------------------------------------- truncation
    def _truncate(self, ids: list[int], mask: list[int]) -> tuple[list[int], list[int]]:
        """
        Keep the full sequence if it already fits. Otherwise keep the head
        and the tail (split evenly) rather than just the head.
        """
        if len(ids) <= self.max_length:
            return ids, mask

        head_len = self.max_length // 2
        tail_len = self.max_length - head_len
        return ids[:head_len] + ids[-tail_len:], mask[:head_len] + mask[-tail_len:]

    def _windows(
        self, ids: list[int], mask: list[int], lead: int = 1, trail: int = 1
    ) -> tuple[list[tuple[list[int], list[int]]], bool]:
        """
        Split a long token sequence into overlapping windows that together cover
        the WHOLE prompt (head, middle and tail), so an injection hidden in the
        middle is classified like any other.

        Each window is ``max_length`` tokens: the leading and trailing special
        tokens (``lead`` / ``trail``, e.g. [CLS] and [SEP]) plus a slice of the
        body. Windows overlap by ``window_overlap`` tokens so a phrase on a
        boundary is seen whole in at least one window.

        If more than ``max_windows`` are needed, evenly spaced windows (always
        including the first and the last) are kept and ``skipped`` is True.
        Upstream, MAX_PROMPT_TOKENS normally keeps prompts short enough that
        this never happens.
        """
        if len(ids) <= self.max_length:
            return [(ids, mask)], False

        head_ids, tail_ids = ids[:lead], ids[len(ids) - trail:] if trail else []
        head_mask, tail_mask = mask[:lead], mask[len(mask) - trail:] if trail else []
        body_ids = ids[lead:len(ids) - trail]
        body_mask = mask[lead:len(mask) - trail]

        size = max(1, self.max_length - lead - trail)
        overlap = min(self.window_overlap, size - 1)
        step = max(1, size - overlap)

        starts: list[int] = []
        pos = 0
        while True:
            starts.append(pos)
            if pos + size >= len(body_ids):
                break
            pos += step
        starts[-1] = max(0, len(body_ids) - size)  # last window ends exactly at the end

        skipped = False
        if len(starts) > self.max_windows:
            skipped = True
            n = self.max_windows
            keep = sorted({round(i * (len(starts) - 1) / (n - 1)) for i in range(n)}) if n > 1 else [0]
            starts = [starts[i] for i in keep]

        windows = [
            (head_ids + body_ids[s:s + size] + tail_ids, head_mask + body_mask[s:s + size] + tail_mask)
            for s in starts
        ]
        return windows, skipped

    def count_tokens(self, text: str) -> int:
        """Number of tokens in ``text`` (no special tokens). Falls back to a
        conservative estimate when the tokenizer is not loaded."""
        if not text:
            return 0
        if self._tokenizer is not None:
            try:
                return len(self._tokenizer.encode(text, add_special_tokens=False).ids)
            except Exception:
                pass
        return len(text) // 3 + 1

    # --------------------------------------------------------------- predict
    def predict(self, text: str, _record_stats: bool = True) -> Layer2Result:
        if not self.is_loaded:
            raise ClassifierUnavailable("Classifier not loaded: call load() first")

        import numpy as np

        start = time.perf_counter()

        encoding = self._tokenizer.encode(text)
        all_ids, all_mask = list(encoding.ids), list(encoding.attention_mask)

        if self.long_prompt_mode == "truncate":
            windows, skipped = [self._truncate(all_ids, all_mask)], len(all_ids) > self.max_length
        else:
            special = list(getattr(encoding, "special_tokens_mask", None) or [])
            lead = 1 if special and special[0] else 0
            trail = 1 if special and special[-1] else 0
            windows, skipped = self._windows(all_ids, all_mask, lead, trail)

        # Classify every window and keep the highest injection score: one bad
        # window is enough to flag the prompt.
        score = 0.0
        for ids, mask in windows:
            ids_arr = np.array([ids], dtype=np.int64)
            mask_arr = np.array([mask], dtype=np.int64)

            # Feed only the inputs the model declares.
            candidates = {
                "input_ids": ids_arr,
                "attention_mask": mask_arr,
                "token_type_ids": np.zeros_like(ids_arr),
            }
            feeds = {k: v for k, v in candidates.items() if k in self._input_names}

            logits = np.asarray(self._session.run(None, feeds)[0], dtype=np.float64)
            score = max(score, self._to_probability(logits.reshape(-1)))

        latency_ms = (time.perf_counter() - start) * 1000.0

        if _record_stats:
            with self._stats_lock:
                self._latencies.append(latency_ms)

        return Layer2Result(score=score, latency_ms=latency_ms, windows=len(windows), windows_skipped=skipped)

    async def predict_async(self, text: str) -> Layer2Result:
        """
        Async wrapper around predict(). Runs the (blocking, CPU-bound)
        inference in a worker thread so it never blocks the event loop.
        """
        return await asyncio.to_thread(self.predict, text)

    # --------------------------------------------------------------- helpers
    def _to_probability(self, logits) -> float:
        import math

        import numpy as np

        if logits.size == 1:
            # single logit -> sigmoid
            prob = 1.0 / (1.0 + np.exp(-logits[0]))
        else:
            if not 0 <= self.label_index < logits.size:
                raise ClassifierUnavailable(
                    f"L2_INJECTION_LABEL_INDEX={self.label_index} is out of range "
                    f"for model output of size {logits.size}"
                )
            shifted = logits - np.max(logits)  # numerical stability
            exp = np.exp(shifted)
            prob = exp[self.label_index] / exp.sum()

        prob = float(prob)
        if not math.isfinite(prob):
            raise ClassifierUnavailable("Model produced a non-finite score (NaN/inf).")

        return min(1.0, max(0.0, prob))

    # --------------------------------------------------------- observability
    def stats(self) -> dict:
        """Latency stats over the most recent real (non-warm-up) predictions."""
        with self._stats_lock:
            latencies = sorted(self._latencies)

        count = len(latencies)
        if count == 0:
            return {"count": 0, "p50_ms": None, "p95_ms": None, "max_ms": None}

        def percentile(p: float) -> float:
            index = min(count - 1, round(p * (count - 1)))
            return latencies[index]

        return {
            "count": count,
            "p50_ms": round(percentile(0.50), 3),
            "p95_ms": round(percentile(0.95), 3),
            "max_ms": round(latencies[-1], 3),
        }

    def status(self) -> dict:
        return {
            "loaded": self.is_loaded,
            "model_path": self.model_path,
            "warmed_up": self._warmed_up,
        }


# ----------------------------------------------------------------------
# Module-level singleton. get_classifier() only constructs the instance -
# it does NOT call load() or warm_up() automatically. Those stay explicit
# calls made once at app startup (src/main.py), so import time never
# touches disk or the model.
# ----------------------------------------------------------------------
_classifier_instance: Layer2Classifier | None = None


def get_classifier() -> Layer2Classifier:
    global _classifier_instance
    if _classifier_instance is None:
        _classifier_instance = Layer2Classifier()
    return _classifier_instance