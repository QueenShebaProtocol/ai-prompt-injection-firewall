"""Layer 2: local ONNX prompt-injection classifier (first version).

Standalone module. It is NOT wired into the pipeline in Week 1.
Week 2 adds warm-up, latency statistics, threshold logic and an async call.

Usage:
    clf = Layer2Classifier()
    clf.load()                      # raises ClassifierUnavailable if files are missing
    result = clf.predict("ignore all previous instructions")
    print(result.score, result.latency_ms)

Heavy libraries (onnxruntime, tokenizers, numpy) are imported inside functions,
so the rest of the app still imports when they are not installed.
No network access is used at any point.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass


class ClassifierUnavailable(RuntimeError):
    """Raised when the model or tokenizer cannot be used."""


@dataclass
class Layer2Result:
    score: float        # probability of the injection class, 0.0 - 1.0
    latency_ms: float   # time spent in predict()


def _settings() -> dict:
    return {
        "model_path": os.getenv("L2_MODEL_PATH", "src/models/classifier.onnx"),
        "tokenizer_dir": os.getenv("L2_TOKENIZER_DIR", "src/models/tokenizer"),
        "max_length": int(os.getenv("L2_MAX_LENGTH", "512")),
        "label_index": int(os.getenv("L2_INJECTION_LABEL_INDEX", "1")),
    }


class Layer2Classifier:
    def __init__(self) -> None:
        cfg = _settings()
        self.model_path: str = cfg["model_path"]
        self.tokenizer_dir: str = cfg["tokenizer_dir"]
        self.max_length: int = cfg["max_length"]
        self.label_index: int = cfg["label_index"]

        self._tokenizer = None
        self._session = None
        self._input_names: set[str] = set()

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
            tokenizer.enable_truncation(max_length=self.max_length)

            session = ort.InferenceSession(
                self.model_path, providers=["CPUExecutionProvider"]
            )
        except Exception as exc:  # corrupt file, wrong format, etc.
            raise ClassifierUnavailable(f"Could not load classifier: {exc}") from exc

        self._tokenizer = tokenizer
        self._session = session
        self._input_names = {i.name for i in session.get_inputs()}

    # --------------------------------------------------------------- predict
    def predict(self, text: str) -> Layer2Result:
        if self._session is None or self._tokenizer is None:
            raise ClassifierUnavailable("Classifier not loaded: call load() first")

        import numpy as np

        start = time.perf_counter()

        encoding = self._tokenizer.encode(text)
        ids = np.array([encoding.ids], dtype=np.int64)
        mask = np.array([encoding.attention_mask], dtype=np.int64)

        # Feed only the inputs the model declares.
        candidates = {
            "input_ids": ids,
            "attention_mask": mask,
            "token_type_ids": np.zeros_like(ids),
        }
        feeds = {k: v for k, v in candidates.items() if k in self._input_names}

        logits = np.asarray(self._session.run(None, feeds)[0], dtype=np.float64)
        logits = logits.reshape(-1)

        score = self._to_probability(logits)
        latency_ms = (time.perf_counter() - start) * 1000.0
        return Layer2Result(score=score, latency_ms=latency_ms)

    # --------------------------------------------------------------- helpers
    def _to_probability(self, logits) -> float:
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

        return float(min(1.0, max(0.0, prob)))
