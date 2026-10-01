# Model Selection

## Purpose

This document records the Week 1 Monday model-selection decision for the
Prompt Injection Firewall.

The models must run locally within the customer's network boundary.
Layer 2 is optimized for fast CPU inference, while Layer 3 is used only
for ambiguous cases and may therefore tolerate higher latency.

## SRS Requirements

### Layer 2

- Local ONNX-based semantic classifier.
- CPU inference required; GPU is optional.
- Model and tokenizer must load from local disk.
- No external network calls during inference.
- Target latency: low double-digit milliseconds.
- Classifier must provide an injection-risk score suitable for firewall
  decision thresholds.
- Commercial/self-hosted use must be permitted by the model license.

### Layer 3

- Locally hosted reasoning model.
- OpenAI-compatible API endpoint.
- Instruction-tuned model suitable for security/prompt analysis.
- Must support conversational context.
- Returns a final decision and rationale.
- Seconds of latency are acceptable because Layer 3 handles only
  ambiguous Layer 2 results.
- Commercial/self-hosted use must be permitted by the model license.

## Layer 2 Candidates

| Candidate | License | ONNX | Tokenizer | Size | Expected CPU latency | Status |
|---|---|---|---|---:|---|---|
| `protectai/deberta-v3-base-prompt-injection-v2` | Apache-2.0 | Yes | `tokenizer.json` | ~739 MB ONNX model | To be measured Wed | Candidate |
| `filip-w/PIGuard-onnx` | MIT | Yes | Available | To be measured | To be measured Wed | Candidate |

### Layer 2 Comparison

`protectai/deberta-v3-base-prompt-injection-v2` is specifically trained
for prompt-injection classification and provides an ONNX export.
Its classifier labels are 0 = benign and 1 = injection.

`filip-w/PIGuard-onnx` is an ONNX-packaged prompt-injection classifier
intended for offline ONNX Runtime inference.

Actual CPU latency and output behavior will be measured by
`scripts/test_models.py` on Wednesday.

### Layer 2 Provisional Decision

**Provisional model:** `filip-w/PIGuard-onnx`

**License:** MIT

**Expected latency:** Low double-digit milliseconds target; measure on
project hardware Wednesday.

**Injection label index:** `1`

**Environment variable:**

```text
L2_INJECTION_LABEL_INDEX=1
```

## Layer 3 Candidates

| Candidate | License | Approx. size | OpenAI-compatible serving | Hardware fit | Status |
|---|---|---:|---|---|---|
| `microsoft/Phi-4-mini-instruct` | MIT | ~7.7 GB | Yes, through a compatible local serving runtime | To be validated | Candidate |
| `Qwen/Qwen2.5-3B-Instruct` | Qwen Research | ~6.2 GB | Yes, through a compatible local serving runtime | To be validated | Candidate |

### Layer 3 Comparison

`microsoft/Phi-4-mini-instruct` is an instruction-tuned model with an
MIT license. It can be exposed through an OpenAI-compatible local
serving runtime.

`Qwen/Qwen2.5-3B-Instruct` is a smaller instruction-tuned candidate.
Its licensing terms must be reviewed before it can be adopted as the
final project model.

### Layer 3 Provisional Decision

**Provisional model:** `microsoft/Phi-4-mini-instruct`

**License:** MIT

**Expected latency:** Seconds; measure during Week 2 integration.

**Environment variables:**

```text
LAYER3_BASE_URL=http://localhost:11434/v1
LAYER3_MODEL=phi-4-mini-instruct
```

The local serving runtime is responsible for exposing the model through
the OpenAI-compatible API.

## Model Locations

The project expects the Layer 2 assets at:

```text
src/models/classifier.onnx
src/models/tokenizer/tokenizer.json
```

Large model binaries must not be committed directly to normal Git
history.

The team should use Git LFS or the approved internal model/artifact
storage mechanism for sharing model binaries.

## Layer 2 Acceptance Checklist — Wednesday

- [ ] Download the selected Layer 2 model.
- [ ] Verify model license.
- [ ] Verify `classifier.onnx` loads with `onnxruntime`.
- [ ] Verify `tokenizer/tokenizer.json` loads with `tokenizers`.
- [ ] Run two injection/jailbreak samples.
- [ ] Run two benign samples.
- [ ] Print model input names.
- [ ] Print output shape.
- [ ] Print class scores.
- [ ] Identify and verify injection class index.
- [ ] Measure CPU inference latency.
- [ ] Confirm no network access is required.
- [ ] Confirm `[OK]` / `[WARN]` / `[FAIL]` output from
  `scripts/test_models.py`.

## License Review

A second team member must independently verify that the selected model
licenses permit the intended self-hosted commercial use before the model
is treated as final.

## Decision Status

Layer 2: **Provisional** — pending Wednesday benchmark and license
confirmation.

Layer 3: **Provisional** — pending serving-runtime validation and license
confirmation.

No latency value in this document is presented as a measured result
until the Wednesday model test is completed.
