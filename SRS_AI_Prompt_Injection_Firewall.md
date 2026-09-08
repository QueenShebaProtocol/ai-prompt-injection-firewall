# Software Requirements Specification (SRS)
## Decentralized AI Prompt Injection Firewall

**Document Version:** 1.0
**Prepared By:** Software Engineering Team
**Classification:** Internal / Technical

---

## Table of Contents

1. Introduction
2. Overall Description
3. System Architecture
4. Functional Requirements
5. Defense Mechanism — Pseudo-Design
6. Data Design (Database Schema)
7. External Interface Requirements
8. Non-Functional Requirements
9. Deployment Architecture
10. Assumptions, Dependencies & Constraints
11. Future Enhancements
12. Appendix — Repository Structure

---

## 1. Introduction

### 1.1 Purpose
This document specifies the software requirements for the **Decentralized AI Prompt Injection Firewall**, an inline security proxy that protects AI-powered applications (LLM assistants, customer support bots, RAG pipelines) from prompt injection, jailbreak attempts, and sensitive data exfiltration. It is intended to guide the engineering team through design, implementation, testing, and deployment, and to serve as a reference for QA, DevOps, and compliance stakeholders.

### 1.2 Scope
The system will be delivered as a **self-contained, dockerized microservice stack** consisting of:
- A reverse-proxy **API Gateway** that intercepts LLM traffic.
- A **multi-layer inspection pipeline** (deterministic rules, ML classifier, LLM-based reasoning) that scores and blocks malicious prompts.
- An **output validation scanner** that inspects LLM completions before they reach the end user.
- A **local relational database** for telemetry, rule storage, and audit logging.
- A **Streamlit-based Admin Dashboard** for real-time monitoring and rule configuration.

The system is designed for **on-premises / private-VPC deployment only**. No prompt data, completions, or telemetry ever leaves the customer's own infrastructure, satisfying data-sovereignty requirements such as GDPR, HIPAA, and SOC 2.

### 1.3 Definitions, Acronyms, and Abbreviations

| Term | Definition |
|---|---|
| LLM | Large Language Model |
| RAG | Retrieval-Augmented Generation |
| PII | Personally Identifiable Information |
| ONNX | Open Neural Network Exchange (portable ML model format) |
| VPC | Virtual Private Cloud |
| SRS | Software Requirements Specification |
| KPI | Key Performance Indicator |
| GIN Index | Generalized Inverted Index (PostgreSQL, used for JSONB) |

### 1.4 References
- OWASP Top 10 for LLM Applications (Prompt Injection, Sensitive Information Disclosure)
- GDPR, HIPAA, SOC 2 compliance frameworks
- PostgreSQL and SQLAlchemy documentation
- Provided project artifacts: system description document, repository file structure, database schema specification

### 1.5 Document Overview
Section 2 describes the product context. Section 3 defines the system architecture. Section 4 lists functional requirements per module. Section 5 provides the pseudo-design of the core defense pipeline. Section 6 documents the database schema. Sections 7–9 cover interfaces, quality attributes, and deployment. Sections 10–12 cover assumptions, roadmap, and repository layout.

---

## 2. Overall Description

### 2.1 Product Perspective
The firewall is a **standalone, drop-in middleware component**. It does not replace or modify the client application's business logic; it sits transparently on the network path between the client application and the downstream LLM provider (e.g., OpenAI, Google Gemini, Anthropic, or a locally hosted model). Integration requires no SDK changes — only redirecting the application's `BASE_URL` to the firewall's local endpoint.

### 2.2 Product Functions (Summary)
- Intercept and inspect inbound prompts in real time.
- Classify prompt risk using a three-tier cascading model.
- Block, redact, or pass through requests based on configurable policy.
- Inspect outbound LLM completions for leakage of secrets, PII, or system prompts.
- Persist all inspection events, rules, and admin actions for audit and analytics.
- Provide a local dashboard for live monitoring and rule tuning.

### 2.3 User Classes and Characteristics

| User Class | Description | Technical Level |
|---|---|---|
| Security Administrator | Configures rules, thresholds, and reviews audit logs | High |
| DevOps Engineer | Deploys and maintains the containerized stack | High |
| Application Developer | Integrates client applications with the firewall proxy | Medium |
| Compliance Officer | Reviews audit trails and exportable reports | Low–Medium |
| End User (indirect) | Interacts with the protected AI application; unaware of the firewall | N/A |

### 2.4 Operating Environment
- **Containerization:** Docker Engine ≥ 20.x, Docker Compose or Kubernetes (Helm charts optional).
- **Backend Runtime:** Python 3.x, FastAPI-based ASGI service.
- **Database:** PostgreSQL (local, in-cluster instance only).
- **Dashboard Runtime:** Streamlit application served over the internal network.
- **ML Runtime:** ONNX Runtime for local, CPU/GPU-optional inference.
- **Network:** No mandatory outbound internet access after image build (air-gapped operation supported).

### 2.5 Design and Implementation Constraints
- All processing (rules, ML inference, reasoning layer, logging) must occur **within the customer's own network boundary** — no data may be transmitted to third-party SaaS analytics or logging services.
- The system must not introduce more than single-digit millisecond overhead for the majority of traffic (Layer 1 short-circuit path).
- The dashboard and proxy must be independently scalable within the same container stack.

### 2.6 Assumptions and Dependencies
- The organization already operates or intends to operate LLM-backed applications that can be reconfigured to point to a new base URL.
- The host environment provides persistent volume support for the PostgreSQL data directory and ONNX model artifacts.
- Administrators have basic familiarity with YAML configuration and Docker operations.

---

## 3. System Architecture

### 3.1 Architectural Style
The system follows a **Standalone Middleware Reverse-Proxy Pattern** combined with a **Cascading Pipeline (Chain of Responsibility) Pattern** for threat evaluation.

```
┌─────────────────────┐        ┌───────────────────────────────────────────┐        ┌───────────────────┐
│   Client Application │──────▶│   Decentralized AI Prompt Injection        │──────▶│  Downstream LLM     │
│ (Chatbot / RAG / etc)│        │   Firewall (Proxy + Inspection Pipeline)   │        │  Provider / Model   │
└─────────────────────┘        └───────────────────────────────────────────┘        └───────────────────┘
                                          │
                                          ▼
                                ┌───────────────────┐
                                │  Local PostgreSQL  │
                                │  (Telemetry, Rules)│
                                └───────────────────┘
                                          │
                                          ▼
                                ┌───────────────────┐
                                │ Streamlit Dashboard│
                                │ (Local, Isolated)  │
                                └───────────────────┘
```

### 3.2 Component Breakdown

| Component | Responsibility |
|---|---|
| **Proxy Layer** (`proxy/handler.py`, `proxy/forwarder.py`) | Accepts inbound HTTP requests, orchestrates inspection, forwards cleared requests, returns custom block responses when denied. |
| **Inspection Engine** (`engine/pipeline.py` + layers) | Executes the multi-tier defense cascade described in Section 5. |
| **Output Scanner** (`engine/output_scanner.py`) | Inspects LLM responses for leakage before returning them to the client. |
| **Database Layer** (`database/`) | Persists logs, rules, metrics, and audit trails; exposes query functions to the dashboard. |
| **ML Assets** (`models/`) | Hosts the local ONNX classifier and tokenizer used by Layer 2. |
| **Admin Dashboard** (`dashboard/`) | Streamlit UI for analytics, forensic log search, and live rule configuration. |

### 3.3 Data Flow (Request Lifecycle)
1. Client application sends a standard LLM API request to the firewall's local base URL.
2. Proxy handler captures the payload (prompt, system instruction, metadata).
3. The inspection engine runs the payload through Layers 1 → 2 → 3 as needed (cascading short-circuit).
4. If cleared, the forwarder relays the request to the actual downstream LLM provider.
5. The LLM's completion is intercepted by the Output Scanner before being returned to the client.
6. All decisions, scores, and metadata are persisted asynchronously to PostgreSQL.
7. The dashboard reads from PostgreSQL (and pre-aggregated metrics) to render real-time analytics.

---

## 4. Functional Requirements

Requirements are grouped by module and use the identifier format **FR-[Module]-[Number]**.

### 4.1 Proxy / Gateway

| ID | Requirement |
|---|---|
| FR-PROXY-01 | The system shall expose an HTTP endpoint compatible with standard LLM SDK request formats (e.g., OpenAI-compatible chat completion schema). |
| FR-PROXY-02 | The system shall accept a configurable downstream `target_model` / base URL per application, defined in `firewall.yaml`. |
| FR-PROXY-03 | The system shall forward a request to the downstream LLM only after it has been cleared by the inspection engine. |
| FR-PROXY-04 | The system shall return a structured, non-generic block response (including reason code) when a request is denied. |
| FR-PROXY-05 | The system shall support redaction mode, allowing sanitized versions of a prompt to be forwarded instead of an outright block, when configured. |
| FR-PROXY-06 | The system shall preserve original request metadata (application ID, client IP) throughout the pipeline for logging purposes. |

### 4.2 Layer 1 — Deterministic Engine

| ID | Requirement |
|---|---|
| FR-L1-01 | The system shall evaluate every inbound prompt against a configurable regex/signature ruleset loaded from `rules_regex.yaml` and the `firewall_rules` table. |
| FR-L1-02 | The system shall detect known jailbreak templates, direct override phrases, and system-prompt keyword leakage patterns. |
| FR-L1-03 | The system shall short-circuit the pipeline and block a request immediately upon a Layer 1 match, without invoking Layers 2 or 3. |
| FR-L1-04 | Layer 1 evaluation shall complete within sub-millisecond to low single-digit millisecond latency under normal load. |
| FR-L1-05 | The system shall support hot-reloading of Layer 1 rules without requiring a service restart. |

### 4.3 Layer 2 — Fast ML Classifier

| ID | Requirement |
|---|---|
| FR-L2-01 | The system shall run prompts that pass Layer 1 through a local ONNX-based semantic classifier. |
| FR-L2-02 | The classifier shall output a normalized risk score between 0.0 and 1.0. |
| FR-L2-03 | The system shall compare the score against configurable high/low confidence thresholds to decide: auto-block (high), auto-pass (low), or escalate to Layer 3 (ambiguous band). |
| FR-L2-04 | Model and tokenizer assets shall be loaded entirely from local disk (`src/models/`), with no external network calls. |

### 4.4 Layer 3 — LLM Intent Evaluator

| ID | Requirement |
|---|---|
| FR-L3-01 | The system shall invoke a locally hosted reasoning model to evaluate prompts flagged as ambiguous by Layer 2. |
| FR-L3-02 | The evaluator shall consider available conversational context (multi-turn history) to detect indirect or staged injection attempts. |
| FR-L3-03 | The evaluator shall return a final decision (ALLOW / BLOCK / REDACT) plus a rationale string for audit purposes. |
| FR-L3-04 | Layer 3 shall be invoked only for the subset of traffic flagged ambiguous, to preserve overall system throughput. |

### 4.5 Output Validation & Exfiltration Scanner

| ID | Requirement |
|---|---|
| FR-OUT-01 | The system shall scan every downstream LLM completion prior to returning it to the client application. |
| FR-OUT-02 | The scanner shall detect accidental exposure of system instructions or developer prompts within the completion text. |
| FR-OUT-03 | The scanner shall detect PII patterns (e.g., emails, phone numbers, government ID formats, credit card numbers) in the completion. |
| FR-OUT-04 | The scanner shall detect API keys, tokens, or credential-like strings in the completion. |
| FR-OUT-05 | The system shall mark flagged completions (`output_flagged = TRUE`) and apply the configured policy (block, redact, or pass with warning). |

### 4.6 Database & Telemetry

| ID | Requirement |
|---|---|
| FR-DB-01 | The system shall persist a record for every inspected request in `threat_logs`, including scores, decisions, and timing metrics. |
| FR-DB-02 | The system shall persist administrator rule changes in `firewall_rules` with full versioning of `is_active` state. |
| FR-DB-03 | The system shall aggregate hourly metrics into `system_metrics` to accelerate long-range dashboard queries. |
| FR-DB-04 | The system shall record every administrative action in `admin_audit_logs`, including before/after snapshots. |
| FR-DB-05 | All database writes related to logging shall be asynchronous and shall not block the proxy's response path. |

### 4.7 Admin Dashboard

| ID | Requirement |
|---|---|
| FR-DASH-01 | The dashboard shall display real-time KPIs: total requests, blocked requests, block rate, and average latency. |
| FR-DASH-02 | The dashboard shall visualize threat volume over time and the distribution of blocks by triggering layer. |
| FR-DASH-03 | The dashboard shall provide a searchable, filterable forensic log table with a detail view of the full JSON breakdown per request. |
| FR-DASH-04 | The dashboard shall allow administrators to create, edit, enable/disable, and delete rules in `firewall_rules`. |
| FR-DASH-05 | The dashboard shall allow administrators to adjust Layer 2 confidence thresholds and toggle individual pipeline layers. |
| FR-DASH-06 | The dashboard shall support exporting filtered log results for compliance reporting. |
| FR-DASH-07 | The dashboard shall run entirely within the local container network, with no external telemetry calls.|

---

## 5. Defense Mechanism — Pseudo-Design

> Note: The following is architectural pseudocode intended to describe control flow and decision logic only. It is **not** implementation code.

### 5.1 High-Level Pipeline Orchestration

```
FUNCTION handle_incoming_request(request):
    request_id       = generate_uuid()
    start_time       = current_time()
    prompt           = request.raw_prompt
    system_prompt    = request.system_instruction
    context          = request.conversation_history   // may be empty

    log_entry = new ThreatLogEntry(request_id, request.client_ip,
                                    request.application_id, request.target_model)

    // ---- LAYER 1: Deterministic Engine ----
    l1_result = evaluate_layer1(prompt, system_prompt)
    IF l1_result.matched:
        log_entry.mark_blocked(layer="LAYER_1", score=1.0, patterns=l1_result.patterns)
        persist_async(log_entry)
        RETURN block_response(reason=l1_result.rule_id)

    // ---- LAYER 2: Fast ML Classifier ----
    l2_score = evaluate_layer2(prompt, context)

    IF l2_score >= HIGH_CONFIDENCE_THRESHOLD:
        log_entry.mark_blocked(layer="LAYER_2", score=l2_score)
        persist_async(log_entry)
        RETURN block_response(reason="high_risk_classifier_score")

    ELSE IF l2_score <= LOW_CONFIDENCE_THRESHOLD:
        decision = "ALLOW"          // clearly benign, skip Layer 3

    ELSE:
        // ---- LAYER 3: LLM Intent Evaluator (ambiguous band only) ----
        l3_result = evaluate_layer3(prompt, system_prompt, context)
        IF l3_result.decision == "BLOCK":
            log_entry.mark_blocked(layer="LAYER_3", score=l2_score, rationale=l3_result.rationale)
            persist_async(log_entry)
            RETURN block_response(reason=l3_result.rationale)
        ELSE IF l3_result.decision == "REDACT":
            prompt = l3_result.sanitized_prompt
            decision = "REDACTED"
        ELSE:
            decision = "ALLOW"

    // ---- Forward to downstream LLM ----
    completion = forward_to_llm(request.target_model, prompt, system_prompt)

    // ---- Output Validation & Exfiltration Scan ----
    out_result = evaluate_output_scanner(completion, system_prompt)
    IF out_result.flagged:
        completion = apply_output_policy(completion, out_result)   // block / redact / warn
        log_entry.output_flagged = TRUE

    log_entry.mark_passed(decision=decision, score=l2_score,
                           execution_time=elapsed_since(start_time))
    persist_async(log_entry)

    RETURN success_response(completion)
END FUNCTION
```

### 5.2 Layer 1 — Deterministic Matching (Pseudocode)

```
FUNCTION evaluate_layer1(prompt, system_prompt):
    combined_text = normalize_text(prompt + " " + system_prompt)

    FOR EACH rule IN active_regex_rules() WHERE rule.rule_type == "REGEX" OR "KEYWORD":
        IF rule.pattern MATCHES combined_text:
            RETURN MatchResult(matched=TRUE, rule_id=rule.rule_id,
                                category=rule.category, patterns=[rule.rule_id])

    RETURN MatchResult(matched=FALSE)
END FUNCTION
```

*Design notes:*
- `active_regex_rules()` reads from an in-memory cache refreshed via the `(is_active, rule_type)` composite index for fast hot-reload.
- Matching is case-insensitive and normalizes common obfuscation tricks (e.g., unicode homoglyphs, extra whitespace) before comparison.

### 5.3 Layer 2 — Semantic Classifier (Pseudocode)

```
FUNCTION evaluate_layer2(prompt, context):
    tokens      = tokenize(prompt, context)
    embedding   = onnx_model.infer(tokens)
    risk_score  = normalize(embedding.output)     // scaled to [0.0, 1.0]
    RETURN risk_score
END FUNCTION
```

*Design notes:*
- The classifier considers recent conversational turns (bounded window) to catch multi-turn manipulation attempts, not just the current message in isolation.
- Threshold values (`HIGH_CONFIDENCE_THRESHOLD`, `LOW_CONFIDENCE_THRESHOLD`) are administrator-configurable via the dashboard and stored in `firewall.yaml`.

### 5.4 Layer 3 — Contextual Intent Evaluation (Pseudocode)

```
FUNCTION evaluate_layer3(prompt, system_prompt, context):
    evaluation_prompt = build_safety_evaluation_prompt(prompt, system_prompt, context)
    reasoning_output   = local_reasoning_model.evaluate(evaluation_prompt)

    decision   = reasoning_output.classification   // ALLOW | BLOCK | REDACT
    rationale  = reasoning_output.explanation
    sanitized  = reasoning_output.sanitized_prompt  IF decision == "REDACT" ELSE NULL

    RETURN EvaluationResult(decision, rationale, sanitized)
END FUNCTION
```

*Design notes:*
- This layer is intentionally the most expensive and is invoked only for the ambiguous score band, keeping average latency low.
- The evaluation prompt template is isolated from the end-user's original prompt to reduce the evaluator's own exposure to injection attempts (i.e., the evaluator is instructed to treat the input strictly as data to be judged, not as instructions to follow).

### 5.5 Output Scanner (Pseudocode)

```
FUNCTION evaluate_output_scanner(completion, system_prompt):
    flags = []

    IF contains_system_prompt_fragment(completion, system_prompt):
        flags.append("SYSTEM_PROMPT_LEAK")

    IF contains_pii_pattern(completion):          // regex + classifier for emails, IDs, etc.
        flags.append("PII_LEAK")

    IF contains_secret_pattern(completion):        // API key / token signatures
        flags.append("SECRET_LEAK")

    RETURN ScanResult(flagged = (flags.length > 0), categories = flags)
END FUNCTION
```

### 5.6 Decision Matrix Summary

| Layer | Trigger Condition | Possible Outcomes | Escalates To |
|---|---|---|---|
| Layer 1 | Regex / keyword match | BLOCK | — (terminal) |
| Layer 2 | Score ≥ high threshold | BLOCK | — (terminal) |
| Layer 2 | Score ≤ low threshold | ALLOW | Forward to LLM |
| Layer 2 | Score in ambiguous band | Escalate | Layer 3 |
| Layer 3 | Reasoning decision | ALLOW / BLOCK / REDACT | Forward or terminal |
| Output Scanner | Leak pattern found | BLOCK / REDACT / WARN | Terminal (response modified) |

---

## 6. Data Design (Database Schema)

The system uses a **PostgreSQL** relational database, isolated within the organization's own container stack. All tables are defined below, with columns and required indexes.

### 6.1 Table: `threat_logs`
Stores granular inspection data for every prompt and response evaluated by the firewall.

| Column | Type / Notes |
|---|---|
| id | UUID, Primary Key |
| request_id | Unique string identifier per HTTP request |
| created_at | Timestamptz — when the request arrived |
| client_ip | IP address of the calling application |
| application_id | Identifier of the originating application/bot |
| target_model | Destination LLM model name (e.g., gpt-4o, gemini-1.5-pro) |
| raw_prompt | Full inbound prompt text |
| system_instruction | System/developer prompt supplied in the payload |
| is_blocked | Boolean — TRUE if halted |
| action_taken | Enum-like string: PASSED / BLOCKED / REDACTED |
| triggered_layer | NONE / LAYER_1 / LAYER_2 / LAYER_3 / OUTPUT_SCANNER |
| risk_score | Float, 0.0–1.0 |
| execution_time_ms | Float — total proxy processing latency |
| layer_details | JSONB — score breakdown per layer |
| detected_patterns | JSONB array — matched signature IDs/descriptions |
| output_completion | Text — downstream LLM response (optional/configurable) |
| output_flagged | Boolean — TRUE if output scanner found PII/leakage |

**Indexes:**
- Primary Key on `id`
- Unique B-Tree on `request_id`
- Descending B-Tree on `created_at`
- Single-column on `is_blocked`
- Single-column on `triggered_layer`
- Single-column on `client_ip`
- Single-column on `risk_score`
- Composite B-Tree on `(created_at, is_blocked)`
- GIN index on `layer_details` (JSONB)

### 6.2 Table: `firewall_rules`
Stores custom security rules, regex patterns, sensitive keywords, and exclusions managed through the dashboard.

| Column | Type / Notes |
|---|---|
| id | Auto-incrementing integer, Primary Key |
| rule_id | Unique human-readable identifier (e.g., RULE_JAILBREAK_01) |
| rule_type | REGEX / KEYWORD / EXCLUSION |
| category | JAILBREAK / PROMPT_LEAK / PII / SYSTEM_OVERRIDE |
| pattern | Regex expression or blocked keyword text |
| description | Human-readable explanation |
| severity | LOW / MEDIUM / HIGH / CRITICAL |
| is_active | Boolean — enforce (TRUE) or disable (FALSE) |
| created_at | Timestamptz |
| updated_at | Timestamptz |

**Indexes:**
- Primary Key on `id`
- Unique B-Tree on `rule_id`
- Composite B-Tree on `(is_active, rule_type)` — fast startup / hot-reload
- Single-column on `category`

### 6.3 Table: `system_metrics`
Pre-aggregated hourly metrics to accelerate long-term dashboard trend rendering.

| Column | Type / Notes |
|---|---|
| id | Auto-incrementing integer, Primary Key |
| bucket_start | Timestamptz, unique — start of the metric hour |
| total_requests | Integer |
| blocked_requests | Integer |
| layer_1_blocks | Integer |
| layer_2_blocks | Integer |
| layer_3_blocks | Integer |
| output_blocks | Integer |
| avg_latency_ms | Float |
| p95_latency_ms | Float |

**Indexes:**
- Primary Key on `id`
- Unique descending index on `bucket_start`

### 6.4 Table: `admin_audit_logs`
Tracks administrative changes made via the dashboard for compliance and security oversight.

| Column | Type / Notes |
|---|---|
| id | UUID, Primary Key |
| timestamp | Timestamptz |
| admin_user | Administrator username/identifier |
| action | RULE_CREATED / RULE_UPDATED / RULE_DELETED / THRESHOLD_CHANGED |
| target_rule_id | Rule affected (if applicable) |
| change_details | JSONB — before/after snapshot |

**Indexes:**
- Primary Key on `id`
- Descending index on `timestamp`

### 6.5 Entity Relationship Summary
- `threat_logs` is the primary fact table; it is written to on every request and is independent of `firewall_rules` at write time (rule identifiers are captured inside `detected_patterns` rather than via a hard foreign key, to keep the hot logging path fast).
- `firewall_rules` is read-heavy at proxy startup/hot-reload and write-light (admin edits only).
- `system_metrics` is derived/aggregated from `threat_logs` on an hourly batch or trigger basis.
- `admin_audit_logs` is written whenever `firewall_rules` (or global thresholds) are modified, and may reference `firewall_rules.rule_id` via `target_rule_id`.

---

## 7. External Interface Requirements

### 7.1 API Interfaces
- **Inbound Proxy Endpoint:** Accepts standard LLM chat/completion-style requests from client applications, compatible with common SDK conventions so that only the base URL needs to change.
- **Downstream Forwarding Interface:** Configurable per-application target (model name + provider endpoint), defined in `firewall.yaml` and/or `.env`.
- **Dashboard Data API:** Internal query layer (`storage.py`) exposing cached analytical getters consumed by the Streamlit pages.

### 7.2 User Interfaces
- **Admin Dashboard (Streamlit):**
  - **Analytics page** — KPI cards, time-series charts, layer distribution charts.
  - **Threat Logs page** — searchable/filterable table with modal detail view of raw JSON.
  - **Configuration page** — threshold sliders, layer enable/disable toggles, rule CRUD forms, deny-list editor.

### 7.3 Hardware Interfaces
- Standard container-host compute (CPU required; GPU optional for accelerating ONNX inference and the local reasoning model at higher throughput).

### 7.4 Communication Interfaces
- Internal Docker network communication between the proxy, database, and dashboard containers.
- Outbound HTTPS call only to the configured downstream LLM provider (or none, if fully local models are used).

---

## 8. Non-Functional Requirements

### 8.1 Performance
- Layer 1 evaluation: sub-millisecond to low single-digit millisecond target latency.
- Layer 2 evaluation: low double-digit millisecond target latency (local ONNX inference).
- Layer 3 evaluation: invoked only for ambiguous traffic to bound average end-to-end latency.
- Dashboard queries must leverage pre-aggregated `system_metrics` for date ranges beyond a configurable recent window, to avoid full scans of `threat_logs`.

### 8.2 Security & Privacy
- No prompt, completion, or telemetry data shall leave the customer's private network boundary.
- All administrative actions must be attributable (`admin_user`) and immutable once logged (`admin_audit_logs`).
- Secrets (database credentials, provider API keys) must be supplied via environment variables (`.env`), never hard-coded or logged in plaintext.
- The output scanner must treat secret/PII detection as a mandatory pre-return step; it cannot be bypassed by configuration alone without an explicit administrator override that is itself audit-logged.

### 8.3 Compliance
- Architecture must support GDPR, HIPAA, and SOC 2 alignment through data locality (self-hosted, no third-party data processors), audit trails, and configurable data retention.

### 8.4 Reliability & Availability
- Logging writes must be asynchronous and must not fail the primary request path if the database is temporarily unavailable (best-effort logging with local buffering/retry).
- The proxy should support horizontal scaling behind a load balancer if traffic volume requires it, with `firewall_rules` and thresholds shared via the common PostgreSQL instance.

### 8.5 Maintainability
- Configuration (thresholds, layer toggles, deny lists) must be externalized to YAML files and/or the database, not hard-coded, to support hot-reload without redeployment.
- Codebase organization (proxy / engine / database / dashboard) should remain modular to allow independent testing of each pipeline layer.

### 8.6 Scalability
- The three-tier cascade is explicitly designed so that the cheapest checks run first and the most expensive (Layer 3) run least often, allowing the system to scale with traffic growth without linear cost increase.

### 8.7 Usability
- The dashboard must present block-rate and latency KPIs in a way that a non-developer compliance reviewer can interpret without needing to read raw JSON logs directly (though the detail view remains available for deep forensic review).

---

## 9. Deployment Architecture

### 9.1 Container Stack
Deployed via `docker-compose.yml` (or a Kubernetes Helm chart for larger environments), comprising:
1. **Firewall/API Gateway service** — FastAPI application (`src/main.py`) hosting the proxy and inspection pipeline.
2. **PostgreSQL service** — persistent volume-backed database for all four schema tables.
3. **Streamlit Dashboard service** — internal web UI, exposed only on the organization's private network.

### 9.2 Configuration Management
- `.env` — environment-specific secrets and endpoints (DB credentials, downstream base URLs, ports).
- `config/firewall.yaml` — global pipeline toggles and thresholds.
- `config/rules_regex.yaml` — Layer 1 signature definitions.
- `config/deny_list.yaml` — static keyword blocklist.

### 9.3 Deployment Steps (Operational Overview)
1. Administrator clones/receives the repository and populates `.env` from `.env.example`.
2. Administrator runs the container orchestration command (Docker Compose up / Helm install).
3. The gateway boots, loads configuration and active rules from the database and YAML files, and begins listening on the configured port.
4. Client applications are reconfigured to point their `BASE_URL` at the firewall's internal address.
5. The dashboard becomes available on its internal port for ongoing monitoring and configuration.

### 9.4 Air-Gapped Operation
Because all ML assets (`classifier.onnx`, tokenizer files) are bundled inside the image/volume and the reasoning model runs locally, the system can operate with no outbound internet dependency for its core inspection logic — only the final forwarding hop to the downstream LLM provider requires network egress (and even that can be a fully local model).

---

## 10. Assumptions, Dependencies & Constraints

**Assumptions**
- Client applications can be reconfigured at the transport layer (base URL) without deeper code changes.
- The organization's infrastructure can host a PostgreSQL instance and persistent storage for ML model artifacts.

**Dependencies**
- PostgreSQL database engine.
- ONNX Runtime for Layer 2 inference.
- A locally hosted or lightweight reasoning model for Layer 3.
- Docker/container orchestration platform.

**Constraints**
- The system must not depend on any external SaaS logging, analytics, or model-hosting service for its core inspection or storage functions.
- Real-time inspection must not introduce unacceptable latency to the protected application's user experience.

---

## 11. Future Enhancements
- Multi-tenant support within a single deployment (isolated rule sets and dashboards per business unit).
- Pluggable model backends for Layer 2/Layer 3 (allowing organizations to swap in their own fine-tuned classifiers).
- Automated rule suggestion based on recurring patterns detected in `detected_patterns` across `threat_logs`.
- Optional integration hooks for SIEM export (while preserving the no-third-party-by-default posture).
- Rate-limiting and anomaly detection keyed on `client_ip` for abuse/DoS pattern detection.

---

## 12. Appendix — Repository Structure Reference

```
ai-prompt-firewall/
├── docker-compose.yml
├── Dockerfile
├── README.md
├── .env.example
├── config/
│   ├── firewall.yaml
│   ├── rules_regex.yaml
│   └── deny_list.yaml
├── src/
│   ├── main.py
│   ├── proxy/
│   │   ├── handler.py
│   │   └── forwarder.py
│   ├── engine/
│   │   ├── pipeline.py
│   │   ├── layer_1_deterministic.py
│   │   ├── layer_2_classifier.py
│   │   ├── layer_3_evaluator.py
│   │   └── output_scanner.py
│   ├── database/
│   │   ├── connection.py
│   │   ├── models.py
│   │   └── storage.py
│   ├── models/
│   │   ├── classifier.onnx
│   │   └── tokenizer/
│   └── dashboard/
│       ├── app.py
│       ├── .streamlit/config.toml
│       ├── components/
│       │   ├── metrics_cards.py
│       │   ├── charts.py
│       │   └── log_table.py
│       └── pages/
│           ├── 1_Analytics.py
│           ├── 2_Threat_Logs.py
│           └── 3_Configuration.py
```

---

*End of Document*
