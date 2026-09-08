# 🛡️ Decentralized AI Prompt Injection Firewall

A standalone, high-performance security reverse proxy designed to inspect, intercept, and block prompt injection attacks, jailbreaks, and sensitive data leakage before they reach downstream Large Language Models (LLMs). 

Built with a **decentralized, privacy-first architecture**, all threat evaluations, local machine learning models, and analytics telemetry remain 100% inside your organization's private security boundary.

---

## 📂 Repository File Structure & Schema

Below is the complete project directory structure along with a single-sentence functional description for every file.

```text
ai-prompt-firewall/
├── docker-compose.yml              # Defines multi-container orchestration for the firewall proxy, PostgreSQL database, and Streamlit dashboard services.
├── Dockerfile                      # Builds the unified, air-gapped production container environment housing the Python gateway engine and dashboard runtime.
├── README.md                       # Serves as the primary project documentation, installation guide, and repository directory reference.
├── .env.example                    # Template file defining necessary environment variables including target base URLs, database passwords, and port configurations.
│
├── config/
│   ├── firewall.yaml               # Global system configuration file governing pipeline toggles, layer sensitivity thresholds, and proxy port bindings.
│   ├── rules_regex.yaml            # Signature configuration file holding Layer 1 regex pattern matrices for sub-millisecond threat detection.
│   └── deny_list.yaml              # Keyword blocklist file containing static strings, system keywords, and sensitive terms blocked across all requests.
│
├── src/
│   ├── main.py                     # Primary execution entrypoint that boots the FastAPI server, initializes model pipelines, and loads configuration files.
│   ├── __init__.py                 # Marks the root source directory as a package module for package discovery.
│   │
│   ├── proxy/                      # Transparent Reverse Proxy Layer
│   │   ├── __init__.py             # Exposes proxy handling modules as an internal sub-package.
│   │   ├── handler.py              # Intercepts inbound API request payloads and handles custom HTTP block response generation.
│   │   └── forwarder.py            # Transparently forwards cleared prompts to the configured target downstream LLM base URL.
│   │
│   ├── engine/                     # Cascading Multi-Layer Security Pipeline
│   │   ├── __init__.py             # Package marker aggregating all security evaluation modules.
│   │   ├── pipeline.py             # Orchestrates sequential execution flow across Layer 1, Layer 2, Layer 3, and the Output Scanner.
│   │   ├── layer_1_deterministic.py# Executes sub-millisecond regex and static pattern matching against inbound text payloads.
│   │   ├── layer_2_classifier.py   # Runs fast local ONNX model inference to calculate a normalized semantic risk score for incoming prompts.
│   │   ├── layer_3_evaluator.py    # Conducts deep contextual intent evaluations for ambiguous prompts using a localized evaluation framework.
│   │   └── output_scanner.py       # Intercepts outgoing LLM completion text to prevent system prompt leakage, PII exposure, and secret token leaks.
│   │
│   ├── database/                   # Decentralized Telemetry & Persistence Layer
│   │   ├── __init__.py             # Package marker for database ORM and storage utilities.
│   │   ├── connection.py           # Manages asynchronous PostgreSQL connection pooling and session lifecycle hooks.
│   │   ├── models.py               # Defines SQLAlchemy relational database schemas for threat logs, dynamic firewall rules, and hourly metrics.
│   │   └── storage.py              # Implements asynchronous write functions for security telemetry and cached analytical query getters for Streamlit.
│   │
│   ├── models/                     # Embedded Local ML Assets
│   │   ├── classifier.onnx         # Pre-trained, quantized ONNX machine learning model used for fast semantic threat detection in Layer 2.
│   │   └── tokenizer/              # Directory containing local vocabulary, configuration files, and tokenizers required for local ML inference.
│   │
│   └── dashboard/                  # Decentralized Streamlit Admin Interface
│       ├── app.py                  # Main entrypoint script configuring Streamlit layout settings, visual themes, and sidebar page navigation.
│       ├── __init__.py             # Package marker for the Streamlit dashboard app module.
│       ├── .streamlit/
│       │   └── config.toml         # Custom Streamlit server setting file controlling brand color palettes, port configurations, and header elements.
│       │
│       ├── components/             # Reusable UI Components
│       │   ├── __init__.py         # Package marker for reusable frontend component modules.
│       │   ├── metrics_cards.py    # Formats key performance indicators into metric card layouts displaying real-time inspection volume and block rates.
│       │   ├── charts.py           # Generates interactive Plotly graphs illustrating threat volume time-series, layer distribution, and risk scores.
│       │   └── log_table.py        # Renders an interactive, searchable data table displaying detailed security inspection logs with JSON detail view modal support.
│       │
│       └── pages/                  # Dashboard View Sections
│           ├── 1_Analytics.py     # Renders the real-time security analytics view with time-series charts, layer execution rates, and threat breakdowns.
│           ├── 2_Threat_Logs.py   # Renders the full forensic audit page for searching, filtering, inspecting, and exporting detailed request payloads.
│           └── 3_Configuration.py # Provides interactive UI controls to adjust sensitivity thresholds, update keyword blocklists, and hot-reload firewall rules.
