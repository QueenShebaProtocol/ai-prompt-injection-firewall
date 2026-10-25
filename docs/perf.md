# Performance report

**Status:** Evidence-incomplete. This report deliberately does not claim that unmeasured performance targets pass.

**Project:** [QueenShebaProtocol/ai-prompt-injection-firewall](https://github.com/QueenShebaProtocol/ai-prompt-injection-firewall) · **Report file:** `docs/perf.md`

## Status at a glance

| Area | Evidence needed | Status |
|---|---|---|
| Layer 1 / Layer 2 / proxy latency | `layer1_latency.json`, `layer2_latency.json`, `proxy_overhead_latency.json` | Missing |
| Layer 3 latency and traffic share | P5 demo measurement and SQL output | Missing |
| Hot-reload timings and failures | `hot_reload_inprocess.json`, integration test output | Missing |
| Dashboard page loads and query plans | Browser timings, `EXPLAIN (ANALYZE, BUFFERS)` | Missing |

Update this table (and the detailed tables below) only from saved result files. When a row is
measured, change its status to `PASS` or `FAIL (measured)` and add the date and commit hash.

## Scope and evidence inventory

This checkout contains the performance test harness in `tests/perf/test_latency.py` and `tests/perf/test_hot_reload.py`, plus the synthetic dashboard data generator in `scripts/seed_demo.py`. The project archive supplied for this report did **not** contain `perf_results/*.json`, P6's Monday/Wednesday benchmark artifacts, P5's Wednesday demo measurements, saved browser timings, or PostgreSQL `EXPLAIN` output. There is no separate SRS document in `docs/`; the latency thresholds below are the defaults documented in the test harness, described there as SRS section 8.1.

Therefore:
- **FAIL (evidence gate)** means the requested acceptance evidence is absent; it does **not** mean a benchmark was run and measured slower than its threshold.
- Never interpret synthetic demo-row `execution_time_ms` values as live latency measurements. The seeder generates illustrative records; its Layer 2 values are generated from a distribution and its Layer 3 values are synthetic.
- Fill the measured columns only from the named JSON result files and recorded commands after running the procedure below. Preserve the original result files with the report/review artifacts.

## Test machine

The benchmark result JSON is the source of truth for the machine used in each run. The uploaded archive does not include a benchmark JSON, so the actual benchmark machine cannot be established from evidence.

| Property | Recorded value |
|---|---|
| OS/platform | NOT RECORDED — read `hardware.platform` from each result JSON |
| CPU / architecture | NOT RECORDED — read `hardware.processor` from each result JSON |
| Logical CPU count | NOT RECORDED — read `hardware.cpu_count` from each result JSON |
| Python | NOT RECORDED — read `hardware.python` from each result JSON |
| ONNX Runtime | NOT RECORDED — `hardware.onnxruntime` in Layer 2 result |
| Database / container versions | NOT RECORDED — capture `docker compose version`, `docker image inspect postgres:16-alpine --format '{{.Id}}'`, and `SELECT version();` |

## Layer 1, Layer 2 and proxy overhead

The test harness records p50/p95/p99/max in milliseconds. Its verdict is based on **p95 only** and uses a strict less-than comparison. The defaults are `PERF_L1_P95_MS=1 ms`, `PERF_L2_P95_MS=30 ms`, and `PERF_PROXY_OVERHEAD_P95_MS=20 ms`. These are harness defaults documented as SRS §8.1; verify them against the canonical SRS before treating them as authoritative requirements.

| Check | Samples in harness | p50 (ms) | p95 (ms) | p99 (ms) | Target (p95) | Verdict |
|---|---:|---:|---:|---:|---:|---|
| Layer 1 `evaluate()` | 1,000 measured + 50 warm-up | NOT MEASURED | NOT MEASURED | NOT MEASURED | `< 1 ms` | **FAIL — result JSON missing** |
| Layer 2 ONNX `predict()` | 200 measured + 20 warm-up (plus model warm-up) | NOT MEASURED | NOT MEASURED | NOT MEASURED | `< 30 ms` | **FAIL — result JSON missing** |
| Proxy request overhead | 300 measured + 30 warm-up | NOT MEASURED | NOT MEASURED | NOT MEASURED | `< 20 ms` | **FAIL — result JSON missing** |

**Interpretation and next step:** these verdicts flag missing acceptance evidence, not measured latency failures. Obtain `layer1_latency.json`, `layer2_latency.json`, and `proxy_overhead_latency.json` from P6. If any file is absent, run the commands in [How to reproduce](#how-to-reproduce) on the intended test machine and retain the generated JSON. Layer 2 cannot be measured unless its real, non-empty ONNX model and tokenizer assets are installed locally; the model files are git-ignored (about 740 MB), so each machine must download them first (see step 1 of How to reproduce).

The proxy test uses an in-process FastAPI ASGI transport, a fake immediate downstream, and a no-op log writer. Its number is **proxy overhead under this harness**, not end-to-end provider latency.

## Layer 3 latency and demo traffic share

**Status: FAIL — P5 demo measurement artifact not present.** No measured Layer 3 latency distribution or traffic count/share was supplied. Do not infer actual Layer 3 latency from the synthetic generator's hard-coded distributions.

For the P5 Wednesday demo, derive traffic share from the actual demo dataset and retain the SQL output and the relevant test/demo artifact. Define the denominator and numerator explicitly:
- **Total demo requests:** all rows in the demo dataset for the demo's stated time window.
- **Layer 3 reached:** rows whose `layer_details` JSON contains a `layer_3` object / whose pipeline telemetry records a Layer 3 invocation. Confirm the field semantics against the demo's actual schema.
- **Share:** `Layer 3 reached / total demo requests × 100%`.
- **Latency:** use actual Layer 3 evaluator timings from request telemetry or a dedicated measured benchmark, report sample count and p50/p95/p99. Do not use the `execution_time_ms` field for Layer 3 latency; it is whole-request execution time.

Example read-only SQL for the schema used by the seeder (adjust only if the measured demo uses a different time window):

```sql
SELECT
  count(*) AS total_demo_requests,
  count(*) FILTER (
    WHERE jsonb_typeof(layer_details -> 'layer_3') = 'object'
  ) AS rows_with_layer3_details,
  round(
    100.0 * count(*) FILTER (
      WHERE jsonb_typeof(layer_details -> 'layer_3') = 'object'
    ) / NULLIF(count(*), 0), 2
  ) AS percent_with_layer3_details
FROM threat_logs
WHERE application_id = 'demo';
```

This query counts **rows containing Layer 3 details**, not necessarily actual Layer 3 invocations, unless the telemetry contract guarantees the equivalence. Validate against the P5 demo event definition before reporting it as traffic share. Add the actual output, time window, and source artifact here before acceptance.

| Metric | Result | Status |
|---|---|---|
| Layer 3 p50 / p95 / p99 latency | NOT MEASURED | **FAIL — evidence missing** |
| Demo total requests | NOT RECORDED | **FAIL — evidence missing** |
| Requests reaching Layer 3 | NOT RECORDED | **FAIL — evidence missing** |
| Share reaching Layer 3 | NOT CALCULABLE | **FAIL — numerator/denominator evidence missing** |

## Hot-reload time-to-effect and request failures

The harness in `tests/perf/test_hot_reload.py` defines two kinds of measurements:
1. In-process rule-list swapping, including p95 during swaps versus `3 × baseline p95 + 0.2 ms`, plus exceptions and missed rule evaluations.
2. Integration hot reload for rule create/deactivate and runtime-config toggles. Poll intervals default to 1 second, with a 1 second margin; the test records time-to-effect and request failures under concurrent load.

No `hot_reload_inprocess.json`, integration test output, or P5/P6 recorded timings were included in the archive.

| Measurement | Target / criterion | Result | Status |
|---|---|---|---|
| Rule swap p95 vs baseline | `< 3 × baseline p95 + 0.2 ms` | NOT MEASURED | **FAIL — result JSON missing** |
| Rule create → block | Within configured polling interval + margin | NOT MEASURED | **FAIL — integration output missing** |
| Rule deactivate → pass | Within configured polling interval + margin | NOT MEASURED | **FAIL — integration output missing** |
| Runtime config disable → effect | Within configured polling interval + margin | NOT MEASURED | **FAIL — integration output missing** |
| Runtime config restore → effect | Within configured polling interval + margin | NOT MEASURED | **FAIL — integration output missing** |
| Failed requests during reload | `0` | NOT MEASURED | **FAIL — integration output missing** |
| Empty/partial-rule evaluations during swap | `0` | NOT MEASURED | **FAIL — result JSON missing** |

Run the integration test against an isolated test database: it creates and removes a temporary firewall rule. Save the full pytest output, not just the exit code. Report both the four time-to-effect values and the number of requests sent/failed.

## Dashboard load times and query plans

**Status: FAIL — browser timing and `EXPLAIN` artifacts absent.** The archive has no recorded large-dataset page-load timings and no query plans. Do not estimate browser load times from SQL execution alone.

The included demo seeder defaults to 5,000 rows and supports up to 1,000,000 rows. The P5 demo's exact seeded row count is not evidenced by this archive. Record the command used and verify the actual row count with SQL. If recreating a large-dataset run, use an isolated database and record the chosen size; do not seed a production database.

### Candidate heavy analytics queries

The analytics implementation in `src/dashboard/pages/1_Analytics.py` includes:
- top matched patterns: filters by timestamp and blocked status, expands `detected_patterns` JSONB arrays, groups and sorts by hit count;
- scanner flags by category: filters timestamp and `output_flagged`, expands JSONB category arrays, groups and sorts;
- risk histogram: timestamp filter and grouped computed risk-score bin;
- recent latency buckets: timestamp filter plus `date_trunc`, average, and `percentile_cont(0.95)`;
- top clients: timestamp filter, grouped counts and filtered blocked counts.

Capture actual plans for the heaviest queries from the measured large dataset using `EXPLAIN (ANALYZE, BUFFERS, VERBOSE, SETTINGS)` on the equivalent SQL with the same time-window and data volume. `ANALYZE` executes the query, so run it against the isolated test database, not production. The exact SQL generated by SQLAlchemy should be captured with bound values from the test run; don't present an approximate query plan as if it were the application's exact SQL.

| Page / query | Dataset row count | Browser p50 / p95 | SQL execution time / plan | Status |
|---|---:|---|---|---|
| Analytics initial load | NOT RECORDED | NOT MEASURED | NOT RECORDED | **FAIL — evidence missing** |
| Threat Logs initial load | NOT RECORDED | NOT MEASURED | NOT RECORDED | **FAIL — evidence missing** |
| Top matched patterns | NOT RECORDED | N/A | `EXPLAIN` absent | **FAIL — evidence missing** |
| Scanner flags by category | NOT RECORDED | N/A | `EXPLAIN` absent | **FAIL — evidence missing** |
| Risk histogram / latency buckets | NOT RECORDED | N/A | `EXPLAIN` absent | **FAIL — evidence missing** |

For browser timings, use a repeatable method (for example, Playwright navigation timing) against the same local URL, browser version, dataset, and warm/cold-cache policy. Report sample count and p50/p95, and separate Streamlit initial page load from subsequent reruns/interactions.

## Bottlenecks, missed targets, and recommendations

### Confirmed limitations of the available evidence

- The required benchmark JSON files and P5/P6 result artifacts are missing from the supplied project archive. This is an **evidence gap**, not proof of a slow implementation.
- Layer 2 measurement is conditional on model assets and dependencies being available; without them the test skips rather than producing a valid latency result.
- The proxy microbenchmark excludes real downstream provider latency, the database log writer, and network transport. Do not generalize its numbers to production end-to-end latency.
- The dashboard has JSONB expansion/grouping and percentile aggregation queries that are worth profiling, but no claim that these are bottlenecks is justified until `EXPLAIN ANALYZE` and page timings are collected.
- Synthetic demo rows are illustrative and cannot establish real Layer 3 latency or measured request-path performance.

### Recommendations, pending measurement

1. Attach P6's raw JSON results and P5's demo evidence to the review; record the commit, command, environment variables affecting targets, timestamp, and machine for every run.
2. Run the benchmark at least once on the agreed reference machine with Layer 2 assets installed. Keep the JSON result directory as an artifact; do not commit large generated result files unless the team workflow requires it.
3. If Layer 1 misses its p95 target, profile rule count, regex complexity, prompt length, and allocations before changing the engine.
4. If Layer 2 misses its p95 target, record model/runtime versions, sequence length, thread settings, and CPU execution provider; compare warm and cold model load separately.
5. If proxy overhead misses its target, profile request validation, pipeline orchestration, JSON serialization, and scanner work separately; then run an additional end-to-end test with real database/network behavior.
6. If reload causes request failures or exceeds the polling bound, inspect polling loops, atomic file replacement, database-to-memory rule synchronization, and config parsing. Preserve the failure count even if the latency target passes.
7. For dashboard queries, compare plans before adding indexes. Check whether the timestamp filter uses an index, whether JSONB expansion or sort spills to disk, and whether a suitable timestamp index exists. Validate changes on the same seeded dataset.
8. Add explicit SRS targets for Layer 3 and dashboard page loads if they are contractual requirements; the supplied repository does not define numeric thresholds for those measurements.

## How to reproduce

Run these commands from the repository root on a disposable development/test environment. Use the project's existing `.env` for local services; do not copy secrets into this document or benchmark artifacts.

### 1. Record environment and check prerequisites

```bash
git rev-parse HEAD
git status --short --branch
date --iso-8601=seconds
uname -a
lscpu
python --version
docker compose version
docker compose ps
```

Confirm `src/models/classifier.onnx` and `src/models/tokenizer/tokenizer.json` are present and non-empty before the Layer 2 benchmark. Do not create empty placeholders. They are not stored in git; download them once:

```bash
mkdir -p src/models/tokenizer
BASE=https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2/resolve/main/onnx
curl -L --fail -o src/models/classifier.onnx "$BASE/model.onnx"
curl -L --fail -o src/models/tokenizer/tokenizer.json "$BASE/tokenizer.json"
ls -lh src/models src/models/tokenizer
```

### 2. Install test dependencies and run microbenchmarks

Use the project's environment/lock policy; a typical local setup is:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt -r requirements-dev.txt
mkdir -p perf_results
PERF_RESULTS_DIR=perf_results pytest -m perf -s tests/perf/test_latency.py
```

Expected JSON files:
- `perf_results/layer1_latency.json`
- `perf_results/layer2_latency.json`
- `perf_results/proxy_overhead_latency.json`

The test's defaults are 1,000 Layer 1 measured calls, 200 Layer 2 measured calls, and 300 proxy measured calls. Warm-up calls are additional and not included in the sample count. Save stdout and stderr with the run artifact.

### 3. Run hot-reload tests

Run the in-process rule-swap check:

```bash
PERF_RESULTS_DIR=perf_results pytest -m perf -s tests/perf/test_hot_reload.py
```

For the integration test, start an isolated PostgreSQL/database and ensure `DATABASE_URL` points to it, then run:

```bash
PERF_RESULTS_DIR=perf_results pytest -m 'perf and integration' -s tests/perf/test_hot_reload.py
```

The integration test uses a fake downstream LLM but a real gateway process and database. Review the test's cleanup output and verify that its temporary rule was removed. Preserve the entire test output because the integration timing summary is printed there.

### 4. Recreate a large demo dataset (isolated DB only)

The seeder's default is 5,000 rows. For a 100,000-row large-data run, the repository documents:

```bash
python -m scripts.seed_demo --rows 100000 --days 30 --yes
```

For a clean repeat, reset only demo rows and re-seed:

```bash
python -m scripts.seed_demo --reset --rows 100000 --days 30 --yes
```

The seeder scopes rows to `application_id='demo'`; still confirm the printed target database and row counts before proceeding. Record the actual count from the database after seeding. The supplied archive does not prove that P5 used 100,000 rows; this is a reproducible rerun suggestion, not a claim about P5's demo.

### 5. Capture row counts and database details

Use `psql` against the same isolated database and record outputs:

```sql
SELECT version();
SELECT count(*) AS all_rows FROM threat_logs;
SELECT count(*) AS demo_rows FROM threat_logs WHERE application_id = 'demo';
SELECT count(*) AS non_demo_rows FROM threat_logs WHERE application_id <> 'demo';
```

Table names are shown as they appear in the project ORM; confirm the deployed schema if migrations or naming conventions differ.

### 6. Measure dashboard and inspect query plans

Start the same Compose stack and dashboard version used for the run. Record:
- exact browser and version;
- local dashboard URL and page;
- dataset row count;
- number of cold and warm navigation samples;
- browser timing source (Playwright trace or browser Performance API);
- page-load p50/p95 and failures;
- the exact SQLAlchemy-generated SQL and bound parameters for the slowest analytics queries;
- `EXPLAIN (ANALYZE, BUFFERS, VERBOSE, SETTINGS)` output for those queries.

Do not claim page-load or query timings until these measurements have been collected.

### 7. Final evidence review

Before changing any table above to PASS or to a measured FAIL:
1. Confirm the JSON `timestamp`, `hardware`, `stats_ms`, `target_p95_ms`, and `result` fields (or corresponding hot-reload fields).
2. Recompute the verdict from the recorded p95 and target using the harness's strict `<` rule.
3. Make sure seeded row counts and Layer 3 traffic share refer to the same demo dataset and time window.
4. Include the exact command and result artifact for every number.
5. Leave a target as **FAIL — evidence missing** until it is backed by a measured artifact; do not silently replace missing results with estimates.
