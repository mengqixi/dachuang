# Claude Implementation Tasks

Each task must stay small, keep existing APIs stable, and include verification notes.

## Task 1: Implement TraceId Middleware

Goal: persist TraceId through request context, response headers, and logs.

Allowed files: `src/security/trace_id.py`, `src/security/middleware.py`, `config/security.yaml`, tests.

Forbidden files: `index.html`, existing detection/encryption/federated algorithms.

Input/output: accepts `X-Trace-Id`; returns `X-Trace-Id`.

Acceptance: every API response has a non-empty TraceId; incoming TraceId is preserved.

Test: Flask test client for `/api/system/health`.

Codex review: ensure no request blocking and no response format break.

## Task 2: Implement Slow API Detection

Goal: record requests exceeding `slow_api.threshold_ms`.

Allowed files: `src/security/slow_api.py`, `src/security/security_logger.py`, SQLite migration script, tests.

Forbidden files: current business routes except minimal hook use.

Input/output: request timing; SQLite log row.

Acceptance: slow request creates a log entry when enabled.

Test: unit test with injected timer.

Codex review: confirm normal requests are not blocked.

## Task 3: Implement Interface Rate Limit

Goal: add local sliding-window rate limiting.

Allowed files: `src/security/rate_limiter.py`, `config/security.yaml`, tests.

Forbidden files: existing frontend pages and old APIs.

Input/output: request path/IP; allow/deny decision.

Acceptance: disabled by default; enabled mode blocks excess requests with `{code,msg,data}`.

Test: call same API more than configured limit.

Codex review: ensure config switch works.

## Task 4: Implement Anti Replay

Goal: validate timestamp and nonce with SQLite nonce storage.

Allowed files: `src/security/anti_replay.py`, database init script, tests.

Forbidden files: encryption core and detection core.

Input/output: `X-Timestamp`, `X-Nonce`; allow/deny decision.

Acceptance: duplicate nonce is rejected only when feature enabled.

Test: two requests with same nonce.

Codex review: check TTL cleanup and no hardcoded secret.

## Task 5: Implement Parameter Signature

Goal: verify request signature for selected paths.

Allowed files: `src/security/sign_verify.py`, `config/security.yaml`, tests.

Forbidden files: Paillier/AES modules unless explicitly needed later.

Input/output: request body/query/header; signature decision.

Acceptance: disabled by default; HMAC-SHA256 available when enabled.

Test: valid and invalid signatures.

Codex review: ensure secrets come from config/env, not source code.

## Task 6: Implement Security Event Log

Goal: create SQLite-backed security event persistence.

Allowed files: `src/security/security_logger.py`, `src/utils/data_storage.py` or a new migration script, tests.

Forbidden files: existing table definitions unless backward compatible.

Input/output: event dict; SQLite row.

Acceptance: security event can be written and queried.

Test: insert and read back event.

Codex review: check schema migration is idempotent.

## Task 7: Implement Behavior Analyzer

Goal: detect simple DDoS/scan/anomaly patterns from event aggregates.

Allowed files: `src/detection/behavior/behavior_analyzer.py`, `config/detection.yaml`, tests.

Forbidden files: existing IF/MLP detector internals.

Input/output: event list; unified risk result.

Acceptance: outputs `risk_score`, `risk_level`, `attack_type`, `confidence`, `evidence`.

Test: synthetic scan and normal events.

Codex review: no heavy dependency and clear false-positive bounds.

## Task 8: Implement Detection Pipeline Adapter

Goal: combine existing detectors with optional new detectors.

Allowed files: `src/detection/pipeline/risk_pipeline.py`, config, tests.

Forbidden files: current API route paths.

Input/output: feature vector/list; unified risk result.

Acceptance: works with existing Isolation Forest and Logistic Regression results.

Test: mocked detector outputs and weight config.

Codex review: verify all detectors are switchable.

## Task 9: Implement Dataset Federated Split

Goal: improve dataset split persistence for four named clients.

Allowed files: `src/preprocess/federated_splitter.py`, `src/federated/secure/`, tests.

Forbidden files: existing simulated federated API paths.

Input/output: dataset arrays; node files and metadata.

Acceptance: four clients get reproducible splits.

Test: generated small dataset.

Codex review: check no external dataset assumption.

## Task 10: Implement Benchmark Attack Simulation

Goal: generate small local benchmark scenarios.

Allowed files: `src/benchmark/benchmark_runner.py`, scripts, tests.

Forbidden files: production routes unless adding a disabled endpoint later.

Input/output: scenario config; benchmark report dict.

Acceptance: can run locally in under 30 seconds.

Test: run benchmark with 100 samples.

Codex review: no long-running default behavior.

## Task 11: Implement Report Export

Goal: export JSON/Markdown reports first.

Allowed files: `src/reports/`, `config/report.yaml`, tests.

Forbidden files: current frontend unless adding a clearly separate button later.

Input/output: report data; stored JSON/Markdown.

Acceptance: no PDF dependency required in first step.

Test: create report artifact.

Codex review: ensure output path is constrained.

## Task 12: Implement Frontend Security Dashboard

Goal: add a small security events view without removing existing pages.

Allowed files: `index.html`, new API endpoint if needed, docs.

Forbidden files: existing page ids and route paths.

Input/output: security event API; dashboard table/chart.

Acceptance: existing 8 pages still work.

Test: browser smoke test and API smoke test.

Codex review: check no page layout regression.
