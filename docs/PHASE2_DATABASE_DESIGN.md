# Phase 2 Database Design

These tables are design placeholders. They are not created automatically in this phase.

## security_events

Fields: `id`, `timestamp`, `trace_id`, `event_type`, `path`, `method`, `ip`, `severity`, `message`, `metadata_json`.

Purpose: store security middleware events.

Read/write module: `src/security/security_logger.py`.

P0 required: yes, for TraceId and slow API auditability.

## rate_limit_logs

Fields: `id`, `timestamp`, `trace_id`, `key`, `path`, `ip`, `limit_per_minute`, `allowed`, `current_count`.

Purpose: record rate-limit decisions.

Read/write module: `src/security/rate_limiter.py`.

P0 required: no. P1 when rate limiting is implemented.

## used_nonces

Fields: `nonce`, `timestamp`, `trace_id`, `path`, `ip`, `expires_at`.

Purpose: prevent replay by storing consumed nonces.

Read/write module: `src/security/anti_replay.py`.

P0 required: no. P1 when anti replay is implemented.

## slow_api_logs

Fields: `id`, `timestamp`, `trace_id`, `path`, `method`, `elapsed_ms`, `threshold_ms`, `ip`.

Purpose: record slow requests for diagnosis and demo dashboards.

Read/write module: `src/security/slow_api.py` and `src/security/security_logger.py`.

P0 required: yes.

## api_switch_rules

Fields: `id`, `path_pattern`, `enabled`, `reason`, `updated_at`, `updated_by`.

Purpose: store dynamic API switch rules.

Read/write module: `src/security/api_switch.py`.

P0 required: no.

## response_actions

Fields: `id`, `timestamp`, `trace_id`, `risk_score`, `risk_level`, `attack_type`, `action`, `reason`, `metadata_json`.

Purpose: record response policy decisions.

Read/write module: `src/response/response_policy.py`.

P0 required: no.

## benchmark_reports

Fields: `id`, `created_at`, `scenario`, `sample_count`, `duration_ms`, `accuracy`, `precision`, `recall`, `f1_score`, `report_json`.

Purpose: store benchmark and attack simulation summaries.

Read/write module: `src/benchmark/benchmark_runner.py`.

P0 required: no.

## detection_pipeline_logs

Fields: `id`, `timestamp`, `trace_id`, `risk_score`, `risk_level`, `attack_type`, `confidence`, `enabled_detectors`, `evidence_json`.

Purpose: record unified pipeline outputs for experiments and reports.

Read/write module: `src/detection/pipeline/risk_pipeline.py`.

P0 required: yes, once the pipeline is connected to APIs.
