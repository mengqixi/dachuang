# Codex Framework Plan

## Current Phase

Build a Phase 2 skeleton that is import-safe, configuration-driven, and reviewable.

Completed scope:

- Security middleware package with safe defaults.
- TraceId generation and response propagation.
- Switchable placeholders for rate limit, anti replay, sign verify, IP filter, slow API, API switch, and security logging.
- Detection pipeline placeholders for behavior, Kitsune-lite, and LUCID-lite.
- Response policy and benchmark placeholders.
- Config files for security, detection, federated secure aggregation, and reports.
- Documentation for architecture, database design, Claude tasks, and review.

## Integration Rules

- Keep existing API paths unchanged.
- Keep existing frontend page ids and navigation unchanged.
- Do not move current modules into the new layout during this phase.
- Every new feature must start behind a config switch.
- Every placeholder must say it is a placeholder.

## Next Codex Review Loop

1. Read Claude's changed files only.
2. Run `python -m py_compile app.py src`.
3. Start `python app.py` on a temporary port.
4. Check `/`, `/api/system/health`, and the changed API.
5. Confirm no new heavy dependency was added.
6. Confirm docs do not claim placeholder features are complete.
