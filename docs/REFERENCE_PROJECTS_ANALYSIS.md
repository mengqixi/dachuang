# Reference Projects Analysis

## Network-Security-Based-On-ML

Useful design ideas:

- Separate algorithm families into pipeline, behavior analysis, Kitsune, LUCID, benchmark, and response modules.
- Keep one unified result contract so UI/API consumers do not need detector-specific parsing.
- Treat benchmark data and attack simulation as first-class engineering tools.
- Keep response policy separate from detection so the same risk result can be logged, blocked, rate limited, or only displayed.

Adaptation for this project:

- Use Flask and existing `app.py`, not FastAPI.
- Use SQLite design docs, not MongoDB.
- Keep Kitsune and LUCID as lite placeholders until the project has data and resource budget.
- Integrate with existing Isolation Forest and Logistic Regression before adding new models.

## Guardian

Useful design ideas:

- Each protection capability is independently switchable.
- TraceId should be available early and returned in the response.
- Slow API logging should observe first, not block.
- Rate limit, anti replay, sign verify, IP filter, API switch, and request crypto are separate modules.
- Persistent security events make later review and demos easier.

Adaptation for this project:

- Use Flask request hooks instead of Java filters/interceptors.
- Use `config/security.yaml` instead of Spring Boot YAML properties.
- Use SQLite tables documented in `PHASE2_DATABASE_DESIGN.md`.
- Default all enforcement checks to disabled to protect current demos.

## Boundaries

No Java code, FastAPI code, MongoDB schema, Redis dependency, TensorFlow/PyTorch model, or external repository file has been copied into the main project.
