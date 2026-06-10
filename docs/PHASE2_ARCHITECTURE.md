# Phase 2 Architecture

## Goal

Phase 2 adds an extensible security and detection framework around the current Flask + SQLite project without replacing the existing system.

The current project remains the source of truth for:

- Flask backend and `app.py`
- SQLite persistence
- Existing frontend pages
- Existing encryption, detection, optimization, and simulated federated learning modules
- Existing API paths and response format

## Reference Ideas Adapted

### Network Security Based On ML

Borrowed ideas:

- Unified multi-model detection pipeline
- Network-flow and behavior-oriented feature extraction
- DDoS, scan, and abnormal traffic categories
- Weighted risk scoring across multiple detector families
- Reinforcement-learning-inspired response policy
- Benchmark and attack traffic simulation
- Experiment reports

Not borrowed:

- FastAPI stack
- MongoDB or external storage
- TensorFlow/PyTorch-heavy Kitsune/LUCID implementations
- Full repository code or training assets

### Guardian

Borrowed ideas:

- TraceId propagation
- Rate limiting
- Anti replay
- Signature verification
- IP allowlist/blocklist
- Slow API detection
- API switch
- Security event logging
- Request/response crypto extension points

Not borrowed:

- Java/Spring Boot starters
- Redis-only design
- Annotation-based Java APIs
- Servlet filter/interceptor code

## New Module Map

| Module | Purpose | Current status |
|---|---|---|
| `src/security/` | Request security middleware extension points | Scaffold only |
| `src/detection/pipeline/` | Unified risk output contract | Scaffold only |
| `src/detection/behavior/` | Behavior pattern detector | Scaffold only |
| `src/detection/kitsune_lite/` | Lightweight Kitsune-style placeholder | Scaffold only |
| `src/detection/lucid_lite/` | Lightweight LUCID-style placeholder | Scaffold only |
| `src/response/` | Risk-to-response policy | Scaffold only |
| `src/benchmark/` | Benchmark and attack simulation runner | Scaffold only |
| `src/reports/` | Future report exports | Scaffold only |
| `src/federated/secure/` | Secure aggregation extension points | Scaffold only |

## Risk Result Contract

All future detectors must normalize to:

```json
{
  "risk_score": 0.0,
  "risk_level": "low",
  "attack_type": "unknown",
  "confidence": 0.0,
  "evidence": []
}
```

## Security Middleware Mode

`config/security.yaml` defaults to safe mode. It creates and returns a TraceId header but does not block requests unless `security.enabled` and specific checks are enabled later.

## Flask Integration

`app.py` registers `SecurityMiddleware` as a non-blocking `before_request` and `after_request` hook. Existing API paths are untouched.

## Non-Goals In This Phase

- No full security enforcement.
- No new heavy model dependencies.
- No database migration execution.
- No frontend page replacement.
- No distributed federated runtime.
