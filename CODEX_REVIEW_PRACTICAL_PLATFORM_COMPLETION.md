# Codex Review - Practical Platform Roadmap Completion

## Conclusion

The practical platform roadmap has been implemented and verified for the current codebase.

Status: **pass**

The remaining dirty files are runtime artifacts created by local verification, not source changes:

- `data/system.db`
- `data/keys/`
- `data/user_submissions/`

These should not be committed.

## Scope Verified

### Task 1 - Roadmap Document

Status: complete

Evidence:

- `PRACTICAL_PLATFORM_ROADMAP.md` defines the product as `密码攻击检测与隐私训练平台`.
- User side is scoped to `上传数据 / 风险检测 / 分析报告`.
- Admin side is scoped to `用户提交 / 数据处理 / 模型版本 / 系统审计`.
- The roadmap removes the standalone risk detail module.
- `Top 20` wording is replaced by `风险排名`.
- The document references `Network-Security-Based-On-ML` only for lightweight ideas: unified pipeline, fused scoring, result format, model status, statistics, and dataset management.

### Task 2 - Lightweight Dataset Import

Status: complete

Evidence:

- `scripts/import_security_datasets.py`
- `config/dataset_sources.json`
- `src/datasets/security_dataset_importer.py`

Verified capabilities:

- Recognizes local generated data sources.
- Defines UNSW-NB15, CIC-IDS2017, CSE-CIC-IDS2018, and CIC-DDoS2019 as configurable sources.
- Uses lightweight CSV import logic suitable for small server resources.
- Normalizes public security datasets into a unified training schema.

### Task 3 - Unified Risk Result Schema

Status: complete

Evidence:

- User analysis results include unified fields:
  - `is_risk`
  - `risk_score`
  - `risk_level`
  - `attack_type`
  - `confidence`
  - `action_suggestion`
  - `detection_time_ms`
  - `trigger_features`
  - `score_breakdown`
  - `reason`
  - `suggestion`
  - `source_dataset`
  - `model_version`
- Risk ranking is sorted by `risk_score` descending.
- Regression coverage exists in `tests/test_practical_platform.py`.

### Task 4 - User Risk Detection And Report Page

Status: complete

Evidence:

- User navigation remains `上传数据 / 风险检测 / 分析报告`.
- User-side risk detail module is not planned as a standalone page.
- Frontend uses `风险排名` and `风险排名摘要`.
- Legacy `Top 20` wording is blocked by test coverage.
- Risk ranking is not a separate page; it remains inside the risk detection/report flow.

### Task 5 - Admin Navigation Refactor

Status: complete

Evidence:

- Admin navigation uses:
  - `用户提交`
  - `数据处理`
  - `模型版本`
  - `系统审计`
  - `退出`
- User submissions are separated from system training data.
- Dataset/source status and training flow are moved into the admin data processing area.
- Model version display is separated from training controls.
- System audit stays independent.

### Task 6 - Dataset Status In Admin Data Processing

Status: complete

Evidence:

- `/api/admin/datasets/sources` returns configured dataset sources.
- Existing sources include sample counts, feature counts, label columns, label distributions, attack type distributions, and scan counts.
- Missing configured datasets show as unavailable instead of being presented as loaded.
- Admin data source table displays distribution tags.

### Task 7 - Model Version And Runtime Model State

Status: complete

Evidence:

- `/api/admin/model-versions` returns runtime model state and version records.
- Version records include:
  - `artifact_status`
  - `can_activate`
  - `current_runtime`
  - `current_display`
  - `activation_reason`
  - `version_role`
- Tracking-only versions are not falsely presented as switchable runtime models.
- Runtime model availability remains visible when no switchable artifact exists.

## Verification

Commands executed:

```bash
python -m compileall -q app.py src scripts tests
python -m unittest discover tests -v
python scripts/smoke_check.py --user-base http://127.0.0.1:5000 --admin-base http://127.0.0.1:5001 --check-admin-login --admin-user root --admin-password root
```

Results:

- Compile check: passed
- Unit test discovery: `128` tests run, `21` skipped by environment flags, `0` failures
- Smoke check:
  - User page: 200
  - System health: 200
  - Dataset status: 200
  - Admin page: 200
  - Admin session: 200
  - Admin login with `root/root`: 200

Known non-blocking note:

- `tests/test_all.py::test_frontend` emits a ResourceWarning because the historical test opens `index.html` without closing the file handle. It does not fail the test suite.

## Merge / Continue Decision

Recommendation: the roadmap implementation can be considered complete for the current planned scope.

Next development should not continue the same roadmap as an open-ended task. If new work is needed, create a new scoped task, preferably one of:

1. Clean runtime artifact handling in tests so `data/system.db`, `data/keys/`, and `data/user_submissions/` are not dirtied during verification.
2. Add browser-level visual regression checks for the user/admin pages.
3. Deploy the latest committed source to the server after explicit confirmation.
