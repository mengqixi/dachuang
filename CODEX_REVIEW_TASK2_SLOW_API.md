# CODEX Task 2 Slow API Review Report

Review date: 2026-06-10

Reviewed commit: `a603fd116abbfd0ad81c90fe47ff7bbc9b58cb9c`

## 1. 是否可以合并

结论：可以合并。

`a603fd1` 的改动集中在 slow_api 慢接口日志能力，未发现旧 API、旧页面、数据库结构、检测/加密/优化/联邦学习核心逻辑被破坏。功能默认只记录日志，不拦截请求，不返回 429。

## 2. 本次 Claude 修改文件清单

`a603fd1` 实际修改文件：

- `config/security.yaml`
- `src/security/middleware.py`
- `src/security/slow_api.py`
- `tests/test_slow_api.py`

用户允许范围内但该提交未修改：

- `src/security/security_logger.py`
- `docs/CLAUDE_IMPLEMENTATION_TASKS.md`
- `docs/REVIEW_CHECKLIST.md`

未发现 Claude 修改允许范围之外的业务代码、前端页面、数据库初始化代码或核心算法代码。

## 3. 合理修改

- `src/security/slow_api.py` 新增 `SlowAPIDetector` 和 `SlowAPILogger`，职责清晰，只做耗时判断和 JSON Lines 文件日志。
- `src/security/middleware.py` 在 `after_request` 中调用 `report_if_slow`，保留 `X-Trace-Id` 和 `X-Response-Time-Ms`。
- `config/security.yaml` 增加 `slow_api.log_path: data/logs/slow_api.log`，`enabled: true`，默认阈值 `threshold_ms: 1000`。
- `tests/test_slow_api.py` 覆盖 logger 写入、多线程写入、阈值以上写入、阈值以下不写、disabled 不写、计时 helper。

## 4. 可疑修改

- `docs/CLAUDE_IMPLEMENTATION_TASKS.md` 没有追加 Task 2 完成状态。
- `docs/REVIEW_CHECKLIST.md` 没有补充 slow_api 审核点。
- `tests/test_slow_api.py` 的 Flask 集成测试默认跳过，必须设置 `FLASK_TEST=1` 才会导入真实 app。
- Flask 集成测试中的 `test_slow_api_disabled_does_not_write` 实际没有切换 `slow_api.enabled=false`，主要验证的是默认阈值下快请求不写入；真正的 disabled 行为由 `SlowAPIDetector` 单元测试覆盖。

这些问题不影响运行，不构成返工阻断。

## 5. 必须修复的问题

本次没有发现必须修复的问题。

验证过程中临时把 `config/security.yaml` 的 `threshold_ms` 改为 `1` 和 `0` 用于触发日志，验证结束后已恢复为 `1000`。临时写入造成的 BOM/空行 diff 已恢复，没有进入提交。

## 6. 建议优化的问题

- 后续可增强 `tests/test_slow_api.py`，用临时 config 或注入 middleware 实例真实验证 `enabled=false` 下不会写 `slow_api.log`。
- 可补充 404 慢接口日志测试，确认异常响应也能保留响应头并写入 trace_id。
- 文档应补充 Task 2 完成状态和 slow_api 审核点，但不建议把未完成的限流、防重放、签名等写成已完成。

## 7. 实际运行验证结果

编译：

- `python -m py_compile app.py src/**/*.py`：通过。

unittest：

- `python -m unittest tests.test_slow_api -v`：通过，10 个测试中 7 个通过，3 个 Flask 集成测试按设计跳过。
- `FLASK_TEST=1 python -m unittest tests.test_slow_api -v`：通过，10 个测试全部通过。

真实服务：

- `python app.py`：可以启动，监听 `http://127.0.0.1:5000`。

HTTP 验证：

| 请求 | 状态码 | X-Trace-Id | X-Response-Time-Ms |
| --- | --- | --- | --- |
| `GET /api/system/health` | 200 | 有 | 有 |
| `GET /` | 200 | 有 | 有 |
| `GET /not-exist-page` | 404 | 有 | 有 |
| `GET /api/system/health` with `X-Trace-Id: codex-slow-api-test` and `threshold_ms: 0` | 200 | `codex-slow-api-test` | 有 |

慢接口日志验证：

- 临时设置 `slow_api.threshold_ms: 0` 后，请求 `/api/system/health` 成功写入 `data/logs/slow_api.log`。
- 日志为 JSON Lines，一行一条记录。
- 指定记录包含：
  - `trace_id: codex-slow-api-test`
  - `path: /api/system/health`
  - `method: GET`
  - `status_code: 200`
  - `duration_ms`
  - `ip`
  - `user_agent`
  - `timestamp`

配置恢复：

- 验证后 `config/security.yaml` 已恢复为 `threshold_ms: 1000`。

## 8. slow_api 功能完成度

完成度：约 90%。

已满足：

- 从 `config/security.yaml` 读取 `slow_api` 配置。
- `enabled=true` 时启用慢接口日志。
- `enabled=false` 时 detector 不写日志。
- `threshold_ms` 生效。
- 超过阈值写入 `data/logs/slow_api.log`。
- 低于阈值不写日志。
- JSON Lines 日志格式。
- 日志包含 trace_id、path、method、status_code、duration_ms、ip、user_agent、timestamp。
- 日志目录不存在时自动创建。
- 日志写入失败不会影响主请求。
- 不拦截请求，不返回 429。
- 保留 `X-Trace-Id` 和 `X-Response-Time-Ms`。
- `/api/system/health` 和 `/` 正常返回 200。
- 404 响应保留 TraceId 和响应耗时头。

待加强：

- Flask 集成测试对 `enabled=false` 的覆盖不够直接。
- 文档未追加 Task 2 完成状态。

## 9. 是否影响旧功能

未发现影响旧功能：

- 首页 `/` 正常返回 200。
- `/api/system/health` 正常返回 200。
- 404 页面正常返回 404，且保留 TraceId/耗时头。
- 未修改数据库结构。
- 未修改现有检测、加密、优化、联邦学习核心逻辑。

禁止项检查：

- 限流：未实现，未启用，未返回 429。
- 防重放：未实现，未启用。
- 参数签名：未实现，未启用。
- IP 黑白名单：未实现，未启用。
- API 开关：未实现，未启用。
- Kitsune-lite / LUCID-lite / Benchmark / 报告导出：未由 Task 2 实现或启用。
- 数据库结构：未修改。

## 10. 是否建议进入 Task 3

可以进入 Task 3。

前提：

- 不把当前工作区未提交的二期骨架、生成数据、本地设置混入 Task 3。
- Task 3 仍需保持默认不影响旧 API 和旧页面。

## 11. Task 3 推荐做什么

Task 3 推荐实现“接口限流 Rate Limit”的最小闭环，但必须谨慎：

- 默认 `rate_limit.enabled: false`，不影响演示。
- 先做内存计数器或轻量 SQLite 日志设计，不引入 Redis 等重型依赖。
- 只在配置显式开启时才可能拦截。
- 拦截响应格式必须和现有 API 风格一致，并保留 `X-Trace-Id`。
- 必须有测试覆盖：关闭不拦截、开启后超限、窗口重置、日志失败不影响非限流请求。

