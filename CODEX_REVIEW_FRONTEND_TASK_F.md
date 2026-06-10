# CODEX Review: Frontend Task F

审查对象：前端重构 Task F，只整理“安全防护”页面说明和看板文案  
Claude 提交：`7bf8626 docs(ui): clarify security dashboard page`  
审查结论：可以合并

## 1. 是否可以合并

可以合并。

Claude 本次提交只修改了 `index.html`，未修改 `app.py`、`src/**`、`config/**`、`tests/**`、`data/**`、`requirements.txt`，也未新增安全后端能力、前端框架、数据库或 API。

Codex 本次没有修改 `index.html`，仅新增本审核报告。

## 2. 本次修改文件清单

Claude 提交 `7bf8626`：

- `index.html`

Codex 本次新增审核报告：

- `CODEX_REVIEW_FRONTEND_TASK_F.md`

未纳入本次提交的既有无关工作区内容：

- `.claude/settings.local.json`
- `src/optimization/environment.py`
- `CURRENT_STATUS.md`
- `DEVELOPMENT_SUMMARY.md`
- `FRONTEND_PRESENTATION_REFACTOR_PLAN.md`
- `NEXT_TASKS_FOR_CODEX.md`
- `config/__init__.py`
- `config/detection.yaml`
- `config/federated.yaml`
- `config/report.yaml`
- `data/generated/`
- `data/models/`
- `data/system.db`
- `docs/`
- `scripts/`
- `src/benchmark/`
- `src/detection/`
- `src/federated/secure/`
- `src/reports/`
- `src/response/`
- `src/security/__init__.py`
- `src/security/anti_replay.py`
- `src/security/api_switch.py`
- `src/security/ip_filter.py`
- `src/security/sign_verify.py`

## 3. 合理修改

`pg-sec` 页面：

- 标题调整为“安全防护 — TraceId / 慢接口 / 限流 / 安全事件看板”。
- 新增说明：当前页面展示系统自身防护与可观测能力，不代表完整企业级安全运营平台。
- 新增流程：请求进入系统 -> TraceId 追踪 -> 慢接口/限流检测 -> 安全事件日志 -> 只读 API 查询 -> 看板展示。
- 统计卡片增加说明：
  - 事件总数：最近查询返回的事件数
  - 高风险：`risk_level: high`
  - 中风险：`risk_level: medium`
  - 低风险：`risk_level: low`
- 新增事件类型统计说明。
- 新增最近事件表字段说明。

## 4. 可疑修改

未发现可疑修改。

重点确认：

- `pg-sec` 页面 id 保留。
- `data-page="sec"` 保留。
- 安全事件统计卡片保留。
- 事件类型统计区域 `#secEventBreakdown` 保留。
- 最近事件表格 `#secTable` / `#secBody` 保留。
- 刷新按钮 `onclick="loadSec()"` 保留。
- 30 秒自动刷新逻辑 `ensureSecTimer()` / `setInterval` 保留。
- `GET /api/security/events/recent?limit=50` 调用保留。

## 5. 必须修复的问题

无必须修复问题。

本次未发现以下问题：

- 未把当前页面写成完整企业级安全运营平台。
- 未写成完整 WAF。
- 未写成全量攻击防护平台。
- 未声称已实现防重放、签名验签、IP 黑白名单或 API 开关。
- 未暗示系统可直接生产部署保护真实业务。

## 6. 建议优化的问题

- 当前 `secLow` 统计逻辑会把除 high/critical/medium 之外的事件都计入低风险，包括缺失 `risk_level` 的事件。该逻辑是既有行为，Task F 未修改。后续如要精确统计，需要单独任务审查。
- 后续 Task G 如新增实验报告页，应仍只改 `index.html`，不接入后端报告导出功能。

## 7. 实际运行验证结果

静态约束检查：

- 页面 id 均存在：
  - `pg-data`
  - `pg-ds`
  - `pg-train`
  - `pg-fed`
  - `pg-detect`
  - `pg-enc`
  - `pg-optim`
  - `pg-dash`
  - `pg-sec`
- `data-page` 集合前后一致：
  - `data`
  - `ds`
  - `train`
  - `fed`
  - `detect`
  - `enc`
  - `optim`
  - `dash`
  - `sec`
- `data-page="sec"` 保留。
- 安全防护相关函数均存在：
  - `loadSec`
  - `ensureSecTimer`
  - `esc`
- 其他原有函数均存在：
  - `genData`
  - `loadDS`
  - `procDS`
  - `buildTable`
  - `startTrain`
  - `loadTrainHist`
  - `loadFed`
  - `runFed`
  - `renderTrainChart`
  - `detSample`
  - `detFile`
  - `showDetRes`
  - `updEnc`
  - `loadOpt`
  - `toggleAuto`
  - `loadDash`
- `index.html` 中 API URL 集合前后一致，无删除、无新增、无改名。

安全防护页面元素检查：

- 安全事件统计卡片 `#secStats`：存在
- 事件总数 `#secTotal`：存在
- 高风险 `#secHigh`：存在
- 中风险 `#secMed`：存在
- 低风险 `#secLow`：存在
- 事件类型统计 `#secEventBreakdown`：存在
- 刷新按钮 `loadSec()`：存在
- 最近事件表格 `#secTable` / `#secBody`：存在
- 30 秒自动刷新逻辑：存在

已执行运行验证：

- `python -m py_compile app.py src/**/*.py`：通过
- `python app.py`：可以启动

真实 HTTP 验证：

| URL | 状态码 | X-Trace-Id | X-Response-Time-Ms | 说明 |
| --- | --- | --- | --- | --- |
| `/` | 200 | 有 | 有 | 页面包含 Task F 安全文案 |
| `/api/system/health` | 200 | 有 | 有 | 健康接口正常 |
| `/api/security/events/recent` | 200 | 有 | 有 | 安全事件接口正常 |

## 8. 是否影响旧功能

未发现影响旧功能。

本次没有修改后端、没有修改 API URL、没有修改 `data-page`、没有修改页面 id、没有修改 JS 函数名，也没有删除按钮或容器。安全事件看板的原有功能入口均保留。

## 9. 是否建议进入 Task G

建议先完成部署同步后再进入 Task G。

本地 Task A-F 已形成完整答辩展示链路，但公网页面仍显示旧版本时，继续开发会增加排查复杂度。应先确认远程仓库、服务器代码和 Flask 进程都已更新。

## 10. Task G 推荐做什么

Task G 推荐范围：

- 只修改 `index.html`。
- 新增静态“实验报告”页面。
- 不接入 `/api/export/report`。
- 不新增后端 API。
- 不修改 `app.py`、`src/**`、`config/**`、`tests/**`、`data/**`。
- 报告页应明确模块状态，不能把预留或模拟能力写成已完成生产能力。

