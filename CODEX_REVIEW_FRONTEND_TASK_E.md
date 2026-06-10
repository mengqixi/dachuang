# CODEX Review: Frontend Task E

审查对象：前端重构 Task E，只整理“加密对比 + 自适应优化”的展示逻辑  
Claude 提交：`6cacde5 docs(ui): clarify encryption comparison and adaptive optimization pages`  
审查结论：可以合并

## 1. 是否可以合并

可以合并。

Claude 本次提交只修改了 `index.html`，未修改 `app.py`、`src/**`、`config/**`、`tests/**`、`data/**`、`requirements.txt`，也未新增前端框架、后端 API、数据库或优化算法。

重点检查了 Claude 执行过程中出现过的 `String to replace not found in file` 风险：当前 `toggleAuto()` 按钮位置完整，未发现半截替换、误删、错改或未完成替换。

Codex 本次没有修改 `index.html`，仅新增本审核报告。

## 2. 本次修改文件清单

Claude 提交 `6cacde5`：

- `index.html`

Codex 本次新增审核报告：

- `CODEX_REVIEW_FRONTEND_TASK_E.md`

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

`pg-enc` 页面：

- 标题调整为“加密对比 — AES / Paillier 性能指标展示”。
- 新增说明：页面展示当前后端接口返回的 AES 与 Paillier 对比指标。
- 明确该页面用于答辩演示性能差异，不代表完整生产级密码学评测。
- 新增流程：样本数据 -> AES / Paillier 对比接口 -> 性能指标展示 -> 优化模块参考。
- 保留加密对比图表 `#encCh`、指标展示容器 `#encTB`、数据量选择 `#encSz` 和刷新按钮 `updEnc()`。

`pg-optim` 页面：

- 标题调整为“自适应优化 — Q-learning 参数调整流程展示”。
- 新增说明：页面通过后端接口展示 Q-learning / 自适应优化相关状态、推荐参数和历史记录。
- 明确该页面不代表完整生产级自动化安全策略平台。
- 新增流程：攻击风险输入 -> 系统状态评估 -> 参数调整策略 -> 加密强度/性能开销平衡 -> 优化历史记录。
- 将按钮文案从“自动优化”调整为“自动优化演示”，但保留 `onclick="toggleAuto()"`。
- 将“优化记录”标题调整为“参数调整历史”。

## 4. 可疑修改

未发现可疑修改。

重点确认：

- `pg-enc` 页面 id 保留。
- `pg-optim` 页面 id 保留。
- `data-page="enc"` 保留。
- `data-page="optim"` 保留。
- `updEnc()`、`loadOpt()`、`toggleAuto()` 函数均保留。
- `onclick="toggleAuto()"` 按钮仍存在。
- 未修改 `POST /api/compare_encryption`。
- 未修改 `GET /api/optimization/status`。
- 未修改 `GET /api/optimization/history`。
- 未修改 `POST /api/optimization/auto`。
- 未新增后端字段依赖。

## 5. 必须修复的问题

无必须修复问题。

本次未发现将 AES / Paillier 对比写成完整生产级密码学评测、将 Paillier 写成完整生产级安全聚合、将 Q-learning 写成生产级智能安全策略平台或暗示系统可直接生产部署的问题。

## 6. 建议优化的问题

- 当前页面仍保留 `pg-enc` 和 `pg-optim` 两个页面 id，这是符合 Task E 约束的。
- 后续如果真正合并两个页面，需要先设计兼容导航和初始化逻辑，避免破坏 `updEnc()` 与 `loadOpt()` 的懒加载。
- `toggleAuto()` 当前会每 2 秒调用 `/api/optimization/auto`，本次没有改动该行为。后续如做 UI 优化，应避免重复创建定时器或误触发请求风暴。

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
- `data-page="enc"` 保留。
- `data-page="optim"` 保留。
- 加密/优化相关函数均存在：
  - `updEnc`
  - `loadOpt`
  - `toggleAuto`
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
  - `loadDash`
  - `loadSec`
- `index.html` 中 API URL 集合前后一致，无删除、无新增、无改名。

页面元素检查：

- 加密对比图表 `#encCh`：存在
- AES / Paillier 指标容器 `#encTB`：存在
- 加密对比刷新按钮 `updEnc()`：存在
- 自适应优化风险条 `#oRB`：存在
- 当前密钥长度 `#oKL`：存在
- 当前轮数 `#oRR`：存在
- 性能增益 `#oG`：存在
- 优化历史表格 `#oTB`：存在
- 自动优化按钮 `toggleAuto()`：存在

已执行运行验证：

- `python -m py_compile app.py src/**/*.py`：通过
- `python app.py`：可以启动

真实 HTTP 验证：

| URL | 状态码 | X-Trace-Id | X-Response-Time-Ms | 说明 |
| --- | --- | --- | --- | --- |
| `/` | 200 | 有 | 有 | 页面包含加密对比和自适应优化文案 |
| `/api/system/health` | 200 | 有 | 有 | 健康接口正常 |
| `/api/security/events/recent` | 200 | 有 | 有 | 安全事件接口正常 |
| `/api/optimization/status` | 200 | 有 | 有 | 优化状态接口正常 |
| `/api/optimization/history` | 200 | 有 | 有 | 优化历史接口正常 |
| `/api/compare_encryption` | 200 | 有 | 有 | POST 返回 traditional / homomorphic 指标 |

说明：

- 当前会话未暴露可用 Browser 工具，因此浏览器点击和控制台检查无法自动执行。本次使用静态 DOM 映射、页面内容检查和真实 HTTP/API 调用替代。

## 8. 是否影响旧功能

未发现影响旧功能。

本次没有修改后端、没有修改 API URL、没有修改 `data-page`、没有修改页面 id、没有修改 JS 函数名，也没有删除按钮或容器。加密对比和自适应优化的原有功能入口均保留。

## 9. 是否建议进入 Task F

可以进入 Task F，但仍建议保持小步提交。

Task F 应只整理“安全防护”页面说明和看板文案，不要新增安全功能、不要修改安全后端、不要改变安全事件 API。

## 10. Task F 推荐做什么

Task F 推荐范围：

- 只修改 `index.html`。
- 保留 `pg-sec` 页面 id。
- 调整安全防护页面标题、说明文案、事件表格说明。
- 明确当前安全防护页展示的是 TraceId、慢接口、限流、安全事件日志和只读查询 API 的演示闭环。
- 不要新增防重放、签名、IP 黑白名单、API 开关。
- 保留以下函数：
  - `loadSec`
  - `ensureSecTimer`
  - `esc`
- 保留以下 API：
  - `GET /api/security/events/recent?limit=50`
- 禁止修改 `app.py`、`src/**`、`config/**`、`tests/**`、`data/**`。
- 禁止新增后端功能。

