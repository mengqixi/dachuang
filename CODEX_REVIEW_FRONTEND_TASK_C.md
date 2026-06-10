# CODEX Review: Frontend Task C

审查对象：前端重构 Task C，整理“模型训练 + 联邦学习”为“联邦训练”的展示逻辑  
Claude 提交：`bed25d0 docs(ui): clarify training and federated learning pages`  
审查结论：小修后可以合并

## 1. 是否可以合并

可以合并。

Claude 的提交只修改了 `index.html`，没有修改后端、配置、测试、数据或依赖文件。页面 id、`data-page`、JS 函数名、按钮事件和 API URL 均保持兼容。

Codex 做了一处必要小修：

- 将训练结果动态说明从“联邦训练在几乎不损失精度前提下保证数据隐私”改为“当前结果用于演示传统训练与联邦训练的指标对比，不代表生产级隐私保护结论”。

该修复避免把模拟/演示性联邦训练写成确定的生产级隐私保护结论。

## 2. 本次修改文件清单

Claude 提交 `bed25d0`：

- `index.html`

Codex 小修：

- `index.html`
- `CODEX_REVIEW_FRONTEND_TASK_C.md`

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

`pg-train` 页面：

- 标题调整为“模型训练 — 本地攻击检测模型训练演示”。
- 新增说明：当前页面展示系统接口返回的训练结果，不代表完整生产级模型训练平台。
- 新增流程说明：训练数据 -> 本地模型训练 -> 精度记录 -> 训练历史保存。
- 将训练配置、训练结果、训练历史标题加上“本地”语义，符合 Task C 的展示目标。

`pg-fed` 页面：

- 标题调整为“联邦训练 — 四节点联合训练演示”。
- 明确 Hospital、Bank、Insurance、Government 是模拟节点。
- 明确当前是单机模拟联邦训练流程，不代表真实生产级跨机构部署。
- 将 FedAvg 和 Paillier/密态聚合描述为“演示 / 预留能力”，符合真实性要求。
- 保留节点卡片、轮次输入、执行一轮、刷新、联邦精度曲线和训练详情区域。

## 4. 可疑修改

Claude 原始变更整体克制，但 `startTrain()` 的动态训练结果里仍保留了一句旧文案：

- “联邦训练在几乎不损失精度前提下保证数据隐私”

该文案与 Task C 的真实性要求不完全一致，已由 Codex 修复。

未发现以下可疑改动：

- 未删除页面块。
- 未删除按钮。
- 未删除 JS 函数。
- 未修改页面 id。
- 未修改 `data-page`。
- 未修改 API URL。
- 未新增前端框架。
- 未修改后端文件。

## 5. 必须修复的问题

已修复：

- 联邦训练结果动态说明过度承诺隐私保护和精度保持的问题。

当前无阻断合并的问题。

## 6. 建议优化的问题

- Task C 仍是展示逻辑整理，`pg-train` 和 `pg-fed` 页面 id 没有真正合并，这是符合本任务约束的。
- 后续如继续优化，可以把“模型训练”导航名称保留为本地基线训练，把“联邦训练”作为独立演示页，不建议强行合并为一个复杂页面。
- 当前 `runFed()` 的结果表格仍会展示 “FedAvg聚合”，这与当前后端接口演示一致；但后续不要扩写为真实多节点通信。

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
- 训练/联邦相关函数均存在：
  - `startTrain`
  - `loadTrainHist`
  - `loadFed`
  - `runFed`
  - `renderTrainChart`
- 其他原有函数均存在：
  - `genData`
  - `loadDS`
  - `procDS`
  - `buildTable`
  - `detSample`
  - `detFile`
  - `updEnc`
  - `loadOpt`
  - `toggleAuto`
  - `loadDash`
  - `loadSec`
- `index.html` 中 API URL 集合前后一致，无删除、无新增、无改名。
- 每个导航 `data-page` 均有对应 `pg-*` 页面。

训练页面元素检查：

- `#pg-train`：存在
- 轮次输入框 `#trE`：存在
- 开始训练按钮 `startTrain()`：存在
- 训练历史按钮 `loadTrainHist()`：存在
- 训练曲线 `#trCh`：存在
- 训练结果 `#trRes`：存在
- 训练历史表格 `#trHistTB`：存在

联邦训练页面元素检查：

- `#pg-fed`：存在
- 节点卡片容器 `#fedNodes`：存在
- 本地轮次输入框 `#fedE`：存在
- 执行一轮按钮 `runFed()`：存在
- 刷新按钮 `loadFed()`：存在
- 联邦精度曲线 `#fedCh`：存在
- 训练详情 `#fedDet`：存在

已执行运行验证：

- `python -m py_compile app.py src/**/*.py`：通过
- `python app.py`：可以启动

真实 HTTP 验证：

| URL | 状态码 | X-Trace-Id | X-Response-Time-Ms | 说明 |
| --- | --- | --- | --- | --- |
| `/` | 200 | 有 | 有 | 页面包含模型训练、联邦训练和四节点名称 |
| `/api/system/health` | 200 | 有 | 有 | 健康接口正常 |
| `/api/security/events/recent` | 200 | 有 | 有 | 安全事件接口正常 |
| `/api/federated/nodes` | 200 | 有 | 有 | 返回 hospital / bank / insurance / government |
| `/api/train/history` | 200 | 有 | 有 | 训练历史接口正常 |

说明：

- 当前会话没有暴露可用 Browser 工具，Node 环境也没有 Playwright，因此浏览器点击和控制台检查使用静态 DOM 映射、页面内容检查和真实 HTTP 接口验证替代。

## 8. 是否影响旧功能

未发现影响旧功能。

本次没有修改后端、没有修改 API URL、没有修改 `data-page`、没有修改页面 id、没有修改 JS 函数名，也没有删除按钮或容器。模型训练和联邦训练相关入口均保留。

## 9. 是否建议进入 Task D

可以进入 Task D，但仍建议严格小步执行。

Task D 应只整理“攻击检测”页面说明和结果表格，不要同时处理加密对比、自适应优化、安全防护或实验报告。

## 10. Task D 推荐做什么

Task D 推荐范围：

- 只修改 `index.html`。
- 保留 `pg-detect` 页面 id，不真正合并页面。
- 调整攻击检测页面标题、说明文案和结果表格说明。
- 明确当前页面展示的是后端攻击检测接口输出，不要把 IF/XGB/LSTM 写成全部已完成生产级模型。
- 保留以下函数：
  - `detSample`
  - `detFile`
  - `showDetRes`
- 保留以下 API：
  - `POST /api/ensemble/detect`
  - `POST /upload`
- 禁止修改 `app.py`、`src/**`、`config/**`、`tests/**`、`data/**`。
- 禁止新增后端功能。

