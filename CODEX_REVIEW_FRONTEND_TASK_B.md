# CODEX Review: Frontend Task B

审查对象：前端重构 Task B，只合并“数据准备 + 数据集”为“数据处理”的展示逻辑，不真正合并页面 id  
Claude 提交：`0f4f630 docs(ui): clarify data processing and dataset pages`  
审查结论：小修后可以合并

## 1. 是否可以合并

可以合并。

Claude 本次提交只修改了 `index.html`，没有修改后端文件、配置文件、测试文件、数据文件或依赖文件。页面 id、`data-page`、JS 函数名、按钮事件和 API URL 均保持兼容。

Codex 做了两处必要小修：

- 将“Paillier 密态样本预览”改为“密态样本预览（Paillier/演示）”，避免在 Paillier 初始化失败回退 mock 时前端文案过度承诺。
- 将 UNSW-NB15 提示中的“4个联邦节点 / 真实攻击”改为“4个模拟联邦节点 / 公开攻击流量标签”，避免被理解成真实跨机构部署或自有业务数据。

## 2. 本次修改文件清单

Claude 提交 `0f4f630`：

- `index.html`

Codex 小修：

- `index.html`
- `CODEX_REVIEW_FRONTEND_TASK_B.md`

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

`pg-data` 页面：

- 标题从“数据处理 — 数据生成与密态加密”调整为“数据处理 — 数据生成与密态处理演示”。
- 新增说明文案，明确当前页面为演示流程，不代表完整生产级加密流水线。
- 新增流程说明：数据生成/加载 -> 密态处理 -> 联邦节点划分 -> 模型训练。
- “明文预览”改为“明文样本预览”。
- 密态预览标题经 Codex 小修为“密态样本预览（Paillier/演示）”。

`pg-ds` 页面：

- 标题从“数据集处理 — UNSW-NB15 真实攻击数据集”调整为“数据集处理 — UNSW-NB15 与联邦节点划分”。
- 新增说明文案，明确四个节点是模拟机构节点。
- 新增流程说明：原始数据 -> 特征提取(18维) -> 按类别分层抽样 -> 拆分为四个模拟机构节点 -> 各自本地训练。
- 公开数据集说明经 Codex 小修，避免将 UNSW-NB15 描述为自有真实业务数据。

## 4. 可疑修改

Claude 原始文案里有两处容易过强：

- “Paillier 密态样本预览”没有体现后端可能回退 mock。
- “拆分为4个联邦节点 / 真实攻击”容易被理解为真实跨机构部署或项目自有业务攻击数据。

这些已由 Codex 修复为更保守、适合答辩的表述。

未发现以下可疑改动：

- 未合并页面 id。
- 未删除页面块。
- 未删除按钮。
- 未删除 JS 函数。
- 未修改后端。
- 未新增前端框架。

## 5. 必须修复的问题

已修复：

- 文案真实性风险。

当前无阻断合并的问题。

## 6. 建议优化的问题

- Task B 仍只是展示逻辑整理，`pg-data` 和 `pg-ds` 仍是两个页面 id，这是符合本任务约束的。
- 后续如进入真正页面合并，需要先明确是否保留隐藏兼容页，避免破坏现有导航逻辑。
- 数据处理流程文案中提到“模型训练”，但本次没有进入训练页面合并；后续 Task C 再处理训练叙事。

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
- JS 函数均存在：
  - `genData`
  - `loadDS`
  - `procDS`
  - `buildTable`
  - `startTrain`
  - `loadTrainHist`
  - `loadFed`
  - `runFed`
  - `detSample`
  - `detFile`
  - `updEnc`
  - `loadOpt`
  - `toggleAuto`
  - `loadDash`
  - `loadSec`
- `index.html` 中 API URL 集合前后一致，无删除、无新增、无改名。
- 每个导航 `data-page` 均有对应 `pg-*` 页面。

数据处理页面元素检查：

- 记录数滑块 `#dc`：存在
- 加密算法选择 `#ea`：存在
- 生成按钮 `genData()`：存在
- 明文样本预览容器 `#pp`：存在
- 密态样本预览容器 `#ep`：存在
- 处理数据集+训练模型按钮 `procDS()`：存在
- 刷新状态按钮 `loadDS()`：存在
- 联邦节点容器 `#dsNodes`：存在

已执行运行验证：

- `python -m py_compile app.py src/**/*.py`：通过
- `python app.py`：可以启动

真实 HTTP 验证：

| URL | 状态码 | X-Trace-Id | X-Response-Time-Ms | 说明 |
| --- | --- | --- | --- | --- |
| `/` | 200 | 有 | 有 | 页面包含数据处理文案和四节点名称 |
| `/api/system/health` | 200 | 有 | 有 | 健康接口正常 |
| `/api/security/events/recent` | 200 | 有 | 有 | 安全事件接口正常 |
| `/api/federated/nodes` | 200 | 有 | 有 | 返回 hospital / bank / insurance / government |
| `/api/dataset/unsw/status` | 200 | 有 | 有 | 数据集状态接口正常 |

说明：

- 当前会话没有暴露可用 Browser 工具，Node 环境也没有 Playwright，因此浏览器点击和控制台检查使用静态 DOM 映射、页面内容检查和真实 HTTP 接口验证替代。

## 8. 是否影响旧功能

未发现影响旧功能。

本次没有修改后端、没有修改 API URL、没有修改 `data-page`、没有修改页面 id、没有修改 JS 函数名，也没有删除按钮或容器。数据处理和数据集处理相关入口均保留。

## 9. 是否建议进入 Task C

可以进入 Task C，但仍建议严格小步执行。

Task C 应只处理“模型训练 + 联邦学习”向“联邦训练”展示逻辑靠拢，不要同时修改攻击检测、自适应优化、安全防护或实验报告。

## 10. Task C 推荐做什么

Task C 推荐范围：

- 只修改 `index.html`。
- 保留 `pg-train` 和 `pg-fed` 页面 id，不真正合并页面 id。
- 调整模型训练与联邦训练页面标题、说明文案和流程文案。
- 明确联邦训练当前是演示/模拟流程，不要写成真实生产级跨机构系统。
- 保留以下函数：
  - `startTrain`
  - `loadTrainHist`
  - `loadFed`
  - `runFed`
  - `renderTrainChart`
- 保留以下 API：
  - `POST /api/train/dual`
  - `GET /api/train/history`
  - `GET /api/federated/nodes`
  - `POST /api/federated/round`
- 禁止修改 `app.py`、`src/**`、`config/**`、`tests/**`、`data/**`。
- 禁止新增后端功能。

