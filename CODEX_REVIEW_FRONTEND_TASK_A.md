# CODEX Review: Frontend Task A

审查对象：前端重构 Task A，只改导航名称和页面标题，不动功能  
Claude 提交：`7702f5c docs(ui): clarify navigation and page titles for presentation flow`  
审查结论：小修后可以合并

## 1. 是否可以合并

可以合并。

Claude 的提交范围符合 Task A：只修改了 `index.html`，没有修改 `app.py`、`src/**`、`config/**`、`tests/**`、`data/**`、`requirements.txt`，也没有新增前端框架或后端 API。

Codex 做了必要小修：将部分新增说明文案降级为更诚实的“演示 / 当前接口输出 / 当前后端返回”表述，避免把模拟联邦、Paillier 流程、AES/Paillier 指标或 Q-learning 优化写成完整生产级实现。

## 2. 本次修改文件清单

Claude 提交 `7702f5c`：

- `index.html`

Codex 小修：

- `index.html`
- `CODEX_REVIEW_FRONTEND_TASK_A.md`

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

导航文案调整更适合答辩展示：

- `数据准备` -> `数据处理`
- `数据集` -> `数据集处理`
- `联邦学习` -> `联邦训练`
- `数据看板` -> `总览`
- `安全` -> `安全防护`

页面标题和说明文案调整方向合理：

- 数据处理页强调数据生成、密态处理和联邦节点划分。
- 数据集处理页强调 UNSW-NB15 数据集处理和节点划分。
- 模型训练页强调传统训练和联邦训练对比。
- 联邦训练页强调多机构联合训练流程。
- 攻击检测页强调风险评分、风险等级和攻击类型。
- 加密对比页强调当前后端返回的对比指标。
- 自适应优化页强调风险和开销驱动的参数调整过程。
- 安全防护页强调 TraceId、慢接口、限流和安全事件日志闭环。

## 4. 可疑修改

Claude 原始新增文案中有几处表述偏强，容易被理解为完整真实实现：

- “通过 Paillier 加密和 FedAvg 聚合形成全局模型”
- “Paillier加密梯度”
- “融合 Isolation Forest、XGBoost 和 LSTM 三种模型”
- “对比 AES 与 Paillier 在加密时间、解密时间、吞吐量、安全性方面的差异”
- “通过 Q-learning 强化学习动态调整密钥长度和加密轮数”

这些已由 Codex 小修为更保守表述。

## 5. 必须修复的问题

已修复：

- 新增说明文案的真实性风险。

未发现以下阻断问题：

- 未删除页面块。
- 未删除按钮。
- 未删除 JS 函数。
- 未删除或改名 API 调用。
- 未修改 `data-page`。
- 未修改页面 id。
- 未修改 JS 函数名。
- 未修改 fetch/XMLHttpRequest URL。

## 6. 建议优化的问题

- Task A 只完成信息架构的第一层文案优化，还没有真正按答辩流程合并页面。
- 当前导航仍有 9 个页签，距离最终推荐的 7 个演示页还有 Task B/C/E/G 等后续工作。
- 后续页面合并必须继续按小任务推进，不要一次性重写 `index.html`。
- 当前会话未暴露可用 Browser 工具，Node 环境也没有 Playwright，因此浏览器点击和控制台检查使用静态 DOM 映射检查替代。

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
- JS 函数均存在：
  - `genData`
  - `loadDS`
  - `procDS`
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
- 每个导航 `data-page` 均有对应 `pg-*` 页面。
- 所有原 `onclick` 处理器前后一致。
- `index.html` 中 API URL 集合前后一致，无删除、无新增、无改名。

已执行运行验证：

- `python -m py_compile app.py src/**/*.py`：通过
- `python app.py`：可以启动

真实 HTTP 验证：

| URL | 状态码 | X-Trace-Id | X-Response-Time-Ms |
| --- | --- | --- | --- |
| `/` | 200 | 有 | 有 |
| `/api/system/health` | 200 | 有 | 有 |
| `/api/security/events/recent` | 200 | 有 | 有 |

说明：

- `/api/system/health` 是后端健康检查接口，不是 `index.html` 内已有前端 API 字符串，因此不在前端 URL 集合中出现；本次已通过真实 HTTP 验证。

## 8. 是否影响旧功能

未发现影响旧功能。

本次修改没有触碰后端，也没有改变页面 id、函数名、按钮事件、API URL 和导航 `data-page`。从静态结构和真实 HTTP 验证看，旧功能入口仍保留。

## 9. 是否建议进入 Task B

可以进入 Task B，但建议仍保持严格小步提交。

Task B 应只做“数据准备 + 数据集”合并为“数据处理”，不要同时合并训练、优化或新增实验报告页。

## 10. Task B 推荐做什么

Task B 推荐范围：

- 只修改 `index.html`。
- 合并 `pg-data` 和 `pg-ds` 的视觉展示为“数据处理”页。
- 保留原页面 id 或使用兼容方式，避免破坏导航切换。
- 保留 `genData()`、`buildTable()`、`loadDS()`、`procDS()`。
- 保留以下 API 调用：
  - `POST /api/generate_dataset`
  - `GET /api/dataset/unsw/status`
  - `GET /api/federated/nodes`
  - `POST /api/dataset/unsw/process`
- 不修改 `app.py`、`src/**`、`config/**`、`tests/**`、`data/**`。
- 不新增后端功能。

