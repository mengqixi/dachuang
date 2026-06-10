# CODEX Review: Frontend Task D

审查对象：前端重构 Task D，只整理攻击检测页面说明和结果表格  
Claude 提交：`68004b6 docs(ui): clarify attack detection page`  
审查结论：可以合并

## 1. 是否可以合并

可以合并。

Claude 本次提交只修改了 `index.html`，未修改 `app.py`、`src/**`、`config/**`、`tests/**`、`data/**`、`requirements.txt`，也未新增前端框架、后端 API、数据库或检测器。

本次 Codex 未对 `index.html` 做代码小修。Claude 的文案整体符合 Task D 的真实性要求，明确使用了“当前接口返回”“演示流程”“项目计划中的多模型融合方向”“实际可运行能力以当前后端接口返回为准”等保守表述。

## 2. 本次修改文件清单

Claude 提交 `68004b6`：

- `index.html`

Codex 本次新增审核报告：

- `CODEX_REVIEW_FRONTEND_TASK_D.md`

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

`pg-detect` 页面：

- 页面标题从“三模型融合 (IF 0.3 + XGB 0.3 + LSTM 0.4)”调整为“攻击检测 — 后端接口驱动的风险评分演示”。
- 新增模块用途说明，明确页面展示的是攻击检测接口演示流程。
- 新增流程文案：样本输入 -> 特征解析 -> 后端检测接口 -> 风险评分 -> 风险等级 / 攻击类型。
- 新增检测逻辑说明框，明确 IF / XGBoost / LSTM 是项目计划中的多模型融合方向，实际能力以后端接口返回为准。
- 统计卡片增加说明：
  - 总记录：本次检测样本数
  - 异常数：高风险样本数
  - 平均置信度：接口返回均值
  - 耗时：检测接口耗时
- 表格说明新增：展示后端接口返回的风险分数、风险等级和攻击类型。
- 表头从 `# / 结果` 调整为 `序号 / 检测结果`，没有新增后端字段依赖。

## 4. 可疑修改

未发现可疑修改。

重点确认：

- 未修改 `pg-detect` 页面 id。
- 未修改 `data-page="detect"`。
- 未删除上传区域。
- 未删除内置样本检测按钮。
- 未删除统计卡片。
- 未删除结果表格。
- 未修改 `detSample`、`detFile`、`showDetRes` 函数名。
- 未修改 `POST /api/ensemble/detect` 和 `POST /upload` 调用路径。

## 5. 必须修复的问题

无必须修复问题。

本次未发现将当前接口输出夸大为真实在线流量检测系统、生产级三模型系统或完整安全态势感知系统的问题。

## 6. 建议优化的问题

- “异常数”副标题写为“高风险样本数”，而当前 JS 仍使用 `d.anomalies` 统计异常数。该差异不影响功能，但后续如进一步优化文案，可改为“异常或高风险样本数”以更贴近现有逻辑。
- 后续 Task D 之后不建议马上大改检测逻辑；如果要增强检测页面，应先由 Codex 审查后端实际检测能力，再决定是否调整模型表述。

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
- `data-page="detect"` 保留。
- 攻击检测相关函数均存在：
  - `detSample`
  - `detFile`
  - `showDetRes`
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
  - `updEnc`
  - `loadOpt`
  - `toggleAuto`
  - `loadDash`
  - `loadSec`
- `index.html` 中 API URL 集合前后一致，无删除、无新增、无改名。

攻击检测页面元素检查：

- 上传 CSV/JSON 区域：存在
- 文件输入 `#detF`：存在
- 内置样本检测按钮 `detSample()`：存在
- 总记录统计卡片 `#detT`：存在
- 异常数统计卡片 `#detA`：存在
- 平均置信度统计卡片 `#detConf`：存在
- 耗时统计卡片 `#detTim`：存在
- 结果表格 `#detTB`：存在

已执行运行验证：

- `python -m py_compile app.py src/**/*.py`：通过
- `python app.py`：可以启动

真实 HTTP 验证：

| URL | 状态码 | X-Trace-Id | X-Response-Time-Ms | 说明 |
| --- | --- | --- | --- | --- |
| `/` | 200 | 有 | 有 | 页面包含攻击检测文案 |
| `/api/system/health` | 200 | 有 | 有 | 健康接口正常 |
| `/api/security/events/recent` | 200 | 有 | 有 | 安全事件接口正常 |
| `/api/ensemble/detect` | 200 | 有 | 有 | POST 小样本后返回 detections |

说明：

- 当前会话未暴露可用 Browser 工具，因此浏览器点击和控制台检查无法自动执行。本次使用静态 DOM 映射、页面内容检查和真实 HTTP 接口调用替代。

## 8. 是否影响旧功能

未发现影响旧功能。

本次没有修改后端、没有修改 API URL、没有修改 `data-page`、没有修改页面 id、没有修改 JS 函数名，也没有删除按钮或容器。攻击检测页面的原有功能入口均保留。

## 9. 是否建议进入 Task E

可以进入 Task E，但建议继续保持小步提交。

Task E 只应整理“加密对比 + 自适应优化”的展示逻辑，不要同时新增实验报告页、安全功能或后端能力。

## 10. Task E 推荐做什么

Task E 推荐范围：

- 只修改 `index.html`。
- 保留 `pg-enc` 和 `pg-optim` 页面 id，不真正合并页面 id。
- 调整加密对比和自适应优化页面标题、说明文案和流程文案。
- 明确 AES / Paillier 对比指标来自当前后端接口返回，不写成完整生产级加密评测。
- 明确 Q-learning / 自适应优化是当前系统展示的参数调整流程，不写成完整生产级自动化安全策略平台。
- 保留以下函数：
  - `updEnc`
  - `loadOpt`
  - `toggleAuto`
- 保留以下 API：
  - `POST /api/compare_encryption`
  - `GET /api/optimization/status`
  - `GET /api/optimization/history`
  - `POST /api/optimization/auto`
- 禁止修改 `app.py`、`src/**`、`config/**`、`tests/**`、`data/**`。
- 禁止新增后端功能。

