# 前端答辩展示重构方案

审查范围：

- 根目录 `index.html`
- `app.py` 中与前端页面和前端 API 调用相关的路由
- `templates/index.html`
- `static/` 目录

审查结论：

- 当前 Flask 首页实际由 `app.py` 的 `/` 路由返回根目录 `index.html`。
- 项目没有 `static/` 目录，当前前端 CSS/JS 基本都内联在根目录 `index.html`。
- `templates/index.html` 存在，但当前主入口没有使用它，本次重构不要误改为主页面。
- 当前前端功能可运行，但页面顺序更像“功能列表”，不适合作为大创答辩的技术路线演示。
- 推荐将页面从 9 个功能页签整理为 7 个演示流程页签，但必须分小任务逐步实施，不要一次性重写。

## 一、当前前端问题

### 1. 导航逻辑问题

当前导航顺序：

1. 数据准备
2. 数据集
3. 模型训练
4. 联邦学习
5. 攻击检测
6. 加密对比
7. 自适应优化
8. 数据看板
9. 安全

问题：

- “数据看板”放在靠后位置，但答辩时总览应该首先出现。
- “数据准备”和“数据集”语义接近，当前拆成两个页面后，演示者需要来回解释两套数据入口。
- “模型训练”和“联邦学习”属于同一条训练路线，当前分离后叙事断裂。
- “加密对比”和“自适应优化”都服务于安全计算与动态优化，可以合并成一个技术亮点页。
- “安全”是 Task 1-6 的安全防护闭环，但当前名称偏短，答辩时不容易体现 TraceId、慢接口、限流、安全事件、看板的完整链路。

### 2. 页面重复问题

可合并页面：

- `pg-data` 数据生成与加密预览 + `pg-ds` UNSW-NB15 数据集处理，可以合并为“数据处理”。
- `pg-train` 模型训练 + `pg-fed` 联邦学习 4 节点，可以合并为“联邦训练”。
- `pg-enc` AES/Paillier 加密对比 + `pg-optim` 自适应优化，可以合并为“自适应优化”。
- `pg-dash` 数据看板应前移为“总览”。
- `pg-sec` 安全事件看板应保留为“安全防护”。

不建议合并页面：

- `pg-detect` 攻击检测需要独立保留，因为它是项目核心业务能力之一。
- 新增“实验报告”应是静态总结页，不应混入真实训练/检测按钮，避免答辩时误触发耗时流程。

### 3. 页面空白问题

当前多个页面依赖接口返回或用户点击后才有内容：

- `pg-train` 初始只显示配置、空图表和训练历史。
- `pg-fed` 初始需要 `loadFed()` 填充节点。
- `pg-optim` 初始需要 `loadOpt()` 才有状态和历史。
- `pg-sec` 无安全事件时只显示空状态。

建议：

- 每个页面顶部增加一句“本页演示什么”的短说明。
- 空表格必须显示明确空状态。
- 指标卡片默认值保留 `--`，但需要有说明标签。
- 实验报告页用静态内容兜底，保证答辩时即使接口没有数据也能讲清技术路线。

### 4. 答辩叙事不清问题

当前页面没有形成完整技术路线：

数据来源 -> 数据处理 -> 联邦训练 -> 攻击检测 -> 加密与自适应优化 -> 安全防护 -> 实验结果

建议新前端围绕这条路线组织，而不是围绕代码模块或 API 名称组织。

## 二、推荐新导航

| 新导航 | 对应原页面 | 页面用途 | 答辩时怎么讲 |
| --- | --- | --- | --- |
| 总览 | `pg-dash` | 先给出系统整体状态、检测率、攻击风险、优化收益 | “这是系统当前整体运行态，包含攻击风险、检测率和优化收益。” |
| 数据处理 | `pg-data` + `pg-ds` | 展示合成数据、加密预览、UNSW-NB15 数据集处理和联邦节点拆分 | “先从数据进入系统，既支持演示用合成数据，也预留真实攻击流量数据集处理。” |
| 联邦训练 | `pg-train` + `pg-fed` | 展示传统训练、联邦训练、节点状态、FedAvg 聚合结果 | “训练环节分为本地模型训练和多机构联邦训练，强调数据不出域。” |
| 攻击检测 | `pg-detect` | 展示上传检测、内置样本检测、风险分数和攻击类型 | “训练后的检测能力用于识别异常流量和攻击行为。” |
| 自适应优化 | `pg-enc` + `pg-optim` | 展示 AES/Paillier 对比、自适应参数调整、优化记录 | “系统在安全计算和性能之间动态调整，体现自适应安全策略。” |
| 安全防护 | `pg-sec` | 展示 TraceId、慢接口、限流、安全事件日志和看板 | “这是二期安全防护闭环，所有安全事件可追踪、可查询、可展示。” |
| 实验报告 | 新增 `pg-report` | 静态总结项目创新点、实验流程、指标和答辩演示步骤 | “最后用报告页收束项目成果和可验证指标。” |

## 三、每个页面应该展示什么

### 1. 总览

对应原页面：

- `pg-dash`

顶部说明文案：

- “系统总览展示攻击风险、检测效果、优化收益和运行趋势，用于答辩开场快速说明项目价值。”

指标卡片：

- 总攻击数：`#daA`
- 检测率：`#daR`
- 效率提升：`#daG`
- 安全等级：`#daL`

表格/图表：

- 攻击风险曲线：`#dmC`
- 系统性能曲线：`#dpC`

操作按钮：

- 时间范围选择：`#dR`

需要保留的原功能：

- `loadDash()`
- `renderDashCharts(recs)`

禁止删除的 API 调用：

- `GET /api/data/statistics`
- `GET /api/data/system_status?hours=...`

### 2. 数据处理

对应原页面：

- `pg-data`
- `pg-ds`

顶部说明文案：

- “数据处理页展示演示数据生成、加密预览、真实数据集处理和联邦节点拆分，是后续训练与检测的输入来源。”

指标卡片：

- 可保留或新增轻量展示：生成记录数、明文预览、密文预览、数据集状态、联邦节点数。

表格/图表：

- 明文预览：`#pp`
- 密文预览：`#ep`
- 联邦节点卡片：`#dsNodes`
- 数据集状态：`#dsInfo`

操作按钮：

- 生成：`genData()`
- 处理数据集+训练模型：`procDS()`
- 刷新状态：`loadDS()`

需要保留的原功能：

- `genData()`
- `buildTable(data)`
- `loadDS()`
- `procDS()`
- 数据量滑块 `#dc`
- 加密算法选择 `#ea`

禁止删除的 API 调用：

- `POST /api/generate_dataset`
- `GET /api/dataset/unsw/status`
- `GET /api/federated/nodes`
- `POST /api/dataset/unsw/process`

注意：

- `procDS()` 当前会自动切到联邦学习页。合并后可以改为切到“联邦训练”，但不要删除跳转逻辑。

### 3. 联邦训练

对应原页面：

- `pg-train`
- `pg-fed`

顶部说明文案：

- “联邦训练页展示传统训练结果、联邦节点本地训练、FedAvg 聚合和训练历史，用于说明数据不出域的协同建模流程。”

指标卡片：

- 训练轮次
- 传统模型精度
- 联邦模型精度
- 节点数量
- 样本数量

表格/图表：

- 训练曲线：`#trCh`
- 训练结果：`#trRes`
- 训练历史：`#trHistTB`
- 节点卡片：`#fedNodes`
- 联邦结果：`#fedRes`
- 联邦曲线：`#fedCh`
- 训练详情：`#fedDet`

操作按钮：

- 开始训练：`startTrain()`
- 训练历史：`loadTrainHist()`
- 执行一轮：`runFed()`
- 刷新联邦节点：`loadFed()`

需要保留的原功能：

- `startTrain()`
- `renderTrainChart(d1, d2)`
- `loadTrainHist()`
- `loadFed()`
- `runFed()`

禁止删除的 API 调用：

- `POST /api/train/dual`
- `GET /api/train/history`
- `GET /api/federated/nodes`
- `POST /api/federated/round`

注意：

- 不要在本轮重构中改动联邦学习后端实现。
- 不要把“模拟联邦学习”写成“真实多节点通信”。

### 4. 攻击检测

对应原页面：

- `pg-detect`

顶部说明文案：

- “攻击检测页展示多模型融合检测结果，支持内置样本和上传 CSV/JSON，用于验证系统对异常流量的识别能力。”

指标卡片：

- 总记录：`#detT`
- 异常数：`#detA`
- 平均置信度：`#detConf`
- 耗时：`#detTim`

表格/图表：

- 检测结果表格：`#detTB`

操作按钮：

- 上传 CSV/JSON：`detFile(inp)`
- 内置样本检测：`detSample()`

需要保留的原功能：

- `detSample()`
- `detFile(inp)`
- `showDetRes(d, time)`

禁止删除的 API 调用：

- `POST /api/ensemble/detect`
- `POST /upload`

注意：

- 页面标题可以更稳妥地写成“多模型融合攻击检测”，不要在前端标题中夸大未完全真实训练的模型状态。

### 5. 自适应优化

对应原页面：

- `pg-enc`
- `pg-optim`

顶部说明文案：

- “自适应优化页展示加密算法性能对比和系统根据风险动态调整密钥长度、轮数等参数的过程。”

指标卡片：

- 当前攻击风险
- 当前密钥长度：`#oKL`
- 当前轮数：`#oRR`
- 性能增益：`#oG`

表格/图表：

- AES-256 vs Paillier 曲线：`#encCh`
- 加密对比表：`#encTB`
- 优化记录表：`#oTB`
- 攻击风险进度条：`#oRB`

操作按钮：

- 刷新加密对比：`updEnc()`
- 自动优化：`toggleAuto()`

需要保留的原功能：

- `updEnc()`
- `loadOpt()`
- `toggleAuto()`

禁止删除的 API 调用：

- `POST /api/compare_encryption`
- `GET /api/optimization/status`
- `GET /api/optimization/history`
- `POST /api/optimization/auto`

注意：

- 不要把 AES 性能估算写成真实加密全流程。
- 不要把 Paillier 展示写成真实联邦梯度加密，除非后端已被 Codex 单独审计确认。

### 6. 安全防护

对应原页面：

- `pg-sec`

顶部说明文案：

- “安全防护页展示 TraceId 请求追踪、慢接口检测、接口限流和安全事件日志形成的可观测闭环。”

指标卡片：

- 事件总数：`#secTotal`
- 高风险数：`#secHigh`
- 中风险数：`#secMed`
- 低风险数：`#secLow`

表格/图表：

- 事件类型统计：`#secEventBreakdown`
- 最近事件表格：`#secBody`

操作按钮：

- 刷新：`loadSec()`

需要保留的原功能：

- `loadSec()`
- `ensureSecTimer()`
- `esc(s)`

禁止删除的 API 调用：

- `GET /api/security/events/recent?limit=50`

注意：

- 该页只读展示，不允许新增写接口、删除日志接口或安全开关操作入口。
- 不要继续实现防重放、签名、IP 黑白名单、API 开关。

### 7. 实验报告

对应原页面：

- 新增 `pg-report`

顶部说明文案：

- “实验报告页汇总项目技术路线、核心能力、实验指标、演示步骤和后续工作，用于答辩收尾。”

指标卡片：

- 数据处理：合成数据 + UNSW-NB15 预留
- 训练方式：传统训练 + 联邦训练
- 检测能力：多模型融合攻击检测
- 安全能力：TraceId + 慢接口 + 限流 + 安全事件

表格/图表：

- 建议使用静态表格，不依赖新后端接口：
  - 技术模块
  - 当前状态
  - 可演示功能
  - 风险说明

操作按钮：

- 可以只提供“刷新总览”或“返回总览”，不新增后端操作。

需要保留的原功能：

- 无需新增业务函数。
- 可复用已有导航逻辑。

禁止删除的 API 调用：

- 不涉及新增 API。
- 不允许删除任何现有 API 调用。

注意：

- 实验报告页应该是静态答辩总结页，不要实现真实报告导出。
- 后端已有 `/api/export/report`，但本阶段不要把它接入为新功能，避免扩大范围。

## 四、当前页面、按钮、JS 函数、API 调用梳理

### 当前页面

| 页面 ID | 当前导航 | 建议归属 |
| --- | --- | --- |
| `pg-data` | 数据准备 | 数据处理 |
| `pg-ds` | 数据集 | 数据处理 |
| `pg-train` | 模型训练 | 联邦训练 |
| `pg-fed` | 联邦学习 | 联邦训练 |
| `pg-detect` | 攻击检测 | 攻击检测 |
| `pg-enc` | 加密对比 | 自适应优化 |
| `pg-optim` | 自适应优化 | 自适应优化 |
| `pg-dash` | 数据看板 | 总览 |
| `pg-sec` | 安全 | 安全防护 |
| 新增 | 无 | 实验报告 |

### 当前按钮与事件

- `genData()`：生成数据。
- `procDS()`：处理 UNSW-NB15 数据集并训练模型。
- `loadDS()`：刷新数据集状态。
- `startTrain()`：启动双模式训练。
- `loadTrainHist()`：刷新训练历史。
- `runFed()`：执行一轮联邦训练。
- `loadFed()`：刷新联邦节点。
- `detSample()`：内置样本检测。
- `detFile(this)`：上传文件检测。
- `updEnc()`：刷新加密对比。
- `toggleAuto()`：开启/关闭自动优化。
- `loadDash()`：刷新总览看板。
- `loadSec()`：刷新安全事件看板。

### 当前前端 API 调用

- `POST /api/generate_dataset`
- `GET /api/dataset/unsw/status`
- `GET /api/federated/nodes`
- `POST /api/dataset/unsw/process`
- `POST /api/train/dual`
- `GET /api/train/history`
- `POST /api/federated/round`
- `POST /api/ensemble/detect`
- `POST /upload`
- `POST /api/compare_encryption`
- `GET /api/optimization/status`
- `GET /api/optimization/history`
- `POST /api/optimization/auto`
- `GET /api/data/statistics`
- `GET /api/data/system_status?hours=...`
- `GET /api/security/events/recent?limit=50`

这些调用在重构过程中禁止删除。可以移动到新的页面结构中，但函数名和调用路径应优先保持不变。

## 五、Claude 后续实施任务拆分

### Task A：只改导航名称和页面标题，不动功能

允许修改文件：

- `index.html`

禁止修改文件：

- `app.py`
- `src/**`
- `config/**`
- `tests/**`
- `data/**`

不允许新增后端功能：

- 不新增 Flask route。
- 不新增 API。
- 不改安全中间件。

不允许删除现有 API：

- 不删除任何 `get(...)` / `post(...)` 调用。

验收标准：

- `/` 能打开。
- 导航文字改为：总览、数据处理、联邦训练、攻击检测、自适应优化、安全防护、实验报告。
- 页面内部标题与新导航一致。
- 所有原按钮仍存在。
- 所有原 JS 函数仍存在。
- `/api/system/health` 和 `/api/security/events/recent` 正常。

Codex 审核重点：

- 是否只改文案和标题。
- 是否误删页面块。
- 是否误删 JS 函数。
- 是否改动后端。

### Task B：合并数据准备 + 数据集为“数据处理”

允许修改文件：

- `index.html`

禁止修改文件：

- `app.py`
- `src/**`
- `config/**`
- `tests/**`
- `data/**`

不允许新增后端功能：

- 不新增数据处理 API。
- 不改数据集处理逻辑。

不允许删除现有 API：

- `POST /api/generate_dataset`
- `GET /api/dataset/unsw/status`
- `GET /api/federated/nodes`
- `POST /api/dataset/unsw/process`

验收标准：

- “数据处理”页同时包含原 `pg-data` 和 `pg-ds` 的核心内容。
- 生成数据、明文预览、密文预览可用。
- 数据集状态刷新可用。
- 处理数据集按钮可用。
- 联邦节点展示可用。

Codex 审核重点：

- `genData()`、`buildTable()`、`loadDS()`、`procDS()` 是否仍可用。
- `procDS()` 的页面跳转是否改到正确的新页签。
- 是否误删数据预览容器 `#pp`、`#ep`、`#dsInfo`、`#dsNodes`。

### Task C：合并模型训练 + 联邦学习为“联邦训练”

允许修改文件：

- `index.html`

禁止修改文件：

- `app.py`
- `src/**`
- `config/**`
- `tests/**`
- `data/**`

不允许新增后端功能：

- 不新增训练 API。
- 不改联邦学习后端实现。

不允许删除现有 API：

- `POST /api/train/dual`
- `GET /api/train/history`
- `GET /api/federated/nodes`
- `POST /api/federated/round`

验收标准：

- “联邦训练”页包含传统/联邦训练对比和 4 节点联邦训练展示。
- 训练曲线、训练结果、训练历史仍显示。
- 联邦节点、执行一轮、联邦结果仍可用。

Codex 审核重点：

- `startTrain()`、`renderTrainChart()`、`loadTrainHist()`、`loadFed()`、`runFed()` 是否仍存在。
- 图表 canvas ID 是否未被改坏：`#trCh`、`#fedCh`。
- 不允许把模拟联邦表述成真实多节点通信。

### Task D：整理攻击检测页面说明和结果表格

允许修改文件：

- `index.html`

禁止修改文件：

- `app.py`
- `src/**`
- `config/**`
- `tests/**`
- `data/**`

不允许新增后端功能：

- 不新增检测器。
- 不新增上传接口。

不允许删除现有 API：

- `POST /api/ensemble/detect`
- `POST /upload`

验收标准：

- 页面顶部增加检测流程说明。
- 内置样本检测仍可用。
- 上传 CSV/JSON 仍可用。
- 检测结果表格字段不减少。

Codex 审核重点：

- `detSample()`、`detFile()`、`showDetRes()` 是否仍存在。
- 用户可控字段是否经过转义或避免直接插入。
- 不允许新增 Kitsune-lite、LUCID-lite、Benchmark。

### Task E：合并加密对比 + 自适应优化为“自适应优化”

允许修改文件：

- `index.html`

禁止修改文件：

- `app.py`
- `src/**`
- `config/**`
- `tests/**`
- `data/**`

不允许新增后端功能：

- 不新增加密 API。
- 不改优化算法。

不允许删除现有 API：

- `POST /api/compare_encryption`
- `GET /api/optimization/status`
- `GET /api/optimization/history`
- `POST /api/optimization/auto`

验收标准：

- “自适应优化”页同时展示加密对比和优化状态。
- 加密对比刷新可用。
- 自动优化按钮可用。
- 优化记录可显示。

Codex 审核重点：

- `updEnc()`、`loadOpt()`、`toggleAuto()` 是否仍存在。
- `optTimer` 是否不会重复创建请求风暴。
- 不允许夸大 AES / Paillier 的真实实现状态。

### Task F：整理安全防护页面

允许修改文件：

- `index.html`

禁止修改文件：

- `app.py`
- `src/**`
- `config/**`
- `tests/**`
- `data/**`

不允许新增后端功能：

- 不新增安全写接口。
- 不新增防重放、签名、IP 黑白名单、API 开关。

不允许删除现有 API：

- `GET /api/security/events/recent?limit=50`

验收标准：

- 安全防护页保留 Task 1-6 展示闭环。
- 安全事件统计、事件类型、事件表格正常。
- 空状态、错误状态正常。
- 30 秒自动刷新不重复创建定时器。

Codex 审核重点：

- `loadSec()`、`ensureSecTimer()`、`esc()` 是否仍存在。
- 所有用户可控字段是否经过 `esc()`。
- 是否误新增写接口或安全配置操作入口。

### Task G：新增静态实验报告页

允许修改文件：

- `index.html`

禁止修改文件：

- `app.py`
- `src/**`
- `config/**`
- `tests/**`
- `data/**`

不允许新增后端功能：

- 不新增报告导出 API。
- 不接入 `/api/export/report`。

不允许删除现有 API：

- 不删除任何已有 API 调用。

验收标准：

- 新增“实验报告”导航和 `pg-report` 页面。
- 页面为静态内容，包含技术路线、模块状态、可演示功能、风险说明、答辩演示步骤。
- 不影响其他页面切换。
- 不引入新框架。

Codex 审核重点：

- 是否只新增静态展示页。
- 是否误接入后端导出能力。
- 是否影响 `/`、`/api/system/health`、`/api/security/events/recent`。

## 六、风险提醒

必须避免：

- 不要一次性重写 `index.html`。
- 不要引入 React、Vue、Angular 或构建工具。
- 不要删除原 JS 函数。
- 不要删除或改名现有 API 调用。
- 不要修改 `app.py`。
- 不要修改 `src/**` 核心检测、加密、优化、联邦学习逻辑。
- 不要影响 `/`、`/api/system/health`、`/api/security/events/recent`。
- 不要把“预留能力”写成“已完成能力”。
- 不要把模拟联邦学习写成真实多节点通信。
- 不要把 AES 性能估算写成完整真实 AES 加密链路。
- 不要把 Paillier 展示写成已完成真实梯度加密，除非后续有独立审计。

每个小任务完成后都应至少验证：

- `python -m py_compile app.py src/**/*.py`
- `python app.py`
- `GET /`
- `GET /api/system/health`
- `GET /api/security/events/recent`
- 页面导航切换无明显 JS 报错

## 七、建议先让 Claude 做哪一个最小任务

建议先做：

**Task A：只改导航名称和页面标题，不动功能。**

原因：

- 风险最低，只改信息架构的第一层。
- 可以先验证新叙事顺序是否适合答辩。
- 不移动 DOM、不合并页面、不改 JS 函数，最容易审查。
- 如果 Task A 通过，再逐步做 B/C/E 的页面合并。

Task A 的核心要求：

- 只改导航文案、页面标题和少量顶部说明文案。
- 暂时不删除任何旧页面。
- 暂时不合并任何 DOM。
- 暂时不新增实验报告功能逻辑。
- 保证所有原按钮、JS 函数、API 调用还在。

