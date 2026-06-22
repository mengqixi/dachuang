# CODEX 实用化改造任务审查报告

## 结论

本轮改造可以合并到代码库。已完成 v4 路线中的主要结构调整：用户端保持三页，管理端调整为四个模块，风险详情独立模块已删除，Top 20 文案已替换为风险排名，并新增轻量数据集导入框架与统一风险结果字段。

运行数据、数据库、用户上传文件未纳入提交。

## 修改范围

合理修改文件：

- `app.py`
- `index.html`
- `README.md`
- `PRACTICAL_PLATFORM_ROADMAP.md`
- `config/dataset_sources.json`
- `scripts/import_security_datasets.py`
- `src/datasets/__init__.py`
- `src/datasets/security_dataset_importer.py`
- `src/user_submission_manager.py`
- `src/encryption/paillier.py`
- `src/optimization/agent.py`
- `src/optimization/environment.py`
- `src/optimization/optimizer.py`

未提交运行数据：

- `data/system.db`
- `data/user_submissions/`

## Task 完成情况

### Task 1：实用化路线文档

已生成 `PRACTICAL_PLATFORM_ROADMAP.md`，明确：

- 项目定位为密码攻击检测与隐私训练平台。
- 用户端为上传数据、风险检测、分析报告。
- 管理端为用户提交、数据处理、模型版本、系统审计。
- 删除独立风险详情模块。
- Top 20 改为风险排名。
- 参考 `Network-Security-Based-On-ML` 的统一检测管道、多来源融合、检测统计、模型状态、数据集管理等思想。
- 明确禁止照搬 TensorFlow / PyTorch / Kitsune / LUCID / DQN / PPO / WAF / 防火墙 / 扫描器等重型或偏离定位的能力。

### Task 2：轻量数据集导入能力

已新增：

- `config/dataset_sources.json`
- `scripts/import_security_datasets.py`
- `src/datasets/security_dataset_importer.py`

支持来源：

- `data/generated/train.csv`
- `data/generated/test.csv`
- UNSW-NB15
- CIC-IDS2017
- CSE-CIC-IDS2018
- CIC-DDoS2019

实现要点：

- CSV 分块读取。
- 按类别采样。
- 输出统一训练字段。
- 不提交原始数据、处理后 CSV、模型文件、数据库和日志。

### Task 3：统一检测管道

用户端提交分析与数据集抽样检测已统一输出关键风险字段：

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

### Task 4：用户端风险检测页改造

已调整：

- 删除独立风险详情模块。
- 删除展开详情按钮和详情面板。
- 删除 Top 20 文案。
- 风险检测页内部展示风险排名。
- 风险排名按 `risk_score` 降序。

### Task 5：分析报告页改造

报告改为风险排名摘要，不再使用 Top 20 表述。报告继续保留：

- 提交编号
- 文件名
- 总样本
- 高 / 中 / 低风险数量
- 主要风险类型
- 当前检测模型
- 加密归档状态
- 敏感字段
- 风险排名摘要
- 处理建议

### Task 6：管理端导航重构

管理端导航已调整为：

- 用户提交
- 数据处理
- 模型版本
- 系统审计

用户提交模块只展示用户上传数据。数据处理模块承接训练数据源、公开数据集状态、四节点准备状态和训练入口。模型版本模块独立展示运行模型、训练任务和版本列表。

### Task 7：模型版本和检测模型状态优化

模型版本接口和前端展示已增强：

- 当前运行检测模型。
- 训练追踪版本。
- 模型文件状态。
- 是否可启用。
- 不可切换原因。

仍需后续完善真实 artifact 管理，当前不会制造假回退效果。

## 验证结果

已执行并通过：

```bash
python -m py_compile app.py src/**/*.py
python -m unittest tests.test_optimization -v
python -m unittest tests.test_encryption -v
python -m unittest tests.test_all.TestOptimization -v
python -m unittest tests.test_all.TestAPI.test_frontend -v
python -m unittest discover tests -v
python scripts/import_security_datasets.py --dataset local_generated_train --output data/datasets/processed/_codex_smoke_security_sample.csv --metadata data/datasets/processed/_codex_smoke_security_metadata.json --per-class-limit 5
git diff --check
```

`python -m unittest discover tests -v` 结果：126 个测试通过，21 个跳过。

数据集导入烟测结果：

- 原始行数：7996
- 采样后行数：10
- 标签分布：`normal=5`，`anomaly_attack=5`

烟测生成的临时处理文件已删除。

## 剩余风险

- 管理端模型版本仍需要后续真实 artifact 生命周期管理。
- 公开大数据集需要由服务器本地下载或挂载，不应提交到 GitHub。
- 双端口浏览器烟测建议在部署后再执行一次。
- `app.py` 旧日志字符串中仍存在历史编码噪声，不影响当前功能，但后续可单独清理。

## 下一步建议

1. 提交本轮代码和文档。
2. 部署前确认不包含 `data/system.db`、`data/user_submissions/`、日志、模型文件。
3. 服务器部署后执行双端口烟测。
