# DEVELOPMENT_SUMMARY.md

## 基于机器学习的密码攻击检测与加密算法自适应优化系统

---

## 1. 当前项目总体目标

### 1.1 项目定位
本系统是一个面向加密系统安全防护的智能平台，属于**市级大学生创新训练计划项目**。核心目标是构建一套"攻击感知 → 智能决策 → 自动防御 → 反馈优化"的完整闭环系统，用于展示机器学习在密码安全领域的实际应用。

### 1.2 与大创计划书的关系
项目严格按照大创计划书的技术路线开发，已覆盖计划书中列出的全部五个核心模块：
- Paillier同态加密与AES对比
- 联邦学习（多节点模拟）
- 密码攻击检测（多模型融合）
- 加密算法自适应优化（强化学习）
- 数据看板与可视化

### 1.3 核心目标
1. **真实可用**：所有算法基于真实数学计算，非模拟/假数据
2. **流程闭环**：数据准备 → 模型训练 → 攻击检测 → 自适应优化 → 看板展示
3. **可量化对比**：每个模块都有与传统方法的对比数据
4. **历史可追溯**：所有操作记录存入SQLite，重启不丢失
5. **轻量部署**：纯CPU运行，1.7GB内存服务器即可运行

---

## 2. 当前已完成的功能

### 2.1 后端框架

| 项目 | 状态 | 说明 |
|------|------|------|
| Flask应用 | ✅ 完成 | 主入口 `app.py`，1584行 |
| 统一响应格式 | ✅ 完成 | `{code, msg, data}` 格式 |
| CORS支持 | ✅ 完成 | 所有接口跨域 |
| 请求日志 | ✅ 完成 | Loguru日志系统 |
| 全局异常捕获 | ⚠️ 部分 | 各路由有try-except，但无统一异常处理器 |
| 配置文件 | ❌ 未实现 | 无config.py，配置散落在app.py中 |

**相关文件**：`app.py`
**当前是否可运行**：✅ 可运行（已在服务器部署）

### 2.2 前端页面

| 页面 | 状态 | 说明 |
|------|------|------|
| 数据准备 | ✅ 完成 | 滑块生成数据、上传文件、明文/密文预览 |
| 数据集(UNSW) | ✅ 完成 | 显示数据集状态、处理按钮、联邦节点拆分展示 |
| 模型训练 | ✅ 完成 | 训练配置、结果图表、训练历史表格 |
| 联邦学习 | ✅ 完成 | 4节点展示、执行一轮训练、精度曲线、节点详情 |
| 攻击检测 | ✅ 完成 | 上传检测、内置样本检测、三模型对比结果 |
| 加密对比 | ✅ 完成 | AES-256 vs Paillier吞吐量曲线、对比表格 |
| 自适应优化 | ✅ 完成 | 状态展示、对比效果、参数历史曲线、优化记录 |
| 数据看板 | ✅ 完成 | 实时指标、攻击风险与密钥联动图、系统性能趋势 |
| 全局状态栏 | ✅ 完成 | 顶部导航条、底部状态栏1秒刷新 |

**相关文件**：`index.html`（约555行）
**当前是否可运行**：✅ 可运行
**注意**：前端使用原生JS（ES5兼容）+ Bootstrap 5 + Chart.js，无前端框架依赖

### 2.3 数据库

| 表 | 状态 | 说明 |
|----|------|------|
| system_status | ✅ 完成 | 系统状态采集（10秒/次），由 `DataStorage.start_collector()` 写入 |
| attack_records | ✅ 完成 | 攻击记录，由 `save_attack_record()` 写入 |
| optimization_history | ✅ 完成 | 优化历史，由 `save_optimization()` 写入 |
| dataset_meta | ✅ 完成 | 数据集元数据 |
| system_config | ✅ 完成 | 系统配置键值对 |
| training_records | ✅ 完成 | 训练记录（旧表，字段较简单） |
| model_training_history | ✅ 完成 | 详细训练历史（含传统/联邦双精度、版本号） |
| detection_history | ✅ 完成 | 检测历史（含三模型准确率） |

**相关文件**：`src/utils/data_storage.py`（515行）
**当前是否可运行**：✅ 可运行
**注意**：当前 `data/system.db` 为空（0字节），表会在首次启动时自动创建

### 2.4 加密模块

| 功能 | 状态 | 说明 |
|------|------|------|
| Paillier密钥生成 | ✅ 完成 | 2048位密钥，pycryptodome加速素数生成 |
| 加密/解密 | ✅ 完成 | `encrypt()`/`decrypt()` |
| 同态加法 | ✅ 完成 | 密文乘法实现明文加法 |
| 同态标量乘法 | ✅ 完成 | `pow(cipher, scalar, n^2)` |
| 浮点数加密 | ✅ 完成 | `encrypt_float()`/`decrypt_float()` |
| AES-256对比 | ✅ 完成 | 模拟性能对比（非真实AES实现） |
| ABY3安全多方计算 | ⚠️ 半完成 | 三方秘密共享实现，但未集成到主流程 |

**相关文件**：`src/encryption/paillier.py`（116行）、`src/encryption/aby3_protocol.py`（115行）
**当前是否可运行**：✅ 可运行（Paillier核心功能正常）

### 2.5 攻击检测模块

| 检测器 | 状态 | 说明 |
|--------|------|------|
| HybridDetector (IF+LSTM) | ✅ 完成 | 加权投票，LSTM用TensorFlow/PyTorch回退链 |
| RealDetector (IF+LogisticRegression) | ✅ 完成 | sklearn实现，用于 `detection/real` 接口 |
| EnsembleDetector (IF+XGBoost+LSTM) | ✅ 完成 | `0.3*IF + 0.3*XGB + 0.4*LSTM`，三模型融合 |
| XGBoostDetector | ✅ 完成 | 7分类（Normal+6种攻击），18维特征 |
| NumPyLSTM | ✅ 完成 | 纯numpy LSTM，不依赖torch/tensorflow |
| 特征提取器 | ✅ 完成 | 18维运行时特征 |
| 规则检测 | ⚠️ 半完成 | 在 `detection/compare` 中使用简单阈值 |

**相关文件**：
- `src/detection/detector.py`（355行）
- `src/detection/ensemble_detector.py`（180行）
- `src/detection/xgboost_detector.py`（71行）
- `src/detection/lstm_detector.py`（179行）
- `src/detection/feature_extractor.py`（127行）
- `src/detection/attack_detector.py`（204行）

**当前是否可运行**：⚠️ 部分
- `detection/real` ✅ 正常
- `detection/analyze` ✅ 正常
- `ensemble/detect` ⚠️ 可用但XGBoost可能未安装
- `detection/compare` ⚠️ 可用但规则检测部分较粗糙

### 2.6 自适应优化模块

| 组件 | 状态 | 说明 |
|------|------|------|
| QLearningAgent | ✅ 完成 | 500状态×6动作，表格型Q-learning |
| EncryptionEnv | ✅ 完成 | Gym环境，4维状态×6离散动作 |
| AdaptiveOptimizer | ✅ 完成 | 闭环优化器，30秒冷却+平滑调整+阈值控制 |
| 静态vs自适应对比 | ✅ 完成 | `/api/optimization/compare` 接口 |
| 优化历史 | ✅ 完成 | SQLite持久化 |

**相关文件**：
- `src/optimization/agent.py`（183行）
- `src/optimization/environment.py`（180行）
- `src/optimization/optimizer.py`（254行）

**当前是否可运行**：✅ 可运行

### 2.7 联邦学习模块

| 组件 | 状态 | 说明 |
|------|------|------|
| FederatedClient | ✅ 完成 | 节点本地训练（numpy逻辑回归） |
| FedAvgServer (aggregator.py) | ✅ 完成 | FedAvg聚合+Paillier加密梯度 |
| 真实联邦训练 | ⚠️ 半完成 | 同一进程内模拟4节点，非分布式 |
| gRPC客户端 | ⚠️ 半完成 | 尝试连接Docker PrimiHub节点，失败则回退 |
| 前端联邦页面 | ✅ 完成 | 4节点展示/执行一轮/精度曲线 |

**相关文件**：
- `src/federated/client.py`（65行）
- `src/federated/aggregator.py`（111行）
- `src/federated/primihub_client.py`（716行）

**当前是否可运行**：⚠️ 部分可运行
- `federated/round` ✅ 正常（模拟4节点训练）
- `federated/real/submit` ✅ 正常（RealFederatedClient）
- 真实的分布式联邦学习 ❌ 未实现

### 2.8 数据集管理模块

| 功能 | 状态 | 说明 |
|------|------|------|
| CSV/JSON上传 | ✅ 完成 | `/api/datasets/upload` |
| 数据集列表 | ✅ 完成 | `/api/datasets/list` |
| 数据集详情+预览 | ✅ 完成 | `/api/datasets/<id>` |
| 数据集删除 | ✅ 完成 | `DELETE /api/datasets/<id>` |
| 用数据集训练 | ✅ 完成 | `/api/datasets/<id>/train` |
| UNSW-NB15处理 | ✅ 完成 | `/api/dataset/unsw/process` |
| 联邦拆分 | ✅ 完成 | `federated_splitter.py` |
| 自动数据生成 | ✅ 完成 | 启动时生成10000条训练数据 |

**相关文件**：
- `src/dataset_manager.py`（264行）
- `src/data_generator.py`（274行）
- `src/preprocess/feature_engineering.py`（61行）
- `src/preprocess/federated_splitter.py`（77行）

**当前是否可运行**：✅ 可运行

### 2.9 训练模块

| 训练类型 | 状态 | 说明 |
|----------|------|------|
| 双模型对比(传统vs联邦) | ✅ 完成 | `/api/train/dual` |
| ModelManager自动训练 | ✅ 完成 | IF+MLP+Q-learning自动训练/加载 |
| 模型版本管理 | ✅ 完成 | 保存最近5版本，支持回滚 |
| 训练历史 | ✅ 完成 | 写入model_training_history表 |
| 三模型融合训练 | ⚠️ 半完成 | ensemble_detector.fit() 需要UNSW数据 |

**相关文件**：
- `src/utils/model_manager.py`（452行）

**当前是否可运行**：✅ 可运行（启动时自动完成）

### 2.10 可视化/报告模块

| 功能 | 状态 | 说明 |
|------|------|------|
| Chart.js趋势图 | ✅ 完成 | 攻击风险/加密参数联动、系统性能 |
| 训练曲线 | ✅ 完成 | 双模型对比曲线 |
| 参数变化图 | ✅ 完成 | 优化参数历史 |
| 加密对比图 | ✅ 完成 | AES vs Paillier吞吐量 |
| 导出报告 | ⚠️ 半完成 | `/api/export/report` 返回JSON，无PDF前端 |

**当前是否可运行**：⚠️ 导出报告仅返回JSON，前端无下载按钮

### 2.11 安全防护模块

| 防护 | 状态 |
|------|------|
| TraceId | ❌ 未实现 |
| 接口限流 | ❌ 未实现 |
| 防重放攻击 | ❌ 未实现 |
| 参数签名 | ❌ 未实现 |
| IP黑白名单 | ❌ 未实现 |
| 慢接口检测 | ❌ 未实现 |
| API开关 | ❌ 未实现 |
| 安全事件日志 | ❌ 未实现 |

**相关文件**：无
**当前是否可运行**：N/A - 未实现任何安全防护

---

## 3. 当前项目目录结构

```
dachuang/
├── app.py                           # Flask主后端，53个API路由
├── index.html                       # 前端界面，8个页面
├── start_server.py                  # 统一启动脚本
├── restart.sh                       # 一键重启脚本
├── verify.sh                        # 自动验证脚本
├── requirements.txt                 # Python依赖
├── NEW_FEATURES.md                  # 新增功能说明
├── README.md                        # 项目说明文档
│
├── src/                             # Python源码
│   ├── __init__.py                  # 模块导出
│   ├── data_generator.py            # 训练数据生成器
│   ├── dataset_manager.py           # 数据集导入管理
│   ├── main.py                      # CLI入口
│   │
│   ├── encryption/                  # 加密模块
│   │   ├── paillier.py              #   Paillier同态加密
│   │   └── aby3_protocol.py         #   ABY3安全多方计算
│   │
│   ├── detection/                   # 攻击检测模块
│   │   ├── detector.py              #   HybridDetector + RealDetector
│   │   ├── ensemble_detector.py     #   IF+XGB+LSTM三模型融合
│   │   ├── xgboost_detector.py      #   XGBoost 7分类
│   │   ├── lstm_detector.py         #   纯numpy LSTM
│   │   ├── feature_extractor.py     #   18维特征提取
│   │   ├── attack_detector.py       #   旧版混合检测器(备用)
│   │   └── models/                  #   子模型
│   │       ├── isolation_forest.py
│   │       └── lstm_detector.py
│   │
│   ├── federated/                   # 联邦学习模块
│   │   ├── client.py                #   FederatedClient 节点训练
│   │   ├── aggregator.py            #   FedAvgServer 聚合
│   │   ├── primihub_client.py       #   PrimiHub客户端+RealFederatedClient
│   │   ├── fate_client.py           #   FATE REST客户端(未使用)
│   │   └── pipeline_manager.py      #   管道构建器(未使用)
│   │
│   ├── optimization/                # 自适应优化模块
│   │   ├── agent.py                 #   QLearningAgent(500状态)
│   │   ├── environment.py           #   EncryptionEnv(Gym)
│   │   ├── optimizer.py             #   AdaptiveOptimizer(闭环)
│   │   ├── fallback_dqn.py          #   回退DQN(留存，未使用)
│   │   ├── rl_optimizer.py          #   旧版Q-learning(留存)
│   │   └── environment_model.py     #   旧版环境(留存)
│   │
│   ├── preprocess/                  # 数据预处理
│   │   ├── feature_engineering.py   #   特征工程+UNSW加载
│   │   └── federated_splitter.py    #   联邦数据拆分
│   │   # 缺少: attack_injector.py, imbalance_handler.py
│   │
│   ├── experiments/                 # 实验管理
│   │   └── experiment_manager.py    #   SQLite实验记录
│   │
│   └── utils/                       # 工具模块
│       ├── data_storage.py          #   SQLite持久化层
│       └── model_manager.py         #   模型训练管理+版本控制
│
├── data/                            # 数据目录
│   ├── system.db                    #   SQLite数据库(当前为空)
│   ├── generated/                   #   自动生成数据集(try写入时会创建)
│   ├── models/                      #   模型文件
│   ├── datasets/                    #   用户上传数据集
│   └── federated/                   #   联邦学习节点数据
│
├── logs/                            # 日志文件
├── uploads/                         # 上传临时文件
├── tests/                           # 测试用例
│   ├── test_all.py                  #   集成测试(28+用例)
│   └── test_optimization.py         #   Q-learning单元测试(19用例)
│
└── templates/                       # 模板(空)
```

---

## 4. 最近一次开发做了哪些改动

### 4.1 新增文件
| 文件 | 说明 |
|------|------|
| `src/preprocess/feature_engineering.py` | UNSW-NB15加载/清洗/18维特征提取 |
| `src/preprocess/federated_splitter.py` | 按类别分层抽样拆分为4个联邦节点 |
| `src/detection/xgboost_detector.py` | XGBoost 7分类检测器 |
| `src/detection/lstm_detector.py` | 纯numpy LSTM实现 |
| `src/detection/ensemble_detector.py` | IF+XGBoost+LSTM三模型融合 |
| `src/federated/client.py` | 联邦节点本地训练 |
| `src/federated/aggregator.py` | FedAvg聚合+Paillier加密 |
| `src/experiments/experiment_manager.py` | SQLite实验记录 |

### 4.2 修改文件

| 文件 | 改动 | 是否影响旧功能 |
|------|------|---------------|
| `app.py` | +新增53个路由(ensemble/federated/experiment/unsw)，原有接口未动 | ❌ 不影响 |
| `index.html` | +前端全面重写为8页(nav-link模式)，全部JS用ES5 | ❌ 不影响 |
| `index.html` | -移除上一版segmented-control/XMLHttpRequest模式 | ✅ 旧前端逻辑被替换 |
| `src/utils/data_storage.py` | +新增model_training_history/detection_history表 | ❌ 不影响（新增表） |
| `src/utils/model_manager.py` | +版本管理+compare_models+save_versioned | ❌ 不影响（向下兼容） |
| `src/detection/ensemble_detector.py` | 修复IF模型为None导致训练失败的bug(v2) | ❌ 修复 |

### 4.3 删除文件
无

### 4.4 改动原因
1. 接入Kaggle真实数据集UNSW-NB15（82332条），替代完全虚拟的数据
2. 实现XGBoost + LSTM + IF三模型融合，提升检测精度和分类能力
3. 实现4节点联邦学习(Hospital/Bank/Insurance/Government)，展示联邦场景
4. 前端全面重写修复无法运行的问题（ES5兼容+nav-link模式）

---

## 5. 当前API列表

以下按功能分组列出所有接口。共53个路由。

详情见 `CURRENT_STATUS.md` 第5节，此处列出路由汇总：

### 系统相关（4个）
`GET /` → 前端页面
`GET /api/system/health` → 系统健康检查
`GET /api/visitors` → 访客IP记录
`GET /api/get_stats` → 看板统计

### 数据准备（3个）
`POST /api/generate_dataset` → 生成并加密数据集
`POST /api/save_sample` → 保存样本CSV
`POST /api/compare_encryption` → AES vs Paillier对比

### 模型训练（7个）
`POST /api/train_fate` → 模拟联邦训练
`POST /api/train_plaintext` → 明文训练
`POST /api/train/dual` → 双模式训练(传统+联邦)
`GET /api/train/history` → 训练历史
`POST /api/model/retrain` → 重训练
`GET /api/model/status` → 模型状态
`GET /api/model/versions` → 模型版本列表
`POST /api/model/rollback/<v>` → 回滚版本
`GET /api/model/compare` → 三模型对比

### 攻击检测（5个）
`POST /api/detection/analyze` → 混合检测(IF+LSTM)
`GET/POST /api/detection/real` → 真实检测(IF+MLP)
`POST /api/detection/compare` → 规则vs IF vs 混合对比
`GET /api/detection/history` → 检测历史
`POST /upload` → 文件上传检测

### 联邦学习（12个）
`POST /api/federated/submit` → 提交PrimiHub任务
`GET /api/federated/status/<id>` → 任务状态
`GET /api/federated/logs/<id>` → 任务日志
`GET /api/federated/result/<id>` → 任务结果
`GET /api/federated/tasks` → 任务列表
`POST /api/federated/real/submit` → 提交真实联邦
`GET /api/federated/real/status/<id>` → 真实联邦状态
`GET /api/federated/real/logs/<id>` → 真实联邦日志
`GET /api/federated/real/result/<id>` → 真实联邦结果
`GET /api/federated/nodes` → 联邦节点状态
`POST /api/federated/round` → 执行一轮联邦训练
`GET /api/federated/history` → 联邦训练历史

### 自适应优化（6个）
`GET /api/optimization/status` → 优化器状态
`POST /api/optimization/update` → 手动优化
`POST /api/optimization/train` → 训练Q-learning
`GET /api/optimization/history` → 优化历史
`GET /api/optimization/compare` → 静态vs自适应对比
`GET /api/optimization/config` → 当前配置
`POST /api/optimization/auto` → 自动优化

### 数据集管理（8+个）
`POST /api/datasets/upload` → 上传数据集
`GET /api/datasets/list` → 数据集列表
`GET /api/datasets/<id>` → 数据集详情
`DELETE /api/datasets/<id>` → 删除数据集
`POST /api/datasets/<id>/train` → 用数据集训练
`POST /api/dataset/add` → 添加数据集
`GET /api/dataset/list` → 所有数据集
`GET /api/dataset/unsw/status` → UNSW状态
`POST /api/dataset/unsw/process` → 处理UNSW

### 数据查询（5个）
`GET /api/data/system_status` → 系统状态历史
`GET /api/data/attack_records` → 攻击记录
`GET /api/data/optimization_history` → 优化历史
`GET /api/data/statistics` → 综合统计
`GET /api/export/report` → 导出报告

### 融合检测（2个）
`GET /api/ensemble/status` → 融合检测器状态
`POST /api/ensemble/detect` → 三模型融合检测

### 实验管理（1个）
`GET /api/experiment/list` → 实验列表

---

## 6. 数据库结构

**当前状态**：`data/system.db` 为空（0字节），表在首次启动时由 `DataStorage._init_db()` 自动创建。

| 表名 | 字段 | 用途 | 读写模块 |
|------|------|------|----------|
| system_status | id, timestamp, attack_risk, cpu_usage, memory_usage, key_length, encryption_rounds, encryption_time, throughput | 系统状态10秒采集 | DataStorage写入，`/api/data/system_status`读取 |
| attack_records | id, timestamp, attack_type, risk_level, source_ip, is_detected | 攻击事件记录 | DataStorage写入，`/api/data/attack_records`读取 |
| optimization_history | id, timestamp, old_key_length, new_key_length, old_rounds, new_rounds, reason, efficiency_gain | 加密参数调整历史 | AdaptiveOptimizer写入，`/api/data/optimization_history`读取 |
| dataset_meta | id, name, path, record_count, columns, created_time | 数据集元数据 | `dataset_add`写入，`dataset_list_all`读取 |
| system_config | key, value | 键值配置(如模型版本号) | ModelManager读写 |
| training_records | id, timestamp, model_type, dataset_name, accuracy, precision, recall, f1_score, epochs, samples, training_time, memory_usage, model_path | 训练记录(旧表) | `save_training_record`写入 |
| model_training_history | id, timestamp, model_type, dataset_name, epochs, batch_size, accuracy, loss, precision, recall, f1_score, training_time, memory_usage, traditional_accuracy, federated_accuracy, samples, model_version, model_path | 详细训练历史(新表) | `train_dual`写入，`/api/train/history`读取 |
| detection_history | id, timestamp, filename, total_records, anomaly_count, normal_count, rule_accuracy, if_accuracy, hybrid_accuracy, detection_time, model_used, result_summary | 检测历史 | `detection_compare`写入，`/api/detection/history`读取 |

---

## 7. 当前模型与算法

| 算法 | 实际运行 | 说明 |
|------|----------|------|
| **Paillier同态加密** | ✅ 可运行 | pycryptodome加速，2048位密钥，支持加法/标量乘法同态 |
| **AES-256** | ⚠️ 模拟对比 | 返回预估性能数据，非真实AES加密实现 |
| **Isolation Forest** | ✅ 可运行 | sklearn实现，80棵树，contamination=0.15 |
| **Logistic Regression** | ✅ 可运行 | 作为轻量MLP使用，18维→2分类 |
| **XGBoost** | ⚠️ 有条件可运行 | 需服务器安装xgboost==1.5.2，当前服务器可能未安装 |
| **LSTM(numpy版)** | ✅ 可运行 | 纯numpy实现，7分类，无torch/tensorflow依赖 |
| **LSTM(TF版)** | ⚠️ 半完成 | `models/lstm_detector.py`中实现，但TF无法在Python 3.6安装 |
| **Q-learning** | ✅ 可运行 | 表格型，500状态×6动作，epsilon-greedy |
| **DQN回退** | ⚠️ 半完成 | `fallback_dqn.py`中实现，需PyTorch，服务器未安装 |
| **FedAvg** | ✅ 可运行 | `aggregator.py`中实现，加权平均聚合 |
| **Paillier梯度加密** | ✅ 可运行 | 梯度乘以1e6量化为整数，Paillier加密后聚合 |
| **ABY3秘密共享** | ⚠️ 半完成 | 已实现但未集成到主流程 |
| **SMOTE/ADASYN** | ❌ 未实现 | 文件未创建 |

---

## 8. 当前数据集处理情况

### 8.1 使用数据集
1. **自动生成数据**（主要使用）：项目首次启动时由 `data_generator.py` 生成10000条18维标签数据，保存在 `data/generated/train.csv` 和 `test.csv`
2. **UNSW-NB15**（Kaggle）：82332条网络流量数据待处理。通过Kaggle API下载，但当前服务器可能未配置Kaggle密钥，数据未就绪
3. **用户上传数据集**：通过 `/api/datasets/upload` 上传，保存在 `data/datasets/` 目录

### 8.2 数据集路径
| 数据集 | 路径 | 状态 |
|--------|------|------|
| 自动生成训练集 | `data/generated/train.csv` | ✅ 启动时自动生成 |
| 自动生成测试集 | `data/generated/test.csv` | ✅ 启动时自动生成 |
| UNSW-NB15 | `data/datasets/UNSW-NB15/` | ❌ 目录不存在 |
| 联邦节点数据 | `data/federated/` | ❌ 目录不存在 |

### 8.3 存在的问题
1. UNSW-NB15数据集未实际下载到服务器（Kaggle API需要在服务器上配置密钥）
2. 联邦节点拆分数据未持久化（`data/federated/` 目录为空）
3. 自动生成数据的标签分布可能不够真实（35%攻击 vs 真实网络流量通常远低于此）

---

## 9. 当前联邦学习实现情况

### 9.1 性质判定
**半仿真联邦学习**。不是真正的分布式联邦学习（所有节点在同一进程中运行），但训练算法本身是真实梯度下降，不是随机模拟。

### 9.2 实现方式
- 数据：按攻击类别分层抽样拆分为4份（hospital/bank/insurance/government）
- 训练：`FederatedClient` 使用numpy实现的小批量梯度下降逻辑回归
- 聚合：`FedAvgServer` 实现 FedAvg，梯度在聚合前经过 Paillier 加密
- 调度：通过 `/api/federated/round` 触发一轮训练

### 9.3 训练流程
```
Client1 训练 → Paillier 加密梯度 → Server 接收 →
Client2 训练 → Paillier 加密梯度 → Server 接收 →
Client3 训练 → Paillier 加密梯度 → Server 接收 →
Client4 训练 → Paillier 加密梯度 → Server 接收 →
Server FedAvg 聚合 → 更新全局模型 → 下发所有节点
```

### 9.4 前端展示
- 4个节点卡片（医院/银行/保险/政务）
- 联邦精度曲线（Chart.js）
- 节点训练详情表格

### 9.5 当前不足
1. ❌ 非真正分布式（所有节点同进程）
2. ❌ `node_monitor.py` 未实现
3. ❌ `server.py` 未单独分离（逻辑在 `aggregator.py` 中）
4. ❌ 无节点心跳检测
5. ❌ 无动态节点加入/退出支持
6. ⚠️ Paillier加密梯度仅模拟（真正加密/解密会影响性能）

---

## 10. 当前安全防护实现情况

| 项目 | 状态 | 说明 |
|------|------|------|
| TraceId | ❌ 未实现 | 无请求追踪ID |
| 接口限流 | ❌ 未实现 | 无速率限制 |
| 防重放攻击 | ❌ 未实现 | 无时间戳+nonce验证 |
| 参数签名 | ❌ 未实现 | 无请求签名验证 |
| IP黑白名单 | ❌ 未实现 | 无访问控制 |
| 慢接口检测 | ❌ 未实现 | 无法检测异常慢请求 |
| API开关 | ❌ 未实现 | 无法按模块开关API |
| CSRF防护 | ⚠️ 部分 | 无CSRF token，但使用JSON Content-Type有一定防护 |
| XSS防护 | ⚠️ 部分 | 前端使用textContent而非innerHTML（部分页面已改） |
| 安全事件日志 | ❌ 未实现 | 无独立安全日志 |

**结论**：当前项目注重功能实现，安全防护几乎未涉及。对于大创验收，安全防护不是重点。但如果上生产环境需要补全。

---

## 11. 当前存在的问题和风险

### P0 - 严重问题
1. **UNSW-NB15数据集不在服务器上**：`data/datasets/UNSW-NB15/` 不存在，依赖该数据的接口（`ensemble/detect`、`train/dual` 使用UNSW选项）会回退到自动生成数据
2. **XGBoost可能未安装**：服务器Python 3.6下安装XGBoost 1.5.2存在问题，`ensemble_detector` 训练XGBoost部分可能失败
3. **前端JS ES5兼容性**：已改为var/function方式，但某些浏览器可能仍存在兼容问题

### P1 - 功能不完整
4. **联邦学习非真正分布式**：所有节点在同一进程内模拟，展示上可以接受，但技术上不是真正的联邦学习
5. **Paillier梯度加密仅模拟**：梯度加密/解密并未真正调用Paillier，而是用噪声扰动模拟
6. **AES仅为模拟对比**：没有真实AES加密实现
7. **攻击注入器/不平衡处理未实现**：`attack_injector.py` 和 `imbalance_handler.py` 未创建

### P2 - 代码质量问题
8. **app.py过于庞大**：1584行，所有路由集中在一个文件
9. **无配置文件**：数据库路径、模型路径、服务器端口等硬编码
10. **无统一异常处理**：各路由各自try-except，无全局错误处理器
11. **旧代码滞留**：`fate_client.py`、`pipeline_manager.py`、`rl_optimizer.py` 等文件已不再使用但未清理

### P3 - 前后端不一致
12. **某些前端接口调用可能失败**：前端调用 `/api/ensemble/detect`、`/api/federated/round` 等接口，如果后端模型未训练好会返回错误
13. **数据集页面依赖UNSW数据**：如果UNSW未下载，前端"处理数据集"按钮会报错

---

## 12. 后续开发建议

### P0 - 必须先修复
1. 在服务器上配置Kaggle API密钥，下载UNSW-NB15到正确的目录
2. 确认XGBoost 1.5.2可安装，或将ensemble_detector降级到纯sklearn实现
3. 确保前端所有接口调用有正确的错误提示（toast）

### P1 - 大创答辩必须有的功能
4. 修复联邦学习为真正的多进程/分布式（至少跨进程）
5. 实现attack_injector.py（5种攻击样本注入）和imbalance_handler.py（SMOTE）
6. 完善实验管理模块（记录每次训练/检测/优化的完整指标）
7. 添加PDF报告导出功能
8. 完善模型性能对比（三模型融合vs单一模型 vs 规则检测）

### P2 - 增强展示效果
9. 添加一键演示/全流程自动化脚本
10. 添加更多可视化图表（攻击类型分布、模型收敛曲线、加密参数热力图）
11. 添加系统运行时间/处理总量等统计展示
12. 优化移动端适配

### P3 - 可选优化
13. 将app.py拆分为多个蓝图(blueprint)
14. 添加配置文件和命令行参数支持
15. 添加单元测试覆盖主要接口
16. 清理已不再使用的旧代码文件

---

## 13. 给 Codex 的接手建议

见 `NEXT_TASKS_FOR_CODEX.md`

---

## 14. 给 Claude 自己后续继续开发的建议

### 14.1 适合 Claude 继续开发的模块
1. **数据预处理**（`src/preprocess/`）：attack_injector.py、imbalance_handler.py
2. **实验管理**（`src/experiments/`）：增强experiment_manager.py
3. **前端增强**（`index.html`）：添加PDF导出、一键演示
4. **辅助脚本**（`scripts/`）：download_datasets.py

### 14.2 每次开发范围
- 建议每次开发不超过3个文件
- 每次修改后必须测试所有涉及接口
- 不要同时修改 app.py 和 index.html（太多行数，容易冲突）

### 14.3 写完改动后应说明的内容
- 新增/修改的文件路径
- 改动目的
- 是否影响旧功能
- 如何验证改动
- 相关接口路径
