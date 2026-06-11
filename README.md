# 基于机器学习的密码攻击检测与加密算法自适应优化系统

> 面向大创答辩展示的 Flask + SQLite 原型系统，串联公开攻击数据集处理、四节点联邦训练、攻击检测、自适应加密优化和安全防护看板。

[![Python](https://img.shields.io/badge/Python-3.6%2B-blue)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Backend-Flask-lightgrey)](https://flask.palletsprojects.com/)
[![SQLite](https://img.shields.io/badge/Storage-SQLite-003B57)](https://www.sqlite.org/)

## 项目简介

本项目用于展示“密码攻击检测 + 加密算法自适应优化”的实验闭环。系统以浏览器页面作为答辩入口，后端基于 Flask 提供 API，数据和日志使用本地文件与 SQLite 保存，适合在轻量服务器上运行和演示。

当前线上展示链路：

```text
公开数据集接入
  → 特征提取与处理
  → 四个联邦节点划分
  → 本地/联邦训练
  → 攻击检测与风险评分
  → 自适应加密参数优化
  → TraceId / 慢接口 / 限流 / 访问 IP 记录
  → 实验报告页汇总展示
```

> 说明：本系统是实验原型，不是生产级 WAF、完整联邦学习平台或企业级安全运营系统。联邦训练、Paillier 梯度保护、自适应优化等能力以当前接口返回和演示流程为准。

## 核心能力

### 1. 数据处理

- 支持检测 `data/datasets/UNSW-NB15/` 下的 UNSW-NB15 CSV 数据。
- 提取 18 维安全检测特征。
- 处理结果保存到 `data/datasets/processed/`。
- 将处理后的样本拆分为 4 个联邦节点：
  - `hospital`
  - `bank`
  - `insurance`
  - `government`

### 2. 联邦训练

- 本地训练用于形成单节点基线。
- 联邦训练页面展示四节点数据划分、样本数和 FedAvg 聚合流程。
- 后端包含 NumPy 逻辑回归、FedAvg 聚合和 Paillier 梯度保护相关实现。

### 3. 攻击检测

- 支持从已处理数据集中抽样检测。
- 支持上传 CSV / JSON 文件检测。
- 检测结果展示：
  - 风险分数
  - 风险等级
  - 攻击类型
  - 检测记录数与异常数
- 当前检测链路包含 Isolation Forest、XGBoost、NumPy LSTM 等模块，实际运行能力以接口返回为准。

### 4. 自适应优化

- 展示攻击风险、密钥长度、加密轮数和参数调整历史。
- 支持 AES 与 Paillier 指标对比。
- Q-learning 模块用于说明“风险驱动参数调整”的实验流程。

### 5. 安全防护与可观测

- TraceId 请求链路追踪。
- 慢接口检测。
- 接口限流事件记录。
- 安全事件只读查询 API。
- 安全防护页面展示安全事件和最近访问记录。
- 访问记录会记录首页访问的 IP、User-Agent、设备类型、浏览器、系统、TraceId 和时间戳。

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 准备数据集

优先使用 UNSW-NB15。服务器或本地运行：

```bash
python scripts/download_dataset.py --dataset unsw-nb15 --limit 50000
```

如果公开数据集下载失败，脚本会尝试生成本地 CSV 作为备用输入，页面会如实显示数据源类型。

### 3. 启动服务

```bash
python app.py
```

访问：

```text
http://127.0.0.1:5000/
```

服务器部署时可使用：

```bash
nohup python3 app.py > app.log 2>&1 &
```

## 常用验证命令

```bash
# 健康检查
curl http://127.0.0.1:5000/api/system/health

# 数据集状态
curl http://127.0.0.1:5000/api/dataset/unsw/status

# 处理数据集并刷新联邦节点
curl -X POST http://127.0.0.1:5000/api/dataset/unsw/process \
  -H "Content-Type: application/json" \
  -d "{}"

# 查看四个联邦节点
curl http://127.0.0.1:5000/api/federated/nodes

# 执行一轮联邦训练
curl -X POST http://127.0.0.1:5000/api/federated/round \
  -H "Content-Type: application/json" \
  -d "{\"epochs\":1}"

# 从已处理数据集中抽样检测
curl -X POST http://127.0.0.1:5000/api/ensemble/detect_from_dataset \
  -H "Content-Type: application/json" \
  -d "{\"limit\":20}"

# 查看安全事件
curl "http://127.0.0.1:5000/api/security/events/recent?limit=50"

# 查看首页访问记录
curl "http://127.0.0.1:5000/api/security/events/recent?limit=50&event_type=site_visit"
```

## 前端页面

当前前端为 7 个答辩展示入口：

| 页面 | 作用 |
| --- | --- |
| 总览 | 展示系统状态、数据源状态、联邦节点状态和推荐演示顺序 |
| 数据处理 | 检查数据源、处理公开数据集、刷新四节点状态 |
| 联邦训练 | 展示本地训练基线和四节点联邦训练流程 |
| 攻击检测 | 从数据集抽样检测或上传文件检测 |
| 自适应优化 | 展示加密对比和风险驱动参数调整 |
| 安全防护 | 展示安全事件、TraceId、慢接口、限流和访问 IP 记录 |
| 实验报告 | 汇总技术路线、模块能力和系统边界 |

## 主要 API

| 方法 | 路由 | 说明 |
| --- | --- | --- |
| `GET` | `/` | 前端页面 |
| `GET` | `/api/system/health` | 系统健康检查 |
| `GET` | `/api/dataset/unsw/status` | 查看 UNSW-NB15 / 本地数据源状态 |
| `POST` | `/api/dataset/unsw/process` | 处理数据集并生成联邦节点数据 |
| `GET` | `/api/federated/nodes` | 查看四个联邦节点状态 |
| `POST` | `/api/federated/round` | 执行一轮联邦训练 |
| `POST` | `/api/train/dual` | 本地训练与联邦训练对比接口 |
| `GET` | `/api/train/history` | 训练历史 |
| `POST` | `/api/ensemble/detect_from_dataset` | 从已处理数据集中抽样检测 |
| `POST` | `/api/ensemble/detect` | 直接传入特征进行融合检测 |
| `POST` | `/upload` | 上传 CSV / JSON 检测 |
| `GET` | `/api/optimization/status` | 自适应优化状态 |
| `POST` | `/api/optimization/auto` | 触发一次自动优化 |
| `GET` | `/api/optimization/history` | 优化历史 |
| `POST` | `/api/compare_encryption` | AES / Paillier 指标对比 |
| `GET` | `/api/security/events/recent` | 读取安全事件与访问记录 |

## 项目结构

```text
dachuang/
├── app.py                    # Flask 主入口与 API
├── index.html                # 答辩展示版前端
├── requirements.txt          # Python 依赖
├── config/
│   └── security.yaml         # TraceId、慢接口、限流、安全事件等配置
├── scripts/
│   └── download_dataset.py   # UNSW-NB15 下载 / 本地数据生成脚本
├── src/
│   ├── detection/            # 攻击检测、融合检测、IF/XGBoost/LSTM 等模块
│   ├── encryption/           # Paillier / AES 相关实现
│   ├── federated/            # 联邦客户端、FedAvg 聚合与梯度保护相关实现
│   ├── optimization/         # Q-learning 与参数优化模块
│   ├── preprocess/           # 特征提取与联邦节点拆分
│   ├── security/             # TraceId、慢接口、限流、安全事件、访问记录
│   └── utils/                # 数据存储、模型管理等工具
├── data/                     # 运行时数据、模型、数据集和日志，通常不提交
└── tests/                    # 单元测试与回归测试
```

## 技术栈

| 层级 | 技术 |
| --- | --- |
| 前端 | HTML、Bootstrap、Chart.js、Font Awesome |
| 后端 | Flask、Loguru、PyYAML |
| 存储 | SQLite、本地 JSON Lines 日志、本地模型文件 |
| 数据处理 | NumPy、Pandas、scikit-learn |
| 攻击检测 | Isolation Forest、XGBoost 风格检测器、NumPy LSTM |
| 联邦训练 | NumPy 逻辑回归、FedAvg、Paillier 梯度保护相关实现 |
| 自适应优化 | 表格型 Q-learning |
| 安全防护 | TraceId、慢接口、限流、访问 IP 记录 |

## 开发与测试

```bash
# Python 语法检查
python -m py_compile app.py src/**/*.py

# 运行已有测试
python -m unittest discover tests -v
```

PowerShell 下 `src/**/*.py` 可能不会自动展开，可使用：

```powershell
$files = @('app.py') + (Get-ChildItem -Path src -Recurse -Filter *.py | ForEach-Object { $_.FullName })
python -m py_compile @files
```

## 部署说明

当前项目可直接以 Flask 开发服务器方式运行，适合课程展示和大创答辩。若要长期公网运行，建议改为 systemd + WSGI 服务托管，并避免把 `data/` 下的数据集、模型、数据库和日志提交到 Git。

更多部署流程可参考：

- `DEPLOYMENT_RUNBOOK.md`

## 系统边界

- 这是实验原型，不是生产级攻击防护平台。
- 联邦训练当前以本地四节点流程为主，不代表真实跨机构生产部署。
- IP 归属地当前采用离线占位识别，不调用第三方地理位置 API。
- AES / Paillier 指标用于页面展示和实验对比，不等同于完整密码学 Benchmark。
- 部分模型具备备用实现或降级路径，最终展示以当前接口返回为准。

## 许可证

仓库当前未单独提供 `LICENSE` 文件。正式开源前建议补充许可证文件并在此处同步说明。
