# 密码攻击检测与隐私保护训练平台

> 一个基于 Flask + SQLite 的双端口安全分析原型系统：用户端用于上传登录安全数据、风险检测和报告生成；管理端用于加密归档数据管理、本地/联邦训练、模型版本和系统审计。

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Backend-Flask-lightgrey)](https://flask.palletsprojects.com/)
[![SQLite](https://img.shields.io/badge/Storage-SQLite-003B57)](https://www.sqlite.org/)

## 项目定位

本项目面向“用户提交数据后的风险分析”和“管理端隐私保护训练”两个场景，串联了数据上传、AES 加密归档、Paillier 密态字段展示、攻击检测、报告生成、本地训练、四节点联邦训练和系统审计。

系统当前采用双端口模式：

| 端口 | 角色 | 页面 |
| --- | --- | --- |
| `5000` | 用户端 | 上传数据、风险检测、分析报告 |
| `5001` | 管理端 | 数据管理、训练中心、系统审计 |

> 说明：本项目是尽可能接近实际平台流程的实验原型，不等同于完整生产级 WAF、企业安全运营平台或真实跨机构联邦学习系统。联邦训练、Paillier 密态展示、自适应优化等能力以当前代码和接口返回为准。

## 核心能力

### 1. 用户端风险分析

- 支持上传 CSV / JSON 登录安全数据。
- 支持生成登录安全样本，用于快速测试上传、检测和报告流程。
- 上传文件会进入服务端加密归档流程，管理端默认只查看摘要和脱敏预览。
- 风险检测会输出：
  - 总样本数
  - 高 / 中 / 低风险数量
  - 风险分数
  - 攻击类型
  - 触发特征
  - 中文原因解释
  - 处理建议
- 分析报告页面提供结构化展示和 Markdown 下载。

### 2. 隐私保护数据管理

- 用户上传数据归档时使用 AES 加密存储。
- 密码、手机号、用户名等敏感字段会脱敏或转换为派生特征。
- 管理端默认不展示原始明文密码。
- 支持将已审核数据标记为可训练数据源。
- 支持本地已有 `data/generated/train.csv` / `test.csv` 作为管理端初始训练数据。

### 3. 攻击检测

- 支持基于登录行为特征的风险检测。
- 支持从已处理数据集中抽样检测。
- 检测结果包含风险等级、风险分数、攻击类型、原因和建议。
- 现有检测链路包含 Isolation Forest、XGBoost 风格检测器、NumPy LSTM 等模块，具体运行能力以当前接口返回为准。

### 4. 本地训练与联邦训练

- 管理端“训练中心”合并本地训练和四节点联邦训练。
- 本地训练用于形成集中式基线。
- 四节点联邦训练使用：
  - `hospital`
  - `bank`
  - `insurance`
  - `government`
- 页面展示节点样本数、标签分布、节点指标、FedAvg 聚合结果和模型版本。
- Paillier 用于展示密态字段保护和安全聚合扩展方向，不表示完整密文训练平台。

### 5. 自适应优化

- 展示风险驱动的加密参数调整过程。
- 支持查看当前风险、密钥长度、轮数、奖励反馈和优化历史。
- Q-learning 模块用于表达参数调整策略流程。
- AES / Paillier 指标用于解释安全与性能权衡。

### 6. 系统审计

- 管理端“系统审计”展示安全事件和最近访问记录。
- 访问记录包含 IP、归属地、设备类型、系统、浏览器、请求方法、端口、路径和 TraceId。
- 安全事件包含慢接口、限流、异常访问等事件的中文原因和处理建议。
- TraceId 用于串联请求生命周期日志。

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 启动服务

```bash
python app.py
```

启动后访问：

```text
用户端：http://127.0.0.1:5000/
管理端：http://127.0.0.1:5001/
```

### 3. 管理端密码

管理端登录需要配置环境变量：

```bash
export ADMIN_USERNAME=admin
export ADMIN_PASSWORD='your-strong-password'
python app.py
```

Windows PowerShell：

```powershell
$env:ADMIN_USERNAME = "admin"
$env:ADMIN_PASSWORD = "your-strong-password"
python app.py
```

如果未配置 `ADMIN_PASSWORD`，公网访问管理端登录会被禁用。默认密码只用于本地调试。

## 常用验证命令

```bash
# 健康检查
curl http://127.0.0.1:5000/api/system/health

# 用户端：上传数据
curl -X POST http://127.0.0.1:5000/api/user/datasets/upload \
  -F "file=@sample_data.csv"

# 用户端：生成登录安全样本
curl -X POST http://127.0.0.1:5000/api/generate_login_security_dataset \
  -H "Content-Type: application/json" \
  -d "{\"n_records\":200}"

# 管理端：查看会话状态
curl http://127.0.0.1:5001/api/admin/session

# 管理端：查看提交列表
curl http://127.0.0.1:5001/api/admin/submissions

# 管理端：本地训练
curl -X POST http://127.0.0.1:5001/api/admin/training/local \
  -H "Content-Type: application/json" \
  -d "{\"limit\":10000}"

# 管理端：四节点联邦训练
curl -X POST http://127.0.0.1:5001/api/admin/training/federated \
  -H "Content-Type: application/json" \
  -d "{\"epochs\":3,\"limit\":10000}"

# 管理端：审计事件
curl "http://127.0.0.1:5001/api/admin/audit/events?limit=100"
```

## 主要接口

### 用户端接口

| 方法 | 路由 | 说明 |
| --- | --- | --- |
| `POST` | `/api/user/datasets/upload` | 上传 CSV / JSON 并加密归档 |
| `POST` | `/api/user/datasets/<submission_id>/analyze` | 对用户提交执行风险检测 |
| `GET` | `/api/user/reports/<submission_id>` | 获取风险分析报告 |
| `POST` | `/api/generate_login_security_dataset` | 生成登录安全样本 |
| `POST` | `/api/generate_privacy_dataset` | 生成隐私字段样本，用于加密展示 |

### 管理端接口

| 方法 | 路由 | 说明 |
| --- | --- | --- |
| `POST` | `/api/admin/login` | 管理员登录 |
| `POST` | `/api/admin/logout` | 管理员退出 |
| `GET` | `/api/admin/session` | 查看管理端会话状态 |
| `GET` | `/api/admin/submissions` | 查看用户提交列表 |
| `GET` | `/api/admin/submissions/<submission_id>` | 查看提交摘要和脱敏预览 |
| `POST` | `/api/admin/submissions/<submission_id>/mark-trainable` | 标记提交为可训练 |
| `POST` | `/api/admin/training/local` | 执行本地训练 |
| `POST` | `/api/admin/training/federated` | 执行四节点联邦训练 |
| `GET` | `/api/admin/training/tasks` | 查看训练任务记录 |
| `GET` | `/api/admin/model-versions` | 查看模型版本 |
| `GET` | `/api/admin/audit/events` | 查看系统审计事件 |

### 兼容接口

| 方法 | 路由 | 说明 |
| --- | --- | --- |
| `GET` | `/api/system/health` | 系统健康检查 |
| `GET` | `/api/dataset/unsw/status` | 查看 UNSW-NB15 / 本地数据源状态 |
| `POST` | `/api/dataset/unsw/process` | 处理数据集并生成四节点数据 |
| `GET` | `/api/federated/nodes` | 查看四个联邦节点状态 |
| `POST` | `/api/federated/round` | 执行一轮兼容联邦训练 |
| `POST` | `/api/ensemble/detect` | 直接传入特征执行融合检测 |
| `POST` | `/api/ensemble/detect_from_dataset` | 从已处理数据集中抽样检测 |
| `POST` | `/api/compare_encryption` | AES / Paillier 指标对比 |
| `GET` | `/api/optimization/status` | 自适应优化状态 |
| `POST` | `/api/optimization/auto` | 触发一次自动优化 |

## 项目结构

```text
dachuang/
├── app.py                         # Flask 主入口与 API
├── index.html                     # 双端口前端页面
├── requirements.txt               # Python 依赖
├── config/                        # 安全、检测、联邦等配置
├── scripts/
│   ├── download_dataset.py        # 数据集下载 / 本地数据生成脚本
│   └── smoke_check.py             # 部署后冒烟检查
├── src/
│   ├── detection/                 # 攻击检测与融合检测模块
│   ├── encryption/                # AES / Paillier 相关实现
│   ├── federated/                 # FedAvg、联邦客户端和聚合逻辑
│   ├── optimization/              # Q-learning 与自适应优化
│   ├── preprocess/                # 特征提取和联邦节点划分
│   ├── security/                  # TraceId、限流、慢接口、安全事件和访问记录
│   ├── user_submission_manager.py # 用户提交、加密归档、分析报告
│   └── utils/                     # SQLite 存储、模型管理等工具
├── data/                          # 运行期数据、模型、数据库和日志，通常不提交
├── tests/                         # 单元测试和回归测试
└── DEPLOYMENT_RUNBOOK.md          # 部署操作手册
```

## 技术栈

| 层级 | 技术 |
| --- | --- |
| 前端 | HTML、Bootstrap、Chart.js、Font Awesome |
| 后端 | Flask、Loguru、PyYAML |
| 存储 | SQLite、本地 JSON Lines 日志、本地模型文件 |
| 数据处理 | NumPy、Pandas、scikit-learn |
| 检测 | Isolation Forest、XGBoost 风格检测器、NumPy LSTM |
| 加密 | AES-256、Paillier 同态加密 |
| 联邦训练 | NumPy 逻辑回归、FedAvg、四节点本地流程 |
| 优化 | Q-learning 风险驱动参数调整 |
| 审计 | TraceId、慢接口、限流、访问 IP 记录 |

## 开发与测试

```bash
# Python 语法检查
python -m py_compile app.py src/**/*.py

# 单元测试
python -m unittest discover tests -v

# 冒烟检查
python scripts/smoke_check.py \
  --user-base http://127.0.0.1:5000 \
  --admin-base http://127.0.0.1:5001
```

PowerShell 中如果 `src/**/*.py` 不自动展开，可使用：

```powershell
$files = @("app.py") + (Get-ChildItem -Path src -Recurse -Filter *.py | ForEach-Object { $_.FullName })
python -m py_compile @files
```

## 部署说明

服务器上可直接使用：

```bash
cd /root/dachuang
git fetch origin
git reset --hard origin/master
export ADMIN_USERNAME=admin
export ADMIN_PASSWORD='your-strong-password'
nohup python3 app.py > app.log 2>&1 &
```

如果服务器无法 `git fetch`，可以按 `DEPLOYMENT_RUNBOOK.md` 使用 SFTP 同步已跟踪代码文件，再重启 Flask。

## 部署安全检查

上线或公网展示前，请先阅读并执行 [DEPLOYMENT_SECURITY_CHECKLIST.md](DEPLOYMENT_SECURITY_CHECKLIST.md)。

必须确认：

- 已配置 `FLASK_SECRET_KEY`，且不是默认值。
- 已配置 `ADMIN_USERNAME` / `ADMIN_PASSWORD`，且管理端不使用默认弱口令。
- 公网环境不启用 Flask debug。
- 上传文件限制、空文件检查、CSV/JSON 格式检查已生效。
- `data/`、`logs/`、密钥、数据库、模型文件和真实凭据不提交到 Git。
- 如面向公网长期运行，建议启用 HTTPS、限制 CORS，并使用 systemd 或等价方式托管服务。

## 数据与安全边界

- `data/` 下的数据库、模型、日志、上传文件和数据集通常不应提交到 Git。
- 用户上传文件会加密归档，但本系统仍是实验原型，不应直接承载真实生产敏感数据。
- 管理端需要强密码，并建议放在内网、VPN 或反向代理认证之后。
- Paillier 当前用于密态字段展示和安全聚合方向说明，不代表完整密文训练系统。
- 联邦训练当前以本机四节点流程为主，不代表真实跨机构部署。
- IP 归属地和设备信息主要基于请求头、User-Agent 和离线解析，不能保证完全准确。

## License

当前仓库未单独提供 `LICENSE` 文件。正式开源前建议补充许可证，并在此处同步说明。
