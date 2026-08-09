# 密码攻击检测与隐私训练平台

这是一个 Flask 原型平台，包含用户数据上传与风险分析、训练数据源准备、本地融合模型训练、四节点 FedAvg 联邦训练、加密归档和安全审计页面。

当前唯一正式 Web 入口是 `app.py`。根目录中的 `final_server.py`、`integrated_server.py`、`simple_server.py` 等文件是历史原型，不应作为启动或部署入口；仓库中的启动脚本均已统一到 `app.py`。

## 系统实际结构

```text
CSV / JSON / 内置数据源
          │
          ▼
固定 18 维字段提取与归一化
(security-fixed-ranges-v1)
          │
          ├──────────────► 本地训练 ─► 运行时融合模型 ─► 用户风险检测
          │                              IF + 分类器 + NumPy LSTM
          │
          ▼
准备版本 preparation_id
          │
          ▼
按标签分层、确定性切分
          │
          ├─ hospital
          ├─ bank
          ├─ insurance
          └─ government
                 │
                 ▼
           四节点本地训练
                 │
                 ▼
              FedAvg
        （独立联邦训练追踪）
```

四个节点是同一份准备数据的模拟分片，不是四家真实机构，也不是四套独立原始数据。联邦聚合权重与用户端运行时融合模型分开保存；联邦训练不会自动替换用户端检测模型。

## 数据处理到底处理什么

数据处理遵循以下固定规则：

- 选择一个当前数据源，计算 `dataset_revision` 和 `preparation_id`。
- 数据源、处理上限和预处理版本都未变化时，直接复用已处理数组与四节点文件。
- 检测到变化时，对当前数据源进行全量重建，不做逐条增量追加。
- 单次最多处理 50,000 行；源数据超过上限时只处理前 50,000 行，并在元数据中标记 `first_limit_rows`。
- 处理只负责特征转换和节点切分，不会暗中启动模型训练。
- 准备结果、训练记录和模型版本均携带数据修订或准备版本，避免不同数据源的节点和权重串线。

因此，“同步当前源到四节点”不是每次都重复处理全部文件：未变化时复用；发生变化时按上限重建当前源，而不是只追加新增行。

## 系统有哪些模型

### 1. 运行时融合模型

用户风险检测实际调用 `src/detection/ensemble_detector.py`：

- Isolation Forest：无监督异常分量；风险分数使用持久化标尺，不随一次请求中的其他样本变化。
- XGBoost 或逻辑回归：有监督分类分量；未安装 XGBoost 时明确回退到逻辑回归。
- NumPy LSTM：轻量时序分量。

干净环境会用内置数据生成一个可追溯的 bootstrap 模型。管理端本地训练会生成可切换的运行时模型快照。模型未就绪时接口返回 503，不使用伪造分数冒充模型结果。

### 2. 四节点 FedAvg 模型

每个节点在自己的准备分片上训练线性二分类权重，服务端按节点样本数加权聚合。数据准备版本变化时，联邦轮次、历史和全局权重会重置。页面上的准确率是各节点留出验证指标的样本加权值，不是独立外部测试集指标。

### 3. 兼容性与研究模块

`ModelManager`、PrimiHub/FATE、ABY3 和旧检测器仍保留给历史 API、兼容验证或论文说明，但不等同于当前用户端运行时模型。Paillier 页面展示参数加密与聚合方向；当前 FedAvg 权重链路仍是明文数值聚合，API 会明确返回 `secure_aggregation: false`，不会宣称已经实现完整密文训练。

## 用户上传数据

- 仅支持 CSV / JSON，并限制文件大小、行数和列数。
- password、token 等敏感字段先转成长度、强度、是否存在等派生特征，再进入归档。
- 新提交的持久副本使用 AES-256-GCM 加密；明文临时文件在索引提交前删除。
- 分析或训练时临时解密，读取完成后立即删除临时文件。
- 管理员审核并标记“可训练”后，提交才会进入训练池。
- 分析结果分别给出隐私暴露风险和攻击风险；隐私分数来自可审计字段策略，不冒充训练模型输出。
- 相同数据修订、模型版本、预处理版本、策略版本和行数上限会复用分析缓存。
- 用户端使用 `POST /api/user/datasets/<submission_id>/analyze`，管理端使用受会话保护的 `POST /api/admin/submissions/<submission_id>/analyze`，两者调用同一分析内核。

## 可选 AI 辅助判定

平台始终以本地检测模型为主。AI 不会自动调用；用户或管理员只有主动点击“使用 AI 辅助判定”时才产生一次外部请求，相同数据、本地模型版本和 AI 配置未变化时复用缓存。

- 用户数据先由本地模型生成风险分数、等级和触发信号；AI 只接收聚合统计与归一化后的重点风险信号，不接收账号、IP、文件名、原始字段值或原始数据行。
- 页面同时保留“本地判定 / AI 判定 / 综合判定”。综合策略以本地模型为主：AI 可以确认结果或提高人工复核等级，但不能降低本地高风险，也不会修改本地风险分数和模型权重。
- 管理端完成同一数据准备版本的普通训练与四节点联邦训练后，可主动使用 AI 分析两种模型的指标差异、安全边界和适用性。指标范围不一致时，系统会明确标记不可直接排名。
- 当前四节点位于同一台服务器，是平台内的数据分区训练；实际模型权重仍由 FedAvg 聚合。Paillier 页面按当前参数量估算接入加密、密态求和与解密的成本，并明确标记为估算，不冒充真实密态聚合或完整密态训练链路。
- AI 未配置、未启用、超时或达到调用上限时，本地检测、加密归档、普通训练、联邦训练和报告均继续正常运行。

管理端“用户提交”页提供小型 AI 接口设置弹窗，不新增独立功能栏目。密钥保存后仅返回掩码，后端使用 AES-256-GCM 加密存储；公网页面只有在 HTTPS 下才允许提交新密钥。也可使用 `.env.example` 中列出的服务器环境变量配置。

## 启动

安装依赖：

```bash
python -m pip install -r requirements.txt
```

启动唯一正式入口：

```bash
python app.py
```

默认地址：

- 用户端：`http://127.0.0.1:5000/`
- 管理端：`http://127.0.0.1:5001/`

设置 `PORT` 时只启动该单端口；否则同一 Flask 应用同时监听 5000 和 5001。

## 管理端与安全配置

本机开发时，默认 `root / root` 仅允许通过 `localhost`、`127.0.0.1` 或 `::1` 登录。公网环境没有配置强密码时，默认账号会被禁用。

生产环境必须通过进程环境、systemd、Docker Compose 或密钥管理服务设置：

```bash
export FLASK_SECRET_KEY='随机强密钥'
export ADMIN_USERNAME='admin'
export ADMIN_PASSWORD='强密码'
export SESSION_COOKIE_SECURE='true'
python3 app.py
```

项目不会自动读取 `.env` 文件。`CORS_ALLOWED_ORIGINS` 仅接受逗号分隔的精确可信源；未配置时使用同源策略，不返回通配符 CORS。

当前 2GB / 40GB 服务器建议保留以下低资源配置：

```bash
export DACHUANG_NUMERIC_THREADS='1'
export DACHUANG_ARCHIVE_QUOTA_MB='8192'
export DACHUANG_MIN_FREE_DISK_MB='2048'
```

数值线程默认即为 1；密文归档达到 8GB 或整盘空闲空间低于 2GB 时，系统只拒绝新上传，不会自动删除本项目或其他服务的数据。

Flask 会在未提供 `FLASK_SECRET_KEY` 时生成并持久化本机随机会话密钥。仓库根目录、源码、数据库、密钥和配置文件不会作为 Flask 静态资源暴露。

## Docker

Compose 只启动当前实际需要的 Flask 应用，不再默认启动未被主链路使用的 MySQL、Redis 或 PrimiHub 容器。

```bash
cd docker
FLASK_SECRET_KEY='随机强密钥' \
ADMIN_USERNAME='admin' \
ADMIN_PASSWORD='强密码' \
docker compose up --build
```

数据和日志分别挂载到项目的 `data/`、`logs/`。Docker 构建上下文通过 `.dockerignore` 排除数据库、上传归档、密钥、模型和日志。

## 验证

结构与语法检查：

```bash
python validate_project.py
```

完整测试：

```bash
python -m unittest discover tests -v
```

启用额外 Flask 集成测试：

```bash
FLASK_TEST=1 python -m unittest discover tests -v
```

服务启动后的只读冒烟检查：

```bash
python scripts/smoke_check.py \
  --user-base http://127.0.0.1:5000 \
  --admin-base http://127.0.0.1:5001
```

## 主要目录

```text
app.py                              正式 Flask 入口与 API 编排
index.html                          当前用户端/管理端单页界面
src/preprocess/                     18 维特征、固定归一化、四节点切分
src/detection/ensemble_detector.py  用户端运行时融合模型与版本快照
src/federated/                      四节点客户端、FedAvg 与可选研究适配器
src/user_submission_manager.py      上传校验、脱敏、加密归档、分析与训练池
src/security/                       Trace ID、限流、慢接口和安全事件
src/utils/data_storage.py           SQLite 业务记录
tests/                              单元测试与 Flask 集成测试
data/                               运行数据、模型、节点文件和加密归档（不入库）
```

线上部署前请先阅读 `DEPLOYMENT_RUNBOOK.md` 和 `DEPLOYMENT_SECURITY_CHECKLIST.md`。旧自动上传/远程重启脚本已停用，因为它们曾包含明文凭据并使用宽泛进程操作。
