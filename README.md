# 密码攻击检测与隐私训练平台

本项目是一个基于 Flask + SQLite 的双端口安全分析平台，面向账号登录安全和高隐私数据训练场景，提供用户端密码攻击风险检测、原因解释、分析报告，以及管理端用户提交审核、数据处理、模型版本追踪和系统审计能力。

核心技术主线：

- AES 加密归档：保护用户上传文件的存储安全。
- Paillier 密态保护：展示敏感数值字段的密态能力，并作为安全聚合方向。
- FedAvg 四节点联邦训练：用于展示数据分散场景下的训练与聚合流程。
- 统一风险检测：融合规则评分、行为特征评分和轻量模型评分。
- 模型版本追踪：记录训练来源、指标、运行状态和可启用状态。
- 系统审计：记录平台访问、安全事件、TraceId 和访问环境信息。

## 端口与角色

| 端口 | 角色 | 页面 |
| --- | --- | --- |
| `5000` | 用户端 | 上传数据、风险检测、分析报告 |
| `5001` | 管理端 | 用户提交、数据处理、模型版本、系统审计 |

用户端负责数据接入、风险检测和报告生成。管理端负责用户提交审核、训练数据处理、模型版本管理和平台审计。训练能力服务于检测模型更新，不作为独立产品主线。

## 当前能力

### 用户端

- 上传 CSV / JSON 登录安全数据。
- 生成登录安全样本和隐私加密样本。
- 自动识别样本数、字段数、缺失率和安全字段。
- 对用户名、手机号、邮箱、密码、token、收入、证件号等敏感字段进行脱敏或派生处理。
- 执行密码攻击风险检测，输出风险等级、风险分数、攻击类型、触发因素和处置建议。
- 按风险分数展示风险排名，不单独设置风险详情页面。
- 生成可下载 Markdown 分析报告。

### 管理端

- 查看用户提交、加密归档状态、审核状态和训练状态。
- 查看当前训练数据源、公开数据集状态和四节点准备状态。
- 执行本地训练与四节点联邦训练。
- 查看当前检测模型、训练任务记录和模型版本列表。
- 查看系统审计、安全事件和最近访问记录。

### 数据集

系统支持三类数据来源：

1. 内置密码攻击训练集：`data/generated/train.csv` 和 `data/generated/test.csv`。
2. 用户上传数据：用户端上传后进入加密归档和风险检测流程。
3. 公开安全数据集：通过轻量导入脚本接入 UNSW-NB15、CIC-IDS2017、CSE-CIC-IDS2018、CIC-DDoS2019。

公开数据集不会提交到 Git。原始数据建议放在 `data/datasets/raw/`，处理后的训练样本放在 `data/datasets/processed/`。

## 统一风险结果

风险检测结果统一使用以下核心字段：

```json
{
  "is_risk": true,
  "risk_score": 0.82,
  "risk_level": "high",
  "attack_type": "疑似暴力破解",
  "confidence": 0.91,
  "action_suggestion": "强制改密并开启二次验证",
  "detection_time_ms": 12.3,
  "trigger_features": ["failed_attempts", "request_frequency"],
  "score_breakdown": {
    "failed_attempts_score": 0.25,
    "request_frequency_score": 0.20,
    "unusual_time_score": 0.10,
    "response_time_score": 0.05,
    "device_ip_score": 0.12,
    "model_score": 0.10
  },
  "reason": "登录失败次数和请求频率偏高。",
  "suggestion": "建议提醒用户改密并开启二次验证。",
  "source_dataset": "user_submission",
  "model_version": "v20260622"
}
```

风险等级为 `low`、`medium`、`high`、`critical`。检测动作建议聚焦账号安全处置，例如观察、提醒改密、强制改密、开启二次验证、人工复核。

## 数据集导入

数据源配置位于：

```text
config/dataset_sources.json
```

导入脚本位于：

```text
scripts/import_security_datasets.py
```

示例：

```bash
python scripts/import_security_datasets.py --dataset local_generated_train
python scripts/import_security_datasets.py --dataset unsw_nb15 --per-class-limit 20000
python scripts/import_security_datasets.py --dataset cic_ids2017 --per-class-limit 20000
```

导入脚本会将不同来源转换为统一训练字段：

```text
sample_id, source_dataset, attack_type, label, src_ip, dst_ip, protocol,
flow_duration, total_fwd_packets, total_bwd_packets, flow_bytes_s,
flow_packets_s, request_frequency, response_time, failed_attempts,
unusual_hour, payload_size, device_type, browser, os, username_masked
```

服务器资源有限时，脚本采用分块读取和按类别采样，避免一次性加载全量大文件。

## 快速启动

安装依赖：

```bash
pip install -r requirements.txt
```

配置管理端账号：

```bash
export ADMIN_USERNAME=root
export ADMIN_PASSWORD=root
```

Windows PowerShell：

```powershell
$env:ADMIN_USERNAME="root"
$env:ADMIN_PASSWORD="root"
```

启动服务：

```bash
python app.py
```

访问地址：

```text
用户端：http://127.0.0.1:5000/
管理端：http://127.0.0.1:5001/
```

公网部署时建议将 `ADMIN_PASSWORD` 改为强密码，并配置 HTTPS、反向代理和访问控制。

## 常用接口

用户端：

```text
POST /api/user/datasets/upload
POST /api/user/datasets/<submission_id>/analyze
GET  /api/user/reports/<submission_id>
POST /api/generate_login_security_dataset
POST /api/generate_privacy_dataset
```

管理端：

```text
GET  /api/admin/submissions
POST /api/admin/submissions/<submission_id>/archive
POST /api/admin/submissions/<submission_id>/reject
POST /api/admin/submissions/<submission_id>/mark-trainable
GET  /api/admin/datasets/sources
POST /api/admin/datasets/<source_id>/prepare
POST /api/admin/datasets/<source_id>/split-federated
GET  /api/admin/federated/nodes/detail
POST /api/admin/training/local
POST /api/admin/training/federated
GET  /api/admin/training/tasks
GET  /api/admin/model-versions
POST /api/admin/model-versions/<id>/activate
GET  /api/admin/audit/events
```

系统：

```text
GET  /api/system/health
POST /api/ensemble/detect_from_dataset
```

## 验证命令

```bash
python -m py_compile app.py src/**/*.py
python -m unittest discover tests -v
```

如需做双端口烟测：

```bash
python scripts/smoke_check.py --user-base http://127.0.0.1:5000 --admin-base http://127.0.0.1:5001 --check-admin-login
```

## Git 忽略策略

以下内容不应提交到 Git：

```text
data/system.db
data/datasets/raw/
data/datasets/processed/*.csv
data/models/
data/user_submissions/
logs/
uploads/
*.pkl
*.npy
*.npz
```

仓库只保留代码、配置、导入脚本、小型说明文件和文档。

## 平台边界

当前系统已经具备用户端风险检测、管理端训练管理、统一风险结果、轻量数据集导入和系统审计的核心闭环。真实生产部署仍需要进一步补充 HTTPS、完整账号权限、独立节点部署、外部评估集、密钥托管、审计留存策略和安全运维配置。

本项目不定位为 WAF、防火墙、漏洞扫描器或大而全网络安全平台。DDoS 和流量型攻击数据集作为可扩展方向，当前核心能力聚焦账号登录安全和密码攻击风险识别。
