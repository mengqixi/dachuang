# 密码攻击检测与隐私训练平台

本项目是**大学生创新创业训练计划项目**“基于机器学习的密码攻击检测与加密算法自适应优化研究”的软件成果。平台将数据接入、加密归档、机器学习风险检测、模型训练、报告导出和安全审计整合到用户端与管理端，面向账号安全分析与隐私计算应用开发。

项目重点是攻击行为识别、联邦协同建模与面向任务的加密策略适配。公开数据检测与三路训练对比是平台的验证案例。

[项目仓库](https://github.com/mengqixi/dachuang) · [当前功能分支](https://github.com/mengqixi/dachuang/tree/codex/external-ai-redacted-analysis-20260809) · [问题反馈](https://github.com/mengqixi/dachuang/issues)

## 快速开始

当前三路对比与新版报告界面位于 `codex/external-ai-redacted-analysis-20260809` 分支，默认分支 `master` 尚未完全同步。体验以下主流程时使用：

```bash
git clone --branch codex/external-ai-redacted-analysis-20260809 https://github.com/mengqixi/dachuang.git
cd dachuang
python -m venv .venv
```

激活虚拟环境：Windows PowerShell 使用 `.\.venv\Scripts\Activate.ps1`；Linux/macOS 使用 `source .venv/bin/activate`。随后安装并启动：

```bash
python -m pip install -r requirements.txt
python app.py
```

- 用户端：[http://127.0.0.1:5000/](http://127.0.0.1:5000/)
- 管理端：[http://127.0.0.1:5001/](http://127.0.0.1:5001/)

`app.py` 是唯一正式 Web 入口。设置环境变量 `PORT` 时仅监听指定端口，管理页面使用 `/?mode=admin`，管理 API 仍需登录。其他历史 server 入口不作为启动或部署入口。

## 平台功能

| 模块 | 主要能力 |
| --- | --- |
| 用户数据接入 | CSV / JSON 上传、字段与容量校验、敏感信息识别和加密归档 |
| 风险检测 | 融合模型与行为信号共同评分，展示风险等级、触发因素及样本明细 |
| 分析报告 | 复用同一提交的分析结果，提供重点记录、处置建议和 PDF 下载 |
| 提交审核 | 管理员查看提交及结果，决定数据是否获准进入训练池 |
| 数据准备 | 固定特征转换、来源与版本管理、训练/验证分区、四逻辑节点数据组织 |
| 训练中心 | 独立更新用户端融合模型，对集中式、普通 FedAvg、Paillier FedAvg 进行同条件比较 |
| 模型版本 | 保存训练来源、模型文件、预处理版本和指标，支持运行时版本管理 |
| 系统审计 | 查询安全事件、访问记录及 TraceId，辅助定位异常行为 |

当前工作区另有高频访问告警、连续异常事件归并和审计自动刷新增强，尚未随代码提交发布；上面的克隆命令不会包含这些未提交改动。

## 使用流程

用户侧：上传文件 → 加密归档 → 本地检测 → 查看原因与重点样本 → 按需 AI 复核 → 导出报告。

管理员侧：审核训练许可 → 准备数据 → 训练并启用融合模型，或执行三路对比 → 查询模型版本与审计记录。

上传不等于授权训练，数据准备不启动训练，三路对比不自动替换用户端检测模型。

## 算法如何检测攻击

平台使用统一的 18 维特征，覆盖请求频率、失败次数、会话与响应时间、协议行为、加密统计及资源状态。字段映射与固定范围归一化贯穿准备、训练和推理，标签与输入特征分别管理。

运行时检测器位于 `src/detection/ensemble_detector.py`：

- **Isolation Forest**：识别偏离既有分布的异常样本，保存评分标尺，使单条与批量分析使用一致的评分转换。
- **监督分类器**：利用正常/攻击标签学习判别关系；支持 XGBoost，无法使用时回退到逻辑回归，实际类型写入模型清单。
- **NumPy LSTM**：对输入顺序中的邻近记录进行门控关联表征，通过输出层更新学习风险映射，提供补充评分。

模型输出再与失败登录、访问频率、异常时段、响应时间及来源设备信息融合，形成风险等级、疑似行为类型和处置建议。隐私暴露与攻击风险分别呈现，具体字段与触发因素支持人工复核。

首次启动的干净环境会生成可追溯的 bootstrap 检测模型。模型未就绪时接口返回明确状态，不用占位分数代替实际预测。

## 模型训练与三路对比

### 实际检测模型

管理端“训练并启用融合模型”使用已准备且获准训练的数据更新组件，保存模型快照与预处理版本，供用户端加载。分析缓存同时关联数据修订、模型及策略版本，保持结果来源清楚。

### 集中式与联邦学习

三路比较共用准备版本、特征定义、同构线性二分类模型、训练预算与共享留出集：

| 路径 | 训练方式 | 参数汇总 |
| --- | --- | --- |
| 普通集中式 | 在合并训练分区上优化 | 明文模型更新 |
| 普通 FedAvg | 四逻辑节点分别本地更新 | 按节点样本量加权平均 |
| Paillier FedAvg | 与普通 FedAvg 相同的本地训练 | 定点编码、加密加权求和、解密聚合结果 |

首次准备默认划分 80% 训练分区与 20% 共享留出集，节点仅使用训练分区。节点按业务 Non-IID 策略分为医疗、银行、保险、政务四类逻辑节点，样本规模与风险分布不同，当前由同一平台进程调度。

本地分类训练使用类别权重、批量梯度下降与 L2 正则化，默认更新预算为 20 轮。FedAvg 汇聚节点学习结果，共享留出集评价全局模型，节点内部指标用于诊断。

对比展示 Accuracy、Precision、Recall、F1、误报漏报、训练与推理开销，以及加密、聚合和解密阶段成本。Paillier 保护参数汇总计算，并不以提高准确率为目标，也不是对 AES 归档密文直接训练。

训练请求进入 SQLite 队列，由后台工作线程顺序执行，页面查询进度。运行时融合模型与三路线性模型分别管理。

### 数据复用与增量准备

- 通过 `dataset_revision`、`preparation_id` 与预处理版本关联数据和训练记录。
- 数据未变化时复用准备结果；获准训练的用户池仅新增提交时，可增量提取新增记录并保持既有共享留出集冻结。
- 撤销授权、来源或结构变化等情况触发全量重建。
- 保存特征分布与标签比例漂移信息，供训练前复核。
- 单次准备最多处理 50,000 行，超过上限时在元数据中明确截取范围。

## 加密保护与按需 AI

文件归档使用 **AES-256-GCM**，用于机密性与完整性保护。password、token 等敏感字段先转换成必要的派生信号；分析和训练按授权临时解密，完成后清理临时文件。

安全聚合使用独立的 **Paillier** 密钥，默认 2048 位。四节点的 19 个线性参数经 `1e6` 定点量化后加密，在密文上按样本量加权求和，只解密最终聚合结果。保存实际阶段耗时与参数差异。当前单进程调度并不构成对平台进程本身隐藏节点明文参数的安全边界。

AI 是可选辅助功能，**只有主动点击相关按钮才发起外部调用**。相同版本已保存的结果可以直接读取，查看历史记录不产生新的调用。

- 外部接口仅接收脱敏统计与归一化信号，不发送账号、IP、文件名或原始记录。
- 保留本地结论与 AI 意见，AI 不修改模型权重，也不降低本地高风险判定。
- AI 未启用、未配置或调用失败时，本地检测、训练与报告继续运行。
- 管理端提供小型设置弹窗，API 密钥加密保存且只返回掩码；公网提交新密钥要求 HTTPS。

## 配置与部署

本机开发默认账号 `root / root` 仅允许从本地地址登录。对外部署必须设置独立强密码与会话密钥。PowerShell 示例：

```powershell
$env:FLASK_SECRET_KEY = 'replace-with-a-random-secret'
$env:ADMIN_USERNAME = 'admin'
$env:ADMIN_PASSWORD = 'replace-with-a-strong-password'
python app.py
```

项目**不会自动读取 .env 文件**，请通过进程环境、systemd、Docker Compose 或密钥管理服务注入配置，说明见 [.env.example](.env.example)。使用 HTTPS 时设置 `SESSION_COOKIE_SECURE=true`；跨域仅允许配置精确可信源。

可调配置包括数值线程、归档容量上限、磁盘空闲下限及聚合密钥长度。容量保护只拒绝新上传，不自动删除已有数据。数据库、归档、密钥、模型和日志不应提交到仓库。

Docker 只启动主应用。Linux/macOS shell 示例：

```bash
cd docker
FLASK_SECRET_KEY='replace-with-a-random-secret' \
ADMIN_USERNAME='admin' \
ADMIN_PASSWORD='replace-with-a-strong-password' \
docker compose up --build
```

Compose 挂载项目的 `data/` 与 `logs/`。部署前阅读 [部署 Runbook](DEPLOYMENT_RUNBOOK.md) 与 [安全检查清单](DEPLOYMENT_SECURITY_CHECKLIST.md)，不要使用历史自动上传或批量停止进程的脚本。

## 开发与验证

```bash
python validate_project.py
python -m unittest discover tests -v
node tests/test_training_triplet_ui.js
node tests/test_report_download_ui.js
```

额外 Flask 集成测试需设置 `FLASK_TEST=1`。服务启动后，可进行只读冒烟检查：

```bash
python scripts/smoke_check.py --user-base http://127.0.0.1:5000 --admin-base http://127.0.0.1:5001
```

请在本地隔离环境验证频率告警，不向线上网站发起高频请求。上述命令是验证入口，不表示可选集成测试在每种环境下都会自动执行。

## 项目结构

```text
app.py                              Flask 主入口与 API 编排
index.html                          用户端与管理端界面
src/preprocess/                     特征处理、数据准备与节点切分
src/detection/ensemble_detector.py   运行时融合检测与模型快照
src/federated/                      本地优化、FedAvg 与安全聚合
src/user_submission_manager.py      上传、归档、分析与训练池
src/security/                       请求追踪、安全事件与访问审计
src/utils/data_storage.py           SQLite 业务记录
tests/                              单元、集成与前端检查
docs/                               技术说明
data/、logs/                        本地运行状态，不应提交
```

ModelManager、PrimiHub/FATE、ABY3 和旧检测器保留用于兼容或扩展，不是当前用户端检测主链路。

## 交流与使用说明

欢迎通过 [Issues](https://github.com/mengqixi/dachuang/issues) 反馈问题。提交修改时请附复现步骤与相关测试，并移除真实账号、密钥和用户数据。

本项目用于大学生创新创业训练计划的研究与软件开发。仓库目前没有声明项目级开源许可证；复制、修改或分发前请联系作者确认授权，依赖与附带资源遵循各自许可证。
