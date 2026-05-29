
# 基于机器学习的密码攻击检测与加密算法自适应优化系统

基于 **Isolation Forest + LogisticRegression 混合检测** 与 **表格型Q-learning 自适应优化** 的智能加密安全平台。所有算法 100% 真实数学计算，数据持久化到 SQLite，支持模型版本管理与历史追溯。

[![Python](https://img.shields.io/badge/Python-3.6%2B-blue)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.0%2B-lightgrey)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/License-Apache%202.0-green)](LICENSE)

---

## 系统架构

```
用户访问 → 浏览器 (Bootstrap 5 + Chart.js 苹果风格UI)
                ↓ HTTP API
          ┌─────────────────────┐
          │   Flask 后端 (30+)  │  ← 统一响应 {code, msg, data}
          │   SQLite 持久化      │
          └──┬──┬──┬──┬──┬──┬──┘
             ↓  ↓  ↓  ↓  ↓  ↓
          加密 检测 优化 联邦 数据集 看板
```

## 核心功能

### 🔐 数据加密
- **Paillier 同态加密**：2048位密钥，支持密态加法/标量乘法
- **AES-256**：传统对称加密基准对比
- 加密算法对比页面：加密/解密时间、吞吐量、安全级别对比

### 🛡️ 攻击检测（Isolation Forest + LogisticRegression 混合模型）
- **18维运行时特征提取**：密钥生成耗时、密文熵值、哈希碰撞次数、请求频率等
- **三模型对比**：规则检测 / 孤立森林 / 混合模型(IF 0.4 + MLP 0.6)
- **加权投票融合**：所有检测结果实时对比展示
- 4种攻击类型：暴力破解、侧信道攻击、密文分析、密钥恢复
- 检测结果永久保存到数据库，支持历史追溯

### 🔄 自适应优化（表格型Q-learning）
- **状态空间**：500离散状态（4维×5档: 风险/CPU/内存/精度）
- **动作空间**：密钥长度(1024/2048/4096) × 加密轮数(10/12)
- **平滑调整**：30秒冷却 + 限幅 ±1档 + 风险变化阈值 0.2
- **静态vs自适应对比**：实时展示效率提升百分比
- 优化历史永久保存到数据库

### 🤝 联邦学习（真实梯度下降）
- 纯numpy实现的梯度下降逻辑回归（无深度学习框架依赖）
- Paillier同态加密梯度扰动
- 数据分割为客方/主方两个节点模拟
- 训练过程输出真实 loss/accuracy 曲线

### 📊 数据看板
- 全真实数据驱动（来自SQLite数据库）
- 攻击风险与加密参数联动图（双Y轴）
- 系统性能趋势图（CPU/内存）
- 时间范围选择（1小时~7天）
- 全局状态条（1秒刷新）

### 📂 数据集管理
- CSV/JSON 数据集导入
- 自动生成10000条训练数据（9:1正常:攻击分布）
- 增量训练支持
- 模型版本管理（保留最近5个版本，支持回滚）

### 🗄️ 数据持久化
- SQLite数据库（6张核心表 + 2张扩展表）
- 系统状态每秒采集（可配置间隔）
- 180天自动清理
- 训练/检测/优化历史永久保存

## 快速开始

### 服务器部署

```bash
# 安装依赖
pip install -r requirements.txt

# 启动系统（后台）
bash restart.sh

# 或直接启动
python3 app.py
```

访问：**http://服务器IP:5000**

### 一键操作

```bash
bash restart.sh   # 重启服务
bash verify.sh    # 自动验证
tail -f logs/server.log  # 查看日志
```

## 项目结构

```
dachuang/
├── app.py                       # Flask主后端（30+ API接口）
├── index.html                   # 前端界面（苹果设计语言）
├── restart.sh / verify.sh       # 一键操作脚本
├── NEW_FEATURES.md              # 功能说明文档
├── requirements.txt             # Python依赖清单
├── data/                        # 数据目录
│   ├── generated/               # 自动生成训练数据集
│   ├── models/                  # 模型文件（含版本管理）
│   ├── datasets/                # 用户上传数据集
│   └── federated/               # 联邦学习节点数据
├── src/                         # 核心算法源码
│   ├── encryption/              # 加密模块
│   │   ├── paillier.py          #   Paillier同态加密
│   │   └── aby3_protocol.py     #   ABY3安全多方计算
│   ├── detection/               # 攻击检测模块
│   │   ├── feature_extractor.py #   18维特征提取
│   │   ├── detector.py          #   HybridDetector+RealDetector
│   │   └── models/              #   子模型
│   ├── federated/               # 联邦学习模块
│   │   └── primihub_client.py   #   真实逻辑回归+gRPC
│   ├── optimization/            # 自适应优化模块
│   │   ├── environment.py       #   Gym环境(6动作)
│   │   ├── agent.py             #   表格型Q-learning(500状态)
│   │   └── optimizer.py         #   闭环优化器(平滑调整)
│   ├── utils/                   # 工具模块
│   │   ├── data_storage.py      #   SQLite持久化层
│   │   └── model_manager.py     #   模型训练管理与版本控制
│   ├── data_generator.py        # 训练数据生成器
│   └── dataset_manager.py       # 数据集导入管理
└── tests/                       # 测试用例
    ├── test_all.py              #   综合测试（28+用例）
    └── test_optimization.py     #   Q-learning单元测试（19用例）
```

## API 接口一览（30+）

| 方法 | 路由 | 说明 |
|------|------|------|
| GET | `/` | 前端页面 |
| GET | `/api/system/health` | 健康检查 |
| | **数据准备** | |
| POST | `/api/generate_dataset` | 生成敏感数据并加密 |
| POST | `/api/compare_encryption` | AES vs Paillier对比 |
| POST | `/api/save_sample` | 保存样本CSV |
| | **模型训练** | |
| POST | `/api/train/dual` | 双模式训练（传统vs联邦） |
| GET | `/api/train/history` | 训练历史 |
| POST | `/api/model/retrain` | 重训练所有模型 |
| GET | `/api/model/status` | 模型训练状态 |
| GET | `/api/model/versions` | 模型版本列表 |
| POST | `/api/model/rollback/<v>` | 回滚模型版本 |
| GET | `/api/model/compare` | 三模型对比 |
| | **攻击检测** | |
| POST | `/api/detection/analyze` | 攻击检测分析 |
| POST | `/api/detection/real` | 真实模型检测（IF+MLP） |
| POST | `/api/detection/compare` | 三模型对比检测 |
| GET | `/api/detection/history` | 检测历史 |
| POST | `/upload` | 文件上传检测 |
| | **自适应优化** | |
| GET | `/api/optimization/status` | 优化器状态 |
| POST | `/api/optimization/update` | 触发优化 |
| POST | `/api/optimization/auto` | 自动闭环优化 |
| GET | `/api/optimization/history` | 优化历史 |
| GET | `/api/optimization/compare` | 静态vs自适应对比 |
| | **联邦学习** | |
| POST | `/api/federated/real/submit` | 提交真实联邦任务 |
| GET | `/api/federated/real/status` | 联邦任务状态 |
| GET | `/api/federated/real/logs` | 联邦训练日志 |
| | **数据集管理** | |
| POST | `/api/datasets/upload` | 上传数据集 |
| GET | `/api/datasets/list` | 数据集列表 |
| POST | `/api/datasets/<id>/train` | 用数据集训练 |
| | **数据查询** | |
| GET | `/api/data/statistics` | 综合统计数据 |
| GET | `/api/data/system_status` | 系统状态历史 |
| GET | `/api/data/attack_records` | 攻击记录 |
| GET | `/api/data/optimization_history` | 优化历史 |
| GET | `/api/export/report` | 导出运行报告 |
| GET | `/api/visitors` | 访客IP记录 |

## 技术栈

| 层级 | 技术 |
|------|------|
| **前端** | Bootstrap 5, Chart.js, Font Awesome 6, 苹果设计语言 |
| **后端** | Flask, Loguru, SQLite |
| **加密** | PyCryptodome (Paillier 2048位), AES-256 |
| **机器学习** | scikit-learn (IsolationForest, LogisticRegression) |
| **强化学习** | 表格型Q-learning (500状态×6动作, Gym) |
| **联邦学习** | 纯numpy梯度下降 + Paillier加密梯度 |
| **持久化** | SQLite (8张表, 180天自动清理) |
| **部署** | CentOS 7, Python 3.6, 1.7GB RAM |

## 技术特色

- **纯CPU运行**：所有算法可在无GPU的服务器上高效运行
- **轻量依赖**：仅依赖 scikit-learn + numpy + Flask，无需 pytorch/tensorflow
- **苹果风格UI**：Nord低饱和度配色、16px圆角、SF Pro字体
- **全链路闭环**：数据准备→模型训练→攻击检测→自适应优化→数据看板
- **版本管理**：模型版本保留+回滚，历史可追溯

## 许可证

本项目基于 Apache 2.0 许可证开源。
