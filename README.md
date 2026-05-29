
# 基于机器学习的密码攻击检测与加密算法自适应优化系统

基于机器学习（LSTM+孤立森林混合模型）的密码攻击检测系统，集成 **PrimiHub 联邦学习** 与 **DQN 强化学习自适应优化** 的智能加密安全平台。

[![Python](https://img.shields.io/badge/Python-3.6%2B-blue)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.0%2B-lightgrey)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/License-Apache%202.0-green)](LICENSE)

---

## 系统架构

```
用户访问
    │
    ▼
┌────────────────────────────────────────────────┐
│            Bootstrap 5 + Chart.js              │  ← 浅色玻璃拟态UI
│            (index.html)                        │
└──────────┬──────────────────────────┬──────────┘
           │ HTTP API (fetch)         │ WebSocket
           ▼                          ▼
┌────────────────────────────────────────────────┐
│           Flask 后端 (app.py)                  │  ← 22+ API接口
│   统一响应格式: {code, msg, data}              │
└──┬────────┬────────┬────────┬────────┬─────────┘
   │        │        │        │        │
   ▼        ▼        ▼        ▼        ▼
┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────────┐
│ 加密  │ │ 检测  │ │ 优化  │ │联邦学习│ │ 数据集   │
│Paillier│ │LSTM+IF│ │ DQN  │ │PrimiHub│ │ 管理     │
│AES-256│ │混合模型│ │强化学习│ │联邦逻辑│ │ 导入/训练│
└──────┘ └──────┘ └──────┘ └──────┘ └──────────┘
```

## 核心功能

### 🔐 数据加密
- **Paillier 同态加密**：支持加密状态下直接计算，2048位密钥
- **AES-256**：传统对称加密基准对比
- 支持密文加法/乘法同态运算

### 🛡️ 攻击检测（LSTM + 孤立森林混合模型）
- **18维运行时特征提取**：密钥生成耗时、密文熵值、哈希碰撞次数、请求频率等
- **孤立森林**：检测静态点异常（scikit-learn）
- **LSTM**：检测时序异常模式（PyTorch/TensorFlow）
- **加权投票融合**：IF权重0.4 + LSTM权重0.6，输出异常概率和置信度
- 支持4种攻击类型：暴力破解、侧信道攻击、密文分析、密钥恢复

### 🔄 自适应优化（DQN强化学习）
- **状态空间**：攻击风险等级 + CPU/内存使用率 + 模型精度
- **动作空间**：密钥长度(1024/2048/4096) × 加密轮数(10/12/14)
- **奖励函数**：综合安全性 + 效率 + 精度的加权评分
- 支持 Stable-Baselines3 和回退 PyTorch 两种实现

### 🤝 联邦学习（PrimiHub）
- 支持2节点联邦逻辑回归
- 密态安全聚合（Secure Aggregation）
- 密态训练精度与明文训练差异 < 1%
- 训练日志实时推送到前端

### 📊 数据看板
- 攻击统计总数/检测率/误报数/响应时间实时展示
- 近6个月攻击检测趋势图（渐变面积图）
- 攻击类型分布环形图
- 访客IP实时监控
- 每5秒自动刷新

### 📂 数据集管理
- 支持 CSV/JSON 数据集导入
- 自动识别标签列和特征列
- 数据集预览和统计
- 一键用数据集增量训练模型
- 训练历史记录保存

### 🌐 访客监控
- 实时记录访问IP、请求路径、时间、User-Agent
- 独立IP统计
- 最新50条记录实时显示

## 快速开始

### 本地运行

```bash
# 安装依赖
pip install -r requirements.txt

# 启动系统
python start_server.py

# 或直接启动
python app.py
```

### 访问系统

打开浏览器访问：**http://127.0.0.1:5000**


### Docker 部署（含 PrimiHub 双节点）

```bash
cd docker
docker-compose up -d
```

## 项目结构

```
dachuang/
├── app.py                       # Flask主后端（29个API接口）
├── index.html                   # 前端界面（浅色玻璃拟态）
├── start_server.py              # 统一启动脚本
├── requirements.txt             # Python依赖清单
├── sample_data.csv              # 示例数据集
├── config/                      # 配置文件
│   ├── config.yaml
│   └── logging.yaml
├── data/                        # 数据目录
├── docker/                      # Docker部署
│   ├── docker-compose.yml       # 含PrimiHub双节点
│   ├── Dockerfile
│   └── init.sql
├── src/                         # 核心算法源码
│   ├── encryption/              # 加密模块
│   │   ├── paillier.py          #   Paillier同态加密
│   │   └── aby3_protocol.py     #   ABY3安全多方计算
│   ├── detection/               # 攻击检测模块
│   │   ├── feature_extractor.py #   18维特征提取
│   │   ├── attack_detector.py   #   LSTM+IF混合检测器
│   │   ├── detector.py          #   加权投票混合模型
│   │   └── models/              #   子模型
│   │       ├── isolation_forest.py
│   │       └── lstm_detector.py
│   ├── federated/               # 联邦学习模块
│   │   └── primihub_client.py   #   PrimiHub客户端封装
│   ├── optimization/            # 自适应优化模块
│   │   ├── environment.py       #   Gymnasium强化学习环境
│   │   ├── agent.py             #   DQN智能体
│   │   ├── optimizer.py         #   闭环优化器
│   │   └── fallback_dqn.py      #   回退DQN实现
│   ├── data_generator.py        # 虚拟数据生成器
│   └── dataset_manager.py       # 数据集管理器
├── templates/                   # 前端模板
└── tests/                       # 测试用例
    ├── test_all.py              #   综合测试（20+用例）
    ├── test_detection.py
    ├── test_encryption.py
    └── test_optimization.py
```

## API 接口一览

| 方法 | 路由 | 说明 |
|------|------|------|
| GET | `/` | 返回前端页面 |
| GET | `/api/get_stats` | 看板统计数据 |
| POST | `/api/generate_dataset` | 生成敏感数据并加密 |
| POST | `/api/save_sample` | 保存样本CSV |
| POST | `/api/compare_encryption` | AES vs Paillier对比 |
| POST | `/api/train_fate` | 模拟联邦训练 |
| POST | `/api/train_plaintext` | 明文对比训练 |
| POST | `/api/federated/submit` | 提交PrimiHub联邦任务 |
| GET | `/api/federated/status/<id>` | 联邦任务状态 |
| GET | `/api/federated/logs/<id>` | 实时训练日志 |
| GET | `/api/federated/result/<id>` | 联邦任务结果 |
| POST | `/api/detection/analyze` | 攻击检测分析 |
| POST | `/upload` | 文件上传检测 |
| GET | `/api/optimization/status` | 优化器状态 |
| POST | `/api/optimization/update` | 触发优化 |
| POST | `/api/optimization/train` | 训练DQN智能体 |
| POST | `/api/optimization/auto` | 自动闭环优化 |
| GET | `/api/datasets/list` | 数据集列表 |
| POST | `/api/datasets/upload` | 上传数据集 |
| GET | `/api/datasets/<id>` | 数据集详情 |
| POST | `/api/datasets/<id>/train` | 用数据集训练 |
| GET | `/api/visitors` | 访客IP记录 |
| GET | `/api/system/health` | 健康检查 |

## 技术栈

| 层级 | 技术 |
|------|------|
| **前端** | Bootstrap 5, Chart.js, Font Awesome 6, Inter字体 |
| **后端** | Flask, Loguru, 原生fetch API |
| **加密** | PyCryptodome (Paillier), AES-256, ABY3 |
| **机器学习** | scikit-learn, PyTorch (可选), TensorFlow (可选) |
| **强化学习** | Stable-Baselines3 / 回退PyTorch DQN, Gymnasium |
| **联邦学习** | PrimiHub (Apache 2.0) |
| **部署** | Docker, Docker Compose, CentOS 7 |

## 参考开源项目

- [PrimiHub](https://github.com/primihub/primihub) - 联邦学习底层框架（Apache 2.0）

## 许可证

本项目基于 Apache 2.0 许可证开源。
