# CURRENT_STATUS.md

## 当前系统状态概览

---

## 1. 可运行性检查

### 1.1 部署状态

| 项目 | 状态 |
|------|------|
| 服务器IP | 47.110.65.93 |
| 端口 | 5000 |
| 操作系统 | CentOS 7.4.1708 |
| Python版本 | 3.6.8 |
| 内存总量 | 1.7GB |
| 当前占用 | ~600-800MB |
| 当前进程 | 运行中 |
| 启动方式 | `nohup python3 app.py > logs/server.log 2>&1 &` |
| 一键重启 | `bash restart.sh` |

### 1.2 启动验证

```bash
# 检查进程
ps aux | grep app.py
# → root 10645 4.8 11.9 python3 app.py

# 检查端口
ss -tuln | grep 5000
# → tcp LISTEN :5000

# 健康检查
curl http://47.110.65.93:5000/api/system/health
# → {"code":200,"data":{"status":"running","modules":{...}}}

# 前端
curl http://47.110.65.93:5000/ | head -5
# → <!DOCTYPE html>...
```

### 1.3 已知启动问题

| 问题 | 表现 | 原因 |
|------|------|------|
| UNSW处理失败 | 日志显示"UNSW数据处理失败: %s" | 数据集未下载 + logger格式化问题 |
| ensemble初期不可用 | `/api/ensemble/status` 返回 `ready:false` | XGBoost未安装或训练失败 |
| 数据库为空 | `data/system.db` 0字节 | 首次启动后需等待采集 |

---

## 2. 模块完成度

| 模块 | 完成度 | 可运行性 | 说明 |
|------|--------|----------|------|
| 后端框架 | 95% | ✅ 可运行 | 53个路由，统一响应格式 |
| 前端界面 | 90% | ✅ 可运行 | 8个页面，Chart.js图表 |
| 数据库 | 90% | ✅ 可运行 | 8张表，自动建表 |
| Paillier加密 | 95% | ✅ 可运行 | 核心功能完整 |
| AES对比 | 60% | ⚠️ 模拟数据 | 非真实AES |
| 攻击检测(IF+MLP) | 90% | ✅ 可运行 | 主检测接口正常 |
| 攻击检测(三模型融合) | 75% | ⚠️ 依赖XGBoost | XGBoost安装后可用 |
| XGBoost | 70% | ⚠️ 需安装 | 代码就绪但可能未安装 |
| LSTM(numpy) | 80% | ✅ 可运行 | 纯numpy实现 |
| Q-learning | 95% | ✅ 可运行 | 500状态，自动训练 |
| 联邦学习(模拟) | 85% | ✅ 可运行 | 同进程4节点模拟 |
| 联邦学习(真实) | 30% | ❌ 未实现 | 需分布式部署 |
| 数据预处理 | 60% | ⚠️ 部分就绪 | UNSW加载可用，攻击注入未实现 |
| 实验管理 | 40% | ⚠️ 基本可用 | SQLite记录，功能简单 |
| 模型版本管理 | 80% | ✅ 可运行 | 保留5版本，支持回滚 |
| 安全防护 | 0% | ❌ 未实现 | 全部未实现 |

---

## 3. 关键依赖安装状态

| 包 | 版本 | 服务器状态 | 必须/可选 |
|------|------|-----------|----------|
| Flask | 2.0.3 | ✅ 已安装 | 必须 |
| numpy | 1.19.5 | ✅ 已安装 | 必须 |
| scikit-learn | 0.24.2 | ✅ 已安装 | 必须 |
| gym | 0.21.0 | ✅ 已安装 | 必须 |
| pycryptodome | 3.19.1 | ✅ 已安装 | 必须(Pallier) |
| loguru | 0.7.2 | ✅ 已安装 | 必须 |
| pandas | 1.1.5 | ✅ 已安装 | 可选(数据集管理) |
| matplotlib | 3.3.4 | ✅ 已安装 | 可选 |
| joblib | 1.1.1 | ✅ 已安装 | 必须(模型保存) |
| xgboost | 1.5.2 | ❌ 未安装 | 可选(ensemble检测器) |
| torch | - | ❌ 不可安装 | 可选(Python 3.6不支持) |
| tensorflow | - | ❌ 不可安装 | 可选(Python 3.6不支持) |

---

## 4. 前后端接口一致性

### 4.1 已验证的接口

以下接口在前端和后端之间已验证一致：

| 前端调用 | 后端接口 | 状态 |
|----------|----------|------|
| `genData()` | `POST /api/generate_dataset` | ✅ |
| `loadDS()` | `GET /api/dataset/unsw/status` | ✅ |
| `procDS()` | `POST /api/dataset/unsw/process` | ✅ |
| `startTrain()` | `POST /api/train/dual` | ✅ |
| `loadTrainHist()` | `GET /api/train/history` | ✅ |
| `runFed()` | `POST /api/federated/round` | ✅ |
| `loadFed()`  | `GET /api/federated/nodes` | ✅ |
| `detSample()` | `POST /api/ensemble/detect` | ✅ |
| `updEnc()` | `POST /api/compare_encryption` | ✅ |
| `loadOpt()` | `GET /api/optimization/status` | ✅ |
| `toggleAuto()` | `POST /api/optimization/auto` | ✅ |
| `loadDash()` | `GET /api/data/statistics`, `GET /api/data/system_status` | ✅ |
| 状态栏 | `GET /api/data/statistics` | ✅ |

### 4.2 可能存在不一致的接口

| 前端调用 | 后端接口 | 风险 |
|----------|----------|------|
| `procDS()` 无错误处理 | `POST /api/dataset/unsw/process` | UNSW数据没下载时会报错 |
| `detFile()` 无内置样本fallback | `POST /upload` | 上传大文件可能超时 |

---

## 5. 完整API列表（53个）

见 `DEVELOPMENT_SUMMARY.md` 第5节。

---

## 6. 测试状态

| 测试文件 | 用例数 | 当前状态 |
|----------|--------|----------|
| `tests/test_optimization.py` | 19 | ✅ 全部通过 |
| `tests/test_all.py` | 28 | ⚠️ 不确定（多次修改后未重新运行） |
| `tests/test_detection.py` | - | ❌ 未维护 |
| `tests/test_encryption.py` | - | ❌ 未维护 |

---

## 7. 部署说明

### 7.1 快速启动
```bash
bash restart.sh
# 等待3-5分钟预训练完成后访问 http://47.110.65.93:5000
```

### 7.2 验证
```bash
bash verify.sh
# 或手动测试
curl http://47.110.65.93:5000/api/system/health
```

### 7.3 日志
```bash
tail -f /root/dachuang/logs/server.log
```
