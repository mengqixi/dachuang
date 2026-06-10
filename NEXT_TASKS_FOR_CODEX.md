# NEXT_TASKS_FOR_CODEX.md

## Codex 接手开发指南

> 本文件面向后续接手的 AI（如 Claude Code、Codex CLI），说明项目的当前状态、优先任务、以及如何安全地继续开发。

---

## 1. 接手后先看的文件

按顺序阅读以下文件以快速了解项目：

| 顺序 | 文件 | 目的 |
|------|------|------|
| 1 | `DEVELOPMENT_SUMMARY.md` | 完整开发记录，模块分类 |
| 2 | `CURRENT_STATUS.md` | 当前系统运行状态 |
| 3 | `app.py`（前200行） | Flask初始化、全局变量、工具函数 |
| 4 | `src/utils/data_storage.py`（前100行） | 数据库架构 |
| 5 | `src/utils/model_manager.py`（前80行） | 模型训练管理逻辑 |
| 6 | `index.html`（前80行+JS部分） | 前端页面结构 |
| 7 | `requirements.txt` | 依赖清单 |

---

## 2. 不能改的地方

以下文件/模块修改需极其谨慎，因为会影响系统核心运行：

| 文件 | 不能改的内容 | 原因 |
|------|-------------|------|
| `app.py` | 现有路由的路径和返回格式 | 前端已适配现有格式 |
| `index.html` | 现有8个页面的HTML结构和id | 页面id被JS引用 |
| `src/utils/data_storage.py` | 表结构和已有方法签名 | 其他模块依赖这些方法 |
| `src/optimization/agent.py` | QlearningAgent的核心算法 | 影响优化器决策 |
| `src/encryption/paillier.py` | 加密/解密核心逻辑 | 影响同态加密功能 |
| `restart.sh` | 启动命令 `python3 app.py` | 部署方式 |

### 可以改的地方
- 新增API路由（使用新路径）
- 新增数据库表（不影响现有表）
- 新增前端页面（用新的id）
- 扩展模型功能（不修改核心算法）

---

## 3. 应该先跑的验证命令

### 3.1 环境检查
```bash
# 检查Python版本
python3 --version  # 必须是 3.6.8

# 检查关键包
python3 -c "import numpy; print(numpy.__version__)"
python3 -c "import sklearn; print(sklearn.__version__)"
python3 -c "import gym; print(gym.__version__)"

# 检查XGBoost（可选）
python3 -c "import xgboost; print(xgboost.__version__)" || echo "XGBoost not installed"
```

### 3.2 测试命令
```bash
# 运行Q-learning单元测试
cd /root/dachuang
python3 -m unittest tests.test_optimization -v

# 运行集成测试（如果可用）
python3 -m unittest tests.test_all -v
```

### 3.3 API测试
```bash
# 健康检查
curl http://127.0.0.1:5000/api/system/health

# 模型状态
curl http://127.0.0.1:5000/api/model/status

# 检测
curl -X POST http://127.0.0.1:5000/api/detection/real \
  -H "Content-Type: application/json" \
  -d '{"data":[{"key_generation_time":0.5}]}'

# 融合检测
curl -X POST http://127.0.0.1:5000/api/ensemble/detect \
  -H "Content-Type: application/json" \
  -d '{"data":[{"key_generation_time":0.5}]}'

# 联邦学习
curl -X POST http://127.0.0.1:5000/api/federated/round \
  -H "Content-Type: application/json" \
  -d '{"epochs":3}'

# 优化
curl http://127.0.0.1:5000/api/optimization/status

# 统计
curl http://127.0.0.1:5000/api/data/statistics
```

---

## 4. 应首先测试的接口

按优先级：

| 优先级 | 接口 | 预期结果 |
|--------|------|----------|
| P0 | `GET /api/system/health` | `{"code":200,"data":{"status":"running"}}` |
| P0 | `GET /` | HTML页面（200 OK） |
| P0 | `POST /api/train/dual` | `{"code":200,"data":{"traditional":{...},"federated":{...}}}` |
| P0 | `GET /api/model/status` | `{"code":200,"data":{"is_ready":true}}` |
| P1 | `GET /api/optimization/status` | 优化器状态信息 |
| P1 | `POST /api/detection/real` | 检测结果 |
| P1 | `GET /api/federated/nodes` | 4个节点信息 |
| P2 | `GET /api/ensemble/status` | 融合检测器是否就绪 |
| P2 | `POST /api/federated/round` | 执行一轮联邦训练 |

---

## 5. 当前最高优先级任务

### P0 - 必须修复
1. **配置Kaggle API并下载UNSW-NB15**
   - 创建 `~/.kaggle/kaggle.json`
   - `kaggle datasets download -d mrk183/unswnb15`
   - 解压到 `data/datasets/UNSW-NB15/`
   - 验证文件存在

2. **安装XGBoost**
   ```bash
   pip3 install xgboost==1.5.2
   ```
   如果失败（Python 3.6兼容性问题），需要修改 `ensemble_detector.py` 回退到纯sklearn实现

### P1 - 大创验收必需
3. **实现攻击注入器** (`src/preprocess/attack_injector.py`)
   - Parameter Tampering、Key Leakage、Differential Attack、Replay Attack、Model Poisoning
   - 注入到训练数据中增强模型鲁棒性

4. **实现不平衡处理** (`src/preprocess/imbalance_handler.py`)
   - SMOTE过采样
   - ADASYN自适应合成采样

5. **完善实验管理**
   - 记录每次训练的完整指标（精度、loss、训练时间等）
   - 前端展示实验对比

### P2 - 展示增强
6. **PDF报告导出**（前端+后端）
7. **一键演示全流程脚本**
8. **修复已知的logger格式化问题**（`%s` 被字面输出）

---

## 6. 代码审查重点

### 6.1 潜在问题
- `logger.info("message %s", var)` 在 Python 3.6 中是否正确工作？
- `app.py` 中的 `ensure_data_generated()` 是否在所有路由前正确初始化？
- 前端 `toast` 函数的 `type` 参数默认值是否正确？
- 所有文件编码是否都是 UTF-8？

### 6.2 性能风险
- 大文件上传 `<input>` 没有文件大小验证
- 联邦学习训练在请求线程中执行（可能阻塞其他请求）
- 数据库查询没有分页时可能返回大量数据

### 6.3 安全风险
- 无认证/授权（所有接口公开）
- 无输入验证（用户上传的CSV/JSON直接解析）
- 文件上传保存到 `uploads/` 无校验

---

## 7. 下一步最适合做的事

### 短期（1-2小时）
1. 安装XGBoost → 测试ensemble检测器
2. 配置Kaggle API密钥 → 下载UNSW-NB15
3. 运行所有单元测试

### 中期（1-2天）
4. 实现 `attack_injector.py` 和 `imbalance_handler.py`
5. 完善前端错误处理
6. 添加PDF报告导出

### 长期（1周）
7. 将app.py拆分为蓝图
8. 添加配置文件和命令行参数
9. 编写完整的测试套件
10. 清理不再使用的旧代码

---

## 8. 关键路径图

```
Kaggle API配置 → UNSW数据下载 → 特征提取 → 联邦拆分
                                            ↓
XGBoost安装 → ├→ 三模型融合训练 → ensemble/detect 可用
              ├→ 联邦4节点训练 → federated/round 可用
              └→ ModelManager自动训练 → model/status 可用
```

---

## 9. 常见问题的解决方案

### 9.1 "ModuleNotFoundError: No module named gym"
```bash
pip3 install gym==0.21.0
# 注意：不是 gymnasium（Python 3.6 兼容）
```

### 9.2 "No module named xgboost"
```bash
pip3 install xgboost==1.5.2
# 如果失败，修改 ensemble_detector.py 的回退逻辑
```

### 9.3 "UNSW数据处理失败"
Kaggle API 未配置或数据集未下载。
手动方案：
```bash
mkdir -p data/datasets/UNSW-NB15/
# 从Kaggle网页手动下载 UNSW_NB15_training-set.csv 到该目录
```

### 9.4 前端页面空白
F12打开控制台检查JS错误。常见原因：
- `var` 被写成 `let`/`const`（浏览器兼容性）
- 调用的API路由不存在（404）
- Chart.js 版本不兼容

---

## 10. 安全操作指南

### 10.1 修改前的准备
```bash
# 备份关键文件
cp app.py app.py.bak
cp index.html index.html.bak
```

### 10.2 修改后的验证
```bash
# 1. 检查Python语法
python3 -c "compile(open('app.py','r',encoding='utf-8').read(),'app.py','exec'); print('OK')"

# 2. 检查HTML结构完整性
grep -c '</html>' index.html  # 应该有1个

# 3. 启动测试
bash restart.sh
sleep 8
curl http://127.0.0.1:5000/api/system/health

# 4. 检查日志
tail -20 logs/server.log
```

### 10.3 回滚
```bash
# 如果修改导致系统不可用
cp app.py.bak app.py
bash restart.sh
```

---

## 11. 注意事项

1. **Python 3.6 兼容性**：所有代码必须兼容 Python 3.6。特别不能使用：
   - `f"{var}"` 字符串格式化
   - `dataclass`（需要 `pip install dataclasses` 回退）
   - `dict` 保持插入顺序（Python 3.7+）
   - `async/await`（Python 3.5+ 可以但建议避免）

2. **服务器资源**：1.7GB 内存，训练时要避免：
   - 一次性加载超过 100MB 的数据
   - 多进程训练（训练在请求线程中串行执行）
   - 安装过大依赖（torch、tensorflow 等）

3. **Git提交**：当前网络无法连接 GitHub。本地 commit 已存在，网络恢复后：
   ```bash
   git push origin master
   ```
   如果 token 失效，更新 token：
   ```bash
   git remote set-url origin https://用户名:新token@github.com/mengqixi/dachuang.git
   git push origin master
   ```
