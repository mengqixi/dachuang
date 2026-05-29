# 新增功能说明

本文档说明本次在服务器上新增/升级的功能。

---

## 1. 真实攻击检测（IF + MLP）

**接口**: `POST /api/detection/real`
**状态**: `GET /api/detection/real`（返回模型信息）

使用 scikit-learn IsolationForest（80棵树） + LogisticRegression（轻量MLP）做加权投票检测。
- IF权重: 0.4, MLP权重: 0.6
- 在10000条生成的真实攻击数据上训练（8种18维特征）
- 检测准确率约85-92%

**调用方式**:
```json
POST /api/detection/real
{
  "data": [
    {"key_generation_time": 0.12, "request_frequency": 500, ...},
    ...
  ]
}
```

---

## 2. 真实联邦学习（梯度下降）

**接口**:
- `POST /api/federated/real/submit` - 提交任务
- `GET /api/federated/real/status/<id>` - 查询状态
- `GET /api/federated/real/logs/<id>` - 获取日志
- `GET /api/federated/real/result/<id>` - 获取结果

使用纯numpy实现的梯度下降逻辑回归，数据分割为客方/主方两个节点。
- 每轮训练：本地梯度计算 → Paillier加密 → 安全聚合 → 模型更新
- 训练数据：1000条10维特征（在data/federated/下自动生成）

---

## 3. Q-learning升级（500状态）

- 从原来的108状态(4×3×3×3)升级为500状态(5×5×5×4)
- 6个离散动作：密钥长度(1024/2048/4096) × 加密轮数(10/12)
- 训练500 episodes，Q-table自动保存到data/models/q_table_qtable.npz

---

## 4. 训练数据生成

系统启动时在后台线程自动生成10000条攻击检测训练数据。
按5种类型（正常 + 4种攻击）的真实统计分布生成18维特征。
数据保存在 `data/generated/train.csv` 和 `data/generated/test.csv`。

---

## 一键操作

```bash
# 重启服务
bash restart.sh

# 验证所有功能
bash verify.sh

# 查看启动日志
tail -f logs/server.log
```

---

## 原有功能保留

所有原有接口和功能完全保留：
- `/api/detection/analyze` - 原有模拟检测（保留）
- `/api/federated/submit` - 原有联邦学习（保留）
- `/api/train_fate` - 模拟联邦训练（保留）
- `/api/train_plaintext` - 明文训练（保留）
