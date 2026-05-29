#!/bin/bash
# 自动验证脚本
echo "============================================"
echo "  系统自动验证 - $(date)"
echo "============================================"

# 1. 检查进程
if ps aux | grep -q "[p]ython.*app.py"; then
    echo "[PASS] Flask服务运行中"
else
    echo "[FAIL] Flask服务未运行"
fi

# 2. 检查训练数据
if [ -f "data/generated/train.csv" ]; then
    ROWS=$(wc -l < data/generated/train.csv)
    echo "[PASS] 训练数据已生成 ($((ROWS-1))条)"
else
    echo "[INFO] 训练数据未生成（启动后自动生成）"
fi

# 3. 检查Q-table
if [ -f "data/models/q_table_qtable.npz" ]; then
    echo "[PASS] Q-learning模型已保存"
else
    echo "[INFO] Q-table未保存（启动后自动训练）"
fi

# 4. 检查端口
if ss -tuln | grep -q :5000; then
    echo "[PASS] 端口5000监听中"
else
    echo "[FAIL] 端口5000未监听"
fi

# 5. API健康检查
HEALTH=$(curl -s http://127.0.0.1:5000/api/system/health 2>/dev/null)
if echo "$HEALTH" | grep -q "running"; then
    echo "[PASS] API健康检查正常"
    echo "       Paillier: $(echo $HEALTH | grep -o '"paillier_ready":[^,]*' | cut -d: -f2)"
    echo "       检测器: $(echo $HEALTH | grep -o '"real_detector_trained":[^,]*' | cut -d: -f2)"
    echo "       Q-learning: $(echo $HEALTH | grep -o '"optimizer_trained":[^,]*' | cut -d: -f2)"
else
    echo "[FAIL] API健康检查异常"
fi

# 6. 真实检测接口
DR_CHECK=$(curl -s -X GET http://127.0.0.1:5000/api/detection/real 2>/dev/null)
if echo "$DR_CHECK" | grep -q "ready"; then
    echo "[PASS] 真实检测接口正常"
else
    echo "[INFO] 真实检测接口状态: $(echo $DR_CHECK | grep -o '"code":[0-9]*')"
fi

# 7. 内存
FREE_MEM=$(free -m | grep Mem | awk '{print $3}')
echo "[INFO] 当前内存使用: ${FREE_MEM}MB"

echo "============================================"
echo "  验证完成"
echo "============================================"
