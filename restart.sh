#!/bin/bash
# 一键重启脚本 - 基于机器学习的密码攻击检测与加密算法自适应优化系统
set -e

echo "=== 正在重启系统服务 ==="

# 1. 停止现有服务
echo "[1/5] 停止现有服务..."
pkill -f "python.*app.py" 2>/dev/null || true
pkill -f "start_server.py" 2>/dev/null || true
sleep 3

# 2. 等待端口释放
echo "[2/5] 等待端口5000释放..."
for i in $(seq 1 10); do
    if ! ss -tuln | grep -q :5000; then
        break
    fi
    echo "  ...等待中 ($i/10)"
    sleep 1
done

# 3. 准备目录
echo "[3/5] 准备目录..."
mkdir -p logs data/generated data/models data/federated uploads

# 4. 启动服务
echo "[4/5] 启动服务..."
nohup python3 app.py > logs/server.log 2>&1 &
PID=$!
echo "  PID: $PID"

# 5. 等待启动并验证
echo "[5/5] 等待服务启动..."
for i in $(seq 1 30); do
    if curl -s http://127.0.0.1:5000/api/system/health > /dev/null 2>&1; then
        echo ""
        echo "=== ✅ 服务启动成功！==="
        echo "   访问地址: http://47.110.65.93:5000"
        echo "   进程PID: $PID"
        echo "   日志文件: logs/server.log"
        echo ""
        echo "后台训练正在进行（约3-5分钟），请稍后刷新页面。"
        echo "查看训练进度: tail -f logs/server.log"
        exit 0
    fi
    sleep 2
done

echo ""
echo "=== ❌ 服务启动超时，请查看日志 ==="
echo "  tail -50 logs/server.log"
exit 1
