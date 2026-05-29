#!/usr/bin/env python3
"""统一启动脚本 - 密码攻击检测与加密算法自适应优化系统"""

import os
import sys
import time

os.chdir(os.path.dirname(os.path.abspath(__file__)))

if __name__ == "__main__":
    print("=" * 60)
    print("  密码攻击检测与加密算法自适应优化系统")
    print("=" * 60)
    print()
    print("系统功能:")
    print("  [1] 实时数据看板 - 攻击检测趋势实时展示")
    print("  [2] 数据准备 - 敏感数据生成与Paillier同态加密")
    print("  [3] 模型训练 - PrimiHub联邦学习 + 模拟训练")
    print("  [4] 加密对比 - AES-256 vs Paillier性能对比")
    print("  [5] 攻击检测 - LSTM+孤立森林混合模型")
    print("  [6] 自适应优化 - DQN强化学习动态调参")
    print()

    for d in ["logs", "data", "uploads"]:
        os.makedirs(d, exist_ok=True)

    print("启动服务器: http://0.0.0.0:5000")
    print("按 Ctrl+C 停止\n")

    try:
        from app import app
        app.run(debug=False, host="0.0.0.0", port=5000, threaded=True)
    except KeyboardInterrupt:
        print("\n服务器已停止")
    except Exception as e:
        print("\n启动失败: %s" % e)
        sys.exit(1)
