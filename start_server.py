
#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
密码攻击检测与加密算法自适应优化系统
启动服务器脚本
"""
import os
import sys
import time
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler

# 确保在正确目录
os.chdir(os.path.dirname(os.path.abspath(__file__)))

# 启动简单HTTP服务器
print("=" * 70)
print("密码攻击检测与加密算法自适应优化系统")
print("=" * 70)
print()

class MyHTTPRequestHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        super().end_headers()

PORT = 5000
server = HTTPServer(('127.0.0.1', PORT), MyHTTPRequestHandler)
print(f"服务器已启动，请访问：http://127.0.0.1:5000/index.html")
print()
print("系统功能：")
print("• 数据看板 - 攻击检测趋势、攻击类型分布")
print("• 数据准备 - 敏感数据生成与Paillier同态加密")
print("• 模型训练 - FATE联邦学习与明文训练对比")
print("• 加密对比 - AES-256 vs Paillier同态加密")
print("• 数据上传 - 上传CSV/JSON进行攻击检测")
print()
print("按 Ctrl+C 停止服务器")
print()
try:
    server.serve_forever()
except KeyboardInterrupt:
    server.shutdown()
    print()
    print("服务器已停止")
