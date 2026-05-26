#!/usr/bin/env python3
import http.server
import socketserver
import os
import sys

PORT = 8080

class CustomHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()

    def log_message(self, format, *args):
        print(f"[{self.address_string()}] {format % args}")

if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    try:
        with socketserver.TCPServer(('127.0.0.1', PORT), CustomHandler) as httpd:
            print(f"========================================")
            print(f"密码攻击检测系统 - 静态文件服务器")
            print(f"========================================")
            print(f"服务器已启动在: http://127.0.0.1:{PORT}/index.html")
            print(f"独立版页面: http://127.0.0.1:{PORT}/standalone.html")
            print(f"API服务端口: http://127.0.0.1:5000/api/")
            print(f"按 Ctrl+C 停止服务器")
            print(f"========================================")
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n服务器已停止")
        sys.exit(0)