@echo off
cd /d "c:\Users\Administrator\Documents\trae_projects\dachuang"
echo ========================================
echo 密码攻击检测系统
echo ========================================
echo 启动静态文件服务器...
python -m http.server 8080 --bind 127.0.0.1