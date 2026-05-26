@echo off
cd /d "c:\Users\Administrator\Documents\trae_projects\dachuang"
echo ========================================
echo 密码攻击检测系统
echo ========================================
echo 正在清理占用端口...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":5000"') do taskkill /f /pid %%a 2>nul
echo 启动 Flask 集成服务器...
python integrated_server.py
pause