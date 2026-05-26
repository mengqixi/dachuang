@echo off
echo ========================================
echo 启动密码攻击检测系统服务
echo ========================================

echo 启动 Flask API 服务器...
start "Flask API" cmd /k "cd /d c:\Users\Administrator\Documents\trae_projects\dachuang && python app.py"

timeout /t 3 /nobreak >nul

echo 启动静态文件服务器...
start "Static Server" cmd /k "cd /d c:\Users\Administrator\Documents\trae_projects\dachuang && python simple_server.py"

echo ========================================
echo 服务启动完成！
echo API服务: http://localhost:5000
echo 前端页面: http://localhost:8080/index.html
echo 独立版页面: http://localhost:8080/standalone.html
echo ========================================