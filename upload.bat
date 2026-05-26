@echo off
setlocal

set "HOST=47.110.65.93"
set "USER=mqx"
set "PASS=Zhj20050219"
set "REMOTE_DIR=/home/mqx/dachuang"

echo 1. 创建远程目录...
echo y | plink.exe -ssh %USER%@%HOST% -pw %PASS% "mkdir -p %REMOTE_DIR%"

echo.
echo 2. 上传 run_server_simple.py...
pscp.exe -pw %PASS% run_server_simple.py %USER%@%HOST%:%REMOTE_DIR%/

echo.
echo 3. 上传 complete.html...
pscp.exe -pw %PASS% complete.html %USER%@%HOST%:%REMOTE_DIR%/

echo.
echo 4. 启动服务器...
plink.exe -ssh %USER%@%HOST% -pw %PASS% "cd %REMOTE_DIR% && nohup python run_server_simple.py > server.log 2>&1 &"

echo.
echo 5. 等待服务器启动...
timeout /t 2 /nobreak > nul

echo.
echo 6. 检查状态...
plink.exe -ssh %USER%@%HOST% -pw %PASS% "ps aux | grep run_server"

echo.
echo 7. 查看日志...
plink.exe -ssh %USER%@%HOST% -pw %PASS% "cat %REMOTE_DIR%/server.log"

echo.
echo ============ 部署完成! ============
echo 访问地址: http://%HOST%:5000/complete.html