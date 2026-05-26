$hostName = "47.110.65.93"
$userName = "mqx"
$password = "Zhj20050219"
$remoteDir = "/home/mqx/dachuang"

$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential ($userName, $securePassword)

Write-Host "1. 创建远程目录..."
Invoke-Command -ComputerName $hostName -Credential $credential -ScriptBlock {
    mkdir -p $args[0]
} -ArgumentList $remoteDir

Write-Host "2. 上传 run_server_simple.py..."
$serverContent = Get-Content -Path "run_server_simple.py" -Raw
Invoke-Command -ComputerName $hostName -Credential $credential -ScriptBlock {
    Set-Content -Path ($args[0] + "/run_server_simple.py") -Value $args[1]
} -ArgumentList $remoteDir, $serverContent

Write-Host "3. 上传 complete.html..."
$htmlContent = Get-Content -Path "complete.html" -Raw
Invoke-Command -ComputerName $hostName -Credential $credential -ScriptBlock {
    Set-Content -Path ($args[0] + "/complete.html") -Value $args[1]
} -ArgumentList $remoteDir, $htmlContent

Write-Host "4. 启动服务器..."
Invoke-Command -ComputerName $hostName -Credential $credential -ScriptBlock {
    cd $args[0]
    $cmd = "nohup python run_server_simple.py > server.log 2>&1 &"
    Invoke-Expression $cmd
} -ArgumentList $remoteDir

Start-Sleep -Seconds 2

Write-Host "5. 检查状态..."
Invoke-Command -ComputerName $hostName -Credential $credential -ScriptBlock {
    ps aux | grep run_server
}

Write-Host "6. 查看日志..."
Invoke-Command -ComputerName $hostName -Credential $credential -ScriptBlock {
    cat /home/mqx/dachuang/server.log
}

Write-Host ""
Write-Host "部署完成!"
Write-Host "访问地址: http://$hostName`:5000/complete.html"