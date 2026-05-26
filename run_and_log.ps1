$p = Start-Process -FilePath python -ArgumentList "app.py" -NoNewWindow -PassThru -RedirectStandardOutput "output.log" -RedirectStandardError "error.log"
Start-Sleep -Seconds 5
if (!$p.HasExited) {
    Write-Host "Flask is running with PID: $($p.Id)"
    Stop-Process -Id $p.Id -Force
} else {
    Write-Host "Flask exited with code: $($p.ExitCode)"
}
if (Test-Path "output.log") {
    Write-Host "=== STDOUT ==="
    Get-Content "output.log" | Select-Object -First 20
}
if (Test-Path "error.log") {
    Write-Host "=== STDERR ==="
    Get-Content "error.log" | Select-Object -First 20
}