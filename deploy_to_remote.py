import subprocess
import time

def run_ssh_command(cmd):
    full_cmd = f'sshpass -p "Zhj20050219" ssh mqx@47.110.65.93 "{cmd}"'
    print(f"Executing: {full_cmd}")
    result = subprocess.run(full_cmd, shell=True, capture_output=True, text=True)
    print(f"Exit code: {result.returncode}")
    if result.stdout:
        print(f"STDOUT:\n{result.stdout}")
    if result.stderr:
        print(f"STDERR:\n{result.stderr}")
    return result

print("=== 1. 检查服务器连接 ===")
run_ssh_command("echo 'Server is reachable'")

print("\n=== 2. 检查Python版本 ===")
run_ssh_command("python --version")

print("\n=== 3. 检查项目文件 ===")
run_ssh_command("ls -la /home/mqx/dachuang/")

print("\n=== 4. 查看服务器日志 ===")
run_ssh_command("cat /home/mqx/dachuang/server.log")

print("\n=== 5. 停止可能运行的进程 ===")
run_ssh_command("pkill -f run_server_simple.py 2>/dev/null; echo 'Done'")

print("\n=== 6. 启动服务器 ===")
cmd = "cd /home/mqx/dachuang && nohup python run_server_simple.py > server.log 2>&1 &"
run_ssh_command(cmd)

time.sleep(3)

print("\n=== 7. 检查服务器是否运行 ===")
run_ssh_command("ps aux | grep python")

print("\n=== 8. 查看最新日志 ===")
run_ssh_command("cat /home/mqx/dachuang/server.log")

print("\n=== 9. 测试API ===")
run_ssh_command("curl -s http://localhost:5000/api/get_stats | head -c 500")