import subprocess
import base64

host = '47.110.65.93'
username = 'mqx'
password = 'Zhj20050219'

with open('run_server_simple.py', 'r', encoding='utf-8') as f:
    server_content = f.read()

with open('complete.html', 'r', encoding='utf-8') as f:
    html_content = f.read()

server_b64 = base64.b64encode(server_content.encode('utf-8')).decode()
html_b64 = base64.b64encode(html_content.encode('utf-8')).decode()

cmds = [
    f'mkdir -p /home/mqx/dachuang',
    f'cd /home/mqx/dachuang && echo "{server_b64}" | base64 -d > run_server_simple.py',
    f'cd /home/mqx/dachuang && echo "{html_b64}" | base64 -d > complete.html',
    f'cd /home/mqx/dachuang && chmod +x run_server_simple.py',
    f'cd /home/mqx/dachuang && nohup python run_server_simple.py > server.log 2>&1 &',
    f'ps aux | grep run_server',
    f'cat /home/mqx/dachuang/server.log'
]

for cmd in cmds:
    full_cmd = f"sshpass -p '{password}' ssh {username}@{host} '{cmd}'"
    print(f"执行: {cmd}")
    result = subprocess.run(full_cmd, shell=True, capture_output=True, text=True)
    if result.stdout:
        print(f"输出: {result.stdout}")
    if result.stderr:
        print(f"错误: {result.stderr}")
    print("---")