import paramiko
import os

host = '47.110.65.93'
port = 22
username = 'mqx'
password = 'Zhj20050219'

local_files = [
    'run_server_simple.py',
    'complete.html'
]

remote_dir = '/home/mqx/dachuang/'

try:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, port, username, password)
    
    stdin, stdout, stderr = ssh.exec_command(f'mkdir -p {remote_dir}')
    stdout.read()
    print(f"✅ 创建目录: {remote_dir}")
    
    sftp = ssh.open_sftp()
    for local_file in local_files:
        if os.path.exists(local_file):
            remote_path = remote_dir + local_file
            sftp.put(local_file, remote_path)
            print(f"✅ 上传: {local_file} -> {remote_path}")
        else:
            print(f"❌ 文件不存在: {local_file}")
    sftp.close()
    
    stdin, stdout, stderr = ssh.exec_command(f'cd {remote_dir} && nohup python run_server_simple.py > server.log 2>&1 &')
    stdout.read()
    print("✅ 启动服务器")
    
    stdin, stdout, stderr = ssh.exec_command(f'ps aux | grep run_server')
    print("进程状态:")
    print(stdout.read().decode())
    
    stdin, stdout, stderr = ssh.exec_command(f'cat {remote_dir}server.log')
    print("服务器日志:")
    print(stdout.read().decode())
    
    ssh.close()
    print("\n🎉 部署完成！")
    print(f"访问地址: http://{host}:5000/complete.html")
    
except Exception as e:
    print(f"❌ 错误: {e}")