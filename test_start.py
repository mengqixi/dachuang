import subprocess
import time
import requests

print("Starting server...")
proc = subprocess.Popen(['python', 'run_server_simple.py'], 
                       stdout=subprocess.PIPE, 
                       stderr=subprocess.PIPE,
                       cwd='c:\\Users\\Administrator\\Documents\\trae_projects\\dachuang')

time.sleep(3)

try:
    print("Testing API...")
    response = requests.get('http://localhost:8080/api/get_stats', timeout=5)
    print(f"API Response: {response.status_code}")
    print(f"Response Content: {response.text[:500]}...")
except Exception as e:
    print(f"Error: {e}")
    print("Checking server output...")
    stdout, stderr = proc.communicate(timeout=2)
    print(f"STDOUT: {stdout.decode('utf-8', errors='ignore')}")
    print(f"STDERR: {stderr.decode('utf-8', errors='ignore')}")
    proc.kill()