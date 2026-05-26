import subprocess
import time
import requests

print("Starting Flask server...")
proc = subprocess.Popen(['python', 'simple_integrated.py'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

time.sleep(3)

try:
    response = requests.get('http://localhost:5000/api/test')
    print(f"API Response: {response.status_code}")
    print(f"Response Content: {response.text}")
except Exception as e:
    print(f"Error: {e}")
    
    stdout, stderr = proc.communicate(timeout=1)
    print(f"STDOUT: {stdout.decode('utf-8', errors='ignore')}")
    print(f"STDERR: {stderr.decode('utf-8', errors='ignore')}")