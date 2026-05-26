import subprocess
import sys
import time
import requests

proc = subprocess.Popen([sys.executable, 'app.py'], 
                       stdout=subprocess.PIPE, 
                       stderr=subprocess.STDOUT,
                       text=True)

print("Flask starting...")
time.sleep(3)

try:
    response = requests.get('http://127.0.0.1:5000/', timeout=5)
    print(f"Status: {response.status_code}")
    print(f"Content length: {len(response.content)}")
    if b'<html' in response.content:
        print("SUCCESS: HTML received!")
    else:
        print("ERROR: HTML not found")
        print(response.content[:300])
except Exception as e:
    print(f"ERROR: {e}")
finally:
    proc.terminate()
    proc.wait()