# -*- coding: utf-8 -*-
import os
import csv
import random
import json

try:
    from http.server import HTTPServer, SimpleHTTPRequestHandler
except ImportError:
    from BaseHTTPServer import HTTPServer
    from SimpleHTTPServer import SimpleHTTPRequestHandler

class CustomHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/api/get_stats':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            data = {
                'total_attacks': 1247,
                'detection_rate': 94.5,
                'false_positives': 32,
                'avg_response_time_ms': 45.2,
                'attack_types': [
                    {'name': 'Brute Force', 'count': 456, 'color': '#EF4444'},
                    {'name': 'Side Channel', 'count': 328, 'color': '#F59E0B'},
                    {'name': 'Ciphertext Analysis', 'count': 289, 'color': '#8B5CF6'},
                    {'name': 'Key Recovery', 'count': 174, 'color': '#2563EB'}
                ],
                'monthly_trend': [
                    {'month': 'Jan', 'attacks': 89, 'detected': 85},
                    {'month': 'Feb', 'attacks': 112, 'detected': 106},
                    {'month': 'Mar', 'attacks': 98, 'detected': 93},
                    {'month': 'Apr', 'attacks': 134, 'detected': 127},
                    {'month': 'May', 'attacks': 156, 'detected': 147},
                    {'month': 'Jun', 'attacks': 178, 'detected': 168}
                ]
            }
            self.wfile.write(json.dumps(data).encode())
            return
        else:
            SimpleHTTPRequestHandler.do_GET(self)
    
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        if self.path == '/api/generate_dataset':
            try:
                data = json.loads(post_data)
                n_records = data.get('n_records', 100)
                dataset = []
                encrypted = []
                for i in range(min(n_records, 20)):
                    phone = '138' + str(random.randint(10000000, 99999999))
                    salary = random.randint(5000, 50000)
                    credit = random.randint(450, 850)
                    dataset.append({
                        'id': i+1,
                        'phone': phone,
                        'salary': salary,
                        'credit_score': credit,
                        'age': random.randint(18, 65),
                        'is_fraud': random.random() < 0.08
                    })
                    encrypted.append({
                        'id': i+1,
                        'phone_encrypted': hex(random.getrandbits(64)),
                        'salary_encrypted': hex(random.getrandbits(64)),
                        'credit_score_encrypted': hex(random.getrandbits(64)),
                        'label': random.choice([0, 1])
                    })
                result = {
                    'success': True,
                    'plaintext': dataset,
                    'encrypted': encrypted,
                    'n_records': n_records
                }
                self.wfile.write(json.dumps(result).encode())
            except:
                self.wfile.write(json.dumps({'success': False}).encode())
        
        elif self.path == '/api/train_fate':
            logs = []
            history = []
            acc = 0.6
            logs.append("Initializing FATE federated learning environment...")
            logs.append("Connecting to all parties...")
            for epoch in range(1, 11):
                acc += random.uniform(0.03, 0.06)
                if acc > 0.98:
                    acc = 0.98
                history.append({'epoch': epoch, 'accuracy': round(acc, 4), 'loss': round(1-acc, 4)})
                logs.append("Epoch " + str(epoch) + "/10 - Accuracy: " + str(round(acc, 4)))
            logs.append("Training complete!")
            self.wfile.write(json.dumps({
                'success': True,
                'logs': logs,
                'history': history,
                'results': {'final_accuracy': round(acc, 4)}
            }).encode())
        
        elif self.path == '/api/train_plaintext':
            logs = []
            history = []
            acc = 0.65
            logs.append("Initializing plaintext training environment...")
            for epoch in range(1, 11):
                acc += random.uniform(0.04, 0.07)
                if acc > 0.99:
                    acc = 0.99
                history.append({'epoch': epoch, 'accuracy': round(acc, 4), 'loss': round(1-acc, 4)})
                logs.append("Epoch " + str(epoch) + "/10 - Accuracy: " + str(round(acc, 4)))
            logs.append("Training complete!")
            self.wfile.write(json.dumps({
                'success': True,
                'logs': logs,
                'history': history,
                'results': {'final_accuracy': round(acc, 4)}
            }).encode())
        
        elif self.path == '/api/compare_encryption':
            data = json.loads(post_data)
            size = data.get('data_size_mb', 10)
            self.wfile.write(json.dumps({
                'success': True,
                'traditional': {
                    'encryption_time_ms': round(12.5 + size*0.8, 2),
                    'decryption_time_ms': round(10.2 + size*0.6, 2),
                    'throughput_mbps': round(80.0 - size*2.5, 2)
                },
                'homomorphic': {
                    'encryption_time_ms': round(45.8 + size*3.2, 2),
                    'decryption_time_ms': round(38.5 + size*2.8, 2),
                    'throughput_mbps': round(25.0 - size*0.8, 2)
                }
            }).encode())
        
        elif self.path == '/api/save_sample':
            if not os.path.exists('data'):
                os.makedirs('data')
            with open('data/sample.csv', 'w') as f:
                writer = csv.writer(f)
                writer.writerow(['id', 'phone', 'salary'])
                for i in range(100):
                    writer.writerow([i+1, '138' + str(random.randint(10000000, 99999999)), random.randint(5000, 50000)])
            self.wfile.write(json.dumps({'success': True}).encode())
        
        else:
            self.wfile.write(json.dumps({'success': False}).encode())

if __name__ == '__main__':
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    server = HTTPServer(('0.0.0.0', 5000), CustomHandler)
    print("Server running on http://localhost:5000/complete.html")
    server.serve_forever()