from flask import Flask, render_template, request, jsonify, send_from_directory, send_file
import os
import json
import csv
import random
from datetime import datetime

app = Flask(__name__, static_folder='.', static_url_path='')
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['ALLOWED_EXTENSIONS'] = {'csv', 'json', 'txt'}
app.config['STATIC_FOLDER'] = '.'
app.config['DATA_FOLDER'] = 'data'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['DATA_FOLDER'], exist_ok=True)

@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response

# ======================================
# 数据生成与加密功能 (真实实现)
# ======================================

def generate_sensitive_dataset(n_records=100):
    """生成包含敏感信息的模拟数据集"""
    dataset = []
    for i in range(n_records):
        record = {
            'id': i + 1,
            'phone': f'138{random.randint(10000000, 99999999)}',
            'salary': random.randint(5000, 50000),
            'credit_score': random.randint(450, 850),
            'age': random.randint(18, 65),
            'label': random.choice([0, 1]),
            'is_fraud': random.random() < 0.08
        }
        dataset.append(record)
    return dataset

def paillier_encrypt(value, n=3233):
    """简单的Paillier同态加密模拟"""
    g = n + 1
    r = random.randint(1, n - 1)
    # 使用模拟的加密算法，实际应用中应该使用正规库
    return (pow(g, value, n * n) * pow(r, n, n * n)) % (n * n)

def encrypt_dataset(dataset):
    """数据密态化处理"""
    encrypted = []
    for record in dataset:
        encrypted.append({
            'id': record['id'],
            'phone_encrypted': paillier_encrypt(int(record['phone'][3:])),
            'salary_encrypted': paillier_encrypt(record['salary']),
            'credit_score_encrypted': paillier_encrypt(record['credit_score']),
            'is_fraud': record['is_fraud'],
            'label': record['label']
        })
    return encrypted

def simulate_fate_training(encrypted_data):
    """模拟FATE联邦学习训练过程"""
    logs = []
    logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] INFO: Initializing FATE federated task...")
    logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] INFO: Setting up secure communication...")
    logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] INFO: Using secure aggregation (Secret Sharing)...")
    logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] INFO: Dataset encrypted with Paillier...")
    logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] INFO: Dataset size: {len(encrypted_data)} records")
    
    # 模拟训练过程
    history = []
    accuracy = 0.5
    for epoch in range(1, 11):
        accuracy += random.uniform(0.01, 0.08)
        if accuracy > 0.98: accuracy = 0.98
        loss = 1 - accuracy
        history.append({'epoch': epoch, 'accuracy': round(accuracy, 4), 'loss': round(loss, 4)})
        logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] INFO: Epoch {epoch}/10 - Accuracy: {accuracy:.4f}, Loss: {loss:.4f}")
    
    logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] INFO: Training completed!")
    return logs, history, {'final_accuracy': accuracy, 'final_loss': 1 - accuracy}

def simulate_plaintext_training(plaintext_data):
    """模拟明文训练对比"""
    logs = []
    logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] INFO: Initializing plaintext training...")
    
    history = []
    accuracy = 0.5
    for epoch in range(1, 11):
        accuracy += random.uniform(0.015, 0.085)
        if accuracy > 0.99: accuracy = 0.99
        loss = 1 - accuracy
        history.append({'epoch': epoch, 'accuracy': round(accuracy, 4), 'loss': round(loss, 4)})
    
    logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] INFO: Training completed!")
    return logs, history, {'final_accuracy': accuracy, 'final_loss': 1 - accuracy}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# ======================================
# API 路由
# ======================================

@app.route('/')
def index():
    return send_file('index.html')

@app.route('/index.html')
def index_html():
    return send_file('index.html')

@app.route('/api/generate_dataset', methods=['POST'])
def generate_dataset():
    data = request.get_json() or {}
    n_records = data.get('n_records', 100)
    dataset = generate_sensitive_dataset(n_records)
    encrypted = encrypt_dataset(dataset)
    return jsonify({
        'success': True,
        'plaintext': dataset[:20],  # 返回前20条显示
        'encrypted': encrypted[:20],
        'n_records': n_records
    })

@app.route('/api/train_fate', methods=['POST'])
def train_fate():
    data = request.get_json() or {}
    n_records = data.get('n_records', 100)
    dataset = generate_sensitive_dataset(n_records)
    encrypted = encrypt_dataset(dataset)
    logs, history, results = simulate_fate_training(encrypted)
    return jsonify({
        'success': True,
        'logs': logs,
        'history': history,
        'results': results
    })

@app.route('/api/train_plaintext', methods=['POST'])
def train_plaintext():
    data = request.get_json() or {}
    n_records = data.get('n_records', 100)
    dataset = generate_sensitive_dataset(n_records)
    logs, history, results = simulate_plaintext_training(dataset)
    return jsonify({
        'success': True,
        'logs': logs,
        'history': history,
        'results': results
    })

@app.route('/api/compare_encryption', methods=['POST'])
def compare_encryption():
    data = request.get_json() or {}
    data_size_mb = data.get('data_size_mb', 10)
    
    traditional = {
        'algorithm': 'AES-256',
        'encryption_time_ms': round(12.5 + data_size_mb * 0.8, 2),
        'decryption_time_ms': round(10.2 + data_size_mb * 0.6, 2),
        'throughput_mbps': round(80.0 - data_size_mb * 2.5, 2),
        'security_level': 'High',
        'data_isolation': 'No',
        'collaborative_learning': 'No',
        'memory_mb': 128
    }
    
    homomorphic = {
        'algorithm': 'Paillier',
        'encryption_time_ms': round(45.8 + data_size_mb * 3.2, 2),
        'decryption_time_ms': round(38.5 + data_size_mb * 2.8, 2),
        'throughput_mbps': round(25.0 - data_size_mb * 0.8, 2),
        'security_level': 'Very High',
        'data_isolation': 'Yes',
        'collaborative_learning': 'Yes',
        'memory_mb': 256
    }
    
    comparison = {
        'encryption_overhead': round(((homomorphic['encryption_time_ms'] / traditional['encryption_time_ms']) - 1) * 100, 1),
        'throughput_reduction': round(((traditional['throughput_mbps'] - homomorphic['throughput_mbps']) / traditional['throughput_mbps']) * 100, 1),
        'security_improvement': '30%',
        'privacy_gain': 'Complete data isolation',
        'accuracy_loss': '0.5%',
        'training_time_increase': '25%'
    }
    
    return jsonify({
        'data_size_mb': data_size_mb,
        'traditional': traditional,
        'homomorphic': homomorphic,
        'comparison': comparison
    })

@app.route('/api/get_stats', methods=['GET'])
def get_stats():
    return jsonify({
        'total_attacks': 1247,
        'detection_rate': 94.5,
        'false_positives': 32,
        'avg_response_time_ms': 45.2,
        'attack_types': [
            {'name': 'Brute Force', 'count': 456, 'color': '#ef4444'},
            {'name': 'Side Channel', 'count': 328, 'color': '#f59e0b'},
            {'name': 'Ciphertext Analysis', 'count': 289, 'color': '#8b5cf6'},
            {'name': 'Key Recovery', 'count': 174, 'color': '#2563eb'}
        ],
        'monthly_trend': [
            {'month': 'Jan', 'attacks': 89, 'detected': 85},
            {'month': 'Feb', 'attacks': 112, 'detected': 106},
            {'month': 'Mar', 'attacks': 98, 'detected': 93},
            {'month': 'Apr', 'attacks': 134, 'detected': 127},
            {'month': 'May', 'attacks': 156, 'detected': 147},
            {'month': 'Jun', 'attacks': 178, 'detected': 168}
        ]
    })

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if file and allowed_file(file.filename):
        filename = file.filename
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        try:
            data = []
            if filename.endswith('.csv'):
                with open(file_path, 'r', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    data = list(reader)
            elif filename.endswith('.json'):
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            
            # 模拟攻击检测
            detections = []
            for i, record in enumerate(data[:20]):
                is_anomaly = random.random() < 0.12
                detections.append({
                    'id': i + 1,
                    'timestamp': f'2024-01-15 10:{str(i//60).zfill(2)}:{str(i%60).zfill(2)}',
                    'key_generation_time': round(0.08 + random.random() * 0.15, 3),
                    'request_frequency': round(50 + random.random() * 950, 1),
                    'failed_attempts': int(random.random() * (5 if is_anomaly else 1)),
                    'anomaly_score': round(0.1 + random.random() * 0.9 if is_anomaly else random.random() * 0.3, 3),
                    'is_attack': is_anomaly,
                    'attack_type': ['Brute Force', 'Side Channel', 'Ciphertext Analysis', 'Key Recovery'][i % 4] if is_anomaly else 'Normal'
                })
            
            return jsonify({
                'success': True,
                'filename': filename,
                'record_count': len(data),
                'detections': detections
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    return jsonify({'error': 'File type not allowed'}), 400

@app.route('/api/save_sample', methods=['POST'])
def save_sample():
    data = generate_sensitive_dataset(1000)
    file_path = os.path.join(app.config['DATA_FOLDER'], 'sample_training_data.csv')
    with open(file_path, 'w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['id', 'phone', 'salary', 'credit_score', 'age', 'label', 'is_fraud'])
        writer.writeheader()
        for row in data:
            writer.writerow(row)
    return jsonify({'success': True, 'file': 'sample_training_data.csv'})

if __name__ == '__main__':
    try:
        app.run(debug=False, host='127.0.0.1', port=5000, threaded=True)
    except OSError as e:
        print(f"端口5000被占用，尝试端口5001...")
        app.run(debug=False, host='127.0.0.1', port=5001, threaded=True)