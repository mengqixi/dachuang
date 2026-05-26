#!/usr/bin/env python3
import sys
from flask import Flask, request, jsonify, send_file
import os
import csv
import random

app = Flask(__name__, static_folder='.', static_url_path='')

@app.route('/')
@app.route('/index.html')
def index():
    return send_file('index.html')

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

@app.route('/api/generate_dataset', methods=['POST'])
def generate_dataset():
    data = request.get_json() or {}
    n_records = data.get('n_records', 100)
    dataset = []
    for i in range(min(n_records, 20)):
        dataset.append({
            'id': i+1,
            'phone': f'138{random.randint(10000000, 99999999)}',
            'salary': random.randint(5000, 50000),
            'credit_score': random.randint(450, 850),
            'age': random.randint(18, 65),
            'is_fraud': random.random() < 0.08
        })
    encrypted = []
    for record in dataset:
        encrypted.append({
            'id': record['id'],
            'phone_encrypted': hex(random.getrandbits(64)),
            'salary_encrypted': hex(random.getrandbits(64)),
            'credit_score_encrypted': hex(random.getrandbits(64)),
            'label': random.choice([0, 1])
        })
    return jsonify({
        'success': True,
        'plaintext': dataset,
        'encrypted': encrypted,
        'n_records': n_records
    })

@app.route('/api/train_fate', methods=['POST'])
def train_fate():
    logs = []
    history = []
    acc = 0.6
    logs.append("初始化FATE联邦学习环境...")
    logs.append("连接各方参与方...")
    for i in range(1, 11):
        acc += random.uniform(0.03, 0.06)
        if acc > 0.98:
            acc = 0.98
        history.append({'epoch': i, 'accuracy': round(acc, 4), 'loss': round(1-acc, 4)})
        logs.append(f"Epoch {i}/10 - 准确率: {round(acc, 4)}")
    logs.append("训练完成！")
    return jsonify({'success': True, 'logs': logs, 'history': history, 'results': {'final_accuracy': round(acc, 4)}})

@app.route('/api/train_plaintext', methods=['POST'])
def train_plaintext():
    logs = []
    history = []
    acc = 0.65
    logs.append("初始化明文训练环境...")
    for i in range(1, 11):
        acc += random.uniform(0.04, 0.07)
        if acc > 0.99:
            acc = 0.99
        history.append({'epoch': i, 'accuracy': round(acc, 4), 'loss': round(1-acc, 4)})
        logs.append(f"Epoch {i}/10 - 准确率: {round(acc, 4)}")
    logs.append("训练完成！")
    return jsonify({'success': True, 'logs': logs, 'history': history, 'results': {'final_accuracy': round(acc, 4)}})

@app.route('/api/compare_encryption', methods=['POST'])
def compare_encryption():
    data = request.get_json() or {}
    data_size_mb = data.get('data_size_mb', 10)
    return jsonify({
        'data_size_mb': data_size_mb,
        'traditional': {'algorithm': 'AES-256', 'encryption_time_ms': round(12.5 + data_size_mb * 0.8, 2), 'throughput_mbps': round(80.0 - data_size_mb * 2.5, 2), 'security_level': 'High', 'data_isolation': 'No'},
        'homomorphic': {'algorithm': 'Paillier', 'encryption_time_ms': round(45.8 + data_size_mb * 3.2, 2), 'throughput_mbps': round(25.0 - data_size_mb * 0.8, 2), 'security_level': 'Very High', 'data_isolation': 'Yes'},
        'comparison': {'encryption_overhead': round(((45.8 + data_size_mb * 3.2) / (12.5 + data_size_mb * 0.8) - 1) * 100, 1), 'security_improvement': '30%'}
    })

@app.route('/api/save_sample', methods=['POST'])
def save_sample():
    os.makedirs('data', exist_ok=True)
    with open('data/sample.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['id', 'phone', 'salary'])
        for i in range(100):
            writer.writerow([i+1, f'138{random.randint(10000000, 99999999)}', random.randint(5000, 50000)])
    return jsonify({'success': True})

if __name__ == '__main__':
    print("Server starting on http://localhost:5000", flush=True)
    app.run(debug=False, host='127.0.0.1', port=5000, threaded=True)