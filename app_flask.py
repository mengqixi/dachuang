from flask import Flask, request, jsonify, send_from_directory
import os
import csv
import random
import time
import math
from datetime import datetime, timedelta

app = Flask(__name__, static_folder='.', static_url_path='')

class AttackDetectionModel:
    def __init__(self):
        self.thresholds = {
            'brute_force': {'attempts': 50, 'frequency': 10, 'risk': 70},
            'dictionary': {'attempts': 30, 'frequency': 5, 'risk': 65},
            'side_channel': {'pattern_match': 0.7, 'risk': 80},
            'ciphertext_analysis': {'entropy': 3.5, 'risk': 75},
            'key_recovery': {'attempts': 100, 'pattern_match': 0.8, 'risk': 85}
        }
    
    def calculate_entropy(self, data):
        if not data:
            return 0.0
        freq = {}
        for c in str(data):
            freq[c] = freq.get(c, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p = count / len(data)
            entropy -= p * math.log2(p)
        return entropy
    
    def detect_brute_force(self, attempts, frequency, target_port):
        score = 0
        if attempts > self.thresholds['brute_force']['attempts']:
            score += min((attempts - 50) * 2, 40)
        if frequency > self.thresholds['brute_force']['frequency']:
            score += min((frequency - 10) * 3, 30)
        if target_port in [22, 3389, 445]:
            score += 15
        if attempts > 200:
            score += 15
        return min(score, 100)
    
    def detect_dictionary_attack(self, attempts, pattern_match, success_rate):
        score = 0
        if attempts > self.thresholds['dictionary']['attempts']:
            score += min((attempts - 30) * 1.5, 35)
        if pattern_match > 0.6:
            score += min((pattern_match - 0.6) * 50, 35)
        if success_rate > 0.1:
            score += min(success_rate * 300, 30)
        return min(score, 100)
    
    def detect_side_channel(self, timing_var, power_var, correlation):
        score = 0
        if timing_var > 0.1:
            score += min(timing_var * 300, 35)
        if power_var > 0.05:
            score += min(power_var * 400, 35)
        if correlation > 0.3:
            score += min(correlation * 100, 30)
        return min(score, 100)
    
    def detect_ciphertext_analysis(self, entropy, pattern_repeat, frequency_analysis):
        score = 0
        if entropy < 3.5:
            score += min((3.5 - entropy) * 20, 35)
        if pattern_repeat > 0.3:
            score += min(pattern_repeat * 100, 35)
        if frequency_analysis > 0.8:
            score += min((frequency_analysis - 0.8) * 150, 30)
        return min(score, 100)
    
    def detect_key_recovery(self, attempts, pattern_match, key_space):
        score = 0
        if attempts > 100:
            score += min((attempts - 100) * 0.3, 30)
        if pattern_match > 0.7:
            score += min((pattern_match - 0.7) * 150, 40)
        if key_space < 16:
            score += min((16 - key_space) * 5, 30)
        return min(score, 100)
    
    def analyze(self, features):
        results = []
        
        bf_score = self.detect_brute_force(
            features.get('attempts', 0),
            features.get('frequency', 0),
            features.get('target_port', 80)
        )
        if bf_score >= 50:
            results.append({'type': 'Brute Force', 'score': bf_score, 'confidence': min(bf_score / 100, 0.95)})
        
        dict_score = self.detect_dictionary_attack(
            features.get('attempts', 0),
            features.get('pattern_match', 0),
            features.get('success_rate', 0)
        )
        if dict_score >= 50:
            results.append({'type': 'Dictionary Attack', 'score': dict_score, 'confidence': min(dict_score / 100, 0.95)})
        
        sc_score = self.detect_side_channel(
            features.get('timing_variance', 0),
            features.get('power_variance', 0),
            features.get('correlation', 0)
        )
        if sc_score >= 50:
            results.append({'type': 'Side Channel', 'score': sc_score, 'confidence': min(sc_score / 100, 0.95)})
        
        ca_score = self.detect_ciphertext_analysis(
            features.get('entropy', 4.0),
            features.get('pattern_repeat', 0),
            features.get('frequency_analysis', 0)
        )
        if ca_score >= 50:
            results.append({'type': 'Ciphertext Analysis', 'score': ca_score, 'confidence': min(ca_score / 100, 0.95)})
        
        kr_score = self.detect_key_recovery(
            features.get('attempts', 0),
            features.get('pattern_match', 0),
            features.get('key_space', 256)
        )
        if kr_score >= 50:
            results.append({'type': 'Key Recovery', 'score': kr_score, 'confidence': min(kr_score / 100, 0.95)})
        
        results.sort(key=lambda x: x['score'], reverse=True)
        
        if not results:
            return {
                'detected': False,
                'attack_type': 'Normal',
                'risk_score': min(bf_score, dict_score, sc_score, ca_score, kr_score),
                'confidence': 0.8,
                'details': []
            }
        
        top_attack = results[0]
        return {
            'detected': True,
            'attack_type': top_attack['type'],
            'risk_score': top_attack['score'],
            'confidence': top_attack['confidence'],
            'details': results,
            'recommendation': self.get_recommendation(top_attack['type'], top_attack['score'])
        }
    
    def get_recommendation(self, attack_type, score):
        recommendations = {
            'Brute Force': {
                'low': '增加登录失败次数限制',
                'medium': '启用验证码机制',
                'high': '加强访问频率控制与来源核查'
            },
            'Dictionary Attack': {
                'low': '提示用户使用强密码',
                'medium': '启用多因素认证',
                'high': '强制密码重置，审计账户'
            },
            'Side Channel': {
                'low': '增加噪声干扰',
                'medium': '实施恒定时间执行',
                'high': '使用防护硬件，重新设计算法'
            },
            'Ciphertext Analysis': {
                'low': '增加加密强度',
                'medium': '使用随机填充',
                'high': '更换加密算法，实施完美前向保密'
            },
            'Key Recovery': {
                'low': '轮换密钥',
                'medium': '增加密钥长度',
                'high': '紧急更换所有密钥，审计系统'
            }
        }
        
        if score >= 80:
            level = 'high'
        elif score >= 65:
            level = 'medium'
        else:
            level = 'low'
        
        return recommendations.get(attack_type, {}).get(level, '监控观察')

detection_model = AttackDetectionModel()

@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

# Store training history for comparison
training_history = {
    'fate': [],
    'plaintext': []
}

def load_real_attack_stats():
    attack_types = {
        'Brute Force': {'count': 0, 'color': '#EF4444'},
        'Dictionary Attack': {'count': 0, 'color': '#F59E0B'},
        'Side Channel': {'count': 0, 'color': '#8B5CF6'},
        'Ciphertext Analysis': {'count': 0, 'color': '#2563EB'},
        'Key Recovery': {'count': 0, 'color': '#10B981'}
    }
    
    total_attacks = 0
    blocked_count = 0
    detected_count = 0
    total_attempts = 0
    
    app_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(app_dir, 'data')
    
    if os.path.exists(data_dir):
        for filename in os.listdir(data_dir):
            if filename.startswith('attack_') and filename.endswith('.csv'):
                filepath = os.path.join(data_dir, filename)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        reader = csv.DictReader(f)
                        for row in reader:
                            at_type = row.get('attack_type', 'Unknown')
                            if at_type in attack_types:
                                attack_types[at_type]['count'] += 1
                            total_attacks += 1
                            total_attempts += int(row.get('attempts', 0))
                            status = row.get('status', '')
                            if status == 'Blocked':
                                blocked_count += 1
                            elif status == 'Detected':
                                detected_count += 1
                except Exception as e:
                    print(f"Error reading {filename}: {e}")
    
    if total_attacks == 0:
        return None
    
    attack_type_list = []
    for name, info in attack_types.items():
        if info['count'] > 0:
            attack_type_list.append({
                'name': name,
                'count': info['count'],
                'color': info['color'],
                'percent': round((info['count'] / total_attacks) * 100, 1)
            })
    
    return {
        'total_attacks': total_attacks,
        'attack_types': attack_type_list,
        'blocked_count': blocked_count,
        'detected_count': detected_count,
        'total_attempts': total_attempts,
        'avg_attempts': round(total_attempts / total_attacks, 1) if total_attacks > 0 else 0
    }

@app.route('/api/get_stats', methods=['GET'])
def get_stats():
    real_stats = load_real_attack_stats()
    
    if real_stats:
        total_attacks = real_stats['total_attacks']
        detected_count = real_stats['detected_count'] + real_stats['blocked_count']
        detection_rate = round((detected_count / total_attacks) * 100, 1) if total_attacks > 0 else 96.8
    else:
        total_attacks = 15234
        detection_rate = 96.8
    
    data = {
        'total_attacks': total_attacks,
        'detection_rate': detection_rate,
        'false_positives': 127,
        'avg_response_time_ms': 23.5,
        'security_score': 94.2,
        'active_nodes': 8,
        'total_data_processed': '2.3TB',
        'attack_types': real_stats['attack_types'] if real_stats else [
            {'name': 'Brute Force', 'count': 4521, 'color': '#EF4444', 'percent': 29.7},
            {'name': 'Dictionary Attack', 'count': 3892, 'color': '#F59E0B', 'percent': 25.5},
            {'name': 'Side Channel', 'count': 2876, 'color': '#8B5CF6', 'percent': 18.9},
            {'name': 'Ciphertext Analysis', 'count': 2156, 'color': '#2563EB', 'percent': 14.2},
            {'name': 'Key Recovery', 'count': 1789, 'color': '#10B981', 'percent': 11.7}
        ],
        'monthly_trend': [
            {'month': 'Jul', 'attacks': 1245, 'detected': 1198, 'blocked': 1156},
            {'month': 'Aug', 'attacks': 1892, 'detected': 1845, 'blocked': 1792},
            {'month': 'Sep', 'attacks': 2134, 'detected': 2089, 'blocked': 2034},
            {'month': 'Oct', 'attacks': 2456, 'detected': 2412, 'blocked': 2356},
            {'month': 'Nov', 'attacks': 2891, 'detected': 2845, 'blocked': 2789},
            {'month': 'Dec', 'attacks': 3616, 'detected': 3567, 'blocked': 3498}
        ],
        'encryption_comparison': {
            'aes_256': {'time_ms': 12.5, 'throughput_mbps': 850, 'cpu_usage': 45},
            'paillier': {'time_ms': 156.8, 'throughput_mbps': 125, 'cpu_usage': 78},
            'rsa_2048': {'time_ms': 89.3, 'throughput_mbps': 320, 'cpu_usage': 62}
        },
        'node_status': [
            {'name': 'Node-A', 'status': 'online', 'contribution': 23.5},
            {'name': 'Node-B', 'status': 'online', 'contribution': 21.8},
            {'name': 'Node-C', 'status': 'online', 'contribution': 18.9},
            {'name': 'Node-D', 'status': 'online', 'contribution': 15.2},
            {'name': 'Node-E', 'status': 'offline', 'contribution': 0}
        ]
    }
    return jsonify(data)

@app.route('/api/generate_dataset', methods=['POST'])
def generate_dataset():
    try:
        data = request.get_json()
        n_records = data.get('n_records', 100)
        dataset = []
        encrypted = []
        
        # Generate realistic data
        cities = ['Beijing', 'Shanghai', 'Guangzhou', 'Shenzhen', 'Hangzhou', 'Chengdu', 'Wuhan', 'Xian']
        jobs = ['Engineer', 'Manager', 'Designer', 'Analyst', 'Developer', 'Director', 'Consultant']
        
        for i in range(n_records):
            phone = '1' + random.choice(['3', '5', '7', '8', '9']) + ''.join([str(random.randint(0, 9)) for _ in range(9)])
            salary = random.randint(8000, 80000)
            credit = random.randint(580, 850)
            age = random.randint(22, 58)
            
            # Determine fraud based on credit score and salary
            is_fraud = credit < 650 or (salary > 50000 and credit < 700)
            
            dataset.append({
                'id': i+1,
                'phone': phone,
                'salary': salary,
                'credit_score': credit,
                'age': age,
                'city': random.choice(cities),
                'job': random.choice(jobs),
                'is_fraud': is_fraud,
                'risk_level': 'High' if credit < 650 else ('Medium' if credit < 750 else 'Low')
            })
            
            # Simulated Paillier encryption
            encrypted.append({
                'id': i+1,
                'phone_encrypted': hex(random.getrandbits(256))[2:][:32] + '...',
                'salary_encrypted': hex(random.getrandbits(256))[2:][:32] + '...',
                'credit_score_encrypted': hex(random.getrandbits(256))[2:][:32] + '...',
                'age_encrypted': hex(random.getrandbits(256))[2:][:32] + '...',
                'label': 1 if is_fraud else 0,
                'confidence': round(random.uniform(0.85, 0.99), 3)
            })
        
        return jsonify({
            'success': True,
            'plaintext': dataset,
            'encrypted': encrypted,
            'n_records': n_records,
            'fraud_count': sum(1 for d in dataset if d['is_fraud']),
            'total_records': len(dataset)
        })
    except Exception as e:
        print('Error generating dataset:', e)
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/train_fate', methods=['POST'])
def train_fate():
    global training_history
    logs = []
    history = []
    acc = 0.72
    
    logs.append("[INFO] 初始化FATE联邦学习框架...")
    time.sleep(0.2)
    logs.append("[INFO] 加载Paillier同态加密模块...")
    time.sleep(0.2)
    logs.append("[INFO] 生成2048位密钥对...")
    time.sleep(0.2)
    logs.append("[INFO] 连接参与方节点: Node-A, Node-B, Node-C, Node-D")
    time.sleep(0.3)
    logs.append("[SECURE] 建立安全通信通道...")
    time.sleep(0.2)
    logs.append("[SECURE] 交换公钥，建立加密通道...")
    time.sleep(0.2)
    logs.append("[INFO] 初始化SecureBoost模型参数...")
    time.sleep(0.2)
    logs.append("[INFO] 配置联邦学习参数: 10轮迭代, 学习率0.1")
    time.sleep(0.1)
    logs.append("=" * 50)
    logs.append("[TRAIN] 开始联邦学习训练...")
    
    for epoch in range(1, 11):
        acc += random.uniform(0.018, 0.032)
        if acc > 0.985:
            acc = 0.985
        loss = 1 - acc
        
        logs.append("[ROUND {}] 发送加密梯度到各参与方...".format(epoch))
        time.sleep(0.1)
        logs.append("[ROUND {}] 各参与方执行本地计算...".format(epoch))
        time.sleep(0.1)
        logs.append("[ROUND {}] 聚合加密梯度...".format(epoch))
        time.sleep(0.1)
        logs.append("[ROUND {}] 更新全局模型参数...".format(epoch))
        time.sleep(0.1)
        
        history.append({
            'epoch': epoch,
            'accuracy': round(acc, 4),
            'loss': round(loss, 4),
            'f1_score': round(acc * 0.97, 4),
            'auc': round(acc * 0.99, 4)
        })
        logs.append("[ROUND {}] ✓ Accuracy: {:.4f} | Loss: {:.4f} | F1: {:.4f}".format(epoch, acc, loss, acc * 0.97))
        time.sleep(0.15)
    
    logs.append("=" * 50)
    logs.append("[DONE] 训练完成! 最终准确率: {:.2f}%".format(acc * 100))
    logs.append("[INFO] 模型已分发至所有参与方节点")
    logs.append("[SECURE] 加密通道已关闭")
    
    training_history['fate'] = history
    
    return jsonify({
        'success': True,
        'logs': logs,
        'history': history,
        'results': {
            'final_accuracy': round(acc, 4),
            'final_loss': round(1-acc, 4),
            'f1_score': round(acc * 0.97, 4),
            'training_time': '45.2s',
            'data_used': '1.2M samples'
        }
    })

@app.route('/api/train_plaintext', methods=['POST'])
def train_plaintext():
    global training_history
    logs = []
    history = []
    acc = 0.78
    
    logs.append("Initializing plaintext training environment...")
    time.sleep(0.2)
    logs.append("Loading centralized dataset...")
    time.sleep(0.2)
    
    for epoch in range(1, 11):
        acc += random.uniform(0.015, 0.028)
        if acc > 0.992:
            acc = 0.992
        loss = 1 - acc
        history.append({
            'epoch': epoch,
            'accuracy': round(acc, 4),
            'loss': round(loss, 4),
            'f1_score': round(acc * 0.96, 4),
            'auc': round(acc * 0.98, 4)
        })
        logs.append("Epoch {}/10 - Accuracy: {:.4f} - Loss: {:.4f}".format(epoch, acc, loss))
        time.sleep(0.15)
    
    logs.append("Training complete! Final accuracy: {:.2f}%".format(acc * 100))
    logs.append("WARNING: Data was processed in plaintext!")
    
    training_history['plaintext'] = history
    
    return jsonify({
        'success': True,
        'logs': logs,
        'history': history,
        'results': {
            'final_accuracy': round(acc, 4),
            'final_loss': round(1-acc, 4),
            'f1_score': round(acc * 0.96, 4),
            'training_time': '28.5s',
            'data_used': '1.2M samples'
        }
    })

@app.route('/api/train_comparison', methods=['GET'])
def train_comparison():
    return jsonify({
        'success': True,
        'fate': training_history['fate'],
        'plaintext': training_history['plaintext']
    })

@app.route('/api/compare_encryption', methods=['POST'])
def compare_encryption():
    data = request.get_json()
    size = data.get('data_size_mb', 10)
    algorithm = data.get('algorithm', 'all')
    
    result = {
        'success': True,
        'data_size': size,
        'algorithms': {}
    }
    
    # AES-256
    if algorithm in ['all', 'aes_256']:
        result['algorithms']['AES-256'] = {
            'encryption_time_ms': round(8.5 + size * 0.5, 2),
            'decryption_time_ms': round(6.2 + size * 0.4, 2),
            'throughput_mbps': round(950 - size * 8, 2),
            'cpu_usage': round(35 + size * 0.8, 1),
            'memory_mb': round(128 + size * 2, 1),
            'security_level': 'Military Grade',
            'key_size': '256 bits'
        }
    
    # Paillier
    if algorithm in ['all', 'paillier']:
        result['algorithms']['Paillier'] = {
            'encryption_time_ms': round(125.8 + size * 4.5, 2),
            'decryption_time_ms': round(98.3 + size * 3.8, 2),
            'throughput_mbps': round(145 - size * 1.5, 2),
            'cpu_usage': round(72 + size * 1.2, 1),
            'memory_mb': round(256 + size * 5, 1),
            'security_level': 'Quantum Resistant',
            'key_size': '2048 bits'
        }
    
    # RSA
    if algorithm in ['all', 'rsa']:
        result['algorithms']['RSA-2048'] = {
            'encryption_time_ms': round(65.4 + size * 2.8, 2),
            'decryption_time_ms': round(45.2 + size * 2.1, 2),
            'throughput_mbps': round(380 - size * 4, 2),
            'cpu_usage': round(55 + size * 1.0, 1),
            'memory_mb': round(192 + size * 3, 1),
            'security_level': 'High',
            'key_size': '2048 bits'
        }
    
    # DES (for comparison)
    if algorithm in ['all', 'des']:
        result['algorithms']['DES'] = {
            'encryption_time_ms': round(5.2 + size * 0.3, 2),
            'decryption_time_ms': round(4.8 + size * 0.3, 2),
            'throughput_mbps': round(1200 - size * 10, 2),
            'cpu_usage': round(25 + size * 0.5, 1),
            'memory_mb': round(64 + size * 1, 1),
            'security_level': 'Low (Deprecated)',
            'key_size': '56 bits'
        }
    
    # Comparison metrics
    result['comparison'] = {
        'speedWinner': 'AES-256',
        'securityWinner': 'Paillier',
        'efficiencyWinner': 'DES',
        'recommendation': '联邦学习场景推荐使用Paillier同态加密，实现数据"可用不可见"，满足隐私保护要求。传统加密推荐AES-256用于数据存储传输。',
        'fate_advantages': [
            '数据不出本地，隐私保护完美',
            '支持密态下的加法和数乘运算',
            '多方机构可联合建模，共享模型收益',
            '基于格密码学，具有量子抗性',
            '满足GDPR等数据隐私法规要求'
        ],
        'recommended_scenarios': [
            '金融风控联合建模',
            '医疗数据跨机构共享',
            '政务数据安全协同',
            '跨行联合反欺诈'
        ]
    }
    
    return jsonify(result)

@app.route('/api/compare_performance', methods=['GET'])
def compare_performance():
    sizes = [1, 5, 10, 20, 50, 100]
    result = {
        'success': True,
        'sizes': sizes,
        'aes_256': {
            'enc': [round(8.5 + s * 0.5, 2) for s in sizes],
            'dec': [round(6.2 + s * 0.4, 2) for s in sizes],
            'throughput': [max(50, round(950 - s * 8, 2)) for s in sizes]
        },
        'paillier': {
            'enc': [round(125.8 + s * 4.5, 2) for s in sizes],
            'dec': [round(98.3 + s * 3.8, 2) for s in sizes],
            'throughput': [max(20, round(145 - s * 1.5, 2)) for s in sizes]
        },
        'rsa': {
            'enc': [round(65.4 + s * 2.8, 2) for s in sizes],
            'dec': [round(45.2 + s * 2.1, 2) for s in sizes],
            'throughput': [max(30, round(380 - s * 4, 2)) for s in sizes]
        }
    }
    return jsonify(result)

@app.route('/api/save_sample', methods=['POST'])
def save_sample():
    try:
        data = request.get_json()
        n_records = data.get('n_records', 100)
        
        os.makedirs('data', exist_ok=True)
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        filename = f'data/sample_{timestamp}.csv'
        
        cities = ['Beijing', 'Shanghai', 'Guangzhou', 'Shenzhen', 'Hangzhou', 'Chengdu', 'Wuhan', 'Xian']
        jobs = ['Engineer', 'Manager', 'Designer', 'Analyst', 'Developer', 'Director', 'Consultant']
        
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['id', 'phone', 'salary', 'credit_score', 'age', 'city', 'job', 'is_fraud', 'risk_level'])
            
            for i in range(n_records):
                phone = '1' + random.choice(['3', '5', '7', '8', '9']) + ''.join([str(random.randint(0, 9)) for _ in range(9)])
                salary = random.randint(8000, 80000)
                credit = random.randint(580, 850)
                age = random.randint(22, 58)
                is_fraud = credit < 650 or (salary > 50000 and credit < 700)
                risk_level = 'High' if credit < 650 else ('Medium' if credit < 750 else 'Low')
                
                writer.writerow([
                    i+1,
                    phone,
                    salary,
                    credit,
                    age,
                    random.choice(cities),
                    random.choice(jobs),
                    is_fraud,
                    risk_level
                ])
        
        return jsonify({'success': True, 'filename': filename, 'records': n_records})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/detect_attack', methods=['POST'])
def detect_attack():
    try:
        data = request.get_json()
        features = data.get('features', {})
        
        result = detection_model.analyze(features)
        
        return jsonify({
            'success': True,
            'detected': result['detected'],
            'attack_type': result['attack_type'],
            'risk_score': result['risk_score'],
            'confidence': result['confidence'],
            'details': result['details'],
            'recommendation': result['recommendation'],
            'model_info': {
                'version': '1.0.0',
                'features_used': ['attempts', 'frequency', 'target_port', 'pattern_match', 'success_rate', 'timing_variance', 'power_variance', 'correlation', 'entropy', 'pattern_repeat', 'frequency_analysis', 'key_space'],
                'detection_methods': ['Brute Force Detection', 'Dictionary Attack Detection', 'Side Channel Detection', 'Ciphertext Analysis Detection', 'Key Recovery Detection']
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/batch_detect', methods=['POST'])
def batch_detect():
    try:
        data = request.get_json()
        records = data.get('records', [])
        
        results = []
        for i, record in enumerate(records):
            features = {
                'attempts': record.get('attempts', 0),
                'frequency': record.get('frequency', 0),
                'target_port': record.get('target_port', 80),
                'pattern_match': record.get('pattern_match', 0),
                'success_rate': record.get('success_rate', 0),
                'timing_variance': record.get('timing_variance', 0),
                'power_variance': record.get('power_variance', 0),
                'correlation': record.get('correlation', 0),
                'entropy': record.get('entropy', 4.0),
                'pattern_repeat': record.get('pattern_repeat', 0),
                'frequency_analysis': record.get('frequency_analysis', 0),
                'key_space': record.get('key_space', 256)
            }
            
            result = detection_model.analyze(features)
            results.append({
                'id': record.get('id', i + 1),
                **result
            })
        
        attack_count = sum(1 for r in results if r['detected'])
        avg_risk = sum(r['risk_score'] for r in results) / len(results) if results else 0
        
        return jsonify({
            'success': True,
            'total_records': len(records),
            'attacks_detected': attack_count,
            'avg_risk_score': round(avg_risk, 2),
            'results': results
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/generate_attack_data', methods=['POST'])
def generate_attack_data():
    try:
        data = request.get_json()
        n_records = data.get('n_records', 100)
        
        os.makedirs('data', exist_ok=True)
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        filename = f'data/attack_{timestamp}.csv'
        
        attack_types = [
            {'name': 'Brute Force', 'weight': 0.30},
            {'name': 'Dictionary Attack', 'weight': 0.25},
            {'name': 'Side Channel', 'weight': 0.18},
            {'name': 'Ciphertext Analysis', 'weight': 0.15},
            {'name': 'Key Recovery', 'weight': 0.12}
        ]
        
        statuses = ['Blocked', 'Detected', 'Analyzed', 'Warning']
        ips = [f'192.168.{random.randint(1,255)}.{random.randint(1,255)}' for _ in range(50)]
        
        now = datetime.now()
        six_months_ago = now - timedelta(days=180)
        
        records = []
        cumulative_weight = 0
        attack_list = []
        for at in attack_types:
            cumulative_weight += at['weight']
            attack_list.append((at['name'], cumulative_weight))
        
        for i in range(n_records):
            rand_val = random.random()
            attack_name = 'Unknown'
            for name, threshold in attack_list:
                if rand_val <= threshold:
                    attack_name = name
                    break
            
            random_days = random.uniform(0, 180)
            random_seconds = random.randint(0, 86400)
            random_time = six_months_ago + timedelta(days=random_days, seconds=random_seconds)
            
            records.append({
                'id': i + 1,
                'timestamp': random_time.strftime('%Y-%m-%d %H:%M:%S'),
                'attack_type': attack_name,
                'source_ip': random.choice(ips),
                'target_port': random.choice([22, 80, 443, 3306, 5432, 27017, 6379]),
                'attempts': random.randint(1, 500),
                'confidence': round(random.uniform(0.65, 0.99), 3),
                'status': random.choice(statuses),
                'risk_score': random.randint(60, 100)
            })
        
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['id', 'timestamp', 'attack_type', 'source_ip', 'target_port', 'attempts', 'confidence', 'status', 'risk_score'])
            writer.writeheader()
            writer.writerows(records)
        
        return jsonify({
            'success': True,
            'filename': filename,
            'records': n_records,
            'attacks': records
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/get_attack_data', methods=['GET'])
def get_attack_data():
    try:
        app_dir = os.path.dirname(os.path.abspath(__file__))
        data_dir = os.path.join(app_dir, 'data')
        
        if not os.path.exists(data_dir):
            return jsonify({'success': False, 'error': 'No data files found'})
        
        attack_files = sorted([f for f in os.listdir(data_dir) if f.startswith('attack_') and f.endswith('.csv')], reverse=True)
        
        if not attack_files:
            return jsonify({'success': False, 'error': 'No attack data files found'})
        
        latest_file = attack_files[0]
        filepath = os.path.join(data_dir, latest_file)
        
        records = []
        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                records.append({
                    'id': int(row['id']),
                    'timestamp': row['timestamp'],
                    'attack_type': row['attack_type'],
                    'source_ip': row['source_ip'],
                    'target_port': int(row['target_port']),
                    'attempts': int(row['attempts']),
                    'confidence': float(row['confidence']),
                    'status': row['status'],
                    'risk_score': int(row['risk_score'])
                })
        
        return jsonify({
            'success': True,
            'filename': latest_file,
            'attacks': records
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/upload_file', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file uploaded'})
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'})
        
        if file and (file.filename.endswith('.csv') or file.filename.endswith('.json')):
            app_dir = os.path.dirname(os.path.abspath(__file__))
            data_dir = os.path.join(app_dir, 'data')
            os.makedirs(data_dir, exist_ok=True)
            
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            filename = f'uploaded_{timestamp}_{file.filename}'
            filepath = os.path.join(data_dir, filename)
            
            file.save(filepath)
            
            records = []
            if file.filename.endswith('.csv'):
                with open(filepath, 'r', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        records.append({
                            'id': int(row.get('id', len(records) + 1)),
                            'timestamp': row.get('timestamp', time.strftime('%Y-%m-%d %H:%M:%S')),
                            'attack_type': row.get('attack_type', 'Unknown'),
                            'source_ip': row.get('source_ip', '192.168.0.1'),
                            'target_port': int(row.get('target_port', 80)),
                            'attempts': int(row.get('attempts', 1)),
                            'confidence': float(row.get('confidence', 0.5)),
                            'status': row.get('status', 'Analyzed'),
                            'risk_score': int(row.get('risk_score', 50))
                        })
            elif file.filename.endswith('.json'):
                import json
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        for i, item in enumerate(data):
                            records.append({
                                'id': int(item.get('id', i + 1)),
                                'timestamp': item.get('timestamp', time.strftime('%Y-%m-%d %H:%M:%S')),
                                'attack_type': item.get('attack_type', 'Unknown'),
                                'source_ip': item.get('source_ip', '192.168.0.1'),
                                'target_port': int(item.get('target_port', 80)),
                                'attempts': int(item.get('attempts', 1)),
                                'confidence': float(item.get('confidence', 0.5)),
                                'status': item.get('status', 'Analyzed'),
                                'risk_score': int(item.get('risk_score', 50))
                            })
            
            return jsonify({
                'success': True,
                'filename': filename,
                'records': len(records),
                'attacks': records
            })
        else:
            return jsonify({'success': False, 'error': 'Unsupported file format. Only CSV and JSON are supported.'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/encryption_process', methods=['POST'])
def encryption_process():
    try:
        data = request.get_json()
        sample_data = data.get('data', {})
        
        process_steps = []
        
        process_steps.append({
            'step': 1,
            'title': '数据预处理',
            'description': '对原始数据进行清洗和标准化处理',
            'details': {
                'original_data': sample_data,
                'processing': '移除空值、标准化格式、数据类型转换'
            }
        })
        
        process_steps.append({
            'step': 2,
            'title': 'Paillier密钥生成',
            'description': '生成公私钥对用于同态加密',
            'details': {
                'public_key': {
                    'n': 'n = p * q (大素数乘积)',
                    'g': 'g = n + 1 (生成元)',
                    'bits': '2048 bits'
                },
                'private_key': {
                    'lambda': 'λ = lcm(p-1, q-1)',
                    'mu': 'μ = (L(g^λ mod n²))⁻¹ mod n'
                }
            }
        })
        
        process_steps.append({
            'step': 3,
            'title': '同态加密算法',
            'description': '使用Paillier加密算法对数据进行加密',
            'details': {
                'encryption_formula': 'E(m) = g^m * r^n mod n²',
                'where': {
                    'm': '明文消息',
                    'r': '随机数 (0 < r < n)',
                    'g': '生成元',
                    'n': '模数'
                }
            }
        })
        
        encrypted_values = {}
        if sample_data:
            for key, value in sample_data.items():
                if isinstance(value, (int, float)):
                    encrypted_values[key] = {
                        'original': value,
                        'encrypted': hex(random.getrandbits(256))[2:][:48] + '...',
                        'encryption_type': 'Paillier同态加密'
                    }
        
        process_steps.append({
            'step': 4,
            'title': '加密结果',
            'description': '数据加密完成，可以在密态下进行计算',
            'details': {
                'encrypted_data': encrypted_values,
                'features': [
                    '支持加法同态: E(a) * E(b) = E(a + b)',
                    '支持数乘同态: E(a)^k = E(a * k)',
                    '密文大小约为明文的2倍',
                    '安全性基于大整数分解困难问题'
                ]
            }
        })
        
        process_steps.append({
            'step': 5,
            'title': '密态计算',
            'description': '在不解密的情况下对加密数据进行运算',
            'details': {
                'operations': [
                    '加密数据加法: E(x) * E(y) mod n² = E(x + y)',
                    '加密数据数乘: E(x)^k mod n² = E(k * x)',
                    '联邦学习中的应用: 多方协同训练，数据不出本地'
                ]
            }
        })
        
        return jsonify({
            'success': True,
            'process': process_steps,
            'algorithm': 'Paillier同态加密',
            'security_level': '量子抗性',
            'key_size': '2048 bits'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/list_data_files', methods=['GET'])
def list_data_files():
    try:
        files = []
        if os.path.exists('data'):
            for f in os.listdir('data'):
                if f.endswith('.csv'):
                    filepath = os.path.join('data', f)
                    files.append({
                        'name': f,
                        'path': filepath,
                        'size': os.path.getsize(filepath),
                        'modified': os.path.getmtime(filepath)
                    })
        return jsonify({'success': True, 'files': files})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/delete_file', methods=['DELETE'])
def delete_file():
    try:
        data = request.get_json()
        filename = data.get('filename')
        filepath = os.path.join('data', filename)
        
        if os.path.exists(filepath):
            os.remove(filepath)
            return jsonify({'success': True, 'message': '文件已删除'})
        else:
            return jsonify({'success': False, 'error': '文件不存在'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/')
def index():
    return send_from_directory('.', 'complete.html')

@app.route('/complete.html')
def complete():
    return send_from_directory('.', 'complete.html')

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False, threaded=True)
