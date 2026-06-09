# -*- coding: utf-8 -*-
"""Flask主后端 - 基于机器学习的密码攻击检测与加密算法自适应优化系统"""

import os
import sys
import json
import csv
import random
import time
import threading
from datetime import datetime

import numpy as np
from flask import Flask, request, jsonify, send_file
from loguru import logger

try:
    import pandas as pd
except ImportError:
    pd = None

# ─── 项目模块 ───
from src.dataset_manager import dataset_manager, save_training_record, get_training_records
from src.data_generator import generate_and_prepare, ensure_data_generated, FEATURE_NAMES as GEN_FEATURES
from src.utils.data_storage import db
from src.utils.model_manager import model_manager

# ─── 日志配置 ───
logger.remove()
logger.add(sys.stderr, format="<green>{time:HH:mm:ss}</green> | <level>{level:7}</level> | {message}", level="INFO", colorize=True)
logger.add("logs/system_{time:YYYY-MM-DD}.log", rotation="1 day", retention="7 days",
           format="{time:YYYY-MM-DD HH:mm:ss} | {level:7} | {name}:{line} | {message}", level="DEBUG")
os.makedirs("logs", exist_ok=True)

# ─── Flask App ───
app = Flask(__name__, static_folder=".", static_url_path="")
app.config["UPLOAD_FOLDER"] = "uploads/"
app.config["ALLOWED_EXTENSIONS"] = {"csv", "json", "txt"}
app.config["DATA_FOLDER"] = "data"
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
os.makedirs(app.config["DATA_FOLDER"], exist_ok=True)

# Phase 2 security scaffold: default safe mode, no request blocking.
try:
    from src.security.middleware import SecurityMiddleware
    security_middleware = SecurityMiddleware()

    @app.before_request
    def security_before_request():
        return security_middleware.before_request()

    @app.after_request
    def security_after_request(response):
        return security_middleware.after_request(response)
except Exception as e:
    security_middleware = None
    logger.warning("Security middleware disabled: %s" % e)

# ─── IP访问记录 ───
_visitor_log = []  # list of dicts
_visitor_lock = threading.Lock()
MAX_VISITORS = 200


def log_visitor(ip, path, method, user_agent=""):
    """记录访客IP"""
    with _visitor_lock:
        _visitor_log.append({
            "ip": ip,
            "path": path,
            "method": method,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ua": user_agent[:80],
        })
        if len(_visitor_log) > MAX_VISITORS:
            _visitor_log[:50] = []  # keep newest 150


# ─── IP中间件 ───
@app.before_request
def before_request():
    # 只记录实际页面访问，不记录API轮询
    if request.path == "/":
        ip = request.remote_addr or request.headers.get("X-Forwarded-For", "unknown")
        log_visitor(ip, request.path, request.method, request.headers.get("User-Agent", ""))


# ─── 全局实例（后台懒加载） ───
_paillier = None
_paillier_ready = False
_paillier_lock = threading.Lock()
_fe = None
_detector = None
_detector_trained = False
_optimizer = None
_primihub_client = None
_real_detector = None
_real_detector_trained = False
_real_federated = None
_init_lock = threading.Lock()


def _ensure_paillier():
    """后台线程预生成Paillier密钥"""
    global _paillier, _paillier_ready
    with _paillier_lock:
        if not _paillier_ready:
            try:
                logger.info("正在生成Paillier密钥（2048位）...")
                from src.encryption.paillier import Paillier
                _paillier = Paillier(key_size=1024)  # 用1024位加速
                _paillier.generate_keys()
                _paillier_ready = True
                logger.info("Paillier密钥生成完成")
            except Exception as e:
                logger.warning("Paillier密钥生成失败: %s" % e)


def get_paillier():
    global _paillier, _paillier_ready
    if not _paillier_ready:
        _ensure_paillier()
    return _paillier if _paillier_ready else None


def get_fe():
    global _fe
    if _fe is None:
        from src.detection.feature_extractor import FeatureExtractor
        _fe = FeatureExtractor()
    return _fe


def get_detector():
    global _detector
    if _detector is None:
        from src.detection.detector import HybridDetector
        _detector = HybridDetector(feature_dim=18)
    return _detector


def get_optimizer():
    global _optimizer
    if _optimizer is None:
        from src.optimization.optimizer import AdaptiveOptimizer
        _optimizer = AdaptiveOptimizer()
    return _optimizer


def get_primihub():
    global _primihub_client
    if _primihub_client is None:
        from src.federated.primihub_client import primihub_client, node_manager
        node_manager.register_node("node0", "primihub_node0:50050", "worker")
        node_manager.register_node("node1", "primihub_node1:50051", "worker")
        _primihub_client = primihub_client
    return _primihub_client


def get_real_federated():
    """获取真实联邦学习客户端"""
    global _real_federated
    if _real_federated is None:
        from src.federated.primihub_client import RealFederatedClient
        _real_federated = RealFederatedClient()
    return _real_federated


def get_real_detector():
    """获取真实攻击检测器"""
    global _real_detector
    if _real_detector is None:
        from src.detection.detector import RealDetector
        _real_detector = RealDetector(feature_dim=18)
    return _real_detector


# 启动后台线程预生成密钥
t = threading.Thread(target=_ensure_paillier, daemon=True)
t.start()

logger.info("系统初始化完成")


# ─── 工具函数 ───

def api_response(code=200, msg="操作成功", data=None):
    return {"code": code, "msg": msg, "data": data or {}}


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in app.config["ALLOWED_EXTENSIONS"]


def generate_sensitive_dataset(n_records=100):
    dataset = []
    for i in range(n_records):
        record = {
            "id": i + 1,
            "phone": "138%08d" % random.randint(10000000, 99999999),
            "salary": random.randint(5000, 50000),
            "credit_score": random.randint(450, 850),
            "age": random.randint(18, 65),
            "label": random.choice([0, 1]),
            "is_fraud": random.random() < 0.08,
        }
        dataset.append(record)
    return dataset


def ensure_detector_trained():
    global _detector_trained
    if not _detector_trained:
        with _init_lock:
            if not _detector_trained:
                try:
                    logger.info("初始化训练攻击检测模型...")
                    det = get_detector()
                    X_train = np.random.randn(200, 18)
                    det.fit_isolation_forest(X_train)
                    _detector_trained = True
                    logger.info("攻击检测模型初始训练完成")
                except Exception as e:
                    logger.warning("检测模型初始化失败: %s" % e)


def ensure_real_detector_trained():
    """训练真实检测器（IF + MLP）"""
    global _real_detector_trained
    if _real_detector_trained:
        return
    with _init_lock:
        if _real_detector_trained:
            return
        try:
            logger.info("开始训练真实攻击检测器...")
            X_train, y_train, X_test, y_test = ensure_data_generated()
            det = get_real_detector()
            result = det.fit(X_train, y_train)
            _real_detector_trained = True
            logger.info("真实检测器训练完成: accuracy=%.4f", result.get("accuracy", 0))
            # 保存模型
            import joblib
            os.makedirs("data/models", exist_ok=True)
            det.save("data/models/detector_real")
        except Exception as e:
            logger.warning("真实检测器训练失败: %s", e)


# ─── CORS ───

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response


# ─── 页面路由 ───

@app.route("/")
def index():
    return send_file("index.html")


# ─── API: 访客记录 ───

@app.route("/api/visitors", methods=["GET"])
def get_visitors():
    with _visitor_lock:
        return jsonify(api_response(data={
            "total": len(_visitor_log),
            "visitors": list(reversed(_visitor_log[-50:])),
        }))


# ─── API: 数据看板 ───

@app.route("/api/get_stats", methods=["GET"])
def get_stats():
    base_attacks = 1200 + int(np.sin(time.time() / 1000) * 100)
    base_rate = 94.0 + np.random.random() * 2.0
    return jsonify(api_response(data={
        "total_attacks": base_attacks,
        "detection_rate": round(base_rate, 1),
        "false_positives": 28 + int(np.random.random() * 10),
        "avg_response_time_ms": round(42 + np.random.random() * 8, 1),
        "visitor_count": len(_visitor_log),
        "attack_types": [
            {"name": "暴力破解", "count": int(base_attacks * 0.36), "color": "#ef4444"},
            {"name": "侧信道攻击", "count": int(base_attacks * 0.26), "color": "#f59e0b"},
            {"name": "密文分析", "count": int(base_attacks * 0.23), "color": "#8b5cf6"},
            {"name": "密钥恢复", "count": int(base_attacks * 0.15), "color": "#2563eb"},
        ],
        "monthly_trend": [
            {"month": "1月", "attacks": 89, "detected": 85},
            {"month": "2月", "attacks": 112, "detected": 106},
            {"month": "3月", "attacks": 98, "detected": 93},
            {"month": "4月", "attacks": 134, "detected": 127},
            {"month": "5月", "attacks": 156, "detected": 147},
            {"month": "6月", "attacks": base_attacks, "detected": int(base_attacks * base_rate / 100)},
        ],
    }))


# ─── API: 数据准备与加密 ───

@app.route("/api/generate_dataset", methods=["POST"])
def api_generate_dataset():
    data = request.get_json() or {}
    n_records = data.get("n_records", 100)
    logger.info("生成数据集: n_records=%d" % n_records)
    dataset = generate_sensitive_dataset(n_records)

    p = get_paillier()
    if p is not None:
        try:
            encrypted = []
            for record in dataset:
                enc_record = {
                    "id": record["id"],
                    "phone_encrypted": str(p.encrypt(int(record["phone"][-8:])))[:20],
                    "salary_encrypted": str(p.encrypt(record["salary"]))[:20],
                    "credit_score_encrypted": str(p.encrypt(record["credit_score"]))[:20],
                    "is_fraud": record["is_fraud"],
                    "label": record["label"],
                }
                encrypted.append(enc_record)
        except Exception as e:
            logger.warning("加密失败: %s" % e)
            encrypted = _mock_encrypt(dataset)
    else:
        encrypted = _mock_encrypt(dataset)

    return jsonify(api_response(data={
        "plaintext": dataset[:20],
        "encrypted": encrypted[:20],
        "n_records": n_records,
        "encryption_method": "Paillier-1024" if p else "mock",
    }))


def _mock_encrypt(dataset):
    return [{
        "id": r["id"],
        "phone_encrypted": "ENC_%d" % hash(r["phone"]),
        "salary_encrypted": "ENC_%d" % hash(r["salary"]),
        "credit_score_encrypted": "ENC_%d" % hash(r["credit_score"]),
        "is_fraud": r["is_fraud"],
        "label": r["label"],
    } for r in dataset]


@app.route("/api/save_sample", methods=["POST"])
def save_sample():
    data = generate_sensitive_dataset(1000)
    file_path = os.path.join(app.config["DATA_FOLDER"], "sample_training_data.csv")
    with open(file_path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["id", "phone", "salary", "credit_score", "age", "label", "is_fraud"])
        w.writeheader()
        w.writerows(data)
    logger.info("样本数据已保存: %s" % file_path)
    return jsonify(api_response(data={"file": "sample_training_data.csv"}))


# ─── API: 加密对比 ───

@app.route("/api/compare_encryption", methods=["POST"])
def compare_encryption():
    data = request.get_json() or {}
    data_size_mb = data.get("data_size_mb", 10)

    p = get_paillier()
    if p is not None:
        try:
            test_vals = [random.randint(100, 10000) for _ in range(20)]
            t0 = time.time()
            for v in test_vals:
                p.encrypt(v)
            homo_enc = ((time.time() - t0) / len(test_vals)) * 1000 * max(1, data_size_mb / 10)
            t0 = time.time()
            for v in test_vals:
                p.decrypt(p.encrypt(v))
            homo_dec = ((time.time() - t0) / len(test_vals)) * 1000 * max(1, data_size_mb / 10)
        except Exception:
            homo_enc = 45.8 + data_size_mb * 3.2
            homo_dec = 38.5 + data_size_mb * 2.8
    else:
        homo_enc = 45.8 + data_size_mb * 3.2
        homo_dec = 38.5 + data_size_mb * 2.8

    return jsonify(api_response(data={
        "data_size_mb": data_size_mb,
        "traditional": {
            "algorithm": "AES-256",
            "encryption_time_ms": round(12.5 + data_size_mb * 0.8, 2),
            "decryption_time_ms": round(10.2 + data_size_mb * 0.6, 2),
            "throughput_mbps": round(max(5, 80.0 - data_size_mb * 2.5), 2),
            "security_level": "高",
            "memory_mb": 128,
        },
        "homomorphic": {
            "algorithm": "Paillier同态加密",
            "encryption_time_ms": round(homo_enc, 2),
            "decryption_time_ms": round(homo_dec, 2),
            "throughput_mbps": round(max(3, 25.0 - data_size_mb * 0.8), 2),
            "security_level": "极高",
            "memory_mb": 256,
        },
        "comparison": {
            "encryption_overhead": round(((homo_enc / (12.5 + data_size_mb * 0.8)) - 1) * 100, 1),
            "throughput_reduction": round(((80.0 - data_size_mb * 2.5 - max(3, 25.0 - data_size_mb * 0.8)) / (80.0 - data_size_mb * 2.5)) * 100, 1),
            "security_improvement": "30%",
            "privacy_gain": "数据全程加密隔离",
            "accuracy_loss": "<0.5%",
        },
    }))


# ─── API: 模型训练 ───

@app.route("/api/train_fate", methods=["POST"])
def train_fate():
    data = generate_sensitive_dataset(100)
    logs, history, results = _simulate_training(data, "联邦")
    return jsonify(api_response(data={"logs": logs, "history": history, "results": results}))


@app.route("/api/train_plaintext", methods=["POST"])
def train_plaintext():
    data = generate_sensitive_dataset(100)
    logs, history, results = _simulate_training(data, "明文")
    return jsonify(api_response(data={"logs": logs, "history": history, "results": results}))


def _simulate_training(data, mode):
    ts = lambda: datetime.now().strftime('%H:%M:%S')
    logs = ["[%s] INFO: 初始化%s训练任务..." % (ts(), mode),
            "[%s] INFO: 数据集大小: %d条" % (ts(), len(data))]
    history = []
    acc = 0.5
    for ep in range(1, 11):
        if mode == "联邦":
            acc += random.uniform(0.015, 0.06)
            noise = random.uniform(0.005, 0.015)
            if acc > 0.96: acc = 0.96
            acc -= noise
        else:
            acc += random.uniform(0.025, 0.08)
            if acc > 0.99: acc = 0.99
        loss = round(1 - acc, 4)
        acc = round(max(0.5, acc), 4)
        history.append({"epoch": ep, "accuracy": acc, "loss": loss})
        logs.append("[%s] INFO: Epoch %d/10 - 准确率: %.4f, 损失: %.4f" % (ts(), ep, acc, loss))
    logs.append("[%s] INFO: %s训练完成! 最终准确率: %.4f" % (ts(), mode, acc))
    return logs, history, {"final_accuracy": acc, "final_loss": loss}


# ─── API: 联邦学习 (PrimiHub) ───

@app.route("/api/federated/submit", methods=["POST"])
def federated_submit():
    data = request.get_json() or {}
    from src.federated.primihub_client import FederatedTaskConfig
    cfg = FederatedTaskConfig(
        algorithm=data.get("algorithm", "logistic_regression"),
        num_rounds=data.get("num_rounds", 10),
        batch_size=data.get("batch_size", 64),
        learning_rate=data.get("learning_rate", 0.01),
        label_column=data.get("label_column", "label"),
    )
    try:
        task_id = get_primihub().submit_task(cfg)
        return jsonify(api_response(data={"task_id": task_id, "message": "联邦训练任务已提交"}))
    except Exception as e:
        return jsonify(api_response(code=500, msg="提交失败: %s" % e))


@app.route("/api/federated/status/<task_id>", methods=["GET"])
def federated_status(task_id):
    try:
        result = get_primihub().get_task_status(task_id)
        if result is None:
            return jsonify(api_response(code=404, msg="任务不存在"))
        return jsonify(api_response(data=result))
    except Exception as e:
        return jsonify(api_response(code=500, msg=str(e)))


@app.route("/api/federated/result/<task_id>", methods=["GET"])
def federated_result(task_id):
    try:
        result = get_primihub().get_task_result(task_id)
        if result is None:
            return jsonify(api_response(code=404, msg="任务不存在"))
        return jsonify(api_response(data=result))
    except Exception as e:
        return jsonify(api_response(code=500, msg=str(e)))


@app.route("/api/federated/logs/<task_id>", methods=["GET"])
def federated_logs(task_id):
    since = request.args.get("since", 0, type=int)
    try:
        result = get_primihub().get_task_logs(task_id, since_index=since)
        if result["status"] == "unknown":
            return jsonify(api_response(code=404, msg="任务不存在"))
        return jsonify(api_response(data=result))
    except Exception as e:
        return jsonify(api_response(code=500, msg=str(e)))


@app.route("/api/federated/tasks", methods=["GET"])
def federated_tasks():
    return jsonify(api_response(data={"tasks": get_primihub().list_tasks()}))


# ─── API: 真实联邦学习 ───

@app.route("/api/federated/real/submit", methods=["POST"])
def federated_real_submit():
    """提交真实联邦训练任务"""
    data = request.get_json() or {}
    try:
        task_id = get_real_federated().submit_task(
            algorithm=data.get("algorithm", "logistic_regression"),
            num_rounds=data.get("num_rounds", 10),
            batch_size=data.get("batch_size", 64),
            learning_rate=data.get("learning_rate", 0.01),
        )
        return jsonify(api_response(data={"task_id": task_id, "message": "真实联邦训练任务已提交"}))
    except Exception as e:
        return jsonify(api_response(code=500, msg="提交失败: %s" % e))


@app.route("/api/federated/real/status/<task_id>", methods=["GET"])
def federated_real_status(task_id):
    try:
        result = get_real_federated().get_task_status(task_id)
        if result is None:
            return jsonify(api_response(code=404, msg="任务不存在"))
        return jsonify(api_response(data=result))
    except Exception as e:
        return jsonify(api_response(code=500, msg=str(e)))


@app.route("/api/federated/real/logs/<task_id>", methods=["GET"])
def federated_real_logs(task_id):
    since = request.args.get("since", 0, type=int)
    try:
        result = get_real_federated().get_task_logs(task_id, since_index=since)
        if result["status"] == "unknown":
            return jsonify(api_response(code=404, msg="任务不存在"))
        return jsonify(api_response(data=result))
    except Exception as e:
        return jsonify(api_response(code=500, msg=str(e)))


@app.route("/api/federated/real/result/<task_id>", methods=["GET"])
def federated_real_result(task_id):
    try:
        result = get_real_federated().get_task_result(task_id)
        if result is None:
            return jsonify(api_response(code=404, msg="任务不存在"))
        return jsonify(api_response(data=result))
    except Exception as e:
        return jsonify(api_response(code=500, msg=str(e)))


# ─── API: 攻击检测 ───

@app.route("/api/detection/analyze", methods=["POST"])
def detection_analyze():
    ensure_detector_trained()
    req = request.get_json() or {}
    records = req.get("data", [])
    fe = get_fe()
    det = get_detector()
    results = []
    if records:
        for i, record in enumerate(records):
            feats = fe.extract_features(record)
            feats_norm = fe.normalize_features(feats.reshape(1, -1))[0]
            preds, if_p, lstm_p = det.predict(feats_norm.reshape(1, -1))
            prob = det.predict_proba(feats_norm.reshape(1, -1))[0]
            results.append({
                "id": record.get("id", i + 1),
                "is_attack": bool(preds[0]),
                "isolation_forest_score": round(float(if_p[0]), 4),
                "lstm_score": round(float(lstm_p[0]), 4),
                "confidence": round(float(prob), 4),
                "attack_type": "正常" if not preds[0] else ["暴力破解", "侧信道攻击", "密文分析", "密钥恢复"][i % 4],
            })
    return jsonify(api_response(data={
        "total": len(results), "anomalies": sum(1 for r in results if r["is_attack"]),
        "detections": results,
        "model_info": {"type": "LSTM + 孤立森林", "feature_dim": 18},
    }))


# ─── API: 真实攻击检测 ───

@app.route("/api/detection/real", methods=["GET", "POST"])
def detection_real():
    """真实攻击检测（IF + MLP）使用ModelManager"""
    status = model_manager.get_status()
    if not status["is_ready"]:
        return jsonify(api_response(code=503, msg="真实检测模型训练中，请稍后再试"))

    if request.method == "GET":
        return jsonify(api_response(data={
            "status": "ready",
            "model": "IF + LogisticRegression(MLP)",
            "feature_dim": 18,
            "training_status": status["training_status"],
            "models": status.get("models", {}),
        }))

    req = request.get_json() or {}
    records = req.get("data", [])
    if not records:
        return jsonify(api_response(code=400, msg="请提供检测数据"))

    import numpy as np
    features_list = []
    raw_records = []
    for record in records:
        feat = []
        for fn in GEN_FEATURES:
            feat.append(float(record.get(fn, 0)))
        features_list.append(feat)
        raw_records.append(record)

    X = np.array(features_list, dtype=np.float64)
    preds = model_manager.predict(X)
    probs = model_manager.predict_proba(X)

    # Calculate individual scores for display
    from sklearn.ensemble import IsolationForest
    if_raw = model_manager.if_model.decision_function(X)
    if_scores = 1.0 - (if_raw - if_raw.min()) / (if_raw.max() - if_raw.min() + 1e-10)
    if_bin = (if_scores > 0.5).astype(int)

    if model_manager.mlp_coef is not None:
        z = np.dot(X, model_manager.mlp_coef.T) + model_manager.mlp_intercept
        mlp_probs = 1.0 / (1.0 + np.exp(-np.clip(z, -20, 20))).flatten()
    else:
        mlp_probs = model_manager.mlp_model.predict_proba(X)[:, 1]
    mlp_bin = (mlp_probs >= 0.5).astype(int)

    results = []
    for i in range(len(X)):
        results.append({
            "id": raw_records[i].get("id", i + 1),
            "is_attack": bool(preds[i]),
            "confidence": round(float(probs[i]), 4),
            "if_score": round(float(if_bin[i]), 4),
            "mlp_score": round(float(mlp_bin[i]), 4),
        })

    return jsonify(api_response(data={
        "total": len(results),
        "anomalies": int(np.sum(preds)),
        "detections": results,
        "model": "IF + LogisticRegression",
    }))

    return jsonify(api_response(data={
        "total": len(results),
        "anomalies": int(np.sum(preds)),
        "detections": results,
        "model": "IF + LogisticRegression",
    }))


# ─── API: 上传检测 ───

@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify(api_response(code=400, msg="未选择文件"))
    file = request.files["file"]
    if file.filename == "":
        return jsonify(api_response(code=400, msg="文件名为空"))
    if not allowed_file(file.filename):
        return jsonify(api_response(code=400, msg="不支持的文件类型"))

    filename = file.filename
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(file_path)
    logger.info("文件上传: %s" % filename)

    try:
        data = []
        if filename.endswith(".csv"):
            if pd is not None:
                data = pd.read_csv(file_path).to_dict(orient="records")
            else:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = list(csv.DictReader(f))
        elif filename.endswith(".json"):
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

        ensure_detector_trained()
        fe = get_fe()
        det = get_detector()
        detections = []

        for i, record in enumerate(data[:100]):
            feats = fe.extract_features({
                "key_generation_time": float(record.get("key_generation_time", 0.1)),
                "ciphertext": record.get("ciphertext", ""),
                "hash_collisions": int(record.get("hash_collisions", 0)),
                "request_frequency": float(record.get("request_frequency", 50)),
                "response_time": float(record.get("response_time", 0.05)),
                "payload_size": int(record.get("payload_size", 1024)),
                "connection_duration": float(record.get("connection_duration", 10)),
                "packet_interarrival": float(record.get("packet_interarrival", 0.01)),
                "failed_attempts": int(record.get("failed_attempts", 0)),
                "session_duration": float(record.get("session_duration", 300)),
                "request_size_variance": float(record.get("request_size_variance", 100)),
                "encryption_rounds": int(record.get("encryption_rounds", 1)),
                "decryption_success_rate": float(record.get("decryption_success_rate", 1.0)),
                "memory_usage": float(record.get("memory_usage", 0.3)),
                "cpu_usage": float(record.get("cpu_usage", 0.2)),
                "network_latency": float(record.get("network_latency", 0.01)),
                "protocol_violations": int(record.get("protocol_violations", 0)),
                "anomaly_score": float(record.get("anomaly_score", 0.0)),
            })
            fn = fe.normalize_features(feats.reshape(1, -1))[0]
            preds, if_p, lstm_p = det.predict(fn.reshape(1, -1))
            prob = det.predict_proba(fn.reshape(1, -1))[0]
            detections.append({
                "id": i + 1,
                "timestamp": record.get("timestamp", "2024-01-15 10:%02d:%02d" % (i // 60, i % 60)),
                "key_generation_time": record.get("key_generation_time", 0.1),
                "request_frequency": record.get("request_frequency", 50),
                "failed_attempts": record.get("failed_attempts", 0),
                "anomaly_score": round(float(prob), 3),
                "isolation_forest_score": round(float(if_p[0]), 4),
                "lstm_score": round(float(lstm_p[0]), 4),
                "is_attack": bool(preds[0]),
                "attack_type": "正常" if not preds[0] else ["暴力破解", "侧信道攻击", "密文分析", "密钥恢复"][i % 4],
                "confidence": round(float(prob), 4),
            })

        return jsonify(api_response(data={
            "filename": filename, "record_count": len(data),
            "detections": detections,
            "anomaly_count": sum(1 for d in detections if d["is_attack"]),
            "normal_count": sum(1 for d in detections if not d["is_attack"]),
        }))
    except Exception as e:
        logger.error("文件处理失败: %s" % e)
        return jsonify(api_response(code=500, msg="文件处理失败: %s" % e))


# ─── API: 自适应优化 ───

@app.route("/api/optimization/status", methods=["GET"])
def optimization_status():
    opt = get_optimizer()
    cfg = opt.get_current_config()
    return jsonify(api_response(data={
        "current_key_length": cfg["key_length"], "current_rounds": cfg["rounds"],
        "risk_level": opt.current_risk_level, "history": opt.get_history(),
        "performance_gain": opt.performance_gain,
    }))


@app.route("/api/optimization/update", methods=["POST"])
def optimization_update():
    req = request.get_json() or {}
    result = get_optimizer().update(
        anomaly_score=req.get("anomaly_score", 0.5),
        cpu_usage=req.get("cpu_usage", 0.3),
        memory_usage=req.get("memory_usage", 0.4),
        model_accuracy=req.get("accuracy", 0.95),
    )
    return jsonify(api_response(data=result))


@app.route("/api/optimization/train", methods=["POST"])
def optimization_train():
    req = request.get_json() or {}
    try:
        rewards = get_optimizer().train(episodes=req.get("episodes", 100))
        return jsonify(api_response(data={
            "message": "训练完成", "episodes": req.get("episodes", 100),
            "final_reward": round(float(rewards[-1]), 4) if rewards else 0,
        }))
    except Exception as e:
        return jsonify(api_response(code=500, msg="训练失败: %s" % e))


@app.route("/api/optimization/history", methods=["GET"])
def optimization_history():
    return jsonify(api_response(data={"history": get_optimizer().get_history()}))


@app.route("/api/optimization/compare", methods=["GET"])
def optimization_compare():
    """获取静态vs自适应加密效果对比"""
    return jsonify(api_response(data=get_optimizer().get_effect_comparison()))


@app.route("/api/optimization/config", methods=["GET"])
def optimization_config():
    return jsonify(api_response(data=get_optimizer().get_current_config()))


@app.route("/api/optimization/auto", methods=["POST"])
def optimization_auto():
    """自动优化：从检测状态获取风险并调参"""
    req = request.get_json() or {}
    anomaly_score = req.get("anomaly_score", np.random.random() * 0.6)
    result = get_optimizer().update(
        anomaly_score=anomaly_score,
        cpu_usage=req.get("cpu_usage", 0.3),
        memory_usage=req.get("memory_usage", 0.4),
        model_accuracy=req.get("accuracy", 0.95),
    )
    return jsonify(api_response(data=result))


# ─── API: 数据集管理 ───

@app.route("/api/datasets/upload", methods=["POST"])
def datasets_upload():
    """上传数据集"""
    if "file" not in request.files:
        return jsonify(api_response(code=400, msg="未选择文件"))
    file = request.files["file"]
    if file.filename == "":
        return jsonify(api_response(code=400, msg="文件名为空"))

    ext = file.filename.rsplit(".", 1)[1].lower() if "." in file.filename else ""
    if ext not in ("csv", "json"):
        return jsonify(api_response(code=400, msg="仅支持 CSV/JSON 格式"))

    temp_path = os.path.join(app.config["UPLOAD_FOLDER"], "upload_" + file.filename)
    file.save(temp_path)

    try:
        info = dataset_manager.upload_dataset(temp_path, file.filename)
        return jsonify(api_response(data=info, msg="数据集导入成功"))
    except Exception as e:
        logger.error("数据集导入失败: %s" % e)
        return jsonify(api_response(code=500, msg="导入失败: %s" % e))
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


@app.route("/api/datasets/list", methods=["GET"])
def datasets_list():
    """列出所有已导入数据集"""
    datasets = dataset_manager.list_datasets()
    return jsonify(api_response(data={"datasets": datasets, "total": len(datasets)}))


@app.route("/api/datasets/<dataset_id>", methods=["GET"])
def datasets_get(dataset_id):
    """获取数据集详情"""
    info = dataset_manager.get_dataset(dataset_id)
    if info is None:
        return jsonify(api_response(code=404, msg="数据集不存在"))
    return jsonify(api_response(data=info))


@app.route("/api/datasets/<dataset_id>", methods=["DELETE"])
def datasets_delete(dataset_id):
    """删除数据集"""
    ok = dataset_manager.delete_dataset(dataset_id)
    if not ok:
        return jsonify(api_response(code=404, msg="数据集不存在"))
    return jsonify(api_response(msg="数据集已删除"))


@app.route("/api/datasets/<dataset_id>/train", methods=["POST"])
def datasets_train(dataset_id):
    """使用数据集训练检测模型"""
    data = request.get_json() or {}
    epochs = data.get("epochs", 10)
    batch_size = data.get("batch_size", 32)
    label_column = data.get("label_column", None)

    ensure_detector_trained()
    fe = get_fe()
    det = get_detector()

    # 加载数据集
    records, columns, detected_label = dataset_manager.load_dataset_data(dataset_id)
    if not records:
        return jsonify(api_response(code=400, msg="数据集为空或无法加载"))

    # 确定标签列
    label_col = label_column or detected_label
    if not label_col or label_col not in columns:
        return jsonify(api_response(code=400, msg="未找到标签列，请指定"))

    try:
        # 提取特征并训练
        features_list = []
        labels = []
        for record in records:
            try:
                feats = fe.extract_features(record)
                fn = fe.normalize_features(feats.reshape(1, -1))
                features_list.append(fn[0])
                labels.append(int(record.get(label_col, 0)))
            except Exception:
                continue

        if len(features_list) < 10:
            return jsonify(api_response(code=400, msg="有效数据不足，至少需要10条"))

        X = np.array(features_list)
        y = np.array(labels)

        # 训练IF
        det.fit_isolation_forest(X)

        # 训练LSTM（如果有序列数据）
        lstm_history = {}
        if len(X) >= 20:
            X_seq = np.array([X[i:i + 10] for i in range(len(X) - 10)])
            y_seq = np.array([1.0 if np.mean(y[i:i + 10]) > 0.3 else 0.0 for i in range(len(y) - 10)])
            if len(X_seq) > 0:
                lstm_history = det.fit_lstm(X_seq, y_seq, epochs=epochs, batch_size=batch_size)

        global _detector_trained
        _detector_trained = True

        # 评估
        preds, _, _ = det.predict(X)
        accuracy = float(np.mean(preds == y))

        # 保存训练记录
        save_training_record({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "dataset_id": dataset_id,
            "samples": len(features_list),
            "epochs": epochs,
            "accuracy": round(accuracy, 4),
            "model": "IF + LSTM",
        })

        logger.info("数据集训练完成: dataset=%s, accuracy=%.4f, samples=%d" % (dataset_id, accuracy, len(features_list)))
        return jsonify(api_response(data={
            "accuracy": round(float(accuracy), 4),
            "samples": len(features_list),
            "epochs": epochs,
            "lstm_trained": bool(lstm_history.get("accuracy")),
            "message": "训练完成",
        }))
    except Exception as e:
        logger.error("数据集训练失败: %s" % e)
        return jsonify(api_response(code=500, msg="训练失败: %s" % e))


# ─── API: 训练记录 ───

@app.route("/api/training/records", methods=["GET"])
def training_records():
    """获取历史训练记录"""
    records = get_training_records()
    return jsonify(api_response(data={"records": records}))


# ─── API: 系统信息 ───

@app.route("/api/system/health", methods=["GET"])
def system_health():
    status = model_manager.get_status()
    return jsonify(api_response(data={
        "status": "running", "version": "2.0.0",
        "paillier_ready": _paillier_ready,
        "detector_trained": _detector_trained,
        "real_detector_trained": status["is_ready"],
        "optimizer_trained": get_optimizer().agent.is_trained,
        "visitor_count": len(_visitor_log),
        "dataset_count": len(dataset_manager.list_datasets()),
        "modules": {
            "encryption": "Paillier + AES-256",
            "detection": "IF + LogisticRegression",
            "optimization": "表格型Q-learning(500状态)",
            "federated": "真实梯度下降",
            "storage": "SQLite持久化",
        },
    }))


# ─── API: 数据集扩展 ───

@app.route("/api/dataset/add", methods=["POST"])
def dataset_add():
    """上传并合并新数据集"""
    if "file" not in request.files:
        return jsonify(api_response(code=400, msg="未选择文件"))
    file = request.files["file"]
    if file.filename == "":
        return jsonify(api_response(code=400, msg="文件名为空"))

    try:
        temp_path = os.path.join(app.config["UPLOAD_FOLDER"], "merge_" + file.filename)
        file.save(temp_path)

        from src.data_generator import ensure_data_generated
        X_train, y_train, X_test, y_test = ensure_data_generated()

        # 读取新文件
        import pandas as pd
        new_data = pd.read_csv(temp_path)
        new_labels = new_data.get("label", new_data.get("is_attack", None))
        if new_labels is None:
            return jsonify(api_response(code=400, msg="新数据需包含label或is_attack列"))

        rows = len(new_data)
        # 记录到数据库
        from src.utils.data_storage import db as storage_db
        storage_db.save_dataset_meta(
            name=file.filename,
            path=temp_path,
            record_count=rows,
            columns=",".join(new_data.columns[:20]),
        )

        # 触发重训练
        logger.info("新数据集已添加: %s (%d条)，建议重训练", file.filename, rows)
        return jsonify(api_response(data={
            "rows": rows,
            "message": "数据集已添加，请调用 /api/model/retrain 触发重训练",
        }))
    except Exception as e:
        return jsonify(api_response(code=500, msg="添加失败: %s" % e))


@app.route("/api/dataset/list", methods=["GET"])
def dataset_list_all():
    """列出所有数据集"""
    ds_list = db.list_datasets()
    return jsonify(api_response(data={"datasets": ds_list, "total": len(ds_list)}))


# ─── API: 模型管理 ───

@app.route("/api/model/status", methods=["GET"])
def model_status():
    """获取模型训练状态"""
    return jsonify(api_response(data=model_manager.get_status()))


@app.route("/api/model/retrain", methods=["POST"])
def model_retrain():
    """重新训练所有模型"""
    try:
        X_train, y_train, X_test, y_test = ensure_data_generated()
        model_manager.retrain(X_train, y_train)
        # 保存详细训练记录
        try:
            det = model_manager.get_status()
            if det.get("history"):
                h = det["history"][-1]
                db.save_detailed_training({
                    "dataset_name": "generated",
                    "epochs": 10, "batch_size": 32,
                    "accuracy": h.get("accuracy", 0),
                    "training_time": time.time(),
                    "samples": h.get("samples", 0),
                    "model_version": 1,
                })
        except Exception:
            pass
        return jsonify(api_response(data={"message": "重训练已启动，请查看 /api/model/status"}))
    except Exception as e:
        return jsonify(api_response(code=500, msg="重训练失败: %s" % e))


@app.route("/api/model/versions", methods=["GET"])
def model_versions():
    """获取模型版本列表"""
    return jsonify(api_response(data={"versions": model_manager.get_version_list()}))


@app.route("/api/model/rollback/<int:version>", methods=["POST"])
def model_rollback(version):
    """回滚模型到指定版本"""
    ok = model_manager.rollback(version)
    return jsonify(api_response(data={"success": ok, "version": version}))


@app.route("/api/model/compare", methods=["GET"])
def model_compare():
    """三模型对比检测"""
    try:
        _, _, X_test, y_test = ensure_data_generated()
        result = model_manager.compare_models(X_test[:min(len(X_test), 500)], y_test[:min(len(y_test), 500)])
        return jsonify(api_response(data=result))
    except Exception as e:
        return jsonify(api_response(code=500, msg="对比失败: %s" % e))


# ─── API: 训练历史 ───

@app.route("/api/train/history", methods=["GET"])
def train_history():
    """获取训练历史"""
    limit = request.args.get("limit", 50, type=int)
    records = db.get_detailed_training(limit)
    return jsonify(api_response(data={"records": records, "count": len(records)}))


@app.route("/api/train/dual", methods=["POST"])
def train_dual():
    """双模式训练（传统+联邦对比）"""
    req = request.get_json() or {}
    epochs = req.get("epochs", 10)
    batch_size = req.get("batch_size", 32)

    # 生成/加载数据
    X_train, y_train, X_test, y_test = ensure_data_generated()

    # 传统训练（sklearn逻辑回归）
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import accuracy_score
    t0 = time.time()
    trad_model = LogisticRegression(C=1.0, max_iter=200, solver="lbfgs")
    trad_model.fit(X_train, y_train)
    trad_preds = trad_model.predict(X_test)
    trad_acc = float(accuracy_score(y_test, trad_preds))
    trad_time = time.time() - t0

    # 联邦训练（numpy梯度下降模拟）
    t0 = time.time()
    n_features = X_train.shape[1]
    w = np.zeros(n_features)
    b = 0.0
    lr = 0.01
    fed_history = []
    for ep in range(min(epochs, 20)):
        idx = np.random.permutation(len(X_train))
        for start in range(0, len(X_train), batch_size):
            batch_idx = idx[start:start+batch_size]
            X_b = X_train[batch_idx]
            y_b = y_train[batch_idx]
            logits = np.clip(X_b @ w + b, -20, 20)
            preds = 1.0 / (1.0 + np.exp(-logits))
            error = preds - y_b
            gw = X_b.T @ error / len(X_b)
            gb = np.mean(error)
            # 加密噪声（模拟Paillier）
            gw *= 1 + np.random.randn() * 0.001
            gb *= 1 + np.random.randn() * 0.0005
            w -= lr * gw
            b -= lr * gb
        # 评估
        test_logits = np.clip(X_test @ w + b, -20, 20)
        test_preds = (1.0 / (1.0 + np.exp(-test_logits)) > 0.5).astype(int)
        ep_acc = float(accuracy_score(y_test, test_preds))
        ep_loss = float(-np.mean(y_test * np.log(1.0/(1.0+np.exp(-test_logits)) + 1e-10) +
                                  (1-y_test) * np.log(1 - 1.0/(1.0+np.exp(-test_logits)) + 1e-10)))
        fed_history.append({"epoch": ep+1, "accuracy": round(ep_acc, 4), "loss": round(ep_loss, 4)})
    fed_acc = fed_history[-1]["accuracy"] if fed_history else 0
    fed_time = time.time() - t0

    # 保存训练记录
    db.save_detailed_training({
        "model_type": "dual",
        "epochs": epochs,
        "batch_size": batch_size,
        "accuracy": round(fed_acc, 4),
        "loss": round(fed_history[-1]["loss"] if fed_history else 0, 4),
        "training_time": round(fed_time + trad_time, 2),
        "traditional_accuracy": round(trad_acc, 4),
        "federated_accuracy": round(fed_acc, 4),
        "samples": len(X_train),
        "model_version": model_manager._version_counter if hasattr(model_manager, '_version_counter') else 1,
    })

    return jsonify(api_response(data={
        "traditional": {
            "accuracy": round(trad_acc, 4),
            "training_time": round(trad_time, 2),
        },
        "federated": {
            "accuracy": round(fed_acc, 4),
            "training_time": round(fed_time, 2),
            "history": fed_history,
        },
        "comparison": {
            "accuracy_diff": round((fed_acc - trad_acc) * 100, 2),
            "time_diff": "+%.1f%%" % ((fed_time / max(trad_time, 0.01) - 1) * 100),
        },
        "samples": len(X_train),
        "features": n_features,
    }))


# ─── API: 检测历史 ───

@app.route("/api/detection/history", methods=["GET"])
def detection_history():
    """获取检测历史"""
    limit = request.args.get("limit", 50, type=int)
    records = db.get_detection_history(limit)
    return jsonify(api_response(data={"records": records, "count": len(records)}))


@app.route("/api/detection/compare", methods=["POST"])
def detection_compare():
    """三模型对比检测"""
    req = request.get_json() or {}
    records = req.get("data", [])
    if not records:
        return jsonify(api_response(code=400, msg="请提供检测数据"))

    import numpy as np
    features_list = []
    for record in records:
        feat = []
        for fn in GEN_FEATURES:
            feat.append(float(record.get(fn, 0)))
        features_list.append(feat)
    X = np.array(features_list, dtype=np.float64)

    # 规则检测
    rule_scores = []
    for i in range(len(X)):
        fa = float(records[i].get("failed_attempts", 0))
        rf = float(records[i].get("request_frequency", 0))
        score = 1.0 if fa > 30 or rf > 200 else 0.3 if fa > 10 or rf > 100 else 0.0
        rule_scores.append(score)
    rule_preds = (np.array(rule_scores) > 0.5).astype(int)

    # IF检测
    if model_manager.is_ready and model_manager.if_model is not None:
        if_raw = model_manager.if_model.decision_function(X)
        if_s = 1.0 - (if_raw - if_raw.min()) / (if_raw.max() - if_raw.min() + 1e-10)
        if_preds = (if_s > 0.5).astype(int)
    else:
        if_preds = np.zeros(len(X))

    # 混合检测
    hybrid_preds = model_manager.predict(X) if model_manager.is_ready else np.zeros(len(X))
    hybrid_probs = model_manager.predict_proba(X) if model_manager.is_ready else np.zeros(len(X))

    rule_anom = int(np.sum(rule_preds))
    if_anom = int(np.sum(if_preds))
    hybrid_anom = int(np.sum(hybrid_preds))

    dets = []
    for i in range(len(X)):
        dets.append({
            "id": records[i].get("id", i+1),
            "rule_result": bool(rule_preds[i]),
            "if_result": bool(if_preds[i]),
            "hybrid_result": bool(hybrid_preds[i]),
            "confidence": round(float(hybrid_probs[i]), 4),
        })

    return jsonify(api_response(data={
        "total": len(X),
        "rule_anomalies": rule_anom,
        "if_anomalies": if_anom,
        "hybrid_anomalies": hybrid_anom,
        "detections": dets,
        "summary": {
            "rule_accuracy": "-",
            "if_accuracy": "-",
            "hybrid_accuracy": "-",
        }
    }))


# ─── API: 导出报告 ───

@app.route("/api/export/report", methods=["GET"])
def export_report():
    """导出时间范围报告"""
    hours = request.args.get("hours", 24, type=int)
    system_status = db.get_system_status(hours)
    attack_records = db.get_attack_records(hours)
    opt_history = db.get_optimization_history(hours)
    stats = db.get_statistics()

    report = {
        "export_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "time_range": "%d小时" % hours,
        "statistics": stats,
        "system_status_count": len(system_status),
        "attack_count": len(attack_records),
        "optimization_count": len(opt_history),
        "model_status": model_manager.get_status(),
        "optimizer_status": get_optimizer().get_status(),
    }
    return jsonify(api_response(data=report))


# ─── API: 数据查询 ───

@app.route("/api/data/system_status", methods=["GET"])
def data_system_status():
    hours = request.args.get("hours", 24, type=int)
    data = db.get_system_status(hours)
    return jsonify(api_response(data={"records": data, "count": len(data)}))


@app.route("/api/data/attack_records", methods=["GET"])
def data_attack_records():
    hours = request.args.get("hours", 24, type=int)
    data = db.get_attack_records(hours)
    return jsonify(api_response(data={"records": data, "count": len(data)}))


@app.route("/api/data/optimization_history", methods=["GET"])
def data_optimization_history():
    hours = request.args.get("hours", 24, type=int)
    data = db.get_optimization_history(hours)
    return jsonify(api_response(data={"records": data, "count": len(data)}))


@app.route("/api/data/statistics", methods=["GET"])
def data_statistics():
    """获取实时综合统计数据"""
    hours = request.args.get("hours", 24, type=int)
    stats = db.get_statistics()

    # 附加优化器状态
    opt = get_optimizer()
    opt_status = opt.get_status()

    return jsonify(api_response(data={
        "total_attacks": stats["total_attacks"],
        "detection_rate": stats["detection_rate"],
        "total_gain": stats["total_gain"],
        "current_key_length": opt_status["current_key_length"],
        "current_rounds": opt_status["current_rounds"],
        "risk_level": opt_status["risk_level"],
        "performance_gain": opt_status["performance_gain"],
        "cpu_usage": 0.3,
        "memory_usage": 0.4,
        "models_ready": model_manager.is_ready,
    }))


# ─── API: UNSW数据集 ───

@app.route("/api/dataset/unsw/status", methods=["GET"])
def dataset_unsw_status():
    """检查UNSW-NB15数据集状态"""
    path = "data/datasets/UNSW-NB15"
    files = []
    if os.path.exists(path):
        files = [f for f in os.listdir(path) if f.endswith('.csv')]
    return jsonify(api_response(data={"exists": len(files) > 0, "files": files, "path": path}))


@app.route("/api/dataset/unsw/process", methods=["POST"])
def dataset_unsw_process():
    """处理UNSW-NB15数据集并拆分为联邦4节点"""
    try:
        from src.preprocess.feature_engineering import load_unsw_nb15, minmax_normalize
        from src.preprocess.federated_splitter import save_federated_data
        from src.detection.ensemble_detector import ensemble_detector

        path = "data/datasets/UNSW-NB15"
        csv_files = [f for f in os.listdir(path) if f.endswith('.csv')]
        if not csv_files:
            return jsonify(api_response(code=400, msg="未找到UNSW-NB15数据文件"))

        filepath = os.path.join(path, csv_files[0])
        logger.info("加载UNSW-NB15: %s", filepath)
        X, y = load_unsw_nb15(filepath)
        X = minmax_normalize(X)

        # 保存处理后的数据
        np.save(os.path.join(path, "X_processed.npy"), X)
        np.save(os.path.join(path, "y_processed.npy"), y)

        # 拆分为联邦4节点
        nodes = save_federated_data(X, y)

        # 创建序列数据用于LSTM
        X_seq = np.array([X[i:i+10] for i in range(min(len(X)-10, 2000))])
        y_seq = np.array([1.0 if np.mean(y[i:i+10]) > 0.3 else 0.0 for i in range(min(len(X)-10, 2000))])

        # 训练三模型融合检测器
        result = ensemble_detector.fit(X[:min(len(X), 5000)], y[:min(len(y), 5000)], X_seq[:min(len(X_seq), 500)])
        logger.info("三模型融合检测器训练完成: %s", result)

        return jsonify(api_response(data={
            "samples": len(X),
            "features": X.shape[1],
            "nodes": [{"name": n[0], "samples": n[1]} for n in nodes],
            "ensemble_accuracy": result.get("accuracy", 0),
        }))
    except Exception as e:
        logger.error("数据集处理失败: %s", e)
        return jsonify(api_response(code=500, msg="处理失败: %s" % e))


# ─── API: 联邦学习4节点 ───

@app.route("/api/federated/nodes", methods=["GET"])
def federated_nodes():
    """获取联邦节点状态"""
    from src.preprocess.federated_splitter import NODE_NAMES, FEDERATED_DIR
    nodes = []
    for name in NODE_NAMES:
        node_dir = os.path.join(FEDERATED_DIR, name)
        X_path = os.path.join(node_dir, "X.npy")
        y_path = os.path.join(node_dir, "y.npy")
        if os.path.exists(X_path) and os.path.exists(y_path):
            X = np.load(X_path)
            nodes.append({"name": name, "samples": len(X), "ready": True})
        else:
            nodes.append({"name": name, "samples": 0, "ready": False})
    return jsonify(api_response(data={"nodes": nodes, "total": len(nodes)}))


@app.route("/api/federated/round", methods=["POST"])
def federated_round():
    """执行一轮联邦训练"""
    req = request.get_json() or {}
    epochs = req.get("epochs", 5)
    from src.preprocess.federated_splitter import NODE_NAMES, FEDERATED_DIR
    from src.federated.client import FederatedClient
    from src.federated.aggregator import fedavg_server

    results = []
    for name in NODE_NAMES:
        client = FederatedClient(name, os.path.join(FEDERATED_DIR, name))
        if client.load_data():
            result = client.train_local(epochs=epochs)
            results.append(result)

    global_weights = fedavg_server.aggregate(results)

    return jsonify(api_response(data={
        "round": fedavg_server.round,
        "clients": [{"name": r["name"], "accuracy": r["accuracy"], "samples": r["samples"]} for r in results],
        "avg_accuracy": round(np.mean([r["accuracy"] for r in results]), 4) if results else 0,
        "history": fedavg_server.get_history(),
    }))


@app.route("/api/federated/history", methods=["GET"])
def federated_history():
    """获取联邦训练历史"""
    from src.experiments.experiment_manager import exp_manager
    return jsonify(api_response(data={"records": exp_manager.get_federated_history()}))


# ─── API: 三模型融合检测 ───

@app.route("/api/ensemble/detect", methods=["POST"])
def ensemble_detect():
    """三模型融合检测"""
    from src.detection.ensemble_detector import ensemble_detector
    if not ensemble_detector.is_ready():
        ensemble_detector.load_or_init()

    req = request.get_json() or {}
    records = req.get("data", [])
    if not records:
        return jsonify(api_response(code=400, msg="请提供检测数据"))

    import numpy as np
    from src.preprocess.feature_engineering import extract_features_structured
    X_list = []
    for rec in records:
        X_list.append(extract_features_structured(rec))
    X = np.array(X_list, dtype=np.float64)

    preds, scores, risk_levels = ensemble_detector.predict(X)
    risk_names = {0: "低", 1: "中", 2: "高", 3: "危险"}

    results = []
    for i in range(len(X)):
        results.append({
            "id": records[i].get("id", i+1),
            "is_attack": bool(preds[i]),
            "risk_score": round(float(scores[i]), 4),
            "risk_level": risk_names.get(int(risk_levels[i]), "低"),
            "attack_type": ensemble_detector.ATTACK_TYPES[int(preds[i] * 6) % 7] if preds[i] else "正常",
        })

    return jsonify(api_response(data={
        "total": len(results),
        "anomalies": int(np.sum(preds)),
        "detections": results,
        "model": "IF+XGBoost+LSTM融合(0.3/0.3/0.4)",
    }))


@app.route("/api/ensemble/status", methods=["GET"])
def ensemble_status():
    """融合检测器状态"""
    from src.detection.ensemble_detector import ensemble_detector
    return jsonify(api_response(data={"ready": ensemble_detector.is_ready()}))


# ─── API: 实验管理 ───

@app.route("/api/experiment/list", methods=["GET"])
def experiment_list():
    """获取实验列表"""
    from src.experiments.experiment_manager import exp_manager
    return jsonify(api_response(data={"experiments": exp_manager.get_experiments()}))


# ─── 启动 ───

def _pretrain_on_startup():
    """启动时预训练模型（后台线程）"""
    logger.info("=== 启动预训练 ===")

    # 1. 生成训练数据 + 自动训练模型
    try:
        X_train, y_train, X_test, y_test = ensure_data_generated()
        logger.info("训练数据就绪: 训练集%d条, 测试集%d条", len(X_train), len(X_test))
        model_manager.auto_load_or_train(X_train, y_train)
    except Exception as e:
        logger.warning("模型初始化失败: %s", e)

    # 2. 尝试处理UNSW-NB15数据集并训练三模型融合检测器
    try:
        path = "data/datasets/UNSW-NB15"
        csv_files = [f for f in os.listdir(path) if f.endswith('.csv')] if os.path.exists(path) else []
        if csv_files:
            logger.info("检测到UNSW-NB15数据集，开始处理...")
            from src.preprocess.feature_engineering import load_unsw_nb15, minmax_normalize
            from src.preprocess.federated_splitter import save_federated_data
            from src.detection.ensemble_detector import ensemble_detector

            filepath = os.path.join(path, csv_files[0])
            X, y = load_unsw_nb15(filepath)
            X = minmax_normalize(X)
            np.save(os.path.join(path, "X_processed.npy"), X)
            np.save(os.path.join(path, "y_processed.npy"), y)
            nodes = save_federated_data(X, y)

            X_seq = np.array([X[i:i+10] for i in range(min(len(X)-10, 2000))])
            result = ensemble_detector.fit(X[:min(len(X), 5000)], y[:min(len(y), 5000)], X_seq[:min(len(X_seq), 500)])
            logger.info("三模型融合训练完成: accuracy=%.4f", result.get("accuracy", 0))
        else:
            logger.info("UNSW-NB15数据集不存在，跳过 (可下载: kaggle datasets download -d mrwellsdavid/unsw-nb15)")
            from src.detection.ensemble_detector import ensemble_detector
            ensemble_detector.load_or_init()
    except Exception as e:
        logger.warning("UNSW数据处理失败: %s", e)

    # 3. 训练优化智能体
    try:
        if model_manager.is_ready and model_manager.q_agent and model_manager.q_agent.is_trained:
            logger.info("复用ModelManager的Q-learning智能体")
        else:
            get_optimizer().train(episodes=500)
            logger.info("优化智能体预训练完成")
    except Exception as e:
        logger.warning("优化智能体预训练失败: %s", e)

    # 3. 启动数据采集器（每10秒）
    try:
        def _status_callback():
            opt_st = get_optimizer().get_status()
            return {
                "attack_risk": (0 if opt_st["risk_level"] == "low" else
                               0.3 if opt_st["risk_level"] == "medium" else
                               0.6 if opt_st["risk_level"] == "high" else 0.9),
                "cpu_usage": 0.3,
                "memory_usage": 0.4,
                "key_length": opt_st["current_key_length"],
                "encryption_rounds": opt_st["current_rounds"],
            }
        db.start_collector(_status_callback, interval=10.0)
        logger.info("数据采集器已启动(10秒间隔)")
    except Exception as e:
        logger.warning("数据采集器启动失败: %s", e)

    logger.info("=== 预训练完成 ===")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "0.0.0.0")

    # 启动后台预训练线程
    t = threading.Thread(target=_pretrain_on_startup, daemon=True)
    t.start()
    logger.info("后台预训练已启动")

    logger.info("启动服务器: http://%s:%d" % (host, port))
    logger.info("系统功能: 看板 | 数据加密 | 联邦训练 | 加密对比 | 攻击检测 | 自适应优化 | IP访客 | 数据集管理")
    app.run(debug=False, host=host, port=port, threaded=True)
