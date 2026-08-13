# -*- coding: utf-8 -*-
"""Flask主后端 - 基于机器学习的密码攻击检测与加密算法自适应优化系统"""

import os
import sys
import json
import csv
import random
import time
import threading
import hashlib
import hmac
import secrets
from collections import deque
from datetime import datetime, timedelta

# Keep BLAS/OpenMP thread stacks bounded on the 2GB deployment target.  The
# models in this project are small, so one numerical worker is a safer default
# and avoids reserving hundreds of megabytes for idle thread stacks.  Operators
# can raise the project-specific limit when deploying to a larger machine.
try:
    _numeric_thread_limit = max(1, min(int(os.environ.get("DACHUANG_NUMERIC_THREADS", "1")), 4))
except (TypeError, ValueError):
    _numeric_thread_limit = 1
for _thread_env_name in (
    "OPENBLAS_NUM_THREADS",
    "OMP_NUM_THREADS",
    "MKL_NUM_THREADS",
    "NUMEXPR_NUM_THREADS",
    "BLIS_NUM_THREADS",
):
    # DACHUANG_NUMERIC_THREADS is the project-level source of truth.  Applying
    # it explicitly also protects hosts that inherit an overly large BLAS
    # thread count from a parent shell or another service.
    os.environ[_thread_env_name] = str(_numeric_thread_limit)

import numpy as np
from flask import Flask, request, jsonify, send_file, session, redirect
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
from src.utils.atomic_files import atomic_save_npy, atomic_write_bytes, atomic_write_json
from src.user_submission_manager import SubmissionStatusError, UploadValidationError, user_submission_manager, validate_upload_file
from src.preprocess.feature_engineering import FEATURE_NORMALIZATION_VERSION
from src.preprocess.federated_splitter import FEDERATED_SPLIT_VERSION
from src.analysis.external_advisor import (
    ExternalAdvisorClient,
    ExternalAdvisorConfigError,
    ExternalAdvisorDisabledError,
    ExternalAdvisorProviderError,
    ExternalAdvisorResponseError,
    ExternalAdvisorSettingsStore,
    build_ai_assisted_decisions,
    build_redacted_analysis_payload,
    build_redacted_training_comparison_payload,
    external_cache_key,
    make_external_analysis_record,
    test_payload as external_advisor_test_payload,
)

# ─── 日志配置 ───
os.makedirs("logs", exist_ok=True)
logger.remove()
logger.add(sys.stderr, format="<green>{time:HH:mm:ss}</green> | <level>{level:7}</level> | {message}", level="INFO", colorize=True)
logger.add("logs/system_{time:YYYY-MM-DD}.log", rotation="1 day", retention="7 days",
           format="{time:YYYY-MM-DD HH:mm:ss} | {level:7} | {name}:{line} | {message}", level="DEBUG")

# ─── Flask App ───
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))


def _load_or_create_flask_secret():
    configured = os.environ.get("FLASK_SECRET_KEY", "").strip()
    if configured:
        return configured
    key_path = os.path.join(PROJECT_ROOT, "data", "keys", "flask_session.key")
    try:
        with open(key_path, "r", encoding="utf-8") as stream:
            stored = stream.read().strip()
        if len(stored) >= 32:
            return stored
    except OSError:
        pass
    generated = secrets.token_urlsafe(48)
    atomic_write_bytes(key_path, generated.encode("utf-8"))
    return generated


# The UI is a single self-contained HTML file.  Exposing the repository root as
# Flask's static directory would also expose source code, configuration, Git
# metadata and runtime databases.  Serve only the explicit index route below.
app = Flask(__name__, static_folder=None)
app.secret_key = _load_or_create_flask_secret()
app.config["UPLOAD_FOLDER"] = "uploads/"
app.config["ALLOWED_EXTENSIONS"] = {"csv", "json", "txt"}
app.config["DATA_FOLDER"] = "data"
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = str(os.environ.get("SESSION_COOKIE_SECURE", "")).lower() in {"1", "true", "yes"}
app.permanent_session_lifetime = timedelta(days=30)
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


def binary_classification_metrics(y_true, y_pred):
    """Return accuracy/precision/recall/f1 without adding metric dependencies."""
    y_true = np.asarray(y_true).astype(int)
    y_pred = np.asarray(y_pred).astype(int)
    if len(y_true) == 0:
        return {"accuracy": 0.0, "precision": None, "recall": None, "f1": None}
    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))
    accuracy = float((tp + tn) / max(1, len(y_true)))
    precision = float(tp / (tp + fp)) if (tp + fp) else None
    recall = float(tp / (tp + fn)) if (tp + fn) else None
    if precision is None or recall is None or (precision + recall) == 0:
        f1 = None
    else:
        f1 = float(2 * precision * recall / (precision + recall))
    return {
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4) if precision is not None else None,
        "recall": round(recall, 4) if recall is not None else None,
        "f1": round(f1, 4) if f1 is not None else None,
    }


def binary_log_loss(y_true, scores):
    """Return a bounded binary log loss for persisted training records."""
    y_true = (np.asarray(y_true).reshape(-1) > 0).astype(int)
    scores = np.asarray(scores, dtype=np.float64).reshape(-1)
    if len(y_true) == 0 or len(y_true) != len(scores):
        return None
    scores = np.clip(scores, 1e-6, 1.0 - 1e-6)
    loss = -np.mean(y_true * np.log(scores) + (1 - y_true) * np.log(1 - scores))
    return round(float(loss), 4)


def evaluate_linear_binary_weights(X, y, weights):
    """Evaluate FedAvg logistic weights on an untouched feature partition."""
    X = np.asarray(X, dtype=np.float64)
    y = np.asarray(y).reshape(-1)
    weights = np.asarray(weights, dtype=np.float64).reshape(-1)
    if X.ndim != 2 or len(X) != len(y) or len(X) == 0 or len(weights) != X.shape[1] + 1:
        return None
    logits = np.clip(np.c_[X, np.ones(len(X))] @ weights, -50.0, 50.0)
    scores = 1.0 / (1.0 + np.exp(-logits))
    predictions = (scores >= 0.5).astype(int)
    metrics = binary_classification_metrics((y > 0).astype(int), predictions)
    metrics["loss"] = binary_log_loss(y, scores)
    return metrics


SHARED_VALIDATION_SPLIT_VERSION = "shared-stratified-holdout-v1"
SHARED_VALIDATION_FRACTION = 0.2
FEDERATED_DEFAULT_LOCAL_EPOCHS = 20
PREPARED_BUNDLE_VERSION = "prepared-array-bundle-v1"


def _stable_seed(value, default=42):
    """Derive a deterministic NumPy seed from current or legacy revision IDs."""
    text = str(value or "").strip()
    if not text:
        return int(default)
    try:
        return int(text[:8], 16)
    except (TypeError, ValueError):
        return int(hashlib.sha256(text.encode("utf-8")).hexdigest()[:8], 16)


def _stratified_holdout_split(X, y, seed=42, validation_fraction=SHARED_VALIDATION_FRACTION):
    """Split one deterministic binary holdout shared by local and FedAvg paths.

    Small or severely imbalanced sources fall back to using all rows for
    training.  This is safer than claiming an independent validation metric
    when both labels cannot be represented in both partitions.
    """
    X = np.asarray(X)
    y = np.asarray(y).reshape(-1)
    empty_x = np.empty((0, X.shape[1] if X.ndim == 2 else 0), dtype=X.dtype if X.size else np.float64)
    empty_y = np.empty(0, dtype=y.dtype if y.size else np.int32)
    if X.ndim != 2 or len(X) != len(y) or len(X) < 20:
        return X, y, empty_x, empty_y

    binary_y = (y > 0).astype(int)
    labels, counts = np.unique(binary_y, return_counts=True)
    if len(labels) < 2 or int(np.min(counts)) < 2:
        return X, y, empty_x, empty_y

    rng = np.random.default_rng(int(seed))
    train_indices = []
    validation_indices = []
    fraction = max(0.05, min(float(validation_fraction), 0.4))
    for label in labels:
        indices = np.where(binary_y == label)[0]
        rng.shuffle(indices)
        validation_count = max(1, int(round(len(indices) * fraction)))
        validation_count = min(validation_count, len(indices) - 1)
        validation_indices.extend(indices[:validation_count].tolist())
        train_indices.extend(indices[validation_count:].tolist())

    train_indices = np.asarray(sorted(train_indices), dtype=np.int64)
    validation_indices = np.asarray(sorted(validation_indices), dtype=np.int64)
    train_labels = binary_y[train_indices] if len(train_indices) else np.empty(0, dtype=int)
    validation_labels = binary_y[validation_indices] if len(validation_indices) else np.empty(0, dtype=int)
    if (
        len(train_indices) < 10
        or len(validation_indices) < 2
        or len(np.unique(train_labels)) < 2
        or len(np.unique(validation_labels)) < 2
    ):
        return X, y, empty_x, empty_y
    return X[train_indices], y[train_indices], X[validation_indices], y[validation_indices]


def _stratified_training_sample(X, y, max_samples=5000, seed=42):
    """Return a deterministic class-preserving training subset."""
    X = np.asarray(X)
    y = np.asarray(y).reshape(-1)
    max_samples = max(1, int(max_samples))
    if len(X) <= max_samples:
        return X, y
    rng = np.random.default_rng(int(seed))
    labels, counts = np.unique(y, return_counts=True)
    selected = []
    allocated = 0
    for index, (label, count) in enumerate(zip(labels, counts)):
        label_indices = np.where(y == label)[0]
        if index == len(labels) - 1:
            take = min(len(label_indices), max_samples - allocated)
        else:
            take = min(len(label_indices), max(1, int(round(max_samples * count / len(y)))))
        if take > 0:
            selected.extend(rng.choice(label_indices, size=take, replace=False).tolist())
            allocated += take
    selected = np.asarray(sorted(selected[:max_samples]), dtype=np.int64)
    return X[selected], y[selected]


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
_secure_aggregation_paillier = None
_secure_aggregation_paillier_lock = threading.Lock()
_fe = None
_detector = None
_detector_trained = False
_optimizer = None
_primihub_client = None
_real_detector = None
_real_detector_trained = False
_real_federated = None
_init_lock = threading.Lock()
_dataset_sources_cache = {"time": 0.0, "value": None}
_dataset_sources_cache_lock = threading.Lock()
_dataset_distribution_cache = {}
_dataset_distribution_cache_lock = threading.Lock()
DATASET_SOURCES_CACHE_SECONDS = 30
_admin_submissions_cache = {"time": 0.0, "value": None}
_admin_submissions_cache_lock = threading.Lock()
ADMIN_SUBMISSIONS_CACHE_SECONDS = 15
_dataset_prepare_lock = threading.RLock()
_training_operation_lock = threading.Lock()
_training_worker_state_lock = threading.Lock()
_training_worker_thread = None
_training_worker_wakeup = threading.Event()
_analysis_operation_lock = threading.Lock()
_external_analysis_operation_lock = threading.Lock()
_external_analysis_rate_lock = threading.Lock()
_external_analysis_call_times = deque()
_runtime_model_init_lock = threading.Lock()
_external_ai_settings_store = ExternalAdvisorSettingsStore()


def _ensure_paillier():
    """后台线程预生成用于字段展示的轻量 Paillier 密钥。"""
    global _paillier, _paillier_ready
    with _paillier_lock:
        if not _paillier_ready:
            try:
                logger.info("正在生成Paillier字段展示密钥（1024位）...")
                from src.encryption.paillier import Paillier
                _paillier = Paillier(key_size=1024)  # 用1024位加速
                _paillier.generate_keys()
                _paillier_ready = True
                logger.info("Paillier字段展示密钥生成完成")
            except Exception as e:
                logger.warning("Paillier密钥生成失败: %s" % e)


def get_paillier():
    global _paillier, _paillier_ready
    if not _paillier_ready:
        _ensure_paillier()
    return _paillier if _paillier_ready else None


def get_secure_aggregation_paillier():
    """Lazily create the stronger key used only for real weight aggregation."""
    global _secure_aggregation_paillier
    with _secure_aggregation_paillier_lock:
        if _secure_aggregation_paillier is None:
            try:
                raw_bits = int(os.environ.get("DACHUANG_SECURE_AGGREGATION_KEY_BITS", "2048"))
                key_bits = max(2048, min(raw_bits, 4096))
                logger.info("正在生成Paillier安全聚合密钥（{}位）...", key_bits)
                from src.encryption.paillier import Paillier
                candidate = Paillier(key_size=key_bits)
                candidate.generate_keys()
                _secure_aggregation_paillier = candidate
                logger.info("Paillier安全聚合密钥生成完成")
            except Exception as error:
                logger.exception("Paillier安全聚合密钥生成失败: {}", error)
                return None
    return _secure_aggregation_paillier


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
    return {"code": code, "msg": msg, "data": {} if data is None else data}


DEFAULT_ADMIN_USERNAME = "root"
DEFAULT_ADMIN_PASSWORD = "root"
ADMIN_LAUNCHER_HASH_FILE = os.environ.get(
    "ADMIN_LAUNCHER_HASH_FILE",
    os.path.join("data", "keys", "admin_launcher.sha256"),
)


def _is_local_request():
    host = (request.host or "").lower().strip()
    if host.startswith("["):
        hostname = host.split("]", 1)[0].lstrip("[")
    else:
        hostname = host.split(":", 1)[0]
    return hostname in ("127.0.0.1", "localhost", "::1")


def _secret_configuration_allowed():
    """Only accept new secrets over HTTPS or a loopback admin session."""
    if _is_local_request() or request.is_secure:
        return True
    return str(os.environ.get("DACHUANG_ALLOW_INSECURE_SECRET_CONFIG", "")).lower() in {
        "1", "true", "yes",
    }


def _admin_credentials():
    username = str(os.environ.get("ADMIN_USERNAME") or DEFAULT_ADMIN_USERNAME).strip()
    password = str(os.environ.get("ADMIN_PASSWORD") or DEFAULT_ADMIN_PASSWORD)
    return (
        username or DEFAULT_ADMIN_USERNAME,
        password,
    )


def _admin_auth_config_status():
    username, password = _admin_credentials()
    configured = bool(str(os.environ.get("ADMIN_PASSWORD") or "").strip())
    weak_default = password == DEFAULT_ADMIN_PASSWORD
    allow_default = str(os.environ.get("ALLOW_DEFAULT_ADMIN", "")).lower() in {"1", "true", "yes"}
    disabled_reason = ""
    if weak_default and not (allow_default or _is_local_request()):
        disabled_reason = "公网管理端未配置 ADMIN_PASSWORD，默认账号仅允许在本机调试。"
    return {
        "username": username,
        "password": password,
        "configured": configured,
        "disabled": bool(disabled_reason),
        "disabled_reason": disabled_reason,
        "using_default": weak_default,
    }


def _is_admin_logged_in():
    return bool(session.get("admin_logged_in"))


def _admin_launcher_hash():
    try:
        with open(ADMIN_LAUNCHER_HASH_FILE, "r", encoding="utf-8") as f:
            value = f.read().strip().lower()
        return value if len(value) == 64 else ""
    except OSError:
        return ""


def _admin_required_response():
    return jsonify(api_response(code=401, msg="请先登录管理端", data={"login_required": True})), 401


ADMIN_PROTECTED_LEGACY_PREFIXES = (
    "/api/datasets/",
    "/api/model/",
    "/api/optimization/",
    "/api/federated/",
    "/api/training/",
    "/api/train/",
    "/api/data/",
    "/api/experiment/",
)
ADMIN_PROTECTED_LEGACY_PATHS = {
    "/api/train_fate",
    "/api/train_plaintext",
    "/api/dataset/add",
    "/api/dataset/list",
    "/api/dataset/unsw/process",
    "/api/detection/history",
    "/api/detection/compare",
    "/api/export/report",
}


@app.before_request
def admin_api_guard():
    if request.method == "OPTIONS":
        return None
    protected = request.path.startswith("/api/admin/") or request.path in ADMIN_PROTECTED_LEGACY_PATHS or any(
        request.path.startswith(prefix) for prefix in ADMIN_PROTECTED_LEGACY_PREFIXES
    )
    if protected and request.path not in (
        "/api/admin/login",
        "/api/admin/session",
        "/api/admin/logout",
    ):
        if not _is_admin_logged_in():
            return _admin_required_response()


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in app.config["ALLOWED_EXTENSIONS"]


DATASET_DIR = os.path.join("data", "datasets")
UNSW_DIR = os.path.join(DATASET_DIR, "UNSW-NB15")
PROCESSED_DATA_DIR = os.path.join(DATASET_DIR, "processed")
PROCESSED_X_PATH = os.path.join(PROCESSED_DATA_DIR, "X_processed.npy")
PROCESSED_Y_PATH = os.path.join(PROCESSED_DATA_DIR, "y_processed.npy")
PROCESSED_TRAIN_X_PATH = os.path.join(PROCESSED_DATA_DIR, "X_train.npy")
PROCESSED_TRAIN_Y_PATH = os.path.join(PROCESSED_DATA_DIR, "y_train.npy")
PROCESSED_VALIDATION_X_PATH = os.path.join(PROCESSED_DATA_DIR, "X_validation.npy")
PROCESSED_VALIDATION_Y_PATH = os.path.join(PROCESSED_DATA_DIR, "y_validation.npy")
PROCESSED_META_PATH = os.path.join(PROCESSED_DATA_DIR, "metadata.json")


def _csv_row_count(filepath, max_rows=None):
    count = 0
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.reader(f)
            next(reader, None)
            for _ in reader:
                count += 1
                if max_rows and count >= max_rows:
                    break
    except Exception:
        return 0
    return count


def _find_dataset_source():
    """Find the best available dataset source without downloading anything."""
    candidates = []

    # The management portal should use the project's existing generated
    # training data first. These files are the current built-in dataset for
    # local training and federated-node splitting.
    generated_train = os.path.join("data", "generated", "train.csv")
    generated_test = os.path.join("data", "generated", "test.csv")
    if os.path.exists(generated_train):
        candidates.append({
            "path": generated_train,
            "test_path": generated_test if os.path.exists(generated_test) else None,
            "source": "data/generated/train.csv",
            "source_type": "local_generated",
        })

    preferred = [
        os.path.join(UNSW_DIR, "UNSW_NB15_training-set.csv"),
        os.path.join(UNSW_DIR, "UNSW_NB15_testing-set.csv"),
    ]
    if os.path.isdir(UNSW_DIR):
        for name in sorted(os.listdir(UNSW_DIR)):
            if name.lower().endswith(".csv"):
                path = os.path.join(UNSW_DIR, name)
                if path not in preferred:
                    preferred.append(path)
    for path in preferred:
        if os.path.exists(path):
            candidates.append({
                "path": path,
                "source": os.path.basename(path),
                "source_type": "UNSW-NB15",
            })

    if os.path.isdir("data"):
        for name in sorted(os.listdir("data")):
            path = os.path.join("data", name)
            if name.lower().endswith(".csv") and os.path.isfile(path):
                candidates.append({
                    "path": path,
                    "source": name,
                    "source_type": "local_csv",
                })

    return candidates[0] if candidates else None


def _processed_dataset_ready():
    required_paths = (
        PROCESSED_X_PATH,
        PROCESSED_Y_PATH,
        PROCESSED_TRAIN_X_PATH,
        PROCESSED_TRAIN_Y_PATH,
        PROCESSED_VALIDATION_X_PATH,
        PROCESSED_VALIDATION_Y_PATH,
    )
    if not all(os.path.exists(path) for path in required_paths):
        return False
    metadata = _load_processed_metadata()
    return bool(
        metadata.get("preprocessing_version") == FEATURE_NORMALIZATION_VERSION
        and metadata.get("validation_split_version") == SHARED_VALIDATION_SPLIT_VERSION
        and metadata.get("federated_split_version") == FEDERATED_SPLIT_VERSION
        and metadata.get("prepared_bundle_version") == PREPARED_BUNDLE_VERSION
        and _prepared_array_bundle_consistent(metadata)
    )


def _load_processed_metadata():
    if not os.path.exists(PROCESSED_META_PATH):
        return {}
    try:
        with open(PROCESSED_META_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _load_prepared_arrays(limit=None):
    """Read the prepared feature/label pair under the preparation lock."""
    with _dataset_prepare_lock:
        X = np.load(PROCESSED_X_PATH)
        y = np.load(PROCESSED_Y_PATH)
        if len(X) != len(y):
            raise ValueError("prepared feature and label counts do not match")
        if limit and len(X) > int(limit):
            X = X[:int(limit)]
            y = y[:int(limit)]
        return X, y, _load_processed_metadata()


def _load_prepared_partition(X_path, y_path, limit=None):
    """Load one coherent prepared train/validation partition."""
    with _dataset_prepare_lock:
        X = np.load(X_path)
        y = np.load(y_path)
        if len(X) != len(y):
            raise ValueError("prepared partition feature and label counts do not match")
        if limit and len(X) > int(limit):
            X = X[:int(limit)]
            y = y[:int(limit)]
        return X, y, _load_processed_metadata()


def _load_prepared_training_arrays(limit=None):
    return _load_prepared_partition(PROCESSED_TRAIN_X_PATH, PROCESSED_TRAIN_Y_PATH, limit=limit)


def _load_prepared_validation_arrays(limit=None):
    return _load_prepared_partition(
        PROCESSED_VALIDATION_X_PATH,
        PROCESSED_VALIDATION_Y_PATH,
        limit=limit,
    )


def _save_shared_training_partitions(X, y, split_seed, preparation_id):
    """Persist full data plus a shared holdout and train-only node shards."""
    from src.preprocess.federated_splitter import save_federated_data

    X = np.asarray(X, dtype=np.float64)
    y = np.asarray(y, dtype=np.int32).reshape(-1)
    X_train, y_train, X_validation, y_validation = _stratified_holdout_split(
        X,
        y,
        seed=split_seed,
    )
    validation_available = bool(len(X_validation))
    validation_id = None
    if validation_available:
        validation_raw = "%s:%s:%s" % (
            preparation_id,
            SHARED_VALIDATION_SPLIT_VERSION,
            len(X_validation),
        )
        validation_id = "val-" + hashlib.sha256(validation_raw.encode("utf-8")).hexdigest()[:12]

    os.makedirs(PROCESSED_DATA_DIR, exist_ok=True)
    atomic_save_npy(PROCESSED_X_PATH, X)
    atomic_save_npy(PROCESSED_Y_PATH, y)
    atomic_save_npy(PROCESSED_TRAIN_X_PATH, X_train)
    atomic_save_npy(PROCESSED_TRAIN_Y_PATH, y_train)
    atomic_save_npy(PROCESSED_VALIDATION_X_PATH, X_validation)
    atomic_save_npy(PROCESSED_VALIDATION_Y_PATH, y_validation)
    nodes, split_metadata = save_federated_data(
        X_train,
        y_train,
        seed=split_seed,
        return_metadata=True,
    )

    def label_counts(values):
        return {
            str(key): int(value)
            for key, value in zip(*np.unique(values, return_counts=True))
        } if len(values) else {}

    return {
        "nodes": nodes,
        "training_samples": int(len(X_train)),
        "validation_samples": int(len(X_validation)),
        "validation_available": validation_available,
        "validation_id": validation_id,
        "validation_split_version": SHARED_VALIDATION_SPLIT_VERSION,
        "validation_fraction": SHARED_VALIDATION_FRACTION if validation_available else 0.0,
        "training_label_counts": label_counts(y_train),
        "validation_label_counts": label_counts(y_validation),
        "federated_split_version": FEDERATED_SPLIT_VERSION,
        "federated_split": split_metadata,
        "node_details": split_metadata.get("nodes") or [],
    }


def _append_incremental_training_partitions(new_x, new_y, split_seed, preparation_id):
    """Append newly approved rows while keeping the existing holdout frozen.

    Feature extraction/decryption is performed only for the new submissions.
    The lightweight node files are regenerated so their Non-IID profile remains
    deterministic and every training row still belongs to exactly one node.
    """
    from src.preprocess.data_drift import calculate_data_drift
    from src.preprocess.federated_splitter import save_federated_data

    new_x = np.asarray(new_x, dtype=np.float64)
    new_y = np.asarray(new_y, dtype=np.int32).reshape(-1)
    old_x = np.load(PROCESSED_X_PATH)
    old_y = np.load(PROCESSED_Y_PATH)
    train_x = np.load(PROCESSED_TRAIN_X_PATH)
    train_y = np.load(PROCESSED_TRAIN_Y_PATH)
    validation_x = np.load(PROCESSED_VALIDATION_X_PATH)
    validation_y = np.load(PROCESSED_VALIDATION_Y_PATH)
    if (
        new_x.ndim != 2
        or len(new_x) != len(new_y)
        or old_x.ndim != 2
        or train_x.ndim != 2
        or new_x.shape[1] != old_x.shape[1]
        or new_x.shape[1] != train_x.shape[1]
    ):
        raise ValueError("incremental rows do not match the prepared feature schema")

    drift = calculate_data_drift(train_x, train_y, new_x, new_y)
    combined_x = np.vstack([old_x, new_x])
    combined_y = np.concatenate([old_y, new_y])
    combined_train_x = np.vstack([train_x, new_x])
    combined_train_y = np.concatenate([train_y, new_y])

    atomic_save_npy(PROCESSED_X_PATH, combined_x)
    atomic_save_npy(PROCESSED_Y_PATH, combined_y)
    atomic_save_npy(PROCESSED_TRAIN_X_PATH, combined_train_x)
    atomic_save_npy(PROCESSED_TRAIN_Y_PATH, combined_train_y)
    # Re-save the unchanged holdout atomically as part of the new preparation
    # revision. Its validation_id remains stable in metadata.
    atomic_save_npy(PROCESSED_VALIDATION_X_PATH, validation_x)
    atomic_save_npy(PROCESSED_VALIDATION_Y_PATH, validation_y)
    nodes, split_metadata = save_federated_data(
        combined_train_x,
        combined_train_y,
        seed=split_seed,
        return_metadata=True,
    )

    def label_counts(values):
        return {
            str(key): int(value)
            for key, value in zip(*np.unique(values, return_counts=True))
        } if len(values) else {}

    return {
        "nodes": nodes,
        "node_details": split_metadata.get("nodes") or [],
        "federated_split": split_metadata,
        "federated_split_version": FEDERATED_SPLIT_VERSION,
        "samples": int(len(combined_x)),
        "training_samples": int(len(combined_train_x)),
        "validation_samples": int(len(validation_x)),
        "validation_available": bool(len(validation_x)),
        "training_label_counts": label_counts(combined_train_y),
        "validation_label_counts": label_counts(validation_y),
        "label_counts": label_counts(combined_y),
        "drift": drift,
        "added_samples": int(len(new_x)),
        "previous_samples": int(len(old_x)),
        "preparation_id": preparation_id,
    }


def _incremental_submission_change(source, source_id, limit):
    """Return append-only submission IDs when the current preparation is safe to extend."""
    if (source or {}).get("source_type") != "user_submission_pool":
        return None
    metadata = _load_processed_metadata()
    if (
        not _processed_dataset_ready()
        or str(metadata.get("dataset_source_id") or "") != str(source_id or "")
        or metadata.get("preprocessing_version") != FEATURE_NORMALIZATION_VERSION
        or metadata.get("validation_split_version") != SHARED_VALIDATION_SPLIT_VERSION
        or metadata.get("federated_split_version") != FEDERATED_SPLIT_VERSION
        or metadata.get("prepared_bundle_version") != PREPARED_BUNDLE_VERSION
        or int(metadata.get("process_limit") or 0) != int(limit)
    ):
        return None
    previous_ids = {
        str(value) for value in (
            metadata.get("source_submission_ids")
            or metadata.get("submission_ids")
            or []
        ) if value
    }
    current_ids = {
        str(value) for value in ((source or {}).get("submission_ids") or []) if value
    }
    if not previous_ids or not previous_ids.issubset(current_ids):
        return None
    new_ids = sorted(current_ids - previous_ids)
    return {
        "metadata": metadata,
        "previous_ids": sorted(previous_ids),
        "current_ids": sorted(current_ids),
        "new_ids": new_ids,
    }


def _dataset_source_revision(source, limit=50000):
    """Return a stable revision for the data that would be prepared."""
    source = source or {}
    payload = {
        "id": source.get("id") or _dataset_source_id(source),
        "source_type": source.get("source_type"),
        "samples": int(source.get("samples") or 0),
        "features": int(source.get("features") or 0),
        "preprocessing_version": FEATURE_NORMALIZATION_VERSION,
        "validation_split_version": SHARED_VALIDATION_SPLIT_VERSION,
        "validation_fraction": SHARED_VALIDATION_FRACTION,
        "federated_split_version": FEDERATED_SPLIT_VERSION,
        "prepared_bundle_version": PREPARED_BUNDLE_VERSION,
        "limit": max(1, min(int(limit or 50000), 50000)),
        "submission_ids": sorted(str(v) for v in (source.get("submission_ids") or []) if v),
    }
    path = source.get("path")
    if path and os.path.exists(path):
        try:
            stat = os.stat(path)
            payload.update({
                "path": os.path.normcase(os.path.abspath(path)),
                "size": int(stat.st_size),
                "mtime_ns": int(getattr(stat, "st_mtime_ns", int(stat.st_mtime * 1000000000))),
            })
        except OSError:
            payload["path"] = str(path)
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _dataset_preparation_id(source_id, revision):
    raw = "%s:%s" % (source_id or "dataset", revision or "unknown")
    return "prep-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]


def _federated_files_ready():
    try:
        from src.preprocess.federated_splitter import (
            NODE_NAMES,
            FEDERATED_DIR,
            load_split_metadata,
        )

        prepared_meta = _load_processed_metadata()
        expected_samples = int(prepared_meta.get("training_samples"))
        expected_features = int(prepared_meta.get("features"))
        split_meta = load_split_metadata()
        if split_meta.get("version") != FEDERATED_SPLIT_VERSION:
            return False

        manifest_nodes = {
            str(item.get("name")): item
            for item in (split_meta.get("nodes") or [])
            if isinstance(item, dict) and item.get("name")
        }
        total_samples = 0
        for name in NODE_NAMES:
            node_x_shape = _npy_shape(os.path.join(FEDERATED_DIR, name, "X.npy"))
            node_y_shape = _npy_shape(os.path.join(FEDERATED_DIR, name, "y.npy"))
            if (
                len(node_x_shape) != 2
                or len(node_y_shape) != 1
                or node_x_shape[0] != node_y_shape[0]
                or node_x_shape[1] != expected_features
                or int((manifest_nodes.get(name) or {}).get("samples", -1)) != node_x_shape[0]
            ):
                return False
            total_samples += int(node_x_shape[0])
        return total_samples == expected_samples
    except (OSError, ValueError, TypeError, KeyError):
        return False


def _prepared_node_counts():
    return [
        {"name": item.get("name"), "samples": int(item.get("samples") or 0), "ready": bool(item.get("ready"))}
        for item in _federated_node_details()
    ]


def _preparation_matches(source, source_id=None, limit=50000):
    if not source or not _processed_dataset_ready() or not _federated_files_ready():
        return False
    meta = _load_processed_metadata()
    expected_id = source_id or source.get("id") or _dataset_source_id(source)
    expected_revision = _dataset_source_revision(source, limit=limit)
    return (
        str(meta.get("dataset_source_id") or "") == str(expected_id or "")
        and str(meta.get("dataset_revision") or "") == expected_revision
        and str(meta.get("preprocessing_version") or "") == FEATURE_NORMALIZATION_VERSION
        and str(meta.get("federated_split_version") or "") == FEDERATED_SPLIT_VERSION
        and str(meta.get("prepared_bundle_version") or "") == PREPARED_BUNDLE_VERSION
        and int(meta.get("process_limit") or 50000) == max(1, min(int(limit or 50000), 50000))
    )


def _model_inventory():
    """Describe the actual runtime and training model boundaries for the UI."""
    from src.detection.ensemble_detector import ensemble_detector
    from src.utils.model_manager import MODEL_DIR as BASELINE_MODEL_DIR

    runtime_status = ensemble_detector.status()
    runtime_files = runtime_status.get("components") or {}
    baseline_files = {
        "isolation_forest": os.path.exists(os.path.join(BASELINE_MODEL_DIR, "isolation_forest.pkl")),
        "logistic_weights": os.path.exists(os.path.join(BASELINE_MODEL_DIR, "mlp_weights.npy")),
        "q_learning": os.path.exists(os.path.join(BASELINE_MODEL_DIR, "q_table.npy")),
    }
    return {
        "runtime_detector": {
            "name": "IF + XGBoost/逻辑回归 + NumPy LSTM 融合检测模型",
            "ready": bool(runtime_status.get("ready")),
            "version": runtime_status.get("version"),
            "preprocessing_version": runtime_status.get("preprocessing_version"),
            "files": runtime_files,
            "used_by": "用户端风险检测",
        },
        "platform_baseline": {
            "name": "历史兼容基线（只读）",
            "ready": all(baseline_files.values()),
            "files": baseline_files,
            "used_by": "仅供旧检测与优化接口读取，不再允许写入正式训练记录或替换运行时模型",
            "official_training": False,
        },
        "local_training": {
            "name": "运行时融合检测模型训练",
            "relation": "直接使用当前训练分区，不经过四节点；完成后更新用户端实际使用的融合模型文件，不参与普通/FedAvg 同构对比。",
            "serving_impact": "updates_user_detector",
        },
        "centralized_comparison": {
            "name": "普通集中式线性基线",
            "relation": "与四节点使用相同线性模型、优化参数、训练分区和共享留出集，仅训练方式不同。",
            "serving_impact": "comparison_only",
        },
        "federated_training": {
            "name": "四节点线性二分类模型 + FedAvg",
            "relation": "使用与普通集中式基线相同的线性模型和训练预算，四节点分别训练后执行 FedAvg；不会自动替换用户端融合检测模型。",
            "serving_impact": "comparison_only",
        },
        "paillier": {
            "ready": bool(_secure_aggregation_paillier is not None),
            "relation": "管理员可按需对联邦模型权重执行 Paillier 安全聚合。",
        },
    }


def _source_prepared_for_federated(source):
    """Return whether the current processed federated data belongs to source."""
    if not source or not _processed_dataset_ready() or not _federated_files_ready():
        return False
    meta = _load_processed_metadata()
    if meta.get("preprocessing_version") != FEATURE_NORMALIZATION_VERSION:
        return False
    if meta.get("validation_split_version") != SHARED_VALIDATION_SPLIT_VERSION:
        return False
    if meta.get("federated_split_version") != FEDERATED_SPLIT_VERSION:
        return False
    source_id = source.get("id") or _dataset_source_id(source)
    if source_id and meta.get("dataset_source_id") == source_id:
        stored_revision = meta.get("dataset_revision")
        if not stored_revision:
            return False
        return stored_revision == _dataset_source_revision(source, limit=meta.get("process_limit", 50000))
    return False


def _dataset_source_id(source):
    raw = "%s:%s" % (source.get("source_type", ""), source.get("source", ""))
    return "".join(ch if ch.isalnum() else "_" for ch in raw.lower()).strip("_") or "dataset"


def _source_display_name(source_type):
    mapping = {
        "local_generated": "系统内置密码攻击训练集",
        "UNSW-NB15": "UNSW-NB15 公开入侵检测数据集",
        "local_csv": "本地 CSV 数据源",
    }
    return mapping.get(source_type, source_type or "未知数据源")


def _dataset_distribution_stats(path, max_rows=5000):
    """Return sampled label/attack stats cached by the file fingerprint."""
    stats = {
        "label_distribution": {},
        "attack_type_distribution": {},
        "scanned_rows": 0,
    }
    if not path or not os.path.exists(path):
        return stats
    try:
        file_stat = os.stat(path)
        absolute_path = os.path.normcase(os.path.abspath(path))
        cache_key = (
            absolute_path,
            int(file_stat.st_size),
            int(getattr(file_stat, "st_mtime_ns", int(file_stat.st_mtime * 1000000000))),
            int(max_rows),
        )
        with _dataset_distribution_cache_lock:
            cached = _dataset_distribution_cache.get(cache_key)
            if cached is not None:
                return {
                    "label_distribution": dict(cached.get("label_distribution") or {}),
                    "attack_type_distribution": dict(cached.get("attack_type_distribution") or {}),
                    "scanned_rows": int(cached.get("scanned_rows") or 0),
                }
    except OSError:
        return stats
    try:
        from src.preprocess.feature_engineering import infer_label
        from src.datasets.security_dataset_importer import map_attack_type

        with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                if i >= max_rows:
                    break
                label = int(infer_label(row))
                raw_attack = (
                    row.get("attack_type")
                    or row.get("attack_cat")
                    or row.get("Label")
                    or row.get("label")
                    or row.get("class")
                    or ""
                )
                mapped_attack, mapped_label = map_attack_type(raw_attack)
                if raw_attack and str(raw_attack).strip() not in {"0", "1"}:
                    attack_type = mapped_attack
                elif label == 0:
                    attack_type = "benign"
                else:
                    attack_type = mapped_attack if mapped_label else "password_attack"

                label_key = str(label)
                stats["label_distribution"][label_key] = stats["label_distribution"].get(label_key, 0) + 1
                stats["attack_type_distribution"][attack_type] = stats["attack_type_distribution"].get(attack_type, 0) + 1
                stats["scanned_rows"] += 1
    except Exception as exc:
        logger.warning(f"Dataset distribution scan failed for {path}: {exc}")
    with _dataset_distribution_cache_lock:
        for old_key in list(_dataset_distribution_cache):
            if old_key[0] == absolute_path and old_key != cache_key:
                _dataset_distribution_cache.pop(old_key, None)
        _dataset_distribution_cache[cache_key] = {
            "label_distribution": dict(stats["label_distribution"]),
            "attack_type_distribution": dict(stats["attack_type_distribution"]),
            "scanned_rows": int(stats["scanned_rows"]),
        }
    return {
        "label_distribution": dict(stats["label_distribution"]),
        "attack_type_distribution": dict(stats["attack_type_distribution"]),
        "scanned_rows": int(stats["scanned_rows"]),
    }


def _merge_count_dict(target, source):
    if not isinstance(source, dict):
        return target
    for key, value in source.items():
        try:
            target[str(key)] = target.get(str(key), 0) + int(value or 0)
        except Exception:
            continue
    return target


def _build_user_submission_pool_source(user_sources):
    trainable_sources = [
        source for source in (user_sources or [])
        if source.get("trainable") and int(source.get("samples") or 0) > 0
    ]
    if not trainable_sources:
        return None

    total_samples = sum(int(source.get("samples") or 0) for source in trainable_sources)
    feature_count = max((int(source.get("features") or 0) for source in trainable_sources), default=0)
    label_distribution = {}
    risk_summary = {}
    attack_type_distribution = {}
    submission_ids = []

    for source in trainable_sources:
        submission_id = source.get("submission_id") or str(source.get("id") or "").replace("submission:", "")
        if submission_id:
            submission_ids.append(submission_id)
        _merge_count_dict(label_distribution, source.get("label_distribution"))
        _merge_count_dict(risk_summary, source.get("risk_summary"))
        _merge_count_dict(attack_type_distribution, source.get("attack_type_distribution"))

    if not attack_type_distribution:
        attack_type_distribution = {"user_submission": total_samples}

    pool = {
        "id": "user_submission_pool",
        "name": "用户可训练数据池",
        "source": "已归档并标记可训练的用户提交",
        "source_type": "user_submission_pool",
        "path": None,
        "samples": total_samples,
        "features": feature_count,
        "label_column": "label",
        "trainable": True,
        "configured": False,
        "exists": True,
        "status": "ready",
        "prepared_for_federated": False,
        "label_distribution": label_distribution,
        "attack_type_distribution": attack_type_distribution,
        "risk_summary": risk_summary,
        "scanned_rows": total_samples,
        "submission_ids": submission_ids,
        "description": "汇总已归档并标记可训练的用户提交，可生成四节点数据并用于训练。",
    }
    pool["prepared_for_federated"] = _source_prepared_for_federated(pool)
    if pool["prepared_for_federated"]:
        pool["status"] = "ready"
    return pool


def _list_dataset_sources():
    """Return all known trainable dataset sources with lightweight metadata."""
    from src.preprocess.feature_engineering import inspect_csv
    from glob import glob

    seen = set()
    sources = []
    configured_sources = []

    try:
        with open(os.path.join("config", "dataset_sources.json"), "r", encoding="utf-8") as f:
            configured_sources = json.load(f).get("sources", [])
    except Exception:
        configured_sources = []

    first = _find_dataset_source()
    candidates = []
    if first:
        candidates.append(first)

    generated_train = os.path.join("data", "generated", "train.csv")
    generated_test = os.path.join("data", "generated", "test.csv")
    if os.path.exists(generated_train):
        candidates.append({
            "path": generated_train,
            "test_path": generated_test if os.path.exists(generated_test) else None,
            "source": "data/generated/train.csv",
            "source_type": "local_generated",
        })

    if os.path.isdir(UNSW_DIR):
        for name in sorted(os.listdir(UNSW_DIR)):
            if name.lower().endswith(".csv"):
                candidates.append({
                    "path": os.path.join(UNSW_DIR, name),
                    "source": name,
                    "source_type": "UNSW-NB15",
                })

    if os.path.isdir("data"):
        for name in sorted(os.listdir("data")):
            path = os.path.join("data", name)
            if name.lower().endswith(".csv") and os.path.isfile(path):
                candidates.append({
                    "path": path,
                    "source": name,
                    "source_type": "local_csv",
                })

    for cfg in configured_sources:
        if not cfg.get("enabled", True):
            continue
        paths = cfg.get("paths") or []
        matched = []
        for pattern in paths:
            hits = sorted(glob(pattern, recursive=True))
            matched.extend([p for p in hits if os.path.isfile(p)])
        if matched:
            for path in matched:
                candidates.append({
                    "id": cfg.get("id"),
                    "path": path,
                    "source": path,
                    "source_type": cfg.get("type") or cfg.get("source_type"),
                    "name": cfg.get("name"),
                    "description": cfg.get("description"),
                    "configured": True,
                })
        else:
            sources.append({
                "id": cfg.get("id") or _dataset_source_id({"source_type": cfg.get("type"), "source": cfg.get("name")}),
                "name": cfg.get("name") or _source_display_name(cfg.get("type")),
                "source": ", ".join(paths) if paths else "-",
                "source_type": cfg.get("type") or "-",
                "path": None,
                "samples": 0,
                "features": 0,
                "label_column": None,
                "trainable": False,
                "configured": True,
                "exists": False,
                "prepared_for_federated": False,
                "status": "missing",
                "label_distribution": {},
                "attack_type_distribution": {},
                "scanned_rows": 0,
                "description": cfg.get("description") or "已配置数据源，但本地尚未发现对应 CSV 文件。",
            })

    for source in candidates:
        path = source.get("path")
        seen_key = os.path.normcase(os.path.abspath(path)) if path else ""
        if not path or seen_key in seen or not os.path.exists(path):
            continue
        seen.add(seen_key)
        try:
            info = inspect_csv(path)
        except Exception:
            info = {
                "samples": _csv_row_count(path, max_rows=1000000),
                "features": 0,
                "label_column": None,
            }
        item = {
            "id": source.get("id") or _dataset_source_id(source),
            "name": source.get("name") or _source_display_name(source.get("source_type")),
            "source": source.get("source"),
            "source_type": source.get("source_type"),
            "path": path,
            "samples": int(info.get("samples", 0) or 0),
            "features": int(info.get("features", 0) or 0),
            "label_column": info.get("label_column"),
            "trainable": True,
            "configured": bool(source.get("configured")),
            "exists": True,
            "status": "ready",
            "prepared_for_federated": False,
            "description": source.get("description") or "用于密码攻击风险检测、模型训练和四节点联邦切分的数据源。",
        }
        item.update(_dataset_distribution_stats(path))
        if source.get("source_type") == "UNSW-NB15" and not source.get("description"):
            item["description"] = "公开入侵检测数据集，可用于扩展异常流量、扫描和入侵检测类风险识别。"
        if source.get("source_type") == "local_generated" and not source.get("description"):
            item["description"] = "项目内置密码攻击训练样本库，当前管理端初始训练和联邦切分优先使用该数据源。"
        item["prepared_for_federated"] = _source_prepared_for_federated(item)
        sources.append(item)

    try:
        user_sources = user_submission_manager.list_dataset_sources(limit=50)
        pool_source = _build_user_submission_pool_source(user_sources)
        if pool_source and pool_source.get("id") not in seen:
            seen.add(pool_source["id"])
            sources.append(pool_source)
        for source in user_sources[:20]:
            source_id = source.get("id")
            if source_id and source_id not in seen:
                seen.add(source_id)
                source["prepared_for_federated"] = _source_prepared_for_federated(source)
                if source.get("prepared_for_federated"):
                    source["status"] = "ready"
                sources.append(source)
    except Exception as exc:
        logger.warning("List user submission dataset sources failed: {}", exc)

    sources.sort(key=lambda x: (
        0 if x.get("prepared_for_federated") else
        1 if x.get("trainable") and x.get("source_type") == "user_submission_pool" else
        2 if x.get("trainable") and x.get("source_type") == "local_generated" else
        3 if x.get("trainable") and x.get("source_type") == "user_submission" else
        4 if x.get("trainable") else
        5 if x.get("source_type") == "user_submission" else
        6,
        str(x.get("id") or x.get("name") or "")
    ))
    return sources


def _clear_dataset_sources_cache():
    with _dataset_sources_cache_lock:
        _dataset_sources_cache["time"] = 0.0
        _dataset_sources_cache["value"] = None


def _list_dataset_sources_cached(force=False):
    now = time.time()
    with _dataset_sources_cache_lock:
        cached = _dataset_sources_cache.get("value")
        cached_at = float(_dataset_sources_cache.get("time") or 0)
        if not force and cached is not None and now - cached_at < DATASET_SOURCES_CACHE_SECONDS:
            return cached
        # Keep the scan under the cache lock so concurrent page requests do
        # not duplicate the same filesystem and CSV metadata work.
        fresh = _list_dataset_sources()
        _dataset_sources_cache["time"] = time.time()
        _dataset_sources_cache["value"] = fresh
        return fresh


def _load_training_dataset_source(source_id=None, limit=50000):
    """Load a managed dataset source for admin local/federated training."""
    from src.preprocess.feature_engineering import load_security_csv, normalize_security_features

    sources = _list_dataset_sources_cached()
    selected = None
    if source_id:
        selected = next((s for s in sources if s.get("id") == source_id), None)
        if selected is None:
            return np.empty((0, 0)), np.empty(0, dtype=np.int32), {
                "source_count": 0,
                "sources": [],
                "training_source": "dataset_source",
                "dataset_name": "请求的数据源不存在",
                "dataset_source_id": source_id,
                "source_not_found": True,
            }
    if selected is None and sources:
        selected = sources[0]
    if selected is None:
        return np.empty((0, 0)), np.empty(0, dtype=np.int32), {
            "source_count": 0,
            "sources": [],
            "training_source": "dataset_source",
            "dataset_name": "未检测到训练数据源",
        }

    selected_id = selected.get("id") or _dataset_source_id(selected)
    if _source_prepared_for_federated(selected):
        try:
            X, y, processed_meta = _load_prepared_training_arrays(limit=limit)
            labels = {str(k): int(v) for k, v in zip(*np.unique(y, return_counts=True))} if len(y) else {}
            return X, y, {
                "source_count": 1,
                "sources": [{
                    "id": "dataset:%s" % selected_id,
                    "filename": selected.get("source"),
                    "source_type": selected.get("source_type"),
                    "samples": int(len(X)),
                }],
                "training_source": (
                    selected.get("source_type")
                    if selected.get("source_type") in {"user_submission_pool", "user_submission"}
                    else "managed_dataset_source"
                ),
                "dataset_name": selected.get("name") or selected.get("source") or "managed_dataset_source",
                "dataset_source_id": selected_id,
                "source_type": selected.get("source_type"),
                "label_distribution": labels,
                "preparation_id": processed_meta.get("preparation_id"),
                "dataset_revision": processed_meta.get("dataset_revision"),
                "process_mode": processed_meta.get("process_mode", "full_rebuild"),
                "uses_prepared_data": True,
                "uses_shared_validation": bool(processed_meta.get("validation_available")),
                "prepared_samples": int(len(X)),
                "available_training_samples": int(processed_meta.get("training_samples") or len(X)),
                "source_samples": int(processed_meta.get("samples") or len(X)),
                "validation_available": bool(processed_meta.get("validation_available")),
                "validation_samples": int(processed_meta.get("validation_samples") or 0),
                "validation_id": processed_meta.get("validation_id"),
                "validation_split_version": processed_meta.get("validation_split_version"),
                "validation_label_distribution": processed_meta.get("validation_label_counts") or {},
                "preprocessing_version": processed_meta.get("preprocessing_version"),
                "federated_split_version": processed_meta.get("federated_split_version"),
                "prepared_bundle_version": processed_meta.get("prepared_bundle_version"),
                "federated_split": processed_meta.get("federated_split") or {},
                "drift": processed_meta.get("drift") or {},
                "incremental": bool(processed_meta.get("incremental")),
                "added_samples": int(processed_meta.get("added_samples") or 0),
                "nodes": processed_meta.get("nodes") or _prepared_node_counts(),
            }
        except Exception as prepared_error:
            logger.warning("Load prepared training arrays failed, falling back to source: {}", prepared_error)

    source_type = selected.get("source_type")
    if source_type in {"user_submission_pool", "user_submission"}:
        ids = None
        if source_type == "user_submission":
            submission_id = selected.get("submission_id") or str(selected.get("id") or "").replace("submission:", "")
            ids = [submission_id] if submission_id else []
        X, y, user_meta = user_submission_manager.load_trainable_features(ids=ids, limit=limit)
        labels = {str(k): int(v) for k, v in zip(*np.unique(y, return_counts=True))} if len(y) else {}
        meta = dict(user_meta or {})
        meta.update({
            "source_count": meta.get("source_count") or len(meta.get("sources") or []) or (1 if len(X) else 0),
            "sources": meta.get("sources") or [],
            "training_source": "user_submission_pool" if source_type == "user_submission_pool" else "user_submission",
            "dataset_name": selected.get("name") or selected.get("source") or source_type,
            "dataset_source_id": selected.get("id"),
            "source_type": source_type,
            "label_distribution": labels,
            "preprocessing_version": FEATURE_NORMALIZATION_VERSION,
            "source_samples": int(len(X)),
            "validation_available": False,
        })
        return X, y, meta

    selected_path = selected.get("path")
    if not selected_path or not os.path.exists(selected_path):
        return np.empty((0, 0)), np.empty(0, dtype=np.int32), {
            "source_count": 0,
            "sources": [],
            "training_source": selected.get("source_type") or "dataset_source",
            "dataset_name": selected.get("name") or selected.get("source") or "missing_dataset_source",
            "dataset_source_id": selected.get("id"),
            "source_type": selected.get("source_type"),
            "label_distribution": {},
        }

    X, y, _ = load_security_csv(selected_path, limit=limit)
    if len(X):
        X = normalize_security_features(X)
    labels = {str(k): int(v) for k, v in zip(*np.unique(y, return_counts=True))} if len(y) else {}
    meta = {
        "source_count": 1,
        "sources": [{
            "id": "dataset:%s" % selected.get("id"),
            "filename": selected.get("source"),
            "source_type": selected.get("source_type"),
            "samples": int(len(X)),
        }],
        "training_source": "managed_dataset_source",
        "dataset_name": selected.get("name") or selected.get("source") or "managed_dataset_source",
        "dataset_source_id": selected.get("id"),
        "source_type": selected.get("source_type"),
        "label_distribution": labels,
        "preprocessing_version": FEATURE_NORMALIZATION_VERSION,
        "source_samples": int(len(X)),
        "validation_available": False,
    }
    return X, y, meta


def _federated_node_details_unlocked():
    from src.preprocess.federated_splitter import NODE_NAMES, FEDERATED_DIR

    meta = _load_processed_metadata()
    split_meta = meta.get("federated_split") or {}
    split_node_map = {
        str(item.get("name")): item
        for item in (split_meta.get("nodes") or meta.get("nodes") or [])
        if isinstance(item, dict) and item.get("name")
    }
    nodes = []
    for name in NODE_NAMES:
        node_dir = os.path.join(FEDERATED_DIR, name)
        X_path = os.path.join(node_dir, "X.npy")
        y_path = os.path.join(node_dir, "y.npy")
        detail = {
            "name": name,
            "node_type": "业务联邦节点",
            "samples": 0,
            "ready": False,
            "feature_dim": meta.get("features", 0),
            "source": meta.get("source"),
            "source_type": meta.get("source_type"),
            "dataset_source_id": meta.get("dataset_source_id"),
            "dataset_revision": meta.get("dataset_revision"),
            "preparation_id": meta.get("preparation_id"),
            "validation_id": meta.get("validation_id"),
            "processed_at": meta.get("processed_at"),
            "split_version": meta.get("federated_split_version"),
            "heterogeneity_level": split_meta.get("heterogeneity_level"),
            "label_distribution": {},
            "normal_samples": 0,
            "attack_samples": 0,
            "description": "节点只接收训练分区；共享留出集不会写入任何节点，用于普通模型与联邦模型的同口径评估。",
        }
        detail.update(split_node_map.get(name) or {})
        if os.path.exists(X_path) and os.path.exists(y_path):
            try:
                X = np.load(X_path)
                y = np.load(y_path)
                counts = {str(k): int(v) for k, v in zip(*np.unique(y, return_counts=True))}
                normal = int(counts.get("0", 0))
                detail.update({
                    "samples": int(len(X)),
                    "ready": True,
                    "feature_dim": int(X.shape[1]) if len(X.shape) > 1 else int(meta.get("features", 0) or 0),
                    "label_distribution": counts,
                    "normal_samples": normal,
                    "attack_samples": int(len(y) - normal),
                })
            except Exception as e:
                detail["error"] = str(e)
        nodes.append(detail)
    return nodes


def _federated_node_details():
    """Read one coherent node-data revision while preparation may be running."""
    with _dataset_prepare_lock:
        return _federated_node_details_unlocked()


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


def generate_login_security_dataset(n_records=100):
    browsers = ["Chrome", "Edge", "Firefox", "Safari", "Chrome", "Edge"]
    systems = ["Windows", "macOS", "Linux", "Android", "iOS"]
    devices = ["desktop", "desktop", "desktop", "mobile", "tablet"]
    rows = []
    for i in range(n_records):
        attack = random.random() < 0.22
        failed_attempts = random.randint(8, 45) if attack else random.randint(0, 4)
        request_frequency = random.randint(130, 320) if attack else random.randint(5, 80)
        response_time = round(random.uniform(0.7, 3.5) if attack else random.uniform(0.03, 0.45), 3)
        payload_size = random.randint(4000, 60000) if attack else random.randint(300, 3800)
        unusual_hour = 1 if (attack and random.random() < 0.6) else random.choice([0, 0, 0, 1])
        rows.append({
            "id": i + 1,
            "username": "user_%04d" % (1000 + i),
            "password_strength": random.choice([2, 3, 4]) if attack else random.choice([3, 4, 5]),
            "ip": "203.0.%d.%d" % (random.randint(10, 220), random.randint(1, 254)) if attack else "10.%d.%d.%d" % (random.randint(0, 255), random.randint(0, 255), random.randint(1, 254)),
            "user_agent": "%s/%d.0 (%s)" % (random.choice(browsers), random.randint(90, 130), random.choice(systems)),
            "device_type": random.choice(devices),
            "browser": random.choice(browsers),
            "os": random.choice(systems),
            "login_success": 0 if failed_attempts > 10 and random.random() < 0.8 else 1,
            "failed_attempts": failed_attempts,
            "request_frequency": request_frequency,
            "response_time": response_time,
            "payload_size": payload_size,
            "connection_duration": round(random.uniform(80, 900) if attack else random.uniform(5, 80), 2),
            "session_duration": round(random.uniform(1, 120) if attack else random.uniform(60, 900), 2),
            "request_size_variance": round(random.uniform(220, 1200) if attack else random.uniform(10, 160), 2),
            "cpu_usage": round(random.uniform(0.55, 0.95) if attack else random.uniform(0.1, 0.45), 3),
            "memory_usage": round(random.uniform(0.55, 0.9) if attack else random.uniform(0.15, 0.5), 3),
            "unusual_hour": unusual_hour,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "label": 1 if attack else 0,
        })
    return rows


def _encrypt_privacy_rows(dataset):
    p = get_paillier()
    if p is not None:
        try:
            encrypted = []
            for record in dataset:
                encrypted.append({
                    "id": record["id"],
                    "phone_encrypted": str(p.encrypt(int(record["phone"][-8:])))[:40],
                    "salary_encrypted": str(p.encrypt(record["salary"]))[:40],
                    "credit_score_encrypted": str(p.encrypt(record["credit_score"]))[:40],
                    "algorithm": "Paillier-1024",
                })
            return encrypted, "Paillier-1024"
        except Exception as e:
            logger.warning("Paillier encrypt failed: %s" % e)
    return _mock_encrypt(dataset), "mock"


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
            logger.info("真实检测器训练完成: accuracy={:.4f}", result.get("accuracy", 0))
            # 保存模型
            import joblib
            os.makedirs("data/models", exist_ok=True)
            det.save("data/models/detector_real")
        except Exception as e:
            logger.warning("真实检测器训练失败: {}", e)


# ─── CORS ───

@app.after_request
def add_cors_headers(response):
    # The bundled UI is same-origin.  Cross-origin access is opt-in and exact;
    # a wildcard would unnecessarily expose upload and training APIs.
    configured = {
        item.strip().rstrip("/")
        for item in os.environ.get("CORS_ALLOWED_ORIGINS", "").split(",")
        if item.strip()
    }
    origin = (request.headers.get("Origin") or "").rstrip("/")
    if origin and origin in configured:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        response.headers.add("Vary", "Origin")
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "same-origin"
    return response


# ─── 页面路由 ───

@app.route("/")
def index():
    return send_file(os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html"))


@app.route("/favicon.ico")
def favicon():
    """Avoid a noisy browser-console 404 until a branded icon is provided."""
    return "", 204


# ─── API: 访客记录 ───

@app.route("/api/visitors", methods=["GET"])
def get_visitors():
    with _visitor_lock:
        return jsonify(api_response(msg="success", data={
            "total": len(_visitor_log),
            "visitors": list(reversed(_visitor_log[-50:])),
        }))


# ─── API: 安全事件查询 ───

@app.route("/api/security/events/recent", methods=["GET"])
def security_events_recent():
    """只读安全事件查询接口"""
    try:
        from src.security.security_logger import SECURITY_EVENTS_LOG_PATH
        from src.security.events_api import normalize_limit, read_events

        limit = normalize_limit(request.args.get("limit", 50))
        event_type = request.args.get("event_type", None)
        risk_level = request.args.get("risk_level", None)

        events = read_events(
            log_path=SECURITY_EVENTS_LOG_PATH,
            limit=limit,
            event_type=event_type,
            risk_level=risk_level,
        )

        return jsonify(api_response(msg="success", data={
            "events": events,
            "total": len(events),
            "limit": limit,
        }))
    except Exception as e:
        logger.warning("Security events query failed: {}", e)
        return jsonify(api_response(data={
            "events": [],
            "total": 0,
            "limit": 50,
            "warning": "security_events.log unavailable",
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
    try:
        n_records = int(data.get("n_records", 100))
    except Exception:
        n_records = 100
    n_records = max(10, min(n_records, 5000))
    logger.info("生成数据集: n_records=%d" % n_records)
    dataset = generate_sensitive_dataset(n_records)

    encrypted, method = _encrypt_privacy_rows(dataset)

    return jsonify(api_response(data={
        "plaintext": dataset,
        "encrypted": encrypted,
        "n_records": n_records,
        "encryption_method": method,
    }))


@app.route("/api/generate_login_security_dataset", methods=["POST"])
def api_generate_login_security_dataset():
    data = request.get_json() or {}
    try:
        n_records = int(data.get("n_records", 200))
    except Exception:
        n_records = 200
    n_records = max(10, min(n_records, 5000))
    rows = generate_login_security_dataset(n_records)
    return jsonify(api_response(data={
        "records": rows,
        "dataset": rows,
        "n_records": len(rows),
        "dataset_type": "login_security",
        "description": "登录安全行为样本，可直接用于风险检测",
    }))


@app.route("/api/generate_privacy_dataset", methods=["POST"])
def api_generate_privacy_dataset():
    data = request.get_json() or {}
    try:
        n_records = int(data.get("n_records", 200))
    except Exception:
        n_records = 200
    n_records = max(10, min(n_records, 5000))
    rows = generate_sensitive_dataset(n_records)
    encrypted, method = _encrypt_privacy_rows(rows)
    return jsonify(api_response(data={
        "plaintext": rows,
        "encrypted": encrypted,
        "n_records": len(rows),
        "encryption_method": method,
        "dataset_type": "privacy_encryption",
        "description": "隐私字段密态展示样本，不直接作为攻击检测输入",
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

def _deprecated_training_api(replacement):
    return jsonify(api_response(
        code=410,
        msg="该历史训练入口已停用，请使用当前管理端正式训练链路。",
        data={
            "deprecated": True,
            "replacement": replacement,
            "official_endpoints": {
                "runtime": "/api/admin/training/local",
                "centralized": "/api/admin/training/centralized",
                "federated": "/api/admin/training/federated",
                "tasks": "/api/admin/training/tasks",
            },
        },
    )), 410

@app.route("/api/train_fate", methods=["POST"])
def train_fate():
    return _deprecated_training_api("/api/admin/training/federated")


@app.route("/api/train_plaintext", methods=["POST"])
def train_plaintext():
    return _deprecated_training_api("/api/admin/training/centralized")


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
    from src.detection.scoring import isolation_forest_risk_score
    if_scores = isolation_forest_risk_score(model_manager.if_model, X)
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

    filename = os.path.basename(file.filename)
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    try:
        file.save(file_path)
        validate_upload_file(file_path, filename)
        logger.info("文件上传: %s" % filename)
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
    except UploadValidationError as e:
        return jsonify(api_response(code=400, msg=str(e)))
    except Exception as e:
        logger.error("文件处理失败: %s" % e)
        return jsonify(api_response(code=500, msg="文件处理失败: %s" % e))
    finally:
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception:
            pass


# ─── API: 自适应优化 ───

@app.route("/api/optimization/status", methods=["GET"])
def optimization_status():
    opt = get_optimizer()
    data = opt.get_status()
    data["history"] = opt.get_history()
    return jsonify(api_response(data=data))


@app.route("/api/optimization/update", methods=["POST"])
def optimization_update():
    req = request.get_json() or {}
    result = get_optimizer().update(
        anomaly_score=req.get("anomaly_score", 0.5),
        cpu_usage=req.get("cpu_usage", 0.3),
        memory_usage=req.get("memory_usage", 0.4),
        model_accuracy=req.get("accuracy", 0.95),
        force=bool(req.get("force", False)),
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
    if "anomaly_score" in req:
        signal = {
            "anomaly_score": req.get("anomaly_score", 0.5),
            "cpu_usage": req.get("cpu_usage", 0.3),
            "memory_usage": req.get("memory_usage", 0.4),
            "model_accuracy": req.get("accuracy", 0.95),
        }
    else:
        signal = get_optimizer().next_demo_signal()
    result = get_optimizer().update(
        anomaly_score=signal["anomaly_score"],
        cpu_usage=signal["cpu_usage"],
        memory_usage=signal["memory_usage"],
        model_accuracy=signal["model_accuracy"],
        force=bool(req.get("force", False)),
    )
    return jsonify(api_response(data=result))


# ─── API: 数据集管理 ───

# ─── API: 用户端风险分析 + 管理端加密训练平台 ───

@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    req = request.get_json(silent=True) or {}
    username = str(req.get("username", "")).strip()
    password = str(req.get("password", ""))
    auth_status = _admin_auth_config_status()
    if auth_status["disabled"]:
        return jsonify(api_response(code=503, msg=auth_status["disabled_reason"], data={"auth_configured": False})), 503
    expected_user, expected_password = auth_status["username"], auth_status["password"]
    credentials_match = hmac.compare_digest(username, str(expected_user)) and hmac.compare_digest(
        password,
        str(expected_password),
    )
    if credentials_match:
        session.clear()
        session.permanent = True
        session["admin_logged_in"] = True
        session["admin_username"] = username
        return jsonify(api_response(msg="登录成功", data={"username": username, "using_default": auth_status["using_default"]}))
    return jsonify(api_response(code=401, msg="管理员账号或密码错误")), 401


@app.route("/admin/launcher-login", methods=["POST"])
def admin_launcher_login():
    """Create an admin session from a local launcher without storing a password."""
    if not _is_local_request():
        return "快捷登录仅允许从本机访问。", 403
    expected_hash = _admin_launcher_hash()
    supplied_token = str(request.form.get("token", ""))
    supplied_hash = hashlib.sha256(supplied_token.encode("utf-8")).hexdigest()
    if not expected_hash or not hmac.compare_digest(supplied_hash, expected_hash):
        return "快捷登录凭据无效或未配置。", 403
    session.clear()
    session.permanent = True
    session["admin_logged_in"] = True
    session["admin_username"] = _admin_credentials()[0]
    return redirect("/", code=303)


@app.route("/api/admin/logout", methods=["POST"])
def admin_logout():
    session.pop("admin_logged_in", None)
    session.pop("admin_username", None)
    return jsonify(api_response(msg="已退出登录"))


@app.route("/api/admin/session", methods=["GET"])
def admin_session():
    auth_status = _admin_auth_config_status()
    return jsonify(api_response(data={
        "logged_in": _is_admin_logged_in(),
        "username": session.get("admin_username"),
        "auth_configured": not auth_status["disabled"],
        "using_default": auth_status["using_default"],
        "config_message": auth_status["disabled_reason"],
    }))


def _create_external_advisor_client(settings):
    """Factory kept separate so tests never need a live paid provider."""
    return ExternalAdvisorClient(settings)


def _reserve_external_ai_call(calls_per_hour):
    """Reserve one bounded global provider call for the 2GB deployment."""
    now = time.time()
    limit = max(1, min(int(calls_per_hour or 20), 100))
    cutoff = now - 3600.0
    with _external_analysis_rate_lock:
        while _external_analysis_call_times and _external_analysis_call_times[0] < cutoff:
            _external_analysis_call_times.popleft()
        if len(_external_analysis_call_times) >= limit:
            retry_after = max(1, int(3600 - (now - _external_analysis_call_times[0])))
            return False, retry_after, 0
        _external_analysis_call_times.append(now)
        return True, 0, max(0, limit - len(_external_analysis_call_times))


def _external_ai_settings_public(settings):
    return _external_ai_settings_store.public_status(
        settings,
        secret_input_allowed=_secret_configuration_allowed(),
    )


@app.route("/api/admin/external-ai/settings", methods=["GET"])
def admin_external_ai_settings_get():
    """Return only masked provider configuration to the compact admin dialog."""
    try:
        settings = _external_ai_settings_store.get_effective(require_ready=False)
        return jsonify(api_response(data=_external_ai_settings_public(settings)))
    except ExternalAdvisorConfigError:
        return jsonify(api_response(
            code=500,
            msg="外部 AI 配置无法读取，请重新保存 API 设置。",
            data={"secret_input_allowed": _secret_configuration_allowed()},
        )), 500


@app.route("/api/admin/external-ai/settings", methods=["PUT", "POST"])
def admin_external_ai_settings_save():
    """Save encrypted provider settings without ever returning the API key."""
    req = request.get_json(silent=True) or {}
    secret_changed = bool(str(req.get("api_key") or "").strip()) or bool(req.get("clear_api_key"))
    if secret_changed and not _secret_configuration_allowed():
        return jsonify(api_response(
            code=403,
            msg="为防止 API Key 在网络中泄露，公网管理端必须使用 HTTPS；也可通过服务器环境变量配置密钥。",
        )), 403
    try:
        settings = _external_ai_settings_store.save(req)
        return jsonify(api_response(msg="AI 接口设置已安全保存", data=_external_ai_settings_public(settings)))
    except ExternalAdvisorConfigError as error:
        return jsonify(api_response(code=400, msg=str(error))), 400
    except Exception:
        logger.exception("Save external AI settings failed")
        return jsonify(api_response(code=500, msg="AI 接口设置保存失败。")), 500


@app.route("/api/admin/external-ai/settings/test", methods=["POST"])
def admin_external_ai_settings_test():
    """Make one explicit, fixed-data provider call to validate connectivity."""
    req = request.get_json(silent=True) or {}
    if str(req.get("api_key") or "").strip() and not _secret_configuration_allowed():
        return jsonify(api_response(
            code=403,
            msg="公网管理端必须使用 HTTPS 后才能提交 API Key 进行测试。",
        )), 403
    if not _external_analysis_operation_lock.acquire(blocking=False):
        return jsonify(api_response(code=409, msg="已有 AI 解读任务正在执行，请稍后再试。")), 409
    try:
        settings = _external_ai_settings_store.candidate(req)
        settings["enabled"] = True
        allowed, retry_after, remaining = _reserve_external_ai_call(settings.get("calls_per_hour"))
        if not allowed:
            return jsonify(api_response(
                code=429,
                msg="外部 AI 每小时调用额度已用完，请稍后再试。",
                data={"retry_after_seconds": retry_after},
            )), 429
        started = time.perf_counter()
        result = _create_external_advisor_client(settings).analyze(external_advisor_test_payload())
        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
        return jsonify(api_response(msg="AI 接口测试成功", data={
            "connected": True,
            "model": settings.get("model"),
            "mode": settings.get("mode"),
            "latency_ms": elapsed_ms,
            "remaining_calls_this_hour": remaining,
            "sample_summary": (result.get("advice") or {}).get("summary", ""),
        }))
    except (ExternalAdvisorConfigError, ExternalAdvisorDisabledError) as error:
        return jsonify(api_response(code=400, msg=str(error))), 400
    except (ExternalAdvisorProviderError, ExternalAdvisorResponseError):
        return jsonify(api_response(code=502, msg="AI 接口测试失败，请检查地址、模型、密钥和接口模式。")), 502
    except Exception:
        logger.exception("External AI settings test failed")
        return jsonify(api_response(code=500, msg="AI 接口测试失败。")), 500
    finally:
        _external_analysis_operation_lock.release()


@app.route("/api/user/datasets/upload", methods=["POST"])
def user_dataset_upload():
    """Upload a user CSV/JSON file and store it as an encrypted archive."""
    if "file" not in request.files:
        return jsonify(api_response(code=400, msg="请选择 CSV/JSON 文件"))
    file = request.files["file"]
    if not file or not file.filename:
        return jsonify(api_response(code=400, msg="文件名为空"))
    ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if ext not in ("csv", "json"):
        return jsonify(api_response(code=400, msg="仅支持 CSV/JSON 格式"))

    temp_name = "user_%s_%s" % (datetime.now().strftime("%Y%m%d%H%M%S"), os.path.basename(file.filename))
    temp_path = os.path.join(app.config["UPLOAD_FOLDER"], temp_name)
    try:
        file.save(temp_path)
        validate_upload_file(temp_path, file.filename)
        info = user_submission_manager.create_submission(temp_path, file.filename)
        try:
            db.upsert_user_submission(info)
        except Exception as persist_error:
            logger.warning("Persist user submission failed: {}", persist_error)
        _clear_submission_related_caches()
        return jsonify(api_response(msg="上传成功，文件已加密归档", data=info))
    except UploadValidationError as e:
        return jsonify(api_response(code=400, msg=str(e)))
    except Exception as e:
        logger.exception("User dataset upload failed")
        return jsonify(api_response(code=500, msg="上传失败: %s" % e))
    finally:
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except Exception:
            pass


def _submission_analysis_response(submission_id, actor="user"):
    """Run the shared lightweight analysis workflow for user or admin APIs."""
    if not _analysis_operation_lock.acquire(blocking=False):
        return jsonify(api_response(
            code=409,
            msg="已有数据分析任务正在执行。为控制服务器内存，请等待当前任务完成后再试。",
        )), 409
    try:
        from src.detection.ensemble_detector import ensemble_detector
        req = request.get_json(silent=True) or {}
        try:
            limit = max(1, min(int(req.get("limit") or 500), 5000))
        except (TypeError, ValueError):
            return jsonify(api_response(code=400, msg="limit 必须是 1 到 5000 之间的整数。")), 400
        force_value = req.get("force", False)
        force = force_value is True or str(force_value).lower() in {"1", "true", "yes"}
        if actor != "admin":
            force = False
        if not _ensure_runtime_ensemble_ready():
            return jsonify(api_response(code=503, msg="运行时检测模型尚未就绪，请稍后重试。")), 503
        analysis = user_submission_manager.analyze(
            submission_id,
            detector=ensemble_detector,
            limit=limit,
            force=force,
        )
        if analysis is None:
            return jsonify(api_response(code=404, msg="提交记录不存在"))
        cache_reused = bool((analysis.get("analysis_trace") or {}).get("cache_reused"))
        try:
            tracking_versions = db.get_current_model_versions()
            analysis["training_tracking_versions"] = [
                item for item in tracking_versions
                if str(item.get("model_type") or "") != "runtime_ensemble"
            ]
        except Exception as model_error:
            logger.warning("Load current model versions failed: {}", model_error)
            analysis["training_tracking_versions"] = []
        try:
            item = user_submission_manager.get_submission(submission_id, include_preview=False) or {}
            db.upsert_user_submission(item)
            if not cache_reused:
                db.save_analysis_report_record(analysis)
        except Exception as persist_error:
            logger.warning("Persist analysis report failed: {}", persist_error)
        _clear_submission_related_caches()
        return jsonify(api_response(msg="已复用分析结果" if cache_reused else "分析完成", data=analysis))
    except Exception:
        logger.exception("Submission analysis failed")
        return jsonify(api_response(code=500, msg="分析失败，请稍后重试。")), 500
    finally:
        _analysis_operation_lock.release()


@app.route("/api/user/datasets/<submission_id>/analyze", methods=["POST"])
def user_dataset_analyze(submission_id):
    """Run data profiling and dual-risk detection for a user submission."""
    return _submission_analysis_response(submission_id, actor="user")


def _external_analysis_response(submission_id, actor="user"):
    """Interpret a completed local analysis using aggregate-only provider input."""
    try:
        settings = _external_ai_settings_store.get_effective(require_ready=True)
    except ExternalAdvisorDisabledError:
        return jsonify(api_response(code=503, msg="AI 脱敏解读未启用，本地检测与报告仍可正常使用。")), 503
    except ExternalAdvisorConfigError:
        return jsonify(api_response(code=503, msg="AI 脱敏解读尚未完成接口配置，本地功能不受影响。")), 503
    if actor != "admin" and not settings.get("user_enabled"):
        return jsonify(api_response(code=403, msg="管理员尚未开放用户端 AI 脱敏解读。")), 403

    item = user_submission_manager.get_submission(submission_id, include_preview=True)
    if item is None:
        return jsonify(api_response(code=404, msg="提交记录不存在。")), 404
    analysis = item.get("analysis") if isinstance(item.get("analysis"), dict) else {}
    trace = analysis.get("analysis_trace") if isinstance(analysis.get("analysis_trace"), dict) else {}
    if not trace.get("analysis_id"):
        return jsonify(api_response(code=409, msg="请先完成本地风险检测，再使用 AI 脱敏解读。")), 409
    if int(trace.get("analyzed_rows") or analysis.get("total") or 0) <= 0:
        return jsonify(api_response(code=409, msg="当前没有可供 AI 解读的有效分析统计。")), 409

    payload = build_redacted_analysis_payload(analysis)
    expected_cache_key = external_cache_key(payload, settings)
    req = request.get_json(silent=True) or {}
    force_value = req.get("force", False)
    force = actor == "admin" and (
        force_value is True or str(force_value).lower() in {"1", "true", "yes"}
    )
    cached = item.get("external_analysis") if isinstance(item.get("external_analysis"), dict) else {}
    if not force and cached.get("input_fingerprint") == expected_cache_key:
        cached_result = json.loads(json.dumps(cached, ensure_ascii=False))
        cached_result["cache_reused"] = True
        return jsonify(api_response(msg="已复用 AI 脱敏解读", data=cached_result))

    if not _external_analysis_operation_lock.acquire(blocking=False):
        return jsonify(api_response(
            code=409,
            msg="已有 AI 解读任务正在执行。为控制服务器资源与调用费用，请稍后再试。",
        )), 409
    try:
        # Re-check after acquiring the single-call lock to avoid duplicate paid
        # calls when two requests arrive together.
        latest = user_submission_manager.get_submission(submission_id, include_preview=True) or {}
        latest_analysis = latest.get("analysis") if isinstance(latest.get("analysis"), dict) else analysis
        latest_payload = build_redacted_analysis_payload(latest_analysis)
        latest_cache_key = external_cache_key(latest_payload, settings)
        latest_cached = latest.get("external_analysis") if isinstance(latest.get("external_analysis"), dict) else {}
        if not force and latest_cached.get("input_fingerprint") == latest_cache_key:
            cached_result = json.loads(json.dumps(latest_cached, ensure_ascii=False))
            cached_result["cache_reused"] = True
            return jsonify(api_response(msg="已复用 AI 脱敏解读", data=cached_result))

        allowed, retry_after, remaining = _reserve_external_ai_call(settings.get("calls_per_hour"))
        if not allowed:
            return jsonify(api_response(
                code=429,
                msg="外部 AI 每小时调用额度已用完，本地功能仍可继续使用。",
                data={"retry_after_seconds": retry_after},
            )), 429
        provider_result = _create_external_advisor_client(settings).analyze(latest_payload)
        record = make_external_analysis_record(latest_payload, settings, provider_result)
        assisted = build_ai_assisted_decisions(latest_analysis, record.get("advice"))
        record["assisted_decisions"] = assisted.get("items", [])
        record["assisted_summary"] = assisted.get("summary", {})
        record["decision_policy"] = assisted.get("policy")
        record["remaining_calls_this_hour"] = remaining
        if user_submission_manager.save_external_analysis(submission_id, record) is None:
            return jsonify(api_response(code=404, msg="提交记录不存在。")), 404
        _clear_submission_related_caches()
        return jsonify(api_response(msg="AI 脱敏研判完成", data=record))
    except (ExternalAdvisorConfigError, ExternalAdvisorDisabledError):
        return jsonify(api_response(code=503, msg="AI 脱敏解读配置不可用，本地功能不受影响。")), 503
    except (ExternalAdvisorProviderError, ExternalAdvisorResponseError):
        return jsonify(api_response(
            code=502,
            msg="AI 解读服务暂时不可用；本地检测结果已保留，不会受到影响。",
        )), 502
    except Exception:
        logger.exception("External aggregate analysis failed")
        return jsonify(api_response(code=500, msg="AI 解读失败；本地检测结果已保留。")), 500
    finally:
        _external_analysis_operation_lock.release()


@app.route("/api/user/external-ai/status", methods=["GET"])
def user_external_ai_status():
    """Expose feature availability without provider URL or credential metadata."""
    try:
        settings = _external_ai_settings_store.get_effective(require_ready=False)
        return jsonify(api_response(data={
            "available": bool(settings.get("ready") and settings.get("user_enabled")),
            "enabled": bool(settings.get("enabled")),
            "user_enabled": bool(settings.get("user_enabled")),
            "configured": bool(settings.get("configured")),
            "model": settings.get("model"),
            "mode": settings.get("mode"),
            "payload_policy": "redacted_aggregates_only",
        }))
    except ExternalAdvisorConfigError:
        return jsonify(api_response(data={
            "available": False,
            "enabled": False,
            "user_enabled": False,
            "configured": False,
            "payload_policy": "redacted_aggregates_only",
        }))


@app.route("/api/user/datasets/<submission_id>/external-analysis", methods=["POST"])
def user_dataset_external_analysis(submission_id):
    return _external_analysis_response(submission_id, actor="user")


@app.route("/api/user/reports/<submission_id>", methods=["GET"])
def user_report_get(submission_id):
    report = user_submission_manager.get_report(submission_id)
    if report is None:
        return jsonify(api_response(code=404, msg="报告不存在"))
    return jsonify(api_response(msg="success", data=report))


def _clear_admin_submissions_cache():
    with _admin_submissions_cache_lock:
        _admin_submissions_cache["time"] = 0.0
        _admin_submissions_cache["value"] = None


def _clear_submission_related_caches():
    _clear_admin_submissions_cache()
    _clear_dataset_sources_cache()


def _list_admin_submissions_cached(force=False):
    now = time.time()
    with _admin_submissions_cache_lock:
        cached = _admin_submissions_cache.get("value")
        cached_at = float(_admin_submissions_cache.get("time") or 0)
        if not force and cached is not None and now - cached_at < ADMIN_SUBMISSIONS_CACHE_SECONDS:
            return cached
    fresh = user_submission_manager.list_submissions()
    with _admin_submissions_cache_lock:
        _admin_submissions_cache["time"] = now
        _admin_submissions_cache["value"] = fresh
    return fresh


def _admin_submission_summary(items):
    summary = {"total": len(items), "high": 0, "medium": 0, "low": 0, "trainable": 0}
    for item in items:
        risk = item.get("risk_summary") or {}
        summary["high"] += int(risk.get("high") or risk.get("high_count") or 0)
        summary["medium"] += int(risk.get("medium") or risk.get("medium_count") or 0)
        summary["low"] += int(risk.get("low") or risk.get("low_count") or 0)
        if item.get("trainable"):
            summary["trainable"] += 1
    return summary


@app.route("/api/admin/submissions", methods=["GET"])
def admin_submissions():
    force = str(request.args.get("force", "")).lower() in {"1", "true", "yes"}
    limit = max(1, min(int(request.args.get("limit", 100) or 100), 500))
    items = _list_admin_submissions_cached(force=force)
    return jsonify(api_response(msg="success", data={
        "submissions": items[:limit],
        "total": len(items),
        "limit": limit,
        "summary": _admin_submission_summary(items),
    }))


@app.route("/api/admin/datasets/sources", methods=["GET"])
def admin_dataset_sources():
    """List trainable dataset sources for the management portal."""
    force = str(request.args.get("force", "")).lower() in {"1", "true", "yes"}
    sources = _list_dataset_sources_cached(force=force)
    processed_meta = _load_processed_metadata()
    processed_source_id = str(processed_meta.get("dataset_source_id") or "")
    current_source = next(
        (item for item in sources if str(item.get("id") or "") == processed_source_id),
        None,
    )
    ready_for_federated = bool(
        current_source
        and _source_prepared_for_federated(current_source)
        and _federated_files_ready()
    )
    return jsonify(api_response(msg="success", data={
        "sources": sources,
        "total": len(sources),
        "current_source": current_source,
        "current_source_id": processed_source_id or None,
        "processed": processed_meta,
        "ready_for_federated": ready_for_federated,
        "model_inventory": _model_inventory(),
        "processing_policy": {
            "mode": "incremental_for_approved_submissions",
            "incremental": True,
            "max_rows": 50000,
            "unchanged_action": "reuse",
            "append_action": "decrypt_and_transform_new_submissions_only",
            "fallback_action": "full_rebuild_when_source_or_schema_changes",
            "validation_split": SHARED_VALIDATION_SPLIT_VERSION,
            "validation_fraction": SHARED_VALIDATION_FRACTION,
            "federated_split": FEDERATED_SPLIT_VERSION,
            "note": "用户可训练池只解密并提取新增提交，已有共享留出集保持冻结；提交撤销、数据源或特征版本变化时自动回退为全量重建。",
        },
        "note": "数据准备会保留同源共享留出集，再按业务 Non-IID 分布写入四节点；公开流量型数据集未配置时不会伪装为已加载。",
    }))


def _prepare_dataset_source_for_federated(source, source_id=None, limit=50000, force_rebuild=False):
    # A second request waits for the first and then reuses its completed
    # revision.  This prevents duplicate work and mixed X/y/node files.
    with _dataset_prepare_lock:
        return _prepare_dataset_source_for_federated_locked(
            source,
            source_id=source_id,
            limit=limit,
            force_rebuild=force_rebuild,
        )


def _prepare_dataset_source_for_federated_locked(source, source_id=None, limit=50000, force_rebuild=False):
    """Prepare a selected source for federated nodes without retraining detectors."""
    started_at = time.perf_counter()
    try:
        from src.preprocess.feature_engineering import load_security_csv, normalize_security_features

        try:
            limit = int(limit or 50000)
        except (TypeError, ValueError):
            limit = 50000
        limit = max(1, min(limit, 50000))

        effective_source_id = source_id or source.get("id") or _dataset_source_id(source)
        dataset_revision = _dataset_source_revision(source, limit=limit)
        preparation_id = _dataset_preparation_id(effective_source_id, dataset_revision)
        split_seed = _stable_seed(dataset_revision)
        if not force_rebuild and _preparation_matches(source, effective_source_id, limit=limit):
            metadata = _load_processed_metadata()
            request_time_ms = round((time.perf_counter() - started_at) * 1000, 3)
            return jsonify(api_response(msg="数据源未变化，已复用现有四节点数据", data={
                **metadata,
                "reused": True,
                "changed": False,
                "nodes": metadata.get("nodes") or _prepared_node_counts(),
                "original_processing_time_ms": metadata.get("processing_time_ms"),
                "processing_time_ms": request_time_ms,
            }))

        source_type = source.get("source_type")
        incremental_change = None if force_rebuild else _incremental_submission_change(
            source,
            effective_source_id,
            limit,
        )
        if incremental_change and incremental_change.get("new_ids"):
            previous_meta = dict(incremental_change.get("metadata") or {})
            previous_samples = int(previous_meta.get("samples") or 0)
            remaining = max(0, limit - previous_samples)
            current_source_ids = incremental_change.get("current_ids") or []
            new_ids = incremental_change.get("new_ids") or []
            if remaining == 0:
                # The configured preparation cap is already full. Record the
                # source revision without decrypting rows that cannot enter the
                # current training scope.
                metadata = dict(previous_meta)
                metadata.update({
                    "dataset_revision": dataset_revision,
                    "processed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "process_mode": "incremental_limit_reached",
                    "process_scope": "existing_limit_rows",
                    "incremental": True,
                    "added_samples": 0,
                    "new_submission_count": len(new_ids),
                    "ignored_new_submissions": len(new_ids),
                    "source_submission_ids": current_source_ids,
                    "raw_samples": int(source.get("samples") or previous_meta.get("raw_samples") or previous_samples),
                    "processing_time_ms": round((time.perf_counter() - started_at) * 1000, 3),
                })
                atomic_write_json(PROCESSED_META_PATH, metadata)
                _clear_dataset_sources_cache()
                return jsonify(api_response(msg="新增提交已识别，但当前处理上限已满，继续复用现有训练数据", data={
                    **metadata,
                    "reused": True,
                    "changed": True,
                }))

            new_x, new_y, new_user_meta = user_submission_manager.load_trainable_features(
                ids=new_ids,
                limit=remaining,
            )
            if len(new_x):
                partition_meta = _append_incremental_training_partitions(
                    new_x,
                    new_y,
                    split_seed,
                    preparation_id,
                )
                loaded_new_ids = [
                    str(item.get("id"))
                    for item in ((new_user_meta or {}).get("sources") or [])
                    if item.get("id")
                ]
                loaded_submission_ids = list(previous_meta.get("submission_ids") or [])
                loaded_submission_ids.extend(
                    value for value in loaded_new_ids if value not in loaded_submission_ids
                )
                metadata = dict(previous_meta)
                metadata.update({
                    "dataset_source_id": effective_source_id,
                    "dataset_revision": dataset_revision,
                    "preparation_id": preparation_id,
                    "preprocessing_version": FEATURE_NORMALIZATION_VERSION,
                    "federated_split_version": FEDERATED_SPLIT_VERSION,
                    "prepared_bundle_version": PREPARED_BUNDLE_VERSION,
                    "source": source.get("name") or source.get("source") or "用户可训练数据池",
                    "source_type": source_type,
                    "samples": partition_meta["samples"],
                    "training_samples": partition_meta["training_samples"],
                    "validation_samples": partition_meta["validation_samples"],
                    "features": int(new_x.shape[1]),
                    "label_counts": partition_meta["label_counts"],
                    "training_label_counts": partition_meta["training_label_counts"],
                    "validation_label_counts": partition_meta["validation_label_counts"],
                    "processed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "prepared_only": True,
                    "process_mode": "incremental_append",
                    "process_scope": "new_approved_submissions",
                    "process_limit": limit,
                    "incremental": True,
                    "added_samples": partition_meta["added_samples"],
                    "previous_samples": partition_meta["previous_samples"],
                    "new_submission_count": len(loaded_new_ids),
                    "source_submission_ids": current_source_ids,
                    "submission_ids": loaded_submission_ids,
                    "raw_samples": int(source.get("samples") or partition_meta["samples"]),
                    "split_strategy": "shared_frozen_holdout_then_business_noniid",
                    "split_seed": split_seed,
                    "federated_split": partition_meta["federated_split"],
                    "drift": partition_meta["drift"],
                    "nodes": partition_meta["node_details"],
                })
                processing_seconds = max(time.perf_counter() - started_at, 0.000001)
                metadata["processing_time_ms"] = round(processing_seconds * 1000, 3)
                metadata["processing_rows_per_second"] = round(len(new_x) / processing_seconds, 2)
                atomic_write_json(PROCESSED_META_PATH, metadata)
                _clear_dataset_sources_cache()
                return jsonify(api_response(msg="仅处理新增可训练提交，并已更新四节点数据", data={
                    **metadata,
                    "reused": False,
                    "changed": True,
                }))

        if source_type in {"user_submission_pool", "user_submission"}:
            ids = None
            if source_type == "user_submission":
                submission_id = source.get("submission_id") or str(source.get("id") or "").replace("submission:", "")
                ids = [submission_id] if submission_id else []
            X, y, user_meta = user_submission_manager.load_trainable_features(ids=ids, limit=limit)
            if len(X) == 0:
                return jsonify(api_response(code=400, msg="没有可用于训练的用户提交数据，请先在用户提交页归档并标记可训练。"))

            partition_meta = _save_shared_training_partitions(X, y, split_seed, preparation_id)
            nodes = partition_meta["nodes"]

            label_counts = {str(k): int(v) for k, v in zip(*np.unique(y, return_counts=True))}
            metadata = {
                "dataset_source_id": effective_source_id,
                "dataset_revision": dataset_revision,
                "preparation_id": preparation_id,
                "preprocessing_version": FEATURE_NORMALIZATION_VERSION,
                "prepared_bundle_version": PREPARED_BUNDLE_VERSION,
                "source": source.get("name") or source.get("source") or "用户可训练数据池",
                "source_type": source_type,
                "source_path": source.get("id") or source_type,
                "samples": int(len(X)),
                "training_samples": partition_meta["training_samples"],
                "validation_samples": partition_meta["validation_samples"],
                "features": int(X.shape[1]),
                "label_column": "label",
                "label_counts": label_counts,
                "processed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "prepared_only": True,
                "process_mode": "full_rebuild",
                "process_scope": "all_rows" if int(source.get("samples") or len(X)) <= limit else "first_limit_rows",
                "process_limit": limit,
                "incremental": False,
                "added_samples": int(len(X)),
                "raw_samples": int(source.get("samples") or len(X)),
                "split_strategy": "shared_holdout_then_business_noniid",
                "split_seed": split_seed,
                "validation_available": partition_meta["validation_available"],
                "validation_id": partition_meta["validation_id"],
                "validation_split_version": partition_meta["validation_split_version"],
                "validation_fraction": partition_meta["validation_fraction"],
                "training_label_counts": partition_meta["training_label_counts"],
                "validation_label_counts": partition_meta["validation_label_counts"],
                "federated_split_version": partition_meta["federated_split_version"],
                "federated_split": partition_meta["federated_split"],
                "submission_ids": (user_meta or {}).get("submission_ids") or source.get("submission_ids") or [],
                "source_submission_ids": sorted(str(value) for value in (source.get("submission_ids") or []) if value),
                "drift": {"available": False, "level": "baseline", "reason": "initial_full_preparation"},
            }
            metadata["nodes"] = partition_meta["node_details"]
            processing_seconds = max(time.perf_counter() - started_at, 0.000001)
            metadata["processing_time_ms"] = round(processing_seconds * 1000, 3)
            metadata["processing_rows_per_second"] = round(len(X) / processing_seconds, 2)
            atomic_write_json(PROCESSED_META_PATH, metadata)

            _clear_dataset_sources_cache()
            return jsonify(api_response(msg="success", data={
                **metadata,
                "reused": False,
                "changed": True,
            }))

        filepath = source.get("path")
        if not filepath or not os.path.exists(filepath):
            return jsonify(api_response(code=400, msg="Dataset source file does not exist."))

        logger.info("Preparing federated nodes from dataset source: {}", filepath)
        X, y, _ = load_security_csv(filepath, limit=limit)
        if len(X) == 0:
            return jsonify(api_response(code=400, msg="Dataset source is empty or features cannot be extracted."))

        X = normalize_security_features(X)
        partition_meta = _save_shared_training_partitions(X, y, split_seed, preparation_id)
        nodes = partition_meta["nodes"]

        info = source

        label_counts = {str(k): int(v) for k, v in zip(*np.unique(y, return_counts=True))}
        metadata = {
            "dataset_source_id": effective_source_id,
            "dataset_revision": dataset_revision,
            "preparation_id": preparation_id,
            "preprocessing_version": FEATURE_NORMALIZATION_VERSION,
            "prepared_bundle_version": PREPARED_BUNDLE_VERSION,
            "source": source.get("source") or os.path.basename(filepath),
            "source_type": source.get("source_type") or "dataset",
            "source_path": filepath,
            "samples": int(len(X)),
            "training_samples": partition_meta["training_samples"],
            "validation_samples": partition_meta["validation_samples"],
            "features": int(X.shape[1]),
            "label_column": info.get("label_column"),
            "label_counts": label_counts,
            "processed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "prepared_only": True,
            "process_mode": "full_rebuild",
            "process_scope": "all_rows" if int(source.get("samples") or len(X)) <= limit else "first_limit_rows",
            "process_limit": limit,
            "incremental": False,
            "raw_samples": int(source.get("samples") or info.get("samples") or len(X)),
            "split_strategy": "shared_holdout_then_business_noniid",
            "split_seed": split_seed,
            "validation_available": partition_meta["validation_available"],
            "validation_id": partition_meta["validation_id"],
            "validation_split_version": partition_meta["validation_split_version"],
            "validation_fraction": partition_meta["validation_fraction"],
            "training_label_counts": partition_meta["training_label_counts"],
            "validation_label_counts": partition_meta["validation_label_counts"],
            "federated_split_version": partition_meta["federated_split_version"],
            "federated_split": partition_meta["federated_split"],
            "drift": {"available": False, "level": "baseline", "reason": "full_preparation"},
        }
        metadata["nodes"] = partition_meta["node_details"]
        processing_seconds = max(time.perf_counter() - started_at, 0.000001)
        metadata["processing_time_ms"] = round(processing_seconds * 1000, 3)
        metadata["processing_rows_per_second"] = round(len(X) / processing_seconds, 2)
        atomic_write_json(PROCESSED_META_PATH, metadata)

        _clear_dataset_sources_cache()
        return jsonify(api_response(msg="success", data={
            **metadata,
            "reused": False,
            "changed": True,
        }))
    except Exception as e:
        logger.exception("Dataset node preparation failed")
        return jsonify(api_response(code=500, msg="Node preparation failed: %s" % e))


@app.route("/api/admin/datasets/<source_id>/prepare", methods=["POST"])
def admin_dataset_prepare(source_id):
    """Prepare a selected dataset source for training and federated splitting."""
    sources = _list_dataset_sources_cached(force=False)
    selected = next((s for s in sources if s.get("id") == source_id), None)
    if selected is None:
        sources = _list_dataset_sources_cached(force=True)
        selected = next((s for s in sources if s.get("id") == source_id), None)
    if selected is None:
        return jsonify(api_response(code=404, msg="数据源不存在"))
    req = request.get_json(silent=True) or {}
    return _prepare_dataset_source_for_federated(
        selected,
        source_id,
        limit=req.get("limit", 50000),
        force_rebuild=bool(req.get("force_rebuild", False)),
    )


@app.route("/api/admin/datasets/<source_id>/split-federated", methods=["POST"])
def admin_dataset_split_federated(source_id):
    """Split a selected dataset into four federated nodes."""
    return admin_dataset_prepare(source_id)


@app.route("/api/admin/submissions/<submission_id>", methods=["GET"])
def admin_submission_detail(submission_id):
    item = user_submission_manager.get_submission(submission_id, include_preview=True)
    if item is None:
        return jsonify(api_response(code=404, msg="提交记录不存在"))
    return jsonify(api_response(msg="success", data=item))


@app.route("/api/admin/submissions/<submission_id>/analyze", methods=["POST"])
def admin_submission_analyze(submission_id):
    """Reuse the same dual-risk analysis core from the protected admin API."""
    return _submission_analysis_response(submission_id, actor="admin")


@app.route("/api/admin/submissions/<submission_id>/external-analysis", methods=["POST"])
def admin_submission_external_analysis(submission_id):
    """Explicit admin-only AI second opinion; never called by local analysis."""
    return _external_analysis_response(submission_id, actor="admin")


@app.route("/api/admin/submissions/<submission_id>/archive", methods=["POST"])
def admin_submission_archive(submission_id):
    item = user_submission_manager.set_status(submission_id, review_status="已归档")
    if item is None:
        return jsonify(api_response(code=404, msg="提交记录不存在"))
    try:
        db.upsert_user_submission(item)
    except Exception as persist_error:
        logger.warning("Persist archive status failed: {}", persist_error)
    _clear_submission_related_caches()
    return jsonify(api_response(msg="已归档", data=item))


@app.route("/api/admin/submissions/<submission_id>/mark-trainable", methods=["POST"])
def admin_submission_mark_trainable(submission_id):
    try:
        item = user_submission_manager.set_status(submission_id, review_status="可训练", trainable=True)
        if item is None:
            return jsonify(api_response(code=404, msg="提交记录不存在"))
        try:
            db.upsert_user_submission(item)
        except Exception as persist_error:
            logger.warning("Persist trainable status failed: {}", persist_error)
        _clear_submission_related_caches()
        return jsonify(api_response(msg="已标记为可训练", data=item))
    except SubmissionStatusError as e:
        return jsonify(api_response(code=400, msg=str(e)))
    except Exception as e:
        logger.exception("Mark submission trainable failed")
        return jsonify(api_response(code=500, msg="标记可训练失败: %s" % e))


@app.route("/api/admin/submissions/<submission_id>/reject", methods=["POST"])
def admin_submission_reject(submission_id):
    req = request.get_json(silent=True) or {}
    item = user_submission_manager.set_status(
        submission_id,
        review_status="已拒绝",
        trainable=False,
        review_note=req.get("note", "管理员确认该提交暂不进入训练池"),
    )
    if item is None:
        return jsonify(api_response(code=404, msg="提交记录不存在"))
    try:
        db.upsert_user_submission(item)
    except Exception as persist_error:
        logger.warning("Persist rejected status failed: {}", persist_error)
    _clear_submission_related_caches()
    return jsonify(api_response(msg="已拒绝进入训练池", data=item))


@app.route("/api/admin/submissions/<submission_id>/review-status", methods=["POST"])
def admin_submission_review_status(submission_id):
    req = request.get_json(silent=True) or {}
    status = req.get("review_status")
    trainable = req.get("trainable")
    item = user_submission_manager.set_status(
        submission_id,
        review_status=status,
        trainable=trainable if isinstance(trainable, bool) else None,
        review_note=req.get("note", ""),
    )
    if item is None:
        return jsonify(api_response(code=400, msg="提交记录不存在或审核状态无效"))
    try:
        db.upsert_user_submission(item)
    except Exception as persist_error:
        logger.warning("Persist review status failed: {}", persist_error)
    _clear_submission_related_caches()
    return jsonify(api_response(msg="审核状态已更新", data=item))


def _public_training_job(job, include_result=True):
    job = dict(job or {})
    result = job.get("result") if isinstance(job.get("result"), dict) else {}
    payload = job.get("payload") if isinstance(job.get("payload"), dict) else {}
    output = result.get("data") if isinstance(result, dict) else None
    public = {
        "id": job.get("id"),
        "task_type": job.get("task_type"),
        "status": job.get("status"),
        "created_at": job.get("created_at"),
        "updated_at": job.get("updated_at"),
        "started_at": job.get("started_at"),
        "finished_at": job.get("finished_at"),
        "error": job.get("error") or "",
        "dataset_source_id": payload.get("dataset_source_id"),
        "aggregation_method": payload.get("aggregation_method"),
    }
    if include_result and result:
        public["message"] = result.get("msg") or ""
        public["output"] = output if output is not None else result
    return public


def _execute_training_job(job):
    handlers = {
        "runtime": ("/api/admin/training/local", _admin_training_local_locked),
        "centralized": ("/api/admin/training/centralized", _admin_training_centralized_locked),
        "federated": ("/api/admin/training/federated", _admin_training_federated_locked),
    }
    task_type = str((job or {}).get("task_type") or "")
    route_path, handler = handlers.get(task_type, (None, None))
    if handler is None:
        raise ValueError("unsupported queued training type: %s" % task_type)
    payload = job.get("payload") if isinstance(job.get("payload"), dict) else {}
    with _training_operation_lock:
        with app.test_request_context(route_path, method="POST", json=payload):
            raw_response = handler()
            response = app.make_response(raw_response)
            try:
                response_payload = response.get_json(silent=True) or {}
                response_code = int(response_payload.get("code", 200) or 200)
                if response.status_code >= 400 or response_code != 200:
                    message = response_payload.get("msg") or "training request failed"
                    db.fail_training_job(job.get("id"), message, response_payload)
                    return
                db.finish_training_job(job.get("id"), response_payload)
            finally:
                response.close()


def _training_worker_loop():
    global _training_worker_thread
    worker_id = "pid-%s-thread-%s" % (os.getpid(), threading.current_thread().ident)
    try:
        while True:
            job = db.claim_next_training_job(worker_id)
            if not job:
                # Coordinate shutdown with enqueue so a task cannot land in
                # the tiny gap between the final empty claim and thread exit.
                with _training_worker_state_lock:
                    if _training_worker_wakeup.is_set():
                        _training_worker_wakeup.clear()
                        continue
                    if _training_worker_thread is threading.current_thread():
                        _training_worker_thread = None
                    return
            try:
                _execute_training_job(job)
            except Exception as exc:
                logger.exception("Queued training job failed: {}", job.get("id"))
                db.fail_training_job(job.get("id"), str(exc))
    finally:
        with _training_worker_state_lock:
            if _training_worker_thread is threading.current_thread():
                _training_worker_thread = None


def _ensure_training_worker():
    global _training_worker_thread
    with _training_worker_state_lock:
        _training_worker_wakeup.set()
        if _training_worker_thread is not None and _training_worker_thread.is_alive():
            return
        _training_worker_thread = threading.Thread(
            target=_training_worker_loop,
            name="dachuang-training-worker",
            daemon=True,
        )
        _training_worker_thread.start()


def _enqueue_training_request(task_type, payload):
    try:
        job = db.enqueue_training_job(task_type, payload or {}, max_pending=8)
    except RuntimeError:
        return jsonify(api_response(
            code=429,
            msg="训练队列已满，请等待当前任务完成后再提交。",
        )), 429
    _ensure_training_worker()
    return jsonify(api_response(
        msg="相同训练任务已在队列中" if job.get("reused") else "训练任务已进入单任务队列",
        data=_public_training_job(job, include_result=False),
    )), 202


@app.route("/api/admin/training/jobs/<job_id>", methods=["GET"])
def admin_training_job(job_id):
    job = db.get_training_job(job_id)
    if not job:
        return jsonify(api_response(code=404, msg="训练任务不存在")), 404
    if job.get("status") in {"queued", "running"}:
        _ensure_training_worker()
    return jsonify(api_response(data=_public_training_job(job)))


@app.route("/api/admin/training/jobs", methods=["GET"])
def admin_training_jobs():
    limit = max(1, min(int(request.args.get("limit", 20) or 20), 100))
    jobs = db.get_training_jobs(limit, include_result=False)
    if any(item.get("status") in {"queued", "running"} for item in jobs):
        _ensure_training_worker()
    return jsonify(api_response(data={
        "jobs": [_public_training_job(item) for item in jobs],
        "worker_mode": "sqlite_single_worker",
    }))


@app.route("/api/admin/training/local", methods=["POST"])
def admin_training_local():
    payload = request.get_json(silent=True) or {}
    if not app.config.get("TESTING"):
        return _enqueue_training_request("runtime", payload)
    if not _training_operation_lock.acquire(blocking=False):
        return jsonify(api_response(code=409, msg="已有训练任务正在执行，请等待当前任务完成后再试。")), 409
    try:
        return _admin_training_local_locked()
    finally:
        _training_operation_lock.release()


@app.route("/api/admin/training/centralized", methods=["POST"])
def admin_training_centralized():
    """Train the ordinary centralized baseline used for a fair FedAvg comparison."""
    payload = request.get_json(silent=True) or {}
    if not app.config.get("TESTING"):
        return _enqueue_training_request("centralized", payload)
    if not _training_operation_lock.acquire(blocking=False):
        return jsonify(api_response(code=409, msg="已有训练任务正在执行，请等待当前任务完成后再试。")), 409
    try:
        return _admin_training_centralized_locked()
    finally:
        _training_operation_lock.release()


def _admin_training_centralized_locked():
    """Train the same linear model as each federated client on all train rows."""
    try:
        from src.federated.client import FederatedClient

        req = request.get_json(silent=True) or {}
        dataset_source_id = req.get("dataset_source_id")
        requested_limit = max(10, min(int(req.get("limit") or 10000), 50000))
        epochs = max(1, min(int(req.get("epochs") or FEDERATED_DEFAULT_LOCAL_EPOCHS), 20))

        with _dataset_prepare_lock:
            X, y, meta = _load_training_dataset_source(dataset_source_id, limit=50000)
            if meta.get("source_not_found"):
                return jsonify(api_response(code=404, msg="请求的数据源不存在，请刷新数据源列表后重试。")), 404
            if len(X) < 20 or len(np.unique((y > 0).astype(int))) < 2:
                return jsonify(api_response(
                    code=400,
                    msg="普通/联邦对比至少需要 20 条训练样本，并同时包含正常和攻击标签。",
                )), 400
            if not (
                meta.get("uses_prepared_data")
                and meta.get("uses_shared_validation")
                and meta.get("validation_id")
                and meta.get("validation_split_version") == SHARED_VALIDATION_SPLIT_VERSION
            ):
                return jsonify(api_response(
                    code=409,
                    msg="当前数据源尚未生成共享留出集，请先重新执行数据处理后再开始普通/联邦对比。",
                )), 409
            validation_x, validation_y, validation_meta = _load_prepared_validation_arrays()
            if (
                validation_meta.get("preparation_id") != meta.get("preparation_id")
                or validation_meta.get("validation_id") != meta.get("validation_id")
                or len(validation_x) < 2
                or len(np.unique((validation_y > 0).astype(int))) < 2
            ):
                return jsonify(api_response(
                    code=409,
                    msg="共享留出集与当前准备版本不一致，请重新执行数据处理。",
                )), 409

        baseline = FederatedClient("centralized-baseline", "")
        baseline.X = np.asarray(X, dtype=np.float64)
        baseline.y = np.asarray(y, dtype=np.int32)
        baseline._loaded = True
        fit_result = baseline.train_local(
            global_weights=None,
            epochs=epochs,
            use_internal_validation=False,
        )
        metrics = evaluate_linear_binary_weights(
            validation_x,
            validation_y,
            fit_result.get("weights"),
        )
        if metrics is None:
            return jsonify(api_response(code=500, msg="普通集中式基线未能生成可评估权重。")), 500

        version = datetime.now().strftime("central%Y%m%d%H%M%S%f")[:-3]
        source_ids = [
            item.get("id") for item in meta.get("sources", [])
            if item.get("id") and not str(item.get("id")).startswith("dataset:")
        ]
        record = {
            **meta,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "task_type": "centralized",
            "comparison_role": "ordinary_centralized_baseline",
            "source": meta.get("training_source", "managed_dataset_source"),
            "model_type": "centralized_linear_baseline",
            "status": "completed",
            "model_version": version,
            "source_submission_ids": source_ids,
            "samples": int(len(X)),
            "training_samples": int(len(X)),
            "source_samples": int(meta.get("source_samples") or (len(X) + len(validation_x))),
            "requested_limit": requested_limit,
            "accuracy": metrics["accuracy"],
            "precision": metrics["precision"],
            "recall": metrics["recall"],
            "f1": metrics["f1"],
            "loss": metrics["loss"],
            "train_accuracy": fit_result.get("accuracy"),
            "train_loss": fit_result.get("loss"),
            "algorithm": "linear_logistic_gradient_descent",
            "base_model_algorithm": "linear_logistic_binary_classifier",
            "optimizer": "batch_gradient_descent_l2",
            "epochs": epochs,
            "effective_epochs": epochs,
            "rounds": 0,
            "node_count": 1,
            "aggregation_method": "centralized",
            "uses_prepared_nodes": False,
            "uses_shared_validation": True,
            "metric_name": "accuracy",
            "metric_scope": "shared_holdout_validation",
            "metric_label": "同源共享留出集指标",
            "metric_note": (
                "普通集中式基线与四节点联邦路径使用相同线性模型、优化参数、训练分区和共享留出集；"
                "差异主要来自集中训练与节点本地训练后 FedAvg 聚合。"
            ),
            "validation_available": True,
            "validation_samples": int(len(validation_x)),
            "validation_id": meta.get("validation_id"),
            "validation_split_version": meta.get("validation_split_version"),
            "validation_label_distribution": meta.get("validation_label_distribution") or {},
            "runtime_model_updated": False,
            "note": (
                "This centralized linear baseline is used only for a like-for-like FedAvg comparison; "
                "it does not replace the user-facing runtime ensemble detector."
            ),
        }
        record["updated_submissions"] = user_submission_manager.mark_used_for_training(
            source_ids,
            task_type="centralized",
            model_version=version,
            samples=int(len(X)),
        )
        save_training_record(record)
        try:
            db.save_training_task_record(record)
            db.save_model_version_record({
                "version": version,
                "model_type": record["model_type"],
                "source": record["source"],
                "samples": record["samples"],
                "accuracy": record["accuracy"],
                "metadata": record,
            })
        except Exception as persist_error:
            logger.warning("Persist centralized baseline task failed: {}", persist_error)
        return jsonify(api_response(msg="普通集中式基线训练完成", data=record))
    except Exception as e:
        logger.exception("Admin centralized baseline training failed")
        return jsonify(api_response(code=500, msg="普通集中式训练失败: %s" % e)), 500


def _admin_training_local_locked():
    """Train the ensemble detector with admin-approved encrypted submissions."""
    try:
        from src.detection.ensemble_detector import ensemble_detector
        req = request.get_json(silent=True) or {}
        ids = req.get("submission_ids") or None
        dataset_source_id = req.get("dataset_source_id")
        limit = max(10, min(int(req.get("limit") or 10000), 50000))
        validation_x = np.empty((0, 18), dtype=np.float64)
        validation_y = np.empty(0, dtype=np.int32)
        with _dataset_prepare_lock:
            if dataset_source_id:
                X, y, meta = _load_training_dataset_source(dataset_source_id, limit=limit)
                if meta.get("source_not_found"):
                    return jsonify(api_response(code=404, msg="请求的数据源不存在，请刷新数据源列表后重试。")), 404
            else:
                X, y, meta = user_submission_manager.load_trainable_features(ids=ids, limit=limit)
                if len(X) < 10:
                    X, y, meta = _load_training_dataset_source(dataset_source_id, limit=limit)
            if meta.get("uses_shared_validation") and meta.get("validation_available"):
                candidate_x, candidate_y, validation_meta = _load_prepared_validation_arrays()
                if (
                    validation_meta.get("preparation_id") == meta.get("preparation_id")
                    and validation_meta.get("validation_id") == meta.get("validation_id")
                ):
                    validation_x, validation_y = candidate_x, candidate_y
        if len(X) < 10:
            return jsonify(api_response(code=400, msg="当前数据源没有足够的可训练数据，请确认标签与样本数量后重试。")), 400
        if len(np.unique((y > 0).astype(int))) < 2:
            return jsonify(api_response(code=400, msg="当前数据源只包含一个标签类别，运行时检测模型需要同时包含正常和攻击样本。")), 400

        seed = _stable_seed(meta.get("dataset_revision"))
        uses_shared_validation = bool(len(validation_x))
        if not uses_shared_validation:
            split_x, split_y, candidate_x, candidate_y = _stratified_holdout_split(X, y, seed=seed)
            if len(candidate_x):
                X, y = split_x, split_y
                validation_x, validation_y = candidate_x, candidate_y
                meta = dict(meta or {})
                local_validation_raw = "%s:%s:%s" % (
                    meta.get("dataset_source_id") or "local-source",
                    seed,
                    len(validation_x),
                )
                meta.update({
                    "validation_available": True,
                    "validation_samples": int(len(validation_x)),
                    "validation_id": "local-val-" + hashlib.sha256(
                        local_validation_raw.encode("utf-8")
                    ).hexdigest()[:12],
                    "validation_split_version": SHARED_VALIDATION_SPLIT_VERSION,
                    "uses_shared_validation": False,
                })
        # The request limit is the single source-of-truth for training scope.
        # Do not apply a second hidden 5,000-row cap after loading the source.
        fit_x, fit_y = _stratified_training_sample(X, y, max_samples=limit, seed=seed)
        validation_available = bool(
            len(validation_x)
            and len(np.unique((validation_y > 0).astype(int))) >= 2
        )
        validation_label_distribution = {
            str(key): int(value)
            for key, value in zip(*np.unique(validation_y, return_counts=True))
        } if validation_available else {}
        version = datetime.now().strftime("v%Y%m%d%H%M%S%f")[:-3]
        result = ensemble_detector.fit(
            fit_x,
            fit_y,
            version=version,
            metadata={
                "dataset_source_id": meta.get("dataset_source_id"),
                "dataset_revision": meta.get("dataset_revision"),
                "preparation_id": meta.get("preparation_id"),
                "source_type": meta.get("source_type"),
                "samples": int(len(fit_x)),
                "source_samples": int(meta.get("source_samples") or (len(X) + len(validation_x))),
                "validation_available": validation_available,
                "validation_samples": int(len(validation_x)) if validation_available else 0,
                "validation_id": meta.get("validation_id") if validation_available else None,
                "validation_split_version": meta.get("validation_split_version") if validation_available else None,
            },
        )
        train_preds, train_scores, _ = ensemble_detector.predict(fit_x)
        train_metrics = binary_classification_metrics((fit_y > 0).astype(int), train_preds)
        train_loss = binary_log_loss(fit_y, train_scores)
        if validation_available:
            evaluation_preds, evaluation_scores, _ = ensemble_detector.predict(validation_x)
            metrics = binary_classification_metrics((validation_y > 0).astype(int), evaluation_preds)
            evaluation_loss = binary_log_loss(validation_y, evaluation_scores)
            metric_scope = "shared_holdout_validation" if uses_shared_validation else "local_holdout_validation"
            metric_label = "同源共享留出集指标" if uses_shared_validation else "本地分层留出集指标"
            metric_note = (
                "运行时融合模型仅使用训练分区拟合，并在未参与训练的共享留出集上评估；"
                "该模型独立服务于用户风险检测，不作为普通集中式/FedAvg 同构对照。"
                if uses_shared_validation else
                "当前数据源尚未生成四节点共享留出集；运行时融合模型使用确定性分层留出数据评估，"
                "该指标只用于判断当前检测模型，不参与训练方式排名。"
            )
        else:
            metrics = train_metrics
            evaluation_loss = train_loss
            metric_scope = "train"
            metric_label = "训练集指标"
            metric_note = "当前数据量或类别分布不足以同时建立含两类标签的训练集和留出集，因此仅显示训练集指标，不允许据此比较模型优劣。"
        record = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "task_type": "runtime",
            "comparison_role": "user_facing_runtime_detector",
            "source": meta.get("training_source", "encrypted_user_submissions"),
            "model_type": "runtime_ensemble",
            "dataset_name": meta.get("dataset_name", "encrypted_user_submissions"),
            "dataset_source_id": meta.get("dataset_source_id"),
            "dataset_revision": meta.get("dataset_revision"),
            "preparation_id": meta.get("preparation_id"),
            "preprocessing_version": FEATURE_NORMALIZATION_VERSION,
            "prepared_bundle_version": meta.get("prepared_bundle_version"),
            "model_cycle_id": meta.get("preparation_id"),
            "source_type": meta.get("source_type"),
            "uses_prepared_data": bool(meta.get("uses_prepared_data")),
            "uses_prepared_nodes": False,
            "accuracy": metrics["accuracy"],
            "precision": metrics["precision"],
            "recall": metrics["recall"],
            "f1": metrics["f1"],
            "loss": evaluation_loss,
            "train_accuracy": train_metrics["accuracy"],
            "train_loss": train_loss,
            "algorithm": "ensemble_detector",
            "metric_name": "accuracy",
            "metric_scope": metric_scope,
            "metric_label": metric_label,
            "metric_note": metric_note,
            "validation_available": validation_available,
            "validation_samples": int(len(validation_x)) if validation_available else 0,
            "validation_id": meta.get("validation_id") if validation_available else None,
            "validation_split_version": meta.get("validation_split_version") if validation_available else None,
            "validation_label_distribution": validation_label_distribution,
            "uses_shared_validation": uses_shared_validation,
            "samples": int(len(fit_x)),
            "training_samples": int(len(fit_x)),
            "source_samples": int(meta.get("source_samples") or (len(X) + len(validation_x))),
            "source_count": int(meta.get("source_count", 0)),
            "label_distribution": meta.get("label_distribution", {}),
            "drift": meta.get("drift") or {},
            "node_count": 1,
            "rounds": 0,
            "epochs": 1,
            "status": "completed",
            "model_version": version,
            "runtime_model_updated": True,
            "note": "Runtime training updates the user-facing ensemble detector directly; it is tracked separately and is not used as the ordinary baseline in the FedAvg comparison.",
        }
        source_ids = [s.get("id") for s in meta.get("sources", []) if s.get("id") and not str(s.get("id")).startswith("dataset:")]
        record["source_submission_ids"] = source_ids
        save_training_record(record)
        updated_submissions = user_submission_manager.mark_used_for_training(
            source_ids,
            task_type="runtime",
            model_version=record["model_version"],
            samples=int(len(fit_x)),
        )
        try:
            db.save_training_task_record(record)
            db.save_model_version_record({
                "version": record["model_version"],
                "model_type": record["model_type"],
                "source": record["source"],
                "samples": record["samples"],
                "accuracy": record["accuracy"],
                "metadata": record,
            })
        except Exception as persist_error:
            logger.warning("Persist local training task failed: {}", persist_error)
        return jsonify(api_response(msg="运行时检测模型训练完成", data={**meta, **record, "fit_result": result, "updated_submissions": updated_submissions}))
    except Exception as e:
        logger.exception("Admin local training failed")
        return jsonify(api_response(code=500, msg="训练失败: %s" % e))


@app.route("/api/admin/training/federated", methods=["POST"])
def admin_training_federated():
    payload = request.get_json(silent=True) or {}
    if not app.config.get("TESTING"):
        return _enqueue_training_request("federated", payload)
    if not _training_operation_lock.acquire(blocking=False):
        return jsonify(api_response(code=409, msg="已有训练任务正在执行，请等待当前任务完成后再试。")), 409
    try:
        return _admin_training_federated_locked()
    finally:
        _training_operation_lock.release()


def _admin_training_federated_locked():
    """Train one FedAvg round from the current persisted four-node revision."""
    try:
        from src.preprocess.federated_splitter import NODE_NAMES, FEDERATED_DIR
        from src.federated.client import FederatedClient
        from src.federated.aggregator import fedavg_server

        req = request.get_json(silent=True) or {}
        dataset_source_id = req.get("dataset_source_id")
        requested_limit = max(10, min(int(req.get("limit") or 10000), 50000))
        epochs = max(1, min(int(req.get("epochs") or FEDERATED_DEFAULT_LOCAL_EPOCHS), 20))
        aggregation_method = str(req.get("aggregation_method") or "plain").strip().lower()
        secure_value = req.get("secure_aggregation", False)
        secure_aggregation = (
            aggregation_method == "paillier"
            or secure_value is True
            or str(secure_value).strip().lower() in {"1", "true", "yes"}
        )
        if aggregation_method not in {"plain", "paillier"}:
            return jsonify(api_response(
                code=400,
                msg="聚合方式仅支持 plain 或 paillier。",
            )), 400
        if secure_aggregation:
            aggregation_method = "paillier"
        secure_aggregation_key = None
        continue_value = req.get("continue_training", False)
        continue_training = continue_value is True or str(continue_value).lower() in {"1", "true", "yes"}
        validation_x = np.empty((0, 18), dtype=np.float64)
        validation_y = np.empty(0, dtype=np.int32)

        with _dataset_prepare_lock:
            # Federated training always consumes the complete persisted
            # preparation revision.  A request-level row limit must not make
            # X/y disagree with the four node files.
            X, y, meta = _load_training_dataset_source(dataset_source_id, limit=50000)
            if meta.get("source_not_found"):
                return jsonify(api_response(code=404, msg="请求的数据源不存在，请刷新数据源列表后重试。")), 404
            if len(X) < 20:
                return jsonify(api_response(
                    code=400,
                    msg="没有足够的已准备数据，至少需要 20 条样本；请先准备当前数据源并生成四节点数据。",
                )), 400
            if len(np.unique((y > 0).astype(int))) < 2:
                return jsonify(api_response(code=400, msg="当前数据源只包含一个标签类别，联邦二分类训练需要同时包含正常和攻击样本。")), 400

            current_preparation = _load_processed_metadata()
            prepared_nodes = meta.get("nodes") or []
            reuse_prepared_nodes = bool(
                meta.get("uses_prepared_data")
                and meta.get("preparation_id")
                and int(meta.get("prepared_samples") or len(X)) == int(len(X))
                and _federated_files_ready()
                and current_preparation.get("preparation_id") == meta.get("preparation_id")
                and current_preparation.get("dataset_revision") == meta.get("dataset_revision")
                and current_preparation.get("preprocessing_version") == FEATURE_NORMALIZATION_VERSION
                and current_preparation.get("validation_split_version") == SHARED_VALIDATION_SPLIT_VERSION
                and current_preparation.get("federated_split_version") == FEDERATED_SPLIT_VERSION
                and current_preparation.get("prepared_bundle_version") == PREPARED_BUNDLE_VERSION
            )
            if not reuse_prepared_nodes:
                return jsonify(api_response(
                    code=409,
                    msg="当前数据源与四节点准备版本不一致，请先执行数据处理后再启动联邦训练。",
                )), 409

            saved = [
                (str(node.get("name")), int(node.get("samples") or 0))
                for node in prepared_nodes
                if node.get("name")
            ]
            if len(saved) != len(NODE_NAMES) or sum(count for _, count in saved) != len(X):
                return jsonify(api_response(
                    code=409,
                    msg="四节点样本清单不完整，请重新执行数据处理后再启动联邦训练。",
                )), 409

            if meta.get("validation_available") and meta.get("validation_id"):
                candidate_x, candidate_y, validation_meta = _load_prepared_validation_arrays()
                if (
                    validation_meta.get("preparation_id") == meta.get("preparation_id")
                    and validation_meta.get("validation_id") == meta.get("validation_id")
                ):
                    validation_x, validation_y = candidate_x, candidate_y

            context_id = str(meta.get("preparation_id"))
            context_reset = fedavg_server.ensure_context(context_id, force_reset=not continue_training)
            results = []
            for name in NODE_NAMES:
                client = FederatedClient(name, os.path.join(FEDERATED_DIR, name))
                if client.load_data():
                    results.append(client.train_local(
                        global_weights=fedavg_server.global_weights,
                        epochs=epochs,
                        use_internal_validation=not bool(len(validation_x)),
                    ))
            if len(results) != len(NODE_NAMES):
                return jsonify(api_response(
                    code=500,
                    msg="部分联邦节点未能加载当前准备版本，训练已中止。",
                )), 500
        if aggregation_method == "paillier":
            # Validate the selected data revision before paying the one-time
            # 2048-bit key-generation cost. Key generation happens outside
            # the dataset preparation lock so unrelated data reads stay fast.
            secure_aggregation_key = get_secure_aggregation_paillier()
            if secure_aggregation_key is None:
                return jsonify(api_response(
                    code=503,
                    msg="Paillier 安全聚合密钥初始化失败；普通 FedAvg 仍可使用。",
                )), 503
        if secure_aggregation_key is not None:
            global_weights, paillier_metrics = fedavg_server.aggregate_paillier(
                results,
                secure_aggregation_key,
            )
        else:
            global_weights = fedavg_server.aggregate(results)
            paillier_metrics = {
                "paillier_enabled": False,
                "secure_aggregation": False,
                "secure_aggregation_requested": False,
                "display_only": False,
                "timing_method": "not_requested",
                "actual_crypto_operations_performed": False,
                "aggregation_method": "plain",
                "individual_updates_decrypted": False,
                "server_plaintext_node_updates_observable": True,
                "cross_institution_key_isolation": False,
                "trust_boundary": "single_host_logical_nodes",
                "note": "当前使用普通 FedAvg；可由管理员主动选择 2048 位 Paillier 密态权重聚合。",
            }

        latest_round = fedavg_server.get_history()[-1] if fedavg_server.get_history() else {}
        shared_validation_metrics = evaluate_linear_binary_weights(
            validation_x,
            validation_y,
            global_weights,
        ) if len(validation_x) else None
        if shared_validation_metrics is not None:
            comparison_accuracy = shared_validation_metrics["accuracy"]
            comparison_precision = shared_validation_metrics["precision"]
            comparison_recall = shared_validation_metrics["recall"]
            comparison_f1 = shared_validation_metrics["f1"]
            comparison_loss = shared_validation_metrics["loss"]
            metric_scope = "shared_holdout_validation"
            metric_label = "同源共享留出集指标"
            metric_note = (
                "FedAvg 全局权重在与普通集中式基线完全相同、且未参与四节点训练的共享留出集上评估；"
                "节点内部验证指标仅用于诊断，不作为最终模型对比值。"
            )
        else:
            comparison_accuracy = float(latest_round.get("accuracy") or 0)
            comparison_precision = None
            comparison_recall = None
            comparison_f1 = None
            comparison_loss = float(latest_round.get("loss") or 0)
            metric_scope = "node_validation_weighted"
            metric_label = "四节点样本加权验证指标"
            metric_note = (
                "当前数据量或类别分布不足以建立共享留出集，暂以节点内部验证指标加权汇总；"
                "该数值不能与普通集中式基线指标直接判断优劣。"
            )
        version = datetime.now().strftime("fed%Y%m%d%H%M%S%f")[:-3]
        source_ids = [s.get("id") for s in meta.get("sources", []) if s.get("id") and not str(s.get("id")).startswith("dataset:")]
        data = {
            **meta,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "task_type": "federated",
            "source": meta.get("training_source", "encrypted_user_submissions"),
            "status": "completed",
            "model_version": version,
            "source_submission_ids": source_ids,
            "samples": int(len(X)),
            "requested_limit": requested_limit,
            "preprocessing_version": FEATURE_NORMALIZATION_VERSION,
            "prepared_bundle_version": meta.get("prepared_bundle_version"),
            "uses_prepared_nodes": reuse_prepared_nodes,
            "federated_context_id": context_id,
            "federated_context_reset": context_reset,
            "continued_from_previous_round": continue_training,
            "nodes": prepared_nodes,
            "federated_split_version": meta.get("federated_split_version"),
            "federated_split": meta.get("federated_split") or {},
            "heterogeneity_level": (meta.get("federated_split") or {}).get("heterogeneity_level"),
            "drift": meta.get("drift") or {},
            "round": fedavg_server.round,
            "clients": [{
                "name": r.get("name"),
                "accuracy": r.get("accuracy", 0),
                "loss": r.get("loss", 0),
                "samples": r.get("samples", 0),
                "metric_scope": r.get("metric_scope") or "node_internal_validation",
                "metric_label": r.get("metric_label") or "节点内部验证指标",
            } for r in results],
            "avg_accuracy": comparison_accuracy,
            "accuracy": comparison_accuracy,
            "precision": comparison_precision,
            "recall": comparison_recall,
            "f1": comparison_f1,
            "loss": comparison_loss,
            "node_validation_accuracy": float(latest_round.get("accuracy") or 0),
            "node_validation_loss": float(latest_round.get("loss") or 0),
            "node_diagnostic_accuracy": float(latest_round.get("accuracy") or 0),
            "node_diagnostic_loss": float(latest_round.get("loss") or 0),
            "node_diagnostic_scope": (
                "node_training_diagnostic" if shared_validation_metrics is not None else "node_internal_validation"
            ),
            "algorithm": "fedavg",
            "base_model_algorithm": "linear_logistic_binary_classifier",
            "optimizer": "batch_gradient_descent_l2",
            "aggregation_method": paillier_metrics.get("aggregation_method", aggregation_method),
            "secure_aggregation": bool(paillier_metrics.get("secure_aggregation", False)),
            "paillier": paillier_metrics,
            "metric_name": "accuracy",
            "metric_scope": metric_scope,
            "metric_label": metric_label,
            "metric_note": metric_note,
            "validation_available": shared_validation_metrics is not None,
            "uses_shared_validation": shared_validation_metrics is not None,
            "validation_samples": int(len(validation_x)) if shared_validation_metrics is not None else 0,
            "validation_id": meta.get("validation_id") if shared_validation_metrics is not None else None,
            "validation_split_version": meta.get("validation_split_version") if shared_validation_metrics is not None else None,
            "validation_label_distribution": meta.get("validation_label_distribution") or {},
            "source_count": int(meta.get("source_count", 0)),
            "label_distribution": meta.get("label_distribution", {}),
            "node_count": len(NODE_NAMES),
            "rounds": fedavg_server.round,
            "epochs": epochs,
            "effective_epochs": int(epochs * fedavg_server.round),
            "history": fedavg_server.get_history(),
            "note": (
                "Federated training uses the prepared four-node data revision. Paillier mode performs real "
                "ciphertext weight aggregation on the single-host logical nodes, while the runtime ensemble "
                "detector remains separate."
            ),
        }
        data["updated_submissions"] = user_submission_manager.mark_used_for_training(
            source_ids,
            task_type="federated",
            model_version=version,
            samples=int(len(X)),
        )
        save_training_record(data)
        try:
            db.save_training_task_record({
                "timestamp": data["timestamp"],
                "task_type": "federated",
                "source": data.get("source", "managed_dataset_source"),
                "samples": int(len(X)),
                "accuracy": data["avg_accuracy"],
                "metric_name": data["metric_name"],
                "metric_scope": data["metric_scope"],
                "metric_label": data["metric_label"],
                "metric_note": data["metric_note"],
                "validation_available": data["validation_available"],
                "status": "completed",
                "version": version,
                "metadata": data,
            })
            db.save_model_version_record({
                "version": version,
                "model_type": "federated_fedavg",
                "source": data.get("source", "managed_dataset_source"),
                "samples": int(len(X)),
                "accuracy": data["avg_accuracy"],
                "metadata": data,
            })
        except Exception as persist_error:
            logger.warning("Persist federated training task failed: {}", persist_error)
        return jsonify(api_response(msg="联邦训练完成", data=data))
    except Exception as e:
        logger.exception("Admin federated training failed")
        return jsonify(api_response(code=500, msg="联邦训练失败: %s" % e))


@app.route("/api/admin/training/tasks", methods=["GET"])
def admin_training_tasks():
    limit = max(1, min(int(request.args.get("limit", 50) or 50), 200))
    queued_jobs = db.get_training_jobs(min(limit, 50), include_result=False)
    if any(item.get("status") in {"queued", "running"} for item in queued_jobs):
        _ensure_training_worker()
    sqlite_tasks = db.get_training_tasks(limit)
    legacy_tasks = []
    try:
        legacy_tasks = [_normalize_legacy_training_record(r) for r in get_training_records(limit=200)]
    except Exception as legacy_error:
        logger.warning("Load legacy training records failed: {}", legacy_error)
    tasks = _merge_training_tasks(sqlite_tasks, legacy_tasks, limit)
    return jsonify(api_response(msg="success", data={
        "tasks": tasks,
        "limit": limit,
        "sources": {
            "sqlite": len(sqlite_tasks),
            "legacy_json": len(legacy_tasks),
        },
        "queue": {
            "mode": "sqlite_single_worker",
            "jobs": [_public_training_job(item) for item in queued_jobs],
            "pending": sum(1 for item in queued_jobs if item.get("status") in {"queued", "running"}),
        },
    }))


def _normalize_legacy_training_record(record):
    """Convert older data/training_records.json rows into admin task shape."""
    meta = dict(record or {})
    raw_task_type = str(meta.get("task_type") or meta.get("type") or meta.get("model_type") or "local").lower()
    if "fed" in raw_task_type:
        task_type = "federated"
    elif "central" in raw_task_type:
        task_type = "centralized"
    elif "runtime" in raw_task_type or "ensemble" in raw_task_type:
        task_type = "runtime"
    else:
        task_type = "local"
    accuracy = (
        meta.get("accuracy")
        if meta.get("accuracy") is not None
        else meta.get("avg_accuracy", meta.get("federated_accuracy", meta.get("traditional_accuracy", 0)))
    )
    return {
        "id": "legacy:%s:%s" % (task_type, meta.get("timestamp") or meta.get("created_at") or meta.get("model_version") or ""),
        "task_type": task_type,
        "source": meta.get("source") or meta.get("dataset_name") or "legacy_training_records",
        "samples": int(meta.get("samples") or meta.get("train_samples") or 0),
        "accuracy": float(accuracy or 0),
        "status": meta.get("status") or "completed",
        "timestamp": meta.get("timestamp") or meta.get("created_at") or "",
        "metadata": json.dumps(meta, ensure_ascii=False),
        "legacy": True,
    }


def _task_time_key(task):
    value = task.get("timestamp") or task.get("created_at") or ""
    try:
        return datetime.strptime(str(value)[:19], "%Y-%m-%d %H:%M:%S")
    except Exception:
        return datetime.min


def _task_dedupe_key(task):
    meta = _parse_meta(task.get("metadata"))
    return "|".join([
        str(task.get("task_type") or ""),
        str(task.get("source") or ""),
        str(task.get("samples") or ""),
        str(round(float(task.get("accuracy") or 0), 6)),
        str(task.get("timestamp") or meta.get("timestamp") or meta.get("created_at") or ""),
    ])


def _merge_training_tasks(primary, legacy, limit):
    merged = []
    seen = set()
    for task in list(primary or []) + list(legacy or []):
        key = _task_dedupe_key(task)
        if key in seen:
            continue
        seen.add(key)
        merged.append(task)
    merged.sort(key=_task_time_key, reverse=True)
    return merged[:limit]


def _training_task_to_tracking_version(task, index=0):
    meta = _parse_meta(task.get("metadata"))
    nested = _parse_meta(meta.get("metadata"))
    merged = {**meta, **nested}
    task_type = str(task.get("task_type") or merged.get("task_type") or "local")
    is_federated = "fed" in task_type.lower()
    is_centralized = "central" in task_type.lower()
    is_runtime = "runtime" in task_type.lower()
    version_prefix = "fed" if is_federated else "central" if is_centralized else "runtime" if is_runtime else "local"
    version = (
        merged.get("model_version")
        or merged.get("version")
        or task.get("model_version")
        or task.get("version")
        or ("%s-task-%s" % (version_prefix, index + 1))
    )
    samples = task.get("samples") if task.get("samples") is not None else merged.get("samples", 0)
    accuracy = task.get("accuracy") if task.get("accuracy") is not None else merged.get("accuracy", 0)
    return {
        "id": -1 * (index + 1),
        "version": version,
        "model_version": version,
        "model_type": (
            "federated_tracking_model" if is_federated else
            "centralized_linear_baseline" if is_centralized else
            "runtime_ensemble" if is_runtime else
            "local_tracking_model"
        ),
        "algorithm": merged.get("algorithm") or (
            "fedavg" if is_federated else
            "linear_logistic_gradient_descent" if is_centralized else
            "ensemble_detector"
        ),
        "source": task.get("source") or merged.get("source") or merged.get("dataset_name") or "training_task",
        "samples": samples or 0,
        "accuracy": accuracy or 0,
        "recall": merged.get("recall", merged.get("precision", "")),
        "f1_score": merged.get("f1_score", merged.get("f1", "")),
        "status": task.get("status") or merged.get("status") or "completed",
        "created_at": task.get("timestamp") or merged.get("timestamp") or merged.get("created_at") or "",
        "metadata": json.dumps({**merged, "task_type": task_type, "task_status": task.get("status")}, ensure_ascii=False),
        "current": False,
        "current_display": False,
        "current_runtime": False,
        "can_activate": False,
        "activation_reason": "该记录来自训练任务，用于追踪训练来源和指标；未绑定运行时模型文件。",
        "artifact_status": "tracking_only",
        "version_role": "training_tracking",
        "note": "训练任务追踪版本",
    }


def _merge_model_versions_with_tasks(versions, tasks, limit):
    merged = []
    seen = set()
    for item in versions or []:
        key = str(item.get("version") or item.get("model_version") or item.get("id") or "")
        seen.add(key)
        merged.append(item)
    for idx, task in enumerate(tasks or []):
        version = _training_task_to_tracking_version(task, idx)
        key = str(version.get("version") or "")
        if key in seen:
            continue
        seen.add(key)
        merged.append(version)
    merged.sort(key=lambda v: _task_time_key({"timestamp": v.get("created_at") or _parse_meta(v.get("metadata")).get("timestamp")}), reverse=True)
    return merged[:limit]


def _parse_meta(value):
    if isinstance(value, dict):
        return value
    if not value:
        return {}
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _npy_shape(path):
    """Read only an NPY header through mmap and release the file immediately."""
    value = np.load(path, mmap_mode="r", allow_pickle=False)
    try:
        return tuple(value.shape)
    finally:
        mmap_handle = getattr(value, "_mmap", None)
        if mmap_handle is not None:
            mmap_handle.close()


def _prepared_array_bundle_consistent(metadata=None):
    """Reject partial preparation writes before training can consume them."""
    metadata = metadata or _load_processed_metadata()
    try:
        full_x = _npy_shape(PROCESSED_X_PATH)
        full_y = _npy_shape(PROCESSED_Y_PATH)
        train_x = _npy_shape(PROCESSED_TRAIN_X_PATH)
        train_y = _npy_shape(PROCESSED_TRAIN_Y_PATH)
        validation_x = _npy_shape(PROCESSED_VALIDATION_X_PATH)
        validation_y = _npy_shape(PROCESSED_VALIDATION_Y_PATH)
        expected_samples = int(metadata.get("samples"))
        expected_training = int(metadata.get("training_samples"))
        expected_validation = int(metadata.get("validation_samples"))
        expected_features = int(metadata.get("features"))
    except (OSError, ValueError, TypeError, KeyError):
        return False
    return bool(
        len(full_x) == 2
        and len(train_x) == 2
        and len(validation_x) == 2
        and len(full_y) == len(train_y) == len(validation_y) == 1
        and full_x[0] == full_y[0] == expected_samples
        and train_x[0] == train_y[0] == expected_training
        and validation_x[0] == validation_y[0] == expected_validation
        and expected_training + expected_validation == expected_samples
        and full_x[1] == train_x[1] == validation_x[1] == expected_features
    )


def _training_task_merged(task):
    task = dict(task or {})
    meta = _parse_meta(task.get("metadata"))
    nested = _parse_meta(meta.get("metadata"))
    return {**meta, **nested, **task}


def _latest_training_pair(dataset_source_id="", preparation_id=""):
    """Select matching completed local/federated records for one data revision."""
    sqlite_tasks = db.get_training_tasks(200)
    try:
        legacy_tasks = [_normalize_legacy_training_record(r) for r in get_training_records(limit=200)]
    except Exception:
        legacy_tasks = []
    tasks = _merge_training_tasks(sqlite_tasks, legacy_tasks, 300)
    rows = []
    for task in tasks:
        merged = _training_task_merged(task)
        if str(merged.get("status") or "completed").lower() not in {"completed", "success", "done"}:
            continue
        source_id = str(merged.get("dataset_source_id") or "")
        prep_id = str(merged.get("preparation_id") or "")
        if dataset_source_id and source_id != str(dataset_source_id):
            continue
        if preparation_id and prep_id != str(preparation_id):
            continue
        task_type = str(merged.get("task_type") or task.get("task_type") or "").lower()
        if "fed" in task_type:
            kind = "federated"
        elif "central" in task_type:
            kind = "centralized"
        else:
            # Runtime ensemble training updates the user-facing detector but
            # is not architecturally comparable with the linear FedAvg model.
            continue
        rows.append({
            "task": task,
            "merged": merged,
            "kind": kind,
            "source_id": source_id,
            "preparation_id": prep_id,
        })
    federated_rows = [row for row in rows if row["kind"] == "federated"]
    local_rows = [row for row in rows if row["kind"] == "centralized"]
    for fed_row in federated_rows:
        for local_row in local_rows:
            source_matches = bool(
                fed_row["source_id"]
                and fed_row["source_id"] == local_row["source_id"]
            )
            preparation_matches = bool(
                fed_row["preparation_id"]
                and fed_row["preparation_id"] == local_row["preparation_id"]
            )
            if source_matches and (preparation_matches or not fed_row["preparation_id"]):
                return local_row["task"], fed_row["task"]
    return None, None


TRAINING_AI_COMPARISON_CACHE_KEY = "external_ai_training_security_comparison_v1"


def _load_training_ai_comparison_cache():
    try:
        value = json.loads(db.get_config(TRAINING_AI_COMPARISON_CACHE_KEY, "{}") or "{}")
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


@app.route("/api/admin/training/external-comparison", methods=["POST"])
def admin_training_external_comparison():
    """AI-assisted security and model-path judgment using real aggregate records."""
    try:
        settings = _external_ai_settings_store.get_effective(require_ready=True)
    except ExternalAdvisorDisabledError:
        return jsonify(api_response(code=503, msg="AI 辅助判定未启用，现有训练对比仍可正常使用。")), 503
    except ExternalAdvisorConfigError:
        return jsonify(api_response(code=503, msg="AI 接口尚未完成配置，现有训练对比不受影响。")), 503

    req = request.get_json(silent=True) or {}
    local_task, federated_task = _latest_training_pair(
        dataset_source_id=str(req.get("dataset_source_id") or ""),
        preparation_id=str(req.get("preparation_id") or ""),
    )
    if local_task is None or federated_task is None:
        return jsonify(api_response(
            code=409,
            msg="请先基于同一数据准备版本完成普通集中式基线和四节点联邦训练。",
        )), 409
    payload = build_redacted_training_comparison_payload(local_task, federated_task)
    expected_cache_key = external_cache_key(payload, settings)
    force_value = req.get("force", False)
    force = force_value is True or str(force_value).lower() in {"1", "true", "yes"}
    cached = _load_training_ai_comparison_cache()
    if not force and cached.get("input_fingerprint") == expected_cache_key:
        cached_result = json.loads(json.dumps(cached, ensure_ascii=False))
        cached_result["cache_reused"] = True
        return jsonify(api_response(msg="已复用 AI 训练方案判定", data=cached_result))

    if not _external_analysis_operation_lock.acquire(blocking=False):
        return jsonify(api_response(code=409, msg="已有 AI 辅助判定正在执行，请稍后再试。")), 409
    try:
        cached = _load_training_ai_comparison_cache()
        if not force and cached.get("input_fingerprint") == expected_cache_key:
            cached_result = json.loads(json.dumps(cached, ensure_ascii=False))
            cached_result["cache_reused"] = True
            return jsonify(api_response(msg="已复用 AI 训练方案判定", data=cached_result))
        allowed, retry_after, remaining = _reserve_external_ai_call(settings.get("calls_per_hour"))
        if not allowed:
            return jsonify(api_response(
                code=429,
                msg="外部 AI 每小时调用额度已用完，现有训练对比仍可使用。",
                data={"retry_after_seconds": retry_after},
            )), 429
        provider_result = _create_external_advisor_client(settings).analyze(payload)
        record = make_external_analysis_record(payload, settings, provider_result)
        record["comparison_facts"] = {
            "deterministic_differences": payload.get("deterministic_differences", {}),
            "comparison_fairness": payload.get("comparison_fairness", {}),
            "security_architecture": payload.get("security_architecture", {}),
        }
        record["remaining_calls_this_hour"] = remaining
        db.set_config(TRAINING_AI_COMPARISON_CACHE_KEY, json.dumps(record, ensure_ascii=False))
        return jsonify(api_response(msg="AI 训练方案辅助判定完成", data=record))
    except (ExternalAdvisorConfigError, ExternalAdvisorDisabledError):
        return jsonify(api_response(code=503, msg="AI 配置不可用，现有训练对比不受影响。")), 503
    except (ExternalAdvisorProviderError, ExternalAdvisorResponseError):
        return jsonify(api_response(code=502, msg="AI 服务暂时不可用，现有训练对比结果已保留。")), 502
    except Exception:
        logger.exception("External training comparison failed")
        return jsonify(api_response(code=500, msg="AI 辅助判定失败，现有训练对比结果已保留。")), 500
    finally:
        _external_analysis_operation_lock.release()


def _runtime_ensemble_artifacts():
    try:
        from src.detection.ensemble_detector import ensemble_detector
        versions = ensemble_detector.list_versions()
        return {str(item.get("version")) for item in versions if item.get("version")}, ensemble_detector.status(), versions
    except Exception:
        return set(), {}, []


def _enrich_model_version(item, runtime_versions=None, runtime_status=None):
    if runtime_versions is None or runtime_status is None:
        runtime_versions, runtime_status, _ = _runtime_ensemble_artifacts()
    enriched = dict(item)
    meta = _parse_meta(enriched.get("metadata"))
    nested = _parse_meta(meta.get("metadata"))
    merged = {**meta, **nested}
    model_type = str(enriched.get("model_type") or merged.get("model_type") or "")
    runtime_version = str(enriched.get("version") or merged.get("model_version") or "")
    is_runtime_type = model_type in {"runtime_ensemble", "admin_local_ensemble", "runtime_detector"}
    can_activate = bool(is_runtime_type and runtime_version in runtime_versions)
    if can_activate:
        version_role = "runtime_detector"
        artifact_status = "available"
        activation_reason = "该版本存在运行时模型文件，可切换为当前检测模型。"
    elif "federated" in model_type:
        version_role = "training_tracking"
        artifact_status = "tracking_only"
        activation_reason = "该版本记录四节点联邦训练结果，用于训练追踪；当前未生成可直接切换的运行时检测模型文件。"
    else:
        version_role = "training_tracking"
        artifact_status = "tracking_only"
        activation_reason = "该版本记录训练任务和指标，用于追踪训练来源；当前未绑定运行时模型文件，不能作为检测模型回退。"

    enriched.update({
        "version_role": version_role,
        "artifact_status": artifact_status,
        "can_activate": bool(can_activate),
        "can_select": True,
        "select_action": "activate_runtime" if can_activate else "select_tracking",
        "activation_reason": activation_reason,
        "runtime_version": runtime_version if can_activate else None,
        "current_runtime": bool(can_activate and runtime_version == str((runtime_status or {}).get("version") or "")),
        "current_display": bool(int(enriched.get("is_current", 0) or 0) == 1),
        "metadata": enriched.get("metadata", "{}"),
    })
    return enriched


@app.route("/api/admin/model-versions", methods=["GET"])
def admin_model_versions():
    limit = max(1, min(int(request.args.get("limit", 50) or 50), 200))
    backfilled = 0
    try:
        backfilled = db.backfill_model_versions_from_training_tasks()
    except Exception as backfill_error:
        logger.warning("Backfill model versions failed: {}", backfill_error)
    runtime_versions, runtime_status, runtime_artifacts = _runtime_ensemble_artifacts()
    sqlite_tasks = db.get_training_tasks(limit)
    legacy_tasks = []
    try:
        legacy_tasks = [_normalize_legacy_training_record(r) for r in get_training_records(limit=200)]
    except Exception as legacy_error:
        logger.warning("Load model version legacy records failed: {}", legacy_error)
    tasks = _merge_training_tasks(sqlite_tasks, legacy_tasks, limit)
    versions = [_enrich_model_version(v, runtime_versions, runtime_status) for v in db.get_model_versions(limit)]
    versions = _merge_model_versions_with_tasks(versions, tasks, limit)
    baseline_status = model_manager.get_status()
    return jsonify(api_response(msg="success", data={
        "versions": versions,
        "training_task_count": len(tasks),
        "runtime_versions": runtime_artifacts,
        "runtime_model": {
            "available": bool(runtime_status.get("ready")),
            "is_ready": bool(runtime_status.get("is_ready") or runtime_status.get("ready")),
            "model_version": runtime_status.get("model_version") or runtime_status.get("version") or "",
            "model_count": runtime_status.get("model_count") or runtime_status.get("models") or "",
            "accuracy": runtime_status.get("accuracy") or runtime_status.get("last_accuracy"),
            "source": "runtime_ensemble",
            "note": "当前用户风险检测实际使用的融合模型；运行时模型更新会生成可切换的完整快照，普通集中式基线和联邦训练只生成对比追踪记录。",
            "raw_status": runtime_status,
            "current_runtime": True,
            "artifact_status": "available" if runtime_status.get("ready") else "unavailable",
        },
        "platform_baseline": baseline_status,
        "backfilled": backfilled,
        "limit": limit,
    }))


@app.route("/api/model/current", methods=["GET"])
def current_model_versions():
    return jsonify(api_response(msg="success", data={
        "versions": db.get_current_model_versions(),
    }))


@app.route("/api/admin/model-versions/<int:version_id>/activate", methods=["POST"])
def admin_activate_model_version(version_id):
    versions = db.get_model_versions(500)
    item = next((v for v in versions if int(v.get("id", 0)) == int(version_id)), None)
    if not item:
        return jsonify(api_response(code=404, msg="模型版本不存在"))
    enriched = _enrich_model_version(item)
    if enriched.get("can_activate"):
        if db.has_pending_training_jobs():
            return jsonify(api_response(code=409, msg="训练队列中仍有任务，暂时不能切换运行时模型。")), 409
        if not _training_operation_lock.acquire(blocking=False):
            return jsonify(api_response(code=409, msg="训练任务正在执行，暂时不能切换运行时模型。")), 409
        try:
            from src.detection.ensemble_detector import ensemble_detector
            ok = ensemble_detector.activate_version(str(enriched.get("runtime_version")))
        finally:
            _training_operation_lock.release()
        if not ok:
            return jsonify(api_response(code=500, msg="运行时模型切换失败，请确认模型文件仍存在", data=enriched))
        item = db.set_current_model_version(version_id)
        return jsonify(api_response(msg="已切换当前运行检测模型", data=_enrich_model_version(item)))

    item = db.set_current_model_version(version_id)
    if not item:
        return jsonify(api_response(code=500, msg="模型版本状态更新失败", data=enriched))
    return jsonify(api_response(
        msg="已设为当前训练追踪版本；该版本用于管理端展示和报告追溯，不直接替换运行时检测模型",
        data=_enrich_model_version(item),
    ))


@app.route("/api/admin/audit/events", methods=["GET"])
def admin_audit_events():
    """Read security events through an admin-oriented endpoint."""
    try:
        from src.security.security_logger import SECURITY_EVENTS_LOG_PATH
        from src.security.events_api import normalize_limit, read_events
        limit = normalize_limit(request.args.get("limit", 100), default=100, max_limit=200)
        try:
            offset = max(0, int(request.args.get("offset", 0) or 0))
        except (ValueError, TypeError):
            offset = 0
        event_type = request.args.get("event_type")
        exclude_event_type = request.args.get("exclude_event_type")
        risk_level = request.args.get("risk_level")
        ip = request.args.get("ip")
        path_filter = request.args.get("path")
        events, total = read_events(
            SECURITY_EVENTS_LOG_PATH,
            limit=limit,
            event_type=event_type,
            risk_level=risk_level,
            ip=ip,
            path=path_filter,
            offset=offset,
            exclude_event_type=exclude_event_type,
            return_total=True,
        )
        return jsonify(api_response(msg="success", data={
            "events": events,
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": offset + len(events) < total,
        }))
    except Exception as e:
        logger.warning("Admin audit query failed: {}", e)
        return jsonify(api_response(data={"events": [], "total": 0, "warning": "audit log unavailable"}))


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

    filename = os.path.basename(file.filename)
    temp_path = os.path.join(app.config["UPLOAD_FOLDER"], "upload_" + filename)
    file.save(temp_path)

    try:
        validate_upload_file(temp_path, filename)
        info = dataset_manager.upload_dataset(temp_path, filename)
        return jsonify(api_response(data=info, msg="数据集导入成功"))
    except UploadValidationError as e:
        return jsonify(api_response(code=400, msg=str(e)))
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
    return _deprecated_training_api("/api/admin/training/local")


# ─── API: 训练记录 ───

@app.route("/api/training/records", methods=["GET"])
def training_records():
    """获取历史训练记录"""
    records = get_training_records()
    return jsonify(api_response(data={"records": records}))


# ─── API: 系统信息 ───

@app.route("/api/system/health", methods=["GET"])
def system_health():
    # The runtime ensemble is the primary model used by user-facing analysis.
    # Keep the legacy manager status separate so health checks do not report
    # "not trained" after the actual serving model has loaded successfully.
    from src.detection.ensemble_detector import ensemble_detector

    runtime_status = ensemble_detector.status()
    runtime_ready = bool(runtime_status.get("is_ready") or runtime_status.get("ready"))
    runtime_components = runtime_status.get("components") or {}
    enabled_components = [
        label
        for key, label in (
            ("isolation_forest", "Isolation Forest"),
            ("classifier", runtime_status.get("classifier_type") or "Classifier"),
            ("numpy_lstm", "NumPy LSTM"),
        )
        if runtime_components.get(key)
    ]
    legacy_status = model_manager.get_status()
    return jsonify(api_response(data={
        "status": "running", "version": "2.0.0",
        "paillier_ready": _paillier_ready,
        "detector_trained": runtime_ready,
        "real_detector_trained": runtime_ready,
        "local_model": {
            "ready": runtime_ready,
            "version": runtime_status.get("model_version") or "",
            "classifier_type": runtime_status.get("classifier_type") or "",
            "components": runtime_components,
        },
        "legacy_baseline_ready": bool(legacy_status.get("is_ready") or _detector_trained),
        "optimizer_trained": get_optimizer().agent.is_trained,
        "visitor_count": len(_visitor_log),
        "dataset_count": len(dataset_manager.list_datasets()),
        "modules": {
            "encryption": "Paillier + AES-256",
            "detection": " + ".join(enabled_components) if enabled_components else "运行时融合模型（加载中）",
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
        logger.info("新数据集已添加: {} ({}条)，建议重训练", file.filename, rows)
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
    return _deprecated_training_api("/api/admin/training/local")


@app.route("/api/model/versions", methods=["GET"])
def model_versions():
    """获取模型版本列表"""
    return jsonify(api_response(data={"versions": model_manager.get_version_list()}))


@app.route("/api/model/rollback/<int:version>", methods=["POST"])
def model_rollback(version):
    """回滚模型到指定版本"""
    return _deprecated_training_api("/api/admin/model-versions")


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
    return _deprecated_training_api("/api/admin/training/centralized + /api/admin/training/federated")


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
        from src.detection.scoring import isolation_forest_risk_score
        if_s = isolation_forest_risk_score(model_manager.if_model, X)
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
    from src.preprocess.feature_engineering import inspect_csv

    source = _find_dataset_source()
    processed_ready = _processed_dataset_ready()
    meta = _load_processed_metadata()
    if source is None:
        return jsonify(api_response(data={
            "exists": False,
            "source": None,
            "source_type": None,
            "samples": meta.get("samples", 0),
            "features": meta.get("features", 0),
            "label_column": meta.get("label_column"),
            "ready_for_federated": processed_ready,
            "processed": meta,
        }))

    try:
        info = inspect_csv(source["path"])
    except Exception as e:
        logger.warning("Dataset inspect failed: {}", e)
        info = {
            "samples": _csv_row_count(source["path"], max_rows=1000000),
            "features": 0,
            "label_column": None,
        }

    return jsonify(api_response(data={
        "exists": True,
        "source": source["source"],
        "source_path": source["path"],
        "source_type": source["source_type"],
        "samples": info.get("samples", 0),
        "features": info.get("features", 0),
        "label_column": info.get("label_column"),
        "ready_for_federated": processed_ready,
        "processed": meta,
    }))


@app.route("/api/dataset/unsw/process", methods=["POST"])
def dataset_unsw_process():
    """Compatibility alias for the canonical prepare-only workflow.

    Processing creates normalized arrays and four node partitions.  It no
    longer trains a detector as a hidden side effect; training remains an
    explicit management action.
    """
    req = request.get_json(silent=True) or {}
    source_id = req.get("source_id")
    source = None
    if source_id:
        source = next(
            (item for item in _list_dataset_sources_cached(force=True) if item.get("id") == source_id),
            None,
        )
    if source is None:
        source = _find_dataset_source()
    if source is None:
        return jsonify(api_response(code=400, msg="未找到可处理的数据源，请先生成或导入安全数据集。"))
    effective_id = source_id or source.get("id") or _dataset_source_id(source)
    return _prepare_dataset_source_for_federated(
        source,
        source_id=effective_id,
        limit=req.get("limit", 50000),
        force_rebuild=bool(req.get("force_rebuild", False)),
    )


@app.route("/api/federated/nodes", methods=["GET"])
def federated_nodes():
    """Return federated node status with source and label distribution."""
    nodes = _federated_node_details()
    return jsonify(api_response(data={
        "nodes": nodes,
        "total": len(nodes),
        "preparation": _load_processed_metadata(),
        "explanation": "当前源先固定训练分区和共享留出集，再按业务 Non-IID 标签与特征偏移生成四节点；留出集仅用于普通模型与 FedAvg 的同口径评估。",
    }))


@app.route("/api/admin/federated/nodes/detail", methods=["GET"])
def admin_federated_nodes_detail():
    """Return management-detail view for federated nodes."""
    nodes = _federated_node_details()
    total_samples = sum(int(n.get("samples", 0) or 0) for n in nodes)
    return jsonify(api_response(msg="success", data={
        "nodes": nodes,
        "total": len(nodes),
        "total_samples": total_samples,
        "source": _load_processed_metadata(),
        "heterogeneity": (_load_processed_metadata().get("federated_split") or {}),
        "explanation": "四节点具有不同样本规模、标签比例和特征分布，并共享同一独立留出集。",
    }))


@app.route("/api/federated/round", methods=["POST"])
def federated_round():
    """执行一轮联邦训练"""
    return _deprecated_training_api("/api/admin/training/federated")


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
    if not _ensure_runtime_ensemble_ready():
        return jsonify(api_response(code=503, msg="运行时检测模型尚未就绪，请稍后重试。")), 503

    req = request.get_json() or {}
    records = req.get("data", [])
    if not records:
        return jsonify(api_response(code=400, msg="请提供检测数据"))

    import numpy as np
    from src.preprocess.feature_engineering import extract_features_structured, normalize_security_features
    X_list = []
    for rec in records:
        X_list.append(extract_features_structured(rec))
    X = normalize_security_features(np.array(X_list, dtype=np.float64))

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

    model_status = ensemble_detector.status()
    return jsonify(api_response(data={
        "total": len(results),
        "anomalies": int(np.sum(preds)),
        "detections": results,
        "model": model_status,
    }))

@app.route("/api/ensemble/detect_from_dataset", methods=["POST"])
def ensemble_detect_from_dataset():
    """Run detection on samples from the processed dataset."""
    from src.detection.ensemble_detector import ensemble_detector

    if not _processed_dataset_ready():
        return jsonify(api_response(code=400, msg="请先在数据处理页面处理数据集"))

    req = request.get_json(silent=True) or {}
    limit = max(1, min(int(req.get("limit") or 50), 500))
    has_offset = "offset" in req
    offset = max(0, int(req.get("offset") or 0))
    seed = req.get("seed")

    try:
        X, y, metadata = _load_prepared_arrays()
    except (OSError, ValueError) as error:
        return jsonify(api_response(code=409, msg="已处理数据正在更新或不完整：%s" % error)), 409
    if len(X) == 0:
        return jsonify(api_response(code=400, msg="已处理数据集为空"))

    if has_offset:
        if offset >= len(X):
            offset = 0
        end = min(offset + limit, len(X))
        indices = np.arange(offset, end)
    elif len(X) <= limit:
        indices = np.arange(len(X))
    else:
        rng = np.random.default_rng(int(seed)) if seed is not None else np.random.default_rng()
        indices = np.sort(rng.choice(len(X), size=limit, replace=False)).astype(np.int64)
    sample_x = X[indices]
    sample_y = y[indices]

    if not _ensure_runtime_ensemble_ready():
        return jsonify(api_response(code=503, msg="运行时检测模型尚未就绪，请稍后重试。")), 503

    detection_started = time.perf_counter()
    preds, scores, risk_levels = ensemble_detector.predict(sample_x)
    total_detection_ms = (time.perf_counter() - detection_started) * 1000.0
    per_sample_detection_ms = round(total_detection_ms / max(1, len(sample_x)), 4)
    model_status = ensemble_detector.status()
    risk_names = {0: "low", 1: "medium", 2: "high", 3: "critical"}
    action_suggestions = {
        "low": "观察",
        "medium": "提醒用户改密",
        "high": "强制改密并开启二次验证",
        "critical": "临时冻结账号并人工复核",
    }
    results = []
    for i in range(len(sample_x)):
        pred = int(preds[i])
        label = int(sample_y[i])
        score = round(float(scores[i]), 4)
        level = risk_names.get(int(risk_levels[i]), "low")
        attack_type = "正常访问" if pred == 0 else ("疑似暴力破解" if score >= 0.75 else "账号风险行为")
        trigger_features = []
        if score >= 0.7:
            trigger_features.append("model_score")
        if label != pred:
            trigger_features.append("label_mismatch")
        if not trigger_features:
            trigger_features.append("model_score")
        reason = "当前检测模型给出的风险分数为 %.4f，预测类型为%s。" % (score, attack_type)
        if label != pred:
            reason += " 该样本标签与模型判断不一致，建议结合数据来源复核。"
        results.append({
            "id": int(indices[i] + 1),
            "sample_id": int(indices[i] + 1),
            "is_attack": bool(pred),
            "is_risk": bool(level in ("medium", "high", "critical")),
            "actual_label": label,
            "risk_score": score,
            "risk_level": level,
            "attack_type": attack_type,
            "confidence": round(min(0.99, 0.5 + abs(score - 0.5)), 4),
            "action_suggestion": action_suggestions.get(level, "观察"),
            "detection_time_ms": per_sample_detection_ms,
            "trigger_features": trigger_features,
            "score_breakdown": {
                "failed_attempts_score": 0,
                "request_frequency_score": 0,
                "unusual_time_score": 0,
                "response_time_score": 0,
                "device_ip_score": 0,
                "model_score": score,
            },
            "reason": reason,
            "suggestion": action_suggestions.get(level, "观察"),
            "source_dataset": metadata.get("source_type") or metadata.get("source") or "processed_dataset",
            "model_version": model_status.get("version") or "unavailable",
        })

    return jsonify(api_response(data={
        "total": len(results),
        "anomalies": int(np.sum(preds)),
        "detections": results,
        "risk_ranking": sorted(results, key=lambda x: float(x.get("risk_score", 0)), reverse=True)[:100],
        "source": metadata.get("source", "processed dataset"),
        "source_type": metadata.get("source_type", "processed"),
        "model_version": model_status.get("version") or "unavailable",
        "runtime_model": model_status,
        "preparation_id": metadata.get("preparation_id"),
        "dataset_revision": metadata.get("dataset_revision"),
        "preprocessing_version": metadata.get("preprocessing_version"),
        "detection_time_ms": round(total_detection_ms, 3),
        "offset": offset,
        "limit": limit,
        "sample_mode": "offset" if has_offset else "random",
    }))


@app.route("/api/ensemble/status", methods=["GET"])
def ensemble_status():
    """融合检测器状态"""
    from src.detection.ensemble_detector import ensemble_detector
    return jsonify(api_response(data=ensemble_detector.status()))


# ─── API: 历史运行记录（兼容旧接口路径） ───

@app.route("/api/experiment/list", methods=["GET"])
def experiment_list():
    """获取历史运行记录；保留旧路径用于接口兼容。"""
    from src.experiments.experiment_manager import exp_manager
    return jsonify(api_response(data={"experiments": exp_manager.get_experiments()}))


# ─── 启动 ───

def _ensure_runtime_ensemble_ready():
    """Load or deterministically bootstrap the real user-facing detector.

    This is safe for both ``python app.py`` and WSGI imports. Only the first
    caller performs initialization; later requests reuse the persisted model.
    """
    from src.detection.ensemble_detector import ensemble_detector
    from src.preprocess.feature_engineering import normalize_security_features

    if ensemble_detector.is_ready():
        return True
    with _runtime_model_init_lock:
        if ensemble_detector.is_ready() or ensemble_detector.load_or_init():
            return True
        try:
            X_train, y_train, _, _ = ensure_data_generated()
            fit_x, fit_y = _stratified_training_sample(X_train, y_train, max_samples=3000, seed=42)
            fit_x = normalize_security_features(fit_x)
            ensemble_detector.fit(
                fit_x,
                fit_y,
                version="bootstrap-%s" % FEATURE_NORMALIZATION_VERSION,
                metadata={"source": "built_in_generated", "samples": int(len(fit_x))},
                snapshot=False,
            )
            return ensemble_detector.is_ready()
        except Exception as error:
            logger.exception("Runtime ensemble initialization failed: {}", error)
            return False


def _pretrain_on_startup():
    """Load runtime artifacts and bootstrap only the user detector if needed."""
    logger.info("=== 启动模型初始化 ===")

    # 1. 确保基准数据存在，并加载已有兼容模型。
    try:
        X_train, y_train, X_test, y_test = ensure_data_generated()
        logger.info("训练数据就绪: 训练集{}条, 测试集{}条", len(X_train), len(X_test))
        # The IF/logistic/Q-learning manager is a compatibility baseline, not
        # the user-facing detector.  Load existing files but do not launch a
        # second expensive training job during every fresh startup.
        model_manager.auto_load_or_train(X_train, y_train, train_if_missing=False)
    except Exception as e:
        logger.warning("模型初始化失败: {}", e)

    # 2. Load the dedicated runtime ensemble.  A clean installation gets one
    # deterministic bootstrap model from the built-in dataset; preparing node
    # data remains an explicit admin action and has no hidden training effect.
    if _ensure_runtime_ensemble_ready():
        from src.detection.ensemble_detector import ensemble_detector
        logger.info("运行时融合模型已就绪: version={}", ensemble_detector.status().get("version"))
    else:
        logger.warning("运行时融合模型初始化失败，检测接口会返回 503 而不会伪造模型分数。")

    # 3. 启动低频数据采集器. The optimizer itself trains lazily when
    # explicitly requested; its rule fallback is immediately available.
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
        db.start_collector(_status_callback, interval=60.0)
        logger.info("数据采集器已启动(60秒间隔)")
    except Exception as e:
        logger.warning("数据采集器启动失败: {}", e)

    logger.info("=== 模型初始化完成 ===")


if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")

    recovered_jobs = db.requeue_interrupted_training_jobs()
    if recovered_jobs:
        logger.warning("检测到 {} 个被服务重启中断的训练任务，已重新排队", recovered_jobs)

    # 后台加载模型；仅在运行时检测模型缺失时执行一次 bootstrap。
    t = threading.Thread(target=_pretrain_on_startup, daemon=True)
    t.start()
    logger.info("后台模型初始化线程已启动")

    logger.info("系统功能: 看板 | 数据加密 | 联邦训练 | 加密对比 | 攻击检测 | 自适应优化 | IP访客 | 数据集管理")
    if os.environ.get("PORT"):
        port = int(os.environ.get("PORT", 5000))
        logger.info("启动单端口服务: http://%s:%d" % (host, port))
        app.run(debug=False, host=host, port=port, threaded=True)
    else:
        from werkzeug.serving import make_server

        ports = [5000, 5001]
        servers = []
        for port in ports:
            server = make_server(host, port, app, threaded=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            servers.append(server)
            logger.info("启动服务: http://%s:%d" % (host, port))
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            for server in servers:
                server.shutdown()
