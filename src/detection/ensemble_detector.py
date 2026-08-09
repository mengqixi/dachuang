# -*- coding: utf-8 -*-
"""User-facing runtime ensemble detector.

The runtime detector owns a dedicated artifact directory and a preprocessing
manifest.  It is intentionally separate from ``ModelManager``, which remains
the platform's legacy IF/logistic/Q-learning baseline.
"""

import json
import os
import re
import tempfile
import threading
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import numpy as np
from loguru import logger

from src.detection.scoring import calibrate_isolation_forest, isolation_forest_risk_score
from src.preprocess.feature_engineering import FEATURE_NORMALIZATION_VERSION
from src.utils.atomic_files import atomic_copy_file, atomic_write_json


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
MODEL_DIR = os.path.join(PROJECT_ROOT, "data", "models", "runtime_ensemble")
CURRENT_DIR = os.path.join(MODEL_DIR, "current")
VERSIONS_DIR = os.path.join(MODEL_DIR, "versions")
MANIFEST_NAME = "manifest.json"
IF_NAME = "isolation_forest.pkl"
CLASSIFIER_NAME = "classifier.pkl"
LSTM_NAME = "lstm_model.npz"


class EnsembleDetector:
    """Isolation Forest + supervised classifier + NumPy LSTM ensemble."""

    ATTACK_TYPES = ["Normal", "DoS", "Backdoor", "Reconnaissance", "Exploits", "Worms", "Shellcode"]
    COMPONENT_WEIGHTS = {
        "isolation_forest": 0.3,
        "classifier": 0.3,
        "numpy_lstm": 0.4,
    }

    def __init__(self):
        self.if_model = None
        self.xgb_model = None  # Backward-compatible attribute name for the classifier.
        self.lstm_model = None
        self.classifier_type = ""
        self._is_ready = False
        self._feature_dim = 18
        self._sequence_length = 10
        self._manifest: Dict = {}
        self._lock = threading.RLock()
        os.makedirs(CURRENT_DIR, exist_ok=True)
        os.makedirs(VERSIONS_DIR, exist_ok=True)

    @staticmethod
    def _read_manifest(directory: str) -> Dict:
        path = os.path.join(directory, MANIFEST_NAME)
        try:
            with open(path, "r", encoding="utf-8") as stream:
                data = json.load(stream)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    @staticmethod
    def _atomic_joblib_dump(value, path: str) -> None:
        import joblib

        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd, temp_path = tempfile.mkstemp(prefix=".%s." % os.path.basename(path), suffix=".tmp", dir=os.path.dirname(path))
        os.close(fd)
        try:
            joblib.dump(value, temp_path)
            os.replace(temp_path, path)
        except Exception:
            try:
                os.remove(temp_path)
            except OSError:
                pass
            raise

    @staticmethod
    def _atomic_lstm_save(model, path: str) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd, temp_path = tempfile.mkstemp(prefix=".%s." % os.path.basename(path), suffix=".npz", dir=os.path.dirname(path))
        os.close(fd)
        try:
            model.save(temp_path)
            os.replace(temp_path, path)
        except Exception:
            try:
                os.remove(temp_path)
            except OSError:
                pass
            raise

    def _reset_models(self) -> None:
        self.if_model = None
        self.xgb_model = None
        self.lstm_model = None
        self.classifier_type = ""
        self._is_ready = False
        self._manifest = {}

    def _load_from_directory(self, directory: str) -> bool:
        import joblib

        manifest = self._read_manifest(directory)
        if not manifest:
            return False
        if manifest.get("preprocessing_version") != FEATURE_NORMALIZATION_VERSION:
            logger.warning(
                "Runtime ensemble preprocessing mismatch: stored={} current={}",
                manifest.get("preprocessing_version"),
                FEATURE_NORMALIZATION_VERSION,
            )
            return False
        if int(manifest.get("feature_dim") or 0) != self._feature_dim:
            return False

        components = manifest.get("components") or {}
        if_model = None
        classifier = None
        lstm_model = None
        try:
            if components.get("isolation_forest"):
                if_model = joblib.load(os.path.join(directory, IF_NAME))
            if components.get("classifier"):
                classifier = joblib.load(os.path.join(directory, CLASSIFIER_NAME))
            if components.get("numpy_lstm"):
                from src.detection.lstm_detector import NumPyLSTM

                candidate = NumPyLSTM(input_dim=self._feature_dim)
                if candidate.load(os.path.join(directory, LSTM_NAME)):
                    lstm_model = candidate
        except Exception as exc:
            logger.warning("Runtime ensemble artifact load failed: {}", exc)
            return False

        ready = if_model is not None and classifier is not None
        if not ready:
            return False
        self.if_model = if_model
        self.xgb_model = classifier
        self.lstm_model = lstm_model
        self.classifier_type = str(manifest.get("classifier_type") or "classifier")
        self._manifest = manifest
        self._is_ready = True
        logger.info("Runtime ensemble loaded: version={}", manifest.get("version") or "unversioned")
        return True

    def load_or_init(self) -> bool:
        """Load a compatible, fully trained runtime model if one exists."""
        with self._lock:
            self._reset_models()
            return self._load_from_directory(CURRENT_DIR)

    @staticmethod
    def _build_sequences(X: np.ndarray, sequence_length: int = 10) -> np.ndarray:
        if len(X) == 0:
            return np.empty((0, sequence_length, X.shape[1] if X.ndim == 2 else 0))
        sequences = np.empty((len(X), sequence_length, X.shape[1]), dtype=np.float64)
        for index in range(len(X)):
            start = max(0, index - sequence_length + 1)
            window = X[start:index + 1]
            if len(window) < sequence_length:
                padding = np.repeat(window[:1], sequence_length - len(window), axis=0)
                window = np.vstack([padding, window])
            sequences[index] = window
        return sequences

    def _persist_current(self, version: str, metadata: Optional[Dict] = None) -> Dict:
        components = {
            "isolation_forest": self.if_model is not None,
            "classifier": self.xgb_model is not None,
            "numpy_lstm": self.lstm_model is not None and self.lstm_model.is_fitted(),
        }
        if components["isolation_forest"]:
            self._atomic_joblib_dump(self.if_model, os.path.join(CURRENT_DIR, IF_NAME))
        if components["classifier"]:
            self._atomic_joblib_dump(self.xgb_model, os.path.join(CURRENT_DIR, CLASSIFIER_NAME))
        if components["numpy_lstm"]:
            self._atomic_lstm_save(self.lstm_model, os.path.join(CURRENT_DIR, LSTM_NAME))
        manifest = {
            "schema_version": 1,
            "version": str(version or "runtime"),
            "model_type": "runtime_ensemble",
            "trained_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "feature_dim": self._feature_dim,
            "sequence_length": self._sequence_length,
            "preprocessing_version": FEATURE_NORMALIZATION_VERSION,
            "classifier_type": self.classifier_type,
            "components": components,
            "weights": self.COMPONENT_WEIGHTS,
            "metadata": metadata or {},
        }
        atomic_write_json(os.path.join(CURRENT_DIR, MANIFEST_NAME), manifest)
        self._manifest = manifest
        return manifest

    @staticmethod
    def _safe_version_dir(version: str) -> str:
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", str(version or "runtime")).strip("._")
        return safe or "runtime"

    def snapshot_version(self, version: str, metadata: Optional[Dict] = None) -> Dict:
        """Snapshot the current runtime artifacts under a switchable version."""
        with self._lock:
            if not self._is_ready:
                raise RuntimeError("runtime ensemble is not ready")
            current_manifest = dict(self._manifest or self._persist_current(version, metadata))
            current_manifest["version"] = str(version)
            current_manifest["metadata"] = metadata or current_manifest.get("metadata") or {}
            target = os.path.join(VERSIONS_DIR, self._safe_version_dir(version))
            os.makedirs(target, exist_ok=True)
            for enabled, filename in (
                (current_manifest.get("components", {}).get("isolation_forest"), IF_NAME),
                (current_manifest.get("components", {}).get("classifier"), CLASSIFIER_NAME),
                (current_manifest.get("components", {}).get("numpy_lstm"), LSTM_NAME),
            ):
                if enabled:
                    atomic_copy_file(os.path.join(CURRENT_DIR, filename), os.path.join(target, filename))
            atomic_write_json(os.path.join(target, MANIFEST_NAME), current_manifest)
            atomic_write_json(os.path.join(CURRENT_DIR, MANIFEST_NAME), current_manifest)
            self._manifest = current_manifest
            return current_manifest

    def fit(
        self,
        X: np.ndarray,
        y: np.ndarray,
        X_seq: Optional[np.ndarray] = None,
        *,
        version: str = "runtime",
        metadata: Optional[Dict] = None,
        snapshot: bool = True,
    ) -> Dict:
        """Train and atomically replace the user-facing runtime ensemble."""
        X = np.asarray(X, dtype=np.float64)
        y_bin = (np.asarray(y).reshape(-1) > 0).astype(int)
        if X.ndim != 2 or X.shape[1] != self._feature_dim or len(X) != len(y_bin):
            raise ValueError("runtime ensemble requires aligned (n, 18) features and labels")
        if len(X) < 10:
            raise ValueError("runtime ensemble requires at least 10 samples")
        if len(np.unique(y_bin)) < 2:
            raise ValueError("runtime ensemble training requires both normal and attack labels")

        with self._lock:
            logger.info("Training runtime ensemble: shape={}", X.shape)
            from sklearn.ensemble import IsolationForest

            new_if = IsolationForest(
                n_estimators=80,
                contamination=0.15,
                random_state=42,
                n_jobs=1,
            )
            new_if.fit(X)
            calibrate_isolation_forest(new_if, X)

            classifier = None
            classifier_type = ""
            try:
                import xgboost as xgb

                classifier = xgb.XGBClassifier(
                    n_estimators=60,
                    max_depth=4,
                    learning_rate=0.1,
                    random_state=42,
                    n_jobs=1,
                    eval_metric="logloss",
                )
                classifier.fit(X, y_bin)
                classifier_type = "xgboost"
            except Exception as exc:
                logger.info("XGBoost unavailable; using logistic classifier: {}", exc)
                from sklearn.linear_model import LogisticRegression

                classifier = LogisticRegression(max_iter=300, solver="lbfgs", random_state=42)
                classifier.fit(X, y_bin)
                classifier_type = "logistic_regression"

            new_lstm = None
            try:
                if X_seq is None or len(X_seq) == 0:
                    sequence_rows = min(len(X), 1000)
                    X_seq = self._build_sequences(X[:sequence_rows], self._sequence_length)
                    y_seq = y_bin[:sequence_rows]
                else:
                    X_seq = np.asarray(X_seq, dtype=np.float64)
                    y_seq = np.array([
                        1.0 if np.mean(y_bin[i:i + self._sequence_length]) > 0.3 else 0.0
                        for i in range(len(X_seq))
                    ])
                if len(X_seq):
                    from src.detection.lstm_detector import NumPyLSTM

                    new_lstm = NumPyLSTM(input_dim=self._feature_dim)
                    new_lstm.fit(X_seq, y_seq, epochs=6, lr=0.01)
            except Exception as exc:
                logger.warning("Runtime NumPy LSTM training failed: {}", exc)
                new_lstm = None

            self.if_model = new_if
            self.xgb_model = classifier
            self.lstm_model = new_lstm
            self.classifier_type = classifier_type
            self._is_ready = True
            manifest = self._persist_current(version, metadata)
            if snapshot:
                manifest = self.snapshot_version(version, metadata)

            preds, _, _ = self._predict_locked(X)
            accuracy = float(np.mean(preds == y_bin))
            logger.info("Runtime ensemble training complete: accuracy={:.4f}", accuracy)
            return {
                "accuracy": accuracy,
                "version": str(version),
                "preprocessing_version": FEATURE_NORMALIZATION_VERSION,
                "classifier_type": classifier_type,
                "components": manifest.get("components", {}),
            }

    def _predict_locked(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        n = len(X)
        if n == 0:
            return np.empty(0, dtype=int), np.empty(0), np.empty(0, dtype=int)

        components: List[Tuple[float, np.ndarray]] = []
        if self.if_model is not None:
            components.append((
                self.COMPONENT_WEIGHTS["isolation_forest"],
                isolation_forest_risk_score(self.if_model, X),
            ))
        if self.xgb_model is not None:
            try:
                classifier_scores = np.asarray(self.xgb_model.predict_proba(X))[:, 1]
            except Exception:
                classifier_scores = np.asarray(self.xgb_model.predict(X), dtype=np.float64)
            components.append((self.COMPONENT_WEIGHTS["classifier"], classifier_scores))
        if self.lstm_model is not None and self.lstm_model.is_fitted():
            sequences = self._build_sequences(X, self._sequence_length)
            components.append((
                self.COMPONENT_WEIGHTS["numpy_lstm"],
                np.asarray(self.lstm_model.predict(sequences), dtype=np.float64),
            ))

        if not components:
            raise RuntimeError("runtime ensemble is not ready")
        total_weight = sum(weight for weight, _ in components)
        final_scores = sum(weight * score for weight, score in components) / max(total_weight, 1e-12)
        final_scores = np.clip(final_scores, 0.0, 1.0)
        final_preds = (final_scores >= 0.5).astype(int)
        risk_levels = np.where(
            final_scores >= 0.8,
            3,
            np.where(final_scores >= 0.5, 2, np.where(final_scores >= 0.2, 1, 0)),
        )
        return final_preds, final_scores, risk_levels

    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        X = np.asarray(X, dtype=np.float64)
        if X.ndim != 2 or (len(X) and X.shape[1] != self._feature_dim):
            raise ValueError("runtime ensemble expects an (n, 18) feature matrix")
        with self._lock:
            return self._predict_locked(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        _, scores, _ = self.predict(X)
        return scores

    def list_versions(self) -> List[Dict]:
        versions = []
        try:
            names = os.listdir(VERSIONS_DIR)
        except OSError:
            names = []
        for name in names:
            directory = os.path.join(VERSIONS_DIR, name)
            if not os.path.isdir(directory):
                continue
            manifest = self._read_manifest(directory)
            if manifest and manifest.get("preprocessing_version") == FEATURE_NORMALIZATION_VERSION:
                versions.append(manifest)
        versions.sort(key=lambda item: str(item.get("trained_at") or ""), reverse=True)
        return versions

    def has_version(self, version: str) -> bool:
        target = str(version)
        return any(str(item.get("version")) == target for item in self.list_versions())

    def activate_version(self, version: str) -> bool:
        target_version = str(version)
        with self._lock:
            target_dir = None
            target_manifest = None
            for name in os.listdir(VERSIONS_DIR):
                directory = os.path.join(VERSIONS_DIR, name)
                manifest = self._read_manifest(directory)
                if str(manifest.get("version")) == target_version:
                    target_dir = directory
                    target_manifest = manifest
                    break
            if not target_dir or not target_manifest:
                return False
            for enabled, filename in (
                (target_manifest.get("components", {}).get("isolation_forest"), IF_NAME),
                (target_manifest.get("components", {}).get("classifier"), CLASSIFIER_NAME),
                (target_manifest.get("components", {}).get("numpy_lstm"), LSTM_NAME),
            ):
                if enabled:
                    atomic_copy_file(os.path.join(target_dir, filename), os.path.join(CURRENT_DIR, filename))
            atomic_write_json(os.path.join(CURRENT_DIR, MANIFEST_NAME), target_manifest)
            self._reset_models()
            return self._load_from_directory(CURRENT_DIR)

    def status(self) -> Dict:
        with self._lock:
            return {
                "ready": self._is_ready,
                "is_ready": self._is_ready,
                "version": self._manifest.get("version") or "",
                "model_version": self._manifest.get("version") or "",
                "trained_at": self._manifest.get("trained_at"),
                "preprocessing_version": self._manifest.get("preprocessing_version") or FEATURE_NORMALIZATION_VERSION,
                "classifier_type": self.classifier_type,
                "components": self._manifest.get("components") or {},
                "model_count": sum(1 for enabled in (self._manifest.get("components") or {}).values() if enabled),
                "artifact_dir": CURRENT_DIR,
            }

    def is_ready(self) -> bool:
        return self._is_ready


ensemble_detector = EnsembleDetector()
