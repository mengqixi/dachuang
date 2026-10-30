"""Measured, bounded runtime statistics for the platform's linear models."""

import hashlib
import platform
import sys
import time

import numpy as np


TIMING_VERSION = "linear-wall-clock-v1"


def runtime_environment_id():
    description = "|".join((platform.node(), platform.machine(), sys.version.split()[0], np.__version__))
    return hashlib.sha256(description.encode("utf-8")).hexdigest()[:16]


def benchmark_linear_inference(X, weights):
    """One warmup, then median of seven real predictions on <=1024 holdout rows.

    No features, labels or model weights are changed. This measures model-only
    batch prediction, not upload, feature extraction, networking or API latency.
    """
    matrix = np.asarray(X, dtype=np.float64)
    vector = np.asarray(weights, dtype=np.float64).reshape(-1)
    if (matrix.ndim != 2 or not len(matrix) or len(vector) != matrix.shape[1] + 1
            or not np.all(np.isfinite(vector))):
        return {}
    batch = matrix[:1024]

    def predict():
        logits = np.clip(np.c_[batch, np.ones(len(batch))] @ vector, -50.0, 50.0)
        return (1.0 / (1.0 + np.exp(-logits)) >= .5).astype(np.int32)

    predict()
    durations = []
    for _ in range(7):
        started = time.perf_counter()
        predict()
        durations.append(max((time.perf_counter() - started) * 1000.0, 0.000001))
    median = float(np.median(durations))
    return {"inference_batch_ms": median, "inference_batch_samples": int(len(batch)),
            "inference_samples_per_second": float(len(batch) * 1000.0 / median),
            "inference_repeats": 7, "inference_warmup": 1}


def training_performance(started, samples, compute_ms, X, weights, **stages):
    # Capture training before benchmarking; benchmark/holdout scoring/storage
    # must not be charged to the training wall clock.
    elapsed = max((time.perf_counter() - started) * 1000.0, 0.000001)
    return dict({
        "timing_version": TIMING_VERSION, "environment_id": runtime_environment_id(),
        "measured_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "training_time_ms": elapsed, "model_compute_time_ms": float(compute_ms),
        "training_samples_per_second": float(samples * 1000.0 / elapsed),
        "execution_mode": "single_host_sequential",
    }, **dict(benchmark_linear_inference(X, weights), **stages))
