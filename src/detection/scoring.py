"""Batch-invariant score conversion for anomaly detectors."""

from typing import Optional

import numpy as np


RISK_SCALE_ATTRIBUTE = "_dachuang_risk_scale"
DEFAULT_RISK_SCALE = 0.08


def calibrate_isolation_forest(model, X: np.ndarray) -> float:
    """Store a robust decision-score scale on a fitted IsolationForest.

    ``decision_function`` uses zero as the model's learned anomaly boundary.
    Keeping that boundary and persisting one scale avoids the previous
    per-request min/max normalization, which changed a sample's score based on
    what other samples happened to be in the same API request.
    """
    raw = np.asarray(model.decision_function(X), dtype=np.float64).reshape(-1)
    finite = raw[np.isfinite(raw)]
    if finite.size:
        scale = max(
            float(np.std(finite)),
            float(np.quantile(np.abs(finite), 0.5)),
            1e-3,
        )
    else:
        scale = DEFAULT_RISK_SCALE
    setattr(model, RISK_SCALE_ATTRIBUTE, scale)
    return scale


def isolation_forest_risk_score(model, X: np.ndarray, scale: Optional[float] = None) -> np.ndarray:
    """Map IsolationForest decisions to stable anomaly scores in ``[0, 1]``."""
    raw = np.asarray(model.decision_function(X), dtype=np.float64).reshape(-1)
    resolved_scale = scale
    if resolved_scale is None:
        resolved_scale = getattr(model, RISK_SCALE_ATTRIBUTE, DEFAULT_RISK_SCALE)
    try:
        resolved_scale = max(float(resolved_scale), 1e-3)
    except (TypeError, ValueError):
        resolved_scale = DEFAULT_RISK_SCALE
    logits = np.clip(raw / resolved_scale, -50.0, 50.0)
    return np.clip(1.0 / (1.0 + np.exp(logits)), 0.0, 1.0)
