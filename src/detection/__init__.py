"""Detection package with lightweight lazy exports."""

from importlib import import_module


_LAZY_EXPORTS = {
    "FeatureExtractor": ("src.detection.feature_extractor", "FeatureExtractor"),
    "HybridDetector": ("src.detection.detector", "HybridDetector"),
    "HybridAttackDetector": ("src.detection.attack_detector", "HybridAttackDetector"),
    "EnsembleDetector": ("src.detection.ensemble_detector", "EnsembleDetector"),
}

__all__ = list(_LAZY_EXPORTS)


def __getattr__(name):
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(name)
    value = getattr(import_module(target[0]), target[1])
    globals()[name] = value
    return value
