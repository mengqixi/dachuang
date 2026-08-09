"""Core package with side-effect-free, backward-compatible lazy exports."""

from importlib import import_module


_LAZY_EXPORTS = {
    "Paillier": ("src.encryption.paillier", "Paillier"),
    "ABY3Protocol": ("src.encryption.aby3_protocol", "ABY3Protocol"),
    "FeatureExtractor": ("src.detection.feature_extractor", "FeatureExtractor"),
    "HybridAttackDetector": ("src.detection.attack_detector", "HybridAttackDetector"),
    "HybridDetector": ("src.detection.detector", "HybridDetector"),
    "PrimiHubClient": ("src.federated.primihub_client", "PrimiHubClient"),
    "FederatedTaskConfig": ("src.federated.primihub_client", "FederatedTaskConfig"),
    "PrimiHubNodeManager": ("src.federated.primihub_client", "PrimiHubNodeManager"),
    "EncryptionEnv": ("src.optimization.environment", "EncryptionEnv"),
    "QLearningAgent": ("src.optimization.agent", "QLearningAgent"),
    "AdaptiveOptimizer": ("src.optimization.optimizer", "AdaptiveOptimizer"),
}

__all__ = list(_LAZY_EXPORTS)


def __getattr__(name):
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(name)
    value = getattr(import_module(target[0]), target[1])
    globals()[name] = value
    return value
