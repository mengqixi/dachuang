"""Federated-learning package with no network work at import time."""

from importlib import import_module


_LAZY_EXPORTS = {
    "PrimiHubClient": ("src.federated.primihub_client", "PrimiHubClient"),
    "FederatedTaskConfig": ("src.federated.primihub_client", "FederatedTaskConfig"),
    "PrimiHubNodeManager": ("src.federated.primihub_client", "PrimiHubNodeManager"),
    "FedAvgServer": ("src.federated.aggregator", "FedAvgServer"),
    "FederatedClient": ("src.federated.client", "FederatedClient"),
}

__all__ = list(_LAZY_EXPORTS)


def __getattr__(name):
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(name)
    value = getattr(import_module(target[0]), target[1])
    globals()[name] = value
    return value
