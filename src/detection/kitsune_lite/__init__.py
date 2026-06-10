"""Kitsune-lite placeholder.

No TensorFlow/PyTorch dependency is introduced in this phase.
"""


class KitsuneLiteDetector:
    def analyze(self, features):
        return {
            "risk_score": 0.0,
            "risk_level": "low",
            "attack_type": "unknown",
            "confidence": 0.0,
            "evidence": [],
        }
