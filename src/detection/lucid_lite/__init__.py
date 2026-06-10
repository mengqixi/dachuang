"""LUCID-lite placeholder.

No CNN/deep-learning runtime is introduced in this phase.
"""


class LucidLiteDetector:
    def analyze(self, flow_window):
        return {
            "risk_score": 0.0,
            "risk_level": "low",
            "attack_type": "unknown",
            "confidence": 0.0,
            "evidence": [],
        }
