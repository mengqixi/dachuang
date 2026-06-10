"""Response policy placeholder for risk-based actions."""


class ResponsePolicy:
    def __init__(self, config=None):
        self.config = config or {}

    def decide(self, risk_result):
        return {"action": "allow", "reason": "default"}
