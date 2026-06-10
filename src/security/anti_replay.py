"""Anti-replay placeholder.

TODO: validate timestamp and nonce, then persist used nonces in SQLite.
Default behavior is allow.
"""


class AntiReplayChecker:
    def __init__(self, config=None):
        self.config = config or {}

    def check(self, request):
        return True, None
