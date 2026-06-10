"""IP allowlist/blocklist placeholder."""


class IPFilter:
    def __init__(self, config=None):
        self.config = config or {}

    def check(self, request):
        return True, None
