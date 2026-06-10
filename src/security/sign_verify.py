"""Request signature verification placeholder."""


class SignVerifier:
    def __init__(self, config=None):
        self.config = config or {}

    def verify(self, request):
        return True, None
