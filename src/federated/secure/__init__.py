"""Secure aggregation placeholders for Phase 2."""


class SecureAggregationPlaceholder:
    def aggregate(self, client_updates):
        return {
            "status": "placeholder",
            "client_count": len(client_updates or []),
        }
