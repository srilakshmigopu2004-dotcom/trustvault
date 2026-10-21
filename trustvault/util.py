from datetime import datetime, timezone


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class ApiError(Exception):
    """Raised anywhere in a request. The transaction is rolled back (no side
    effects), then `audit` (if given) is written in a fresh transaction so that
    refused attempts are still on the record."""

    def __init__(self, status: int, message: str, audit: dict | None = None):
        super().__init__(message)
        self.status = status
        self.message = message
        self.audit = audit
