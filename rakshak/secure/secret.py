"""RAKSHA_SECRET handling.

The secret is read once, kept as bytes, and only ever used as an HMAC key. It is never
formatted into a string, logged, written to disk, or included in an exception message.
"""
from __future__ import annotations

import hashlib
import hmac
import os


class MissingSecret(Exception):
    """Raised when RAKSHA_SECRET is absent: we fail closed instead of running unkeyed."""


_SECRET: bytes | None = None


def secret() -> bytes:
    global _SECRET
    if _SECRET is None:
        value = os.environ.get("RAKSHA_SECRET", "")
        if not value:
            raise MissingSecret()
        _SECRET = value.encode("utf-8")
    return _SECRET


def keyed(label: str, message: str) -> bytes:
    """HMAC-SHA256(secret, label | message). Labels separate the uses (pseudonym, shift, ...)."""
    return hmac.new(secret(), label.encode("utf-8") + b"|" + message.encode("utf-8"), hashlib.sha256).digest()


def keyed_int(label: str, message: str) -> int:
    return int.from_bytes(keyed(label, message)[:8], "big")
