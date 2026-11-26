"""Encoded payloads that hide personal data: base64 attachments (FHIR attachment.data, scanned forms).

A string is treated as an encoded document only if it is valid base64 AND decodes to mostly
printable UTF-8 text. It is then decoded, cleaned like any other text, and re-encoded, so the
result is still valid base64 (FHIR base64Binary stays valid).
"""
from __future__ import annotations

import base64
import binascii
import re

_B64 = re.compile(r"^[A-Za-z0-9+/\s]{24,}={0,2}$")


def decode_b64_text(value: str) -> str | None:
    if not isinstance(value, str) or not _B64.match(value):
        return None
    compact = re.sub(r"\s+", "", value)
    if len(compact) % 4 not in (0,):
        compact += "=" * (-len(compact) % 4)
    try:
        raw = base64.b64decode(compact, validate=True)
        text = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    if not text:
        return None
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    return text if printable >= 0.95 * len(text) else None


def encode_b64_text(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")
