"""Decide how to treat a file from its extension AND its bytes (extensions lie)."""
from __future__ import annotations

SUPPORTED = {".csv": "csv", ".tsv": "tsv", ".json": "json", ".txt": "text"}

_MAGIC = (
    (b"%PDF", "pdf"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"\x89PNG", "png"),
    (b"GIF8", "gif"),
    (b"PK\x03\x04", "zip"),
    (b"\x1f\x8b", "gzip"),
)


class Quarantine(Exception):
    """Raised with a fixed reason code (never file content) when a file cannot be released safely."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def sniff(ext: str, raw: bytes) -> str:
    """Return a supported kind or raise Quarantine."""
    if not raw.strip():
        raise Quarantine("empty_file")
    for magic, _name in _MAGIC:
        if raw.startswith(magic):
            raise Quarantine("unsupported_format")
    kind = SUPPORTED.get(ext.lower())
    if kind is None:
        raise Quarantine("unsupported_format")
    head = raw[:64].lstrip(b"\xef\xbb\xbf \t\r\n")
    if head.startswith(b"<?xml") or (head.startswith(b"<") and kind != "text"):
        raise Quarantine("unsupported_format")
    if kind in ("csv", "tsv") and head[:1] in (b"{", b"["):
        raise Quarantine("format_mismatch")  # JSON hiding behind a .csv extension
    return kind


def json_depth_exceeds(text: str, limit: int) -> bool:
    """Iterative bracket-depth scan (string-aware), so a 1,500-deep JSON never hits recursion."""
    depth = 0
    in_str = False
    esc = False
    for ch in text:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "[{":
            depth += 1
            if depth > limit:
                return True
        elif ch in "]}":
            depth -= 1
    return False
