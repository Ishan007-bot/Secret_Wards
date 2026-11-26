"""Text decoding cascade: BOM -> UTF-16 heuristic -> strict UTF-8 -> plausible cp1252 -> refuse.

Returns (text, encoding) or (None, None). A file we cannot decode with confidence is
quarantined by the caller; it is never passed through half-decoded.
"""
from __future__ import annotations

import unicodedata


def _plausible(text: str) -> bool:
    """Reject mojibake / binary that cp1252 happens to accept (every byte maps to something)."""
    if not text:
        return True
    bad = 0
    for ch in text:
        if ch in "\r\n\t":
            continue
        cat = unicodedata.category(ch)
        if cat in ("Cc", "Co", "Cn"):
            bad += 1
        elif ch in "ÿþ":  # BOM fragments: a strong sign of corrupted bytes
            bad += 1
    return bad == 0


def decode(raw: bytes) -> tuple[str | None, str | None]:
    if raw.startswith(b"\xef\xbb\xbf"):
        try:
            return raw[3:].decode("utf-8"), "utf-8-sig"
        except UnicodeDecodeError:
            return None, None
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return raw.decode("utf-16"), "utf-16"
        except UnicodeDecodeError:
            return None, None
    # UTF-16 without BOM: many NUL bytes in alternating positions
    if len(raw) >= 4 and raw.count(b"\x00") > len(raw) // 4:
        for enc in ("utf-16-le", "utf-16-be"):
            try:
                text = raw.decode(enc)
            except UnicodeDecodeError:
                continue
            if _plausible(text):
                return text, enc
        return None, None
    try:
        return raw.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        pass
    try:
        text = raw.decode("cp1252")
    except UnicodeDecodeError:
        return None, None
    return (text, "cp1252") if _plausible(text) else (None, None)
