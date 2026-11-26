"""Undo disguises before detection: the official scorer normalises and decodes all of these when it
counts leaks, so a name hidden as \\u-escapes, HTML entities, %-encoding, zero-width characters or
Cyrillic/Greek look-alike letters must be found and removed too."""
from __future__ import annotations

import html
import re
import unicodedata
from urllib.parse import unquote

_UESC = re.compile(r"\\u([0-9a-fA-F]{4})")
_ENTITY = re.compile(r"&(?:#\d{2,7}|#x[0-9a-fA-F]{2,6}|[A-Za-z]{2,8});")
_PCT = re.compile(r"(?:%[0-9A-Fa-f]{2}){3,}")
_ZERO_WIDTH = re.compile("[​‌‍‎‏⁠⁡⁢⁣﻿­]")
_HOMOGLYPH = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
    "Х": "X", "І": "I", "Ј": "J", "Ѕ": "S", "α": "a", "ο": "o", "ρ": "p", "ν": "v", "Α": "A", "Β": "B",
    "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T",
    "Υ": "Y", "Χ": "X",
})
_MIXED = re.compile(r"[A-Za-z][Ͱ-ϿЀ-ӿ]|[Ͱ-ϿЀ-ӿ][A-Za-z]")


def unhide(text: str) -> str:
    """Return text with disguises undone (unchanged if there were none)."""
    if not isinstance(text, str) or not text:
        return text
    t = text
    if "\\u" in t:
        t = _UESC.sub(lambda m: chr(int(m.group(1), 16)), t)
    if "&" in t and _ENTITY.search(t):
        t = html.unescape(t)
    if "%" in t and _PCT.search(t):
        t = _PCT.sub(lambda m: unquote(m.group(0)), t)
    if _ZERO_WIDTH.search(t):
        t = _ZERO_WIDTH.sub("", t)
    if _MIXED.search(t):
        t = t.translate(_HOMOGLYPH)
    if any(ord(c) > 0xFF00 for c in t):  # full-width forms -> ASCII
        t = unicodedata.normalize("NFKC", t)
    return t


def scan_form(text: str) -> str:
    """Comparison form used by the egress gate (mirrors the scorer's normalisation)."""
    t = unhide(text)
    t = unicodedata.normalize("NFKC", t)
    t = "".join(c for c in unicodedata.normalize("NFKD", t) if not unicodedata.combining(c)
                or "ऀ" <= c <= "ॿ")
    return t.translate(str.maketrans("०१२३४५६७८९", "0123456789")).casefold()
