"""Small text utilities shared by detection, linkage and the egress gate."""
from __future__ import annotations

import re
import unicodedata

_DEVA_DIGITS = str.maketrans("०१२३४५६७८९", "0123456789")
DEVA = r"ऀ-ॿ"
RX_DEVA = re.compile(f"[{DEVA}]")


def ascii_digits(text: str) -> str:
    """Devanagari digits -> ASCII. Same length, so span offsets stay valid."""
    return text.translate(_DEVA_DIGITS)


def digits_only(text: str) -> str:
    return re.sub(r"\D", "", ascii_digits(text))


def fold(text: str) -> str:
    """Comparison form: NFKC, casefold, collapse whitespace/underscores/dots."""
    t = unicodedata.normalize("NFKC", text).casefold()
    t = re.sub(r"[\s_.\-]+", " ", t)
    return t.strip()


def is_devanagari(text: str) -> bool:
    return bool(RX_DEVA.search(text))
