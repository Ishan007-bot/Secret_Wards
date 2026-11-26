"""Truthful age bands: the band ALWAYS contains the real age; very old ages are top-coded."""
from __future__ import annotations

from ..policy import POLICY


def age_band(age: int, width: int | None = None) -> str:
    width = int(width or POLICY["age_band_years"])
    top = int(POLICY["age_top_code"])
    if age >= top:
        return f"{top}+"
    lo = (age // width) * width
    hi = min(lo + width - 1, top - 1)
    return f"{lo}-{hi}"


def band_text(value: str, width: int | None = None) -> str | None:
    """'48' -> '40-49'; returns None if value is not a plausible age."""
    try:
        age = int(str(value).strip())
    except ValueError:
        return None
    if 0 <= age <= 125:
        return age_band(age, width)
    return None
