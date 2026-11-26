"""Bootstrap identifier patterns (M0). Replaced by the full layered detector in M2/M3."""
from __future__ import annotations

import re
from collections import Counter

PATTERNS = [
    ("PHONE", re.compile(r"(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)")),
    ("AADHAAR", re.compile(r"(?<!\d)\d{4}[\s-]?\d{4}[\s-]?\d{4}(?!\d)")),
    ("EMAIL", re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")),
    ("PAN", re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")),
]


class Detector:
    def __init__(self):
        self.entities: Counter = Counter()

    def clean_text(self, text: str) -> str:
        for kind, rx in PATTERNS:
            text, n = rx.subn(f"[{kind}]", text)
            self.entities[kind] += n
        return text

    def clean_value(self, v):
        if isinstance(v, str):
            return self.clean_text(v)
        if isinstance(v, list):
            return [self.clean_value(x) for x in v]
        if isinstance(v, dict):
            return {self.clean_text(k): self.clean_value(x) for k, x in v.items()}
        return v
