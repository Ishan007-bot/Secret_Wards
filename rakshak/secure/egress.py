"""Egress gate: the last check before any byte leaves the firewall.

Every finished output is re-scanned in the scorer's normalised form (NFKC, case-folded, Indic digits,
diacritics, decoded base64 / escapes) against the identity vault: harvested phone / Aadhaar / ABHA /
hospital-ID digit cores, learned ID formats and full patient / relative names. Doctor names
(protected spans) are not counted. A hit is re-cleaned; if it survives, the file is quarantined.
"""
from __future__ import annotations

import re

from ..detect.engine import _PROTECT
from ..detect.hidden import decode_b64_text
from ..detect.unhide import scan_form, unhide

_DIGIT_RUN = re.compile(r"\d(?:[\s\-./]?\d){5,17}")
_B64_RUN = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_GATE_KINDS = {"PHONE", "AADHAAR", "ABHA_NUMBER", "MRN", "INSURANCE_ID"}


def _expanded(text: str) -> str:
    extra = []
    for m in _B64_RUN.finditer(text):
        d = decode_b64_text(m.group(0))
        if d:
            extra.append(d)
    return text + ("\n" + "\n".join(extra) if extra else "")


def find_leaks(text: str, vault) -> int:
    """Number of vault identifiers still present in `text` (0 = clean)."""
    if not text:
        return 0
    raw = _expanded(text)
    form = scan_form(raw)
    hits = 0
    cv = vault.compiled()
    for m in _DIGIT_RUN.finditer(form):
        d = re.sub(r"\D", "", m.group(0))
        kind = cv.digits.get(d) or (cv.digits.get(d[-10:]) if len(d) in (11, 12) else None)
        if kind in _GATE_KINDS and len(d) >= 6:
            hits += 1
    if cv.shape_rx and cv.shape_rx.search(form):
        hits += len(cv.shape_rx.findall(form))
    if cv.full_name_rx:
        plain = unhide(raw)
        protected = [(p.start(), p.end()) for rx in _PROTECT for p in rx.finditer(plain)]
        for m in cv.full_name_rx.finditer(plain):
            if not any(ps <= m.start() and m.end() <= pe for ps, pe in protected):
                hits += 1
    return hits
