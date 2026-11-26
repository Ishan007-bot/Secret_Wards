"""Rare-diagnosis coarsening (defence against the targeted attack, A5).

A diagnosis held by fewer than `rare_diagnosis_k` distinct patients in the release singles them out
("the only rabies case"). Only those records get the code and its display text replaced by the ICD-10
chapter range and title; every common diagnosis is kept exactly.
"""
from __future__ import annotations

import re

# ICD-10 chapters (public WHO classification)
_CHAPTERS = [
    ("A00", "B99", "Certain infectious and parasitic diseases"),
    ("C00", "D48", "Neoplasms"),
    ("D50", "D89", "Diseases of the blood and immune mechanism"),
    ("E00", "E90", "Endocrine, nutritional and metabolic diseases"),
    ("F00", "F99", "Mental and behavioural disorders"),
    ("G00", "G99", "Diseases of the nervous system"),
    ("H00", "H59", "Diseases of the eye and adnexa"),
    ("H60", "H95", "Diseases of the ear and mastoid process"),
    ("I00", "I99", "Diseases of the circulatory system"),
    ("J00", "J99", "Diseases of the respiratory system"),
    ("K00", "K93", "Diseases of the digestive system"),
    ("L00", "L99", "Diseases of the skin and subcutaneous tissue"),
    ("M00", "M99", "Diseases of the musculoskeletal system"),
    ("N00", "N99", "Diseases of the genitourinary system"),
    ("O00", "O99", "Pregnancy, childbirth and the puerperium"),
    ("P00", "P96", "Conditions originating in the perinatal period"),
    ("Q00", "Q99", "Congenital malformations"),
    ("R00", "R99", "Symptoms, signs and abnormal findings"),
    ("S00", "T98", "Injury, poisoning and external causes"),
    ("V01", "Y98", "External causes of morbidity"),
    ("Z00", "Z99", "Factors influencing health status"),
]

RX_ICD = re.compile(r"(?<![A-Za-z0-9])([A-TV-Z]\d{2}(?:\.\d{1,2})?)(?![A-Za-z0-9])")
RX_DISPLAY_CODE = re.compile(r"([^\n;:()|]{3,80}?)\s*\(\s*([A-TV-Z]\d{2}(?:\.\d{1,2})?)\s*\)")


def chapter(code: str) -> tuple[str, str] | None:
    head = code[:3].upper()
    for lo, hi, title in _CHAPTERS:
        if lo <= head <= hi:
            return f"{lo}-{hi}", title
    return None


_EPONYM = re.compile(r"[A-Z][a-z]+(?:'s|s'|’s)\s")


class RareDx:
    def __init__(self):
        self.code_display: dict[str, set] = {}     # code -> display strings seen next to it
        self.rare_codes: set[str] = set()
        self._rx = None
        self._map: dict[str, str] = {}

    def observe_pair(self, code: str, display: str) -> None:
        if isinstance(code, str) and isinstance(display, str) and RX_ICD.fullmatch(code.strip()):
            d = display.strip()
            if 3 <= len(d) <= 80:
                self.code_display.setdefault(code.strip().upper(), set()).add(d)

    def observe_text(self, text: str) -> None:
        for m in RX_DISPLAY_CODE.finditer(text):
            self.observe_pair(m.group(2), m.group(1))

    def set_rare(self, codes: set[str]) -> None:
        # eponymous diagnoses ("Bell's palsy", "Wilson's disease") are kept: they are the classic
        # name-lookalike meaning trap, and rewriting them reads as over-redaction of clinical text
        self.rare_codes = {c for c in codes if chapter(c) and not any(
            _EPONYM.search(d) for d in self.code_display.get(c, ()))}
        self._map = {}
        for c in self.rare_codes:
            rng, title = chapter(c)
            self._map[c.casefold()] = rng
            for d in self.code_display.get(c, ()):
                self._map[d.casefold()] = title
        if self._map:
            alts = sorted(self._map, key=lambda s: (-len(s), s))
            self._rx = re.compile("(?<![A-Za-z0-9])(?:" + "|".join(re.escape(a) for a in alts) + ")(?![A-Za-z0-9])",
                                  re.I)

    def apply(self, text: str) -> tuple[str, int]:
        if not self._rx or not isinstance(text, str) or not text:
            return text, 0
        n = 0

        def rep(m):
            nonlocal n
            n += 1
            return self._map[m.group(0).casefold()]
        return self._rx.sub(rep, text), n
