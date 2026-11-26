"""Layered span detector for any string (cell, JSON leaf, note, key, header, file name).

L1 identifier patterns      phones, Aadhaar (+masked), ABHA, PAN, email, insurance, MRN families
L1b learned ID shapes       formats learned from this dataset's own ID columns
L1c vault digit cores       any digit run whose digits belong to a harvested phone/ID/Aadhaar/PIN
L2  vault text              harvested full names (any order / separator / case), name tokens, addresses
L3  context rules           labels (Name:, नाम:, Attendant:, UHID:, Address:, DOB:, Age:), S/o D/o W/o C/O
L5  protection              Dr. names, ASHA workers, hospital wards, eponyms, hospitals: never redacted
                            (hard identifiers such as phones still win inside protected text)
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass

from ..privacy.ages import band_text
from . import lexicon as L
from .textnorm import DEVA, ascii_digits, digits_only, is_devanagari
from .unhide import unhide
from .vault import Vault

HARD = {"PHONE", "AADHAAR", "AADHAAR_MASKED", "PHONE_MASKED", "ABHA_NUMBER", "ABHA_ADDRESS", "PAN", "EMAIL",
        "INSURANCE_ID", "MRN"}

PLACEHOLDER = {
    "PATIENT": "[PATIENT]", "RELATIVE": "[RELATIVE]", "PHONE": "[PHONE]", "PHONE_MASKED": "[PHONE]",
    "AADHAAR": "[AADHAAR]", "AADHAAR_MASKED": "[AADHAAR]", "ABHA_NUMBER": "[ABHA]", "ABHA_ADDRESS": "[ABHA]",
    "PAN": "[PAN]", "EMAIL": "[EMAIL]", "INSURANCE_ID": "[INSURANCE_ID]", "MRN": "[ID]", "ADDRESS": "[ADDRESS]",
    "VILLAGE": "[LOCATION]", "PIN": "[PIN]", "DOB": "[DOB]",
}


@dataclass
class Span:
    start: int
    end: int
    kind: str
    prio: int
    repl: str | None = None   # explicit replacement (age bands keep their surface form)
    src: str = ""             # which layer found it (pattern, shape, digits, vault_*, label, age, proximity)


# ---------------------------------------------------------------------------------------- L1
_P = [
    ("ABHA_ADDRESS", r"(?<![\w.])[A-Za-z0-9._]{3,}@(?:abdm|sbx|ndhm)\b", 0),
    ("EMAIL", r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[A-Za-z]{2,})+", 0),
    ("AADHAAR_MASKED", r"(?<![A-Za-z0-9])[Xx*]{4}[\s-]?[Xx*]{4}[\s-]?\d{4}(?!\d)", 0),
    ("PHONE_MASKED", r"(?<!\d)[6-9]\d[Xx*]{5,6}\d{2,3}(?!\d)", 0),
    ("ABHA_NUMBER", r"(?<!\d)\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}(?!\d)", 0),
    ("AADHAAR", r"(?<!\d)[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}(?!\d)", 0),
    ("PHONE", r"(?<![\d+])(?:(?:\+|00)?91[\s-]?|0)?[6-9]\d(?:[\s-]?\d){8}(?!\d)", 0),
    ("PAN", r"(?<![A-Za-z0-9])[A-Z]{5}\d{4}[A-Z](?![A-Za-z0-9])", 0),
    ("INSURANCE_ID", r"(?<![A-Za-z0-9])(?:AB-?)?PM-?JAY[-\s/]?[A-Z]{2}[-\s/]?\d{6,12}(?!\d)", re.I),
    ("INSURANCE_ID", r"(?<![A-Za-z0-9])POL(?:ICY)?[-/ ]?\d{2,4}[-/ ]\d{6,10}(?!\d)", re.I),
    ("MRN", r"(?<![A-Za-z0-9])(?:UHID|MRN|ADM|IPD|IP|CR|REG)[-/ _.]?(?:\d{2,4}[-/ _.])?\d{4,}(?![A-Za-z0-9])", re.I),
]
PATTERNS = [(k, re.compile(p, f)) for k, p, f in _P]

_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_DIGIT_RUN = re.compile(r"(?<![0-9])\+?\d(?:[\s\-./]?\d){3,17}(?![0-9])")

# ---------------------------------------------------------------------------------------- L3
_NAME_CH = rf"A-Za-z{DEVA}"
_SEP = r"\s*[:：\-–]\s*"
_LBL_NAME = (r"(?:Patient(?:'s|s)?\s*(?:Full\s*)?Name|Pt\.?\s*(?:Full\s*)?Name|Name\s+of\s+(?:the\s+)?Patient|Patient|"
             r"Full\s*Name|Name|Naam|Pt\.?|Mareez(?:\s+ka)?(?:\s+Naam)?|Rogi(?:\s+ka)?(?:\s+Naam)?|"
             r"मरीज़?\s+का\s+नाम|रोगी\s+का\s+नाम|मरीज़?|रोगी|नाम)")
_LBL_REL = (r"(?:Attendant|Informant|Guardian|Father'?s?\s*Name|Husband'?s?\s*Name|Mother'?s?\s*Name|"
            r"Spouse(?:'s)?\s*Name|Spouse|Next\s+of\s+Kin|Relative(?:'s)?\s*Name|Relative|Caller|"
            r"Accompanied\s+by|Brought\s+by|Escort|Rishtedar|Parijan|Kin|Emergency\s+Contact(?:\s+Name)?|"
            r"पति\s+का\s+नाम|पिता\s+का\s+नाम|माता\s+का\s+नाम|परिजन)")
_LBL_REL_NOCOLON = r"(?:called\s+by|raised\s+by|witnessed\s+by|referred\s+by\s+(?!Dr)|brought\s+by|accompanied\s+by)"
_LBL_ID = (r"(?:UHID|MRN|MR\s*No\.?|Reg(?:istration)?\.?\s*(?:No|Number|ID)\.?|Patient\s*ID|IPD\s*No\.?|"
           r"IP\s*No\.?|Adm(?:ission)?\.?\s*No\.?|CR\s*No\.?|Hospital\s*ID|पंजीकरण\s*सं\.?|आईपीडी\s*सं\.?)")
_LBL_ADDR = r"(?:(?:Permanent\s+|Present\s+|Current\s+)?Address|Addr\.?|Residence|Pata|पता)(?:\s*\([^)\n]{0,25}\))?"
_LBL_VILL = r"(?:Village|Vill\.?|Gram|Gaon|ग्राम|गाँव|गांव)"
_LBL_DOB = r"(?:DOB|D\.O\.B\.?|Date\s+of\s+Birth|Birth\s*Date|Janm\s+Tithi|जन्म\s+तिथि)"
_LBL_AGE = r"(?:Age\s*/\s*Sex|Age\s*/\s*Gender|Age|Umar|आयु|उम्र)"

RX_NAME_LABEL = re.compile(rf"(?<![A-Za-z{DEVA}]){_LBL_NAME}{_SEP}", re.I)
RX_REL_LABEL = re.compile(rf"(?<![A-Za-z{DEVA}]){_LBL_REL}{_SEP}", re.I)
RX_REL_NOCOLON = re.compile(rf"(?<![A-Za-z]){_LBL_REL_NOCOLON}\s+", re.I)
RX_ID_LABEL = re.compile(rf"(?<![A-Za-z{DEVA}]){_LBL_ID}{_SEP}", re.I)
RX_ADDR_LABEL = re.compile(rf"(?<![A-Za-z{DEVA}]){_LBL_ADDR}{_SEP}", re.I)
RX_VILL_LABEL = re.compile(rf"(?<![A-Za-z{DEVA}]){_LBL_VILL}(?:\s*[:：\-–]\s*|\.\s*|\s+)(?=[A-Z{DEVA}])", re.I)
RX_DOB_LABEL = re.compile(rf"(?<![A-Za-z{DEVA}]){_LBL_DOB}{_SEP}", re.I)
RX_AGE_LABEL = re.compile(rf"(?<![A-Za-z{DEVA}]){_LBL_AGE}\s*[:：\-–]?\s*(\d{{1,3}})(?!\d)", re.I)
RX_AGE_FORMS = [
    re.compile(r"(?<![\d/.:])(\d{1,3})\s*(?:Y|Yr|Yrs|Year|Years|yr|yrs|years|y)\.?\s*/\s*(?:[MFmf]\b|Male|Female)"),
    re.compile(r"(?<![\d/.:])(\d{1,3})\s*/\s*(?:[MF]\b|Male\b|Female\b)"),
    re.compile(r"(?<![\d/.:])(\d{1,3})\s*(?:yrs?|years?)\s*,\s*(?:male|female)\b", re.I),
    re.compile(r"(?<![\d/.:])(\d{1,3})\s*वर्ष\s*/\s*(?:महिला|पुरुष)"),
]
RX_RELATION = re.compile(
    rf"(?<![A-Za-z/]){L.RELATION_MARKERS}\.?[ \t]*[:\-]?[ \t]*"
    rf"((?:[A-Z][A-Za-z.']*|[{DEVA}]+)(?:[ \t]+(?:[A-Z][A-Za-z.']*|[{DEVA}]+)){{0,3}})")
RX_RELATION_DEVA = re.compile(
    rf"(?<![{DEVA}]){L.RELATION_MARKERS_DEVA}[ \t]*[:\-]?[ \t]*([{DEVA}]+(?:[ \t]+[{DEVA}]+){{0,2}})")
_DATE_VALUE = re.compile(r"\d{1,4}[-/.]\d{1,2}[-/.]\d{1,4}|\d{1,2}\s+[A-Za-z]{3,9}\s+\d{4}")

_STOP_WORDS = re.compile(r"\s+(?:Age|Sex|Mob|Mobile|Ph|Phone|Reg|UHID|DOB|IPD|Date|Gender|आयु|उम्र|मोबाइल|पंजीकरण)\b.*$",
                         re.I)

# ---------------------------------------------------------------------------------------- L5
_PROTECT = [
    re.compile(r"(?<![A-Za-z])(?:Dr|DR|Doctor)\.?\s*[A-Z][A-Za-z.'-]*(?:\s+[A-Z][A-Za-z'-]*){0,3}"),
    re.compile(rf"डॉ\.?\s*[{DEVA}]+(?:\s+[{DEVA}]+){{0,2}}"),
    re.compile(r"\bASHA\s+(?:worker|workers|karyakarta|karyakartri|didi|sahyogini)\b", re.I),
    re.compile(r"\bWard\s*\d+\s*\([^)\n]{1,40}\)"),
    re.compile(r"\bWard\s*/\s*Bed\b[^\n]*"),
    re.compile(r"\bBed\s*(?:No\.?\s*)?\d+\b"),
    re.compile(r"\b[A-Z][a-z]+(?:'s|’s|s')\s+(?:disease|syndrome|palsy|sign|phenomenon|anomaly|ulcer|sarcoma|"
               r"lymphoma|disorder|test|tumou?r|fracture|chorea|encephalopathy)\b", re.I),
    re.compile(r"(?:[A-Z][A-Za-z]+\s+){1,4}(?:Hospital|Sadan|Pathology|Diagnostics|Clinic|Laboratory|Labs?|"
               r"Nursing\s+Home|Medical\s+College|Health\s+Centre|Dispensary)\b"),
]


def _cut_value(rest: str) -> tuple[int, int]:
    """Given text after a label, return (start, end) of the value: stops at 2+ spaces, punctuation, EOL."""
    m = re.match(r"[ \t]*", rest)
    s = m.end()
    e = s
    while e < len(rest):
        ch = rest[e]
        if ch in "\n\r,;|()[]{}\t" or ch.isdigit() or rest.startswith("  ", e):
            break
        e += 1
    val = rest[s:e]
    cut = _STOP_WORDS.search(val)
    if cut:
        e = s + cut.start()
    while e > s and rest[e - 1] in " .:-":
        e -= 1
    return s, e


_NON_PERSON_BEFORE_LABEL = re.compile(
    r"(?:Doctor|Dr|Consultant|Hospital|Test|Drug|Medicine|Lab|Ward|File|Facility|Department|Scheme|Package|"
    r"Procedure|Company|Insurer|Payer|Bank)['’]?s?\s*$", re.I)
_VILLAGE_BAD_BEFORE = re.compile(r"\d\s*$")

# generic "<Word(s)> No / # / ID :" labels whose value looks like an identifier
RX_GENERIC_ID_LABEL = re.compile(r"(?<![A-Za-z])((?:[A-Z][A-Za-z.]{1,15}\s*){1,3})(?:No\.?|Number|#|ID|Id)\s*[:：\-–]\s*")
_NOT_PATIENT_ID_LABEL = re.compile(r"\b(?:Bill|Invoice|Sample|Visit|Trip|Ticket|Bed|Ward|Room|Lot|Batch|Order|Test|"
                                   r"Package|Claim|Receipt|Token|Serial|Sr|S\.?No|Item|Page|Version)\b", re.I)
_ID_LIKE = re.compile(r"(?=.*\d)(?:[A-Za-z]{1,8}[-/:._ ]?\d[\d\-/:._]{2,}[A-Za-z]?|\d{5,})")

# address grammar (Latin and Devanagari), for address text that carries no label
_ADDRESS_GRAMMAR = [
    ("HOUSE", re.compile(r"(?<![A-Za-z])(?:H\.?\s?No\.?|House(?:\s+No\.?)?|Makan(?:\s+No\.?)?|Flat(?:\s+No\.?)?|"
                         r"Plot(?:\s+No\.?)?|Door(?:\s+No\.?)?|Qtr\.?(?:\s+No\.?)?)\s*[:\-]?\s*\d+[A-Za-z]?(?:/\d+)?\b",
                         re.I)),
    ("HOUSE", re.compile(r"मकान\s*(?:नं\.?|नंबर|संख्या)?\s*[\d०-९]+")),
    ("LOCALITY", re.compile(r"(?<![A-Za-z])Mohalla\s+[A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+){0,2}")),
    ("LOCALITY", re.compile(r"मोहल्ला\s+[ऀ-ॿ]+(?:\s+[ऀ-ॿ]+){0,2}")),
    ("LOCALITY_WARD", re.compile(r"(?<![A-Za-z])Ward\s*(?:No\.?\s*)?\d{1,3}(?!\s*\()(?![\d/])")),
    ("LOCALITY_WARD", re.compile(r"वार्ड\s*(?:नं\.?\s*)?[\d०-९]{1,3}")),
    ("LANDMARK", re.compile(r"(?<![A-Za-z])(?:near|opp\.?|opposite|behind|beside|next\s+to)\s+(?:the\s+)?"
                            r"[A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+){0,3}")),
    ("LANDMARK", re.compile(r"[ऀ-ॿ]+(?:\s+[ऀ-ॿ]+){0,3}\s+(?:के\s+(?:पास|पीछे|सामने|बगल\s+में)|"
                            r"की\s+ओर)")),
]
_ADDRESS_CONTEXT = re.compile(r"H\.?\s?No|House|Makan|Mohalla|Tehsil|Distt|District|Gram|Village|मकान|मोहल्ला|"
                              r"तहसील|जिला|near|opp", re.I)
_RELATIVE_BEFORE_NAME_LABEL = re.compile(
    r"(?:पिता|पति|माता|पत्नी|पुत्र|पुत्री|अभिभावक|Father|Husband|Mother|Spouse|Guardian|Wife|Relative|Attendant)"
    r"(?:'s|’s|s)?\s*(?:का|की|के)?\s*$", re.I)
_HINDI_FUNCTION_WORDS = {"का", "की", "के", "को", "है", "हैं", "से", "में", "ने", "पर", "और", "था", "थी", "थे", "नाम",
                         "भी", "तो", "ही", "एक", "यह", "वह", "बुखार", "दर्द", "साथ", "लिए"}


def _relation_ok(marker: str, val: str) -> bool:
    first = val.split()[0]
    if marker == "h/o":
        return False  # "H/O" is almost always "history of"
    if marker == "c/o" and first.lower() in L.COMPLAINT_WORDS | L.CLINICAL_WORDS:
        return False  # "C/O fever" = complaint of
    if len(val.split()) == 1 and first.isupper() and len(first) <= 4:
        return False  # abbreviations: "C/O DM", "S/O HTN"
    return _looks_like_name(val)


def _looks_like_name(value: str) -> bool:
    v = value.strip()
    if not v or len(v) > 60 or re.search(r"\d", v):
        return False
    if re.match(r"(?:Dr|DR|Doctor)\b", v):
        return False
    words = re.findall(rf"[{_NAME_CH}.']+", v)
    if not words or len(words) > 6:
        return False
    if is_devanagari(v):
        return True
    if all(w.lower().strip(".") in L.CLINICAL_WORDS for w in words):
        return False
    return words[0][:1].isupper()


class Engine:
    def __init__(self, vault: Vault | None = None):
        self.vault = vault or Vault()
        self.counts: Counter = Counter()

    # ------------------------------------------------------------------ pass 1: harvest from labelled text
    def harvest_text(self, text: str) -> None:
        if not text or not isinstance(text, str):
            return
        text = unhide(text)
        for kind, value in self._label_values(text):
            if kind == "PATIENT":
                self.vault.add_name(value, "PATIENT")
            elif kind == "RELATIVE":
                self.vault.add_name(value, "RELATIVE")
            elif kind == "MRN":
                self.vault.add_id(value, "MRN")
            elif kind == "ADDRESS":
                self.vault.add_address(value)
            elif kind == "VILLAGE":
                self.vault.add_text(value, "VILLAGE")

    def _label_values(self, text: str):
        for kind, (s, e) in self._label_spans(text):
            if kind in ("PATIENT", "RELATIVE", "MRN", "ADDRESS", "VILLAGE"):
                yield kind, text[s:e]

    # ------------------------------------------------------------------ pass 2: find spans
    def find(self, text: str) -> list[Span]:
        if not text:
            return []
        norm = ascii_digits(text)
        spans: list[Span] = []
        add = spans.append

        for kind, rx in PATTERNS:                                         # L1
            for m in rx.finditer(norm):
                add(Span(m.start(), m.end(), kind, 3, src="pattern"))

        cv = self.vault.compiled()
        if cv.shape_rx:                                                   # L1b
            for m in cv.shape_rx.finditer(norm):
                add(Span(m.start(), m.end(), "MRN", 3, src="shape"))
        if cv.digits:                                                     # L1c
            for m in _DIGIT_RUN.finditer(norm):
                d = digits_only(m.group(0))
                kind = cv.digits.get(d) or (cv.digits.get(d[-10:]) if len(d) in (11, 12) else None)
                if kind:
                    add(Span(m.start(), m.end(), "PIN" if kind == "PIN" else kind, 3 if kind != "PIN" else 2,
                             src="digits"))
                    continue
                for g in re.finditer(r"\d+", m.group(0)):
                    gk = cv.digits.get(g.group(0))
                    if gk and gk != "PIN":
                        add(Span(m.start() + g.start(), m.start() + g.end(), gk, 3, src="digits"))

        if cv.full_name_rx:                                               # L2
            for m in cv.full_name_rx.finditer(text):
                add(Span(m.start(), m.end(), cv.full_name_kind.get(_fold_key(m.group(0)), "PATIENT"), 2,
                         src="vault_full"))
        if cv.text_rx:
            for m in cv.text_rx.finditer(text):
                k = cv.text_kind.get(_fold_key(m.group(0)), "ADDRESS")
                add(Span(m.start(), m.end(), k, 2, src="vault_text"))
        for rx in (cv.token_rx, cv.deva_rx):
            if rx:
                for m in rx.finditer(text):
                    add(Span(m.start(), m.end(), cv.token_kind.get(m.group(0).casefold(), "PATIENT"), 1,
                             src="vault_tok"))

        for kind, value_span in self._label_spans(text):                  # L3
            add(Span(value_span[0], value_span[1], kind, 2, src="label"))
        for rx in [RX_AGE_LABEL] + RX_AGE_FORMS:
            for m in rx.finditer(norm):
                band = band_text(m.group(1))
                if band:
                    add(Span(m.start(1), m.end(1), "AGE", 2, band, src="age"))

        protected = [(m.start(), m.end()) for rx in _PROTECT for m in rx.finditer(text)]   # L5
        spans.extend(_phone_proximity_names(text, spans))                                 # L3b
        uuids = [(m.start(), m.end()) for m in _UUID.finditer(text)]
        if uuids:  # resource ids / references are random UUIDs: never personal data, never touched
            spans = [s for s in spans if not any(us <= s.start and s.end <= ue for us, ue in uuids)]
        return _resolve(spans, protected)

    def _label_spans(self, text: str):
        for kind, rx in (("RELATIVE", RX_REL_LABEL), ("RELATIVE", RX_REL_NOCOLON), ("PATIENT", RX_NAME_LABEL)):
            for m in rx.finditer(text):
                before = text[max(0, m.start() - 20):m.start()]
                if _NON_PERSON_BEFORE_LABEL.search(before):
                    continue
                if kind == "PATIENT" and _RELATIVE_BEFORE_NAME_LABEL.search(before):
                    continue  # "पिता का नाम:", "Father's Name:" are relatives (handled above)
                s, e = _cut_value(text[m.end():])
                val = text[m.end() + s:m.end() + e]
                if _looks_like_name(val):
                    yield kind, (m.end() + s, m.end() + e)
        for m in RX_RELATION.finditer(text):
            marker = m.group(0)[:3].lower()
            if _relation_ok(marker, m.group(1)):
                yield "RELATIVE", (m.start(1), m.end(1))
        for m in RX_RELATION_DEVA.finditer(text):
            toks = m.group(1).split()
            if toks and not any(t in _HINDI_FUNCTION_WORDS for t in toks):
                yield "RELATIVE", (m.start(1), m.end(1))
        for m in RX_ID_LABEL.finditer(text):
            v = re.match(r"[A-Za-z0-9](?:[A-Za-z0-9/_.\-]|:(?=[A-Za-z0-9]))*", text[m.end():])
            if v and re.search(r"\d", v.group(0)):
                yield "MRN", (m.end(), m.end() + len(v.group(0).rstrip(".-/")))
        for m in RX_GENERIC_ID_LABEL.finditer(text):           # unseen labels: "Hosp No:", "Regn #:"
            if _NOT_PATIENT_ID_LABEL.search(m.group(1)):
                continue
            v = re.match(r"[A-Za-z0-9](?:[A-Za-z0-9/_.\-]|:(?=[A-Za-z0-9]))*", text[m.end():])
            if v and _ID_LIKE.fullmatch(v.group(0).rstrip(".-/")):
                yield "MRN", (m.end(), m.end() + len(v.group(0).rstrip(".-/")))
        for kind, rx in _ADDRESS_GRAMMAR:                        # addresses with no label at all
            for m in rx.finditer(text):
                if kind == "LOCALITY_WARD" and not _ADDRESS_CONTEXT.search(
                        text[max(0, m.start() - 40):m.end() + 40]):
                    continue
                yield "ADDRESS", (m.start(), m.end())
        for m in RX_ADDR_LABEL.finditer(text):
            line_end = text.find("\n", m.end())
            end = line_end if line_end >= 0 else len(text)
            while end > m.end() and text[end - 1] in " \r\t":
                end -= 1
            if end > m.end():
                yield "ADDRESS", (m.end(), end)
        for m in RX_VILL_LABEL.finditer(text):
            if _VILLAGE_BAD_BEFORE.search(text[max(0, m.start() - 4):m.start()]):
                continue  # "1 gram ..." is a dose, not a village
            s, e = _cut_value(text[m.end():])
            val = text[m.end() + s:m.end() + e]
            if val and not re.search(r"\d", val) and val.split()[0].lower() not in L.CLINICAL_WORDS:
                yield "VILLAGE", (m.end() + s, m.end() + e)
        for m in RX_DOB_LABEL.finditer(text):
            dm = _DATE_VALUE.match(ascii_digits(text[m.end():]))
            if dm:
                yield "DOB", (m.end(), m.end() + dm.end())

    # ------------------------------------------------------------------ rewrite
    def clean(self, text: str, hard_only: bool = False, rec=None) -> str:
        """Replace every detected span. With a record context (`rec`), the record's own patient name /
        ID become its pseudonym, DOBs are jittered, and the remaining text has its dates shifted."""
        if not isinstance(text, str) or not text:
            return text
        text = unhide(text)
        spans = self.find(text)
        if hard_only:
            spans = [s for s in spans if s.kind in HARD]
        shift = rec.shift_text if (rec is not None and rec.shifter is not None) else (lambda s: s)
        if not spans:
            return shift(text)
        out, pos = [], 0
        for sp in spans:
            out.append(shift(text[pos:sp.start]))
            out.append(self._replacement(sp, text[sp.start:sp.end], rec))
            self.counts[sp.kind] += 1
            pos = sp.end
        out.append(shift(text[pos:]))
        return "".join(out)

    def _replacement(self, sp: Span, surface: str, rec) -> str:
        if sp.repl is not None:
            if rec is not None and sp.kind == "AGE":
                rec.generalized = True
            return sp.repl
        if rec is not None:
            if sp.kind == "DOB" and rec.shifter is not None:
                jittered = rec.shifter.shift_text(surface, dob=True)
                if jittered != surface:
                    rec.generalized = True
                    return jittered
            if rec.psn and sp.kind == "MRN" and rec.owns_id(surface):
                rec.used = True
                return rec.psn
            if rec.psn and sp.kind == "PATIENT" and rec.owns_name(surface, sp.src):
                rec.used = True
                return rec.psn
        return PLACEHOLDER.get(sp.kind, "[REDACTED]")


_CAP_SEQ = re.compile(r"(?<![A-Za-z])([A-Z][a-z]{1,20}(?:[ \t]+[A-Z][a-z]{1,20}){1,3})(?![A-Za-z])")
_NOT_NAME_WORDS = L.CLINICAL_WORDS | L.REGION_WORDS | L.COMPLAINT_WORDS | {
    "mob", "mobile", "phone", "ph", "contact", "call", "callback", "tel", "reg", "no", "number", "address", "the",
    "village", "tehsil", "district", "distt", "pin", "code", "house", "near", "opp", "behind", "road", "street",
    "koi", "problem", "please", "kindly", "thanks", "thank", "regards", "dear", "sir", "madam", "hello", "hi",
    "multispeciality", "charitable", "seva", "sadan", "jeevan", "jyoti", "sanjeevani", "arogya", "city",
    "lifeline", "pathkind", "trip", "from", "to", "via", "en", "route", "oxygen", "given", "billing", "query",
    "came", "visited", "called", "informed", "spoke", "attended", "brought", "relative", "guardian", "husband",
    "wife", "son", "daughter", "father", "mother", "brother", "sister", "friend", "neighbour", "neighbor"}


def _phone_proximity_names(text: str, spans: list[Span]) -> list[Span]:
    """A capitalised 2-4 word sequence on the same line as a phone / Aadhaar / email is a person
    (attendant, caller, visitor), unless every word is known non-name vocabulary. This finds names
    that are in no list at all (canaries)."""
    anchors = [s for s in spans if s.kind in ("PHONE", "AADHAAR", "EMAIL", "PHONE_MASKED")]
    if not anchors:
        return []
    out = []
    for a in anchors:
        ls = text.rfind("\n", 0, a.start) + 1
        le = text.find("\n", a.end)
        le = len(text) if le < 0 else le
        for m in _CAP_SEQ.finditer(text, ls, le):
            # trim known non-name words from both edges ("Visitor Ngurthansanga Hmar" -> the name)
            toks = list(re.finditer(r"[A-Za-z]+", m.group(1)))
            while toks and toks[0].group(0).lower() in _NOT_NAME_WORDS:
                toks.pop(0)
            while toks and toks[-1].group(0).lower() in _NOT_NAME_WORDS:
                toks.pop()
            if len(toks) < 2 or any(t.group(0).lower() in _NOT_NAME_WORDS for t in toks):
                continue
            base = m.start(1)
            out.append(Span(base + toks[0].start(), base + toks[-1].end(), "PATIENT", 1, src="proximity"))
    return out


def _fold_key(s: str) -> str:
    from .textnorm import fold
    return fold(s)


def _resolve(spans: list[Span], protected: list[tuple[int, int]]) -> list[Span]:
    def overlaps_protected(sp: Span) -> bool:
        return any(sp.start < pe and ps < sp.end for ps, pe in protected)

    kept = [sp for sp in spans if sp.kind in HARD or sp.kind == "AGE" or not overlaps_protected(sp)]
    kept.sort(key=lambda s: (-s.prio, -(s.end - s.start), s.start))
    chosen: list[Span] = []
    for sp in kept:
        if all(sp.end <= c.start or sp.start >= c.end for c in chosen):
            chosen.append(sp)
    chosen.sort(key=lambda s: s.start)
    return chosen
