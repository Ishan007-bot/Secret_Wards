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
from ..policy import POLICY
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
    "VILLAGE": "[LOCATION]", "PIN": "[PIN]", "DOB": "[DOB]", "NAME": "[NAME]",
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
    ("PHONE", r"(?<![\d+])(?:(?:\+|00)?91[\s.-]?|0)?[6-9]\d(?:[\s.-]?\d){8}(?![\d.]\d)", 0),
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
            r"Husband|Wife|Father|Mother|Son|Daughter|Brother|Sister|Pati|Pita|Mata|"
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
RX_LANDLINE = re.compile(r"(?<![A-Za-z])(?:Tel(?:ephone)?|Landline|Ph(?:one)?|Contact|Mob(?:ile)?|Fax)\.?\s*"
                         r"(?:No\.?|Number)?\s*[:：\-–]?\s*(\(?0\d{2,4}\)?[\s-]?\d{6,8})(?!\d)", re.I)
RX_ID_LABEL_LOOSE = re.compile(r"(?<![A-Za-z])(?:(?:UHID|MRN|Regn|Registration)\.?[ \t]*(?:No\.?|Number|#|ID)?|"
                               r"(?:Reg|IPD?|OPD?|CR|Policy|Card|Member|Beneficiary|File|Case|Ref(?:erence)?|Folio|"
                               r"Unique)\.?[ \t]*(?:No\.?|Number|#|ID)(?![A-Za-z]))[ \t]*[:：\-–#]?[ \t]*"
                               r"(?=[A-Za-z0-9/\-]*\d)", re.I)
RX_HONORIFIC_NAME = re.compile(r"(?<![A-Za-z])(?:Smt|Shri|Sh|Shrimati|Sushri|Kumari|Km|Mr|Mrs|Ms|Miss|Late|Master|Baby)\.?"
                               r"[ \t]+((?:[A-Z][a-z]+|[A-Z]\.)(?:[ \t]+(?:[A-Z][a-z]+|[A-Z]\.)){0,3})")
RX_HONORIFIC_DEVA = re.compile(rf"(?<![{DEVA}])(?:श्रीमती|श्री|सुश्री|कुमारी|स्व\.)[ \t]+([{DEVA}]+(?:[ \t]+[{DEVA}]+){{0,2}})")
_INSTITUTION_AFTER = re.compile(r"^[^\n]{0,40}?\b(?:Hospital|Clinic|Nursing|Medical|Trust|Memorial|Charitable|College|"
                                r"Institute|Centre|Center|Pharmacy|Diagnostics|Labs?|अस्पताल|चिकित्सालय)\b", re.I)
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


_GEN_AFTER = re.compile(r"[ 	]+(?:Kumar|Kumari|Singh|Devi|Kaur|Lal|Prasad|Bano|Begum|Khatoon|Khatun|Bibi|Rani|"
                        r"Nath|Chand|Das|KUMAR|SINGH|DEVI|KAUR)(?![\wऀ-ॿ])")
_HON_AFTER = re.compile(r"[ 	]+(?:%s)(?![\wऀ-ॿ])" % "|".join(
    re.escape(h) for h in sorted(L.HONORIFICS_AFTER, key=len, reverse=True)), re.I)


class Engine:
    def __init__(self, vault: Vault | None = None):
        self.vault = vault or Vault()
        self.counts: Counter = Counter()
        self.src_counts: Counter = Counter()      # spans removed per detection layer (counts only)

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
            elif kind == "NAME":
                self.vault.add_name(value, "RELATIVE")

    def _label_values(self, text: str):
        for kind, (s, e) in self._label_spans(text):
            if kind in ("PATIENT", "RELATIVE", "MRN", "ADDRESS", "VILLAGE", "NAME"):
                yield kind, text[s:e]

    # ------------------------------------------------------------------ pass 2: find spans
    def find(self, text: str, crf: bool = True) -> list[Span]:
        if not text:
            return []
        cv = self.vault.compiled()
        cache = self.__dict__.setdefault("_find_cache", {})
        if cache.get("__cv__") is not cv:            # the vault changed: results may differ
            cache.clear()
            cache["__cv__"] = cv
        key = (text, crf)
        hit = cache.get(key)
        if hit is None:
            if len(cache) > 200000:
                cache.clear()
                cache["__cv__"] = cv
            hit = cache[key] = self._find(text, crf)
        return list(hit)

    def _find(self, text: str, crf: bool = True) -> list[Span]:
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

        for s, e, kind, src in cv.matches(text):                         # L2 (token index)
            add(Span(s, e, kind, 1 if src == "vault_tok" else 2, src=src))

        for kind, value_span in self._label_spans(text):                  # L3
            add(Span(value_span[0], value_span[1], kind, 2, src="label"))
        for rx in [RX_AGE_LABEL] + RX_AGE_FORMS:
            for m in rx.finditer(norm):
                band = band_text(m.group(1))
                if band:
                    add(Span(m.start(1), m.end(1), "AGE", 2, band, src="age"))

        protected = [(m.start(), m.end()) for rx in _PROTECT for m in rx.finditer(text)]   # L5
        spans.extend(_phone_proximity_names(text, spans))                                 # L3b
        if crf and POLICY.get("ml_tagger") == "on":                                       # L4 (CRF)
            spans.extend(_crf_spans(text))
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
                    tail = _SURNAME_FIRST.match(text, m.end() + e)
                    if tail and (val.isupper() or len(val.split()) == 1) and tail.group(1).lower() not in \
                            L.CLINICAL_WORDS | L.REGION_WORDS:
                        e = tail.end() - m.end()                  # "KUMAR, RAMESH" / "Sharma, Anita"
                    yield kind, (m.end() + s, m.end() + e)
        for m in RX_RELATION.finditer(text):
            marker = m.group(0)[:3].lower()
            if _relation_ok(marker, m.group(1)):
                end = m.end(1)
                stop = _SENTENCE_END.search(m.group(1))       # "C/O Ravi Kumar. ICD-10 ..." ends at the full stop
                if stop:
                    end = m.start(1) + stop.start()
                yield "RELATIVE", (m.start(1), end)
        for m in RX_RELATION_DEVA.finditer(text):
            toks = m.group(1).split()
            if toks and not any(t in _HINDI_FUNCTION_WORDS for t in toks):
                yield "RELATIVE", (m.start(1), m.end(1))
        for m in RX_ID_LABEL.finditer(text):
            v = re.match(r"[A-Za-z0-9](?:[A-Za-z0-9/_.\-]|:(?=[A-Za-z0-9]))*", text[m.end():])
            if v and re.search(r"\d", v.group(0)):
                yield "MRN", (m.end(), m.end() + len(v.group(0).rstrip(".-/")))
        for m in RX_ID_LABEL_LOOSE.finditer(text):             # "Reg No. 2026/OPD/00456", "IP No 26/1234"
            v = re.match(r"[A-Za-z0-9](?:[A-Za-z0-9/_\-]|[.:](?=[A-Za-z0-9]))*", text[m.end():])
            if v and len(re.findall(r"\d", v.group(0))) >= 4 and not _NOT_PATIENT_ID_LABEL.search(m.group(0)):
                yield "MRN", (m.end(), m.end() + len(v.group(0)))
        for m in RX_LANDLINE.finditer(text):
            yield "PHONE", (m.start(1), m.end(1))
        for rx in (RX_HONORIFIC_NAME, RX_HONORIFIC_DEVA):                # "Smt. Kamla Devi", "श्रीमती कमला"
            for m in rx.finditer(text):
                if _INSTITUTION_AFTER.match(text[m.start(1):m.start(1) + 60]):
                    continue                                          # "Shri Ram Hospital" is a place
                words = re.findall(r"[A-Za-z]+|[ऀ-ॿ]+", m.group(1))
                if all(w.lower() in L.CLINICAL_WORDS or w.lower() in L.REGION_WORDS for w in words):
                    continue
                end = m.end(1)
                toks = list(re.finditer(r"\S+", m.group(1)))
                for i, t in enumerate(toks):                 # "कमला देवी को ...": the name stops before को
                    if t.group(0) in _HINDI_FUNCTION_WORDS:
                        toks = toks[:i]
                        break
                if not toks:
                    continue
                end = m.start(1) + toks[-1].end()
                yield "NAME", (m.start(1), end)
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
            lbl = m.group(0).rstrip()
            if lbl.endswith(".") and not re.match(r"vill\.", lbl, re.I):
                continue  # "... of the village. TDS 0-0-1": a sentence end, not a label
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
        for i, sp in enumerate(spans):
            if sp.start < pos:
                continue
            out.append(shift(text[pos:sp.start]))
            out.append(self._replacement(sp, text[sp.start:sp.end], rec))
            self.counts[sp.kind] += 1
            self.src_counts[_LAYER.get(sp.src, sp.src)] += 1
            pos = sp.end
            if sp.kind in ("PATIENT", "RELATIVE"):
                # "Ojas Bhaiya", "Charvi ji": the kinship/honorific word is part of the name mention
                m = _HON_AFTER.match(text, pos) or _GEN_AFTER.match(text, pos)
                if m and (i + 1 >= len(spans) or spans[i + 1].start >= m.end()):
                    pos = m.end()
        out.append(shift(text[pos:]))
        return "".join(out)

    def _replacement(self, sp: Span, surface: str, rec) -> str:
        if sp.kind == "ADDRESS" and sp.src == "label":
            return _generalise_address(surface)
        if sp.repl is not None:
            if rec is not None and sp.kind == "AGE":
                rec.generalized = True
                if rec.age_width:
                    return band_text(surface, rec.age_width) or sp.repl
            return sp.repl
        if rec is not None:
            if sp.kind == "DOB" and rec.shifter is not None and POLICY["dob_mode"] == "jitter":
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


_ADDR_SPLIT = re.compile(r"(\s*[,;|]\s*|\s+-\s+)")
_ADDR_REGION_PREFIX = re.compile(r"^(?:jila|zila|district|distt?\.?|dist\.?|state|जिला|ज़िला)\s*[:.]?\s*", re.I)


def _generalise_address(value: str) -> str:
    """Address line -> house / locality / village / tehsil removed, district and state kept (they are
    released on purpose, location_level: district), PIN cut to its prefix. Fails closed."""
    out = []
    for part in _ADDR_SPLIT.split(value):
        if not part or _ADDR_SPLIT.fullmatch(part):
            out.append(part)
            continue
        core = part.strip(" .")
        d = ascii_digits(core)
        if re.fullmatch(r"\d{6}", d):
            n = int(POLICY["pin_prefix_digits"])
            out.append(d[:n] + "*" * (6 - n))
            continue
        rest = _ADDR_REGION_PREFIX.sub("", core)
        words = re.findall(r"[A-Za-z]+|[ऀ-ॿ]+", rest)
        if words and not re.search(r"\d", rest) and all(_region_word(w) for w in words):
            out.append(part)
            continue
        out.append("[ADDRESS]")
    text = "".join(out)
    return re.sub(r"\[ADDRESS\](?:\s*(?:[,;|]|\s-)\s*\[ADDRESS\])+", "[ADDRESS]", text)


def _region_word(w: str) -> bool:
    if is_devanagari(w):
        from ..link.translit import deva_to_latin
        w = deva_to_latin(w)
    return w.lower() in L.REGION_WORDS


_SENTENCE = re.compile(r"[a-zऀ-ॿ]{3,}")
_SURNAME_FIRST = re.compile(r",[ \t]*([A-Z][A-Za-z]+|[A-Z]+)(?=[ \t]*(?:$|[\n,;|(]|[ \t]{2}))", re.M)
_SENTENCE_END = re.compile(r"(?<=[a-z]{3})\.(?=[ 	])")
_THE_BEFORE = re.compile(r"\b(?:the|of|this|that|our|same)\s+$", re.I)
_LAYER = {"pattern": "L1_patterns", "shape": "L1_learned_id_shapes", "digits": "L2_vault_identifiers",
          "vault_full": "L2_vault_names", "vault_tok": "L2_vault_names", "vault_text": "L2_vault_addresses",
          "label": "L3_context_rules", "age": "L3_age_bands", "proximity": "L3_phone_proximity",
          "crf": "L4_crf_tagger"}
_DOC_WORDS = {"policy", "claim", "card", "scheme", "insurance", "form", "receipt", "bill", "invoice", "ticket",
              "token", "reference", "ref", "file", "case", "folio", "member", "beneficiary", "package", "amount",
              "status", "remarks", "remark", "comments", "comment", "approved", "rejected", "pending", "total"}
_CRF_KIND = {"NAME": "NAME", "ADDR": "ADDRESS"}
_DEVA_CUE = re.compile(r"(?:नाम|मरीज़?|रोगी|पिता|पति|पत्नी|माता|पुत्र|पुत्री|पता|ग्राम|गाँव|गांव|मोहल्ला|मकान|श्री|श्रीमती|"
                       r"S/o|W/o|D/o|C/O)\s*(?:का|की|के)?\s*(?:नाम)?\s*[:\-]?\s*$")


def _deva_gaz(w: str) -> bool:
    from ..link.translit import deva_to_latin
    lw = deva_to_latin(w).lower()
    return w in L.FIRST_NAMES or w in L.SURNAMES or lw in L.FIRST_NAMES or lw in L.SURNAMES


def _crf_spans(text: str) -> list[Span]:
    """Self-trained CRF (rakshak/ml): extra NAME / ADDR recall on free text, lowest priority.
    Never on structured cells (needs sentence-like text), never over protected clinical terms
    (resolved by L5), never a span made only of clinical / context words."""
    if len(text) < 20 or not _SENTENCE.search(text):
        return []
    from ..ml import tagger
    from ..ml.features import CONTEXT_VOCAB
    out = []
    for s, e, typ, _p in tagger.get().spans(text):
        words = re.findall(r"[A-Za-z]+|[ऀ-ॿ]+", text[s:e])
        if not words:
            continue
        if all(w.lower() in L.CLINICAL_WORDS or w.lower() in CONTEXT_VOCAB or w.lower() in L.REGION_WORDS
               or w.lower() in _DOC_WORDS for w in words):
            continue
        if typ == "NAME" and not any(w[0].isupper() or is_devanagari(w) for w in words):
            continue
        if _INSTITUTION_AFTER.match(text[s:e]) or _INSTITUTION_AFTER.match(text[s:s + 60]):
            continue  # "Shri Ram Hospital", "श्री राम अस्पताल": an institution, not a person or home address
        if all(is_devanagari(w) for w in words) and not (
                _DEVA_CUE.search(text[max(0, s - 40):s]) or any(_deva_gaz(w) for w in words)):
            continue  # Devanagari has no capital letters: demand a label / relation cue or a known name
        out.append(Span(s, e, _CRF_KIND.get(typ, "NAME"), 0, src="crf"))
    return out


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
