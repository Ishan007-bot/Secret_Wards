"""Name-agnostic token features for the CRF tagger, shared by training and inference (no skew).

The model never sees the identity of a capitalised or unknown word: only its shape, script, length,
a few gazetteer/lexicon flags, a short list of name-typical morphemes, and the identity of
neighbouring words *only when they belong to a fixed, non-personal context vocabulary* (labels,
honorifics, relation markers, function words, Hinglish particles, clinical words). This is what
lets it generalise to names it has never seen (canaries) and makes it impossible to memorise or
leak any practice name.
"""
from __future__ import annotations

import re

from ..detect import lexicon as L
from ..link.translit import deva_to_latin

TOKEN_RX = re.compile(r"[A-Za-z]+(?:['’][A-Za-z]+)?|[ऀ-ॣ०-ॿ]+|\d+|[^\s]")
_DEVA = re.compile(r"[ऀ-ॿ]")
_PHONE_LINE = re.compile(r"(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{2}[\s-]?\d{2}[\s-]?\d{5}(?!\d)|[6-9]\d{4}[\s-]?\d{5}")

# fixed, non-personal context vocabulary (lower-case). Audited by tools/audit_repo.py.
CONTEXT_VOCAB = frozenset("""
name names patient patients pt pts naam mareez mariz rogi father husband mother wife son daughter guardian
attendant attendants relative relatives relation brother sister uncle aunty informant caller visitor visitors
contact contacts mob mobile phone ph tel no number address addr add village gram gaon vill mohalla ward bed
house h makan near opp opposite behind beside next road lane gali street colony nagar post po tehsil district
distt jila state pin pincode dr doctor consultant surgeon physician by called seen referred reviewed witnessed
raised informed accompanied age sex yrs yr years year y m f male female gender uhid mrn ip ipd opd reg id
registration date dob birth s d w c o of and the with to in for at on is was has had by from a an his her he
she they patient's mr mrs ms smt shri sri kumari baby master late ka ki ke ko ne se hai hain tha thi mein aur
wala wali wale bhi ji sahab saheb behenji bhai bhaiya chachu chacha mama papa amma didi dada dadi nana nani
bhabhi beta beti baba sir madam came come brought admitted discharged complaint complaints c/o k/c/o h/o
fever pain cough history diagnosis advice tab cap inj syp mg ml od bd tds hs sos x days day weeks months
hospital clinic report lab test result note notes nursing summary visit follow up review stable condition
forwarded attachment message msg pm am
नाम मरीज़ मरीज रोगी पिता पति पत्नी माता पुत्र पुत्री बेटा बेटी पता ग्राम गाँव गांव मोहल्ला वार्ड मकान नं पास
का की के को ने से है हैं था थी में और जी श्री श्रीमती डॉ डॉक्टर उम्र आयु वर्ष तहसील जिला
""".split())

NAME_MORPHEMES = ("esh", "endra", "ita", "preet", "deen", "uddin", "kumar", "ansh", "jeet", "inder", "want",
                  "vati", "wati", "ini", "eem", "ima", "ana", "ika", "ali", "aan", "ain", "esha", "ish",
                  "raj", "lal", "nath", "jit", "dev", "deep", "pal", "bir", "ram", "ina", "een")
_MORPH_IDX = {m: i for i, m in enumerate(NAME_MORPHEMES)}
_FIRST = frozenset(L.FIRST_NAMES)
_SUR = frozenset(L.SURNAMES)
_CLIN = frozenset(L.CLINICAL_WORDS)
_HON_A = frozenset(h.lower() for h in L.HONORIFICS_AFTER)
_HON_B = frozenset(h.lower().rstrip(".") for h in L.HONORIFICS_BEFORE)
_REGION = frozenset(L.REGION_WORDS)
_REL = frozenset({"s/o", "d/o", "w/o", "c/o", "पुत्र", "पुत्री", "पत्नी", "पति", "पिता", "माता"})
_LABEL_NAME = frozenset({"name", "naam", "patient", "pt", "mareez", "mariz", "rogi", "नाम", "मरीज़", "मरीज", "रोगी"})
_LABEL_REL = frozenset({"father", "husband", "mother", "wife", "guardian", "attendant", "relative", "informant",
                        "पिता", "पति", "पत्नी", "माता", "son", "daughter", "brother", "sister", "caller",
                        "visitor"})
_LABEL_ADDR = frozenset({"address", "addr", "village", "gram", "gaon", "vill", "mohalla", "पता", "ग्राम", "गाँव",
                         "गांव", "मोहल्ला", "house", "makan", "मकान"})
_LABEL_DOC = frozenset({"dr", "doctor", "consultant", "surgeon", "physician", "डॉ", "डॉक्टर"})


def tokenize(text: str) -> list[tuple[int, int, str]]:
    return [(m.start(), m.end(), m.group(0)) for m in TOKEN_RX.finditer(text)]


def _shape(w: str) -> str:
    if _DEVA.match(w):
        return "D"
    if w.isdigit():
        return "d" if len(w) < 4 else "dddd"
    if not w[0].isalnum():
        return w[0]
    s = re.sub(r"[A-Z]+", "X", re.sub(r"[a-z]+", "x", w))
    return s[:4]


def _lex(w: str) -> str:
    """The word itself if it is in the fixed non-personal vocabulary, else its shape."""
    lw = w.lower()
    if lw in CONTEXT_VOCAB:
        return lw
    if not w[0].isalnum() and len(w) == 1:
        return w
    return "~" + _shape(w)


def _gaz(w: str) -> tuple[bool, bool]:
    lw = w.lower()
    if _DEVA.match(w):
        lw = deva_to_latin(w).lower()
    return lw in _FIRST, lw in _SUR


def _len_bucket(n: int) -> str:
    return "1" if n == 1 else "2" if n == 2 else "3" if n == 3 else "4-5" if n <= 5 else "6-8" if n <= 8 else "9+"


def sent_features(text: str, toks: list[tuple[int, int, str]]) -> list[list[str]]:
    """Feature strings for every token of one text segment."""
    words = [t[2] for t in toks]
    n = len(words)
    lex = [_lex(w) for w in words]
    shp = [_shape(w) for w in words]
    gaz = [_gaz(w) for w in words]
    # line-level cues
    line_of, line_phone, label_cls, after_colon = [], {}, [], []
    line_starts = [0] + [m.end() for m in re.finditer(r"\n", text)]
    import bisect
    for s, _, _ in toks:
        line_of.append(bisect.bisect_right(line_starts, s) - 1)
    for li in set(line_of):
        a = line_starts[li]
        b = line_starts[li + 1] if li + 1 < len(line_starts) else len(text)
        line_phone[li] = bool(_PHONE_LINE.search(text[a:b]))
    cls, pos = "none", 0
    cur_line = -1
    for i, w in enumerate(words):
        if line_of[i] != cur_line:
            cur_line, cls, pos = line_of[i], "none", 0
        if w == ":" or w == "-" and i > 0 and words[i - 1].lower() in (_LABEL_NAME | _LABEL_REL | _LABEL_ADDR):
            prev = [x.lower() for x in words[max(0, i - 3):i]]
            if any(p in _LABEL_REL for p in prev):
                cls = "rel"
            elif any(p in _LABEL_NAME for p in prev):
                cls = "name"
            elif any(p in _LABEL_ADDR for p in prev):
                cls = "addr"
            elif any(p in _LABEL_DOC for p in prev):
                cls = "doc"
            else:
                cls = "other"
            pos = 0
            label_cls.append(cls)
            after_colon.append(0)
            continue
        if w in (",", ";", "|", "(", ")") and cls != "none":
            pos += 5
        label_cls.append(cls)
        pos += 1
        after_colon.append(pos)
    out = []
    for i, w in enumerate(words):
        lw = w.lower()
        f = ["b", "sh=" + shp[i], "len=" + _len_bucket(len(w)), "lex=" + lex[i]]
        if w[0].isupper():
            f.append("title")
        if w.isupper() and len(w) > 1:
            f.append("upper")
        if _DEVA.match(w):
            f.append("deva")
        fi, su = gaz[i]
        if fi:
            f.append("gaz_first")
        if su:
            f.append("gaz_sur")
        if lw in _CLIN:
            f.append("clin")
        if lw in _HON_A:
            f.append("hon_after")
        if lw in _HON_B:
            f.append("hon_before")
        if lw in _REGION:
            f.append("region")
        best = None
        for k in range(2, 6):                      # same choice as "first NAME_MORPHEMES entry that matches"
            m = lw[-k:]
            if len(m) == k and m in _MORPH_IDX and len(lw) > k + 1 and (best is None or _MORPH_IDX[m] < _MORPH_IDX[best]):
                best = m
        if best:
            f.append("morph=" + best)
        f.append("lab=" + label_cls[i])
        f.append("pos=" + str(min(after_colon[i], 6)))
        if line_phone.get(line_of[i]):
            f.append("line_phone")
        for d in (-2, -1, 1, 2):
            j = i + d
            if 0 <= j < n:
                f.append(f"lex{d}=" + lex[j])
                if d in (-1, 1):
                    f.append(f"sh{d}=" + shp[j])
                    if words[j][0].isupper():
                        f.append(f"title{d}")
                    if gaz[j][0]:
                        f.append(f"gaz_first{d}")
                    if gaz[j][1]:
                        f.append(f"gaz_sur{d}")
                    if words[j].lower() in _REL:
                        f.append(f"rel{d}")
                    if line_of[j] != line_of[i]:
                        f.append(f"nl{d}")
            else:
                f.append(f"edge{d}")
        if i > 0 and words[i - 1] == "." and i > 1 and words[i - 2].lower() in _LABEL_DOC:
            f.append("after_dr")
        if i > 0 and words[i - 1].lower() in _LABEL_DOC:
            f.append("after_dr")
        out.append(f)
    return out
