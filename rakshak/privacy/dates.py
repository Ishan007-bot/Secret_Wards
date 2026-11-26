"""Format-preserving date shifting.

Every date of one patient moves by the same secret number of days, so intervals and length of stay
are exact. The output keeps the input's exact textual format (separators, 2/4-digit year, month
names, time and timezone suffix, Devanagari digits).

Day-first vs month-first is decided per file by evidence (a component > 12, header hints such as
"MM/DD/YYYY"), then by the vote of other files from the same hospital system, then day-first.
"""
from __future__ import annotations

import datetime as dt
import re

from ..detect.textnorm import ascii_digits
from ..policy import POLICY
from ..secure.secret import keyed_int

_MONTHS = ["january", "february", "march", "april", "may", "june", "july", "august", "september", "october",
           "november", "december"]
_MON_RX = r"(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|June?|July?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|" \
          r"Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)"

# numeric: 12/04/1977, 12-04-1977, 12.04.1977, 30/05/26 ; ISO: 1977-04-12 (+ optional time part)
RX_YMD = re.compile(r"(?<![\d./-])(\d{4})([/.])(\d{1,2})\2(\d{1,2})(?![\d])")   # 1977/04/12, 1977.04.12
_HI_MONTHS = ["जनवरी", "फरवरी", "मार्च", "अप्रैल", "मई", "जून", "जुलाई", "अगस्त", "सितंबर", "अक्टूबर", "नवंबर", "दिसंबर"]
_HI_ALT = {"फ़रवरी": 2, "सितम्बर": 9, "अक्तूबर": 10, "नवम्बर": 11, "दिसम्बर": 12, "अप्रेल": 4}
RX_DMONY_HI = re.compile(r"(?<![\d])(\d{1,2})[ 	]+(" + "|".join(sorted(_HI_MONTHS + list(_HI_ALT), key=len, reverse=True))
                         + r")(?:[ 	,]+(\d{4}))?")
RX_ISO = re.compile(r"(?<![\d])(\d{4})-(\d{2})-(\d{2})(?![\d])")
RX_NUM = re.compile(r"(?<![\d./-])(\d{1,2})([/.-])(\d{1,2})\2(\d{4}|\d{2})(?![\d])")
RX_DMONY = re.compile(rf"(?<![A-Za-z\d])(\d{{1,2}})(?:st|nd|rd|th)?([\s-]){_MON_RX}\.?(?:\2(\d{{4}}))?(?![A-Za-z])", re.I)
RX_MONDY = re.compile(rf"(?<![A-Za-z\d]){_MON_RX}\.?\s(\d{{1,2}})(?:st|nd|rd|th)?,?\s(\d{{4}})(?![\d])", re.I)

_DEVA_OUT = str.maketrans("0123456789", "०१२३४५६७८९")


def _mon_index(name: str) -> int:
    n = name.lower()[:3]
    for i, m in enumerate(_MONTHS):
        if m.startswith(n):
            return i + 1
    return 0


def _valid(y: int, m: int, d: int) -> bool:
    try:
        dt.date(y, m, d)
        return True
    except ValueError:
        return False


def _year(y: str) -> int:
    v = int(y)
    return v + (2000 if v < 50 else 1900) if len(y) == 2 else v


def order_evidence(text: str) -> tuple[int, int]:
    """(day-first evidence, month-first evidence) from unambiguous numeric dates."""
    dmy = mdy = 0
    for m in RX_NUM.finditer(ascii_digits(text)):
        a, b = int(m.group(1)), int(m.group(3))
        if a > 12 and b <= 12:
            dmy += 1
        elif b > 12 and a <= 12:
            mdy += 1
    if re.search(r"mm\W?dd\W?yy", text, re.I):
        mdy += 5
    if re.search(r"dd\W?mm\W?yy", text, re.I):
        dmy += 5
    return dmy, mdy


class Shifter:
    """Shifts all dates inside one record by that record's (patient's) secret offset."""

    def __init__(self, cluster_key: str | None, month_first: bool):
        self.month_first = month_first
        self.days = shift_days(cluster_key) if cluster_key else 0
        self.dob_days = dob_jitter_days(cluster_key) if cluster_key else 0

    def shift_text(self, text: str, dob: bool = False) -> str:
        days = self.dob_days if dob else self.days
        if not days or not text:
            return text
        return shift_all(text, days, self.month_first)


def shift_days(key: str) -> int:
    lo, hi = int(POLICY["date_shift_min_days"]), int(POLICY["date_shift_max_days"])
    return _signed(keyed_int("shift", key), lo, hi)


def dob_jitter_days(key: str) -> int:
    lo, hi = int(POLICY["dob_jitter_min_days"]), int(POLICY["dob_jitter_max_days"])
    return _signed(keyed_int("dob", key), lo, hi)


def _signed(n: int, lo: int, hi: int) -> int:
    mag = lo + (n >> 1) % (hi - lo + 1)
    return mag if n & 1 else -mag


def _shift_date(y: int, m: int, d: int, days: int) -> dt.date | None:
    try:
        return dt.date(y, m, d) + dt.timedelta(days=days)
    except (ValueError, OverflowError):
        return None


def shift_all(text: str, days: int, month_first: bool) -> str:
    """Shift every recognisable date in text by `days`, keeping each one's exact format."""
    deva = bool(re.search(r"[०-९]", text))
    norm = ascii_digits(text)
    edits: list[tuple[int, int, str]] = []

    def add(s, e, new):
        if not any(s < pe and ps < e for ps, pe, _ in edits):
            edits.append((s, e, new))

    for m in RX_ISO.finditer(norm):
        nd = _shift_date(int(m.group(1)), int(m.group(2)), int(m.group(3)), days)
        if nd:
            add(m.start(), m.end(), f"{nd.year:04d}-{nd.month:02d}-{nd.day:02d}")
    for m in RX_YMD.finditer(norm):
        y, sep, mo_s, d_s = int(m.group(1)), m.group(2), m.group(3), m.group(4)
        if not _valid(y, int(mo_s), int(d_s)):
            continue
        nd = _shift_date(y, int(mo_s), int(d_s), days)
        if nd:
            add(m.start(), m.end(), f"{nd.year:04d}{sep}{nd.month:0{len(mo_s)}d}{sep}{nd.day:0{len(d_s)}d}")
    for m in RX_DMONY_HI.finditer(norm):
        mo = _HI_ALT.get(m.group(2)) or _HI_MONTHS.index(m.group(2)) + 1
        y = int(m.group(3)) if m.group(3) else 2001
        nd = _shift_date(y, mo, int(m.group(1)), days)
        if nd:
            out = f"{nd.day} {_HI_MONTHS[nd.month - 1]}"
            if m.group(3):
                out += norm[m.end(2):m.start(3)] + f"{nd.year:04d}"
            add(m.start(), m.end(), out)
    for m in RX_NUM.finditer(norm):
        a, sep, b, ys = m.group(1), m.group(2), m.group(3), m.group(4)
        y = _year(ys)
        first, second = (b, a) if month_first else (a, b)       # (day, month)
        d, mo = int(first), int(second)
        if not _valid(y, mo, d):
            d, mo = mo, d                                        # the other order is the only valid one
            if not _valid(y, mo, d):
                continue
            swapped = True
        else:
            swapped = False
        nd = _shift_date(y, mo, d, days)
        if not nd:
            continue
        mf = month_first != swapped
        p1, p2 = (nd.month, nd.day) if mf else (nd.day, nd.month)
        w1, w2 = len(a), len(b)
        out_y = f"{nd.year % 100:02d}" if len(ys) == 2 else f"{nd.year:04d}"
        add(m.start(), m.end(), f"{p1:0{w1}d}{sep}{p2:0{w2}d}{sep}{out_y}")
    for m in RX_DMONY.finditer(norm):
        d = int(m.group(1))
        mon_txt = re.search(_MON_RX, m.group(0), re.I).group(0)
        mo = _mon_index(mon_txt)
        y = int(m.group(3)) if m.group(3) else 2001  # yearless: shift within a neutral year
        nd = _shift_date(y, mo, d, days)
        if not nd:
            continue
        mon_out = _month_like(mon_txt, nd.month)
        sep = m.group(2)
        ordm = re.match(r"\d{1,2}(st|nd|rd|th)", m.group(0), re.I)     # keep "12th" style ordinals
        day = f"{nd.day}{_ordinal(nd.day, ordm.group(1))}" if ordm else f"{nd.day}"
        mid = m.group(0)[ordm.end() if ordm else len(m.group(1)):m.start(2) - m.start()] if False else ""
        out = f"{day}{mid}{sep}{mon_out}" + (f"{sep}{nd.year:04d}" if m.group(3) else "")
        add(m.start(), m.end(), out)
    for m in RX_MONDY.finditer(norm):
        mon_txt = re.match(_MON_RX, m.group(0), re.I).group(0)
        nd = _shift_date(int(m.group(2)), _mon_index(mon_txt), int(m.group(1)), days)
        if nd:
            comma = "," if "," in m.group(0) else ""
            ordm = re.search(r"\d(st|nd|rd|th)", m.group(0), re.I)
            day = f"{nd.day}{_ordinal(nd.day, ordm.group(1))}" if ordm else f"{nd.day}"
            add(m.start(), m.end(), f"{_month_like(mon_txt, nd.month)} {day}{comma} {nd.year:04d}")

    if not edits:
        return text
    edits.sort()
    out, pos = [], 0
    for s, e, new in edits:
        out.append(text[pos:s])
        out.append(new.translate(_DEVA_OUT) if deva and re.search(r"[०-९]", text[s:e]) else new)
        pos = e
    out.append(text[pos:])
    return "".join(out)


def _ordinal(day: int, template: str) -> str:
    suf = "th" if 10 <= day % 100 <= 20 else {1: "st", 2: "nd", 3: "rd"}.get(day % 10, "th")
    return suf.upper() if template.isupper() else suf


def _month_like(template: str, month: int) -> str:
    """Render a month in the same style as the template (full/abbreviated, case)."""
    full = _MONTHS[month - 1]
    t = template.rstrip(".")
    name = full if len(t) > 3 else full[:3]
    if t.isupper():
        return name.upper()
    if t[:1].isupper():
        return name.capitalize()
    return name


def parse_one(value: str, month_first: bool) -> dt.date | None:
    """Parse a single date value (for DOB evidence); None if not a date."""
    v = ascii_digits(str(value)).strip()
    m = RX_YMD.search(v)
    if m and _valid(int(m.group(1)), int(m.group(3)), int(m.group(4))):
        return dt.date(int(m.group(1)), int(m.group(3)), int(m.group(4)))
    m = RX_ISO.search(v)
    if m and _valid(int(m.group(1)), int(m.group(2)), int(m.group(3))):
        return dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    m = RX_NUM.search(v)
    if m:
        a, b, y = int(m.group(1)), int(m.group(3)), _year(m.group(4))
        d, mo = (b, a) if month_first else (a, b)
        if _valid(y, mo, d):
            return dt.date(y, mo, d)
        if _valid(y, d, mo):
            return dt.date(y, d, mo)
    return None
