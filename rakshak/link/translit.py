"""Cross-script name normalisation (team-written; no external dependency).

deva_to_latin('मोहम्मद आरिफ')  -> 'mohammad aarif'   (Hindi schwa deletion applied)
phonetic('Mohammad') == phonetic('मोहम्मद') == phonetic('Mohd')
phonetic('Fatima') ~ phonetic('Fatma'), phonetic('Reena') == phonetic('Rina')
"""
from __future__ import annotations

import re
import unicodedata
from functools import lru_cache

from ..detect import lexicon as L

_CONS = {
    "क": "k", "ख": "kh", "ग": "g", "घ": "gh", "ङ": "n", "च": "ch", "छ": "chh", "ज": "j", "झ": "jh", "ञ": "n",
    "ट": "t", "ठ": "th", "ड": "d", "ढ": "dh", "ण": "n", "त": "t", "थ": "th", "द": "d", "ध": "dh", "न": "n",
    "प": "p", "फ": "ph", "ब": "b", "भ": "bh", "म": "m", "य": "y", "र": "r", "ल": "l", "व": "v", "श": "sh",
    "ष": "sh", "स": "s", "ह": "h", "ळ": "l", "क़": "q", "ख़": "kh", "ग़": "g", "ज़": "z", "ड़": "r", "ढ़": "rh",
    "फ़": "f", "य़": "y",
}
_NUKTA_BASE = {"क": "q", "ख": "kh", "ग": "g", "ज": "z", "ड": "r", "ढ": "rh", "फ": "f"}
_VOWELS = {"अ": "a", "आ": "aa", "इ": "i", "ई": "ee", "उ": "u", "ऊ": "oo", "ऋ": "ri", "ए": "e", "ऐ": "ai",
           "ओ": "o", "औ": "au", "ऑ": "o"}
_MATRAS = {"ा": "aa", "ि": "i", "ी": "ee", "ु": "u", "ू": "oo", "ृ": "ri", "े": "e", "ै": "ai", "ो": "o",
           "ौ": "au", "ॉ": "o", "ॅ": "e"}
_VIRAMA, _NUKTA = "्", "़"
_NASAL = {"ं": "n", "ँ": "n", "ः": "h"}


def _deva_word(word: str) -> str:
    """Transliterate one Devanagari word with the standard Hindi schwa-deletion heuristic."""
    w = unicodedata.normalize("NFC", word)
    units: list[list] = []  # [latin, kind] kind: C (consonant with inherent a), V (vowel), X (other)
    i = 0
    while i < len(w):
        ch = w[i]
        nxt = w[i + 1] if i + 1 < len(w) else ""
        if ch in _CONS or ch in _NUKTA_BASE:
            lat = _CONS.get(ch, "")
            if nxt == _NUKTA and ch in _NUKTA_BASE:
                lat = _NUKTA_BASE[ch]
                i += 1
                nxt = w[i + 1] if i + 1 < len(w) else ""
            if nxt == _VIRAMA:
                units.append([lat, "c"])          # dead consonant
                i += 2
                continue
            if nxt in _MATRAS:
                units.append([lat + _MATRAS[nxt], "V"])
                i += 2
                continue
            units.append([lat, "C"])              # inherent schwa (decided below)
        elif ch in _VOWELS:
            units.append([_VOWELS[ch], "V"])
        elif ch in _NASAL:
            units.append([_NASAL[ch], "X"])
        elif ch in _MATRAS:
            units.append([_MATRAS[ch], "V"])
        elif ch not in (_VIRAMA, _NUKTA):
            units.append([ch, "X"])
        i += 1
    out = []
    n = len(units)
    for k, (lat, kind) in enumerate(units):
        if kind != "C":
            out.append(lat)
            continue
        last = k == n - 1 or all(u[1] == "X" for u in units[k + 1:])
        if last and n > 1:
            out.append(lat)                       # word-final schwa deleted
            continue
        # medial: delete schwa in V C _ C V context
        prev_vowelish = k > 0 and units[k - 1][1] in ("V", "C")
        nxt_cons = k + 1 < n and units[k + 1][1] in ("C", "c")
        nxt_has_vowel = k + 1 < n and units[k + 1][1] == "C" and k + 2 < n
        if prev_vowelish and nxt_cons and nxt_has_vowel and k > 0:
            out.append(lat)
        else:
            out.append(lat + "a")
    return "".join(out)


@lru_cache(maxsize=65536)
def deva_to_latin(text: str) -> str:
    return re.sub(r"[ऀ-ॿ]+", lambda m: _deva_word(m.group(0)), text).lower()


_VARIANTS = {"md": "mohammad", "mohd": "mohammad", "mohammed": "mohammad", "muhammad": "mohammad",
             "muhammed": "mohammad", "mohamad": "mohammad", "mahmad": "mohammad", "sk": "shaikh",
             "shekh": "shaikh", "sheikh": "shaikh", "shri": "", "smt": "", "km": "", "mr": "", "mrs": "", "ms": ""}


@lru_cache(maxsize=65536)
def phonetic(token: str) -> str:
    """Spelling-insensitive form of one name token."""
    t = deva_to_latin(token.lower()) if re.search(r"[ऀ-ॿ]", token) else token.lower()
    t = re.sub(r"[^a-z]", "", unicodedata.normalize("NFKD", t))
    t = _VARIANTS.get(t, t)
    if not t:
        return ""
    t = re.sub(r"ey$", "e", t)                     # Pandey / पांडे
    for a, b in (("aa", "a"), ("ee", "i"), ("ii", "i"), ("oo", "u"), ("uu", "u"), ("ou", "au"), ("qui", "ki"),
                 ("ph", "f"), ("w", "v"), ("z", "j"), ("q", "k"), ("ck", "k"), ("sh", "s"), ("kh", "k"),
                 ("gh", "g"), ("chh", "c"), ("ch", "c"), ("jh", "j"), ("th", "t"), ("dh", "d"), ("bh", "b"),
                 ("x", "ks"), ("y", "i"), ("ai", "e")):
        t = t.replace(a, b)
    t = re.sub(r"(.)\1+", r"\1", t)              # collapse doubled letters
    if len(t) > 3:
        t = re.sub(r"[ah]$", "", t)               # trailing schwa / h (Reena/Rina, Shah/Sha)
    return t


def skeleton(token: str) -> str:
    """Consonant skeleton for blocking: keeps the first letter, drops vowels."""
    p = phonetic(token)
    return p[:1] + re.sub(r"[aeiou]", "", p[1:]) if p else ""


_DROP = {h.lower() for h in L.HONORIFICS_AFTER + L.HONORIFICS_BEFORE} | {"", "dr"}


def name_tokens(name: str) -> tuple:
    """Phonetic tokens of a person name, honorifics removed, order-free (sorted)."""
    toks = []
    for raw in re.split(r"[\s_.,\-/]+", str(name)):
        if not raw or raw.lower() in _DROP:
            continue
        p = phonetic(raw)
        if p and p not in _DROP:
            toks.append(p)
    return tuple(sorted(toks))


def generic(tok: str) -> bool:
    return tok in _GENERIC_PHON


_GENERIC_PHON = {phonetic(t) for t in L.GENERIC_NAME_TOKENS if phonetic(t)}


@lru_cache(maxsize=262144)
def jaro_winkler(a: str, b: str) -> float:
    if a == b:
        return 1.0
    la, lb = len(a), len(b)
    if not la or not lb:
        return 0.0
    rng = max(la, lb) // 2 - 1
    am, bm = [False] * la, [False] * lb
    matches = 0
    for i in range(la):
        lo, hi = max(0, i - rng), min(lb, i + rng + 1)
        for j in range(lo, hi):
            if not bm[j] and a[i] == b[j]:
                am[i] = bm[j] = True
                matches += 1
                break
    if not matches:
        return 0.0
    t, k = 0, 0
    for i in range(la):
        if am[i]:
            while not bm[k]:
                k += 1
            if a[i] != b[k]:
                t += 1
            k += 1
    jaro = (matches / la + matches / lb + (matches - t / 2) / matches) / 3
    prefix = 0
    for x, y in zip(a[:4], b[:4]):
        if x != y:
            break
        prefix += 1
    return jaro + prefix * 0.1 * (1 - jaro)


def token_match(a: str, b: str) -> bool:
    if a == b:
        return True
    if len(a) == 1 or len(b) == 1:           # initials: "A." vs "Arif"
        return a[0] == b[0]
    # same consonant skeleton AND close spelling: Fatima/Fatma yes, Sunita/Sunil and Rina/Rana no
    sa = a[:1] + re.sub(r"[aeiou]", "", a[1:])
    sb = b[:1] + re.sub(r"[aeiou]", "", b[1:])
    return sa == sb and jaro_winkler(a, b) >= 0.85


def names_compatible(a: tuple, b: tuple) -> bool:
    """True if one name's distinctive tokens are all found in the other (order-free, spelling-tolerant)."""
    if not a or not b:
        return True
    da = [t for t in a if not generic(t)] or list(a)
    db = [t for t in b if not generic(t)] or list(b)
    short, long_ = (da, db) if len(da) <= len(db) else (db, da)
    used = set()
    for t in short:
        hit = next((i for i, u in enumerate(long_) if i not in used and token_match(t, u)), None)
        if hit is None:
            return False
        used.add(hit)
    return True


def names_equal(a: tuple, b: tuple) -> bool:
    da = [t for t in a if not generic(t)]
    db = [t for t in b if not generic(t)]
    return bool(da) and len(da) == len(db) and names_compatible(tuple(da), tuple(db))


def place_key(value: str) -> str:
    """Village / locality comparison key across scripts."""
    toks = [skeleton(t) for t in re.split(r"[\s_.,\-]+", deva_to_latin(str(value))) if t]
    return " ".join(t for t in toks if t)
