"""Identity vault: every personal value harvested from structured fields and labelled text in pass 1.

It lives in process memory only (never written to disk). Pass 2 uses it to find the same values
anywhere else: free text, keys, headers, file names, metadata, decoded attachments, and in any
spelling of separators, letter case or digit grouping.
"""
from __future__ import annotations

import re
from collections import defaultdict

from . import lexicon as L
from .textnorm import DEVA, ascii_digits, digits_only, fold, is_devanagari

_JUNK = {"", "-", "--", "na", "n/a", "nil", "none", "null", "unknown", "not known", "x", "xx", "xxx", "."}

# address fragments that are generic structure, not identifying values
_ADDR_GENERIC = re.compile(r"^(?:tehsil|distt?\.?|district|jila|zila|state|up|uttar pradesh|india|pin|pincode|"
                           r"तहसील|जिला|उत्तर प्रदेश)\b", re.I)


class Vault:
    def __init__(self):
        self.full_names: dict[str, str] = {}      # folded full name -> kind (PATIENT / RELATIVE)
        self.name_tokens: dict[str, str] = {}     # single name token (original case-folded) -> kind
        self.texts: dict[str, str] = {}           # folded address/village text -> kind
        self.digits: dict[str, str] = {}          # digit core -> kind (PHONE, AADHAAR, ABHA_NUMBER, MRN, PIN)
        self.ids: dict[str, str] = {}             # exact ID string (upper) -> kind
        self.id_shapes: set[str] = set()          # regex sources learned from ID values
        self.core_to_id: dict[str, str] = {}      # digit core -> normalised full ID ("" if ambiguous)
        self.keep: set[str] = set()               # values released on purpose (districts): never vaulted
        self._compiled = None

    # ------------------------------------------------------------------ harvesting
    def add_name(self, value: str, kind: str = "PATIENT") -> None:
        v = re.sub(r"\s+", " ", str(value)).strip(" ,.;:-()")
        if fold(v) in _JUNK or len(v) < 2 or re.search(r"\d", v):
            return
        tokens = [t for t in re.split(r"[\s_]+", v) if t]
        tokens = [t for t in tokens if t.lower().strip(".") not in L.HONORIFICS_BEFORE
                  and t.lower() not in L.HONORIFICS_AFTER]
        if not tokens:
            return
        full = fold(" ".join(tokens))
        if len(tokens) >= 2:
            self._put(self.full_names, full, kind)
            self._put(self.full_names, fold(" ".join(reversed(tokens))), kind)
        for t in tokens:
            tl = t.strip(".,").casefold()
            if len(tl) < 3 or tl in L.GENERIC_NAME_TOKENS or tl in L.CLINICAL_WORDS or tl in L.REGION_WORDS:
                continue
            self._put(self.name_tokens, tl, kind)
        self._compiled = None

    def add_text(self, value: str, kind: str) -> None:
        v = re.sub(r"\s+", " ", str(value)).strip(" ,.;:-")
        f = fold(v)
        if f in _JUNK or len(f) < 3 or f in L.REGION_WORDS or _ADDR_GENERIC.match(f):
            return
        if f.isdigit():
            return
        if re.fullmatch(r"(?:ward|bed|room|block|sector|floor|gali|lane|no)\s*\d{1,3}", f):
            return  # too generic to search globally ("Ward 4" is also a hospital ward); removed in context
        self._put(self.texts, f, kind)
        self._compiled = None

    def keep_text(self, value: str) -> None:
        self.keep.add(fold(re.sub(r"\s+", " ", str(value)).strip(" ,.;:-")))
        self._compiled = None

    def add_address(self, value: str) -> None:
        """Split a free address line into its parts and keep the identifying ones."""
        for part in re.split(r"[,;\n]| - ", str(value)):
            part = part.strip()
            if not part:
                continue
            if re.match(r"^(?:C/O|C\\O|c/o)\s+", part):
                self.add_name(re.sub(r"^(?:C/O|C\\O|c/o)\s+", "", part), "RELATIVE")
                continue
            if re.fullmatch(r"\d{6}", ascii_digits(part)):
                self.add_digits(part, "PIN")
                continue
            m = re.match(r"^(?:Vill\.?|Village|Gram|Gaon|ग्राम|गाँव|गांव)\s+(.+)$", part, re.I)
            if m:
                self.add_text(m.group(1), "VILLAGE")
                continue
            self.add_text(part, "ADDRESS")

    def add_digits(self, value, kind: str) -> None:
        d = digits_only(str(value))
        if kind == "PHONE":
            if len(d) >= 10:
                self.digits[d[-10:]] = "PHONE"
            return
        if kind == "PIN":
            if len(d) == 6:
                self.digits.setdefault(d, "PIN")
            return
        if len(d) >= 6:
            self.digits[d] = kind

    def add_id(self, value: str, kind: str = "MRN") -> None:
        v = str(value).strip()
        if fold(v) in _JUNK or not re.search(r"\d", v) or len(v) > 40:
            return
        self.ids[v.upper()] = kind
        full = re.sub(r"[^A-Z0-9]", "", ascii_digits(v).upper())
        # digit cores: the full digit string and every long digit group (the scorer matches digit cores)
        groups = re.findall(r"\d+", ascii_digits(v))
        whole = "".join(groups)
        cores = [whole] if len(whole) >= 5 else []
        cores += [g for g in groups if len(g) >= 5 or (len(g) >= 4 and g.startswith("0"))]
        for c in cores:
            self.digits.setdefault(c, kind)
            prev = self.core_to_id.get(c, full)
            self.core_to_id[c] = full if prev == full else ""   # "" = ambiguous core, never used to link
        shape = id_shape(v)
        if shape:
            self.id_shapes.add(shape)
        self._compiled = None

    @staticmethod
    def _put(store: dict, key: str, kind: str) -> None:
        # PATIENT wins over RELATIVE when the same string is both
        if store.get(key) != "PATIENT":
            store[key] = kind

    # ------------------------------------------------------------------ matching
    def compiled(self):
        if self._compiled is None:
            self._compiled = _Compiled(self)
        return self._compiled


def id_shape(value: str) -> str | None:
    """'SNJ/26/064127' -> regex 'SNJ[-/ _]?\\d{2}[-/ _]?\\d{6}' (prefix literal, digit counts, any separator)."""
    v = value.strip()
    parts = re.findall(r"[A-Za-z]+|\d+", v)
    if not parts or sum(len(p) for p in parts if p.isdigit()) < 4:
        return None
    if not parts[0].isalpha():
        return None  # pure-digit IDs are covered by digit cores
    out = []
    for p in parts:
        out.append(re.escape(p.upper()) if p.isalpha() else r"\d{%d}" % len(p))
    return r"[-/ _.:]?".join(out)


_WORD = re.compile(r"[A-Za-z0-9]+|[ऀ-ॣ०-ॿ]+")
_GAP = re.compile(r"[\s_.,\-]*")


def _alternation(words, deva: bool = False) -> str:
    words = sorted(set(words), key=lambda w: (-len(w), w))
    return "|".join(re.escape(w) for w in words)


class _Compiled:
    def __init__(self, v: Vault):
        sep = r"[\s_.,\-]+"
        # multi-token names / address texts: case-insensitive, any separator between tokens
        def multi(phrases):
            pats = []
            for p in sorted(set(phrases), key=lambda s: (-len(s), s)):
                toks = p.split(" ")
                pats.append(sep.join(re.escape(t) for t in toks))
            return pats


        # token index (linear time, independent of vault size): first word -> phrases starting with it
        self.phrases: dict[str, list] = {}
        for store, src in ((v.full_names, "vault_full"), (v.texts, "vault_text")):
            for p, kind in store.items():
                if src == "vault_text" and p in v.keep:
                    continue
                toks = tuple(t.casefold() for t in _WORD.findall(p))
                if toks:
                    self.phrases.setdefault(toks[0], []).append((toks, kind, src))
        for lst in self.phrases.values():
            lst.sort(key=lambda x: -len(x[0]))
        self.single = dict(v.name_tokens)

        shapes = sorted(v.id_shapes, key=lambda s: (-len(s), s))
        self.shape_rx = (re.compile(r"(?<![A-Za-z0-9])(?:%s)(?![A-Za-z0-9])" % "|".join(shapes), re.I)
                         if shapes else None)
        self.digits = v.digits
        self.ids = v.ids

    def matches(self, text: str) -> list[tuple[int, int, str, str]]:
        """All vault phrases (full names, address texts) and single name tokens in `text`:
        (start, end, kind, src). Words are compared case-insensitively; between the words of a phrase
        only separators (space, _, ., comma, -) may appear. Single Latin tokens must be Title/UPPER case."""
        words = [(m.start(), m.end(), m.group(0)) for m in _WORD.finditer(text)]
        low = [w[2].casefold() for w in words]
        out = []
        n = len(words)
        for i, (s, e, w) in enumerate(words):
            for toks, kind, src in self.phrases.get(low[i], ()):
                k = len(toks)
                if i + k <= n and tuple(low[i:i + k]) == toks and all(
                        _GAP.fullmatch(text, words[j][1], words[j + 1][0]) for j in range(i, i + k - 1)):
                    out.append((s, words[i + k - 1][1], kind, src))
                    break
            kind = self.single.get(low[i])
            if kind and (is_devanagari(w) or (w[0].isupper() and (w[1:].islower() or w.isupper()))):
                out.append((s, e, kind, "vault_tok"))
        return out
