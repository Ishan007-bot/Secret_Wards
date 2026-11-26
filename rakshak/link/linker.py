"""Conservative patient linkage.

Mirrors the dataset's own definition of "must link":
  R1  a shared strong identifier (hospital ID, Aadhaar, ABHA, phone, email, insurance ID) that
      belongs to one person only (exclusivity check: never seen with an incompatible name/DOB);
  R2  the same name plus a second clue (DOB, relative's name, or village + age within 1 year)
      whose combination is not shared by two different registered people.
Every merge is checked at cluster level (DOB, gender, Aadhaar, name, age), so a chain of weak
links can never fuse two different people. When evidence is too weak the record stays alone.
"""
from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass, field

from .translit import name_tokens, names_compatible, place_key, skeleton, generic


@dataclass
class Evidence:
    rid: str                                     # stable record id: "<input rel path>|<loc>"
    ids: set = field(default_factory=set)        # normalised hospital / IPD IDs
    phones: set = field(default_factory=set)
    aadhaar: set = field(default_factory=set)
    abha: set = field(default_factory=set)
    emails: set = field(default_factory=set)
    insurance: set = field(default_factory=set)
    names: list = field(default_factory=list)    # name token tuples (strong: role or label)
    weak_names: list = field(default_factory=list)
    relatives: list = field(default_factory=list)
    dobs: set = field(default_factory=set)       # candidate ISO dates
    ages: set = field(default_factory=set)
    genders: set = field(default_factory=set)
    villages: set = field(default_factory=set)
    dx: set = field(default_factory=set)         # ICD-10 codes mentioned in the record
    districts: set = field(default_factory=set)

    def primary_name(self):
        """The name this record is mostly about (records also mention relatives and other people)."""
        if not self.names:
            return None
        best, best_score = None, None
        for n in self.names:
            support = sum(1 for m in self.names if names_compatible(n, m))
            score = (support, len(n), n)
            if best_score is None or score > best_score:
                best, best_score = n, score
        return best

    def has_identity(self) -> bool:
        return bool(self.ids or self.phones or self.aadhaar or self.abha or self.emails or self.insurance
                    or self.names or self.weak_names)

    def strong_keys(self):
        for k in sorted(self.ids):
            yield ("id", k)
        for k in sorted(self.aadhaar):
            yield ("aa", k)
        for k in sorted(self.abha):
            yield ("abha", k)
        for k in sorted(self.phones):
            yield ("ph", k)
        for k in sorted(self.emails):
            yield ("em", k)
        for k in sorted(self.insurance):
            yield ("ins", k)

    # -------------------------------------------------------------- adders
    def add_name(self, value: str, strong: bool = True) -> None:
        t = name_tokens(value)
        if t and any(not generic(x) for x in t):
            (self.names if strong else self.weak_names).append(t)

    def add_relative(self, value: str) -> None:
        t = name_tokens(value)
        if t and any(not generic(x) for x in t):
            self.relatives.append(t)

    def add_gender(self, value: str) -> None:
        v = str(value).strip().lower()
        if v in ("m", "male", "पुरुष", "पु", "man", "boy") or v.startswith("male"):
            self.genders.add("M")
        elif v in ("f", "female", "महिला", "स्त्री", "woman", "girl") or v.startswith("female"):
            self.genders.add("F")

    def add_age(self, value) -> None:
        m = re.match(r"\s*(\d{1,3})", str(value))
        if m and 0 <= int(m.group(1)) <= 125:
            self.ages.add(int(m.group(1)))

    def add_dob(self, dates: list) -> None:
        for d in dates:
            if isinstance(d, dt.date):
                self.dobs.add(d.isoformat())

    def add_village(self, value: str) -> None:
        k = place_key(value)
        if k:
            self.villages.add(k)


def norm_id(value: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", str(value).upper())


class _Cluster:
    __slots__ = ("members", "names", "dobs", "genders", "aadhaar", "ages", "strong", "keys")

    def __init__(self, ev: Evidence):
        self.members = [ev.rid]
        p = ev.primary_name()
        self.names = [p] if p else []
        self.dobs = set(ev.dobs)
        self.genders = set(ev.genders)
        self.aadhaar = set(ev.aadhaar)
        self.ages = set(ev.ages)
        self.strong = bool(ev.ids or ev.aadhaar or ev.abha)
        self.keys = sorted(f"{k}:{v}" for k, v in ev.strong_keys())


def _conflict(a: _Cluster, b: _Cluster) -> bool:
    if a.dobs and b.dobs and not (a.dobs & b.dobs):
        return True
    if a.genders and b.genders and not (a.genders & b.genders):
        return True
    if a.aadhaar and b.aadhaar and not (a.aadhaar & b.aadhaar):
        return True
    if a.ages and b.ages and (max(a.ages | b.ages) - min(a.ages | b.ages)) > 3:
        return True
    for x in a.names:
        for y in b.names:
            if not names_compatible(x, y):
                return True
    return False


class Linker:
    def __init__(self, evidence: list[Evidence]):
        self.ev = {e.rid: e for e in evidence}
        self.order = sorted(self.ev)
        self.parent = {r: r for r in self.order}
        self.cl = {r: _Cluster(self.ev[r]) for r in self.order}

    def find(self, r: str) -> str:
        while self.parent[r] != r:
            self.parent[r] = self.parent[self.parent[r]]
            r = self.parent[r]
        return r

    def _merge(self, a: str, b: str) -> bool:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return True
        ca, cb = self.cl[ra], self.cl[rb]
        if _conflict(ca, cb):
            return False
        if rb < ra:
            ra, rb, ca, cb = rb, ra, cb, ca
        self.parent[rb] = ra
        ca.members += cb.members
        ca.names += cb.names
        ca.dobs |= cb.dobs
        ca.genders |= cb.genders
        ca.aadhaar |= cb.aadhaar
        ca.ages |= cb.ages
        ca.strong = ca.strong or cb.strong
        ca.keys = sorted(set(ca.keys) | set(cb.keys))
        del self.cl[rb]
        return True

    # ------------------------------------------------------------------ R1
    def link_strong(self) -> None:
        index: dict[tuple, list[str]] = {}
        for r in self.order:
            for k in self.ev[r].strong_keys():
                index.setdefault(k, []).append(r)
        for key in sorted(index, key=lambda k: (_KEY_RANK.get(k[0], 9), k)):
            rids = index[key]
            if len(rids) < 2:
                continue
            group = self._exclusive_group(rids)
            for r in group[1:]:
                self._merge(group[0], r)

    def _exclusive_group(self, rids: list[str]) -> list[str]:
        """Records sharing a strong key that belong to ONE person.

        All named records agree -> all of them. One clear majority identity (>= 75% of the named
        records) -> that majority plus the unnamed records; the outliers stay apart. Two substantial
        identities (a couple sharing a phone) -> nobody is linked through this key."""
        named = [(r, self.ev[r].primary_name()) for r in rids]
        with_name = [(r, n) for r, n in named if n]
        unnamed = [r for r, n in named if not n]
        if not with_name:
            return self._dob_consistent(rids)
        best, best_members = None, []
        for _, n in with_name:
            members = [r for r, m in with_name if names_compatible(n, m)]
            if len(members) > len(best_members):
                best, best_members = n, members
        if len(best_members) < 0.75 * len(with_name):
            return []
        return self._dob_consistent(sorted(best_members + unnamed))

    def _dob_consistent(self, rids: list[str]) -> list[str]:
        dobs = [self.ev[r].dobs for r in rids if self.ev[r].dobs]
        for i in range(len(dobs)):
            for j in range(i + 1, len(dobs)):
                if not (dobs[i] & dobs[j]):
                    return []
        return rids

    # ------------------------------------------------------------------ R2
    def link_name_clues(self) -> None:
        index: dict[tuple, list[str]] = {}
        for r in self.order:
            e = self.ev[r]
            for key in _clue_keys(e):
                index.setdefault(key, []).append(r)
        for key in sorted(index):
            rids = index[key]
            if len(rids) < 2:
                continue
            roots = sorted({self.find(r) for r in rids})
            if len(roots) < 2:
                continue
            rich = [x for x in roots if self.cl[x].strong]
            if len(rich) > 1:
                continue  # two different registered people share this combination: ambiguous
            target = rich[0] if rich else roots[0]
            for x in roots:
                if x != target:
                    self._merge(target, x)

    # ------------------------------------------------------------------ result
    def clusters(self) -> dict[str, str]:
        """record id -> canonical cluster key (or '' when the record carries no identity).

        The key must be unique per cluster: two clusters kept apart on purpose (a couple sharing a
        phone) may share a strong key, so the key is the cluster's smallest member record id."""
        out = {}
        for r in self.order:
            if not self.ev[r].has_identity():
                out[r] = ""
                continue
            out[r] = "rec:" + min(self.cl[self.find(r)].members)
        return out


_KEY_RANK = {"id": 0, "aa": 1, "abha": 2, "em": 3, "ins": 4, "ph": 5}


def _distinct(tokens: tuple) -> tuple:
    return tuple(sorted({skeleton(t) for t in tokens if not generic(t)}))


def _clue_keys(e: Evidence):
    p = e.primary_name()
    names = [_distinct(p)] if p else []
    weak = [_distinct(n) for n in e.weak_names]
    rels = [_distinct(r) for r in e.relatives]
    for n in names:
        if not n:
            continue
        for d in e.dobs:
            yield ("n_dob", n, d)
        for rel in rels:
            if rel:
                yield ("n_rel", n, rel)
        for v in e.villages:
            for a in e.ages:
                for aa in (a - 1, a, a + 1):
                    yield ("n_vil_age", n, v, aa)
    # first-name level keys (fragmented notes: "Meera, W/o Rajan"): every name token x relative token
    for n in names + weak:
        for tok in n:
            for rel in rels:
                for rtok in rel:
                    if tok != rtok and rtok not in n:   # a shared family surname is not a clue
                        yield ("tok_rel", tok, rtok)
