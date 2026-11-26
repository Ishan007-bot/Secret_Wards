"""Per-record rewrite context: which pseudonym, whose names/IDs, which date shift."""
from __future__ import annotations

from dataclasses import dataclass, field

from ..detect.textnorm import digits_only
from ..privacy.dates import Shifter
from .linker import norm_id
from .translit import name_tokens, names_compatible


@dataclass
class RecordCtx:
    psn: str | None = None
    names: list = field(default_factory=list)      # name token tuples of the record's cluster
    ids: set = field(default_factory=set)          # normalised IDs and digit cores of the cluster
    shifter: Shifter | None = None
    used: bool = False                             # True once the pseudonym was written into the record
    generalized: bool = False                      # True if a quasi-identifier was coarsened in this record
    age_width: int | None = None                   # wider age band for patients in a small (k-anonymity) cell

    def shift_text(self, text: str) -> str:
        if not self.shifter:
            return text
        out = self.shifter.shift_text(text)
        if out != text:
            self.generalized = True
        return out

    def owns_id(self, surface: str) -> bool:
        n = norm_id(surface)
        d = digits_only(surface)
        return bool(n) and (n in self.ids or (len(d) >= 5 and d in self.ids))

    def owns_name(self, surface: str, src: str) -> bool:
        t = name_tokens(surface)
        if not t:
            return False
        if not self.names:
            return src == "label"
        return any(names_compatible(t, n) for n in self.names)


NO_CTX = None
