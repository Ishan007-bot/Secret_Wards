"""Runtime inference for the self-trained CRF (pure Python, no third-party dependency).

The model file (models/ner_crf.json) holds the linear-chain CRF weights exported after training
with python-crfsuite: state weights per (feature, label) and label-transition weights. Inference
is forward-backward over at most 5 labels, so it is deterministic, CPU-only and tiny.
If the model is missing or unreadable the tagger is disabled and the pipeline runs rules-only.
"""
from __future__ import annotations

import json
import math
from pathlib import Path

from .features import sent_features, tokenize

MODEL_PATH = Path(__file__).resolve().parent.parent.parent / "models" / "ner_crf.json"


class Tagger:
    def __init__(self, path: Path = MODEL_PATH):
        self.ok = False
        try:
            m = json.loads(Path(path).read_text(encoding="utf-8"))
            self.labels: list[str] = m["labels"]
            self.state: dict[str, list[float]] = {k: v for k, v in m["state"].items()}
            self.trans: list[list[float]] = m["trans"]
            self.threshold: float = float(m.get("threshold", 0.5))
            self.max_chars: int = int(m.get("max_chars", 200000))
            self.ok = True
        except (OSError, ValueError, KeyError, TypeError):
            self.ok = False

    def spans(self, text: str) -> list[tuple[int, int, str, float]]:
        """(start, end, entity type, confidence) for NAME / ADDR spans the model finds."""
        if not self.ok or not text or len(text) > self.max_chars:
            return []
        toks = tokenize(text)
        if len(toks) < 4:
            return []
        out = []
        # tag line blocks independently (bounded cost, local context only)
        start = 0
        for i in range(1, len(toks) + 1):
            if i == len(toks) or (i - start >= 120 and "\n" in text[toks[i - 1][1]:toks[i][0]]):
                seg = toks[start:i]
                lo, hi = seg[0][0], seg[-1][1]
                local = [(s - lo, e - lo, w) for s, e, w in seg]
                out.extend((s + lo, e + lo, k, p) for s, e, k, p in self._tag(text[lo:hi], local))
                start = i
        return out

    def _tag(self, text, toks):
        feats = sent_features(text, toks)
        L = len(self.labels)
        emit = []
        for f in feats:
            row = [0.0] * L
            for a in f:
                w = self.state.get(a)
                if w:
                    for k in range(L):
                        row[k] += w[k]
            emit.append(row)
        n = len(emit)
        T = self.trans
        # forward-backward in log space -> per-token marginals
        alpha = [emit[0][:]]
        for t in range(1, n):
            prev = alpha[-1]
            alpha.append([emit[t][j] + _lse([prev[i] + T[i][j] for i in range(L)]) for j in range(L)])
        beta = [[0.0] * L for _ in range(n)]
        for t in range(n - 2, -1, -1):
            nxt = beta[t + 1]
            beta[t] = [_lse([T[i][j] + emit[t + 1][j] + nxt[j] for j in range(L)]) for i in range(L)]
        z = _lse(alpha[-1])
        marg = [[math.exp(alpha[t][k] + beta[t][k] - z) for k in range(L)] for t in range(n)]
        o = self.labels.index("O")
        out, cur = [], None
        for t in range(n):
            p_ent = 1.0 - marg[t][o]
            best = max(range(L), key=lambda k: (marg[t][k] if k != o else -1.0))
            lab = self.labels[best]
            typ = lab[2:]
            if p_ent >= self.threshold:
                if cur and cur[2] == typ and (lab.startswith("I-") or toks[t][0] - toks[cur[1]][1] <= 1):
                    cur[1] = t
                    cur[3] = min(cur[3], p_ent)
                else:
                    if cur:
                        out.append(cur)
                    cur = [t, t, typ, p_ent]
            else:
                if cur:
                    out.append(cur)
                cur = None
        if cur:
            out.append(cur)
        return [(toks[a][0], toks[b][1], typ, p) for a, b, typ, p in out]


def _lse(xs):
    m = max(xs)
    return m + math.log(sum(math.exp(x - m) for x in xs))


_TAGGER = None


def get() -> Tagger:
    global _TAGGER
    if _TAGGER is None:
        _TAGGER = Tagger()
    return _TAGGER
