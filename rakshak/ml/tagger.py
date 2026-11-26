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
            self._exp_trans = [[math.exp(w) for w in row] for row in self.trans]
            self._cache: dict = {}
            self.threshold: float = float(m.get("threshold", 0.5))
            self.max_chars: int = int(m.get("max_chars", 200000))
            self.ok = True
        except (OSError, ValueError, KeyError, TypeError):
            self.ok = False

    def spans(self, text: str) -> list[tuple[int, int, str, float]]:
        """(start, end, entity type, confidence) for NAME / ADDR spans the model finds."""
        if not self.ok or not text or len(text) > self.max_chars:
            return []
        hit = self._cache.get(text)
        if hit is not None:
            return hit
        res = self._spans(text)
        if len(self._cache) > 20000:
            self._cache.clear()
        self._cache[text] = res
        return res

    def _spans(self, text: str):
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
        ET = self._exp_trans
        # scaled forward-backward in probability space (numerically safe, ~10x faster than log space)
        pe = []
        for row in emit:
            m = max(row)
            pe.append([math.exp(x - m) for x in row])
        alpha, scale = [], []
        a0 = pe[0][:]
        z = sum(a0)
        alpha.append([x / z for x in a0])
        scale.append(z)
        for t in range(1, n):
            prev = alpha[-1]
            cur = [pe[t][j] * sum(prev[i] * ET[i][j] for i in range(L)) for j in range(L)]
            z = sum(cur) or 1e-300
            alpha.append([x / z for x in cur])
            scale.append(z)
        beta = [[1.0] * L for _ in range(n)]
        for t in range(n - 2, -1, -1):
            nxt = beta[t + 1]
            row = [sum(ET[i][j] * pe[t + 1][j] * nxt[j] for j in range(L)) for i in range(L)]
            z = scale[t + 1]
            beta[t] = [x / z for x in row]
        marg = []
        for t in range(n):
            m = [alpha[t][k] * beta[t][k] for k in range(L)]
            z = sum(m) or 1e-300
            marg.append([x / z for x in m])
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
