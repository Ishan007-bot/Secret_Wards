#!/usr/bin/env python3
"""Train the name-agnostic CRF tagger and export it for the pure-Python runtime tagger.

    python training/train_crf.py --sources dev,faker,mendeley [--with-ai4p] --out models/ner_crf.json

Selects (c1, c2) on span F2 over the held-out splits (dev-holdout by patient + faker dev), with a
fixed data order, so training is deterministic. Weights are exported as JSON
{labels, state: {feature: [w per label]}, trans: [[w]]}; tiny weights are pruned.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path

import sklearn_crfsuite

from bio import BIO, ROOT, read_jsonl, to_bio
from rakshak.ml.features import sent_features

LABELS = ["O", "B-NAME", "I-NAME", "B-ADDR", "I-ADDR"]


def load(sources: list[str], with_ai4p: bool):
    files = {"dev": "dev.jsonl", "faker": "faker.jsonl", "mendeley": "mendeley_train.jsonl"}
    train, held = [], []
    for s in sources:
        for r in read_jsonl(BIO / files[s]):
            (held if r["split"] == "dev" else train).append(r)
    if with_ai4p:
        train += list(read_jsonl(BIO / "ai4p_train.jsonl"))
    return train, held


def xy(rows):
    X, Y = [], []
    for r in rows:
        toks, tags, _ = to_bio(r["text"], r["spans"])
        if not toks:
            continue
        X.append(sent_features(r["text"], toks))
        Y.append(tags)
    return X, Y


def spans_from_tags(tags):
    out, cur = set(), None
    for i, t in enumerate(tags + ["O"]):
        if t.startswith("B-") or t == "O" or (t.startswith("I-") and (cur is None or cur[2] != t[2:])):
            if cur:
                out.add((cur[0], i - 1, cur[2]))
                cur = None
            if t != "O":
                cur = [i, i, t[2:]]
    return out


def f2(gold, pred):
    tp = sum(len(g & p) for g, p in zip(gold, pred))
    ng, np_ = sum(len(g) for g in gold), sum(len(p) for p in pred)
    p = tp / np_ if np_ else 0.0
    r = tp / ng if ng else 0.0
    return (5 * p * r / (4 * p + r) if p + r else 0.0), p, r


def export(crf, path: Path, threshold: float, meta: dict) -> dict:
    labels = LABELS
    idx = {l: i for i, l in enumerate(labels)}
    state: dict[str, list[float]] = {}
    for (attr, lab), w in crf.state_features_.items():
        if abs(w) < 0.01 or lab not in idx:
            continue
        state.setdefault(attr, [0.0] * len(labels))[idx[lab]] = round(w, 4)
    trans = [[0.0] * len(labels) for _ in labels]
    for (a, b), w in crf.transition_features_.items():
        if a in idx and b in idx:
            trans[idx[a]][idx[b]] = round(w, 4)
    model = {"format": "rakshak-crf/1", "labels": labels, "threshold": threshold, "state": dict(sorted(state.items())),
             "trans": trans, "meta": meta}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(model, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    return model


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sources", default="dev,faker,mendeley")
    ap.add_argument("--with-ai4p", action="store_true")
    ap.add_argument("--out", default=str(ROOT / "models" / "ner_crf.json"))
    ap.add_argument("--grid", default="0.05:0.01,0.1:0.05,0.3:0.1")
    ap.add_argument("--max-iter", type=int, default=150)
    ap.add_argument("--threshold", type=float, default=0.5)
    a = ap.parse_args()
    train, held = load(a.sources.split(","), a.with_ai4p)
    t0 = time.time()
    Xtr, Ytr = xy(train)
    Xh, Yh = xy(held)
    print(f"train {len(Xtr)} seqs / {sum(map(len, Xtr))} tokens; held-out {len(Xh)} seqs ({time.time() - t0:.0f}s features)",
          flush=True)
    best = None
    for pair in a.grid.split(","):
        c1, c2 = map(float, pair.split(":"))
        crf = sklearn_crfsuite.CRF(algorithm="lbfgs", c1=c1, c2=c2, max_iterations=a.max_iter,
                                   all_possible_transitions=True)
        crf.fit(Xtr, Ytr)
        pred = crf.predict(Xh)
        score, p, r = f2([spans_from_tags(y) for y in Yh], [spans_from_tags(y) for y in pred])
        print(f"c1={c1} c2={c2}: held-out span F2 {score:.4f} (P {p:.4f} R {r:.4f})", flush=True)
        if best is None or score > best[0]:
            best = (score, c1, c2, crf, p, r)
    score, c1, c2, crf, p, r = best
    digest = hashlib.sha256()
    for row in train:
        digest.update(row["text"].encode("utf-8"))
    meta = {"sources": a.sources.split(",") + (["ai4privacy"] if a.with_ai4p else []), "c1": c1, "c2": c2,
            "max_iterations": a.max_iter, "train_sequences": len(Xtr), "train_tokens": sum(map(len, Xtr)),
            "heldout_f2": round(score, 4), "heldout_p": round(p, 4), "heldout_r": round(r, 4),
            "train_data_sha256": digest.hexdigest()}
    m = export(crf, Path(a.out), a.threshold, meta)
    size = Path(a.out).stat().st_size
    print(f"best c1={c1} c2={c2} F2 {score:.4f}; exported {len(m['state'])} features, {size / 1e6:.2f} MB -> {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
