#!/usr/bin/env python3
"""Evaluate rules-only vs CRF-only vs rules+CRF on every held-out / external test set.

Span level, per source and per script: recall = share of gold NAME/ADDR spans whose characters are
covered (>= 50%) by a predicted span; precision = share of predicted characters that fall inside a
gold span. Uses the exact runtime code (rakshak.ml.tagger + rakshak.detect.engine), so what is
measured is what ships.

    python training/eval_crf.py --model models/ner_crf.json [--thresholds 0.3,0.5,0.7]
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

from bio import BIO, read_jsonl
from rakshak.detect.engine import Engine
from rakshak.ml.tagger import Tagger

RULE_KINDS = {"PATIENT", "RELATIVE", "ADDRESS", "VILLAGE", "NAME"}
SETS = [("dev-holdout", "dev.jsonl", lambda r: r["split"] == "dev" and not r.get("clean")),
        ("dev-clean-docs", "dev.jsonl", lambda r: r.get("clean")),
        ("faker-dev", "faker.jsonl", lambda r: r["split"] == "dev"),
        ("mendeley-test", "mendeley_test.jsonl", lambda r: True),
        ("ai4p-en", "ai4p_test.jsonl", lambda r: r["source"].endswith("_en")),
        ("ai4p-hi", "ai4p_test.jsonl", lambda r: r["source"].endswith("_hi")),
        ("chaos-holdout", "chaos.jsonl", lambda r: r["split"] == "dev" and not r.get("clean"))]


def rule_spans(text):
    eng = Engine()
    eng.harvest_text(text)
    return [(s.start, s.end) for s in eng.find(text) if s.kind in RULE_KINDS]


def score(rows, predict):
    rec = defaultdict(lambda: [0, 0])
    pc = [0, 0]
    for r in rows:
        pred = predict(r["text"])
        covered = [False] * len(r["text"])
        for s, e in pred:
            for i in range(s, min(e, len(covered))):
                covered[i] = True
        gold_chars = [False] * len(r["text"])
        for s, e, typ, script in r["spans"]:
            n = sum(covered[s:e])
            rec[script][1] += 1
            rec[script][0] += n >= 0.5 * (e - s)
            rec["all"][1] += 1
            rec["all"][0] += n >= 0.5 * (e - s)
            for i in range(s, e):
                gold_chars[i] = True
        for s, e in pred:
            seg = r["text"][s:e]
            for i in range(s, min(e, len(gold_chars))):
                if not r["text"][i].isspace():
                    pc[1] += 1
                    pc[0] += gold_chars[i]
    out = {k: round(v[0] / v[1], 4) if v[1] else None for k, v in rec.items()}
    out["precision"] = round(pc[0] / pc[1], 4) if pc[1] else 1.0
    out["n"] = rec["all"][1]
    out["pred_chars"] = pc[1]
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="models/ner_crf.json")
    ap.add_argument("--thresholds", default="0.5")
    ap.add_argument("--limit", type=int, default=1500)
    ap.add_argument("--json-out")
    a = ap.parse_args()
    results = {}
    for name, fn, keep in SETS:
        p = BIO / fn
        if not p.is_file():
            continue
        rows = [r for r in read_jsonl(p) if keep(r)][: a.limit]
        if not rows:
            continue
        res = {"rules": score(rows, rule_spans)}
        for th in map(float, a.thresholds.split(",")):
            tg = Tagger(Path(a.model))
            tg.threshold = th
            def crf(t, tg=tg):
                from rakshak.detect import engine as E
                from rakshak.ml import tagger as TG
                TG._TAGGER = tg
                return [(sp.start, sp.end) for sp in E._crf_spans(t)]
            res[f"crf@{th}"] = score(rows, crf)
            res[f"rules+crf@{th}"] = score(rows, lambda t, crf=crf: rule_spans(t) + crf(t))
        results[name] = res
        print(f"\n== {name} ({len(rows)} segments)")
        for k, v in res.items():
            print(f"   {k:<16} {json.dumps(v)}")
    if a.json_out:
        Path(a.json_out).write_text(json.dumps(results, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
