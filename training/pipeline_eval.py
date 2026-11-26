#!/usr/bin/env python3
"""End-to-end acceptance test for the CRF: run the FULL pipeline (tagger off vs on) on standalone
notes whose names exist only in free text (Faker notes, Mendeley notes, ai4privacy sentences).

Reports, per test set and script: share of gold NAME/ADDR spans still visible after sanitising
(leak), and the share of non-PII word tokens kept (over-redaction), plus runtime.

    python training/pipeline_eval.py --work <scratch dir> [--n 300]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

from bio import BIO, ROOT, read_jsonl

SETS = [("faker-dev", "faker.jsonl", lambda r: r["split"] == "dev"),
        ("mendeley-test", "mendeley_test.jsonl", lambda r: True),
        ("ai4p-en", "ai4p_test.jsonl", lambda r: r["source"].endswith("_en") and r["spans"]),
        ("ai4p-hi", "ai4p_test.jsonl", lambda r: r["source"].endswith("_hi") and r["spans"])]
WORD = re.compile(r"[A-Za-z]{3,}|[ऀ-ॿ]{2,}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", required=True)
    ap.add_argument("--n", type=int, default=300)
    a = ap.parse_args()
    work = Path(a.work)
    base_pol = (ROOT / "config/policy.yaml").read_text(encoding="utf-8")
    for name, fn, keep in SETS:
        rows = [r for r in read_jsonl(BIO / fn) if keep(r)][: a.n]
        inp = work / name / "input"
        inp.mkdir(parents=True, exist_ok=True)
        for i, r in enumerate(rows):
            (inp / f"note_{i:05d}.txt").write_text(r["text"], encoding="utf-8")
        res = {}
        for mode in ("off", "on"):
            pol = work / f"policy_{mode}.yaml"
            pol.write_text(base_pol + f"\nml_tagger: {mode}\n", encoding="utf-8")
            out = work / name / f"out_{mode}"
            env = dict(os.environ, RAKSHA_POLICY=str(pol), RAKSHA_SECRET="eval-secret")
            t0 = time.time()
            subprocess.run([sys.executable, str(ROOT / "main.py"), "--input", str(inp), "--output", str(out)],
                           env=env, check=True, capture_output=True)
            dt = time.time() - t0
            leak = defaultdict(lambda: [0, 0])
            kept = total = 0
            for i, r in enumerate(rows):
                p = out / "sanitized" / f"note_{i:05d}.txt"
                o = p.read_text(encoding="utf-8") if p.is_file() else ""
                pii_words = set()
                for s, e, typ, script in r["spans"]:
                    val = r["text"][s:e]
                    words = WORD.findall(val)
                    pii_words |= set(words)
                    vis = bool(words) and all(re.search(r"(?<!\w)" + re.escape(w) + r"(?!\w)", o) for w in words)
                    leak[script][0] += vis
                    leak[script][1] += 1
                    leak["all"][0] += vis
                    leak["all"][1] += 1
                ins = Counter(w for w in WORD.findall(r["text"]) if w not in pii_words)
                outs = Counter(WORD.findall(o))
                total += sum(ins.values())
                kept += sum((ins & outs).values())
            res[mode] = {"leak": {k: round(v[0] / v[1], 4) for k, v in leak.items() if v[1]},
                         "non_pii_kept": round(kept / total, 4) if total else 1.0, "seconds": round(dt, 1)}
        print(f"== {name} ({len(rows)} notes)")
        for mode, v in res.items():
            print(f"   tagger {mode:<3} {json.dumps(v)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
