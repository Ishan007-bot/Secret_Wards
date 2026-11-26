"""Shared helpers for building BIO training data: one JSONL line per text segment
{"text", "spans": [[start, end, TYPE, script]], "source", "split"} -> tokens + tags at train time."""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from rakshak.ml.features import tokenize  # noqa: E402

DATA = ROOT / "training" / "data"
BIO = DATA / "bio"
TYPES = {"PATIENT_NAME": "NAME", "RELATIVE_NAME": "NAME", "CANARY": "NAME", "HOUSE": "ADDR",
         "LOCALITY": "ADDR", "LANDMARK": "ADDR", "VILLAGE": "ADDR"}


def script_of(s: str) -> str:
    if re.search(r"[ऀ-ॿ]", s):
        return "deva"
    return "latin"


def find_all(text: str, needle: str) -> list[tuple[int, int]]:
    out, i = [], 0
    if not needle:
        return out
    while True:
        j = text.find(needle, i)
        if j < 0:
            return out
        a, b = j, j + len(needle)
        if (a == 0 or not text[a - 1].isalnum()) and (b == len(text) or not text[b].isalnum()):
            out.append((a, b))
        i = j + 1


def to_bio(text: str, spans: list) -> tuple[list, list, list]:
    toks = tokenize(text)
    tags = ["O"] * len(toks)
    for s, e, typ, _ in sorted(spans, key=lambda x: (x[0], -(x[1] - x[0]))):
        first = True
        for k, (ts, te, _) in enumerate(toks):
            if ts >= s and te <= e:
                if tags[k] != "O" and first:
                    break
                tags[k] = ("B-" if first else "I-") + typ
                first = False
    return toks, tags, [t[2] for t in toks]


def split_of(key: str, holdout_pct: int = 20) -> str:
    h = int(hashlib.sha256(key.encode()).hexdigest()[:8], 16) % 100
    return "dev" if h < holdout_pct else "train"


def write_jsonl(path: Path, rows) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
            n += 1
    return n


def read_jsonl(path: Path):
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                yield json.loads(line)
