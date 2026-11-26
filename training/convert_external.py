#!/usr/bin/env python3
"""External synthetic datasets -> span JSONL.

ai4privacy/open-pii-masking-500k (en + hi rows): GIVENNAME/SURNAME -> NAME, STREET/BUILDINGNUM -> ADDR,
everything else O (phones/IDs are regex territory; CITY is district-level, which we keep).
Hindi rows whose name values are in a different script than the sentence are dropped (the dataset
card marks Hindi as experimental). TITLE (Mr/Dr) stays O.

Mendeley synthetic Indian clinical notes: silver labels. Only "Patient Name:" holds a person
(the consultant is a doctor and stays O; the address is city/state level).

    python training/convert_external.py --ai4p-train 20000 --ai4p-test 4000 --mendeley-train 1500
"""
from __future__ import annotations

import argparse
import json
import re

from bio import BIO, DATA, write_jsonl

MAP = {"GIVENNAME": "NAME", "SURNAME": "NAME", "STREET": "ADDR", "BUILDINGNUM": "ADDR"}
DEVA = re.compile(r"[ऀ-ॿ]")


def ai4p(path, cap_per_lang: int, split: str):
    counts = {"en": 0, "hi": 0}
    with open(path, encoding="utf-8") as f:
        for line in f:
            if all(v >= cap_per_lang for v in counts.values()):
                break
            d = json.loads(line)
            lang = d.get("language")
            if lang not in counts or counts[lang] >= cap_per_lang:
                continue
            text = d["source_text"]
            spans = []
            ok = True
            for m in d.get("privacy_mask") or []:
                typ = MAP.get(m["label"])
                if not typ:
                    continue
                s, e = m["start"], m["end"]
                val = text[s:e]
                if lang == "hi" and bool(DEVA.search(val)) != bool(DEVA.search(text)):
                    ok = False
                    break
                spans.append([s, e, typ, "deva" if DEVA.search(val) else "latin"])
            if not ok:
                continue
            # merge adjacent GIVENNAME + SURNAME into one NAME span
            spans.sort()
            merged = []
            for sp in spans:
                if merged and merged[-1][2] == sp[2] and 0 <= sp[0] - merged[-1][1] <= 1:
                    merged[-1][1] = sp[1]
                else:
                    merged.append(sp)
            counts[lang] += 1
            yield {"text": text, "spans": merged, "source": f"ai4privacy_{lang}", "split": split}


_HON = re.compile(r"^(?:Baby|Master|Mr\.?|Mrs\.?|Ms\.?|Smt\.?|Shri|Km\.?)\s+")


def mendeley(path, n: int, split: str, offset: int = 0):
    notes = json.load(open(path, encoding="utf-8"))
    for x in notes[offset:offset + n]:
        text = x["note"]
        spans = []
        m = re.search(r"^Patient Name:[ \t]*(.+)$", text, re.M)
        if m:
            s, e = m.start(1), m.end(1)
            h = _HON.match(text[s:e])
            if h:
                s += h.end()
            spans.append([s, e, "NAME", "latin"])
        yield {"text": text, "spans": spans, "source": "mendeley", "split": split, "id": x.get("id")}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ai4p-train", type=int, default=20000)
    ap.add_argument("--ai4p-test", type=int, default=4000)
    ap.add_argument("--mendeley-train", type=int, default=1500)
    ap.add_argument("--mendeley-test", type=int, default=1000)
    a = ap.parse_args()
    base = DATA / "ai4privacy/data"
    n1 = write_jsonl(BIO / "ai4p_train.jsonl", ai4p(base / "train/train.jsonl", a.ai4p_train // 2, "train"))
    n2 = write_jsonl(BIO / "ai4p_test.jsonl", ai4p(base / "validation/test.jsonl", a.ai4p_test // 2, "test"))
    n3 = write_jsonl(BIO / "mendeley_train.jsonl",
                     mendeley(DATA / "mendeley_nn5r5htbpx/synthetic_notes_medium_v2.json", a.mendeley_train, "train"))
    n4 = write_jsonl(BIO / "mendeley_test.jsonl",
                     mendeley(DATA / "mendeley_bzgjmph5n2/synthetic_notes_medium.json", a.mendeley_test, "test"))
    print(f"ai4privacy train {n1}, test {n2}; mendeley train {n3}, test {n4}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
