#!/usr/bin/env python3
"""Organiser practice data -> span JSONL (free-text segments only), split 80/20 BY PATIENT.

Entity surfaces from truth.json are located in each segment; occurrences inside a preserve-probe
(e.g. a doctor who shares a relative's first name) stay O, so they become hard negatives.

    python training/convert_dev.py --kit ../Secret-Wards-ToolKit
"""
from __future__ import annotations

import argparse
import csv
import io
import json
from pathlib import Path

from bio import BIO, TYPES, find_all, split_of, write_jsonl

csv.field_size_limit(1 << 30)


def segments(text: str, fmt: str, delim: str | None):
    if fmt == "text":
        yield "doc", text
    elif fmt in ("csv", "tsv"):
        try:
            rows = list(csv.reader(io.StringIO(text.lstrip("﻿")), delimiter=delim or ","))
        except csv.Error:
            return
        for i, r in enumerate(rows[1:]):
            for cell in r:
                if len(cell.split()) >= 4:
                    yield f"row:{i}", cell
    elif fmt == "json":
        try:
            data = json.loads(text)
        except ValueError:
            return
        stack = [("", data)]
        while stack:
            p, n = stack.pop()
            if isinstance(n, dict):
                stack.extend((f"{p}/{k}", v) for k, v in n.items())
            elif isinstance(n, list):
                stack.extend((f"{p}/{i}", v) for i, v in enumerate(n))
            elif isinstance(n, str) and len(n.split()) >= 4:
                yield p, n


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kit", required=True)
    ap.add_argument("--input", help="input folder (default <kit>/dev/input)")
    ap.add_argument("--truth", help="truth.json (default <kit>/dev/truth/truth.json)")
    ap.add_argument("--name", default="dev", help="output name: training/data/bio/<name>.jsonl")
    a = ap.parse_args()
    kit = Path(a.kit)
    inp = Path(a.input) if a.input else kit / "dev/input"
    truth = json.loads(Path(a.truth or kit / "dev/truth/truth.json").read_text(encoding="utf-8"))
    rows = []
    for rel, f in sorted(truth["files"].items()):
        if f.get("expect") == "either" or f.get("clean") and False:
            continue
        try:
            text = (inp / rel).read_bytes().decode(f.get("encoding") or "utf-8")
        except (OSError, UnicodeDecodeError, LookupError):
            continue
        ents, preserve, patients = [], [], set()
        for u in f["units"].values():
            if u.get("patient"):
                patients.add(u["patient"])
            for e in u["entities"]:
                if e["type"] in TYPES and e.get("channel") in ("content", "base64") and len(e["surface"]) >= 2:
                    ents.append((e["surface"], TYPES[e["type"]], e["script"]))
            preserve += [pv["text"] for pv in u.get("preserve") or []]
        split = split_of(min(patients) if patients else rel)
        for loc, seg in segments(text, f["format"], f.get("delimiter")):
            blocked = [ab for p in preserve for ab in find_all(seg, p)]
            spans = []
            for surface, typ, script in sorted(set(ents), key=lambda x: -len(x[0])):
                for s, e in find_all(seg, surface):
                    if any(bs <= s and e <= be for bs, be in blocked):
                        continue
                    if any(not (e <= x[0] or s >= x[1]) for x in spans):
                        continue
                    spans.append([s, e, typ, script])
            rows.append({"text": seg, "spans": sorted(spans), "source": "dev", "split": split,
                         "file": rel, "clean": bool(f.get("clean"))})
    n = write_jsonl(BIO / f"{a.name}.jsonl", rows)
    ns = sum(len(r["spans"]) for r in rows)
    print(f"{a.name}: {n} segments, {ns} entity spans, holdout {sum(r['split'] == 'dev' for r in rows)} segments")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
