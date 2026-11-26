#!/usr/bin/env python3
"""Dev-only diagnostics against the practice answer key (never imported by the pipeline).

Lists: medical values we destroyed (with context), canaries still present, and every leaked
entity grouped by type. Complements the kit's check_dev.py.

    python tools/diagnose.py --kit ../Secret-Wards-ToolKit --output out_a
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import unicodedata
from collections import Counter
from pathlib import Path


def norm(s: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", s).casefold().split())


def with_b64(text: str) -> str:
    extra = []
    for m in re.finditer(r"[A-Za-z0-9+/]{24,}={0,2}", text):
        tok = m.group(0)
        try:
            extra.append(base64.b64decode(tok + "=" * (-len(tok) % 4)).decode("utf-8", errors="ignore"))
        except (binascii.Error, ValueError):
            pass
    return text + "\n" + "\n".join(extra)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kit", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--limit", type=int, default=60)
    a = ap.parse_args()
    kit, out = Path(a.kit), Path(a.output)
    truth = json.loads((kit / "dev/truth/truth.json").read_text(encoding="utf-8"))
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    renamed = {e["input_sha256"]: e["output"] for e in report["files"]}
    lost, leaks, canaries = [], Counter(), []
    leak_list = []
    everything = ""
    for p in sorted(out.rglob("*")):
        if p.is_file():
            everything += p.name + "\n" + with_b64(p.read_bytes().decode("utf-8", "replace"))
    everything = norm(everything)
    for rel, f in truth["files"].items():
        o = renamed.get(f["sha256"])
        if not o:
            continue
        text = norm(with_b64((out / o).read_bytes().decode("utf-8", "replace")))
        for loc, u in f["units"].items():
            for pv in u.get("preserve") or []:
                if norm(pv["text"]) not in text:
                    lost.append((pv.get("kind"), pv["text"], rel))
            for e in u["entities"]:
                if e["type"] == "CANARY":
                    if norm(e["surface"]) in everything:
                        canaries.append((e["surface"], rel))
                    continue
                hay = norm(o) if e["channel"] == "filename" else text
                if norm(e["surface"]) in hay:
                    leaks[e["type"]] += 1
                    leak_list.append((e["type"], e["script"], e["channel"], rel, e["surface"]))
    print(f"LOST MEDICAL VALUES: {len(lost)}")
    for x in lost[: a.limit]:
        print("   ", x)
    print(f"CANARIES PRESENT: {canaries}")
    print(f"LEAKS: {dict(leaks)}")
    for x in leak_list[: a.limit]:
        print("   ", x)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
