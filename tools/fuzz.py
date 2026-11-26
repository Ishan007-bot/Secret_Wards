#!/usr/bin/env python3
"""Dev-only robustness fuzzer: hostile and broken inputs must never crash the run, never be copied raw,
and must always be listed in report.json.

    python tools/fuzz.py --kit ../Secret-Wards-ToolKit --work <dir> [--seed 1] [--n 40]
"""
from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def mutations(rnd: random.Random, samples: list[Path]):
    for i in range(40):
        src = rnd.choice(samples)
        raw = bytearray(src.read_bytes())
        kind = rnd.choice(["flip", "truncate", "nul", "latin1", "dup", "shuffle_lines"])
        if kind == "flip" and raw:
            for _ in range(rnd.randint(1, 30)):
                raw[rnd.randrange(len(raw))] = rnd.randrange(256)
        elif kind == "truncate" and raw:
            raw = raw[:rnd.randrange(len(raw))]
        elif kind == "nul" and raw:
            pos = rnd.randrange(len(raw))
            raw[pos:pos] = b"\x00" * rnd.randint(1, 8)
        elif kind == "latin1":
            raw += "\n Pat. naam: Tëjas Hälder ©".encode("latin-1")
        elif kind == "dup":
            raw = raw * rnd.randint(2, 5)
        elif kind == "shuffle_lines":
            lines = bytes(raw).split(b"\n")
            rnd.shuffle(lines)
            raw = bytearray(b"\n".join(lines))
        yield f"mut/{kind}_{i:02d}{src.suffix}", bytes(raw)
    yield "edge/bom_only.csv", b"\xef\xbb\xbf"
    yield "edge/whitespace.txt", b"   \n\t\n  "
    yield "edge/nan.json", b'{"a": NaN, "b": Infinity, "name": "Tejasvi Halder"}'
    yield "edge/scalar.json", b'"just a string with phone 9876543210"'
    yield "edge/empty_obj.json", b"{}"
    yield "edge/null.json", b"null"
    yield "edge/depth199.json", b"[" * 199 + b"1" + b"]" * 199
    yield "edge/depth201.json", b"[" * 201 + b"1" + b"]" * 201
    yield "edge/unbalanced.csv", b'Name,Phone\n"Tejasvi Halder,9876543210\nSita,98765\n'
    yield "edge/one_column.csv", b"Name\nTejasvi Halder\nSita Devi\n"
    yield "edge/long_line.txt", (b"Patient Tejasvi Halder 9876543210 " * 160000)[:5_000_000]
    yield "edge/binary.txt", bytes(random.Random(3).randrange(256) for _ in range(20000))
    yield "edge/utf16_no_bom.tsv", "Naam\tPhone\nरमेश\t9876543210\n".encode("utf-16-le")
    yield "edge/cp1252.csv", "Name,Temp\nTejasvi Halder,101.2°F – ok\n".encode("cp1252")
    yield "edge/crlf_mixed.csv", b"Name,Phone\r\nTejasvi Halder,9876543210\nSita,9123456780\r\n"
    yield "edge/sp ace & ünïcode नाम.txt", "मरीज़ का नाम: तेजस्वी हालदार, मोबाइल ९८७६५४३२१०".encode("utf-8")
    yield "edge/" + "x" * 150 + ".txt", b"Name: Tejasvi Halder"
    yield "edge/no_extension", b"Name: Tejasvi Halder 9876543210"
    yield "edge/UPPER.CSV", b"NAME,PHONE\nTEJASVI HALDER,9876543210\n"
    yield "edge/array_root.json", json.dumps([{"name": "Tejasvi Halder", "phone": "9876543210"}] * 50).encode()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kit", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()
    rnd = random.Random(a.seed)
    work = Path(a.work)
    inp, out = work / "input", work / "output"
    import shutil
    shutil.rmtree(work, ignore_errors=True)
    samples = sorted(p for p in (Path(a.kit) / "dev/input").rglob("*") if p.is_file() and p.stat().st_size < 200_000)
    written = {}
    for rel, data in mutations(rnd, samples):
        p = inp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        written[rel] = data
    t0 = time.time()
    r = subprocess.run([sys.executable, str(ROOT / "main.py"), "--input", str(inp), "--output", str(out)],
                       env=dict(os.environ, RAKSHA_SECRET="fuzz"), capture_output=True, text=True, encoding="utf-8",
                       errors="replace")
    dt = time.time() - t0
    problems = []
    if r.returncode != 0:
        problems.append(f"exit code {r.returncode}: {r.stderr[-300:]}")
    try:
        rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        rep = {"files": []}
        problems.append("report.json missing or invalid")
    import hashlib
    shas = {hashlib.sha256(d).hexdigest() for d in written.values()}
    listed = {e["input_sha256"] for e in rep["files"]}
    if shas - listed:
        problems.append(f"{len(shas - listed)} input files missing from report")
    for e in rep["files"]:
        if e.get("output"):
            data = (out / e["output"]).read_bytes()
            if e["status"] != "sanitized":
                problems.append("non-sanitized file exported")
            if hashlib.sha256(data).hexdigest() == e["input_sha256"] and b"9876543210" in data:
                problems.append(f"raw copy with PII: {e['output']}")
    blob = "\n".join(p.read_text("utf-8", "replace") for p in out.rglob("*") if p.is_file())
    for v in ("Tejasvi Halder", "9876543210", "तेजस्वी हालदार", "९८७६५४३२१०"):
        if v in blob:
            problems.append(f"leak of fixture value {v!r}")
    q = sum(1 for e in rep["files"] if e["status"] == "quarantined")
    print(f"fuzz: {len(written)} hostile files, exit {r.returncode}, {dt:.1f}s, "
          f"{len(rep['files']) - q} sanitized / {q} quarantined")
    for p in problems:
        print("  PROBLEM", p)
    print("FUZZ OK" if not problems else f"FUZZ FAILED ({len(problems)})")
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
