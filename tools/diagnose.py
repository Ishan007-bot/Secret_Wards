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
    ap.add_argument("--truth", default=None)
    a = ap.parse_args()
    kit, out = Path(a.kit), Path(a.output)
    truth = json.loads(Path(a.truth or kit / "dev/truth/truth.json").read_text(encoding="utf-8"))
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

    # ---- dates: every shifted date of one patient must move by the same number of days
    import csv as _csv
    import datetime as _dt
    import io as _io
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from rakshak.privacy.dates import parse_one
    deltas = defaultdict(set) if False else {}
    unmatched = exact = 0
    for rel, f in truth["files"].items():
        o = renamed.get(f["sha256"])
        if not o:
            continue
        otext = (out / o).read_bytes().decode("utf-8", "replace")
        mf = f.get("date_hint") == "mdy"
        rows = None
        if f.get("format") in ("csv", "tsv"):
            rows = list(_csv.reader(_io.StringIO(otext), delimiter="\t" if f["format"] == "tsv" else ","))
        for loc, u in f["units"].items():
            for d in u.get("dates") or []:
                true = _dt.date.fromisoformat(d["true"])
                got = None
                if d.get("anchor") and d["anchor"] in otext:
                    seg = otext[otext.index(d["anchor"]) + len(d["anchor"]):][:40]
                    got = parse_one(seg, mf)
                elif d.get("path", "").startswith("col:") and rows and loc.startswith("row:"):
                    col = d["path"][4:]
                    if col in rows[0]:
                        r = int(loc[4:]) + 1
                        if r < len(rows):
                            got = parse_one(rows[r][rows[0].index(col)], mf)
                if got is None:
                    unmatched += 1
                    continue
                if got == true:
                    exact += 1
                deltas.setdefault(d["patient"], set()).add((got - true).days)
    inconsistent = {p: v for p, v in deltas.items() if len(v) > 1}
    print(f"DATES: checked {sum(len(v) for v in deltas.values())} patient-delta values, "
          f"{len(inconsistent)} patients with >1 shift, {exact} dates left unshifted, {unmatched} not located")
    for p, v in list(inconsistent.items())[:8]:
        print("   ", p, sorted(v))

    # ---- age bands / fields must contain the truth
    bad_band = 0
    for rel, f in truth["files"].items():
        o = renamed.get(f["sha256"])
        if not o or f.get("format") not in ("csv", "tsv"):
            continue
        rows = list(_csv.reader(_io.StringIO((out / o).read_bytes().decode("utf-8", "replace")),
                                delimiter="\t" if f["format"] == "tsv" else ","))
        for loc, u in f["units"].items():
            for fld in u.get("fields") or []:
                if fld["kind"] == "age" and str(fld.get("path", "")).startswith("col:") and loc.startswith("row:"):
                    col = fld["path"][4:]
                    r = int(loc[4:]) + 1
                    if col in rows[0] and r < len(rows):
                        cell = rows[r][rows[0].index(col)]
                        m = re.search(r"(\d+)\s*-\s*(\d+)|(\d+)\+", cell)
                        ok = m and ((m.group(1) and int(m.group(1)) <= fld["true"] <= int(m.group(2)))
                                    or (m.group(3) and fld["true"] >= int(m.group(3))))
                        bad_band += not ok
    print(f"AGE BANDS NOT CONTAINING TRUE AGE: {bad_band}")

    # ---- linking: wrong merges and missed links
    from collections import defaultdict
    ours = {}
    for line in (out / "records.jsonl").read_text(encoding="utf-8").splitlines():
        r = json.loads(line)
        ours[(r["file"].replace("sanitized/", "", 1), r["loc"])] = r["patient"]
    by_psn = defaultdict(list)
    by_true = defaultdict(list)
    for rel, f in truth["files"].items():
        o = renamed.get(f["sha256"])
        if not o:
            continue
        o = o.replace("sanitized/", "", 1)
        for loc, u in f["units"].items():
            if loc.startswith("@") or not u.get("patient"):
                continue
            psn = ours.get((o, loc))
            by_true[u["patient"]].append((rel, loc, psn, u.get("link")))
            if psn:
                by_psn[psn].append((u["patient"], rel, loc))
    print("WRONG MERGES:")
    for psn, items in by_psn.items():
        pats = {p for p, _, _ in items}
        if len(pats) > 1:
            print("   ", psn, Counter(p for p, _, _ in items))
            for p, rel, loc in items:
                print("        ", p, rel, loc)
    print("SPLIT / UNLINKED PATIENTS (required units only):")
    for p, items in sorted(by_true.items()):
        req = [x for x in items if x[3] == "required"]
        psns = Counter(x[2] for x in req)
        if len(psns) > 1:
            main_psn = psns.most_common(1)[0][0]
            odd = [x for x in req if x[2] != main_psn]
            print(f"    {p}: {dict(psns)}")
            for x in odd[:6]:
                print("        ", x[0], x[1], "->", x[2])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
