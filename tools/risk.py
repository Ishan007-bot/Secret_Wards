#!/usr/bin/env python3
"""Dev-only: measured re-identification risk of a release, against the practice attacker knowledge.

Profile attack (A2/A4 style): every output record's quasi-identifiers (gender, age or age band,
district) are pooled per pseudonym; each profile is matched against the voter-list registry.
  k = number of registry people consistent with the profile; risk = 1/k when the true person is
  among them. Reported: % of patients with k == 1 (unique), k <= 2, mean risk.
Targeted (A5 style): for every known fact (visit date, condition) about a real patient, is that
exact date / condition still visible in that patient's output records?

    python tools/risk.py --kit ../Secret-Wards-ToolKit --output out
    python tools/risk.py --kit ../Secret-Wards-ToolKit --raw     # same attack on the raw input
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import io
import json
import re
from collections import defaultdict
from pathlib import Path

AGE_BAND = re.compile(r"(?<![\d/.:-])(\d{1,3})\s*-\s*(\d{1,3})(?=\s*(?:Y|Yrs|yrs|years|वर्ष|/|,|$|\s))")
AGE_TOP = re.compile(r"(?<!\d)(\d{2,3})\+")
AGE_EXACT = re.compile(r"(?:Age(?:/Sex)?|आयु|Umar)\s*[:\-]?\s*(\d{1,3})(?![\d-])|(?<![\d/.:-])(\d{1,3})\s*(?:Y|Yrs|yrs)\s*/|"
                       r"(?<![\d/.:-])(\d{1,3})\s*/\s*[MF]\b", re.I)
GENDER = re.compile(r"(?<![A-Za-z])(?:/\s*([MF])\b|(Male|Female|male|female)\b)|(महिला|पुरुष)")


def record_texts(root: Path, records_file: Path | None, truth: dict, raw: bool):
    """Yield (true_patient, pseudonym_or_None, text) for every record."""
    if raw:
        for rel, f in truth["files"].items():
            p = root / rel
            if not p.is_file():
                continue
            text = p.read_bytes().decode(f.get("encoding") or "utf-8", "replace")
            for loc, u in f["units"].items():
                if u.get("patient") and not loc.startswith("@"):
                    yield u["patient"], u["patient"], _slice(text, loc, f.get("format"))
        return
    report = json.loads((root / "report.json").read_text(encoding="utf-8"))
    renamed = {e["input_sha256"]: e["output"] for e in report["files"] if e["output"]}
    ours = {}
    for line in records_file.read_text(encoding="utf-8").splitlines():
        r = json.loads(line)
        ours[(r["file"], r["loc"])] = r["patient"]
    for rel, f in truth["files"].items():
        o = renamed.get(f["sha256"])
        if not o:
            continue
        text = (root / o).read_bytes().decode("utf-8", "replace")
        for loc, u in f["units"].items():
            if u.get("patient") and not loc.startswith("@"):
                yield u["patient"], ours.get((o, loc)) or ours.get((o, "doc")), _slice(text, loc, f.get("format"))


def _slice(text: str, loc: str, fmt: str | None) -> str:
    if loc.startswith("row:") and fmt in ("csv", "tsv"):
        rows = list(csv.reader(io.StringIO(text), delimiter="\t" if fmt == "tsv" else ","))
        i = int(loc[4:]) + 1
        if i < len(rows):
            return " | ".join(f"{h}: {v}" for h, v in zip(rows[0], rows[i]))
        return ""
    if loc.startswith("/"):
        try:
            node = json.loads(text)
            for part in loc.strip("/").split("/"):
                node = node[int(part)] if isinstance(node, list) else node[part.replace("~1", "/").replace("~0", "~")]
            return json.dumps(node, ensure_ascii=False)
        except (ValueError, KeyError, IndexError, TypeError):
            return text
    return text


def evidence(text: str, districts: list[str]) -> dict:
    ev = {"gender": set(), "lo": 0, "hi": 200, "district": set()}
    for m in GENDER.finditer(text):
        g = (m.group(1) or m.group(2) or m.group(3) or "").lower()
        ev["gender"].add("F" if g in ("f", "female", "महिला") else "M")
    for m in AGE_BAND.finditer(text):
        lo, hi = int(m.group(1)), int(m.group(2))
        if 0 <= lo < hi <= 120 and hi - lo in (4, 9, 19):
            ev["lo"], ev["hi"] = max(ev["lo"], lo), min(ev["hi"], hi)
    for m in AGE_TOP.finditer(text):
        ev["lo"] = max(ev["lo"], int(m.group(1)))
    for m in AGE_EXACT.finditer(text):
        a = int(next(g for g in m.groups() if g))
        if a <= 120:
            ev["lo"], ev["hi"] = max(ev["lo"], a - 1), min(ev["hi"], a + 2)
    low = text.lower()
    for d in districts:
        if d.lower() in low:
            ev["district"].add(d)
    return ev


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kit", required=True)
    ap.add_argument("--output")
    ap.add_argument("--raw", action="store_true")
    a = ap.parse_args()
    kit = Path(a.kit)
    truth = json.loads((kit / "dev/truth/truth.json").read_text(encoding="utf-8"))
    registry = list(csv.DictReader(open(kit / "dev/attacker/registry.csv", encoding="utf-8")))
    facts = [json.loads(l) for l in open(kit / "dev/attacker/known_facts.jsonl", encoding="utf-8")]
    districts = sorted({r["district"] for r in registry if r["district"]})
    rid_of = {pid: p["rid"] for pid, p in truth["patients"].items()}
    pid_of_rid = {v: k for k, v in rid_of.items()}

    root = kit / "dev/input" if a.raw else Path(a.output)
    rf = None if a.raw else root / "records.jsonl"
    profiles: dict[str, dict] = {}
    true_of_profile: dict[str, set] = defaultdict(set)
    texts_of_patient: dict[str, list] = defaultdict(list)
    for i, (pid, psn, text) in enumerate(record_texts(root, rf, truth, a.raw)):
        key = psn or f"__single{i}"
        ev = evidence(text, districts)
        p = profiles.setdefault(key, {"gender": set(), "lo": 0, "hi": 200, "district": set()})
        p["gender"] |= ev["gender"]
        p["lo"], p["hi"] = max(p["lo"], ev["lo"]), min(p["hi"], ev["hi"])
        p["district"] |= ev["district"]
        true_of_profile[key].add(pid)
        texts_of_patient[pid].append(text)

    def candidates(p):
        c = registry
        for f in (lambda r: not p["district"] or r["district"] in p["district"],
                  lambda r: not p["gender"] or r["gender"] in p["gender"],
                  lambda r: p["lo"] - 1 <= int(r["age"] or -99) <= p["hi"] + 2):
            nxt = [r for r in c if f(r)]
            if nxt:                      # the attacker skips a filter that would empty the set
                c = nxt
        return c

    per_patient = defaultdict(list)
    for key, p in profiles.items():
        cands = candidates(p)
        rids = {r["rid"] for r in cands}
        for pid in true_of_profile[key]:
            per_patient[pid].append(1 / len(cands) if rid_of.get(pid) in rids else 0.0)
    best = {pid: max(v) for pid, v in per_patient.items()}
    n = len(best)
    uniq = sum(1 for v in best.values() if v >= 1.0)
    conf = sum(1 for v in best.values() if v >= 0.5)
    mean = sum(best.values()) / n if n else 0
    print(f"{'RAW INPUT' if a.raw else 'RELEASE'}: {n} patients, {len(profiles)} profiles")
    print(f"  profile attack: unique (k=1) {uniq} ({100 * uniq / n:.1f}%), confident >=0.5 {conf} "
          f"({100 * conf / n:.1f}%), mean risk {mean:.3f}")

    hit_date = hit_cond = n_date = n_cond = 0
    for f in facts:
        pid = pid_of_rid.get(f["rid"])
        if not pid:
            continue                     # decoy: never a patient
        blob = "\n".join(texts_of_patient.get(pid, [])).lower()
        for d in f.get("visit_dates", []):
            n_date += 1
            y, m, dd = d.split("-")
            forms = {d, f"{dd}/{m}/{y}", f"{dd}-{m}-{y}", f"{m}/{dd}/{y}", f"{dd}/{m}/{y[2:]}"}
            hit_date += any(x in blob for x in forms)
        if f.get("condition_hint"):
            n_cond += 1
            hit_cond += f["condition_hint"].lower() in blob
    print(f"  targeted facts still visible: visit dates {hit_date}/{n_date}, conditions {hit_cond}/{n_cond}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
