#!/usr/bin/env python3
"""Dev-only re-implementation of the published scoring formulas (docs/SCORING.md, scoring.toml).

    python tools/selfscore.py --kit ../Secret-Wards-ToolKit --output out_a \
        [--rerun out_b] [--other out_c] [--input DIR --truth FILE --no-attack]

Projects every category score and the 100-point total, including critical penalties. The parts
of the official evaluator that are not published (exact record location, lab-median and LOS
histogram details, stdout capture) are approximated and marked "approx" in the output.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import io
import itertools
import json
import math
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

from _common import (count_key, load_records, load_report, load_truth, norm, output_map, read,
                     record_for, scan, unit_text)
from rakshak.formats import fhir
from rakshak.link.translit import generic
from rakshak.privacy.dates import parse_one

TYPE_W = {"AADHAAR": 1.0, "ABHA_NUMBER": 1.0, "ABHA_ADDRESS": 1.0, "PHONE": 1.0, "EMAIL": 1.0, "MRN": 1.0,
          "PAN": 1.0, "INSURANCE_ID": 0.8, "PATIENT_NAME": 1.0, "RELATIVE_NAME": 0.8, "DOB": 0.7, "HOUSE": 0.6,
          "LOCALITY": 0.6, "LANDMARK": 0.5, "VILLAGE": 0.5, "PIN": 0.5, "AADHAAR_MASKED": 0.5, "CANARY": 1.0}
WEIGHTS = {"detection": 0.20, "identity": 0.15, "privacy": 0.25, "utility": 0.20, "integrity": 0.10,
           "performance": 0.10}
TOKEN = re.compile(r"[A-Za-zऀ-ॿ]+|\d+(?:\.\d+)?")


def f_beta(p, r, b):
    return (1 + b * b) * p * r / (b * b * p + r) if p + r else 0.0


def keys_of(e: dict) -> list:
    m = e.get("match")
    if m == "name":
        return [t for t in (e.get("tokens") or []) if not generic(t)] or list(e.get("tokens") or [])
    if m == "dob":
        return [e["key"]]
    return [e.get("key") or norm(e["surface"])]


def count(e: dict, key, text_norm: str, text_raw: str, month_first: bool) -> int:
    if e.get("match") == "dob":
        from attacker import all_dates
        target = dt.date.fromisoformat(key)
        return sum(1 for d in all_dates(text_raw) if d == target)
    return count_key(e, norm(key) if e.get("match") in ("text", "name") else key, text_norm)


class Ctx:
    def __init__(self, kit, out, truth, inp):
        self.kit, self.out, self.truth, self.inp = kit, out, truth, inp
        self.omap = output_map(out)
        self.recs = load_records(out)
        self.report = load_report(out)
        self.cache = {}

    def in_text(self, rel, f):
        k = ("in", rel)
        if k not in self.cache:
            try:
                self.cache[k] = (self.inp / rel).read_bytes().decode(f.get("encoding") or "utf-8", "replace")
            except (OSError, LookupError):
                self.cache[k] = read(self.inp / rel)
        return self.cache[k]

    def out_rel(self, f):
        return self.omap.get(f["sha256"])

    def out_text(self, f):
        o = self.out_rel(f)
        if not o:
            return None
        k = ("out", o)
        if k not in self.cache:
            self.cache[k] = read(self.out / o)
        return self.cache[k]


# ============================================================================ detection
def detection(c: Ctx) -> dict:
    per_type, per_script = defaultdict(list), defaultdict(list)
    leaked_critical = set()
    exposed_patients = set()
    canaries = set()
    everything = []
    for p in sorted(c.out.rglob("*")):
        if p.is_file():
            everything.append(p.name)
            everything.append(read(p))
    everything = scan("\n".join(everything))
    for rel, f in c.truth["files"].items():
        o = c.out_rel(f)
        otext = c.out_text(f)
        itext = c.in_text(rel, f)
        mf = f.get("date_hint") == "mdy"
        for loc, u in f["units"].items():
            pres_in = [norm(pv["text"]) for pv in u.get("preserve") or []]
            ui = unit_text(itext, loc, f.get("format"), f.get("delimiter")) or itext
            uo = None
            if otext is not None:
                uo = unit_text(otext, loc, f.get("format"), f.get("delimiter"))
                if uo is None:
                    uo = otext                     # not locatable: anywhere in the file counts
            ui_n, uo_n = scan(ui), (scan(uo) if uo is not None else "")
            for e in u["entities"]:
                if e["type"] == "CANARY":
                    if norm(e["surface"]) and norm(e["surface"]) in everything:
                        canaries.add(e["surface"])
                    continue
                if e["channel"] == "filename":
                    hay_in, hay_out = norm(rel), norm(o or "")
                    raw_in, raw_out = rel, o or ""
                else:
                    hay_in, hay_out, raw_in, raw_out = ui_n, uo_n, ui, uo or ""
                leaks = []
                for k in keys_of(e):
                    occ_in = count(e, k, hay_in, raw_in, mf)
                    allowed = sum(count(e, k, pv, pv, mf) for pv in pres_in) if e.get("match") != "dob" else 0
                    pii = max(occ_in - allowed, 1)
                    occ_out = count(e, k, hay_out, raw_out, mf) if (otext is not None or e["channel"] == "filename") else 0
                    leaks.append(min(max(occ_out - allowed, 0), pii) / pii)
                leak = sum(leaks) / len(leaks) if leaks else 0.0
                per_type[e["type"]].append(1 - leak)
                per_script[e["script"]].append(1 - leak)
                if e.get("critical") and leak > 0:
                    leaked_critical.add((e["type"], norm(e["surface"])))
                    if e.get("role") == "patient" and u.get("patient"):
                        exposed_patients.add(u["patient"])
    type_rec = {t: sum(v) / len(v) for t, v in per_type.items()}
    script_rec = {s: sum(v) / len(v) for s, v in per_script.items()}
    tw = sum(TYPE_W.get(t, 1.0) for t in type_rec)
    macro_type = sum(TYPE_W.get(t, 1.0) * r for t, r in type_rec.items()) / tw if tw else 1.0
    macro_script = sum(script_rec.values()) / len(script_rec) if script_rec else 1.0
    recall = 0.5 * macro_type + 0.5 * macro_script

    groups = defaultdict(list)
    for rel, f in c.truth["files"].items():
        otext = c.out_text(f)
        for loc, u in f["units"].items():
            uo = unit_text(otext, loc, f.get("format"), f.get("delimiter")) if otext is not None else None
            hay = norm(uo if uo is not None else (otext or ""))
            for pv in u.get("preserve") or []:
                if pv.get("trap"):
                    groups[pv["trap"]].append(norm(pv["text"]) in hay)
    trap = {g: sum(v) / len(v) for g, v in groups.items()}
    clean_ret = token_retention(c, clean_only=True)
    parts = list(trap.values()) + [clean_ret]
    precision = sum(parts) / len(parts)
    return {"score": f_beta(precision, recall, 2.0), "precision": precision, "recall": recall,
            "macro_type": macro_type, "macro_script": macro_script,
            "type_recall": {k: round(v, 4) for k, v in sorted(type_rec.items())},
            "script_recall": {k: round(v, 4) for k, v in sorted(script_rec.items())},
            "trap_groups": {k: round(v, 4) for k, v in sorted(trap.items())}, "clean_retention": clean_ret,
            "_leaked_critical": leaked_critical, "_exposed": exposed_patients, "_canaries": canaries}


def token_retention(c: Ctx, clean_only: bool = False) -> float:
    kept = total = 0
    for rel, f in c.truth["files"].items():
        if clean_only and not f.get("clean"):
            continue
        if f.get("expect") == "either":
            continue
        pii = set()
        for u in f["units"].values():
            for e in u["entities"]:
                pii |= {t.casefold() for t in TOKEN.findall(e["surface"])}
            for d in u.get("dates") or []:
                pass
        it = Counter(t.casefold() for t in TOKEN.findall(c.in_text(rel, f))
                     if t.casefold() not in pii and not t.isdigit())
        ot = c.out_text(f)
        oc = Counter(t.casefold() for t in TOKEN.findall(ot or ""))
        total += sum(it.values())
        kept += sum((it & oc).values())
    return kept / total if total else 1.0


# ============================================================================ identity
def identity(c: Ctx) -> dict:
    units = []
    for rel, f in c.truth["files"].items():
        o = c.out_rel(f)
        for loc, u in f["units"].items():
            if not u.get("patient") or u.get("link") not in ("required", "ambiguous") or loc.startswith("@"):
                continue
            y = record_for(o, loc, c.recs)[0] if o else None
            units.append((u["patient"], y, u.get("link")))
    if not any(y for _, y, _ in units):
        return {"score": 0.0, "note": "no pseudonyms"}
    tp = fp = 0
    for i, j in itertools.combinations(range(len(units)), 2):
        a, b = units[i], units[j]
        if a[1] and a[1] == b[1]:
            if a[0] == b[0]:
                tp += 1
            else:
                fp += 1
    req = [x for x in units if x[2] == "required"]
    by_true = Counter(t for t, _, _ in req)
    linkable = sum(n * (n - 1) // 2 for n in by_true.values())
    tp_req = sum(1 for i, j in itertools.combinations(range(len(req)), 2)
                 if req[i][1] and req[i][1] == req[j][1] and req[i][0] == req[j][0])
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp_req / linkable if linkable else 1.0
    f05 = f_beta(p, r, 0.5)
    # B-cubed (records without a pseudonym are singletons)
    cl = [y or f"_s{i}" for i, (_, y, _) in enumerate(units)]
    by_c = defaultdict(list)
    for i, k in enumerate(cl):
        by_c[k].append(i)
    by_t = defaultdict(list)
    for i, (t, _, _) in enumerate(units):
        by_t[t].append(i)
    bp = br = 0.0
    for i, (t, _, _) in enumerate(units):
        same_c = by_c[cl[i]]
        same_t = by_t[t]
        inter = sum(1 for j in same_c if units[j][0] == t)
        bp += inter / len(same_c)
        br += inter / len(same_t)
    bp, br = bp / len(units), br / len(units)
    b3 = f_beta(bp, br, 1.0)
    traps = c.truth["traps"]

    def pair_recall(pats):
        tot = hit = 0
        for pid in pats:
            ys = [y for t, y, l in req if t == pid]
            for a, b in itertools.combinations(ys, 2):
                tot += 1
                hit += bool(a and a == b)
        return hit / tot if tot else 1.0
    homo_tot = homo_ok = 0
    for a, b in traps.get("homonym_pairs", []):
        ya = {y for t, y, _ in units if t == a and y}
        yb = {y for t, y, _ in units if t == b and y}
        homo_tot += 1
        homo_ok += not (ya & yb)
    lang, frag = pair_recall(traps.get("language", [])), pair_recall(traps.get("fragmented", []))
    homo = homo_ok / homo_tot if homo_tot else 1.0
    score = 0.4 * f05 + 0.3 * b3 + 0.1 * lang + 0.1 * frag + 0.1 * homo
    return {"score": score, "precision": p, "recall": r, "f05": f05, "b3": b3, "language": lang,
            "fragmented": frag, "homonym": homo}


# ============================================================================ utility
def _date_at(otext, d, f, loc):
    mf = f.get("date_hint") == "mdy"
    if d.get("anchor"):
        uo = unit_text(otext, loc, f.get("format"), f.get("delimiter")) or otext
        for hay in (uo, otext):
            idx = hay.find(d["anchor"])
            if idx >= 0:
                from attacker import all_dates
                seg = hay[idx + len(d["anchor"]):][:160]
                got = parse_one(seg[:48], mf)
                if got is None:
                    ds = all_dates(seg)
                    got = ds[0] if ds else None
                if got is not None:
                    return got
    path = d.get("path") or ""
    if path.startswith("/") and loc.startswith("/"):
        v = unit_text(otext, loc.rstrip("/") + path, "json")
        if v is not None:
            try:
                v = json.loads(v)
            except ValueError:
                pass
            return parse_one(str(v), mf)
    if path.startswith("col:") and loc.startswith("row:"):
        rows = list(csv.reader(io.StringIO(otext), delimiter=f.get("delimiter") or ","))
        col, r = path[4:], int(loc[4:]) + 1
        if rows and col in rows[0] and r < len(rows) and rows[0].index(col) < len(rows[r]):
            return parse_one(rows[r][rows[0].index(col)], mf)
    if path.startswith("/"):
        v = unit_text(otext, path, "json")
        if v:
            try:
                v = json.loads(v)
            except ValueError:
                pass
            return parse_one(str(v), mf)
    return None


def utility(c: Ctx) -> dict:
    # clinical probes
    num = den = 0.0
    for rel, f in c.truth["files"].items():
        otext = c.out_text(f)
        for loc, u in f["units"].items():
            uo = unit_text(otext, loc, f.get("format"), f.get("delimiter")) if otext is not None else None
            for pv in u.get("preserve") or []:
                w = pv.get("weight", 1.0)
                den += w
                t = norm(pv["text"])
                if uo is not None and t in norm(uo):
                    num += w
                elif otext is not None and t in norm(otext):
                    num += 0.8 * w
    probes = num / den if den else 1.0
    # temporal
    events = defaultdict(list)
    for rel, f in c.truth["files"].items():
        otext = c.out_text(f)
        for loc, u in f["units"].items():
            for d in u.get("dates") or []:
                got = _date_at(otext, d, f, loc) if otext is not None else None
                events[d.get("patient") or u.get("patient")].append((dt.date.fromisoformat(d["true"]), got, d["event"]))
    iv_tot = iv_score = 0.0
    los_tot = los_score = 0.0
    shifts = defaultdict(set)
    for pid, evs in events.items():
        for (t1, g1, e1), (t2, g2, e2) in itertools.combinations(evs, 2):
            iv_tot += 1
            if g1 and g2:
                diff = abs(((g2 - g1) - (t2 - t1)).days)
                iv_score += 1.0 if diff == 0 else 0.5 if diff == 1 else 0.0
            if {e1, e2} == {"admission", "discharge"}:
                los_tot += 1
                if g1 and g2:
                    los_score += 1.0 if (g2 - g1) == (t2 - t1) else 0.0
        for t, g, _ in evs:
            if g:
                shifts[pid].add((g - t).days)
    temporal = 0.6 * (iv_score / iv_tot if iv_tot else 1.0) + 0.4 * (los_score / los_tot if los_tot else 1.0)
    # generalization
    gen = []
    for rel, f in c.truth["files"].items():
        otext = c.out_text(f)
        for loc, u in f["units"].items():
            for fld in u.get("fields") or []:
                v = _field_value(otext, fld, f, loc) if otext is not None else None
                gen.append(_gen_score(fld, v))
    generalization = sum(gen) / len(gen) if gen else 1.0
    # statistics (approx): ICD distribution + LOS + lab probes
    icd_in, icd_out = Counter(), Counter()
    rx = re.compile(r"(?<![A-Za-z0-9])([A-TV-Z]\d{2}(?:\.\d{1,2})?)(?![A-Za-z0-9])")
    labs = []
    for rel, f in c.truth["files"].items():
        if f.get("clean"):
            continue
        icd_in.update(rx.findall(c.in_text(rel, f)))
        icd_out.update(rx.findall(c.out_text(f) or ""))
        ot = norm(c.out_text(f) or "")
        for u in f["units"].values():
            for pv in u.get("preserve") or []:
                if pv.get("kind") == "lab":
                    labs.append(norm(pv["text"]) in ot)
    def tvd(a, b):
        sa, sb = sum(a.values()) or 1, sum(b.values()) or 1
        return 0.5 * sum(abs(a[k] / sa - b[k] / sb) for k in set(a) | set(b))
    stats = (1 - tvd(icd_in, icd_out) + (los_score / los_tot if los_tot else 1.0) +
             (sum(labs) / len(labs) if labs else 1.0)) / 3
    tok = token_retention(c)
    loc_ok = loc_all = 0
    for rel, f in c.truth["files"].items():
        if f.get("expect") == "either":
            continue
        otext = c.out_text(f)
        for loc in f["units"]:
            loc_all += 1
            loc_ok += otext is not None and unit_text(otext, loc, f.get("format"), f.get("delimiter")) is not None
    rec_ret = loc_ok / loc_all if loc_all else 1.0
    score = 0.35 * probes + 0.20 * temporal + 0.10 * generalization + 0.15 * stats + 0.10 * tok + 0.10 * rec_ret
    return {"score": score, "probes": probes, "temporal": temporal, "generalization": generalization,
            "statistics_approx": stats, "token_retention": tok, "record_retention": rec_ret,
            "patients_multi_shift": sum(1 for v in shifts.values() if len(v) > 1),
            "unshifted_dates": sum(1 for v in shifts.values() if 0 in v)}


def _field_value(otext, fld, f, loc):
    path = fld.get("path") or ""
    if path.startswith("col:") and loc.startswith("row:"):
        rows = list(csv.reader(io.StringIO(otext), delimiter=f.get("delimiter") or ","))
        col, r = path[4:], int(loc[4:]) + 1
        if rows and col in rows[0] and r < len(rows) and rows[0].index(col) < len(rows[r]):
            return rows[r][rows[0].index(col)]
        return None
    if path.startswith("/"):
        v = unit_text(otext, path, "json")
        if v is None:
            return None
        try:
            return json.loads(v)
        except ValueError:
            return v
    return None


def _gen_score(fld, v) -> float:
    k, true = fld["kind"], fld.get("true")
    if v is None or str(v).strip() == "" or str(v).startswith("["):
        return 0.0
    s = str(v)
    if k == "age":
        m = re.search(r"(\d{1,3})\s*-\s*(\d{1,3})", s)
        if m:
            lo, hi = int(m.group(1)), int(m.group(2))
            if not lo <= int(true) <= hi:
                return 0.0
            w = hi - lo + 1
            return 0.9 if w <= 5 else 0.8 if w <= 10 else 0.6 if w <= 20 else 0.3
        m = re.search(r"(\d{1,3})\+", s)
        if m:
            return 0.3 if int(true) >= int(m.group(1)) else 0.0
        m = re.search(r"\d{1,3}", s)
        return 1.0 if m and int(m.group(0)) == int(true) else 0.0
    if k == "gender":
        return 1.0 if s.strip().lower()[:1] in ("m", "f", "म", "प") or s.strip() in ("पुरुष", "महिला") else 0.0
    if k == "dob":
        if re.fullmatch(r"\d{4}", s.strip()):
            return 0.8 if s.strip() == true[:4] else 0.0
        for mf in (False, True):
            d = parse_one(s, mf)
            if d:
                diff = abs((d - dt.date.fromisoformat(true)).days)
                return 1.0 if diff == 0 else 0.9 if diff <= 366 else 0.0
        return 0.0
    if k == "village":
        return 1.0 if norm(s) == norm(str(true)) else 0.7     # replaced by district
    if k == "district":
        return 1.0 if norm(s) == norm(str(true)) else 0.0
    if k == "pin":
        d = re.sub(r"\D", "", s)
        return 1.0 if d == str(true) else 0.7 if len(d) == 3 and str(true).startswith(d) else 0.0
    return 0.0


# ============================================================================ integrity
def integrity(c: Ctx, crit: set) -> dict:
    fmt, schema, fh = [], [], []
    for rel, f in c.truth["files"].items():
        o = c.out_rel(f)
        if not o or f.get("expect") == "either":
            continue
        raw = (c.out / o).read_bytes()
        try:
            text = raw.decode("utf-8")
            ok = True
        except UnicodeDecodeError:
            fmt.append(0.0)
            continue
        itext = c.in_text(rel, f)
        if f["format"] in ("csv", "tsv"):
            d = f.get("delimiter") or ","
            try:
                ri = list(csv.reader(io.StringIO(itext.lstrip("﻿")), delimiter=d))
                ro = list(csv.reader(io.StringIO(text.lstrip("﻿")), delimiter=d))
            except csv.Error:
                ok = False
                ri = ro = []
            if ok and ri:
                parts = [len(ri) == len(ro),
                         bool(ro) and len(ri[0]) == len(ro[0]),
                         bool(ro) and sum(a == b for a, b in zip(ri[0], ro[0])) / max(len(ri[0]), 1) >= 0.99,
                         all(len(a) == len(b) for a, b in zip(ri, ro))]
                schema.append(sum(parts) / len(parts))
        elif f["format"] == "json":
            try:
                ji, jo = json.loads(itext), json.loads(text)
                pi, po = set(_paths(ji)), set(_paths(jo))
                jac = len(pi & po) / len(pi | po) if pi | po else 1.0
                ti, to = dict(_typed(ji)), dict(_typed(jo))
                same = sum(1 for k in ti if k in to and ti[k] == to[k]) / len(ti) if ti else 1.0
                schema.append(0.5 * jac + 0.5 * same)
                if fhir.is_fhir(jo):
                    fh.append(0.0 if fhir.problems(jo) else 1.0)
            except ValueError:
                ok = False
        else:
            li, lo = itext.count("\n") + 1, text.count("\n") + 1
            schema.append(min(li, lo) / max(li, lo))
        fmt.append(1.0 if ok else 0.0)
    # pseudonym consistency
    claims = hit = 0
    for (file, loc), y in c.recs.items():
        if not y:
            continue
        claims += 1
        t = read(c.out / file)
        u = unit_text(t, loc, "csv" if file.endswith(".csv") else "tsv" if file.endswith(".tsv")
                      else "json" if file.endswith(".json") else "text",
                      "\t" if file.endswith(".tsv") else ",")
        hit += y in (u if u is not None else t)
    pc = hit / claims if claims else 0.0
    # channel hygiene: report, records, logs, other files, file names (stdout/stderr, tmp: assumed clean)
    def dirty(text):
        n = scan(text)
        return any(s and s in n for _, s in crit)
    chans = [read(c.out / "report.json"), read(c.out / "records.jsonl"),
             "\n".join(read(p) for p in (c.out / "logs").rglob("*") if p.is_file()) if (c.out / "logs").is_dir() else "",
             "\n".join(read(p) for p in c.out.iterdir() if p.is_file() and p.name not in ("report.json", "records.jsonl")),
             "\n".join(str(p.relative_to(c.out)) for p in c.out.rglob("*"))]
    hyg = (sum(0.0 if dirty(t) else 1.0 for t in chans) + 2) / 7
    # quarantine handling
    either = [f for f in c.truth["files"].values() if f.get("expect") == "either"]
    reported = {e.get("input_sha256") for e in c.report.get("files") or []}
    safe = raw_copies = 0
    for f in either:
        o = c.out_rel(f)
        src = c.inp / f["path"]
        copied = bool(o) and src.is_file() and (c.out / o).read_bytes() == src.read_bytes()
        raw_copies += copied
        safe += not copied
    silent = sum(1 for f in c.truth["files"].values() if f["sha256"] not in reported)
    n = len(c.truth["files"])
    qh = 0.5 * (safe / len(either) if either else 1.0) + 0.3 * (1 - silent / n) + 0.2 * (1 - raw_copies / max(len(either), 1))
    # report quality
    rep = c.report
    cnt = rep.get("counts") or {}
    need = ["files_total", "files_sanitized", "files_quarantined", "records_processed", "identifiers_detected",
            "records_linked", "records_generalized", "records_suppressed", "records_quarantined"]
    complete = (sum(k in cnt for k in need) / len(need) + bool(rep.get("files")) + bool(rep.get("entities"))) / 3
    timing = isinstance(rep.get("timing"), dict) and isinstance(rep.get("resources"), dict)
    files = rep.get("files") or []
    listed_all = {e.get("input_sha256") for e in files} >= {f["sha256"] for f in c.truth["files"].values()}
    exported = sum(1 for e in files if e.get("output") and (c.out / e["output"]).is_file())
    honest = (cnt.get("files_total") == len(files) and cnt.get("files_sanitized") == exported and
              cnt.get("files_quarantined") == sum(1 for e in files if e.get("status") == "quarantined"))
    complete = 0.8 * complete + 0.2 * timing if listed_all else 0.0
    rq = 0.5 * complete + 0.5 * honest
    parts = {"format_validity": sum(fmt) / len(fmt) if fmt else 1.0,
             "schema_preservation": sum(schema) / len(schema) if schema else 1.0,
             "fhir_validity": sum(fh) / len(fh) if fh else 1.0, "pseudonym_consistency": pc,
             "channel_hygiene": hyg, "quarantine_handling": qh, "report_quality": rq}
    w = {"format_validity": .15, "schema_preservation": .20, "fhir_validity": .15, "pseudonym_consistency": .10,
         "channel_hygiene": .15, "quarantine_handling": .15, "report_quality": .10}
    return {"score": sum(w[k] * v for k, v in parts.items()), **parts, "_raw_copies": raw_copies, "_silent": silent}


def _paths(node, prefix=""):
    if isinstance(node, dict):
        for k, v in node.items():
            yield prefix + "/" + k
            yield from _paths(v, prefix + "/" + k)
    elif isinstance(node, list):
        for x in node:
            yield from _paths(x, prefix + "/*")


def _typed(node, prefix=""):
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _typed(v, prefix + "/" + k)
    elif isinstance(node, list):
        for i, x in enumerate(node):
            yield from _typed(x, prefix + "/" + str(i))
    else:
        yield prefix, type(node).__name__


# ============================================================================ performance
def performance(c: Ctx, rerun: Path | None) -> dict:
    rep = c.report
    t = next((rep[k] for k in ("runtime_seconds", "wall_seconds", "elapsed_seconds") if k in rep), None)
    if t is None and isinstance(rep.get("timing"), dict):
        t = next(iter(v for v in rep["timing"].values() if isinstance(v, (int, float))), None)
    mem = next((rep[k] for k in ("peak_rss_mb", "peak_memory_mb") if k in rep), None)
    if mem is None and isinstance(rep.get("resources"), dict):
        mem = rep["resources"].get("peak_rss_mb")

    def loglin(x, good, limit):
        if x is None:
            return 1.0
        if x <= good:
            return 1.0
        if x >= limit:
            return 0.0
        return 1 - (math.log(x) - math.log(good)) / (math.log(limit) - math.log(good))
    det = 1.0
    if rerun:
        same = tot = 0
        for p in (c.out / "sanitized").rglob("*"):
            if p.is_file():
                tot += 1
                q = rerun / p.relative_to(c.out)
                same += q.is_file() and q.read_bytes() == p.read_bytes()
        same += read(c.out / "records.jsonl") == read(rerun / "records.jsonl")
        det = same / (tot + 1)
    ts, ms = loglin(t, 60, 900), loglin(mem, 512, 4096)
    return {"score": 0.3 * 1.0 + 0.3 * ts + 0.2 * ms + 0.2 * det, "time_s": t, "mem_mb": mem, "determinism": det}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kit", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--rerun", help="second run, same secret (determinism)")
    ap.add_argument("--other", help="run with a different secret (A7)")
    ap.add_argument("--input")
    ap.add_argument("--truth")
    ap.add_argument("--no-attack", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    kit, out = Path(a.kit), Path(a.output)
    truth = load_truth(kit, a.truth)
    c = Ctx(kit, out, truth, Path(a.input) if a.input else kit / "dev/input")
    det = detection(c)
    ide = identity(c)
    uti = utility(c)
    crit = det["_leaked_critical"]
    all_crit = {(e["type"], norm(e["surface"])) for f in truth["files"].values() for u in f["units"].values()
                for e in u["entities"] if e.get("critical")}
    integ = integrity(c, crit)
    perf = performance(c, Path(a.rerun) if a.rerun else None)
    priv = {"score": None}
    if not a.no_attack and (kit / "dev/attacker/registry.csv").is_file() and not a.truth:
        import attacker as A
        raw = A.attack(c.inp, kit, truth, raw=True)
        rel = A.attack(out, kit, truth, raw=False)
        n = rel["patients"] or 1
        a1 = len(det["_exposed"]) / n
        inv = A.inversion(out, truth, kit)
        xr = A.cross_release(out, Path(a.other), truth) if a.other else None
        pr = A.privacy_risk(rel, {**raw, "direct_exposure": 1.0}, inv, xr, a1)
        priv = {"score": (1 - pr["risk"]) * min(1.0, uti["score"] / 0.40), "risk": pr["risk"],
                **pr["components"], "raw": {k: round(v, 3) for k, v in raw.items() if isinstance(v, float)}}
    pen_leak = min(25, len(crit))
    pen_canary = min(15, 3 * len(det["_canaries"]))
    pen_raw = min(20, 5 * integ["_raw_copies"])
    pen_false = 10 if integ["_silent"] else 0
    scores = {"detection": det["score"], "identity": ide["score"], "utility": uti["score"],
              "integrity": integ["score"], "performance": perf["score"],
              "privacy": priv["score"] if priv["score"] is not None else 0.0}
    penalties = pen_leak + pen_canary + pen_raw + pen_false
    total = 100 * sum(WEIGHTS[k] * v for k, v in scores.items()) - penalties
    clean = lambda d: {k: (round(v, 4) if isinstance(v, float) else v) for k, v in d.items() if not k.startswith("_")}
    result = {"total": round(total, 2), "penalties": {"leaked_identifiers": pen_leak, "canaries": pen_canary,
                                                     "raw_copies": pen_raw, "false_success": pen_false},
              "points": {k: round(100 * WEIGHTS[k] * v, 2) for k, v in scores.items()},
              "detection": clean(det), "identity": clean(ide), "privacy": clean(priv), "utility": clean(uti),
              "integrity": clean(integ), "performance": clean(perf),
              "leaked_critical_examples": sorted(crit)[:15]}
    if a.json:
        print(json.dumps(result, ensure_ascii=False, indent=1))
        return 0
    print("=" * 70)
    print(f" PROJECTED TOTAL {result['total']:.2f} / 100   (penalties -{penalties})")
    print("=" * 70)
    for k, v in result["points"].items():
        print(f"  {k:<12} {v:6.2f} / {100 * WEIGHTS[k]:.0f}")
    for k in ("detection", "identity", "privacy", "utility", "integrity", "performance"):
        print(f"\n[{k}]", json.dumps(result[k], ensure_ascii=False))
    if crit:
        print("\nleaked critical:", result["leaked_critical_examples"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
