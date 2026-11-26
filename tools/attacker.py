#!/usr/bin/env python3
"""Dev-only re-implementation of the published privacy attacker (docs/ATTACKS.md), A1-A7.

    python tools/attacker.py --kit ../Secret-Wards-ToolKit --output out_a [--other out_c]

Runs every attack on the release AND on the raw input (A1-A5 are scored relative to raw), and
prints the privacy risk exactly as SCORING.md combines it. Never imported by the pipeline.
"""
from __future__ import annotations

import argparse
import base64
import csv
import datetime as dt
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

from _common import (digit_rx, load_records, load_truth, norm, output_map, read, record_for,
                     scan, unit_text, with_payloads)
from rakshak.link.translit import deva_to_latin, phonetic, skeleton
from rakshak.privacy.dates import _MON_RX, RX_ISO, RX_NUM, _mon_index, _valid, _year

RX_DMONY = re.compile(rf"(?<![A-Za-z\d])(\d{{1,2}})(?:st|nd|rd|th)?[\s-]+({_MON_RX})\.?[\s,-]+(\d{{4}})(?!\d)", re.I)
RX_MONDY = re.compile(rf"(?<![A-Za-z\d])({_MON_RX})\.?\s(\d{{1,2}})(?:st|nd|rd|th)?,?\s(\d{{4}})(?!\d)", re.I)

# ----------------------------------------------------------------------------- evidence
RX_PHONE = re.compile(r"(?<!\d)(?:\+?91[\s-]?)?([6-9]\d{2}[\s-]?\d{2}[\s-]?\d{5}|[6-9]\d{4}[\s-]?\d{5})(?!\d)")
RX_MASKED_PHONE = re.compile(r"(?<![\dX])(\d{2})[X*x]{6}(\d{2})(?![\dX])")
RX_LAST4 = re.compile(r"[X*x]{4}[\s-]?[X*x]{4}[\s-]?(\d{4})(?!\d)")
RX_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")
RX_PIN = re.compile(r"(?<![\d-])([1-8]\d{5})(?![\d-])")
RX_PINPFX = re.compile(r"(?<!\d)(\d{3})\s?(?:\*{3}|XXX|xxx)(?![\d*])")
RX_AGE_BAND = re.compile(r"(?<![\d/.:-])(\d{1,3})\s*-\s*(\d{1,3})(?=\s*(?:Y\b|Yrs|yrs|years|वर्ष|/|\)|,|$|\s*\n))")
RX_AGE_BRACKET = re.compile(r"\[(\d{1,3}),\s*(\d{1,3})\)")
RX_AGE_TOP = re.compile(r"(?<!\d)(\d{2,3})\+")
RX_AGE_EXACT = re.compile(r"(?:\bAge(?:/Sex)?|आयु|Umar|उम्र)\s*[:\-]?\s*\"?(\d{1,3})(?![\d-])|"
                          r"(?<![\d/.:-])(\d{1,3})\s*(?:Y|Yrs|yrs|years)\s*/|(?<![\d/.:-])(\d{1,3})\s*/\s*[MF]\b|"
                          r"(?<![\d/.:-])(\d{1,3})\s*वर्ष|\"age\"\s*:\s*(\d{1,3})\b", re.I)
RX_GENDER = re.compile(r"(?<![A-Za-z])(?:/\s*([MF])\b|(Male|Female|male|female|MALE|FEMALE)\b)|(महिला|पुरुष)|"
                       r"\b(S/o|D/o|W/o)\b|\b(sahab|behenji|bhai|amma|didi)\b", re.I)
RX_DOB = re.compile(r"(?:DOB|D\.O\.B|Date of Birth|birthDate|dob|Janm Tithi|जन्म तिथि)\W{0,4}([^\n,;\"]{4,24})", re.I)
RX_HOUSE = re.compile(r"(?:H\.?\s?No\.?|House(?:\s+No\.?)?|Makan\s+No\.?|मकान\s+नं\.?)\s*[:#]?\s*(\d{1,4})", re.I)
RX_REL = re.compile(r"\b(?:S/o|D/o|W/o|C/O|C/o|c/o|पिता|पति)\b\.?\s*:?\s*((?:[A-Z][a-z]+\.?\s?){1,3}|[ऀ-ॿ]+(?:\s[ऀ-ॿ]+){0,2})")
RX_DR = re.compile(r"\b(?:Dr|DR|Doctor)\.?\s+((?:[A-Z][a-z]+\s?){1,3})")
RX_WORD = re.compile(r"[A-Za-z]+|[ऀ-ॿ]+")


def _tok_key(t: str) -> str:
    if re.search(r"[ऀ-ॿ]", t):
        t = deva_to_latin(t)
    return phonetic(t.lower())


def all_dates(text: str) -> list[dt.date]:
    out = []
    for m in RX_ISO.finditer(text):
        y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
        if _valid(y, mo, d):
            out.append(dt.date(y, mo, d))
    for m in RX_NUM.finditer(text):
        a, b, y = int(m.group(1)), int(m.group(3)), _year(m.group(4))
        for mo, d in ((b, a), (a, b)):           # attacker tries both orders
            if _valid(y, mo, d):
                out.append(dt.date(y, mo, d))
    for m in RX_DMONY.finditer(text):
        mo = _mon_index(m.group(2))
        y, d = int(m.group(3)), int(m.group(1))
        if _valid(y, mo, d):
            out.append(dt.date(y, mo, d))
    for m in RX_MONDY.finditer(text):
        mo, d, y = _mon_index(m.group(1)), int(m.group(2)), int(m.group(3))
        if _valid(y, mo, d):
            out.append(dt.date(y, mo, d))
    return out


class Gaz:
    """Public knowledge: place gazetteer and name vocabulary (from the registry), rare conditions."""

    def __init__(self, registry: list[dict], facts: list[dict]):
        self.districts = {norm(r["district"]): r["district"] for r in registry if r["district"]}
        self.tehsils = {norm(r["tehsil"]): r["tehsil"] for r in registry if r["tehsil"]}
        self.villages = {norm(r["village"]): r["village"] for r in registry if r["village"]}
        self.name_keys = set()
        for r in registry:
            for t in RX_WORD.findall(r["name"] + " " + r["relative_name"]):
                self.name_keys.add(_tok_key(t))
        self.conditions = sorted({norm(f["condition_hint"]) for f in facts if f.get("condition_hint")})
        self.hospitals = sorted({norm(f["hospital"]) for f in facts if f.get("hospital")})
        self.place_deva = {}
        for store in (self.districts, self.tehsils, self.villages):
            for k in store:
                self.place_deva[phonetic(k.replace(" ", ""))] = k


def evidence(text: str, gz: Gaz) -> dict:
    t = with_payloads(text)
    low = norm(t)
    ev = {"phones": set(), "masked": set(), "last4": set(), "emails": set(), "district": set(),
          "tehsil": set(), "village": set(), "pin": set(), "pinpfx": set(), "gender": set(),
          "lo": 0, "hi": 200, "by": set(), "names": set(), "rels": set(), "house": set(),
          "cond": set(), "hosp": set(), "dates": set(), "stays": set(), "refs": set()}
    for m in RX_PHONE.finditer(t):
        ev["phones"].add(re.sub(r"\D", "", m.group(1))[-10:])
    for m in RX_MASKED_PHONE.finditer(t):
        ev["masked"].add((m.group(1), m.group(2)))
    for m in RX_LAST4.finditer(t):
        ev["last4"].add(m.group(1))
    for m in RX_EMAIL.finditer(t):
        ev["emails"].add(m.group(0).lower())
    for m in RX_PIN.finditer(t):
        if not any(m.group(1) in p for p in ev["phones"]):
            ev["pin"].add(m.group(1))
    for m in RX_PINPFX.finditer(t):
        ev["pinpfx"].add(m.group(1))
    for k in gz.districts:
        if re.search(r"(?<!\w)" + re.escape(k) + r"(?!\w)", low):
            ev["district"].add(k)
    for k in gz.tehsils:
        if re.search(r"(?<!\w)" + re.escape(k) + r"(?!\w)", low):
            ev["tehsil"].add(k)
    for k in gz.villages:
        if re.search(r"(?<!\w)" + re.escape(k) + r"(?!\w)", low):
            ev["village"].add(k)
    for w in re.findall(r"[ऀ-ॿ]+(?:\s[ऀ-ॿ]+)?", t):  # Devanagari place names
        k = gz.place_deva.get(phonetic(deva_to_latin(w).replace(" ", "")))
        if k:
            for store, key in ((gz.districts, "district"), (gz.tehsils, "tehsil"), (gz.villages, "village")):
                if k in store:
                    ev[key].add(k)
    for m in RX_GENDER.finditer(t):
        g = next((x for x in m.groups() if x), "").lower()
        if g in ("f", "female", "महिला", "d/o", "w/o", "behenji", "amma", "didi"):
            ev["gender"].add("F")
        elif g:
            ev["gender"].add("M")
    for m in RX_AGE_BAND.finditer(t):
        lo, hi = int(m.group(1)), int(m.group(2))
        if 0 <= lo < hi <= 120 and hi - lo <= 25:
            ev["lo"], ev["hi"] = max(ev["lo"], lo), min(ev["hi"], hi)
    for m in RX_AGE_BRACKET.finditer(t):
        lo, hi = int(m.group(1)), int(m.group(2)) - 1
        if 0 <= lo < hi <= 120:
            ev["lo"], ev["hi"] = max(ev["lo"], lo), min(ev["hi"], hi)
    for m in RX_AGE_TOP.finditer(t):
        if 60 <= int(m.group(1)) <= 100:
            ev["lo"] = max(ev["lo"], int(m.group(1)))
    for m in RX_AGE_EXACT.finditer(t):
        a = int(next(g for g in m.groups() if g))
        if a <= 120:
            ev["lo"], ev["hi"] = max(ev["lo"], a), min(ev["hi"], a)
    for m in RX_DOB.finditer(t):
        for d in all_dates(m.group(1)):
            ev["by"].add(d.year)
    doctors = set()
    for m in RX_DR.finditer(t):
        doctors |= {_tok_key(x) for x in RX_WORD.findall(m.group(1))}
    for m in RX_REL.finditer(t):
        for x in RX_WORD.findall(m.group(1)):
            k = _tok_key(x)
            if k in gz.name_keys:
                ev["rels"].add(k)
    for x in RX_WORD.findall(t):
        if len(x) < 3:
            continue
        if x[0].isupper() or re.match(r"[ऀ-ॿ]", x):
            k = _tok_key(x)
            if k in gz.name_keys and k not in doctors:
                ev["names"].add(k)
    for m in RX_HOUSE.finditer(t):
        ev["house"].add(m.group(1))
    for c in gz.conditions:
        if c in low:
            ev["cond"].add(c)
    for h in gz.hospitals:
        if h in low:
            ev["hosp"].add(h)
    ds = sorted(set(all_dates(t)))
    ev["dates"] = set(ds)
    for i in range(len(ds)):
        for j in range(i + 1, len(ds)):
            ev["stays"].add((ds[j] - ds[i]).days)
    for m in re.finditer(r"\b(PSN-[0-9A-Z]{6,})\b|\b([A-Z]{2,6}[-/]?\d{2,4}[-/]?\d{3,7})\b", t):
        ev["refs"].add(m.group(0))
    return ev


def merge(a: dict, b: dict) -> dict:
    out = {}
    for k, v in a.items():
        if isinstance(v, set):
            out[k] = v | b[k]
    out["lo"], out["hi"] = max(a["lo"], b["lo"]), min(a["hi"], b["hi"])
    if out["lo"] > out["hi"]:                    # contradictory evidence: keep the looser
        out["lo"], out["hi"] = min(a["lo"], b["lo"]), max(a["hi"], b["hi"])
    return out


# ----------------------------------------------------------------------------- registry attack
def candidates(ev: dict, reg: list[dict], ref_year: int) -> list[dict]:
    filters = [
        lambda r: bool(ev["phones"]) and r["phone"] in ev["phones"],
        lambda r: bool(ev["emails"]) and r["email"].lower() in ev["emails"],
        lambda r: bool(ev["last4"]) and r["aadhaar_last4"] in ev["last4"],
        lambda r: bool(ev["masked"]) and any(r["phone"][:2] == a and r["phone"][-2:] == b for a, b in ev["masked"]),
        lambda r: bool(ev["district"]) and norm(r["district"]) in ev["district"],
        lambda r: bool(ev["gender"]) and r["gender"] in ev["gender"],
        lambda r: (ev["lo"] > 0 or ev["hi"] < 200) and r["age"] != "" and ev["lo"] - 1 <= int(r["age"]) <= ev["hi"] + 2,
        lambda r: bool(ev["by"]) and r["age"] != "" and any(abs(ref_year - y - int(r["age"])) <= 1 for y in ev["by"]),
        lambda r: bool(ev["tehsil"]) and norm(r["tehsil"]) in ev["tehsil"],
        lambda r: bool(ev["village"]) and norm(r["village"]) in ev["village"],
        lambda r: bool(ev["pin"]) and r["pin"] in ev["pin"],
        lambda r: bool(ev["pinpfx"]) and r["pin"][:3] in ev["pinpfx"],
    ]
    active = [bool(ev["phones"]), bool(ev["emails"]), bool(ev["last4"]), bool(ev["masked"]),
              bool(ev["district"]), bool(ev["gender"]), ev["lo"] > 0 or ev["hi"] < 200, bool(ev["by"]),
              bool(ev["tehsil"]), bool(ev["village"]), bool(ev["pin"]), bool(ev["pinpfx"])]
    c = reg
    for f, on in zip(filters, active):
        if not on:
            continue
        nxt = [r for r in c if f(r)]
        if nxt:                                   # a filter that would empty the set is skipped
            c = nxt
    return c


def posterior(ev: dict, cands: list[dict]) -> dict:
    w = {}
    for r in cands:
        x = 1.0
        nt = [_tok_key(t) for t in RX_WORD.findall(r["name"])]
        if nt and all(k in ev["names"] for k in nt):
            x *= 60
        else:
            if nt and nt[0] in ev["names"]:
                x *= 8
            if len(nt) > 1 and nt[-1] in ev["names"]:
                x *= 3
        rt = [_tok_key(t) for t in RX_WORD.findall(r["relative_name"])]
        if rt and (rt[0] in ev["rels"] or (rt[0] in ev["names"] and ev["rels"])):
            x *= 8
        if r["house_no"] and r["house_no"] in ev["house"]:
            x *= 2
        w[r["rid"]] = x
    s = sum(w.values()) or 1.0
    return {k: v / s for k, v in w.items()}


# ----------------------------------------------------------------------------- releases
def release_records(root: Path, truth: dict, raw: bool):
    """(true patient, text, file key) for every patient-bearing record of a release."""
    if raw:
        for rel, f in truth["files"].items():
            p = root / rel
            if not p.is_file():
                continue
            try:
                text = p.read_bytes().decode(f.get("encoding") or "utf-8", "replace")
            except LookupError:
                text = read(p)
            for loc, u in f["units"].items():
                if u.get("patient") and not loc.startswith("@"):
                    yield u["patient"], unit_text(text, loc, f.get("format"), f.get("delimiter")) or text, rel
        return
    omap = output_map(root)
    for rel, f in truth["files"].items():
        o = omap.get(f["sha256"])
        if not o:
            continue
        text = read(root / o)
        for loc, u in f["units"].items():
            if u.get("patient") and not loc.startswith("@"):
                ut = unit_text(text, loc, f.get("format"), f.get("delimiter"))
                yield u["patient"], ut if ut is not None else text, o


def attack(root: Path, kit: Path, truth: dict, raw: bool, a1_exposed: set | None = None) -> dict:
    reg = list(csv.DictReader(open(kit / "dev/attacker/registry.csv", encoding="utf-8")))
    facts = [json.loads(l) for l in open(kit / "dev/attacker/known_facts.jsonl", encoding="utf-8")]
    ref_year = int(truth.get("ref_date", "2026-11-20")[:4])
    gz = Gaz(reg, facts)
    rid_of = {pid: p["rid"] for pid, p in truth["patients"].items()}
    pid_of = {v: k for k, v in rid_of.items()}

    recs = []
    for pid, text, fk in release_records(root, truth, raw):
        recs.append((pid, evidence(text, gz)))
    # A2/A3: record linkage
    rec_probs = []
    for pid, ev in recs:
        post = posterior(ev, candidates(ev, reg, ref_year))
        rec_probs.append(post.get(rid_of.get(pid), 0.0))
    linkage = sum(rec_probs) / len(rec_probs) if rec_probs else 0.0

    # A4: profiles through shared pseudonyms / reference values (union-find on refs)
    parent = list(range(len(recs)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i
    by_ref = defaultdict(list)
    for i, (_, ev) in enumerate(recs):
        for r in ev["refs"]:
            by_ref[r].append(i)
    for members in by_ref.values():
        for j in members[1:]:
            parent[find(j)] = find(members[0])
    groups = defaultdict(list)
    for i in range(len(recs)):
        groups[find(i)].append(i)
    profiles = []
    for g, members in groups.items():
        ev = recs[members[0]][1]
        for j in members[1:]:
            ev = merge(ev, recs[j][1])
        post = posterior(ev, candidates(ev, reg, ref_year))
        profiles.append({"members": members, "ev": ev, "post": post,
                         "true": Counter(recs[j][0] for j in members)})
    best = defaultdict(float)
    for p in profiles:
        for j in p["members"]:
            pid = recs[j][0]
            best[pid] = max(best[pid], p["post"].get(rid_of.get(pid), 0.0), rec_probs[j])
    patients = sorted(best)
    reid = sum(1 for pid in patients if best[pid] >= 0.5) / len(patients) if patients else 0.0

    # A5: targeted attack, with global shift recovery
    offsets = Counter()
    for f in facts:
        pid = pid_of.get(f["rid"])
        for p in profiles:
            if p["post"].get(f["rid"], 0) >= 0.9:
                for kd in f.get("visit_dates", []):
                    k = dt.date.fromisoformat(kd)
                    for d in p["ev"]["dates"]:
                        off = (d - k).days
                        if off != 0 and abs(off) <= 400:
                            offsets[(off, f["rid"])] += 1
    per_off = Counter(off for off, _ in offsets)
    shift = 0
    if per_off:
        off, n = per_off.most_common(1)[0]
        if n >= 2:
            shift = off
    cond_share = Counter()
    for p in profiles:
        for c in p["ev"]["cond"]:
            cond_share[c] += 1
    succ, decoy_claims, targets = [], 0, 0
    for f in facts:
        pid = pid_of.get(f["rid"])
        person = next((r for r in reg if r["rid"] == f["rid"]), None)
        known = {dt.date.fromisoformat(d) for d in f.get("visit_dates", [])}
        cond = norm(f.get("condition_hint") or "")
        hosp = norm(f.get("hospital") or "")
        weights = []
        for p in profiles:
            dates = {d - dt.timedelta(days=shift) for d in p["ev"]["dates"]}
            w = 0.0
            if known & dates:
                w += 1
            if cond and cond in p["ev"]["cond"]:
                w += 8 if cond_share[cond] <= 3 else 1
            if f.get("stay_days") is not None and f["stay_days"] in p["ev"]["stays"]:
                w += 1
            if w == 0:
                continue
            if person is not None and person["rid"] not in p.setdefault(
                    "cand", {r["rid"] for r in candidates(p["ev"], reg, ref_year)}):
                continue                          # evidence inconsistent with this person
            if hosp and hosp in p["ev"]["hosp"]:
                w *= 2
            weights.append((w, pid is not None and p["true"].get(pid, 0) > 0))
        if pid is None:
            decoy_claims += bool(weights)
            continue
        targets += 1
        tot = sum(w for w, _ in weights)
        succ.append(sum(w for w, ok in weights if ok) / tot if tot else 0.0)
    targeted = sum(succ) / len(succ) if succ else 0.0
    out = {"records": len(recs), "patients": len(patients), "record_linkage": linkage,
           "patients_reidentified": reid, "targeted": targeted, "targets": targets,
           "decoy_claims": decoy_claims, "recovered_shift": shift}
    if a1_exposed is not None:
        out["direct_exposure"] = len(a1_exposed & set(patients)) / len(patients) if patients else 0.0
    return out


# ----------------------------------------------------------------------------- A6 / A7
def _transforms(v: str) -> set[str]:
    out = set()
    for s in {v, v.lower(), v.upper(), re.sub(r"\D", "", v), v[::-1]}:
        if not s:
            continue
        out.add(s.lower())
        b = s.encode()
        out.add(base64.b64encode(b).decode().lower().rstrip("="))
        for h in (hashlib.md5, hashlib.sha1, hashlib.sha256, hashlib.sha512):
            out.add(h(b).hexdigest())
    return out


def inversion(out: Path, truth: dict, kit: Path) -> float:
    """A6: share of pseudonymised patients whose pseudonym is reversible."""
    recs = load_records(out)
    omap_rev = {}
    for rel, f in truth["files"].items():
        omap_rev[f["sha256"]] = rel
    omap = output_map(out)
    psn_of = defaultdict(set)
    originals = defaultdict(set)
    for rel, f in truth["files"].items():
        o = omap.get(f["sha256"])
        for loc, u in f["units"].items():
            pid = u.get("patient")
            if not pid:
                continue
            for e in u["entities"]:
                if e.get("role") == "patient" and e["type"] in ("MRN", "AADHAAR", "PHONE", "ABHA_NUMBER", "PATIENT_NAME"):
                    originals[pid].add(e["surface"])
            if o:
                y, _ = record_for(o, loc, recs)
                if y:
                    psn_of[pid].add(y)
    inv = 0
    for pid, ps in psn_of.items():
        tf = set()
        for v in originals[pid]:
            tf |= _transforms(v)
        bad = False
        for p in ps:
            core = re.sub(r"^PSN-", "", p).lower()
            if any(core == t or (len(core) >= 8 and t.startswith(core)) for t in tf):
                bad = True
            for v in originals[pid]:
                d = re.sub(r"\D", "", v)
                if len(d) >= 5 and d in re.sub(r"\D", "", p):
                    bad = True
        inv += bad
    return inv / len(psn_of) if psn_of else 0.0


def cross_release(a: Path, c: Path, truth: dict) -> float:
    """A7: max(share of patients with the same pseudonym, share of shifted dates on the same value)."""
    ra, rc = load_records(a), load_records(c)
    ma, mc = output_map(a), output_map(c)
    same_psn, n_psn = set(), set()
    same_dates = n_dates = 0
    for rel, f in truth["files"].items():
        oa, oc = ma.get(f["sha256"]), mc.get(f["sha256"])
        if not oa or not oc:
            continue
        ta, tc = read(a / oa), read(c / oc)
        for loc, u in f["units"].items():
            pid = u.get("patient")
            if pid:
                ya, _ = record_for(oa, loc, ra)
                yc, _ = record_for(oc, loc, rc)
                if ya and yc:
                    n_psn.add(pid)
                    if ya == yc:
                        same_psn.add(pid)
        da, dc = Counter(all_dates(ta)), Counter(all_dates(tc))
        if f.get("clean"):
            continue
        n_dates += sum(da.values())
        same_dates += sum((da & dc).values())
    p = len(same_psn) / len(n_psn) if n_psn else 0.0
    d = same_dates / n_dates if n_dates else 0.0
    return max(p, d)


def privacy_risk(rel: dict, raw: dict, inv: float | None, xrel: float | None, a1: float) -> dict:
    comps = {"direct_exposure": (0.20, a1 / max(raw.get("direct_exposure", 1.0), 1e-9)),
             "record_linkage": (0.20, rel["record_linkage"] / max(raw["record_linkage"], 1e-9)),
             "profile_reidentification": (0.20, rel["patients_reidentified"] / max(raw["patients_reidentified"], 1e-9)),
             "targeted_attack": (0.20, rel["targeted"] / max(raw["targeted"], 1e-9))}
    if inv is not None:
        comps["pseudonym_inversion"] = (0.10, inv)
    if xrel is not None:
        comps["cross_release"] = (0.10, xrel)
    comps = {k: (w, min(1.0, v)) for k, (w, v) in comps.items()}
    risk = sum(w * v for w, v in comps.values()) / sum(w for w, _ in comps.values())
    return {"risk": risk, "components": {k: round(v, 4) for k, (_, v) in comps.items()}}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kit", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--other", help="a second run with a DIFFERENT secret (A7)")
    ap.add_argument("--truth")
    a = ap.parse_args()
    kit, out = Path(a.kit), Path(a.output)
    truth = load_truth(kit, a.truth)
    raw = attack(kit / "dev/input", kit, truth, raw=True)
    rel = attack(out, kit, truth, raw=False)
    inv = inversion(out, truth, kit)
    xrel = cross_release(out, Path(a.other), truth) if a.other else None
    print("RAW     ", json.dumps({k: round(v, 4) if isinstance(v, float) else v for k, v in raw.items()}))
    print("RELEASE ", json.dumps({k: round(v, 4) if isinstance(v, float) else v for k, v in rel.items()}))
    print("A6 inversion", round(inv, 4), " A7 cross-release", xrel)
    pr = privacy_risk(rel, {**raw, "direct_exposure": 1.0}, inv, xrel, a1=0.0)
    print("RISK (A1 assumed 0 here; selfscore computes it from the leak scan):", json.dumps(pr))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
