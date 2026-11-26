#!/usr/bin/env python3
"""Dev-only: build an UNSEEN-FORMAT test dataset (with its own answer key) from the practice data.

Mutations (consistent across all files, so linkage truth is unchanged):
  * every patient / relative name token -> a new pan-Indian name the pipeline has never seen
    (Latin and Devanagari pools; doctors' names untouched)
  * hospital-ID prefixes changed (SNJ -> KGH, JJH -> RMC, UHID -> MRNO, ...)
  * CSV/TSV headers renamed (Contact#, Gram/Mohalla, Rishtedar, Hospital No, ...)
  * free-text labels changed (Pt Name -, Contact No:, Residence:, मरीज:, ...)
  * phone formats changed ((+91) 7286-490658, 0091 ...)

Output: <out>/input/... and <out>/truth/truth.json in the kit's format, so the kit's check_dev.py
and our tools/diagnose.py work unchanged:  python check_dev.py --output o --truth <out>/truth/truth.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import shutil
from pathlib import Path

# (Latin, Devanagari) pairs, so one person keeps one name across scripts in the test data
PAIRS = [tuple(p.split("/")) for p in """Abhinav/अभिनव Aniruddh/अनिरुद्ध Bhuvan/भुवन Charan/चरण Darshit/दर्शित
Eshan/ईशान Faiyaz/फैयाज़ Girdhar/गिरधर Hemang/हेमांग Ishwar/ईश्वर Jatin/जतिन Kshitij/क्षितिज Madhav/माधव
Nakul/नकुल Ojas/ओजस Pranav/प्रणव Raghunandan/रघुनंदन Saket/साकेत Tanmay/तन्मय Uday/उदय Vaibhav/वैभव Yuvraj/युवराज
Zeeshan/ज़ीशान Anwesha/अन्वेषा Bhavna/भावना Charvi/चार्वी Damini/दामिनी Eshita/ईशिता Falguni/फाल्गुनी Gargi/गार्गी
Hiral/हिरल Jahnavi/जाह्नवी Kalyani/कल्याणी Lavanya/लावण्या Mrinal/मृणाल Naina/नैना Pallavi/पल्लवी
Rukmini/रुक्मिणी Shalini/शालिनी Tanvi/तन्वी Urvashi/उर्वशी Vidisha/विदिशा Yamini/यामिनी Zoya/ज़ोया
Hazarika/हज़ारिका Baruah/बरुआ Gogoi/गोगोई Kalita/कलिता Phukan/फुकन Saikia/सैकिया Konwar/कोंवर Ilango/इलांगो
Perumal/पेरुमल Kurien/कुरियन Varghese/वर्गीज़ Lyngdoh/लिंगदोह Ralte/राल्टे Sailo/सैलो Tsewang/त्सेवांग
Dorjee/दोरजी Thangamani/थंगमणि Velusamy/वेलुसामी Bhowmick/भौमिक Borthakur/बोरठाकुर""".split()]

ID_PREFIX = [("SNJ", "KGH"), ("JJH", "RMC"), ("UHID", "MRNO"), ("DHH", "CHC"), ("IPD", "INP"), ("ADM", "ADX")]
HEADERS = {
    "Patient Name": "Patient's Name", "Mobile": "Contact#", "Village/Mohalla": "Gram/Mohalla",
    "UHID": "Hospital No", "Aadhaar No": "UID No.", "Relative Name": "Rishtedar", "Address": "Residence",
    "DOB": "Birth Date", "PIN": "Postal Code", "Reg Date": "Registered On", "ABHA No": "Health ID",
    "Naam": "Mareez", "Mobile No": "Sampark", "Gaon": "Gram", "Pata": "Niwas", "patient_name": "pt_full_name",
    "uhid": "hosp_no", "LastName": "Surname", "FirstName": "GivenName", "Phone": "Tel", "Zip": "Pincode",
}
LABELS = [("Patient Name:", "Pt Name -"), ("Mobile:", "Contact No:"), ("Address:", "Residence:"),
          ("Attendant:", "Accompanied by:"), ("नाम:", "मरीज:"), ("UHID:", "Hosp No:"), ("Mob:", "Ph:"),
          ("Name:", "Pt:"), ("DOB:", "Birth Date:"), ("Reg No:", "Regn #:")]
GENERIC = {"devi", "kumar", "kumari", "singh", "kaur", "bano", "begum", "lal", "bai", "md", "mohd", "ji",
           "mohammad", "khatoon", "देवी", "कुमार", "सिंह", "कौर", "बानो"}


def _ymd(text: str) -> str:
    """dd/mm/yyyy -> yyyy/mm/dd (a date format the practice data never uses)."""
    return re.sub(r"(?<![\d/])(\d{2})/(\d{2})/(\d{4})(?![\d/])", r"\3/\2/\1", text)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kit", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--hard", action="store_true",
                    help="also: ';' delimiters in some CSVs and yyyy/mm/dd dates in d/m/y files")
    a = ap.parse_args()
    hard_delim: dict = {}
    rnd = random.Random(a.seed)
    kit, out = Path(a.kit), Path(a.out)
    truth = json.loads((kit / "dev/truth/truth.json").read_text(encoding="utf-8"))
    if out.exists():
        shutil.rmtree(out)

    # ---- tokens to replace: patient / relative name tokens, never doctors' tokens
    doctor_tokens = set()
    for f in truth["files"].values():
        for u in f["units"].values():
            for p in u.get("preserve") or []:
                if p.get("kind") == "doctor":
                    doctor_tokens |= {t.lower() for t in re.findall(r"[A-Za-zऀ-ॿ]+", p["text"])}
    name_tokens = set()
    for f in truth["files"].values():
        for u in f["units"].values():
            for e in u["entities"]:
                if e["type"] in ("PATIENT_NAME", "RELATIVE_NAME", "CANARY"):
                    for t in re.findall(r"[A-Za-zऀ-ॿ]+", e["surface"]):
                        if len(t) > 2 and t.lower() not in GENERIC and t.lower() not in doctor_tokens:
                            name_tokens.add(t)
    lat = sorted({t.lower() for t in name_tokens if not re.search(r"[ऀ-ॿ]", t)})
    dev = sorted({t for t in name_tokens if re.search(r"[ऀ-ॿ]", t)})
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from rakshak.link.translit import phonetic, token_match

    pairs = PAIRS[:]
    rnd.shuffle(pairs)
    n = len(pairs)

    def pair(i: int) -> tuple:
        if i < n:
            return pairs[i]
        a, b = pairs[i % n], pairs[(i // n * 7 + 3) % n]       # compound: full concatenation
        return a[0] + b[0].lower(), a[1] + b[1]

    # spelling variants of one name (Rina/Reena, Harish/Hareesh) get the same replacement
    reps: list[str] = []
    rep_of = {}
    for t in lat:
        r = next((x for x in reps if token_match(phonetic(t), phonetic(x))), None)
        if r is None:
            reps.append(t)
            r = t
        rep_of[t] = r
    lmap, lat_to_dev, by_rep = {}, {}, {}
    for i, r in enumerate(reps):
        by_rep[r] = pair(i)
    for t in lat:
        lmap[t], lat_to_dev[t] = by_rep[rep_of[t]]
    dmap, extra = {}, len(reps)
    for t in dev:
        twin = next((l for l in lat if token_match(phonetic(t), phonetic(l))), None)
        if twin:
            dmap[t] = lat_to_dev[twin]
        else:
            dmap[t] = pair(extra)[1]
            extra += 1
    lat_rx = re.compile(r"(?<![A-Za-z])(" + "|".join(sorted(map(re.escape, lmap), key=len, reverse=True)) + r")(?![A-Za-z])(?!\s+workers?)",
                        re.I)  # "ASHA worker" is a job title (a meaning trap), not the name Asha
    dev_rx = re.compile("(" + "|".join(sorted(map(re.escape, dmap), key=len, reverse=True)) + ")")

    def case_like(src: str, new: str) -> str:
        return new.upper() if src.isupper() else new.lower() if src.islower() else new.capitalize()

    def mutate(text: str, header_line: str | None = None) -> str:
        t = lat_rx.sub(lambda m: case_like(m.group(0), lmap[m.group(0).lower()]), text)
        t = dev_rx.sub(lambda m: dmap[m.group(0)], t)
        for old, new in ID_PREFIX:
            t = re.sub(rf"(?<![A-Za-z]){old}(?=[-/_]?\d)", new, t)
            t = re.sub(rf"(?<![A-Za-z]){old.lower()}(?=[-/_]?\d)", new.lower(), t)
        t = re.sub(r"\+91 (\d{4})(\d) (\d{5})", r"(+91) \1-\2\3", t)
        for old, new in LABELS:
            t = t.replace(old, new)
        return t

    files_out = {}
    for rel, f in truth["files"].items():
        src = kit / "dev/input" / rel
        new_rel = mutate(rel)
        dst = out / "input" / new_rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        raw = src.read_bytes()
        enc = f.get("encoding") or "utf-8"
        if f["format"] in ("csv", "tsv", "json", "fhir", "text") and f.get("expect") != "either":
            try:
                text = raw.decode(enc)
                if f["format"] in ("csv", "tsv"):
                    first, _, rest = text.partition("\n")
                    delim = "\t" if f["format"] == "tsv" else ","
                    first = delim.join(HEADERS.get(h.strip().lstrip("﻿"), h) if h.strip() else h
                                       for h in first.split(delim))
                    text = first + _ + rest
                text = mutate(text)
                if a.hard and f.get("date_hint") == "dmy":
                    text = _ymd(text)                      # 12/04/1977 -> 1977/04/12
                if a.hard and f["format"] == "csv" and int(hashlib.sha256(rel.encode()).hexdigest(), 16) % 2:
                    import csv as _csv
                    import io as _io
                    rows = list(_csv.reader(_io.StringIO(text, newline="")))
                    buf = _io.StringIO()
                    _csv.writer(buf, delimiter=";", lineterminator="\r\n" if "\r\n" in text else "\n").writerows(rows)
                    text = buf.getvalue()
                    hard_delim[rel] = ";"
                data = text.encode(enc if enc != "utf-8-sig" else "utf-8-sig")
            except (UnicodeError, LookupError):
                data = raw
        else:
            data = raw
        dst.write_bytes(data)
        nf = json.loads(json.dumps(f))
        nf["sha256"] = hashlib.sha256(data).hexdigest()
        if rel in hard_delim:
            nf["delimiter"] = hard_delim[rel]
        conv = _ymd if a.hard and f.get("date_hint") == "dmy" else (lambda t: t)
        for u in nf["units"].values():
            for e in u["entities"]:
                e["surface"] = conv(mutate(e["surface"]))
            for p in u.get("preserve") or []:
                p["text"] = conv(mutate(p["text"])) if p.get("kind") not in ("doctor",) else p["text"]
        files_out[new_rel] = nf
    nt = dict(truth)
    nt["files"] = files_out
    (out / "truth").mkdir(parents=True, exist_ok=True)
    (out / "truth/truth.json").write_text(json.dumps(nt, ensure_ascii=False), encoding="utf-8")
    print(f"chaos dataset: {len(files_out)} files, {len(lmap)} Latin + {len(dmap)} Devanagari name tokens replaced")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
