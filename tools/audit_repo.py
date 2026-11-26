#!/usr/bin/env python3
"""Static self-audit of the submission repo (the evaluator's `audit` flags the same things).

Fails (exit 1) if any committed file contains a practice-data identifier or name:
  * digit identifiers (phone, Aadhaar, ABHA, UHID/IPD digit cores >= 5 digits) from truth.json
  * full patient / relative / canary names, emails, PAN, insurance IDs, house / locality / landmark /
    village strings, full hospital IDs
  * ANY practice name token inside the shipped gazetteer (rakshak/data) or the model's features
Also fails on: LLM / transformer / cloud packages, runtime network imports in rakshak/, committed
practice data (dev/) or external training data (training/data/).

    python tools/audit_repo.py --kit ../Secret-Wards-ToolKit
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import unicodedata
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BANNED_PKGS = re.compile(r"^\s*(transformers|torch|tensorflow|keras|openai|anthropic|google-generativeai|"
                         r"langchain|llama|vllm|sentence-transformers|spacy-transformers|requests|httpx|boto3)\b",
                         re.I | re.M)
NET_IMPORT = re.compile(r"^\s*(?:import|from)\s+(socket|urllib\.request|http\.client|requests|httpx|ftplib|"
                        r"smtplib|aiohttp)\b", re.M)


def tracked_files() -> list[Path]:
    out = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard"], cwd=ROOT,
                         capture_output=True, text=True, check=True).stdout.splitlines()
    return [ROOT / p for p in out if (ROOT / p).is_file()]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kit", required=True)
    a = ap.parse_args()
    truth = json.loads((Path(a.kit) / "dev/truth/truth.json").read_text(encoding="utf-8"))
    digits, phrases, tokens = set(), set(), set()
    for f in truth["files"].values():
        for u in f["units"].values():
            for e in u["entities"]:
                surf = e["surface"].strip()
                if e.get("match") in ("digits", "digits_exact") and len(e.get("key") or "") >= 5:
                    if e["type"] != "PIN":
                        digits.add(e["key"])
                if e["type"] in ("PATIENT_NAME", "RELATIVE_NAME", "CANARY"):
                    if len(surf.split()) >= 2:
                        phrases.add(surf.lower())
                    tokens |= {t.lower() for t in e.get("tokens") or [] if len(t) >= 3}
                    if e["type"] == "CANARY":
                        phrases.add(surf.lower())
                elif e["type"] in ("EMAIL", "PAN", "INSURANCE_ID", "ABHA_ADDRESS", "MRN"):
                    phrases.add(surf.lower())
                elif e["type"] in ("HOUSE", "LOCALITY", "LANDMARK", "VILLAGE") and len(surf) >= 6 and \
                        not re.fullmatch(r"(?:ward|gali|lane|sector)\s*\d+", surf.lower()):
                    phrases.add(surf.lower())
    sys.path.insert(0, str(ROOT))
    from rakshak.detect import lexicon as L
    generic = {h.lower().rstrip(".") for h in L.HONORIFICS_AFTER + L.HONORIFICS_BEFORE} | set(L.GENERIC_NAME_TOKENS)
    tokens = {unicodedata.normalize("NFC", t) for t in tokens} - generic   # kinship words are not names
    # runtime code (rakshak/, config/) must not contain practice hospital / lab names or practice name words,
    # not even as stop-words: behaviour must come from general rules, never from memorised practice values
    kit = Path(a.kit)
    inst = set()
    for f in truth["files"].values():
        for u in f["units"].values():
            for pv in u.get("preserve") or []:
                if pv.get("kind") == "hospital":
                    inst |= {w.lower() for w in re.findall(r"[A-Za-z]{4,}", pv["text"])}
    try:
        for line in (kit / "dev/attacker/known_facts.jsonl").read_text(encoding="utf-8").splitlines():
            inst |= {w.lower() for w in re.findall(r"[A-Za-z]{4,}", json.loads(line).get("hospital", ""))}
    except (OSError, ValueError):
        pass
    inst -= {"hospital", "multispeciality", "charitable", "seva", "sadan", "district", "community", "health",
             "centre", "center", "clinic", "pathology", "diagnostics", "nursing", "home", "medical", "city"}
    allowed_runtime = {"mohammad", "mohammed", "shaikh", "asha", "मोहम्मद"}   # generic variant table / job title
    runtime_banned = (inst | {t for t in tokens if len(t) >= 4}) - allowed_runtime
    problems = []
    files = tracked_files()
    for p in files:
        rel = p.relative_to(ROOT).as_posix()
        if (rel.startswith("rakshak/") and rel.endswith(".py")) or rel.startswith("config/"):
            words = set(re.findall(r"[a-zऀ-ॿ]{4,}", unicodedata.normalize("NFC", p.read_text(
                encoding="utf-8").lower())))
            hit = sorted(words & runtime_banned)
            if hit:
                problems.append(f"{rel}: practice name / institution words in runtime code ({len(hit)})")
    for p in files:
        rel = p.relative_to(ROOT).as_posix()
        if rel.startswith(("dev/", "training/data/")) or "/dev/input/" in rel:
            problems.append(f"{rel}: practice/training data must not be committed")
            continue
        if p.suffix.lower() in (".pdf", ".png", ".jpg", ".pyc"):
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        low = text.lower()
        for d in digits:
            if re.search(r"(?<!\d)" + d + r"(?!\d)", text):
                problems.append(f"{rel}: practice digit identifier ...{d[-4:]}")
        for ph in phrases:
            if ph in low and len(ph) >= 6:
                problems.append(f"{rel}: practice value '{ph[:3]}…' ({len(ph)} chars)")
        if (rel.startswith("rakshak/data/") or rel.startswith("models/")) and p.suffix in (".txt", ".json"):
            words = set(re.findall(r"[a-zऀ-ॿ]+", unicodedata.normalize("NFC", low)))
            hit = sorted(words & tokens)
            if hit:
                problems.append(f"{rel}: {len(hit)} practice name tokens in shipped gazetteer/model")
        if rel == "requirements.txt" and BANNED_PKGS.search(text):
            problems.append(f"{rel}: banned/network package")
        if rel.startswith("rakshak/") and rel.endswith(".py") and NET_IMPORT.search(text):
            problems.append(f"{rel}: network import in runtime code")
    print(f"audited {len(files)} files against {len(digits)} digit ids, {len(phrases)} values, "
          f"{len(tokens)} name tokens")
    for x in sorted(set(problems)):
        print("  FAIL", x)
    print("AUDIT CLEAN" if not problems else f"AUDIT FAILED ({len(set(problems))})")
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
