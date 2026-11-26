#!/usr/bin/env python3
"""Download the external SYNTHETIC datasets used for training and testing (never at runtime).

Organisers confirmed that external synthetic datasets may be used for testing and training.
Everything lands in training/data/ (gitignored). Every file is pinned (revision / SHA-256) and the
manifest training/data/MANIFEST.json records source, URL, licence and hash.

    python training/fetch_external.py [--skip-synthea]

Sources (all synthetic; no real patient text):
  * ai4privacy/open-pii-masking-500k-ai4privacy (Hugging Face, pinned revision). Template + Llama
    generated PII sentences with token labels, incl. Hindi. Licence: Llama 3.1/3.3 Community
    Licence terms (see the dataset card). Used for TESTING; training use is an ablation only.
  * Mendeley Data 10.17632/nn5r5htbpx "Clinical Notes Based on Indian Format" (CC BY 4.0).
  * Mendeley Data 10.17632/bzgjmph5n2.1 "Synthetic Indian Clinical Notes for NLP Research" (CC BY 4.0).
  * Synthea (MITRE, Apache-2.0), generated locally with Java -> FHIR R4 bundles + CSV.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import urllib.request
from pathlib import Path

DATA = Path(__file__).resolve().parent / "data"

AI4P_REPO = "ai4privacy/open-pii-masking-500k-ai4privacy"
AI4P_REV = "506996d625ed970a0063432daf6007cf4a3a48e3"
AI4P_FILES = ["README.md", "llama-3.1-community-license.txt", "llama-3.3-community-license.txt",
              "data/validation/test.jsonl", "data/train/train.jsonl"]

MENDELEY = [
    ("mendeley_nn5r5htbpx", "synthetic_notes_medium_v2.json",
     "https://data.mendeley.com/public-files/datasets/nn5r5htbpx/files/7ab14897-9666-4331-ae66-2e69ce02845a/file_downloaded",
     "3db824146984b311c2d4d44d285ca0280a7c813fae832e721e77e2011ce71b56", "CC BY 4.0",
     "https://doi.org/10.17632/nn5r5htbpx.1"),
    ("mendeley_bzgjmph5n2", "synthetic_notes_medium.json",
     "https://data.mendeley.com/public-files/datasets/bzgjmph5n2/files/18522252-bfea-45ab-8e8b-b023233a4a9a/file_downloaded",
     "4f09411b0114a8f43ae580511707c96515eac15bdb280e4db754890e133ef3d4", "CC BY 4.0",
     "https://doi.org/10.17632/bzgjmph5n2.1"),
]

SYNTHEA_JAR = "https://github.com/synthetichealth/synthea/releases/download/master-branch-latest/synthea-with-dependencies.jar"


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.is_file() and dest.stat().st_size > 0:
        return
    req = urllib.request.Request(url, headers={"User-Agent": "dataset-fetch/1.0"})
    with urllib.request.urlopen(req, timeout=600) as r, open(dest, "wb") as f:
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            f.write(chunk)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-synthea", action="store_true")
    ap.add_argument("--synthea-patients", type=int, default=60)
    a = ap.parse_args()
    manifest = []

    from huggingface_hub import hf_hub_download
    for f in AI4P_FILES:
        p = Path(hf_hub_download(AI4P_REPO, f, repo_type="dataset", revision=AI4P_REV,
                                 local_dir=str(DATA / "ai4privacy")))
        manifest.append({"source": AI4P_REPO, "revision": AI4P_REV, "file": f, "sha256": sha256(p),
                         "license": "Llama 3.1/3.3 Community License (dataset card)",
                         "url": f"https://huggingface.co/datasets/{AI4P_REPO}"})
        print("ok", f, flush=True)

    for folder, name, url, digest, lic, doi in MENDELEY:
        dest = DATA / folder / name
        download(url, dest)
        got = sha256(dest)
        if got != digest:
            print(f"HASH MISMATCH {name}", file=sys.stderr)
            return 1
        manifest.append({"source": doi, "file": name, "sha256": got, "license": lic, "url": url})
        print("ok", name, flush=True)

    if not a.skip_synthea:
        jar = DATA / "synthea" / "synthea-with-dependencies.jar"
        download(SYNTHEA_JAR, jar)
        outdir = DATA / "synthea" / "output"
        if not (outdir / "fhir").is_dir():
            subprocess.run(["java", "-jar", str(jar), "-p", str(a.synthea_patients), "-s", "7", "-cs", "7",
                            "--exporter.baseDirectory", str(outdir), "--exporter.fhir.export", "true",
                            "--exporter.csv.export", "true", "--exporter.hospital.fhir.export", "false",
                            "--exporter.practitioner.fhir.export", "false"],
                           check=True, cwd=str(jar.parent))
        manifest.append({"source": "Synthea (MITRE)", "file": jar.name, "sha256": sha256(jar),
                         "license": "Apache-2.0 (code); generated data is synthetic", "url": SYNTHEA_JAR,
                         "args": f"-p {a.synthea_patients} -s 7 -cs 7"})
        print("ok synthea", flush=True)

    (DATA / "MANIFEST.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print("manifest written:", len(manifest), "entries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
