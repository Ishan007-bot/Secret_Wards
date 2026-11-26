#!/usr/bin/env python3
"""Dev-only policy sweep (Master Plan section 8): measure the privacy/utility trade-off of each setting.

For every candidate policy: run the pipeline on the practice data, score it with selfscore.py
(utility, detection, ...) and attacker.py (A1-A7), and print one row per setting.

    python tools/policy_sweep.py --kit ../Secret-Wards-ToolKit --work <scratch dir>
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

GRID = [
    {},                                                    # current config/policy.yaml
    {"age_band_years": 5},
    {"age_band_years": 20},
    {"k_anonymity": 2},
    {"k_anonymity": 5},
    {"k_anonymity": 8},
    {"age_band_wide_years": 30},
    {"dob_mode": "jitter"},
    {"location_level": "none"},
    {"rare_diagnosis_k": 3},
    {"rare_diagnosis_k": 1},
    {"age_top_code": 80},
    {"pin_prefix_digits": 2},
    {"k_anonymity": 5, "age_band_wide_years": 30},
]


def run(kit: Path, work: Path, override: dict) -> dict:
    base = (ROOT / "config/policy.yaml").read_text(encoding="utf-8")
    tag = "_".join(f"{k}={v}" for k, v in override.items()) or "baseline"
    pol = work / f"policy_{tag}.yaml"
    pol.write_text(base + "\n" + "\n".join(f"{k}: {v}" for k, v in override.items()) + "\n", encoding="utf-8")
    out = work / f"out_{tag}"
    env = dict(os.environ, RAKSHA_POLICY=str(pol), RAKSHA_SECRET="sweep-secret", PYTHONIOENCODING="utf-8")
    subprocess.run([sys.executable, str(ROOT / "main.py"), "--input", str(kit / "dev/input"), "--output", str(out)],
                   env=env, check=True, capture_output=True)
    res = subprocess.run([sys.executable, "-X", "utf8", str(ROOT / "tools/selfscore.py"), "--kit", str(kit),
                          "--output", str(out), "--json"], env=env, check=True, capture_output=True)
    d = json.loads(res.stdout.decode("utf-8"))
    return {"setting": tag, "total": d["total"], "privacy": d["points"]["privacy"],
            "utility": d["points"]["utility"], "detection": d["points"]["detection"],
            "A3": d["privacy"].get("record_linkage"), "A4": d["privacy"].get("profile_reidentification"),
            "A5": d["privacy"].get("targeted_attack"), "gen": d["utility"]["generalization"],
            "probes": d["utility"]["probes"]}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kit", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--grid", help="JSON list of overrides (default: the built-in grid)")
    a = ap.parse_args()
    grid = json.loads(a.grid) if a.grid else GRID
    work = Path(a.work)
    work.mkdir(parents=True, exist_ok=True)
    rows = []
    for o in grid:
        r = run(Path(a.kit), work, o)
        rows.append(r)
        print(json.dumps(r), flush=True)
    print("\nsetting                                   total  priv   util   det    A3     A4     A5     gen")
    for r in sorted(rows, key=lambda r: -r["total"]):
        print(f"{r['setting'][:40]:<40} {r['total']:6.2f} {r['privacy']:6.2f} {r['utility']:6.2f} {r['detection']:6.2f} "
              f"{r['A3']:.3f}  {r['A4']:.3f}  {r['A5']:.3f}  {r['gen']:.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
