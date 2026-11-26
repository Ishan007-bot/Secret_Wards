"""Reads config/policy.yaml (flat `key: value` lines; no PyYAML dependency)."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

DEFAULTS = {
    "date_shift_min_days": 7,
    "date_shift_max_days": 180,
    "dob_jitter_min_days": 30,
    "dob_jitter_max_days": 365,
    "dob_mode": "remove",
    "age_band_years": 10,
    "age_top_code": 85,
    "location_level": "district",
    "pin_prefix_digits": 3,
    "k_anonymity": 3,
    "age_band_wide_years": 20,
    "rare_diagnosis_k": 3,
    "max_json_depth": 200,
}


def _coerce(v: str):
    v = v.strip().strip('"').strip("'")
    if v.lstrip("-").isdigit():
        return int(v)
    try:
        return float(v)
    except ValueError:
        return v


def load_policy(path: Path | None = None) -> dict:
    policy = dict(DEFAULTS)
    path = path or ROOT / "config" / "policy.yaml"
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if ":" in line:
                k, v = line.split(":", 1)
                policy[k.strip()] = _coerce(v)
    return policy


POLICY = load_policy()
