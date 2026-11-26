"""JSON helpers: record segmentation (RFC 6901 pointers), layout-preserving dump."""
from __future__ import annotations

import json


def escape_token(key: str) -> str:
    return key.replace("~", "~0").replace("/", "~1")


def is_fhir_bundle(data) -> bool:
    return isinstance(data, dict) and data.get("resourceType") == "Bundle"


def _record_array(v) -> bool:
    return isinstance(v, list) and bool(v) and all(isinstance(x, dict) for x in v)


def record_pointers(data) -> list[str]:
    """Locators the evaluator uses: /key/N for arrays of objects under a top-level key, /N for a
    top-level array of objects, otherwise the whole file is one record ("doc")."""
    if is_fhir_bundle(data):
        return ["doc"]
    if _record_array(data):
        return [f"/{i}" for i in range(len(data))]
    if isinstance(data, dict):
        ptrs = []
        for k, v in data.items():
            if _record_array(v):
                ptrs.extend(f"/{escape_token(k)}/{i}" for i in range(len(v)))
        if ptrs:
            return ptrs
    return ["doc"]


def record_locs(data) -> list[str]:
    """All locators we report: the array records plus a whole-file 'doc' record. The evaluator matches
    each of its records to the longest locator we give, so 'doc' safely covers files it treats as one
    document (e.g. a lab report whose 'panels' array is not a list of patients)."""
    ptrs = record_pointers(data)
    return ptrs if ptrs == ["doc"] else ptrs + ["doc"]


def detect_indent(text: str) -> int | None:
    for line in text.splitlines()[1:6]:
        stripped = line.lstrip(" ")
        if stripped and len(stripped) != len(line):
            return len(line) - len(stripped)
    return None


def dump(data, indent: int | None, trailing_newline: bool) -> str:
    out = json.dumps(data, ensure_ascii=False, indent=indent)
    return out + ("\n" if trailing_newline else "")
