"""Shared helpers for the dev-only measurement tools (selfscore.py, attacker.py).

Never imported by the pipeline. Mirrors the published evaluator rules in docs/SCORING.md:
both sides are normalised (NFKC, homoglyphs, zero-width, Indic digits, diacritics, casefold) and
hidden payloads (base64, hex, \\uXXXX, HTML entities, %-encoding) are decoded and appended.
"""
from __future__ import annotations

import base64
import binascii
import csv
import html
import io
import json
import re
import sys
import unicodedata
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

csv.field_size_limit(1 << 30)

_HOMO = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "А": "a", "В": "b", "Е": "e", "К": "k", "М": "m", "Н": "h", "О": "o", "Р": "p", "С": "c", "Т": "t",
    "Х": "x", "І": "i", "Ј": "j", "Ѕ": "s", "α": "a", "ο": "o", "ρ": "p", "ν": "v", "Α": "a", "Β": "b",
    "Ε": "e", "Ζ": "z", "Η": "h", "Ι": "i", "Κ": "k", "Μ": "m", "Ν": "n", "Ο": "o", "Ρ": "p", "Τ": "t",
    "Υ": "y", "Χ": "x",
})
_ZW = re.compile("[​‌‍‎‏⁠⁡⁢⁣﻿­]")
_IND = str.maketrans("०१२३४५६७८९", "0123456789")
_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
_UESC = re.compile(r"\\u([0-9a-fA-F]{4})")
_PCT = re.compile(r"(?:%[0-9A-Fa-f]{2}){2,}")


def norm(s: str) -> str:
    t = unicodedata.normalize("NFKC", s)
    t = _ZW.sub("", t).translate(_HOMO).translate(_IND)
    t = "".join(c for c in unicodedata.normalize("NFKD", t) if not unicodedata.combining(c)) \
        if not t.isascii() else t
    t = unicodedata.normalize("NFC", t)
    return " ".join(t.casefold().split())


def with_payloads(text: str) -> str:
    extra = []
    for m in _B64.finditer(text):
        tok = m.group(0)
        try:
            extra.append(base64.b64decode(tok + "=" * (-len(tok) % 4)).decode("utf-8", errors="ignore"))
        except (binascii.Error, ValueError):
            pass
    for m in _HEX.finditer(text):
        try:
            extra.append(bytes.fromhex(m.group(0)).decode("utf-8", errors="ignore"))
        except ValueError:
            pass
    if "\\u" in text:
        extra.append(_UESC.sub(lambda m: chr(int(m.group(1), 16)), text))
    if "&" in text:
        extra.append(html.unescape(text))
    if "%" in text:
        extra.append(_PCT.sub(lambda m: unquote(m.group(0)), text))
    return text + ("\n" + "\n".join(extra) if extra else "")


def scan(text: str) -> str:
    return norm(with_payloads(text))


def read(p: Path) -> str:
    try:
        return p.read_bytes().decode("utf-8", "replace")
    except OSError:
        return ""


def load_truth(kit: Path, truth: str | None = None) -> dict:
    return json.loads(Path(truth or kit / "dev/truth/truth.json").read_text(encoding="utf-8"))


def load_report(out: Path) -> dict:
    try:
        return json.loads((out / "report.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"files": []}


def output_map(out: Path) -> dict:
    """input sha256 -> output rel path under out/ (e.g. 'sanitized/x.csv') or None."""
    return {e.get("input_sha256"): e.get("output") for e in load_report(out).get("files") or []}


def load_records(out: Path) -> dict:
    """(file rel to out/, loc) -> pseudonym or None."""
    recs = {}
    try:
        for line in (out / "records.jsonl").read_text(encoding="utf-8").splitlines():
            if line.strip():
                r = json.loads(line)
                recs[(str(r["file"]), str(r["loc"]))] = r.get("patient")
    except (OSError, ValueError, KeyError):
        pass
    return recs


def record_for(file: str, loc: str, recs: dict):
    """Longest reported locator covering this record (exact, JSON-pointer ancestor, or doc)."""
    if (file, loc) in recs:
        return recs[(file, loc)], True
    if loc.startswith("/"):
        parts = loc.split("/")
        for i in range(len(parts) - 1, 1, -1):
            anc = "/".join(parts[:i])
            if (file, anc) in recs:
                return recs[(file, anc)], True
    if (file, "doc") in recs:
        return recs[(file, "doc")], True
    return None, False


def _unescape_ptr(p: str) -> str:
    return p.replace("~1", "/").replace("~0", "~")


def unit_text(text: str, loc: str, fmt: str | None, delimiter: str | None = None):
    """The text of one record inside a file (None when it cannot be located)."""
    if loc.startswith("@") or loc == "doc":
        return text
    if loc.startswith("row:") and fmt in ("csv", "tsv"):
        delim = delimiter or ("\t" if fmt == "tsv" else ",")
        try:
            rows = list(csv.reader(io.StringIO(text), delimiter=delim))
        except csv.Error:
            return None
        i = int(loc[4:]) + 1
        if 0 < i < len(rows):
            hdr = rows[0]
            return "\n".join(f"{hdr[k] if k < len(hdr) else k}: {v}" for k, v in enumerate(rows[i]))
        return None
    if loc.startswith("/"):
        try:
            node = json.loads(text)
            for part in loc.strip("/").split("/"):
                node = node[int(part)] if isinstance(node, list) else node[_unescape_ptr(part)]
            return json.dumps(node, ensure_ascii=False)
        except (ValueError, KeyError, IndexError, TypeError):
            return None
    return text


def digit_rx(key: str) -> re.Pattern:
    """A digit key matched across any separators."""
    return re.compile(r"(?<!\d)" + r"[\s\-./()+]{0,3}".join(re.escape(c) for c in key) + r"(?!\d)")


def count_key(e: dict, key, hay: str) -> int:
    """Occurrences of one key of an entity inside normalised text."""
    m = e.get("match")
    if m in ("digits",):
        return len(digit_rx(key).findall(hay))
    if m == "digits_exact":
        return len(re.findall(r"(?<!\d)" + re.escape(key) + r"(?!\d)", hay))
    if m == "name":
        return len(re.findall(r"(?<![\w])" + re.escape(key) + r"(?![\w])", hay))
    return hay.count(key) if key else 0
