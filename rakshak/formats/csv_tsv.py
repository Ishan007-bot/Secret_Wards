"""CSV/TSV: parse, and write back with the same delimiter, header, row count and row shapes."""
from __future__ import annotations

import csv
import io


def parse(text: str, delimiter: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(text, newline=""), delimiter=delimiter))


def sniff_delimiter(text: str, default: str) -> str:
    """Pick the delimiter the file really uses (',' ';' '|' or TAB): the one that splits the header and
    the next rows into the same number (> 1) of columns most consistently. Falls back to the default."""
    sample = "\n".join(text.splitlines()[:30])
    best, best_key = default, None
    for d in (default, ",", ";", "|", "\t"):
        try:
            rows = [r for r in csv.reader(io.StringIO(sample, newline=""), delimiter=d) if r]
        except csv.Error:
            continue
        if not rows or len(rows[0]) < 2:
            continue
        width = len(rows[0])
        agree = sum(1 for r in rows if len(r) == width) / len(rows)
        key = (agree >= 0.8, width if agree >= 0.8 else 0, d == default)
        if best_key is None or key > best_key:
            best, best_key = d, key
    return best


def line_terminator(text: str) -> str:
    return "\r\n" if "\r\n" in text else "\n"


def write(rows: list[list[str]], delimiter: str, terminator: str) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=delimiter, lineterminator=terminator, quoting=csv.QUOTE_MINIMAL)
    for row in rows:
        w.writerow(row)
    return buf.getvalue()
