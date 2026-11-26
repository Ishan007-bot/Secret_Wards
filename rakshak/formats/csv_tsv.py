"""CSV/TSV: parse, and write back with the same delimiter, header, row count and row shapes."""
from __future__ import annotations

import csv
import io


def parse(text: str, delimiter: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(text, newline=""), delimiter=delimiter))


def line_terminator(text: str) -> str:
    return "\r\n" if "\r\n" in text else "\n"


def write(rows: list[list[str]], delimiter: str, terminator: str) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=delimiter, lineterminator=terminator, quoting=csv.QUOTE_MINIMAL)
    for row in rows:
        w.writerow(row)
    return buf.getvalue()
