"""Pipeline orchestration.

Stages (filled in phase by phase):
  P0 discover + hash + sniff + decode + parse   (failures -> quarantine, reason code only)
  P1 understand + harvest identity vault        (M2)
  P2 link + pseudonyms                          (M5)
  P3 privacy plan                               (M6)
  P4 rewrite every record                       (M2-M4)
  P5 egress gate, write, records.jsonl, report  (M4)
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from .detect.patterns import Detector
from .formats import csv_tsv, json_doc
from .io.decode import decode
from .io.sniff import Quarantine, json_depth_exceeds, sniff
from .policy import POLICY
from .report import write_report
from .secure import log
from .secure.secret import MissingSecret, secret


@dataclass
class Job:
    rel: str                     # input-relative POSIX path (never logged)
    sha: str
    kind: str = ""
    text: str = ""
    encoding: str = ""
    data: object = None          # parsed rows (csv/tsv) or JSON value
    status: str = "pending"      # sanitized | quarantined
    reason: str = ""
    out_rel: str = ""            # output path relative to sanitized/
    output_text: str = ""
    records: list = field(default_factory=list)


def discover(inp: Path) -> list[Path]:
    return sorted((p for p in inp.rglob("*") if p.is_file()), key=lambda p: p.relative_to(inp).as_posix())


def load(path: Path, rel: str) -> Job:
    raw = path.read_bytes()
    job = Job(rel=rel, sha=hashlib.sha256(raw).hexdigest())
    try:
        job.kind = sniff(path.suffix, raw)
        text, enc = decode(raw)
        if text is None:
            raise Quarantine("undecodable_text")
        job.text, job.encoding = text, enc
        if job.kind in ("csv", "tsv"):
            job.data = csv_tsv.parse(text, "\t" if job.kind == "tsv" else ",")
        elif job.kind == "json":
            if json_depth_exceeds(text, int(POLICY["max_json_depth"])):
                raise Quarantine("nesting_too_deep")
            try:
                job.data = json.loads(text)
            except ValueError:
                raise Quarantine("malformed_json") from None
    except Quarantine as q:
        job.status, job.reason = "quarantined", q.reason
    except (csv.Error, UnicodeError, RecursionError, MemoryError) as exc:
        job.status, job.reason = "quarantined", "parse_error_" + log.error_kind(exc).lower()
    return job


def rewrite(job: Job, det: Detector) -> None:
    job.out_rel = job.rel  # M4: rename when the file name itself holds PII
    out_file = f"sanitized/{job.out_rel}"
    if job.kind in ("csv", "tsv"):
        delim = "\t" if job.kind == "tsv" else ","
        rows = job.data
        out_rows = []
        for i, row in enumerate(rows):
            out_rows.append([det.clean_text(c) for c in row])
            if i > 0:
                job.records.append({"file": out_file, "loc": f"row:{i - 1}", "patient": None})
        job.output_text = csv_tsv.write(out_rows, delim, csv_tsv.line_terminator(job.text)) if rows else ""
    elif job.kind == "json":
        for ptr in json_doc.record_pointers(job.data):
            job.records.append({"file": out_file, "loc": ptr, "patient": None})
        job.output_text = json_doc.dump(det.clean_value(job.data), json_doc.detect_indent(job.text),
                                        job.text.endswith("\n"))
    else:
        job.records.append({"file": out_file, "loc": "doc", "patient": None})
        job.output_text = det.clean_text(job.text)
    job.status = "sanitized"


def run(inp: Path, out: Path) -> dict:
    t0 = time.monotonic()
    san = out / "sanitized"
    san.mkdir(parents=True, exist_ok=True)
    det = Detector()

    jobs = [load(p, p.relative_to(inp).as_posix()) for p in discover(inp)]          # P0
    for job in jobs:                                                                 # P4
        if job.status != "pending":
            continue
        try:
            rewrite(job, det)
        except Exception as exc:  # noqa: BLE001 - fail safe: never export a half-cleaned file
            job.status, job.reason, job.records = "quarantined", "process_error_" + log.error_kind(exc).lower(), []

    files, records = [], []
    for job in jobs:                                                                 # P5
        if job.status == "sanitized":
            dest = san / job.out_rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(job.output_text, encoding="utf-8", newline="")
            files.append({"input_sha256": job.sha, "output": f"sanitized/{job.out_rel}", "status": "sanitized"})
            records.extend(job.records)
        else:
            files.append({"input_sha256": job.sha, "output": None, "status": "quarantined",
                          "reason": job.reason})

    with open(out / "records.jsonl", "w", encoding="utf-8", newline="\n") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")

    return write_report(out, files, records, det.entities, generalized=0, suppressed=0,
                        seconds=time.monotonic() - t0)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Clarity privacy firewall")
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    a = ap.parse_args(argv)
    sys.setrecursionlimit(10000)
    try:
        secret()  # fail closed before touching anything
    except MissingSecret:
        log.emit("no_secret", stream=sys.stderr)
        return 2
    try:
        report = run(Path(a.input), Path(a.output))
    except Exception as exc:  # noqa: BLE001 - message is the class name only, never content
        log.emit("fatal", stream=sys.stderr, kind=log.error_kind(exc))
        return 1
    c = report["counts"]
    log.emit("summary", files=c["files_total"], sanitized=c["files_sanitized"],
             quarantined=c["files_quarantined"], records=c["records_processed"], linked=c["records_linked"])
    return 0
