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

from collections import Counter

from .detect.engine import Engine
from .formats import csv_tsv, json_doc
from .io.decode import decode
from .io.sniff import Quarantine, json_depth_exceeds, sniff
from .policy import POLICY
from .process import Processor
from .report import write_report
from .secure import log
from .secure.secret import MissingSecret, keyed, secret

_B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


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


def harvest(job: Job, proc: Processor) -> None:
    if job.kind in ("csv", "tsv"):
        proc.csv_harvest(job.data)
    elif job.kind == "json":
        proc.json_harvest(job.data)
    else:
        proc.text_harvest(job.text)


def safe_name(rel: str, taken: set[str]) -> str:
    """Keyed, deterministic replacement for a file name that contains personal data."""
    folder, _, name = rel.rpartition("/")
    ext = name[name.rfind("."):] if "." in name else ""
    n = int.from_bytes(keyed("fname", rel)[:8], "big")
    length = 10
    while True:
        code = "".join(_B32[(n >> (5 * i)) & 31] for i in range(length))
        cand = (folder + "/" if folder else "") + f"file_{code}{ext.lower()}"
        if cand not in taken:
            return cand
        length += 1


def rewrite(job: Job, proc: Processor) -> None:
    out_file = f"sanitized/{job.out_rel}"
    if job.kind in ("csv", "tsv"):
        delim = "\t" if job.kind == "tsv" else ","
        rows = job.data
        for i in range(1, len(rows)):
            job.records.append({"file": out_file, "loc": f"row:{i - 1}", "patient": None})
        job.output_text = csv_tsv.write(proc.csv_rewrite(rows), delim, csv_tsv.line_terminator(job.text)) if rows else ""
    elif job.kind == "json":
        for ptr in json_doc.record_pointers(job.data):
            job.records.append({"file": out_file, "loc": ptr, "patient": None})
        job.output_text = json_doc.dump(proc.json_rewrite(job.data), json_doc.detect_indent(job.text),
                                        job.text.endswith("\n"))
    else:
        job.records.append({"file": out_file, "loc": "doc", "patient": None})
        job.output_text = proc.text_rewrite(job.text)
    job.status = "sanitized"


def run(inp: Path, out: Path) -> dict:
    t0 = time.monotonic()
    san = out / "sanitized"
    san.mkdir(parents=True, exist_ok=True)
    engine = Engine()
    proc = Processor(engine)

    jobs = [load(p, p.relative_to(inp).as_posix()) for p in discover(inp)]          # P0
    for job in jobs:                                                                 # P1 harvest
        if job.status == "pending":
            try:
                harvest(job, proc)
            except Exception as exc:  # noqa: BLE001
                job.status, job.reason = "quarantined", "harvest_error_" + log.error_kind(exc).lower()

    taken = {j.rel for j in jobs}                                                    # file names
    for job in jobs:
        job.out_rel = job.rel
        if job.status == "pending" and proc.name_has_pii(job.rel):
            job.out_rel = safe_name(job.rel, taken)
            taken.add(job.out_rel)

    for job in jobs:                                                                 # P4 rewrite
        if job.status != "pending":
            continue
        try:
            rewrite(job, proc)
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

    entities = Counter(engine.counts) + Counter(proc.role_counts)
    entities.pop("AGE", None)  # age bands are generalisations, not identifier detections
    return write_report(out, files, records, entities, generalized=proc.generalized_records, suppressed=0,
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
