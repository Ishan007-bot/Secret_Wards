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
import re
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .detect.engine import Engine
from .formats import csv_tsv, fhir, json_doc
from .link.context import RecordCtx
from .link.linker import Linker
from .link.pseudonym import PseudonymIssuer
from .link.translit import names_compatible
from .privacy.ages import band_text
from .privacy.dates import Shifter, order_evidence
from .secure.egress import find_leaks
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
    month_first: bool = False    # date order of this file (decided from evidence)
    family: str = ""             # hospital ID family (for date-order voting)
    delim: str = ","             # CSV/TSV delimiter the file really uses (sniffed)


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
            default = "\t" if job.kind == "tsv" else ("|" if path.suffix.lower() == ".psv" else ",")
            job.delim = csv_tsv.sniff_delimiter(text, default)     # ';' or '|' inside a .csv, ...
            job.data = csv_tsv.parse(text, job.delim)
        elif job.kind == "json":
            if json_depth_exceeds(text, int(POLICY["max_json_depth"])):
                raise Quarantine("nesting_too_deep")
            try:
                job.data = json.loads(text)
            except ValueError:
                if not _json_lines(text):
                    raise Quarantine("malformed_json") from None
                job.kind = "text"            # JSON Lines saved as .json: sanitised line by line as text
    except Quarantine as q:
        job.status, job.reason = "quarantined", q.reason
    except (csv.Error, UnicodeError, RecursionError, MemoryError) as exc:
        job.status, job.reason = "quarantined", "parse_error_" + log.error_kind(exc).lower()
    return job


def _json_lines(text: str) -> bool:
    lines = [l for l in text.splitlines() if l.strip()]
    if len(lines) < 2:
        return False
    try:
        return all(isinstance(json.loads(l), (dict, list)) for l in lines)
    except ValueError:
        return False


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


def evidence(job: Job, proc: Processor) -> list:
    if job.kind in ("csv", "tsv"):
        return proc.csv_evidence(job.data, job.rel, job.month_first)
    if job.kind == "json":
        return proc.json_evidence(job.data, job.rel, job.month_first)
    return proc.text_evidence(job.text, job.rel, job.month_first)


def decide_date_order(jobs: list[Job], evs: dict) -> None:
    """Day-first vs month-first per file: own evidence, else the vote of files from the same hospital
    ID family, else the dataset-wide vote, else day-first (the Indian default)."""
    family_vote: dict[str, list[int]] = {}
    total = [0, 0]
    own = {}
    for job in jobs:
        if job.status != "pending":
            continue
        dmy, mdy = order_evidence(job.text)
        own[job.rel] = (dmy, mdy)
        fam = _id_family(evs.get(job.rel, []))
        job.family = fam
        v = family_vote.setdefault(fam, [0, 0])
        v[0] += dmy
        v[1] += mdy
        total[0] += dmy
        total[1] += mdy
    for job in jobs:
        if job.status != "pending":
            continue
        dmy, mdy = own[job.rel]
        if dmy != mdy:
            job.month_first = mdy > dmy
            continue
        fv = family_vote.get(job.family, [0, 0])
        if fv[0] != fv[1]:
            job.month_first = fv[1] > fv[0]
        else:
            job.month_first = total[1] > total[0] * 2  # only if the whole dataset is clearly month-first


def _id_family(ev_list: list) -> str:
    fams = Counter()
    for ev in ev_list:
        for i in ev.ids:
            m = re.match(r"[A-Z]+", i)
            if m:
                fams[m.group(0)] += 1
    return fams.most_common(1)[0][0] if fams else ""


def build_contexts(jobs: list[Job], evs: dict, proc: Processor) -> dict:
    """Link records, issue pseudonyms, and create one RecordCtx per record id."""
    all_ev = [e for job in jobs for e in evs.get(job.rel, [])]
    linker = Linker(all_ev)
    linker.link_strong()
    linker.link_name_clues()
    cluster_of = linker.clusters()
    by_cluster: dict[str, list] = {}
    for e in all_ev:
        k = cluster_of.get(e.rid, "")
        if k:
            by_cluster.setdefault(k, []).append(e)
    issuer = PseudonymIssuer()
    psn = {k: issuer.get(k) for k in sorted(by_cluster)}
    month_first = {job.rel: job.month_first for job in jobs}
    ctxs = {}
    for k, members in by_cluster.items():
        # the cluster's own names: each record's primary name and its spelling variants only. Other people
        # mentioned in the same document (a register, a log, JSON Lines) must never receive this pseudonym.
        primaries = [p for p in (e.primary_name() for e in members) if p]
        names = [n for e in members for n in e.names + e.weak_names
                 if not primaries or any(names_compatible(n, p) for p in primaries)]
        ids = set()
        for e in members:
            ids |= e.ids
            for i in e.ids:
                d = re.sub(r"\D", "", i)
                if len(d) >= 5:
                    ids.add(d)
        for e in members:
            rel = e.rid.rsplit("|", 1)[0]
            ctxs[e.rid] = RecordCtx(psn=psn[k], names=names, ids=ids,
                                    shifter=Shifter(k, month_first.get(rel, False)))
    proc.linked_clusters = len(by_cluster)
    # rare diagnoses: codes held by fewer than k distinct patients in this release
    holders: dict[str, set] = {}
    for e in all_ev:
        k = cluster_of.get(e.rid, "")
        if k:
            for code in e.dx:
                holders.setdefault(code, set()).add(k)
    _k_anonymity(by_cluster, ctxs)
    k_dx = int(POLICY["rare_diagnosis_k"])
    proc.rare.set_rare({c for c, h in holders.items() if len(h) < k_dx})
    return ctxs


def _k_anonymity(by_cluster: dict, ctxs: dict) -> None:
    """Patients whose (gender, age band, district) cell holds fewer than k patients get a wider
    (still truthful) age band in every one of their records."""
    k = int(POLICY["k_anonymity"])
    wide = int(POLICY.get("age_band_wide_years", 20))
    cells: dict[tuple, list] = {}
    for key, members in by_cluster.items():
        genders = sorted({g for e in members for g in e.genders})
        ages = sorted({a for e in members for a in e.ages})
        dists = sorted({d for e in members for d in e.districts})
        if not ages:
            continue
        cell = (genders[0] if len(genders) == 1 else "?", band_text(str(ages[0])) or "?",
                dists[0] if len(dists) == 1 else "?")
        cells.setdefault(cell, []).append(key)
    for cell, keys in cells.items():
        if len(keys) < k:
            for key in keys:
                for e in by_cluster[key]:
                    if e.rid in ctxs:
                        ctxs[e.rid].age_width = wide


def egress_gate(job: Job, proc: Processor, gate: Counter) -> None:
    """Re-scan the finished output; re-clean once if anything identifying survived, else quarantine."""
    if not find_leaks(job.output_text, proc.vault):
        return
    gate["rechecked"] += 1
    eng = proc.engine
    if job.kind == "json":
        cleaned = json_doc.dump(_deep_clean(json.loads(job.output_text), eng), json_doc.detect_indent(job.text),
                                job.text.endswith("\n"))
    else:
        cleaned = eng.clean(job.output_text)
    if find_leaks(cleaned, proc.vault):
        gate["blocked"] += 1
        raise Quarantine("egress_blocked")
    job.output_text = cleaned


def _deep_clean(node, eng):
    if isinstance(node, dict):
        return {eng.clean(k): _deep_clean(v, eng) for k, v in node.items()}
    if isinstance(node, list):
        return [_deep_clean(x, eng) for x in node]
    return eng.clean(node) if isinstance(node, str) else node


def _record(out_file: str, loc: str, rec: RecordCtx) -> dict:
    return {"file": out_file, "loc": loc, "patient": rec.psn if rec.used else None,
            "status": "generalized" if rec.generalized else "sanitized"}


def rewrite(job: Job, proc: Processor, ctxs: dict) -> None:
    out_file = f"sanitized/{job.out_rel}"

    def rec_for(loc: str) -> RecordCtx:
        return ctxs.get(f"{job.rel}|{loc}") or RecordCtx()

    if job.kind in ("csv", "tsv"):
        delim = job.delim
        rows = job.data
        recs = [rec_for(f"row:{i}") for i in range(max(0, len(rows) - 1))]
        job.output_text = (csv_tsv.write(proc.csv_rewrite(rows, recs), delim, csv_tsv.line_terminator(job.text))
                           if rows else "")
        for i, rec in enumerate(recs):
            job.records.append(_record(out_file, f"row:{i}", rec))
    elif job.kind == "json":
        pointers = json_doc.record_locs(job.data)
        recmap = {p: rec_for(p) for p in pointers}
        new_data = proc.json_rewrite(job.data, recmap)
        if fhir.is_fhir(job.data) and fhir.new_problems(job.data, new_data):
            raise Quarantine("fhir_invalid_after_rewrite")   # never export a FHIR resource we broke
        job.output_text = json_doc.dump(new_data, json_doc.detect_indent(job.text), job.text.endswith("\n"))
        for p in pointers:
            rec = recmap[p]
            job.records.append(_record(out_file, p, rec))
    else:
        rec = rec_for("doc")
        job.output_text = proc.text_rewrite(job.text, rec)
        job.records.append(_record(out_file, "doc", rec))
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

    evs = {}                                                                         # P1b evidence
    for job in jobs:
        if job.status == "pending":
            try:
                evs[job.rel] = evidence(job, proc)
            except Exception as exc:  # noqa: BLE001
                job.status, job.reason = "quarantined", "evidence_error_" + log.error_kind(exc).lower()
    decide_date_order(jobs, evs)
    ctxs = build_contexts(jobs, evs, proc)                                           # P2 link
    gate = Counter()

    for job in jobs:                                                                 # P4 rewrite
        if job.status != "pending":
            continue
        try:
            rewrite(job, proc, ctxs)
            egress_gate(job, proc, gate)
        except Quarantine as q:
            job.status, job.reason, job.records = "quarantined", q.reason, []
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
    proc.gate = gate
    return write_report(out, files, records, entities, generalized=sum(1 for r in records if r.get("status") == "generalized"), suppressed=0,
                        seconds=time.monotonic() - t0,
                        extra={"egress_gate": {"files_rechecked": gate["rechecked"],
                                               "files_blocked": gate["blocked"]},
                               "patients_pseudonymised": getattr(proc, "linked_clusters", 0)})


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
