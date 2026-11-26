"""Structural FHIR R4 checks (no external dependency).

Mirrors what the published integrity score checks: resource types, ids, required elements, value
sets, date/dateTime/instant syntax, base64 attachments, XHTML narrative, and every reference
resolvable inside the Bundle. The pipeline compares problems before and after sanitising: a
rewrite must never introduce a new problem (else the file is quarantined, never exported broken).
"""
from __future__ import annotations

import base64
import binascii
import re

RESOURCE_TYPES = {
    "Bundle", "Patient", "Practitioner", "PractitionerRole", "Organization", "Encounter", "Condition",
    "Observation", "MedicationRequest", "MedicationStatement", "Medication", "Procedure", "Composition",
    "DocumentReference", "DiagnosticReport", "AllergyIntolerance", "Immunization", "CarePlan", "Location",
    "RelatedPerson", "ServiceRequest", "Specimen", "Claim", "Coverage", "ExplanationOfBenefit",
    "Appointment", "Provenance", "ImagingStudy", "Device", "Goal", "CareTeam", "SupplyDelivery",
    "MedicationAdministration", "QuestionnaireResponse", "Binary", "List", "Media", "Consent",
}
RX_ID = re.compile(r"^[A-Za-z0-9\-.]{1,64}$")
RX_DATE = re.compile(r"^\d{4}(-(0[1-9]|1[0-2])(-(0[1-9]|[12]\d|3[01]))?)?$")
RX_DATETIME = re.compile(r"^\d{4}(-(0[1-9]|1[0-2])(-(0[1-9]|[12]\d|3[01])(T([01]\d|2[0-3]):[0-5]\d:([0-5]\d|60)"
                         r"(\.\d{1,9})?(Z|[+-]((0\d|1[0-3]):[0-5]\d|14:00)))?)?)?$")
RX_INSTANT = re.compile(r"^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:([0-5]\d|60)"
                        r"(\.\d{1,9})?(Z|[+-]((0\d|1[0-3]):[0-5]\d|14:00))$")
DATE_FIELDS = {"birthDate": RX_DATE, "recordedDate": RX_DATETIME, "authoredOn": RX_DATETIME,
               "effectiveDateTime": RX_DATETIME, "performedDateTime": RX_DATETIME, "onsetDateTime": RX_DATETIME,
               "abatementDateTime": RX_DATETIME, "issued": RX_INSTANT, "timestamp": RX_INSTANT,
               "lastUpdated": RX_INSTANT, "start": RX_DATETIME, "end": RX_DATETIME, "date": RX_DATETIME,
               "deceasedDateTime": RX_DATETIME, "occurrenceDateTime": RX_DATETIME, "created": RX_DATETIME}
VALUE_SETS = {
    ("Patient", "gender"): {"male", "female", "other", "unknown"},
    ("Bundle", "type"): {"document", "message", "transaction", "transaction-response", "batch",
                         "batch-response", "history", "searchset", "collection"},
    ("Encounter", "status"): {"planned", "arrived", "triaged", "in-progress", "onleave", "finished",
                              "cancelled", "entered-in-error", "unknown"},
    ("Observation", "status"): {"registered", "preliminary", "final", "amended", "corrected", "cancelled",
                                "entered-in-error", "unknown"},
    ("MedicationRequest", "status"): {"active", "on-hold", "cancelled", "completed", "entered-in-error",
                                      "stopped", "draft", "unknown"},
    ("MedicationRequest", "intent"): {"proposal", "plan", "order", "original-order", "reflex-order",
                                      "filler-order", "instance-order", "option"},
    ("Composition", "status"): {"preliminary", "final", "amended", "entered-in-error"},
    ("Procedure", "status"): {"preparation", "in-progress", "not-done", "on-hold", "stopped", "completed",
                              "entered-in-error", "unknown"},
    ("DocumentReference", "status"): {"current", "superseded", "entered-in-error"},
    ("DiagnosticReport", "status"): {"registered", "partial", "preliminary", "final", "amended", "corrected",
                                     "appended", "cancelled", "entered-in-error", "unknown"},
}
REQUIRED = {
    "Observation": ("status", "code"), "Encounter": ("status", "class"), "Condition": ("subject",),
    "MedicationRequest": ("status", "intent", "subject"), "Composition": ("status", "type", "date", "author", "title"),
    "Procedure": ("status", "subject"), "DocumentReference": ("status", "content"),
    "DiagnosticReport": ("status", "code"), "Bundle": ("type",),
}


def is_fhir(data) -> bool:
    return isinstance(data, dict) and isinstance(data.get("resourceType"), str)


def problems(data) -> list[str]:
    """Problem codes (no values, so they are safe to log/compare)."""
    out: list[str] = []
    if not is_fhir(data):
        return ["not_fhir"]
    resources = []
    full_urls = set()
    if data.get("resourceType") == "Bundle":
        _check_resource(data, out, top=True)
        for i, e in enumerate(data.get("entry") or []):
            if not isinstance(e, dict) or not isinstance(e.get("resource"), dict):
                out.append("entry_without_resource")
                continue
            if isinstance(e.get("fullUrl"), str):
                full_urls.add(e["fullUrl"])
            r = e["resource"]
            resources.append(r)
            if isinstance(r.get("resourceType"), str) and isinstance(r.get("id"), str):
                full_urls.add(f"{r['resourceType']}/{r['id']}")
                full_urls.add(f"urn:uuid:{r['id']}")
    else:
        resources.append(data)
    for r in resources:
        _check_resource(r, out)
    for ref in _references(data):
        if ref.startswith("#") or ref.startswith("http"):
            continue
        if data.get("resourceType") == "Bundle" and ref not in full_urls:
            out.append("unresolved_reference")
    return out


def _check_resource(r: dict, out: list, top: bool = False) -> None:
    rt = r.get("resourceType")
    if rt not in RESOURCE_TYPES:
        out.append("unknown_resource_type")
        return
    rid = r.get("id")
    if rid is not None and (not isinstance(rid, str) or not RX_ID.match(rid)):
        out.append("bad_id")
    for k in REQUIRED.get(rt, ()):
        if r.get(k) in (None, "", [], {}):
            out.append(f"missing_{rt}.{k}")
    for (vrt, k), allowed in VALUE_SETS.items():
        if vrt == rt and k in r and r[k] not in allowed:
            out.append(f"bad_code_{rt}.{k}")
    if not top or rt != "Bundle":
        _walk_values(r, out, rt)
    else:
        for k in ("timestamp",):
            if k in r and not (isinstance(r[k], str) and RX_INSTANT.match(r[k])):
                out.append("bad_instant")
        meta = r.get("meta")
        if isinstance(meta, dict) and "lastUpdated" in meta and not (
                isinstance(meta["lastUpdated"], str) and RX_INSTANT.match(meta["lastUpdated"])):
            out.append("bad_instant")


def _walk_values(node, out: list, rt: str, key: str | None = None) -> None:
    if isinstance(node, dict):
        if "resourceType" in node and key is not None:
            return  # contained resources are checked on their own
        for k, v in node.items():
            if k == "text" and isinstance(v, dict) and "div" in v:
                d = v.get("div")
                if not (isinstance(d, str) and d.lstrip().startswith("<div") and d.rstrip().endswith("</div>")):
                    out.append("bad_narrative")
                if v.get("status") not in ("generated", "extensions", "additional", "empty"):
                    out.append("bad_narrative_status")
            if k == "data" and isinstance(v, str):
                try:
                    base64.b64decode(v, validate=True)
                except (binascii.Error, ValueError):
                    out.append("bad_base64")
            if k in DATE_FIELDS and isinstance(v, str) and not DATE_FIELDS[k].match(v):
                out.append(f"bad_date_{k}")
            if k == "reference" and not isinstance(v, str):
                out.append("bad_reference")
            _walk_values(v, out, rt, k)
    elif isinstance(node, list):
        for x in node:
            _walk_values(x, out, rt, key)


def _references(node):
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "reference" and isinstance(v, str):
                yield v
            else:
                yield from _references(v)
    elif isinstance(node, list):
        for x in node:
            yield from _references(x)


def new_problems(before, after) -> list[str]:
    """Problems present after sanitising that were not in the input (multiset difference)."""
    from collections import Counter
    return sorted((Counter(problems(after)) - Counter(problems(before))).elements())
