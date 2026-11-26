"""Per-format processing.

pass 1 (harvest): classify every column / JSON key, put personal values into the identity vault.
pass 2 (rewrite): replace or generalise every value according to its role; free text goes through the
                  layered engine. Structure is preserved exactly (rows, cells, keys, value types where
                  possible).
"""
from __future__ import annotations

import re
from collections import Counter

from .detect import columns as C
from .detect import lexicon as L
from .detect.engine import Engine
from .detect.hidden import decode_b64_text, encode_b64_text
from .detect.textnorm import digits_only, is_devanagari
from .privacy.ages import band_text
from .policy import POLICY

ROLE_PLACEHOLDER = {
    C.NAME: "[PATIENT]", C.RELATIVE: "[RELATIVE]", C.PHONE: "[PHONE]", C.EMAIL: "[EMAIL]",
    C.ID_PRIMARY: "[ID]", C.ID_OTHER: "[ID]", C.AADHAAR: "[AADHAAR]", C.ABHA: "[ABHA]", C.ABHA_ADDR: "[ABHA]",
    C.PAN: "[PAN]", C.INSURANCE: "[INSURANCE_ID]", C.ADDRESS: "[ADDRESS]", C.HOUSE: "[ADDRESS]",
    C.LOCALITY: "[ADDRESS]", C.LANDMARK: "[ADDRESS]", C.DOB: "[DOB]",
}
ROLE_ENTITY = {
    C.NAME: "PATIENT", C.RELATIVE: "RELATIVE", C.PHONE: "PHONE", C.EMAIL: "EMAIL", C.ID_PRIMARY: "MRN",
    C.ID_OTHER: "MRN", C.AADHAAR: "AADHAAR", C.ABHA: "ABHA_NUMBER", C.ABHA_ADDR: "ABHA_ADDRESS", C.PAN: "PAN",
    C.INSURANCE: "INSURANCE_ID", C.ADDRESS: "ADDRESS", C.HOUSE: "ADDRESS", C.LOCALITY: "ADDRESS",
    C.LANDMARK: "ADDRESS", C.VILLAGE: "VILLAGE", C.PIN: "PIN", C.DOB: "DOB",
}
_REL_PREFIX = re.compile(r"^\s*((?:S|D|W|C|H)\s*[/.\\]\s*O\.?|पुत्र|पुत्री|पत्नी|पति)\s*[:\-]?\s*", re.I)


def _blank(v) -> bool:
    return v is None or (isinstance(v, str) and not v.strip())


class Processor:
    def __init__(self, engine: Engine):
        self.engine = engine
        self.vault = engine.vault
        self.role_counts: Counter = Counter()
        self.generalized_records = 0

    # ====================================================================== harvest
    def harvest(self, role: str, value) -> None:
        if _blank(value) or isinstance(value, bool):
            return
        v = str(value)
        vt = self.vault
        if role == C.NAME:
            vt.add_name(v, "PATIENT")
        elif role == C.RELATIVE:
            vt.add_name(_REL_PREFIX.sub("", v), "RELATIVE")
        elif role == C.PHONE:
            vt.add_digits(v, "PHONE")
        elif role == C.AADHAAR:
            vt.add_digits(v, "AADHAAR")
        elif role == C.ABHA:
            vt.add_digits(v, "ABHA_NUMBER")
        elif role in (C.ID_PRIMARY, C.ID_OTHER):
            vt.add_id(v, "MRN")
        elif role == C.INSURANCE:
            vt.add_id(v, "INSURANCE_ID")
        elif role == C.ADDRESS:
            vt.add_address(v)
        elif role in (C.HOUSE, C.LOCALITY, C.LANDMARK):
            vt.add_text(v, "ADDRESS")
        elif role == C.VILLAGE:
            vt.add_text(v, "VILLAGE")
        elif role == C.PIN:
            vt.add_digits(v, "PIN")
        elif role in (C.TEXT, C.KEEP) and isinstance(value, str):
            decoded = decode_b64_text(v)
            self.engine.harvest_text(decoded if decoded is not None else v)

    # ====================================================================== rewrite one value
    def rewrite(self, role: str, value, ctx: dict | None = None):
        if _blank(value) or isinstance(value, bool):
            return value
        eng = self.engine
        if role in ROLE_PLACEHOLDER:
            self.role_counts[ROLE_ENTITY[role]] += 1
            if role == C.RELATIVE and isinstance(value, str):
                m = _REL_PREFIX.match(value)
                if m:
                    return value[:m.end()] + "[RELATIVE]"
            return ROLE_PLACEHOLDER[role]
        if role == C.VILLAGE:
            self.role_counts["VILLAGE"] += 1
            district = (ctx or {}).get(C.DISTRICT)
            return district if district else "[LOCATION]"
        if role == C.PIN:
            d = digits_only(str(value))
            self.role_counts["PIN"] += 1
            n = int(POLICY["pin_prefix_digits"])
            return d[:n] + "*" * (6 - n) if len(d) == 6 else "[PIN]"
        if role == C.AGE:
            band = band_text(str(value).strip().split()[0]) if str(value).strip() else None
            if band is None:
                return eng.clean(str(value)) if isinstance(value, str) else value
            if isinstance(value, str):
                return re.sub(r"\d{1,3}", band, value, count=1)
            return band
        if role == C.AGE_SEX and isinstance(value, str):
            m = re.match(r"\s*(\d{1,3})", value)
            if m and band_text(m.group(1)):
                return value[:m.start(1)] + band_text(m.group(1)) + value[m.end(1):]
            return eng.clean(value)
        if role == C.DOCTOR:
            return eng.clean(value, hard_only=True) if isinstance(value, str) else value
        # KEEP, TEXT, RELATION, GENDER, DATE, TEHSIL, DISTRICT, STATE: full detection on strings
        if isinstance(value, str):
            decoded = decode_b64_text(value)
            if decoded is not None:
                cleaned = eng.clean(decoded)
                return encode_b64_text(cleaned) if cleaned != decoded else value
            return eng.clean(value)
        if isinstance(value, int) and len(str(abs(value))) >= 6:
            s = str(value)
            cleaned = eng.clean(s)
            if cleaned != s:
                return cleaned
        return value

    # ====================================================================== CSV / TSV
    def csv_roles(self, rows: list[list[str]]) -> list[str]:
        if not rows:
            return []
        header, body = rows[0], rows[1:]
        roles = []
        for j, h in enumerate(header):
            role = C.classify_header(h)
            values = [r[j] for r in body if j < len(r)]
            prof = C.profile_values(values)
            if prof and role not in C.PII_ROLES:
                role = prof
            roles.append(role)
        # structural rule: an unrecognised column right after a relation column (values like W/o, D/o)
        # holds the relative's name
        for j in range(1, len(roles)):
            if roles[j] == C.TEXT and roles[j - 1] == C.RELATION:
                vals = [r[j] for r in body if j < len(r) and r[j].strip()]
                if vals and not any(re.search(r"\d", v) for v in vals):
                    roles[j] = C.RELATIVE
        return roles

    def csv_harvest(self, rows: list[list[str]]) -> None:
        if not rows:
            return
        roles = self.csv_roles(rows)
        self.engine.harvest_text(" | ".join(rows[0]))  # labelled PII inside headers
        for row in rows[1:]:
            names = []
            for j, cell in enumerate(row):
                role = roles[j] if j < len(roles) else C.TEXT
                self.harvest(role, cell)
                if role == C.NAME and cell.strip():
                    names.append(cell.strip())
            if len(names) > 1:
                self.vault.add_name(" ".join(names), "PATIENT")
                self.vault.add_name(" ".join(reversed(names)), "PATIENT")

    def csv_reclassify(self, rows: list[list[str]], roles: list[str]) -> list[str]:
        """Unknown short-text columns whose values are mostly harvested names become NAME columns."""
        cv = self.vault.compiled()
        out = list(roles)
        for j, role in enumerate(roles):
            if role != C.TEXT:
                continue
            vals = [r[j].strip() for r in rows[1:] if j < len(r) and r[j].strip()]
            if len(vals) < 2 or any(len(v.split()) > 4 or re.search(r"\d", v) for v in vals):
                continue
            hits = sum(1 for v in vals if cv.full_name_rx and cv.full_name_rx.fullmatch(v))
            if hits >= 0.6 * len(vals):
                out[j] = C.NAME
        return out

    def csv_rewrite(self, rows: list[list[str]]) -> list[list[str]]:
        if not rows:
            return rows
        roles = self.csv_reclassify(rows, self.csv_roles(rows))
        header = [self.engine.clean(h) for h in rows[0]]
        out = [header]
        for row in rows[1:]:
            ctx = {}
            for j, cell in enumerate(row):
                if j < len(roles) and roles[j] == C.DISTRICT and cell.strip():
                    ctx[C.DISTRICT] = cell.strip()
            new = []
            for j, cell in enumerate(row):
                role = roles[j] if j < len(roles) else C.TEXT
                new.append(self.rewrite(role, cell, ctx))
            if any(r in (C.AGE, C.AGE_SEX, C.VILLAGE, C.PIN, C.DOB) and j < len(row) and row[j].strip()
                   for j, r in enumerate(roles)):
                self.generalized_records += 1
            out.append(new)
        return out

    # ====================================================================== JSON (generic + FHIR)
    def json_harvest(self, data) -> None:
        self._walk(data, [], None, harvest=True)

    def json_rewrite(self, data):
        return self._walk(data, [], None, harvest=False)

    def _walk(self, node, keys: list[str], resource: str | None, harvest: bool, ctx: dict | None = None):
        if isinstance(node, dict):
            resource = node.get("resourceType") if isinstance(node.get("resourceType"), str) else resource
            local_ctx = dict(ctx or {})
            for k, v in node.items():
                if isinstance(v, str) and C.classify_json_path(keys + [k], resource) == C.DISTRICT:
                    local_ctx[C.DISTRICT] = v
            ext_person = _person_extension(node)
            if harvest:
                names = [v for k, v in node.items() if isinstance(v, str) and not is_devanagari(v)
                         and C.classify_json_path(keys + [k], resource) == C.NAME]
                if len(names) > 1:
                    self.vault.add_name(" ".join(names), "PATIENT")
                for k, v in node.items():
                    if ext_person and k == "valueString":
                        self.harvest(C.RELATIVE, v)
                    else:
                        self._walk(v, keys + [k], resource, True, local_ctx)
                return None
            out = {}
            for k, v in node.items():
                nk = self._clean_key(k, out)
                if ext_person and k == "valueString" and isinstance(v, str):
                    out[nk] = self.rewrite(C.RELATIVE, v)
                else:
                    out[nk] = self._walk(v, keys + [k], resource, False, local_ctx)
            return out
        if isinstance(node, list):
            if harvest:
                for x in node:
                    self._walk(x, keys, resource, True, ctx)
                return None
            return [self._walk(x, keys, resource, False, ctx) for x in node]
        role = C.classify_json_path(keys, resource)
        if harvest:
            self.harvest(role, node)
            return None
        return self.rewrite(role, node, ctx)

    def _clean_key(self, key: str, taken: dict) -> str:
        new = self.engine.clean(key)
        if new != key:
            base, i = new, 2
            while new in taken:
                new = f"{base}_{i}"
                i += 1
        return new

    # ====================================================================== text
    def text_harvest(self, text: str) -> None:
        self.engine.harvest_text(text)

    def text_rewrite(self, text: str) -> str:
        return self.engine.clean(text)

    # ====================================================================== file names
    def name_has_pii(self, rel: str) -> bool:
        stem = rel.rsplit("/", 1)[-1]
        stem = stem.rsplit(".", 1)[0] if "." in stem else stem
        probe = re.sub(r"[_]+", " ", stem)
        spans = self.engine.find(probe) + self.engine.find(stem)
        return any(s.kind != "AGE" for s in spans)


def _person_extension(node: dict) -> bool:
    url = node.get("url")
    return (isinstance(url, str) and "valueString" in node
            and bool(re.search(r"name|mother|father|spouse|husband|wife|guardian|relative|kin", url, re.I)))
