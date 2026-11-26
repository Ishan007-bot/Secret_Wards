"""Per-format processing.

pass 1  harvest   classify every column / JSON key, put personal values into the identity vault
pass 1b evidence  per record (row:N, /json/pointer, doc): IDs, phones, names, relatives, DOB, age...
pass 2  rewrite   per record, with that record's pseudonym and date shift; structure preserved
"""
from __future__ import annotations

import re
from collections import Counter

from .detect import columns as C
from .detect.engine import Engine
from .detect.hidden import decode_b64_text, encode_b64_text
from .detect.textnorm import digits_only, is_devanagari
from .detect.unhide import unhide
from .formats import json_doc
from .link.context import RecordCtx
from .link.linker import Evidence, norm_id
from .policy import POLICY
from .privacy import dates as D
from .privacy.ages import band_text
from .privacy.rare import RX_ICD, RareDx

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
_GENERALISED = (C.AGE, C.AGE_SEX, C.VILLAGE, C.TEHSIL, C.PIN, C.DOB)


def _blank(v) -> bool:
    return v is None or (isinstance(v, str) and not v.strip())


class Processor:
    def __init__(self, engine: Engine):
        self.engine = engine
        self.vault = engine.vault
        self.role_counts: Counter = Counter()
        self.generalized_records = 0
        self.rare = RareDx()

    # ====================================================================== pass 1: harvest
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
        elif role in (C.VILLAGE, C.TEHSIL):
            vt.add_text(v, "VILLAGE")
        elif role == C.DISTRICT:
            vt.keep_text(v)          # a district is released on purpose: never redact it via the vault
        elif role == C.PIN:
            vt.add_digits(v, "PIN")
        elif role in (C.TEXT, C.KEEP) and isinstance(value, str):
            decoded = decode_b64_text(v)
            self.engine.harvest_text(decoded if decoded is not None else v)

    # ====================================================================== pass 1b: evidence
    def evidence_from_role(self, ev: Evidence, role: str, value, month_first: bool) -> None:
        if _blank(value) or isinstance(value, bool):
            return
        v = str(value)
        if role == C.NAME:
            ev.add_name(v)
        elif role == C.RELATIVE:
            ev.add_relative(_REL_PREFIX.sub("", v))
        elif role == C.PHONE:
            d = digits_only(v)
            if len(d) >= 10:
                ev.phones.add(d[-10:])
        elif role == C.AADHAAR:
            d = digits_only(v)
            if len(d) == 12:
                ev.aadhaar.add(d)
        elif role == C.ABHA:
            d = digits_only(v)
            if len(d) == 14:
                ev.abha.add(d)
        elif role in (C.ID_PRIMARY, C.ID_OTHER):
            n = norm_id(v)
            if n and re.search(r"\d", n):
                ev.ids.add(n)
        elif role == C.INSURANCE:
            ev.insurance.add(norm_id(v))
        elif role == C.EMAIL:
            ev.emails.add(v.strip().lower())
        elif role == C.DOB:
            ev.add_dob(_date_candidates(v, month_first))
        elif role == C.AGE:
            ev.add_age(v)
        elif role == C.AGE_SEX:
            ev.add_age(v)
            m = re.search(r"/\s*([MFmf])\b|\b(male|female)\b", v, re.I)
            if m:
                ev.add_gender(m.group(1) or m.group(2))
        elif role == C.GENDER:
            ev.add_gender(v)
        elif role == C.DISTRICT:
            ev.districts.add(v.strip().casefold())
        elif role == C.VILLAGE:
            ev.add_village(v)
        elif role in (C.TEXT, C.KEEP) and isinstance(value, str):
            decoded = decode_b64_text(v)
            self.evidence_from_text(ev, decoded if decoded is not None else v, month_first)

    def evidence_from_text(self, ev: Evidence, text: str, month_first: bool) -> None:
        if _INERT.fullmatch(text):
            return
        text = unhide(text)
        self.rare.observe_text(text)
        ev.dx |= {m.group(1).upper() for m in RX_ICD.finditer(text)}
        for sp in self.engine.find(text, crf=False):   # CRF hits never create linkage evidence
            s = text[sp.start:sp.end]
            k = sp.kind
            if k == "MRN":
                n = norm_id(s)
                if n.isdigit():
                    # a bare digit core links only if it is a whole run of 6+ digits naming one known ID
                    full = self.vault.core_to_id.get(n) if len(n) >= 6 else None
                    if full and _whole_digit_run(text, sp.start, sp.end):
                        ev.ids.add(full)
                else:
                    ev.ids.add(n)
            elif k in ("PHONE",):
                d = digits_only(s)
                if len(d) >= 10:
                    ev.phones.add(d[-10:])
            elif k == "AADHAAR":
                ev.aadhaar.add(digits_only(s))
            elif k == "ABHA_NUMBER":
                ev.abha.add(digits_only(s))
            elif k == "EMAIL":
                ev.emails.add(s.lower())
            elif k == "INSURANCE_ID":
                ev.insurance.add(norm_id(s))
            elif k == "PATIENT":
                if sp.src in ("label", "vault_full"):
                    ev.add_name(s)
                elif sp.src == "vault_tok":
                    ev.add_name(s, strong=False)
            elif k == "RELATIVE":
                ev.add_relative(s)
            elif k == "DOB":
                ev.add_dob(_date_candidates(s, month_first))
            elif k == "AGE":
                ev.add_age(s)
            elif k == "VILLAGE":
                ev.add_village(s)

    # ====================================================================== pass 2: rewrite one value
    def rewrite(self, role: str, value, ctx: dict | None = None, rec: RecordCtx | None = None):
        if _blank(value) or isinstance(value, bool):
            return value
        eng = self.engine
        if rec is not None and role in _GENERALISED:
            rec.generalized = True
        if role in (C.ID_PRIMARY, C.NAME) and rec is not None and rec.psn:
            self.role_counts[ROLE_ENTITY[role]] += 1
            rec.used = True
            return rec.psn
        if role == C.DOB:
            self.role_counts["DOB"] += 1
            if POLICY["dob_mode"] == "jitter" and rec is not None and rec.shifter is not None                     and isinstance(value, str):
                jittered = rec.shifter.shift_text(value, dob=True)
                if jittered != value:
                    return jittered
            return "[DOB]"
        if role in ROLE_PLACEHOLDER:
            self.role_counts[ROLE_ENTITY[role]] += 1
            if role == C.RELATIVE and isinstance(value, str):
                m = _REL_PREFIX.match(value)
                if m:
                    return value[:m.end()] + "[RELATIVE]"
            return ROLE_PLACEHOLDER[role]
        if role == C.DISTRICT and POLICY["location_level"] == "none" and isinstance(value, str):
            self.role_counts["VILLAGE"] += 1
            return "[LOCATION]"
        if role in (C.VILLAGE, C.TEHSIL):        # location_level: district
            self.role_counts["VILLAGE"] += 1
            district = (ctx or {}).get(C.DISTRICT) if POLICY["location_level"] == "district" else None
            return district if district else "[LOCATION]"
        if role == C.PIN:
            d = digits_only(str(value))
            self.role_counts["PIN"] += 1
            n = int(POLICY["pin_prefix_digits"])
            return d[:n] + "*" * (6 - n) if len(d) == 6 else "[PIN]"
        width = rec.age_width if rec is not None else None
        if role == C.AGE:
            band = band_text(str(value).strip().split()[0], width) if str(value).strip() else None
            if band is None:
                return eng.clean(str(value), rec=rec) if isinstance(value, str) else value
            if isinstance(value, str):
                return re.sub(r"\d{1,3}", band, value, count=1)
            return band
        if role == C.AGE_SEX and isinstance(value, str):
            m = re.match(r"\s*(\d{1,3})", value)
            if m and band_text(m.group(1), width):
                return value[:m.start(1)] + band_text(m.group(1), width) + value[m.end(1):]
            return eng.clean(value, rec=rec)
        if role == C.DOCTOR:
            return eng.clean(value, hard_only=True) if isinstance(value, str) else value
        if role == C.DATE and isinstance(value, str):
            return eng.clean(value, rec=rec)
        # KEEP, TEXT, RELATION, GENDER, TEHSIL, DISTRICT, STATE: full detection on strings
        if isinstance(value, str) and _INERT.fullmatch(value):
            return value          # URL / URN / UUID / lowercase code word: cannot hold PII (egress gate re-checks)
        if isinstance(value, str):
            decoded = decode_b64_text(value)
            if decoded is not None:
                cleaned = self._coarsen(eng.clean(decoded, rec=rec), rec)
                return encode_b64_text(cleaned) if cleaned != decoded else value
            return self._coarsen(eng.clean(value, rec=rec), rec)
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
            if role == C.TEXT and C.profile_id_column(h, values):
                role = C.ID_PRIMARY
            roles.append(role)
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
        self.engine.harvest_text(" | ".join(rows[0]))
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
        cv = self.vault.compiled()
        out = list(roles)
        for j, role in enumerate(roles):
            if role != C.TEXT:
                continue
            vals = [r[j].strip() for r in rows[1:] if j < len(r) and r[j].strip()]
            if len(vals) < 2 or any(len(v.split()) > 4 or re.search(r"\d", v) for v in vals):
                continue
            hits = sum(1 for v in vals if any(s == 0 and e == len(v) and src == "vault_full"
                                              for s, e, _k, src in cv.matches(v)))
            if hits >= 0.6 * len(vals):
                out[j] = C.NAME
        return out

    def csv_evidence(self, rows: list[list[str]], rel: str, month_first: bool) -> list[Evidence]:
        if not rows:
            return []
        roles = self.csv_reclassify(rows, self.csv_roles(rows))
        out = []
        for i, row in enumerate(rows[1:]):
            ev = Evidence(rid=f"{rel}|row:{i}")
            names = []
            for j, cell in enumerate(row):
                role = roles[j] if j < len(roles) else C.TEXT
                if role == C.NAME:
                    if cell.strip():
                        names.append(cell.strip())
                    continue
                self.evidence_from_role(ev, role, cell, month_first)
            if names:
                ev.add_name(" ".join(names))
            out.append(ev)
        return out

    def csv_rewrite(self, rows: list[list[str]], recs: list | None = None) -> list[list[str]]:
        if not rows:
            return rows
        roles = self.csv_reclassify(rows, self.csv_roles(rows))
        header = [self.engine.clean(h) for h in rows[0]]
        out = [header]
        for i, row in enumerate(rows[1:]):
            rec = recs[i] if recs and i < len(recs) else None
            ctx = {}
            for j, cell in enumerate(row):
                if j < len(roles) and roles[j] == C.DISTRICT and cell.strip():
                    ctx[C.DISTRICT] = cell.strip()
            new = [self.rewrite(roles[j] if j < len(roles) else C.TEXT, cell, ctx, rec) for j, cell in enumerate(row)]
            out.append(new)
        return out

    # ====================================================================== JSON (generic + FHIR)
    def json_harvest(self, data) -> None:
        self._walk(data, [], None, mode="harvest")

    def json_evidence(self, data, rel: str, month_first: bool) -> list[Evidence]:
        pointers = json_doc.record_locs(data)
        evs = {p: Evidence(rid=f"{rel}|{p}") for p in pointers}
        self._walk(data, [], None, mode="evidence", ptr=[], recmap=evs, month_first=month_first,
                   cur=evs.get("doc"))
        return [evs[p] for p in pointers]

    def json_rewrite(self, data, recmap: dict | None = None):
        recmap = recmap or {}
        return self._walk(data, [], None, mode="rewrite", ptr=[], recmap=recmap, cur=recmap.get("doc"))

    def _walk(self, node, keys, resource, mode, ctx=None, ptr=None, recmap=None, cur=None, month_first=False):
        if ptr is not None and recmap:
            here = "/" + "/".join(ptr) if ptr else None
            if here in recmap:
                cur = recmap[here]
        if isinstance(node, dict):
            resource = node.get("resourceType") if isinstance(node.get("resourceType"), str) else resource
            local_ctx = dict(ctx or {})
            for k, v in node.items():
                if isinstance(v, str) and C.classify_json_path(keys + [k], resource) == C.DISTRICT:
                    local_ctx[C.DISTRICT] = v
            ext_person = _person_extension(node)
            if mode == "harvest":
                names = [v for k, v in node.items() if isinstance(v, str) and not is_devanagari(v)
                         and C.classify_json_path(keys + [k], resource) == C.NAME]
                if len(names) > 1:
                    self.vault.add_name(" ".join(names), "PATIENT")
            if mode == "evidence":
                code, disp = node.get("code"), node.get("display")
                if isinstance(code, str) and isinstance(disp, str):
                    self.rare.observe_pair(code, disp)
            if mode == "evidence" and cur is not None:
                names = [v for k, v in node.items() if isinstance(v, str) and not is_devanagari(v)
                         and C.classify_json_path(keys + [k], resource) == C.NAME]
                if len(names) > 1:
                    cur.add_name(" ".join(names))
            out = {} if mode == "rewrite" else None
            geo = node.get("url") in ("latitude", "longitude") or any(
                str(k).lower() in _GEO_KEYS for k in node)
            for k, v in node.items():
                if mode == "rewrite" and geo and isinstance(v, float) and (
                        k == "valueDecimal" or str(k).lower() in _GEO_KEYS):
                    out[k] = round(v, 1)          # exact coordinates locate a home: keep ~10 km only
                    continue
                child_ptr = ptr + [json_doc.escape_token(str(k))] if ptr is not None else None
                if ext_person and k == "valueString":
                    if mode == "harvest":
                        self.harvest(C.RELATIVE, v)
                    elif mode == "evidence" and cur is not None:
                        self.evidence_from_role(cur, C.RELATIVE, v, month_first)
                    else:
                        out[self._clean_key(k, out)] = self.rewrite(C.RELATIVE, v, None, cur)
                    continue
                if (mode == "rewrite" and resource and isinstance(v, str) and POLICY["dob_mode"] == "remove"
                        and C.classify_json_path(keys + [k], resource) == C.DOB):
                    self.role_counts["DOB"] += 1          # FHIR date type: a placeholder would be invalid R4,
                    if cur is not None:                   # so the element is dropped (it is optional)
                        cur.generalized = True
                    continue
                res = self._walk(v, keys + [k], resource, mode, local_ctx, child_ptr, recmap, cur, month_first)
                if mode == "rewrite":
                    out[self._clean_key(k, out)] = res
            return out
        if isinstance(node, list):
            results = [self._walk(x, keys, resource, mode, ctx, (ptr + [str(i)]) if ptr is not None else None,
                                  recmap, cur, month_first) for i, x in enumerate(node)]
            return results if mode == "rewrite" else None
        role = C.classify_json_path(keys, resource)
        if mode == "harvest":
            self.harvest(role, node)
            return None
        if mode == "evidence":
            if cur is not None:
                self.evidence_from_role(cur, role, node, month_first)
            return None
        return self.rewrite(role, node, ctx, cur)

    def _clean_key(self, key: str, taken: dict) -> str:
        cache = self.__dict__.setdefault("_key_cache", {})
        new = cache.get(key)
        if new is None:
            new = cache[key] = self.engine.clean(key)
        if new != key:
            base, i = new, 2
            while new in taken:
                new = f"{base}_{i}"
                i += 1
        return new

    # ====================================================================== text
    def text_harvest(self, text: str) -> None:
        self.engine.harvest_text(text)

    def text_evidence(self, text: str, rel: str, month_first: bool) -> list[Evidence]:
        ev = Evidence(rid=f"{rel}|doc")
        self.evidence_from_text(ev, text, month_first)
        return [ev]

    def text_rewrite(self, text: str, rec: RecordCtx | None = None) -> str:
        return self._coarsen(self.engine.clean(text, rec=rec), rec)

    def _coarsen(self, text: str, rec: RecordCtx | None) -> str:
        """Rare diagnoses -> ICD chapter, only inside a patient's record."""
        if rec is None or rec.shifter is None:
            return text
        out, n = self.rare.apply(text)
        if n:
            rec.generalized = True
        return out

    # ====================================================================== file names
    def name_has_pii(self, rel: str) -> bool:
        stem = rel.rsplit("/", 1)[-1]
        stem = stem.rsplit(".", 1)[0] if "." in stem else stem
        probe = re.sub(r"[_]+", " ", stem)
        spans = self.engine.find(probe) + self.engine.find(stem)
        return any(s.kind != "AGE" for s in spans)


_INERT = re.compile(r"(?:https?://|urn:(?:oid|uuid):)[A-Za-z0-9./#:_-]*[A-Za-z/#._-]|"
                    r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}|[a-z][a-z-]{0,29}")
_GEO_KEYS = {"lat", "lng", "lon", "long", "latitude", "longitude"}


def _whole_digit_run(text: str, s: int, e: int) -> bool:
    """True if text[s:e] is not part of a longer number / ID (e.g. the '00987' inside 'OPD/31/07/00987')."""
    before = text[max(0, s - 1):s]
    after = text[e:e + 1]
    return not re.match(r"[0-9/\-.]", before or " ") and not re.match(r"[0-9/\-.]", after or " ")


def _date_candidates(value: str, month_first: bool) -> list:
    """Both readings of an ambiguous numeric date (so a d/m vs m/d mix-up never blocks a link)."""
    a = D.parse_one(value, month_first)
    b = D.parse_one(value, not month_first)
    return [x for x in {a, b} if x is not None]


def _person_extension(node: dict) -> bool:
    url = node.get("url")
    return (isinstance(url, str) and "valueString" in node
            and bool(re.search(r"name|mother|father|spouse|husband|wife|guardian|relative|kin", url, re.I)))
