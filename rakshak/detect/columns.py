"""Role classification for CSV/TSV columns and JSON keys.

Two independent signals:
  1. the header / key name (English, Hinglish and Devanagari vocabulary, order-sensitive rules);
  2. the values themselves (phones, 12-digit IDs, emails, PAN, ...), which can override a
     misleading or unseen header. Unknown columns fall back to "text": full free-text detection.
"""
from __future__ import annotations

import re
from functools import lru_cache

# roles
NAME, RELATIVE, RELATION, DOCTOR = "name", "relative", "relation", "doctor"
PHONE, EMAIL, ID_PRIMARY, ID_OTHER = "phone", "email", "id_primary", "id_other"
AADHAAR, ABHA, ABHA_ADDR, PAN, INSURANCE = "aadhaar", "abha", "abha_address", "pan", "insurance"
ADDRESS, HOUSE, LOCALITY, LANDMARK, VILLAGE = "address", "house", "locality", "landmark", "village"
TEHSIL, DISTRICT, STATE, PIN = "tehsil", "district", "state", "pin"
DOB, AGE, AGE_SEX, GENDER, DATE = "dob", "age", "age_sex", "gender", "date"
KEEP, TEXT = "keep", "text"

PII_ROLES = {NAME, RELATIVE, PHONE, EMAIL, ID_PRIMARY, ID_OTHER, AADHAAR, ABHA, ABHA_ADDR, PAN, INSURANCE,
             ADDRESS, HOUSE, LOCALITY, LANDMARK, VILLAGE, PIN, DOB}


def norm_header(h: str) -> str:
    h = h.replace("﻿", "").strip().lower()
    h = re.sub(r"[_/\\#.()\[\]:\-'’`]+", " ", h)
    return re.sub(r"\s+", " ", h).strip()


@lru_cache(maxsize=None)
def _word_rx(w: str):
    return re.compile(r"(?<![a-z0-9])" + re.escape(w) + r"(?![a-z0-9])")


def _has(h: str, *words: str) -> bool:
    """Whole-word match for Latin words, substring match for Devanagari words."""
    for w in words:
        if "ऀ" <= w[:1] <= "ॿ":
            if w in h:
                return True
        elif w in h and _word_rx(w).search(h):
            return True
    return False


_NOT_PERSON = ("drug", "test", "hospital", "lab", "facility", "file", "system", "form", "category", "package",
               "procedure", "panel", "department", "dept", "ward", "doctor", "medicine", "medication", "item",
               "product", "scheme", "insurer", "payer", "company", "organisation", "organization", "unit",
               "specimen", "sample", "report", "diagnosis", "disease", "condition", "service", "plan",
               "consultant", "physician", "provider", "practitioner", "author", "bank", "branch")


@lru_cache(maxsize=65536)
def classify_header(header: str) -> str:
    h = norm_header(header)
    if not h:
        return TEXT
    # dates first ("Reg Date", "Registered (MM/DD/YYYY)" are dates, not IDs)
    if _has(h, "dob", "d o b", "birth", "birthdate", "janm", "जन्म"):
        return DOB
    if _has(h, "age sex", "age gender", "agesex", "age_sex") or ("age" in h.split() and ("sex" in h or "gender" in h)):
        return AGE_SEX
    if _has(h, "age", "umar", "umr", "उम्र", "आयु", "age years", "age yrs"):
        return AGE
    if _has(h, "gender", "sex", "ling", "लिंग"):
        return GENDER
    if _has(h, "date", "dt", "tithi", "तारीख", "तिथि", "time", "timestamp", "registered", "admitted",
            "discharged", "collected", "reported", "generated", "updated", "created", "on") and not _has(
            h, "name", "naam", "no", "number", "id"):
        return DATE
    if _has(h, "relation", "relationship", "rel type", "rishta", "रिश्ता"):
        return RELATION
    if _has(h, "doctor", "dr", "consultant", "physician", "referred by", "ref doctor", "ref by",
            "treating", "surgeon", "डॉक्टर", "chikitsak"):
        return DOCTOR
    if _has(h, "guardian", "relative", "father", "husband", "mother", "pita", "pati", "पिता", "पति", "माता",
            "spouse", "next of kin", "nok", "attendant", "parent", "wife", "care of", "c o", "s o", "w o",
            "d o", "informant", "kin", "emergency contact name", "witness", "caller", "rishtedar",
            "rishtedaar", "parijan", "परिजन", "रिश्तेदार", "abhibhavak", "अभिभावक"):
        return RELATIVE
    if _has(h, "email", "e mail", "mail", "mail id", "ईमेल"):
        return EMAIL
    if _has(h, "aadhaar", "aadhar", "adhar", "aadhaar no", "uid", "uidai", "आधार"):
        return AADHAAR
    if _has(h, "abha address", "health id address", "phr address", "phr"):
        return ABHA_ADDR
    if _has(h, "abha", "health id", "healthid", "abha no", "abha number"):
        return ABHA
    if _has(h, "pan", "pan no", "payer pan", "pan card", "पैन"):
        return PAN
    if _has(h, "policy", "pmjay", "insurance", "insured", "member id", "card no", "claim id", "beneficiary id",
            "scheme id", "tpa id"):
        return INSURANCE
    if _has(h, "mobile", "phone", "contact", "mob", "tel", "telephone", "cell", "callback", "whatsapp",
            "landline", "फोन", "फ़ोन", "मोबाइल", "sampark", "संपर्क"):
        return PHONE
    if _has(h, "uhid", "mrn", "mr no", "reg no", "registration no", "reg id", "registration id", "patient id",
            "hospital no", "hosp no", "hosp id", "regn", "regn no", "mr number", "medical record", "record no",
            "file no", "hospital number", "patient number",
            "patientid", "patient ref", "patient no", "pid", "crn", "cr no", "hospital id", "hospital uhid",
            "case no", "op no", "opd no", "pt id", "पंजीकरण", "panjikaran", "reg", "registration number"):
        return ID_PRIMARY
    if _has(h, "ipd", "ip no", "ipd no", "adm no", "admission no", "admission id", "inpatient no", "bed ticket",
            "आईपीडी"):
        return ID_OTHER
    if _has(h, "pin", "pincode", "pin code", "zip", "zipcode", "postal", "postal code", "पिन", "पिनकोड"):
        return PIN
    if _has(h, "district", "jila", "zila", "distt", "जिला", "जनपद"):
        return DISTRICT
    if _has(h, "tehsil", "taluk", "taluka", "block", "तहसील", "mandal"):
        return TEHSIL
    if _has(h, "state", "राज्य", "country"):
        return STATE
    if _has(h, "village", "gaon", "gram", "ग्राम", "गाँव", "गांव", "city", "town", "mohalla", "locality",
            "colony", "basti", "place", "residence area", "mauza"):
        return VILLAGE
    if _has(h, "house", "h no", "house no", "makan", "flat", "door", "मकान"):
        return HOUSE
    if _has(h, "landmark", "near"):
        return LANDMARK
    if _has(h, "address", "addr", "pata", "पता", "street", "line", "residence", "location", "niwas", "nivas",
            "निवास", "ghar", "residential"):
        return ADDRESS
    if _has(h, "name", "naam", "नाम", "patient", "pt", "full name", "first name", "last name", "firstname",
            "lastname", "given", "family", "surname", "first", "last", "मरीज़", "मरीज", "रोगी", "mareez"):
        if _has(h, *_NOT_PERSON):
            return KEEP if _has(h, "doctor", "consultant", "physician", "practitioner") else TEXT
        return NAME
    return TEXT


# ---------------------------------------------------------------------------------------- values
_RX_PHONE = re.compile(r"^\s*(?:\+?91[\s-]?|0)?[6-9]\d(?:[\s-]?\d){8}\s*$")
_RX_AADHAAR = re.compile(r"^\s*[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\s*$")
_RX_EMAIL = re.compile(r"^\s*[\w.+-]+@[\w-]+\.[\w.]+\s*$")
_RX_PAN = re.compile(r"^\s*[A-Z]{5}\d{4}[A-Z]\s*$")


def profile_values(values: list[str]) -> str | None:
    """Return a PII role if the values are unmistakably of one kind (>= 60% of non-empty cells)."""
    vals = [v for v in values if v and v.strip()]
    if len(vals) < 1:
        return None
    n = len(vals)
    for role, rx in ((PHONE, _RX_PHONE), (AADHAAR, _RX_AADHAAR), (EMAIL, _RX_EMAIL), (PAN, _RX_PAN)):
        if sum(1 for v in vals if rx.match(v)) >= 0.6 * n:
            return role
    if sum(1 for v in vals if _RX_ADDRESS.search(v)) >= 0.5 * n:
        return ADDRESS
    return None


_RX_ADDRESS = re.compile(r"H\.?\s?No\.?\s*\d|House\s*(?:No\.?)?\s*\d|Makan\s*(?:No\.?)?\s*\d|Mohalla\s|Tehsil\s|"
                         r"Distt\.?\s|मकान\s*नं|मोहल्ला|तहसील|जिला", re.I)
_RX_IDLIKE = re.compile(r"^\s*[A-Z]{1,8}[-/:._ ]?\d{2,}(?:[-/:._ ]?\d+)*\s*$")
_ID_HEADER_WORDS = ("no", "number", "id", "code", "ref", "regn", "hosp", "mr", "mrn", "card")
_NOT_PATIENT_ID_HEADER = ("sample", "bill", "invoice", "visit", "trip", "ticket", "order", "test", "package",
                          "claim", "receipt", "token", "serial", "item", "batch", "lot", "bed", "ward", "room",
                          "loinc", "icd", "code")


def profile_id_column(header: str, values: list[str]) -> bool:
    """An unrecognised header that reads like an identifier column ('Hospital No', 'hosp_no', 'Regn #')
    and whose values are mostly letter-prefixed codes is a patient ID column."""
    h = norm_header(header)
    if not any(_has(h, w) for w in _ID_HEADER_WORDS) and "#" not in header:
        return False
    if any(_has(h, w) for w in _NOT_PATIENT_ID_HEADER):
        return False
    vals = [v for v in values if v and v.strip()]
    return bool(vals) and sum(1 for v in vals if _RX_IDLIKE.match(v)) >= 0.8 * len(vals)


# ---------------------------------------------------------------------------------------- JSON keys
_NAME_KEYS = {"name", "first", "last", "given", "family", "local", "full_name", "fullname", "first_name",
              "last_name", "firstname", "lastname", "surname", "patient_name", "patientname", "naam"}
_RELATIVE_CONTEXT = {"guardian", "relative", "contact", "attendant", "mother", "father", "spouse", "husband",
                     "wife", "kin", "nok", "next_of_kin", "emergency", "parent", "informant", "witness"}
_NON_PERSON_CONTEXT = {"facility", "hospital", "lab", "laboratory", "organization", "organisation", "panel",
                       "panels", "test", "tests", "drug", "drugs", "medication", "medicine", "rx", "department",
                       "ward", "system", "form", "category", "package", "procedure", "coding", "code", "type",
                       "unit", "results", "practitioner", "doctor", "author", "performer", "location",
                       "serviceprovider", "insurer", "payer", "diagnosis", "condition", "observation",
                       "medicationcodeableconcept", "dosageinstruction", "qualification", "relationship",
                       "class", "section", "_export_meta", "meta", "schema"}
_PERSON_RESOURCES = {"Patient", "RelatedPerson", "Person"}
_NON_PERSON_RESOURCES = {"Practitioner", "PractitionerRole", "Organization", "Location", "Medication",
                         "HealthcareService", "Device", "Endpoint"}


def classify_json_path(keys: list[str], resource: str | None) -> str:
    """keys: the object keys from the root to this leaf (array indices removed)."""
    return _classify_json_path(tuple(keys), resource)


@lru_cache(maxsize=65536)
def _classify_json_path(keys: tuple, resource: str | None) -> str:
    keys = list(keys)
    if not keys:
        return TEXT
    leaf = keys[-1]
    low = [k.lower() for k in keys]
    leaf_l = low[-1]
    parent = low[-2] if len(low) > 1 else ""
    anc = set(low[:-1])

    # ---- FHIR element semantics
    if resource:
        if resource in _NON_PERSON_RESOURCES:
            return TEXT if leaf_l in ("div", "data") else KEEP
        if leaf_l == "div":
            return TEXT
        if parent == "telecom" and leaf_l == "value":
            return PHONE
        if parent == "identifier" and leaf_l == "value":
            if resource in _PERSON_RESOURCES:
                return ID_PRIMARY
            if resource == "Bundle":
                return KEEP
            return ID_OTHER
        if leaf_l == "birthdate":
            return DOB
        if parent == "address" or "address" in anc:
            return {"line": ADDRESS, "text": ADDRESS, "city": VILLAGE, "postalcode": PIN, "district": DISTRICT,
                    "state": STATE, "country": STATE}.get(leaf_l, TEXT)
        if leaf_l in ("display",) and parent in ("subject", "patient", "beneficiary", "individual", "for"):
            return NAME
        if "name" in anc or leaf_l == "name":
            if "contact" in anc or resource == "RelatedPerson":
                return RELATIVE
            if resource in _PERSON_RESOURCES:
                return NAME
        if leaf_l == "valuestring" and "extension" in anc:
            return TEXT
        if leaf_l in ("display", "text", "title", "code", "system", "url", "status", "reference", "fullurl", "id"):
            return KEEP if leaf_l not in ("text", "title") else TEXT
        return TEXT

    # ---- generic JSON
    if leaf_l in _NAME_KEYS or (leaf_l == "text" and parent == "name"):
        if anc & _NON_PERSON_CONTEXT and not (anc & {"patient", "patients", "raised_by", "person"}):
            return KEEP
        if anc & _RELATIVE_CONTEXT:
            return RELATIVE
        return NAME
    if leaf_l in ("relation", "relationship"):
        return RELATION
    role = classify_header(leaf)
    if role == NAME and anc & _NON_PERSON_CONTEXT:
        return KEEP
    if role == TEXT and parent and anc & _RELATIVE_CONTEXT and leaf_l in ("name", "display"):
        return RELATIVE
    return role
