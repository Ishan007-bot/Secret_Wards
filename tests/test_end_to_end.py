"""End-to-end and privacy-layer tests (Master Plan section 7A). Synthetic fixtures written for these
tests only: no organiser practice names or identifiers (enforced by tools/audit_repo.py).

Run: python -m unittest discover -s tests
"""
import base64
import hashlib
import json
import os
import random
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("RAKSHA_SECRET", "unit-test-secret")

from rakshak.detect.engine import Engine, _generalise_address  # noqa: E402
from rakshak.formats import fhir  # noqa: E402
from rakshak.ml.tagger import Tagger  # noqa: E402

REG = ("Patient Name,Gender,Age,DOB,Father/Husband,Mobile,Village,Tehsil,District,PIN,Aadhaar,UHID,Reg Date\n"
       "Tejasvi Halder,F,46,03/07/1979,Ojas Halder,9876501234,Kesharganj,Bilgram,Hardoi,241001,4321 8765 2109,KGH/31/556677,04/02/2026\n"
       "Bhuvan Rathi,M,33,21/11/1992,Charan Rathi,8899001122,Amargarh,Sandila,Hardoi,241204,5432 1098 7654,KGH/31/556678,06/02/2026\n")
NOTE = ("DISCHARGE SUMMARY\nPatient: Tejasvi Halder   UHID: KGH/31/556677\nW/o Ojas Halder, Mob 98765-01234\n"
        "Date of Admission: 07/02/2026\nDate of Discharge: 19/02/2026\nK/C/O hypertension. C/O fever for 6 days.\n"
        "Tab Amlodipine 5 mg 0-0-1. Dr. Ojas Mehrotra reviewed the patient. Referred by ASHA worker.\n"
        "Visitor: Nirupama Kandula (attendant, bed 12), mob 9012345678\n")
FHIR = {"resourceType": "Bundle", "id": "b1", "type": "document", "timestamp": "2026-02-19T10:00:00+05:30",
        "entry": [{"fullUrl": "urn:uuid:11111111-2222-3333-4444-555555555555",
                   "resource": {"resourceType": "Patient", "id": "11111111-2222-3333-4444-555555555555",
                                "name": [{"use": "official", "text": "Tejasvi Halder", "prefix": ["Smt."]}],
                                "gender": "female", "birthDate": "1979-07-03",
                                "identifier": [{"system": "urn:kgh", "value": "KGH/31/556677"}],
                                "address": [{"line": ["H.No. 41, Mohalla Teliyan"], "city": "Kesharganj",
                                             "district": "Hardoi", "postalCode": "241001",
                                             "extension": [{"url": "latitude", "valueDecimal": 27.39127},
                                                           {"url": "longitude", "valueDecimal": 80.13114}]}]}},
                  {"fullUrl": "urn:uuid:99999999-2222-3333-4444-555555555555",
                   "resource": {"resourceType": "Encounter", "id": "99999999-2222-3333-4444-555555555555",
                                "status": "finished", "class": {"code": "IMP"},
                                "subject": {"reference": "urn:uuid:11111111-2222-3333-4444-555555555555",
                                            "display": "Tejasvi Halder"},
                                "period": {"start": "2026-02-07", "end": "2026-02-19"}}}]}


def tree_hash(p: Path) -> str:
    h = hashlib.sha256()
    for f in sorted(p.rglob("*")):
        if f.is_file():
            h.update(str(f.relative_to(p)).encode())
            h.update(f.read_bytes())
    return h.hexdigest()


class Pipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        inp = cls.tmp / "in"
        (inp / "registration").mkdir(parents=True)
        (inp / "notes").mkdir()
        (inp / "fhir").mkdir()
        (inp / "registration" / "reg.csv").write_text(REG, encoding="utf-8")
        (inp / "notes" / "Discharge_Tejasvi_Halder_KGH-31-556677.txt").write_text(NOTE, encoding="utf-8")
        (inp / "fhir" / "bundle.json").write_text(json.dumps(FHIR, indent=2), encoding="utf-8")
        (inp / "notes" / "scan.pdf").write_bytes(b"%PDF-1.4 Tejasvi Halder 9876501234")
        (inp / "notes" / "empty.txt").write_bytes(b"")
        rnd = random.Random(5)
        (inp / "notes" / "noise.bin.txt").write_bytes(bytes(rnd.randrange(256) for _ in range(4096)))
        cls.inp = inp
        cls.before = tree_hash(inp)
        cls.outs = {}
        for tag, secret in (("a", "secret-one"), ("b", "secret-one"), ("c", "secret-two")):
            out = cls.tmp / f"out_{tag}"
            env = dict(os.environ, RAKSHA_SECRET=secret)
            r = subprocess.run([sys.executable, str(ROOT / "main.py"), "--input", str(inp), "--output", str(out)],
                               env=env, capture_output=True, text=True, encoding="utf-8")
            cls.outs[tag] = (out, r)

    def everything(self, tag="a"):
        out, r = self.outs[tag]
        parts = [r.stdout, r.stderr]
        for f in out.rglob("*"):
            parts.append(f.name)
            if f.is_file():
                parts.append(f.read_bytes().decode("utf-8", "replace"))
        return "\n".join(parts)

    def test_exit_and_report(self):                                     # T-DS-05, T-IN-03
        out, r = self.outs["a"]
        self.assertEqual(r.returncode, 0, r.stderr)
        rep = json.loads((out / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(rep["counts"]["files_total"], 6)
        self.assertEqual(len(rep["files"]), 6)
        exported = sum(1 for e in rep["files"] if e["output"] and (out / e["output"]).is_file())
        self.assertEqual(rep["counts"]["files_sanitized"], exported)

    def test_no_pii_anywhere(self):                                     # T-DS-03, T-NM-05
        blob = self.everything()
        for v in ("Tejasvi", "Halder", "Bhuvan", "Nirupama", "Kandula", "9876501234", "98765-01234", "556677",
                  "4321 8765 2109", "Kesharganj", "Amargarh", "241001", "Teliyan", "secret-one", "1979-07-03"):
            self.assertNotIn(v, blob, v)

    def test_meaning_traps_kept(self):                                  # T-KP-*
        out, _ = self.outs["a"]
        note = next((out / "sanitized" / "notes").glob("*.txt")).read_text(encoding="utf-8")
        for keep in ("K/C/O hypertension", "C/O fever for 6 days", "Tab Amlodipine 5 mg 0-0-1",
                     "Dr. Ojas Mehrotra", "ASHA worker"):
            self.assertIn(keep, note)

    def test_input_untouched_and_no_raw_copy(self):                     # T-IN-09, T-IN-06
        self.assertEqual(tree_hash(self.inp), self.before)
        out, _ = self.outs["a"]
        for f in (out / "sanitized").rglob("*"):
            if f.is_file():
                self.assertNotEqual(f.read_bytes(), (self.inp / "notes" / "scan.pdf").read_bytes())

    def test_deterministic_and_secret_dependent(self):                  # T-DS-01, T-DS-02, A7
        a, _ = self.outs["a"]
        b, _ = self.outs["b"]
        c, _ = self.outs["c"]
        self.assertEqual(tree_hash(a / "sanitized"), tree_hash(b / "sanitized"))
        self.assertEqual((a / "records.jsonl").read_bytes(), (b / "records.jsonl").read_bytes())
        pa = {json.loads(l)["patient"] for l in (a / "records.jsonl").read_text(encoding="utf-8").splitlines()} - {None}
        pc = {json.loads(l)["patient"] for l in (c / "records.jsonl").read_text(encoding="utf-8").splitlines()} - {None}
        self.assertTrue(pa and pc and not (pa & pc))

    def test_linked_and_pseudonym_inside_records(self):                 # T-LK-01, pseudonym consistency
        out, _ = self.outs["a"]
        recs = [json.loads(l) for l in (out / "records.jsonl").read_text(encoding="utf-8").splitlines()]
        reg0 = next(r for r in recs if r["file"].endswith("reg.csv") and r["loc"] == "row:0")
        note = next(r for r in recs if "notes/" in r["file"] and r["file"].endswith(".txt") and r["patient"])
        self.assertEqual(reg0["patient"], note["patient"])
        self.assertIn(note["patient"], (out / note["file"]).read_text(encoding="utf-8"))
        bund = next(r for r in recs if r["file"].endswith("bundle.json") and r["patient"])
        self.assertEqual(bund["patient"], reg0["patient"])

    def test_interval_preserved_and_dates_shifted(self):                # T-PV-01
        out, _ = self.outs["a"]
        note = next((out / "sanitized" / "notes").glob("*.txt")).read_text(encoding="utf-8")
        import re
        import datetime as dt
        a = re.search(r"Admission: (\d\d)/(\d\d)/(\d{4})", note)
        d = re.search(r"Discharge: (\d\d)/(\d\d)/(\d{4})", note)
        da = dt.date(int(a.group(3)), int(a.group(2)), int(a.group(1)))
        dd = dt.date(int(d.group(3)), int(d.group(2)), int(d.group(1)))
        self.assertEqual((dd - da).days, 12)
        self.assertNotEqual(da, dt.date(2026, 2, 7))

    def test_fhir_valid_and_generalised(self):                          # T-DS-06, T-PV-05/06
        out, _ = self.outs["a"]
        b = json.loads((out / "sanitized" / "fhir" / "bundle.json").read_text(encoding="utf-8"))
        self.assertEqual(fhir.problems(b), [])
        pat = b["entry"][0]["resource"]
        self.assertNotIn("birthDate", pat)                              # dob_mode: remove (valid R4)
        self.assertEqual(pat["name"][0]["use"], "official")
        self.assertEqual(pat["address"][0]["district"], "Hardoi")       # district kept
        self.assertEqual(pat["address"][0]["postalCode"], "241***")
        self.assertEqual(pat["address"][0]["extension"][0]["valueDecimal"], 27.4)
        enc = b["entry"][1]["resource"]["period"]
        import datetime as dt
        self.assertEqual((dt.date.fromisoformat(enc["end"]) - dt.date.fromisoformat(enc["start"])).days, 12)

    def test_registration_generalised(self):                            # T-PV-04/05/06
        out, _ = self.outs["a"]
        import csv
        import io
        rows = list(csv.DictReader(io.StringIO((out / "sanitized" / "registration" / "reg.csv").read_text(encoding="utf-8"))))
        r = rows[0]
        lo, hi = map(int, r["Age"].split("-"))
        self.assertTrue(lo <= 46 <= hi)
        self.assertEqual(r["DOB"], "[DOB]")
        self.assertEqual(r["Village"], "Hardoi")                        # village -> district
        self.assertEqual(r["Tehsil"], "Hardoi")                         # tehsil -> district
        self.assertEqual(r["PIN"], "241***")

    def test_filename_renamed(self):                                    # T-HC-01
        out, _ = self.outs["a"]
        names = [p.name for p in (out / "sanitized" / "notes").glob("*")]
        self.assertTrue(names and not any("Tejasvi" in n or "556677" in n for n in names))

    def test_pseudonym_not_reversible(self):                            # T-PV-08 (A6)
        out, _ = self.outs["a"]
        recs = [json.loads(l) for l in (out / "records.jsonl").read_text(encoding="utf-8").splitlines()]
        psn = next(r["patient"] for r in recs if r["patient"])
        core = psn.split("-", 1)[1].lower()
        for v in ("KGH/31/556677", "9876501234", "432187652109", "Tejasvi Halder"):
            for h in (hashlib.md5, hashlib.sha1, hashlib.sha256):
                self.assertFalse(h(v.encode()).hexdigest().startswith(core))
            self.assertNotIn(core, base64.b64encode(v.encode()).decode().lower())


class Units(unittest.TestCase):
    def test_address_generalisation(self):
        self.assertEqual(_generalise_address("Lucknow, Uttar Pradesh"), "Lucknow, Uttar Pradesh")
        self.assertEqual(_generalise_address("H.No. 9, Gram Kesharganj, Jila Hardoi - 241001"),
                         "[ADDRESS], Jila Hardoi - 241***")

    def test_honorific_absorbed(self):
        e = Engine()
        e.vault.add_name("Ojas Halder", "RELATIVE")
        out = e.clean("[08/09/26, 9:32 pm] Ojas Bhaiya: report bhej diya")
        self.assertNotIn("Bhaiya", out)
        self.assertNotIn("Ojas", out)

    def test_fhir_validator_catches_breakage(self):
        bad = json.loads(json.dumps(FHIR))
        bad["entry"][0]["resource"]["birthDate"] = "[DOB]"
        bad["entry"][1]["resource"]["subject"]["reference"] = "urn:uuid:missing"
        self.assertIn("bad_date_birthDate", fhir.problems(bad))
        self.assertIn("unresolved_reference", fhir.problems(bad))
        self.assertEqual(fhir.problems(FHIR), [])

    def test_tagger_missing_model_falls_back(self):                     # 13A.5
        t = Tagger(Path(tempfile.mkdtemp()) / "missing.json")
        self.assertFalse(t.ok)
        self.assertEqual(t.spans("Called by Somebody Unknown at night, mob 9000000000"), [])

    def test_tagger_finds_unseen_name(self):
        t = Tagger()
        if not t.ok:
            self.skipTest("model not present")
        txt = "Visitor log: 18:40 - Brindavan Kothapalli (attendant, bed 12) came to see the patient."
        spans = t.spans(txt)
        self.assertTrue(any(txt[s:e] == "Brindavan Kothapalli" for s, e, _, _ in spans))

    def test_uuid_digits_not_identifiers(self):
        from rakshak.detect.vault import Vault
        from rakshak.secure.egress import find_leaks
        v = Vault()
        v.add_id("c8e60506-bdf8-1cb7-8ffa-b79df5451c67", "MRN")
        self.assertEqual(find_leaks('{"reference": "urn:uuid:c8e60506-bdf8-1cb7-0000-000000000001"}', v), 0)


if __name__ == "__main__":
    unittest.main()


class ForcedFailure(unittest.TestCase):                                 # T-DS-04
    def test_exception_quarantines_file_and_leaks_nothing(self):
        import contextlib
        import io
        from rakshak import cli
        from rakshak.process import Processor
        tmp = Path(tempfile.mkdtemp())
        (tmp / "in").mkdir()
        (tmp / "in" / "a.txt").write_text("Patient: Tejasvi Halder, BP 120/80\n", encoding="utf-8")
        (tmp / "in" / "b.txt").write_text("Routine note, BP 118/76\n", encoding="utf-8")
        orig = Processor.text_rewrite

        def boom(self, text, rec=None):
            if "Tejasvi" in text:
                raise ValueError("cannot handle Tejasvi Halder 9876501234")
            return orig(self, text, rec)
        Processor.text_rewrite = boom
        err, out = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
                cli.run(tmp / "in", tmp / "out")
        finally:
            Processor.text_rewrite = orig
        rep = json.loads((tmp / "out" / "report.json").read_text(encoding="utf-8"))
        status = sorted(e["status"] for e in rep["files"])
        self.assertEqual(status, ["quarantined", "sanitized"])
        reasons = [e.get("reason") for e in rep["files"] if e["status"] == "quarantined"]
        self.assertEqual(reasons, ["process_error_valueerror"])
        blob = err.getvalue() + out.getvalue() + json.dumps(rep)
        self.assertNotIn("Tejasvi", blob)
        self.assertNotIn("9876501234", blob)
        self.assertFalse((tmp / "out" / "sanitized" / "a.txt").exists())


class UnseenFormatHardening(unittest.TestCase):
    """Regression tests for the unseen-format hardening (synthetic strings only)."""

    def test_identifier_and_name_forms(self):
        e = Engine()
        cases = {"ph. 98765.43210": "98765.43210", "Tel: (0522) 2345678": "2345678",
                 "Reg No. 2031/OPD/00456": "00456", "IP No 31/1234": "1234",
                 "Policy no. HDFC/2031/778812": "778812", "Name: KHANNA, TEJAS": "TEJAS",
                 "Smt. Kamla Rathi w/o Late Shri Ramdin": "Kamla", "Husband - Vinod Kumar Gupta": "Vinod",
                 "Relative contacted: Sneha D'Souza": "Souza"}
        for text, gone in cases.items():
            self.assertNotIn(gone, e.clean(text), text)
        for keep in ("Ref range 70-140 mg/dL", "Bill No: 445566", "Ward 4 (Medicine)", "Shri Ram Hospital, Lucknow",
                     "Late onset diabetes", "hospital opd 2026 02 json", "Referred by ASHA worker of the village.",
                     "of the village. TDS 0-0-1", "ICD-10 E11.9", "Son: 2 children"):
            self.assertEqual(e.clean(keep), keep, keep)

    def test_possessive_still_matches_vault(self):
        e = Engine()
        e.vault.add_name("Tejasvi Rathi", "PATIENT")
        self.assertNotIn("Tejasvi", e.clean("Sample received from Tejasvi's attendant."))

    def test_relative_name_stops_at_sentence_end(self):
        e = Engine()
        self.assertEqual(e.clean("C/O Ravi Kumar. ICD-10 E11.9"), "C/O [RELATIVE]. ICD-10 E11.9")

    def test_date_formats_shifted_and_kept(self):
        from rakshak.privacy.dates import shift_all
        self.assertEqual(shift_all("1977/04/12", 10, False), "1977/04/22")
        self.assertEqual(shift_all("1977.04.12", 10, False), "1977.04.22")
        self.assertEqual(shift_all("12th April 1977", 10, False), "22nd April 1977")
        self.assertEqual(shift_all("Apr 12 1977", 10, False), "Apr 22 1977")
        self.assertEqual(shift_all("12 अप्रैल 1977", 10, False), "22 अप्रैल 1977")

    def test_hex_and_base64_payloads(self):
        from rakshak.process import Processor
        p = Processor(Engine())
        hx = "Patient Tejasvi Rathi phone 9876501234".encode().hex()
        b64 = base64.b64encode("Patient Tejasvi Rathi phone 9876501234".encode()).decode()
        text = f"hex {hx}\nb64 {b64}\nuuid 3f2a9c1e-1111-2222-3333-444444444444"
        p.text_harvest(text)
        out = p.text_rewrite(text)
        import re
        dec = bytes.fromhex(re.search(r"hex ([0-9a-f]+)", out).group(1)).decode()
        dec += base64.b64decode(re.search(r"b64 (\S+)", out).group(1)).decode()
        self.assertNotIn("Tejasvi", dec)
        self.assertNotIn("9876501234", dec)
        self.assertIn("3f2a9c1e-1111-2222-3333-444444444444", out)

    def test_delimiters_formats_and_shared_documents(self):
        tmp = Path(tempfile.mkdtemp())
        inp = tmp / "in"
        inp.mkdir()
        (inp / "semi.csv").write_text("Patient Name;Mobile;Village\nKeshav Rathi;9876543210;Daulatganj\n"
                                      "Nirmala Joshi;8765432109;Kesharganj\n", encoding="utf-8")
        (inp / "piped.psv").write_text("Naam|Phone\nKeshav Rathi|9876543210\n", encoding="utf-8")
        (inp / "visits.json").write_text('{"patient": "Keshav Rathi", "phone": "9876543210"}\n'
                                         '{"patient": "Nirmala Joshi", "phone": "8765432109"}\n', encoding="utf-8")
        (inp / "desk.log").write_text("called by Keshav Rathi 9876543210\n", encoding="utf-8")
        env = dict(os.environ, RAKSHA_SECRET="fmt-secret")
        r = subprocess.run([sys.executable, str(ROOT / "main.py"), "--input", str(inp), "--output", str(tmp / "out")],
                           env=env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        rep = json.loads((tmp / "out" / "report.json").read_text(encoding="utf-8"))
        self.assertTrue(all(e["status"] == "sanitized" for e in rep["files"]))
        semi = (tmp / "out" / "sanitized" / "semi.csv").read_text(encoding="utf-8")
        self.assertTrue(semi.startswith("Patient Name;Mobile;Village"))
        blob = "".join(p.read_text(encoding="utf-8") for p in (tmp / "out" / "sanitized").iterdir())
        for v in ("Keshav", "Nirmala", "9876543210", "Daulatganj"):
            self.assertNotIn(v, blob)
        lines = (tmp / "out" / "sanitized" / "visits.json").read_text(encoding="utf-8").splitlines()
        psn = [json.loads(l)["patient"] for l in lines]
        self.assertNotEqual(psn[0], psn[1])          # two people in one file never share a pseudonym
