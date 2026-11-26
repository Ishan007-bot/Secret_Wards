"""Detection tests (plan §7A: T-ID, T-NM, T-KP, T-HC). Synthetic fixtures only: invented names/IDs."""
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("RAKSHA_SECRET", "unit-test-secret")

from rakshak.detect import columns as C  # noqa: E402
from rakshak.detect.engine import Engine  # noqa: E402
from rakshak.detect.hidden import decode_b64_text, encode_b64_text  # noqa: E402
from rakshak.process import Processor  # noqa: E402


def engine_with_vault():
    e = Engine()
    v = e.vault
    v.add_name("Tarini Moolchand", "PATIENT")
    v.add_name("Hemraj Moolchand", "RELATIVE")
    v.add_name("तारिणी मूलचंद", "PATIENT")
    v.add_id("KVH/27/551234")
    v.add_id("IPD-2027-00777")
    v.add_digits("+91 98111 22334", "PHONE")
    v.add_text("Mohalla Kesar Bagh", "ADDRESS")
    v.add_text("Bhimsar Kalan", "VILLAGE")
    return e


class IdentifierTests(unittest.TestCase):  # T-ID
    def gone(self, text, *secrets):
        out = Engine().clean(text)
        for s in secrets:
            self.assertNotIn(s, out, msg=out)
        return out

    def test_phones(self):
        for p in ["+91 72864 90658", "+91-8099123456", "75600-10034", "060062-72163", "8077712345",
                  "6012398745", "७५६००१००३४"]:
            self.gone(f"Mob: {p}", p)

    def test_aadhaar_abha_pan_email_insurance(self):
        self.gone("Aadhaar 8799 6191 4045", "8799 6191 4045")
        self.gone("uid 5185-9480-8328", "5185-9480-8328")
        self.gone("XXXX XXXX 5866", "5866")
        self.gone("ABHA 91-7938-3729-8403", "91-7938-3729-8403")
        self.gone("PAN QWRTY9876K ok", "QWRTY9876K")
        self.gone("mail a.b9@example.com", "a.b9@example.com")
        self.gone("PMJAY-UP-5566778899", "5566778899")
        self.gone("POL/41/90817263", "90817263")

    def test_learned_id_shapes_and_cores(self):
        e = engine_with_vault()
        for t, s in [("ref KVH-27-551234 seen", "551234"), ("file kvh_27_551234.txt", "551234"),
                     ("path D:\\exp\\Tarini_Moolchand_551234\\x.json", "551234"),
                     ("IPD No: IPD-2027-00777", "00777")]:
            self.assertNotIn(s, e.clean(t), msg=t)

    def test_unseen_id_label(self):
        e = Engine()
        e.harvest_text("UHID: QZR:2031:004455")
        self.assertNotIn("004455", e.clean("seen again as QZR-2031-004455 today"))


class NameTests(unittest.TestCase):  # T-NM
    def test_vault_variants(self):
        e = engine_with_vault()
        for t in ["TARINI MOOLCHAND admitted", "Moolchand Tarini", "Tarini ji ka BP 120/80", "Tarini_Moolchand",
                  "नाम: तारिणी मूलचंद", "Attendant: Hemraj, Mob. 9811122334"]:
            out = e.clean(t)
            for s in ("Tarini", "TARINI", "Hemraj", "तारिणी", "9811122334"):
                self.assertNotIn(s, out, msg=out)

    def test_labels_without_vault(self):
        e = Engine()
        self.assertNotIn("Zoravar", e.clean("Patient Name: Zoravar Teklu        Age/Sex: 52 Yrs/F"))
        self.assertNotIn("Ilango", e.clean("W/o Ilango Perumal\nAddress: x"))
        self.assertNotIn("Perumal", e.clean("C/O Ilango Perumal, H.No. 77"))
        self.assertNotIn("Kolappan", e.clean("called by Vardhini Kolappan 94054-71434"))
        self.assertNotIn("Tirkey", e.clean("18:40 - Ekansh Tirkey (attendant, bed 12), mob 6987001122"))
        self.assertNotIn("Ngurthansanga", e.clean("Visitor Ngurthansanga Hmar came at 18:00, mob 9612233445"))

    def test_relation_does_not_cross_lines(self):
        e = Engine()
        e.harvest_text("W/o Naseem\nAddress: Makan No. 1")
        self.assertNotIn("address", e.vault.name_tokens)


class MeaningTrapTests(unittest.TestCase):  # T-KP
    KEEP = ["Dr. Hemant Srivastava reviewed the patient.", "C/O fever for 6 days", "C/O pain abdomen x 7 days",
            "1-0-1", "Dolo 650 BD x 5 days", "Ramipril 5 mg", "450 mg + 300 mg", "K/C/O addison's disease",
            "K/C/O DM2 x 9 yrs", "H/O TB 8 yrs back", "Parkinson's disease", "Bell's palsy",
            "Ward 4 (Medicine) / Bed 29", "Referred by ASHA worker of the village", "BP 128/85 mmHg",
            "SpO2 97%", "Haemoglobin 8.2 g/dL", "Total WBC Count 13000 /uL", "N39.0", "718-7"]

    def test_clinical_text_survives(self):
        e = engine_with_vault()
        e.vault.add_name("Ramesh Kumar", "RELATIVE")  # a relative sharing the doctor's first name
        for t in self.KEEP:
            self.assertEqual(e.clean(t), t)

    def test_doctor_kept_relative_removed(self):
        e = engine_with_vault()
        e.vault.add_name("Hemant Kujur", "RELATIVE")
        out = e.clean("Attendant: Hemant Kujur. Dr. Hemant Srivastava reviewed the patient.")
        self.assertIn("Dr. Hemant Srivastava", out)
        self.assertNotIn("Yadav", out)

    def test_age_band_truthful(self):
        e = Engine()
        self.assertIn("50-59 Yrs/F", e.clean("Age/Sex: 52 Yrs/F"))
        self.assertIn("30-39 वर्ष", e.clean("आयु: 39 वर्ष"))
        self.assertIn("85+", e.clean("Age: 96"))
        self.assertIn("x 12 yrs", e.clean("K/C/O DM2 x 12 yrs"))  # durations are not ages


class HiddenChannelTests(unittest.TestCase):  # T-HC
    def test_base64_roundtrip(self):
        e = engine_with_vault()
        p = Processor(e)
        payload = encode_b64_text("Referral: Tarini Moolchand (KVH/27/551234), mobile 9811122334.")
        out = p.rewrite(C.TEXT, payload)
        text = decode_b64_text(out)
        self.assertIsNotNone(text)
        for s in ("Tarini", "551234", "9811122334"):
            self.assertNotIn(s, text)

    def test_json_keys_no_collision(self):
        e = engine_with_vault()
        e.vault.add_name("Ojas Brahmbhatt")
        p = Processor(e)
        out = p.json_rewrite({"by_name": {"Tarini Moolchand": "KVH/27/551234", "Ojas Brahmbhatt": "x"}})
        self.assertEqual(len(out["by_name"]), 2)
        self.assertNotIn("Tarini", str(out))

    def test_filename_detection(self):
        e = engine_with_vault()
        p = Processor(e)
        self.assertTrue(p.name_has_pii("discharge/Discharge_Summary_Tarini_Moolchand_KVH-27-551234.txt"))
        self.assertTrue(p.name_has_pii("lab/9811122334_report_0010.json"))
        self.assertTrue(p.name_has_pii("notes/nursing_ipd-2027-00777.txt"))
        self.assertFalse(p.name_has_pii("opd/hospital_opd_2026_02.json"))


class ColumnTests(unittest.TestCase):
    def test_headers(self):
        cases = {"Patient's Name": C.NAME, "Naam": C.NAME, "Pita/Pati ka Naam": C.RELATIVE, "Contact#": C.PHONE,
                 "Gram/Mohalla": C.VILLAGE, "Janm Tithi": C.DOB, "Umar": C.AGE, "Reg Date": C.DATE,
                 "Reg No": C.ID_PRIMARY, "payer_pan": C.PAN, "pmjay_id": C.INSURANCE, "ref_doctor": C.DOCTOR,
                 "Zip": C.PIN, "drug_name": C.TEXT, "age_sex": C.AGE_SEX, "Aadhar": C.AADHAAR}
        for h, role in cases.items():
            self.assertEqual(C.classify_header(h), role, msg=h)

    def test_unknown_column_after_relation_is_relative(self):
        p = Processor(Engine())
        rows = [["Rishta", "Jodidar"], ["W/o", "Velusamy Raman"], ["D/o", "Lalthanzara Ralte"]]
        out = p.csv_rewrite(rows)
        self.assertEqual(out[1], ["W/o", "[RELATIVE]"])
        self.assertEqual(C.classify_header("Rishtedar"), C.RELATIVE)

    def test_value_profile_overrides_unknown_header(self):
        self.assertEqual(C.profile_values(["9876543210", "+91 98765 43210", "", "7012345678"]), C.PHONE)


if __name__ == "__main__":
    unittest.main()
