"""Linkage, pseudonyms, dates and rare values (plan §7A: T-LK, T-PV). Synthetic fixtures only."""
import datetime as dt
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("RAKSHA_SECRET", "unit-test-secret")

from rakshak.link.linker import Evidence, Linker  # noqa: E402
from rakshak.link.translit import name_tokens, names_compatible, names_equal  # noqa: E402
from rakshak.privacy.dates import shift_all  # noqa: E402
from rakshak.privacy.rare import RareDx  # noqa: E402


def ev(rid, **kw):
    e = Evidence(rid=rid)
    for name in kw.pop("names", []):
        e.add_name(name)
    for name in kw.pop("weak", []):
        e.add_name(name, strong=False)
    for rel in kw.pop("rels", []):
        e.add_relative(rel)
    for k, v in kw.items():
        getattr(e, k).update(v)
    return e


class TranslitTests(unittest.TestCase):
    def test_cross_script_and_variants(self):
        for a, b in [("Mohammad Tahir", "मोहम्मद ताहिर"), ("Md. Tahir", "Mohammad Tahir"), ("Fatima Noor", "Fatma Noor"),
                     ("Reena Kol", "Rina Kol"), ("Tahir Mohammad", "Mohammad Tahir"), ("Gurleen Kaur", "गुरलीन कौर")]:
            self.assertTrue(names_equal(name_tokens(a), name_tokens(b)), (a, b))

    def test_different_people_not_compatible(self):
        for a, b in [("Sunita Kol", "Sunil Kol"), ("Rina Kol", "Rana Kol"), ("Asha Kol", "Usha Kol")]:
            self.assertFalse(names_compatible(name_tokens(a), name_tokens(b)), (a, b))


class LinkerTests(unittest.TestCase):
    def run_linker(self, evs):
        lk = Linker(evs)
        lk.link_strong()
        lk.link_name_clues()
        return lk.clusters()

    def test_strong_id_links_across_scripts(self):
        c = self.run_linker([ev("a", names=["Mohammad Tahir"], ids={"KVH27551234"}),
                             ev("b", names=["मोहम्मद ताहिर"], ids={"KVH27551234"}),
                             ev("c", weak=["Tahir"], ids={"KVH27551234"})])
        self.assertEqual(len({c["a"], c["b"], c["c"]}), 1)

    def test_homonyms_never_merged(self):
        c = self.run_linker([ev("a", names=["Harsh Vala"], ids={"X1001"}, dobs={"1965-11-25"}, ages={59}),
                             ev("b", names=["Harsh Vala"], ids={"X2002"}, dobs={"2005-01-10"}, ages={21}),
                             ev("c", names=["Harsh Vala"], ages={59})])
        self.assertNotEqual(c["a"], c["b"])

    def test_shared_phone_of_couple_not_merged(self):
        c = self.run_linker([ev("h", names=["Ravi Kol"], phones={"9811122334"}, genders={"M"}),
                             ev("w", names=["Meera Kol"], phones={"9811122334"}, genders={"F"})])
        self.assertNotEqual(c["h"], c["w"])

    def test_name_plus_relative_links_fragment(self):
        c = self.run_linker([ev("reg", names=["Meera Kol"], rels=["Rajan Kol"], ids={"X3003"}),
                             ev("frag", weak=["Meera"], rels=["Rajan"])])
        self.assertEqual(c["reg"], c["frag"])

    def test_ambiguous_fragment_left_alone(self):
        c = self.run_linker([ev("r1", names=["Meera Kol"], rels=["Rajan Kol"], ids={"X1"}, dobs={"1980-01-01"}),
                             ev("r2", names=["Meera Das"], rels=["Rajan Das"], ids={"X2"}, dobs={"1990-01-01"}),
                             ev("frag", weak=["Meera"], rels=["Rajan"])])
        self.assertNotIn(c["frag"], (c["r1"], c["r2"]))

    def test_conflicting_dob_blocks_merge(self):
        c = self.run_linker([ev("a", names=["Nisha Kol"], phones={"9000000001"}, dobs={"1990-01-01"}),
                             ev("b", names=["Nisha Kol"], phones={"9000000001"}, dobs={"1991-05-05"})])
        self.assertNotEqual(c["a"], c["b"])


class DateTests(unittest.TestCase):
    def test_interval_and_format_preserved(self):
        out = shift_all("Date of Admission: 07/02/2026\nDate of Discharge: 19/02/2026", 23, False)
        a, b = out.split("\n")
        da = dt.datetime.strptime(a.split(": ")[1], "%d/%m/%Y")
        db = dt.datetime.strptime(b.split(": ")[1], "%d/%m/%Y")
        self.assertEqual((db - da).days, 12)

    def test_formats(self):
        self.assertEqual(shift_all("01/13/2026 22:00", 10, True), "01/23/2026 22:00")
        self.assertEqual(shift_all("2026-04-21T17:15:00+05:30", 10, False), "2026-05-01T17:15:00+05:30")
        self.assertEqual(shift_all("[30/05/26, 9:32 pm]", 10, False), "[09/06/26, 9:32 pm]")
        self.assertEqual(shift_all("Visit: 5 September", 10, False), "Visit: 15 September")
        self.assertEqual(shift_all("१०/११/२०२६", 10, True), "१०/२१/२०२६")

    def test_clinical_numbers_untouched(self):
        t = "Haemoglobin 12.0-16.0, BP 112/78, 1-0-1, A15.0, 9:32, Dolo 650"
        self.assertEqual(shift_all(t, 40, False), t)


class RareTests(unittest.TestCase):
    def test_only_rare_records_coarsened(self):
        r = RareDx()
        r.observe_text("Diagnosis: Rabies, unspecified (A82.9); Typhoid fever (A01.0)")
        r.set_rare({"A82.9"})
        out, n = r.apply("Diagnosis: Rabies, unspecified (A82.9); Typhoid fever (A01.0)")
        self.assertNotIn("Rabies", out)
        self.assertNotIn("A82.9", out)
        self.assertIn("Typhoid fever (A01.0)", out)
        self.assertEqual(n, 2)


if __name__ == "__main__":
    unittest.main()
