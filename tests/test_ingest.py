"""M0 tests: ingestion safety, decoding, locators, pseudonyms. Synthetic fixtures only.

Run: python -m unittest discover -s tests
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("RAKSHA_SECRET", "unit-test-secret")

from rakshak.formats import json_doc  # noqa: E402
from rakshak.io.decode import decode  # noqa: E402
from rakshak.io.sniff import Quarantine, json_depth_exceeds, sniff  # noqa: E402
from rakshak.link.pseudonym import PseudonymIssuer  # noqa: E402


class DecodeTests(unittest.TestCase):
    def test_utf8_bom_utf16_cp1252(self):
        text = "Naam,Gaon\nटेस्ट,गाँव\n"
        self.assertEqual(decode(("﻿" + text).encode("utf-8"))[0], text)
        self.assertEqual(decode(text.encode("utf-16"))[0], text)
        self.assertEqual(decode("Temp 101.2°F – ok".encode("cp1252"))[0], "Temp 101.2°F – ok")

    def test_mojibake_refused(self):
        self.assertIsNone(decode(b"OPD note \xff\xfe\xc3( more")[0])


class SniffTests(unittest.TestCase):
    def check(self, ext, raw, reason):
        with self.assertRaises(Quarantine) as cm:
            sniff(ext, raw)
        self.assertEqual(cm.exception.reason, reason)

    def test_quarantine_reasons(self):
        self.check(".csv", b"", "empty_file")
        self.check(".pdf", b"%PDF-1.4 ...", "unsupported_format")
        self.check(".json", b"%PDF-1.4 ...", "unsupported_format")
        self.check(".jpg", b"\xff\xd8\xff\xe0", "unsupported_format")
        self.check(".xml", b"<?xml version='1.0'?><a/>", "unsupported_format")
        self.check(".csv", b'{"a": 1}', "format_mismatch")
        self.check(".dat", b"hello", "unsupported_format")

    def test_supported(self):
        self.assertEqual(sniff(".TSV", b"a\tb\n"), "tsv")
        self.assertEqual(sniff(".txt", b"note"), "text")

    def test_depth(self):
        deep = '{"l":' * 1500 + "1" + "}" * 1500
        self.assertTrue(json_depth_exceeds(deep, 200))
        self.assertFalse(json_depth_exceeds('{"a": "[[[[[[[[[["}', 3))


class LocatorTests(unittest.TestCase):
    def test_pointers(self):
        self.assertEqual(json_doc.record_pointers({"meta": {}, "visits": [{}, {}]}), ["/visits/0", "/visits/1"])
        self.assertEqual(json_doc.record_pointers({"resourceType": "Bundle", "entry": [{}]}), ["doc"])
        self.assertEqual(json_doc.record_pointers({"a/b": [{}]}), ["/a~1b/0"])
        self.assertEqual(json_doc.record_pointers({"name": "x"}), ["doc"])


class PseudonymTests(unittest.TestCase):
    def test_stable_and_format(self):
        a, b = PseudonymIssuer(), PseudonymIssuer()
        self.assertEqual(a.get("k1"), b.get("k1"))
        self.assertRegex(a.get("k1"), r"^PSN-[0-9A-HJKMNP-TV-Z]{8}$")
        self.assertNotEqual(a.get("k1"), a.get("k2"))


class EndToEndTests(unittest.TestCase):
    def test_contract_and_fail_safe(self):
        with tempfile.TemporaryDirectory() as tmp:
            inp, out = Path(tmp, "in"), Path(tmp, "out")
            (inp / "reg").mkdir(parents=True)
            (inp / "reg" / "a.csv").write_text("id,phone\nX1,9876543210\n", encoding="utf-8")
            (inp / "reg" / "b.json").write_text('{"v": [', encoding="utf-8")
            (inp / "reg" / "c.pdf").write_bytes(b"%PDF-1.4")
            env = dict(os.environ, RAKSHA_SECRET="e2e-secret")
            p = subprocess.run([sys.executable, str(ROOT / "main.py"), "--input", str(inp), "--output", str(out)],
                               env=env, capture_output=True, text=True)
            self.assertEqual(p.returncode, 0)
            self.assertNotIn("9876543210", p.stdout + p.stderr)
            report = json.loads((out / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["counts"]["files_total"], 3)
            self.assertEqual(report["counts"]["files_quarantined"], 2)
            self.assertFalse((out / "sanitized" / "reg" / "c.pdf").exists())
            self.assertNotIn("9876543210", (out / "sanitized" / "reg" / "a.csv").read_text(encoding="utf-8"))

    def test_missing_secret_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {k: v for k, v in os.environ.items() if k != "RAKSHA_SECRET"}
            p = subprocess.run([sys.executable, str(ROOT / "main.py"), "--input", tmp, "--output", str(Path(tmp, "o"))],
                               env=env, capture_output=True, text=True)
            self.assertEqual(p.returncode, 2)
            self.assertFalse(Path(tmp, "o").exists())


if __name__ == "__main__":
    unittest.main()
