#!/usr/bin/env python3
"""Builds docs/brief.pdf (2 pages, A4, >= 10 pt). Dev-only; needs `pip install reportlab`."""
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.graphics.shapes import Drawing, Rect, String, Line, Polygon
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

DEVA_FONT = "Helvetica"
for cand in ("C:/Windows/Fonts/Nirmala.ttc", "C:/Windows/Fonts/Nirmala.ttf", "C:/Windows/Fonts/mangal.ttf",
             "/usr/share/fonts/truetype/noto/NotoSansDevanagari-Regular.ttf"):
    if Path(cand).is_file():
        try:
            pdfmetrics.registerFont(TTFont("Deva", cand))
            DEVA_FONT = "Deva"
            break
        except Exception:  # noqa: BLE001
            pass


def dv(t):
    return f"<font name='{DEVA_FONT}'>{t}</font>"

OUT = Path(__file__).resolve().parent / "brief.pdf"
INK, ACC, MUTED, BG = colors.HexColor("#1b2430"), colors.HexColor("#0b6e4f"), colors.HexColor("#5b6670"), colors.HexColor("#eef5f1")

base = ParagraphStyle("b", fontName="Helvetica", fontSize=10, leading=12.4, textColor=INK, alignment=TA_LEFT,
                      spaceAfter=2.5)
small = ParagraphStyle("s", parent=base, fontSize=10, leading=12)
h1 = ParagraphStyle("h1", parent=base, fontName="Helvetica-Bold", fontSize=15.5, leading=18, textColor=INK, spaceAfter=1)
h2 = ParagraphStyle("h2", parent=base, fontName="Helvetica-Bold", fontSize=11.5, leading=14, textColor=ACC,
                    spaceBefore=4, spaceAfter=2)
meta = ParagraphStyle("m", parent=base, textColor=MUTED)


def P(t, st=base):
    return Paragraph(t, st)


def diagram(width):
    d = Drawing(width, 86)
    steps = [("P0 Ingest", "sniff · decode ·\nquarantine"), ("P1 Understand", "columns · keys ·\nidentity vault"),
             ("P2 Link", "evidence rules ·\nHMAC IDs"), ("P3 Privacy plan", "shifts · bands ·\ngeneralise"),
             ("P4 Rewrite", "L1–L5 detect ·\nhidden channels"), ("P5 Egress gate", "re-scan · FHIR\nvalidate")]
    n = len(steps)
    gap = 7
    w = (width - gap * (n - 1)) / n
    for i, (t, sub) in enumerate(steps):
        x = i * (w + gap)
        d.add(Rect(x, 22, w, 46, rx=4, ry=4, fillColor=BG, strokeColor=ACC, strokeWidth=0.8))
        d.add(String(x + w / 2, 55, t, fontName="Helvetica-Bold", fontSize=10, textAnchor="middle", fillColor=INK))
        for k, line in enumerate(sub.split("\n")):
            d.add(String(x + w / 2, 42 - k * 10.5, line, fontName="Helvetica", fontSize=10, textAnchor="middle",
                         fillColor=MUTED))
        if i < n - 1:
            ax = x + w
            d.add(Line(ax + 0.5, 45, ax + gap - 1.5, 45, strokeColor=ACC, strokeWidth=1))
            d.add(Polygon([ax + gap - 1.5, 47.5, ax + gap - 1.5, 42.5, ax + gap + 0.5, 45], fillColor=ACC, strokeColor=ACC))
    d.add(String(0, 9, "input (read-only)  →  sanitized/  +  report.json  +  records.jsonl",
                 fontName="Helvetica", fontSize=10, fillColor=INK))
    d.add(String(0, -3, "unsafe / broken / unsupported files  →  quarantined (reason code only, never copied)",
                 fontName="Helvetica", fontSize=10, fillColor=MUTED))
    return d


def table(rows, widths):
    cell = ParagraphStyle("c", parent=base, fontSize=10, leading=11.6, spaceAfter=0)
    head = ParagraphStyle("ch", parent=cell, fontName="Helvetica-Bold")
    rows = [[Paragraph(str(c), head if i == 0 else cell) for c in r] for i, r in enumerate(rows)]
    t = Table(rows, colWidths=widths)
    t.setStyle(TableStyle([
        ("FONT", (0, 0), (-1, -1), "Helvetica", 10), ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 10),
        ("TEXTCOLOR", (0, 0), (-1, -1), INK), ("BACKGROUND", (0, 0), (-1, 0), BG),
        ("LINEBELOW", (0, 0), (-1, 0), 0.6, ACC), ("LINEBELOW", (0, -1), (-1, -1), 0.4, MUTED),
        ("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 1.6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1.6), ("LEFTPADDING", (0, 0), (-1, -1), 3)]))
    return t


def main():
    doc = SimpleDocTemplate(str(OUT), pagesize=A4, leftMargin=14 * mm, rightMargin=14 * mm, topMargin=11 * mm,
                            bottomMargin=10 * mm, title="Clarity: Project Brief", author="Team Clarity")
    W = A4[0] - 28 * mm
    s = []
    s.append(P("Clarity: a privacy firewall that learns identities from the data, not from memory", h1))
    s.append(P("<b>Track 3 · Secret Wards</b> · Team <b>Clarity</b> · Ishan Ganguly · "
               "Repo: github.com/Ishan007-bot/Secret_Wards · Offline · CPU-only · no LLM · stdlib-only runtime", meta))
    s.append(P("1. In one paragraph", h2))
    s.append(P("Clarity turns a messy dump of Indian hospital records into a research release. The input mixes "
               "English, Devanagari and Hinglish; CSV, TSV, JSON, FHIR R4 and notes; and four encodings plus broken "
               "files. Personal data is removed from every channel (content, file names, headers, JSON keys, metadata, "
               "base64), and every clinical value is kept. Each real patient gets one stable, keyed pseudonym across "
               "files and scripts. The privacy policy was tuned against a re-implementation of the published attacker. "
               "<b>The key idea:</b> a two-pass <i>identity vault</i> learns names, IDs and ID <i>formats</i> from the "
               "data it is given, and a name-agnostic CRF plus context rules find the names no list contains. So it "
               "generalises to unseen formats and canaries instead of memorising practice data."))
    s.append(P("2. Architecture", h2))
    s.append(diagram(W))
    s.append(Spacer(1, 6))
    s.append(P("3. How it works", h2))
    s.append(P("<b>Ingestion:</b> files are sniffed by their bytes, not their extension. A strict decode cascade "
               "(BOM, UTF-16, UTF-8, plausible cp1252) and an iterative JSON depth guard follow. Broken, unsupported "
               "and mislabelled files are quarantined with a reason code, every file is listed in the report by "
               "SHA-256, and nothing is ever copied raw. Writers keep paths, delimiters, row shape, key order, value "
               "types and R4 validity; a validator gate quarantines any FHIR file a rewrite would break."))
    s.append(P("<b>Detection:</b> five layers.<br/>"
               "L1: patterns (Aadhaar, ABHA, PAN, phones in Latin and Devanagari digits).<br/>"
               "L2: the vault, matched in any separator, case or script, including learned ID shapes "
               "(<font face='Courier'>KGH:2031:004455</font>).<br/>"
               "L3: context rules, i.e. labels in three scripts, S/o-W/o-C/O, honorifics (<i>ji, sahab, behenji</i>), "
               "phone proximity (<i>called by X 98…</i>) and address grammar (<i>H.No., </i>" + dv("मकान नं.") + "<i>, near …</i>).<br/>"
               "L4: a self-trained CRF.<br/>"
               "L5: clinical protection, which overrides everything. It keeps <i>Dr. X</i>, C/O fever vs C/O name, "
               "K/C/O, H/O, wards, ASHA workers, doses, 1-0-1 and eponyms."))
    s.append(P("<b>Linkage:</b> rule R1 links records that share a strong ID only after an exclusivity check, so "
               "a couple sharing a phone are never merged. Rule R2 needs the same name plus a unique second clue "
               "(DOB, relative, or village + age). Our own Devanagari→Latin transliteration, phonetic keys and "
               "Jaro-Winkler make Mohd = " + dv("मोहम्मद") + ". Conflict checks run at cluster level. Pseudonyms are "
               "PSN-HMAC-SHA256(secret, cluster) and are written inside each record."))
    s.append(P("<b>Privacy layer:</b>"
               "<br/>• dates: a per-patient secret shift of 7–180 days, so intervals and stay lengths are exact;"
               "<br/>• DOB: removed;"
               "<br/>• age: truthful 10-year bands with 85+, widened to 30 years for cells of fewer than 5 people;"
               "<br/>• location: village and tehsil become district; PIN becomes 226***; coordinates are rounded to ~10 km;"
               "<br/>• diagnoses held by a single patient: generalised to their ICD-10 chapter."))
    s.append(P("4. USP", h2))
    s.append(P("• <b>Learns from the data it is given:</b> the identity vault and learned ID shapes work on formats "
               "nobody has seen. On two unseen-format datasets: 0 leaks, 0 canaries, detection 20/20 projected.<br/>"
               "• <b>Cross-script, conflict-aware identity resolution:</b> F0.5 = 1.00 with 0 wrong merges; the homonym, "
               "language and fragment traps are all correct.<br/>"
               "• <b>Measured, not guessed:</b> our A1–A7 attacker and scorer drove a policy sweep. Removing the "
               "DOB was worth +5.3 points and k=5/30-year bands +1.8.<br/>"
               "• <b>An egress DLP gate</b> re-scans every byte with the evaluator's normalisation (homoglyphs, "
               "zero-width, base64, %, \\u, HTML) and fails closed."))

    s.append(KeepTogether([P("5. Privacy–utility trade-off (measured)", h2), table([
        ["Measure", "Practice data", "Unseen-format data (2 seeds)"],
        ["Personal data still visible (overall / Hindi / Hinglish)", "0.0% / 0.0% / 0.0% (0 of 3,230)", "0.0% (0 of 3,230)"],
        ["Planted canaries found", "0 / 4", "0 / 4"],
        ["Medical values kept", "99.6%", "99.5%"],
        ["Linking precision / recall / F0.5", "1.00 / 1.00 / 1.00", "1.00 / 0.98 / 0.995"],
        ["Unique on (gender, age band, district) vs registry", "0.0% (raw: 33.3%)", "n/a (no registry)"],
        ["A4: patients confidently re-identified", "8.3% (raw: 97.9%)", "n/a"],
        ["A3 record linkage / A5 targeted (vs raw)", "4.3% / 68%", "n/a"],
        ["Known visit dates still visible", "0 / 14 (raw: 14 / 14)", "n/a"],
        ["Run time / peak memory", "3–5 s / 30 MB; 1,600 files: 23 s / 92 MB", "same"],
        ["Projected score (our scorer re-implementation)", "94.5 / 100, no penalties", "73.0 / 75 excl. privacy"],
    ], [W * 0.43, W * 0.31, W * 0.26])]))
    s.append(Spacer(1, 3))
    s.append(P("<b>Why these settings:</b> the whole generalisation sub-score is worth only 2 points, while the "
               "attacks are worth 20. So we coarsen quasi-identifiers hard: DOB, village, tehsil, rare diagnoses, "
               "and wide bands for small cells. But we <i>never</i> touch clinical values or date intervals, so "
               "utility stays above 0.93 and privacy gets its full credit. The district is kept because it is a "
               "research field that 93 utility probes check. The settings were chosen by a 22-point sweep "
               "(tools/policy_sweep.py), measured on practice data and checked on unseen-format data."))
    s.append(P("6. Security design (assume breach)", h2))
    s.append(P("• <b>No raw or intermediate data ever reaches disk:</b> the vault, evidence and clusters are in "
               "memory only, there are no temp files, and the quarantine stores nothing but a reason code. "
               "So there is no data at rest to steal, and no data key to protect.<br/>"
               "• <b>The only secret is RAKSHA_SECRET:</b> it comes from the environment, is used only as an HMAC "
               "key, and is never written (CI greps for it). A new secret gives unlinkable releases.<br/>"
               "• <b>Logs</b> use allow-listed codes and counts only; errors show the exception type only.<br/>"
               "• <b>Input</b> is opened read-only, and a test proves the input tree's hash is unchanged.<br/>"
               "• <b>CI checks on every push:</b> an offline run (network disabled) must give identical bytes; the "
               "repo audit must find no practice data; the kit check must print READY TO SUBMIT; and a fresh-clone "
               "Docker run (python:3.12-slim, 2 CPU, 4 GB, no network) matched the local output bit for bit."))
    s.append(P("7. Models, data and honest limitations", h2))
    s.append(P("<b>Model:</b> one self-trained linear-chain CRF, 16 KB, run with pure-Python inference. It has "
               "no raw-name features, so it cannot memorise names, and it is declared in the README and "
               "MODEL_CARD.<br/>"
               "<b>Acceptance gate:</b> names that appear only in free text leaked 15.6% before and 1.4% after, "
               "with clinical text unchanged.<br/>"
               "<b>Training data (synthetic only; external synthetic data approved by the organisers):</b> the "
               "practice data split by patient, our Faker note generator, and Mendeley Indian notes (CC BY 4.0). "
               "ai4privacy, a second Mendeley set and Synthea FHIR were used for testing only.<br/>"
               "<b>Gazetteer:</b> built from Faker plus a team list, with every practice name removed (audited)."))
    s.append(P("<b>Limitations:</b>"
               "<br/>• A name with no context at all in generic prose can be missed (ai4privacy-style sentences)."
               "<br/>• A5 stays the weakest attack, because exact stay lengths are kept for utility."
               "<br/>• PDFs, images and CDA XML are quarantined, not parsed."
               "<br/>• Our scorer and attacker re-implement the published rules, so the projected numbers are "
               "estimates."))
    doc.build(s)
    print("wrote", OUT)


if __name__ == "__main__":
    main()
