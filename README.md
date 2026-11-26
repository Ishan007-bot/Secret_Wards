# Clarity: a privacy firewall for Indian hospital records

**Yugaantar DevForge · Track 3 · Secret Wards** · Team **Clarity** · Project brief: [`docs/brief.pdf`](docs/brief.pdf)

Clarity is an **offline, CPU-only, LLM-free** privacy firewall. It reads a messy dump of synthetic
hospital records and produces a research release that hospitals could actually share. The input covers:

- **languages:** English, Devanagari Hindi and Hinglish;
- **formats:** CSV, TSV, JSON, FHIR R4 and free-text notes;
- **encodings:** UTF-8, UTF-8 BOM, UTF-16 and cp1252, plus broken and unsupported files.

The release:

- **removes personal data everywhere:** content, file names, CSV headers, JSON keys, metadata and base64 attachments;
- **keeps clinical meaning exactly:** medicines, doses, `1-0-1` schedules, vitals, labs, diagnoses, procedures, stay lengths, doctors and wards;
- **gives each real patient one stable, keyed pseudonym** across files, hospitals and scripts, without ever merging two different people;
- **was measured against a re-implementation of the published attacker (A1–A7)** and tuned until re-identification risk was low;
- **never leaks** through logs, errors, temp files or the report, and **quarantines** anything it cannot clean safely.

**The one idea behind it:** Clarity learns *from the data it is given*. Its identity vault, its learned ID shapes and its name-agnostic CRF mean it does not depend on memorised names or formats. That is what the unseen-format ("chaos") round tests.

---

## Setup and run

```bash
pip install -r requirements.txt            # nothing to install: the runtime uses only the Python standard library
RAKSHA_SECRET=<secret> python main.py --input <input dir> --output <empty output dir>
```

`raksha.toml` runs exactly this. Python 3.10+ on Linux, Windows or macOS gives byte-identical output.

- The secret is read only from `RAKSHA_SECRET` and is used only as an HMAC key.
- It is never printed, logged or written.
- Without it, the program refuses to run (exit 2), so it fails closed.

```
output/
├── sanitized/      cleaned mirror of the input (same relative paths and formats, UTF-8)
├── report.json     every input file by SHA-256 (never by name), honest counts, entities, timing, peak memory
└── records.jsonl   one line per patient record: file, locator (row:N | /json/pointer | doc), pseudonym or null
```

## Architecture

```
input (read-only, never modified)
  │
  ├─ P0 INGEST     sorted walk · SHA-256 · sniff by bytes · decode cascade · iterative depth guard · parse
  │                └─► unsafe / broken / unsupported ─► quarantined (reason code only, never copied)
  ├─ P1 UNDERSTAND column/key role classifier (header meaning + value profile) · FHIR-aware JSON paths
  │                └─► IDENTITY VAULT (in memory only): names, relatives, IDs + learned ID shapes, phones, addresses
  ├─ P2 LINK       evidence per record · strong-ID rule with exclusivity · name + second-clue rule ·
  │                cross-script phonetic keys · conflict-aware clustering ─► keyed HMAC pseudonyms
  ├─ P3 PLAN       per-patient secret date shift · DOB removal · truthful age bands + k-anonymity widening ·
  │                village/tehsil→district · PIN→3 digits · rare-diagnosis coarsening · geo rounding
  ├─ P4 REWRITE    layered detection (L1 patterns · L2 vault · L3 context rules · L4 CRF · L5 clinical
  │                protection) on content, file names, headers, keys, metadata, base64 · format-faithful writers
  └─ P5 EGRESS     evaluator-style normalisation (NFKC, homoglyphs, zero-width, Indic digits, base64/%/\u/HTML)
                   re-scan against the vault ─► re-clean once ─► still dirty? quarantine · FHIR R4 validator gate
                   └─► sanitized/ + records.jsonl + report.json
```

## How each part works

### Ingestion (fail-safe)
| Situation | Behaviour |
|---|---|
| UTF-8, UTF-8 BOM, UTF-16 (with or without BOM), cp1252 | decoded by a strict cascade, written back as UTF-8 |
| bytes that only decode as mojibake / random binary | quarantined `undecodable_text` |
| PDF, images, XML/CDA, archives, unknown types | quarantined `unsupported_format` |
| JSON behind a `.csv` extension | quarantined `format_mismatch` |
| truncated / invalid JSON | quarantined `malformed_json` |
| JSON nested deeper than 200 levels | quarantined `nesting_too_deep` (iterative scan: no recursion crash) |
| empty file | quarantined `empty_file` |
| any unexpected error inside one file | that file is quarantined, the run continues, stderr shows the exception *type* only |
| a FHIR file whose rewrite would break R4 validity | quarantined `fhir_invalid_after_rewrite` (never exported broken) |
| `;`, `\|` or TAB used inside a `.csv` | the delimiter is sniffed from the file's own lines and written back unchanged |
| `.psv`, `.jsonl` / `.ndjson`, `.log`, `.md`, `.text`, `.note` | sanitised (tables as tables; logs and JSON Lines as text, structure kept byte-for-byte) |
| JSON Lines saved with a `.json` extension | sanitised line by line instead of being rejected as malformed |
| a huge document (e.g. a 5 MB single-line log) | processed in ~64 KB pieces cut at line/word boundaries, so time stays linear |

Every input file appears in `report.json`, and nothing is ever byte-copied. Ragged CSV rows, multi-line cells, CRLF endings, BOMs, the delimiter, JSON key order, indentation and value types are all preserved.

### Detection (English, Devanagari, Hinglish)
1. **Structured fields** are classified by header meaning (English, Hinglish and Devanagari synonyms such as `Naam`, `Pita/Pati ka Naam`, `Gaon`, `मरीज़ का नाम`) *and* by a value profile (phone, Aadhaar, PAN, e-mail, address, ID shape). A renamed column like `Contact#` is still recognised from its values.
2. **The identity vault (two passes).**
   - Pass 1 collects every name, relative, ID, phone, Aadhaar, address part and village from structured fields and labelled text. It also **learns each ID format** (e.g. `KGH:2031:004455` → `KGH[sep]\d{4}[sep]\d{6}`).
   - Pass 2 finds those values *everywhere*: in any separator, letter case or digit grouping, in Devanagari digits, file names, headers, JSON keys, metadata paths and base64 attachments.
3. **Context rules.** These find what no list contains, including the planted canaries:
   - name and relative labels (`Pt Name -`, `नाम:`), relation markers (`S/o`, `W/o`, `C/O <name>`, `पति`), honorifics (`ji`, `sahab`, `behenji`, `bhaiya`, `श्री`);
   - **phone-proximity** (`called by <name> <phone>`, `<name> (attendant, bed 12), mob …`);
   - address grammar (`H.No.`, `Makan No.`, `मकान नं.`, `Mohalla`, `near …`, `… के पास`);
   - honorific names with no label (`Smt. Kamla Devi`, `श्रीमती …`, but never `Shri Ram Hospital`), surname-first
     names (`KHANNA, TEJAS`), apostrophe names (`D'Souza`), bare kinship labels (`Husband - …`), loose ID labels
     (`Reg No. 2031/OPD/00456`, `IP No 31/1234`, `Policy no. …`), dotted phones and landlines.
4. **A self-trained, name-agnostic CRF** adds recall on free text (see *Models and data*).
5. **The clinical protection layer** keeps the meaning traps:
   - `Dr. <name>` stays even when a relative shares the first name;
   - `C/O fever` (complaint) vs `C/O <name>` (care of); `K/C/O`, `H/O`;
   - `Ward 4 (Medicine)`, `Bed 29`, `ASHA worker`;
   - doses and `1-0-1` schedules;
   - eponyms (`Bell's palsy`, `Parkinson's disease`).
6. **Disguises are undone before detection** and again at the egress gate: `\uXXXX` escapes, HTML entities, %-encoding, zero-width characters, Cyrillic/Greek homoglyphs and full-width forms. **Base64 and hex payloads** anywhere in a cell or note are decoded, cleaned and re-encoded in the same encoding (UUIDs and hashes are left alone).
7. **Dates in any common form are shifted with their format kept:** `12/04/1977`, `1977-04-12T10:30+05:30`, `1977/04/12`, `1977.04.12`, `12-Apr-1977`, `12th April 1977`, `Apr 12 1977`, yearless `5 September`, and Hindi months (`12 अप्रैल 1977`, Devanagari digits).

### Linkage and pseudonyms
This mirrors the dataset's own definition of "must link", and is conservative so that F0.5 stays high:

- **R1:** a shared strong identifier (hospital ID, Aadhaar, ABHA, phone, e-mail, insurance ID) that belongs to one person. An exclusivity check means a phone shared by a married couple never merges them.
- **R2:** the same name plus a second clue (DOB, relative's name, or village + age ±1) whose combination is unique.

Names are compared across scripts with our own Devanagari→Latin transliterator (schwa deletion, nukta folding), phonetic keys, a consonant skeleton and Jaro-Winkler. As a result, Mohammad = Mohd = मोहम्मद, Fatima ≈ Fatma, Bhowmick = Bhaumik = भौमिक, Chowdhury = Chaudhary and Eshan = ईशान (Ishan), while Asha ≠ Usha and Sunita ≠ Sunil. Token order is ignored. Every merge is checked at cluster level (DOB, gender, Aadhaar, age, name), so a chain of weak links can never fuse two people. When evidence is too weak, the record gets `null`.

In a document that mentions several people (a register, a log, JSON Lines), only the record's own patient receives its pseudonym. Every other person becomes a placeholder, never someone else's pseudonym.

Pseudonyms are `PSN-` plus 8 Crockford base-32 characters from **HMAC-SHA256(secret, cluster)**. That is keyed, so it cannot be reversed by hashing originals, and it changes with the secret. The pseudonym is written **inside** each record: in the ID column, the `Patient:` line and the FHIR identifier.

### Privacy layer (values chosen by measurement; `config/policy.yaml`)
| Quasi-identifier | Release | Why |
|---|---|---|
| visit, admission, lab dates | shifted by a **per-patient secret offset**, 7–180 days, never 0; format kept (d/m vs m/d inferred per file) | intervals and stay lengths stay exact; one global shift would be recoverable (A5) |
| date of birth | removed (`[DOB]`; optional FHIR `birthDate` dropped so R4 stays valid) | a jittered DOB still gave the attacker the birth year: measured +5.3 projected points |
| age | truthful 10-year band (`40-49`), `85+` top-code; cells with fewer than 5 people get 30-year bands | sweep: k=5/30 y beat k=3/20 y |
| village, mohalla, tehsil | → district (district is kept: it is a research field) | registry filters on village/tehsil |
| PIN | `226***` | |
| diagnosis held by one patient | → its ICD-10 chapter (eponyms kept) | the "rare condition + age band" trap |
| geolocation | rounded to 0.1° (~10 km) | |
| file names with PII | keyed rename `file_<HMAC>.ext` | |

**Every release measures itself.** `report.json` carries a PII-free `privacy_assessment` with these parts:

- **the release's own k-anonymity** on (gender, age band, district), showing patients in cells below k before and after widening, unique patients and the median cell size;
- **rare-diagnosis codes generalised**;
- **the shift / DOB / location policy** applied.

The report also carries `detection_layers`, the number of spans each layer removed (L1 patterns, L1 learned ID shapes, L2 vault, L3 context rules, L3 phone proximity, L4 CRF), and `egress_gate` statistics. All of these are counts only.

### Security design ("assume the server is breached")
- **No raw or intermediate data ever touches disk:**
  - the vault, the evidence and the clusters live only in process memory;
  - no temp files are written (verified: TMPDIR empty after a run);
  - the quarantine stores *nothing*, only a reason code in the report.
- **No data at rest needs encrypting, so there are no data keys to steal.** The only secret is `RAKSHA_SECRET`:
  - it comes from the environment and is used only as an HMAC key;
  - it is never logged or written (CI greps every output for it);
  - a different secret gives different pseudonyms, shifts and file names, so releases cannot be linked to each other.
- **PII-free logging:** allow-listed message codes and counts only. Exceptions print only their type name, never a value.
- **The egress gate** re-scans every byte against the vault with the scorer's normalisation before writing. It fails closed.
- **The input is opened read-only**, and a test proves its hash is unchanged after a run.

## Measured results

### Practice data (`Secret-Wards-ToolKit/dev`)
| Measure | Value |
|---|---|
| personal data still visible (kit `check_dev.py`) | **0 / 3,230** (0.0% overall, Hindi 0%, Hinglish 0%, every hiding channel 0%) |
| planted canaries found | **0 / 4** |
| medical values kept | **99.6%** (4,835 / 4,855) |
| linking precision / recall / F0.5 | **1.00 / 1.00 / 1.00** (0 wrong merges; homonym, language and fragment traps all correct) |
| run time / peak memory | about 3–5 s / 30 MB (practice); 1,600 files: 16 s / 92 MB; 8 MB of Synthea FHIR: 13 s; a 5 MB single-line log: 20 s |
| determinism | byte-identical across runs and across Windows / Linux (Docker) |

**Re-identification, measured with our re-implementation of the published A1–A7 attacker** (`tools/attacker.py`):

| Attack | Raw input | Clarity release |
|---|---|---|
| A3 record linkage (mean probability on the true person) | 0.70 | **0.03** (4.3% of raw) |
| A4 patients confidently re-identified from pooled profiles | 97.9% | **8.3%** |
| A5 targeted attack (known visit date / condition) | 0.77 | 0.52 (68% of raw) |
| unique on (gender, age band, district) against the registry | 33.3% | **0.0%** |
| known visit dates still visible | 14 / 14 | **0 / 14** |
| A6 pseudonym inversion / A7 cross-release linkability | n/a | **0 / 0.05** |

Our projected score with a re-implementation of the published formulas (`tools/selfscore.py`) is **94.5 / 100**, with no penalties. That is an estimate, not the official score. For reference, the organisers' reference system scores about 80–85.

### Data we did not tune on
These are unseen-format datasets from `tools/gen_chaos.py`, with three seeds. They have:

- new pan-Indian names in both scripts;
- renamed columns (`Patient's Name`, `Contact#`, `Gram/Mohalla`);
- new labels (`Pt Name -`, `मरीज:`);
- new ID prefixes and new phone formats;
- for the `--hard` seed, `;`-delimited CSVs and `yyyy/mm/dd` dates as well.

| Measure | Result |
|---|---|
| leaks | **0 / 3,230** on every seed |
| canaries | **0 / 4** |
| medical values kept | 99.5–99.6% |
| linking F0.5 | 0.98–1.00, with 0 wrong merges |
| projected non-privacy points | 72.5–73.1 of 75 (practice: 73.6) |

Other unseen tests:
- **An independent adversarial dataset written by a different LLM** (36 files, 2,132 PII values, with traps, homoglyphs, zero-width characters, `\u` escapes, base64 and broken files): **0 leaks**. Its 6 findings (apostrophe surnames, a sentence-ending full stop inside a relative's name, "village." read as a label, villages named like districts, base64 lines in notes, generic surnames) were all fixed, and each is now a regression test.
- **Hostile-input fuzzing** (`tools/fuzz.py`, 60 files per seed: byte flips, truncation, NUL bytes, 5 MB single lines, JSON depth 199/201, NaN, odd Unicode file names): exit 0, every file reported, nothing copied raw, no leaks. CI runs it on every push.
- **Synthetic Indian discharge notes from another author (Mendeley):** 99% of patient names removed in a format never seen before.
- **Synthea FHIR bundles:** still valid R4 after sanitising.

## Models and data (declared)
- **One model:** a **self-trained linear-chain CRF** (`models/ner_crf.json`, 16 KB, 383 feature weights).
  - It is not a transformer, not generative and not pretrained by anyone.
  - It runs in pure Python (`rakshak/ml/tagger.py`).
  - It uses no raw word identity for capitalised or unknown words, so it cannot memorise names.
  - It shipped only after passing an acceptance gate: names that appear only in free text leaked 15.6% → 1.4%, with no loss of clinical text.
  - Full details are in [`models/MODEL_CARD.md`](models/MODEL_CARD.md).
- **Training data (synthetic only).** The organisers confirmed that external *synthetic* datasets may be used for training and testing. Sources:
  - the organiser practice data (split by patient);
  - our Faker-based generator (`training/gen_faker_notes.py`);
  - Mendeley *Clinical Notes Based on Indian Format* (CC BY 4.0).
- **Test-only data:**
  - ai4privacy `open-pii-masking-500k`. Adding it to training lowered accuracy, and its Llama licence binds trained models, so it is used for testing only;
  - Mendeley *Synthetic Indian Clinical Notes*;
  - Synthea (MITRE) FHIR bundles.
- **Provenance:** sources, revisions and SHA-256 hashes are recorded by `training/fetch_external.py`. No external data is committed.
- **Gazetteers:** name lists come from Faker `en_IN`/`hi_IN` plus a team list, with **every practice-data name removed**. The district list is the public Uttar Pradesh / India gazetteer. `tools/audit_repo.py` proves the repository contains no practice name, ID, phone or address, and CI runs it on every push.

## Reproduce and self-test
```bash
python -m unittest discover -s tests                         # 61 unit / end-to-end tests (synthetic fixtures)
python tools/audit_repo.py --kit ../Secret-Wards-ToolKit     # no practice data in the repo
RAKSHA_SECRET=a python main.py --input ../Secret-Wards-ToolKit/dev/input --output out_a
python ../Secret-Wards-ToolKit/validate_output.py --input ../Secret-Wards-ToolKit/dev/input --output out_a
python ../Secret-Wards-ToolKit/check_dev.py --output out_a
python tools/selfscore.py --kit ../Secret-Wards-ToolKit --output out_a      # projected score + attacker
python tools/gen_chaos.py --kit ../Secret-Wards-ToolKit --out chaos --seed 11 --hard  # unseen-format test set
python tools/fuzz.py --kit ../Secret-Wards-ToolKit --work fuzz --seed 1      # hostile / broken inputs
tools/regress.sh ../Secret-Wards-ToolKit work [extra dataset]                # the full regression gate
python tools/policy_sweep.py --kit ../Secret-Wards-ToolKit --work sweep     # privacy/utility trade-off
tools/sandbox.sh <input> <output>          # fresh clone in python:3.12-slim, --network none, 2 CPU, 4 GB
pip install -r training/requirements-train.txt && python training/fetch_external.py   # retrain (optional)
```

CI runs all of this on Linux on every push:
- unit tests and the repo audit;
- three runs, then the contract check, a determinism diff, a grep for the secret, and the kit self-check;
- the projected score;
- hostile-input fuzzing (two seeds) and an unseen-format leak gate (`gen_chaos --hard`);
- a run with networking disabled (`unshare -n`), which must give identical bytes;
- `check_submission.py --run`, which must print **READY TO SUBMIT**.

## Known limitations
- **Generic web-style prose with foreign names** (e.g. the ai4privacy sentences) is still hard. In Indian clinical text, names are found by labels, relations, honorifics, phone-proximity and the vault. A name with no context at all, in an otherwise empty free-text field, can be missed.
- **The targeted attack (A5) stays the weakest component.** Intervals must stay exact for clinical utility, so a known length of stay combined with a common diagnosis can still single a person out. Suppressing that would cost temporal utility.
- **We read only text and structured formats.** PDFs, images and HL7/CDA XML are quarantined (never exported), not parsed.
- **Our scorer and attacker are re-implementations of the published rules.** Some parts of the official evaluator are not published (e.g. lab medians), so our projected numbers are estimates.
