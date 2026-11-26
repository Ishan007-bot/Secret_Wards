# Clarity: a privacy firewall for Indian hospital records

**Yugaantar DevForge · Track 3 · Secret Wards** · Team **Clarity**

Clarity is an **offline, CPU-only, LLM-free** privacy firewall. It reads a messy dump of
synthetic hospital records (English, Devanagari Hindi and Hinglish; CSV, TSV, JSON, FHIR R4 and
free-text notes in several encodings) and produces a research release that:

- removes personal information everywhere: content, file names, CSV headers, JSON keys, metadata and base64 attachments;
- keeps every clinical value exactly: medicines, doses, frequencies, vitals, labs, diagnoses, procedures and stay lengths;
- gives each real patient one stable, keyed pseudonym across files, hospitals and scripts, without merging different people;
- resists re-identification through per-patient secret date shifts, truthful age bands, location generalisation and rare-value coarsening;
- never leaks through logs, errors or temp files, and quarantines anything it cannot clean safely.

> Status: under active development during the hackathon. Sections marked *(in progress)* are completed as each phase lands.

## Setup and run

```bash
pip install -r requirements.txt            # standard library only at the moment
RAKSHA_SECRET=<secret> python main.py --input <input dir> --output <empty output dir>
```

The secret is read only from the `RAKSHA_SECRET` environment variable and is used only as an
HMAC key. It is never printed or written anywhere. Without it, the program refuses to run (exit code 2).

Output:

```
output/
├── sanitized/      cleaned mirror of the input (same paths and formats, UTF-8)
├── report.json     every input file by SHA-256, honest counts, timing and peak memory
└── records.jsonl   record locator -> pseudonym (or null when the evidence is too weak)
```

## Architecture

```
input (read-only)
  └─► P0 ingest: sorted walk, SHA-256, sniff by bytes, decode cascade, parse   ─► quarantine (reason code only)
      └─► P1 understand: column/key classifier, identity vault (memory only)
          └─► P2 link: evidence rules, conflict-aware clustering, HMAC pseudonyms
              └─► P3 privacy plan: date shifts, age bands, location, rare values
                  └─► P4 rewrite: layered detection + clinical protection, hidden channels
                      └─► P5 egress gate ─► sanitized/ + records.jsonl + report.json
```

## Fail-safe ingestion (implemented)

| Situation | Behaviour |
|---|---|
| UTF-8, UTF-8 BOM, UTF-16 (with or without BOM), cp1252 | decoded; written back as UTF-8 |
| bytes that only decode as mojibake | quarantined `undecodable_text` |
| PDF, images, archives, XML, unknown extensions | quarantined `unsupported_format` |
| JSON content behind a `.csv` extension | quarantined `format_mismatch` |
| truncated / invalid JSON | quarantined `malformed_json` |
| JSON nested deeper than the policy limit | quarantined `nesting_too_deep` (iterative scan, no recursion crash) |
| empty file | quarantined `empty_file` |
| any unexpected error while cleaning a file | that file is quarantined; the run continues |

Every input file appears in `report.json`, and nothing is ever copied raw.

## Security design *(in progress)*

- The secret is used only as an HMAC key (pseudonyms, date shifts); a missing secret means fail closed.
- Logging accepts only fixed message codes with numeric values: no file names, no content, no exception text.
- No intermediate data is written to disk.

## Detection, linkage and privacy layers *(in progress)*

## Models and data *(in progress)*

## Known limitations *(in progress)*
