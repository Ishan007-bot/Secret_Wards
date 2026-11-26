# Model card: `ner_crf.json` (Clarity free-text NAME / ADDR tagger)

| | |
|---|---|
| **Type** | Linear-chain CRF (classical ML). Not a transformer, not an LLM, not generative, not pretrained by anyone else. |
| **Labels** | `O`, `B-NAME`, `I-NAME`, `B-ADDR`, `I-ADDR` |
| **Size** | 383 weighted feature strings + 5×5 transitions, 16 KB of JSON |
| **Trained with** | `sklearn-crfsuite` 0.5.0 (L-BFGS, c1 = 0.1, c2 = 0.05, 150 iterations, all transitions), chosen from a 3-point grid by held-out span F2 |
| **Runtime** | Pure-Python forward-backward in `rakshak/ml/tagger.py`; no third-party package, CPU-only, deterministic, offline |
| **Decision rule** | A token is tagged when P(not O) ≥ 0.3 (tuned on held-out + unseen-format data) |
| **Fallback** | Missing/unreadable model, or `ml_tagger: off` in `config/policy.yaml`: rules-only, same contract |

## Features: name-agnostic by design
These are defined in `rakshak/ml/features.py`, and the same code is used for training and inference.

- **What the model sees about a token:**
  - token shape, length bucket and script;
  - title/upper case;
  - a few lexicon flags: honorific, clinical word, region word, and name-gazetteer membership;
  - name-typical morphemes such as `-esh` or `-preet`.
- **What it sees about context:**
  - the identity of the ±2 neighbouring words, *only* if they belong to a fixed non-personal context vocabulary (labels, honorifics, relation markers, function words, Hinglish particles, clinical words);
  - whether the token follows a label and which kind of label it is;
  - whether a phone number is on the same line.
- **What it never sees: the identity of a capitalised or unknown word.** So it cannot memorise any name, it generalises to names it has never seen (canaries), and its weights contain no personal data. `tools/audit_repo.py` checks the model file and the gazetteer for every practice-data name token, and CI runs it on every push.

The gazetteer (`rakshak/data/*.txt`) is built by `training/build_gazetteer.py` from the Faker `en_IN`/`hi_IN` person providers (MIT) plus a team list. **Every name that occurs in the organiser practice data is removed.**

## Training data (synthetic only; organisers confirmed external synthetic data may be used for training and testing)
Total: 7,362 sequences, 737,719 tokens. Data hash: `8a76b0ad32e9c32a…`.

| Source | Use | Licence |
|---|---|---|
| Organiser practice data (`dev/input` + `truth.json` spans) | 80% of segments, **split by patient**; preserve-probes kept as `O` (hard negatives: doctors, wards, eponyms, ASHA, C/O complaints) | event data |
| Our generator `training/gen_faker_notes.py` (6,000 notes) | 10 document styles, new labels, pan-Indian + invented names, meaning traps in every note | Faker (MIT) |
| Mendeley "Clinical Notes Based on Indian Format" 10.17632/nn5r5htbpx.1 (1,500 notes) | Silver labels: only `Patient Name:` is a person (the consultant is a doctor and stays `O`) | CC BY 4.0 |

**Evaluated but not used for training:**
- **ai4privacy `open-pii-masking-500k`** (Hindi + English rows, revision `506996d6`). In the ablation, adding it *lowered* held-out F2 (0.9846 vs 0.9972). Its licence (Llama Community Licence) also places naming and attribution duties on distributed models. It is used only as a test set.
- **Mendeley 10.17632/bzgjmph5n2.1**, used as an unseen-format test set.
- **Synthea (MITRE)** FHIR R4 bundles, used for robustness tests of the FHIR path.

URLs, revisions and SHA-256 of every external file are recorded by `training/fetch_external.py` (data lives in the git-ignored `training/data/`).

## Evaluation
`training/eval_crf.py` measures span recall per script, using the exact runtime code. The "rules" row is a single document with no cross-file vault, i.e. the hard case.

| Test set | Rules only | **Rules + CRF** |
|---|---|---|
| Practice holdout (unseen patients) | recall 0.65 (latin 0.71, hinglish 0.13, deva 1.0), char-precision 0.76 | **recall 0.95** (latin 0.91, hinglish 1.0, deva 1.0), precision 0.87 |
| Unseen-format chaos holdout (new names, labels, IDs) | recall 0.62 (hinglish 0.10), precision 0.80 | **recall 0.84** (latin 0.91, hinglish 0.45, deva 1.0), precision 0.89 |
| Mendeley unseen-format notes | recall 1.0, precision 0.35 | recall 1.0 |

### Acceptance gate (whole pipeline, `training/pipeline_eval.py`)
Share of gold names/addresses still visible after sanitising, comparing tagger off with tagger on:

| Test set | Leaked, off → on | Non-PII words kept |
|---|---|---|
| Faker notes, names only in free text | **15.6% → 1.4%** | 97.0% → 97.0% |
| ai4privacy English | 75% → 66% | 96.9% → 96.1% |
| ai4privacy Hindi | 76% → 68% | 80.5% → 79.4% |
| Mendeley | 1.0% → 1.0% | unchanged |

On the practice data and two unseen-format datasets, the tagger changes no trap-group precision and no clean-document retention. **Decision: shipped, on.**

## Safety rules in the pipeline
- The CRF runs only on sentence-like free text.
- The meaning-trap protection layer (doctors, wards, eponyms, ASHA, doses) overrides it.
- Spans made only of clinical, context or region words are dropped.
- A Devanagari span needs a label or relation cue, or a gazetteer name, because Devanagari has no capital letters.
- A CRF hit only ever *adds* redaction: it never creates linkage evidence.

## Limitations
- Generic web-style English/Hindi prose with non-Indian names (ai4privacy) is still hard; recall there is about 34%.
- Training labels for the Mendeley notes are silver labels.
- The practice holdout shares document templates with the training split. The chaos set is the fairer estimate.
