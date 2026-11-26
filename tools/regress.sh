#!/usr/bin/env bash
# Full regression gate (dev-only): unit tests, repo audit, practice score + kit self-check,
# two unseen-format (chaos) datasets, and an optional extra dataset with an answer key.
#   tools/regress.sh <kit dir> <work dir> [extra dataset dir with input/ + answer_key.json]
set -uo pipefail
KIT=$1; WORK=$2; EXTRA=${3:-}
PY="python -X utf8"
mkdir -p "$WORK"
export RAKSHA_SECRET=regress-a
$PY -c "import re,glob,sys; b=[f for f in glob.glob('**/*.py',recursive=True) if re.search('[\x00-\x08\x0b\x0c\x0e-\x1f]',open(f,encoding='utf-8').read())]; print('control chars in source:', b or 'none')"
$PY -m unittest discover -s tests 2>&1 | tail -1
$PY tools/audit_repo.py --kit "$KIT" | tail -1
rm -rf "$WORK"/p_a "$WORK"/p_b "$WORK"/p_c
$PY main.py --input "$KIT/dev/input" --output "$WORK/p_a" >/dev/null
$PY main.py --input "$KIT/dev/input" --output "$WORK/p_b" >/dev/null
RAKSHA_SECRET=regress-c $PY main.py --input "$KIT/dev/input" --output "$WORK/p_c" >/dev/null
$PY "$KIT/validate_output.py" --input "$KIT/dev/input" --output "$WORK/p_a" | tail -1
$PY tools/selfscore.py --kit "$KIT" --output "$WORK/p_a" --rerun "$WORK/p_b" --other "$WORK/p_c" | sed -n 2p
$PY "$KIT/check_dev.py" --output "$WORK/p_a" | grep -E "PERSONAL|CANAR|MEDICAL|LINKING"
for seed in 7 11; do
  [ -d "$WORK/chaos_$seed" ] || $PY tools/gen_chaos.py --kit "$KIT" --out "$WORK/chaos_$seed" --seed $seed >/dev/null
  rm -rf "$WORK/chaos_${seed}_out"
  $PY main.py --input "$WORK/chaos_$seed/input" --output "$WORK/chaos_${seed}_out" >/dev/null
  $PY tools/selfscore.py --kit "$KIT" --output "$WORK/chaos_${seed}_out" --input "$WORK/chaos_$seed/input" \
     --truth "$WORK/chaos_$seed/truth/truth.json" --no-attack --json | \
     $PY -c "import json,sys;d=json.load(sys.stdin);p=d['points'];print('chaos $seed non-privacy',round(sum(v for k,v in p.items() if k!='privacy'),2),'/75',d['penalties'])"
done
if [ -n "$EXTRA" ]; then
  rm -rf "$EXTRA/output"
  $PY main.py --input "$EXTRA/input" --output "$EXTRA/output" >/dev/null
  $PY - "$EXTRA" <<'PY'
import json, pathlib, re, sys
base = pathlib.Path(sys.argv[1]); key = json.loads((base / "answer_key.json").read_text(encoding="utf-8"))
texts = [p.name + "\n" + p.read_text("utf-8", "replace") for p in (base / "output").rglob("*") if p.is_file()]
n = 0
for x in key["pii"]:
    v = str(x["value"]).strip()
    if len(v) <= 3: continue
    rx = re.compile(r"(?<![\w])" + re.escape(v) + r"(?![\w])", re.I)
    for t in texts:
        for m in rx.finditer(t):
            if re.search(r"Dr\.?\s+(?:\w+\s+)?$", t[max(0, m.start()-25):m.start()]) or t[m.end():m.end()+8].lower().startswith(" worker"):
                continue
            n += 1
print(f"extra dataset: {len(key['pii'])} PII values, {n} leaks")
PY
fi
