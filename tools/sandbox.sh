#!/usr/bin/env bash
# Run Clarity like the evaluator: fresh clone, python:3.12-slim (Linux), no network, 2 CPUs, 4 GB.
#   tools/sandbox.sh <input dir> <output dir> [git ref]
set -euo pipefail
IN=$(cd "$1" && pwd); OUT=$(mkdir -p "$2" && cd "$2" && pwd); REF=${3:-HEAD}
REPO=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
git -C "$REPO" archive "$REF" | tar -x -C "$WORK"                 # exactly what is committed
docker run --rm -v "$WORK":/repo -w /repo python:3.12-slim pip install -q --target /repo/.deps -r requirements.txt
docker run --rm --network none --cpus 2 --memory 4g -e RAKSHA_SECRET="${RAKSHA_SECRET:-sandbox-secret}" \
  -e PYTHONPATH=/repo/.deps -v "$WORK":/repo:ro -v "$IN":/data/input:ro -v "$OUT":/data/output -w /repo \
  python:3.12-slim bash -c 'start=$(date +%s.%N); python main.py --input /data/input --output /data/output;
    echo "wall $(echo "$(date +%s.%N) - $start" | bc 2>/dev/null || true) s"; ls /tmp | wc -l | xargs echo "tmp files:"'
