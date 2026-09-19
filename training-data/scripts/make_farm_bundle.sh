#!/usr/bin/env bash
# Packages the minimal set of files needed to run pipeline_chain_builder.py
# standalone on another machine -- NOT a clone of the whole repo (skips
# agent.py, the committed dataset jsonl files, mnemoria/, .beads/, etc.,
# none of which the harness needs to run). Preserves the exact relative
# layout pipeline_chain_builder.py's sys.path.insert(..., "..", "..")
# expects (training-data/scripts/ two levels under the repo root), so it
# unpacks and runs with zero code changes.
#
# Usage: training-data/scripts/make_farm_bundle.sh [output.tar.gz]
# On the target machine:
#   tar xzf pipeline-farm-bundle.tar.gz -C /path/to/custom-dir
#   cd /path/to/custom-dir
#   uv venv && uv pip install -r requirements.txt   # or pip install -r requirements.txt
#   cp .env.example .env && vi .env                  # fill in THIS machine's config
#   cp training-data/scripts/pipeline_targets.example.json training-data/scripts/pipeline_targets.json
#   vi training-data/scripts/pipeline_targets.json    # remap targets to what THIS machine can reach
#   set -a && source .env && set +a
#   python3 training-data/scripts/pipeline_chain_builder.py --list
#   python3 training-data/scripts/pipeline_chain_builder.py --shuffle --out my_output.jsonl
# Then copy my_output.jsonl back to the main checkout and run:
#   python3 training-data/scripts/merge_pipeline_chain_outputs.py my_output.jsonl
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="${1:-pipeline-farm-bundle.tar.gz}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

mkdir -p "$STAGE/training-data/scripts"

# Execution core -- what tools.py/remote_exec.py/config.py actually need.
cp "$REPO_ROOT/config.py" "$STAGE/"
cp "$REPO_ROOT/tools.py" "$STAGE/"
cp "$REPO_ROOT/remote_exec.py" "$STAGE/"
cp "$REPO_ROOT/requirements.txt" "$STAGE/"
cp "$REPO_ROOT/pyproject.toml" "$STAGE/" 2>/dev/null || true
cp "$REPO_ROOT/.env.example" "$STAGE/"

# The harness itself -- deliberately NOT the committed dataset jsonl files
# (baseline_cleaned.jsonl etc.) or the other build scripts -- a farming
# machine only ever produces pipeline_chains_generated.jsonl-shaped output,
# it never needs to run merge_scripts_format.py/export_chatml_format.py.
for f in pipeline_chain_builder.py pipeline_recipes.py dataset_taxonomy.py \
         merge_pipeline_chain_outputs.py pipeline_targets.example.json; do
    cp "$REPO_ROOT/training-data/scripts/$f" "$STAGE/training-data/scripts/"
done

tar czf "$OUT" -C "$STAGE" .
echo "Wrote $OUT ($(du -h "$OUT" | cut -f1))"
echo "Contents:"
tar tzf "$OUT"
