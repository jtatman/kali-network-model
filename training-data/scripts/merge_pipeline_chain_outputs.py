#!/usr/bin/env python3
"""Merges one or more pipeline_chain_builder.py output files (each
produced independently -- e.g. on a different Kali machine, via --out) into
the canonical training-data/pipeline_chains_generated.jsonl, deduping on
exact (pathway, chain) so re-running overlapping recipes across machines
doesn't multiply rows.

This is the "farm it out, parse results after" half of the workflow: run
pipeline_chain_builder.py independently on however many machines, copy
each machine's output file back to this repo (scp/rsync/whatever), then
run this script once to fold them all in. It does NOT run
merge_scripts_format.py itself -- that's still a separate, deliberate step
after reviewing what came back.

Run: python3 training-data/scripts/merge_pipeline_chain_outputs.py \
       machine2_output.jsonl machine3_output.jsonl [...]
     (training-data/pipeline_chains_generated.jsonl is always included as
     a base and always the write target -- this appends/dedupes into it
     in place.)
"""
import json
import os
import sys

HERE = os.path.dirname(__file__)
CANONICAL = os.path.join(HERE, "..", "pipeline_chains_generated.jsonl")


def load(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def main():
    extra_paths = sys.argv[1:]
    if not extra_paths:
        print("Usage: merge_pipeline_chain_outputs.py <file1.jsonl> [file2.jsonl ...]")
        print(f"(merges into {CANONICAL} in place, deduped)")
        sys.exit(1)

    seen = set()
    combined = []
    stats = {}

    for path in [CANONICAL] + extra_paths:
        rows = load(path)
        kept = 0
        for row in rows:
            key = (row.get("pathway"), json.dumps(row.get("chain"), sort_keys=True))
            if key in seen:
                continue
            seen.add(key)
            combined.append(row)
            kept += 1
        stats[path] = {"raw": len(rows), "kept": kept}

    with open(CANONICAL, "w") as f:
        for row in combined:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(f"Wrote {len(combined)} deduped rows to {CANONICAL}\n")
    for path, s in stats.items():
        print(f"  {path}: {s['raw']} -> {s['kept']} new")

    failed = sum(1 for r in combined if r.get("stage_1_failed"))
    blocked = sum(1 for r in combined if r.get("stage_2_blocked_pending_override"))
    print(f"\n{failed} rows have a real stage-1/stage-2 failure (kept for review, "
          f"excluded from merge_scripts_format.py's trusted merge).")
    print(f"{blocked} rows are stage-1-only pending the pipeline override.")


if __name__ == "__main__":
    main()
