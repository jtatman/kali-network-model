#!/usr/bin/env python3
"""Builds training-data/combined_scripts_format.jsonl -- the corpus in the
exact shape agent.py's own prompts produce and tools.py's ToolExecutor
consumes: {"goal", "chain": [{"tool": ..., <params>}], "scope", "pathway",
"turn", "source"}. No extra columns -- this is the "prefix each module
expects" format, kept clean on purpose. For the general-purpose/ChatML
export with danger-level/safeguard metadata, see export_chatml_format.py.

Source selection (see training-data/README.md "Gold-standard plan" for the
full reasoning):
  INCLUDED (reviewed or hand-verified, ready to train on):
    - pipeline_chains_generated.jsonl (live-verified output of
      pipeline_chain_builder.py -- minus any stage_2_blocked_pending_override
      row, same reasoning as excluding reviewed==False below: an
      incomplete/gated chain isn't ready to train on as-is; also minus any
      stale_target_placeholder row -- syntax kept in the canonical file for
      future reuse against a target that doesn't exist yet, e.g. rows still
      referencing the removed juice-shop container, not something to train
      on as if it were a currently-reachable target)
    - converted_baseline.jsonl       (1000)
    - converted_nmap_capped.jsonl    (100, capped by design -- see convert_nmap.py)
    - generated_pathways.jsonl       (62)
    - playbook_dvwa.jsonl            (6)
    - exports_transcript1_extracted.jsonl (1)
    - exports_transcript2_extracted.jsonl (18, minus reviewed==False rows)
    - failure_recovery.jsonl         (7, reviewed==True)
  EXCLUDED:
    - logs_extracted_UNREVIEWED.jsonl -- every row is reviewed: false/absent
      by construction (mechanically pulled from real session logs, known to
      contain the model's own historical mistakes -- see its own docstring
      in extract_logs.py). Needs a human/live-replay curation pass first.
    - raw_kali_pentest_data.jsonl / baseline_cleaned.jsonl / raw_nmap_commands.jsonl
      / nmap_cleaned_full.jsonl -- raw or intermediate forms superseded by
      their *_cleaned/converted/capped output.

Validates every chain's tool name against the real tools.SUPPORTED_TOOLS
(imported directly, not hand-copied) and drops+reports anything that
doesn't match. Dedups on exact (goal, chain) across the WHOLE combined set
(not just within one file) -- source files were built independently and
were never cross-checked against each other for repeats.

Run: python3 training-data/scripts/merge_scripts_format.py
Writes: training-data/combined_scripts_format.jsonl
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from tools import SUPPORTED_TOOLS  # noqa: E402

HERE = os.path.dirname(__file__)
DATA_DIR = os.path.join(HERE, "..")

# (filename, source_label_for_report) in priority order -- first occurrence
# of a duplicate (goal, chain) pair wins, so higher-confidence sources
# should be listed first.
SOURCES = [
    "pipeline_chains_generated.jsonl",
    "playbook_dvwa.jsonl",
    "failure_recovery.jsonl",
    "exports_transcript1_extracted.jsonl",
    "exports_transcript2_extracted.jsonl",
    "generated_pathways.jsonl",
    "converted_baseline.jsonl",
    "converted_nmap_capped.jsonl",
]

OUT_PATH = os.path.join(DATA_DIR, "combined_scripts_format.jsonl")
SCHEMA_KEYS = ("goal", "chain", "scope", "pathway", "turn", "source")


def load(fname):
    path = os.path.join(DATA_DIR, fname)
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def main():
    combined = []
    seen = set()
    stats = {}
    invalid_tool_rows = []
    dupes_dropped = {}
    unreviewed_dropped = {}

    for fname in SOURCES:
        rows = load(fname)
        kept = 0
        for row in rows:
            if (
                row.get("reviewed") is False
                or row.get("stage_2_blocked_pending_override")
                or row.get("stage_1_failed")
                or row.get("stale_target_placeholder")
            ):
                unreviewed_dropped[fname] = unreviewed_dropped.get(fname, 0) + 1
                continue
            chain = row.get("chain") or []
            bad_tools = [s.get("tool") for s in chain if s.get("tool") not in SUPPORTED_TOOLS]
            if bad_tools:
                invalid_tool_rows.append((fname, row.get("goal", "")[:80], bad_tools))
                continue
            key = (row.get("goal"), json.dumps(chain, sort_keys=True))
            if key in seen:
                dupes_dropped[fname] = dupes_dropped.get(fname, 0) + 1
                continue
            seen.add(key)
            clean = {k: row.get(k) for k in SCHEMA_KEYS}
            combined.append(clean)
            kept += 1
        stats[fname] = {"raw": len(rows), "kept": kept}

    with open(OUT_PATH, "w") as f:
        for row in combined:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(f"Wrote {len(combined)} examples to {OUT_PATH}\n")
    print("Per-source: raw -> kept")
    for fname in SOURCES:
        s = stats[fname]
        extra = []
        if fname in unreviewed_dropped:
            extra.append(f"{unreviewed_dropped[fname]} unreviewed/gated dropped")
        if fname in dupes_dropped:
            extra.append(f"{dupes_dropped[fname]} exact-dupes dropped")
        suffix = f" ({', '.join(extra)})" if extra else ""
        print(f"  {fname}: {s['raw']} -> {s['kept']}{suffix}")

    if invalid_tool_rows:
        print(f"\n{len(invalid_tool_rows)} rows dropped for an unrecognized tool name:")
        for fname, goal, bad in invalid_tool_rows[:20]:
            print(f"  [{fname}] {bad}: {goal}")
    else:
        print("\nAll chain tool names validated against tools.SUPPORTED_TOOLS -- 0 invalid.")

    total_dupes = sum(dupes_dropped.values())
    total_unreviewed = sum(unreviewed_dropped.values())
    print(
        f"\nTotals: {total_dupes} cross-file exact duplicates dropped, "
        f"{total_unreviewed} unreviewed rows excluded, "
        f"{len(invalid_tool_rows)} invalid-tool rows dropped."
    )


if __name__ == "__main__":
    main()
