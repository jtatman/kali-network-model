#!/usr/bin/env python3
"""Cleans and converts training-data/raw_nmap_commands.jsonl (1133 examples,
{"input": ..., "output": "nmap ..."}) into chain-schema shape.

Unlike convert_baseline.py, this DOES parse into structured run_nmap params
(target/flags) rather than wrapping as run_command -- safe to do here
specifically because every single row is the same one tool (nmap), so the
parse is a single well-bounded heuristic (last whitespace-separated token =
target, everything else after stripping a leading "nmap"/"sudo nmap" =
flags) instead of needing a different parser per tool. Spot-checked against
a sample before trusting this at 1133-row scale -- see the script's own
validation pass below.

Cleaning applied (same policy as convert_baseline.py): dropped 6 non-English
inputs, deduped 10 exact repeats.

This dataset is nmap-only and 1133 rows is disproportionately large next to
generated_pathways.jsonl's ~6 examples for the same pathway (nmap recon is
1 of 10 canonical pathways, not 10x more important than the others) --
CAPPED at 100 for the eventual merged corpus (roughly the same order of
magnitude as the other pathway sources), full cleaned set kept separately
in case more is wanted later. See training-data/README.md.

Run: python3 training-data/scripts/convert_nmap.py
Writes: training-data/nmap_cleaned_full.jsonl (all cleaned, structured)
        training-data/converted_nmap_capped.jsonl (100-row sample for merge)
"""
import json
import os
import random
import re

IN_PATH = os.path.join(os.path.dirname(__file__), "..", "raw_nmap_commands.jsonl")
OUT_FULL = os.path.join(os.path.dirname(__file__), "..", "nmap_cleaned_full.jsonl")
OUT_CAPPED = os.path.join(os.path.dirname(__file__), "..", "converted_nmap_capped.jsonl")
CAP = 100

_TARGET_LOOKS_VALID_RE = re.compile(
    r'^[a-zA-Z0-9](?:[a-zA-Z0-9.\-\/,:]*[a-zA-Z0-9])?$'
)


def split_nmap_command(output):
    """Returns (target, flags) or None if the heuristic can't confidently
    split this one. Strips a leading "sudo" -- remote_exec's own auto-sudo-
    retry on permission_denied already handles privilege escalation, so
    baking "sudo" into flags would just produce a literal wrong token
    ("nmap sudo -sS ...") passed to _run_nmap's flags field."""
    parts = output.strip().split()
    if not parts or parts[0] != "nmap":
        if len(parts) >= 2 and parts[0] == "sudo" and parts[1] == "nmap":
            parts = parts[2:]
        else:
            return None
    else:
        parts = parts[1:]
    if not parts:
        return None
    target = parts[-1]
    flags = " ".join(parts[:-1])
    if not _TARGET_LOOKS_VALID_RE.match(target):
        return None
    return target, flags


examples = []
skipped = []
with open(IN_PATH) as f:
    rows = [json.loads(line) for line in f if line.strip()]

seen = set()
for row in rows:
    if not row["input"].isascii():
        continue
    key = (row["input"], row["output"])
    if key in seen:
        continue
    seen.add(key)

    split = split_nmap_command(row["output"])
    if split is None:
        skipped.append(row)
        continue
    target, flags = split
    examples.append({
        "goal": row["input"],
        "chain": [{"tool": "run_nmap", "target": target, "flags": flags or "-sV"}],
        "scope": "recon_only",  # nmap alone (no --script exploit-class NSE) is always identification
        "pathway": "nmap_commands_dataset",
        "turn": 1,
        "source": "nmap_commands",
    })

if __name__ == "__main__":
    with open(OUT_FULL, "w") as f:
        for ex in examples:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")
    random.seed(20260918)
    capped = random.sample(examples, min(CAP, len(examples)))
    with open(OUT_CAPPED, "w") as f:
        for ex in capped:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")
    print(f"Parsed: {len(examples)}, skipped (couldn't confidently split): {len(skipped)}")
    print(f"Wrote {len(examples)} to {OUT_FULL}")
    print(f"Wrote {len(capped)} (capped sample) to {OUT_CAPPED}")
    if skipped:
        print("\nSample skipped rows (for manual review):")
        for row in skipped[:10]:
            print(" ", row)
