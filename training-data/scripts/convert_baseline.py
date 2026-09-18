#!/usr/bin/env python3
"""Converts training-data/baseline_cleaned.jsonl (1000 bare-CLI-command
examples, {"instruction": ..., "response": "<shell command>"}) into the
agent's actual chain-schema format.

Design choice, stated explicitly rather than silently: every response here
is wrapped as a single run_command step with the command VERBATIM, not
parsed into per-tool structured params (target=/service=/etc.). Attempting
to parse 1000 heterogeneous real command lines into the right structured
fields for ~25 different tools risks silently mangling a real, working
command into a subtly wrong one -- exactly the class of bug this whole
session has been about finding and fixing. run_command is a fully legitimate
first-class tool, not a fallback hack, so this loses nothing in
executability. It DOES mean this file teaches breadth/variety of real
command lines rather than structured per-tool param usage -- that's what
training-data/generated_pathways.jsonl is for instead (hand-verified,
per-tool structured examples). The two files are complementary, not
duplicates -- see training-data/README.md.

These are modeled as single-turn freeform goals (turn=1, no Target:/Port:
attack-loop wrapper) since that's the actual prompt shape they match: e.g.
"Perform a basic TCP SYN scan on a single host..." is exactly what a bare
call_model(goal) freeform request looks like in agent.py's REPL, not a
run_attack_loop round.

scope is left null/unclassified here, DELIBERATELY -- this dataset wasn't
authored with the recon_only/exploit_authorized taxonomy in mind (see
kali-network-model-bdu), and guessing wrong in either direction is worse
than leaving it for a follow-up classification pass.

Run: python3 training-data/scripts/convert_baseline.py
Writes: training-data/converted_baseline.jsonl
"""
import json
import os

IN_PATH = os.path.join(os.path.dirname(__file__), "..", "baseline_cleaned.jsonl")
OUT_PATH = os.path.join(os.path.dirname(__file__), "..", "converted_baseline.jsonl")

examples = []
with open(IN_PATH) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        row = json.loads(line)
        examples.append({
            "goal": row["instruction"],
            "chain": [{"tool": "run_command", "command": row["response"]}],
            "scope": None,
            "pathway": None,
            "turn": 1,
            "source": "baseline_cleaned",
        })

if __name__ == "__main__":
    with open(OUT_PATH, "w") as f:
        for ex in examples:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")
    print(f"Wrote {len(examples)} examples to {OUT_PATH}")
