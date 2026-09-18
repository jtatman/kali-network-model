#!/usr/bin/env python3
"""Extracts real (goal, chain, outcome) triples from every AgentLogger
session under logs/*.json -- these are genuine round-by-round prompts and
the model's ACTUAL historical responses, not synthetic examples.

IMPORTANT, unlike the other three build_*.py scripts in this directory:
this does NOT produce ready-to-train examples. A logged "decision" event
records what the model actually said, which this session repeatedly found
to be wrong in specific, now-understood ways (the login.php?id=1 few-shot
contamination, the malformed hydra http-post-form attempt against /config/,
etc.) -- training on it unreviewed would teach the model its own past
mistakes. This script's only job is the MECHANICAL extraction; each row is
tagged with a real, verifiable outcome (did the immediately-following
tool_call event report success?) so a reviewer can filter, but every row
needs human/model review before being merged into the actual training set.
See training-data/README.md's "Known gaps" section.

Run: python3 training-data/scripts/extract_logs.py
Writes: training-data/logs_extracted_UNREVIEWED.jsonl
"""
import glob
import json
import os

LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "logs")
OUT_PATH = os.path.join(os.path.dirname(__file__), "..", "logs_extracted_UNREVIEWED.jsonl")

examples = []

for log_path in sorted(glob.glob(os.path.join(LOG_DIR, "session_*.json"))):
    try:
        data = json.load(open(log_path))
    except (json.JSONDecodeError, OSError):
        continue
    events = data.get("events", [])
    session_id = data.get("session_id", os.path.basename(log_path))

    for i, event in enumerate(events):
        if event.get("event_type") != "decision":
            continue
        decision = event["data"]
        goal = decision.get("reasoning", "")
        chain = decision.get("chosen_action", {}).get("chain", [])
        if not chain:
            continue

        # The real outcomes for this chain's steps are the tool_call events
        # immediately following this decision, up to the next decision.
        outcomes = []
        for follow in events[i + 1:]:
            if follow.get("event_type") == "decision":
                break
            if follow.get("event_type") == "tool_call":
                fd = follow.get("data", {})
                outcomes.append({
                    "tool": fd.get("tool"),
                    "status": fd.get("result", {}).get("status"),
                })

        examples.append({
            "goal": goal,
            "chain": chain,
            "real_outcomes": outcomes,
            "scope": None,
            "pathway": None,
            "turn": None,
            "source": "logs",
            "session_id": session_id,
            "reviewed": False,
        })

if __name__ == "__main__":
    with open(OUT_PATH, "w") as f:
        for ex in examples:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")
    print(f"Wrote {len(examples)} unreviewed extracted examples to {OUT_PATH}")
    print("These are NOT ready to train on -- see the script's own docstring.")
