#!/usr/bin/env python3
"""Builds training-data/combined_chatml_format.jsonl -- the general-purpose,
model/harness-agnostic export: standard {"messages": [...]} chat turns plus
a sibling "metadata" object (danger_level, safeguards, scope, pathway,
source, reviewed, threading_confidence). No run_*/tools.py-specific
assumptions -- this is meant to be usable outside this repo's own script
pipeline, unlike combined_scripts_format.jsonl.

Reads training-data/combined_scripts_format.jsonl (already deduped and
tool-name-validated by merge_scripts_format.py -- run that first) so both
exports are built from the same underlying, already-cleaned row set.

Multi-turn threading is only attempted where it's actually verified
sequential in the source data:
  - source == "playbook" (playbooks/dvwa_full_chain.sh, re-encoded as one
    continuous exploit_authorized sequence, turns 1..6, one pathway) --
    grouped by pathway.
  - source == "exports" (mined directly from a real session transcript,
    turns sequential within a pathway, one pathway = one real exchange)
    -- grouped by pathway.
Everything else in pathway_generator/baseline_cleaned/nmap_commands/
logs_failure_recovery is exported as an INDEPENDENT single-turn example
even where its own `turn` field is >1 -- confirmed by inspection that e.g.
generated_pathways.jsonl's "authenticated_sqli" pathway has six rows all
at turn=2 with no turn=1 companions, i.e. `turn` there means "this example
simulates the shape of round N's prompt", not "these rows chain together".
Grouping those by pathway would silently fabricate conversations that
never happened.

EXCEPTION: individual pathway names in VERIFIED_SEQUENTIAL_PATHWAYS below
are genuinely sequential even though their `source` (pathway_generator)
is not -- this is a per-pathway allowlist, not a blanket source rule,
because within one hand-authored source file some pathways are real
matched-pair conversations and most aren't. Only add a pathway here after
confirming by inspection (like the check above) that ALL its rows for a
given turn actually continue from the previous turn, not just share a
label. See training-data/README.md's "Gold-standard plan" section.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from dataset_taxonomy import tag_row  # noqa: E402

HERE = os.path.dirname(__file__)
DATA_DIR = os.path.join(HERE, "..")
IN_PATH = os.path.join(DATA_DIR, "combined_scripts_format.jsonl")
OUT_PATH = os.path.join(DATA_DIR, "combined_chatml_format.jsonl")

SEQUENTIAL_SOURCES = {"playbook", "exports"}
VERIFIED_SEQUENTIAL_PATHWAYS = {"cve_conditional_exploit"}


def _is_sequential(row):
    return row.get("source") in SEQUENTIAL_SOURCES or row.get("pathway") in VERIFIED_SEQUENTIAL_PATHWAYS


def to_chain_content(chain):
    return json.dumps({"chain": chain}, ensure_ascii=False)


def build_conversation(rows, threading_confidence):
    messages = []
    for row in rows:
        messages.append({"role": "user", "content": row["goal"]})
        messages.append({"role": "assistant", "content": to_chain_content(row["chain"])})
    tags = tag_row(rows[-1])  # tag on the highest-danger/last turn's real content
    # take the max danger_level across all turns in the conversation, not
    # just the last -- an early recon turn shouldn't hide a later exploit turn
    all_tags = [tag_row(r) for r in rows]
    max_level_tag = max(all_tags, key=lambda t: t["danger_level"])
    safeguards = sorted(set().union(*(set(t["safeguards"]) for t in all_tags)))
    requires_override = any(t["requires_override"] for t in all_tags)
    return {
        "messages": messages,
        "metadata": {
            "pathway": rows[0].get("pathway"),
            "source": rows[0].get("source"),
            "scope": rows[0].get("scope"),
            "danger_level": max_level_tag["danger_level"],
            "danger_level_name": max_level_tag["danger_level_name"],
            "danger_rule": max_level_tag["danger_rule"],
            "safeguards": safeguards,
            "pipeline_stage": "stage_2" if requires_override else "stage_1",
            "requires_override": requires_override,
            "turns": len(rows),
            "threading_confidence": threading_confidence,
        },
    }


def main():
    with open(IN_PATH) as f:
        rows = [json.loads(line) for line in f if line.strip()]

    conversations = []

    sequential = [r for r in rows if _is_sequential(r)]
    standalone = [r for r in rows if not _is_sequential(r)]

    # SEQUENTIAL_SOURCES (playbook/exports) group cleanly on (source,
    # pathway) alone -- each pathway there is already exactly one real
    # conversation, confirmed by inspection. VERIFIED_SEQUENTIAL_PATHWAYS
    # is different: a pathway_generator pathway name can legitimately be
    # reused across several independent target/turn-1 starts (e.g.
    # cve_conditional_exploit's two separate matched-pair scenarios), so
    # those need the goal's stated target folded into the key too, or two
    # unrelated 2-turn pairs would wrongly merge into one fabricated
    # 4-turn conversation. Only pathway_generator's rows reliably start
    # every turn with "Target: X Port: Y ..." -- exports' turn>=2 goals
    # are free-flowing narrative continuations with no such prefix, so
    # applying this same extraction there would (and, when tried, did)
    # break their otherwise-correct single-pathway grouping instead.
    by_pathway = {}
    for r in sequential:
        if r.get("pathway") in VERIFIED_SEQUENTIAL_PATHWAYS:
            target = (r.get("goal") or "").split("Port:")[0].split("Target:")[-1].strip()
            key = (r.get("source"), r.get("pathway"), target)
        else:
            key = (r.get("source"), r.get("pathway"))
        by_pathway.setdefault(key, []).append(r)
    for key, group in by_pathway.items():
        group.sort(key=lambda r: r.get("turn") or 0)
        conversations.append(build_conversation(group, "verified_sequential"))

    for r in standalone:
        conversations.append(build_conversation([r], "independent_sample"))

    with open(OUT_PATH, "w") as f:
        for c in conversations:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")

    danger_counts = {}
    safeguard_counts = {}
    for c in conversations:
        m = c["metadata"]
        danger_counts[m["danger_level_name"]] = danger_counts.get(m["danger_level_name"], 0) + 1
        for s in m["safeguards"]:
            safeguard_counts[s] = safeguard_counts.get(s, 0) + 1

    print(f"Wrote {len(conversations)} conversations ({len(rows)} underlying turns) to {OUT_PATH}")
    print(f"  {len(by_pathway)} verified-sequential multi-turn conversations "
          f"({sum(len(g) for g in by_pathway.values())} turns)")
    print(f"  {len(standalone)} independent single-turn samples")
    print("\ndanger_level distribution:")
    for name, count in sorted(danger_counts.items()):
        print(f"  {name}: {count}")
    print("\nsafeguard tag distribution:")
    for name, count in sorted(safeguard_counts.items()):
        print(f"  {name}: {count}")


if __name__ == "__main__":
    main()
