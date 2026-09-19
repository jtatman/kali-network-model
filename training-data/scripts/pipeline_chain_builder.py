#!/usr/bin/env python3
"""Stage-1 -> stage-2 pipeline-chain-building harness for generating more
real, live-verified multi-turn fine-tune examples against the lab.

Gated by CONFIG.ALLOW_FULL_PIPELINE_CHAINS (see .env.example) -- this is
the "flag that needs to be overtly overridden" for full pipelines. False
by default: running a recipe here executes its stage-1 step(s) for real
against the configured target, then STOPS and records a stage-1-only row
instead of touching stage 2, regardless of what the recipe defines. Set
ALLOW_FULL_PIPELINE_CHAINS=true in .env only when pointed at a target
you're authorized to run the full chain against (e.g. a local
known-vulnerable lab container) -- the harness has no target allowlist of
its own; the override is a deliberate, repo-wide opt-in, not per-target.

Deliberately separate from agent.py's live engage/run_attack_loop path,
which this flag does NOT affect either way -- see CONFIG.ALLOW_FULL_PIPELINE_CHAINS's
own docstring in config.py. This harness is ONLY for building more
training-data rows, never a REPL command, and it uses the same production
tools.py/remote_exec.py execution path as agent.py -- no parallel exec
mechanism, just a stage-boundary check in front of it.

Recipes are now TEMPLATE-generated (pipeline_recipes.py), not hand-authored
one at a time -- see that module's docstring for the template/variation-
grid design. This is meant to be run repeatedly, on different machines
(each pointed at its own lab via its own .env), with the real output
farmed back for review/merging rather than every recipe being hand-tested
in one session first. A stage-1 step that fails for real gets recorded
with `stage_1_failed: true` and excluded from the trusted merge (see
merge_scripts_format.py) but KEPT in the output file -- a wrong-syntax or
unexpected-output failure is itself useful negative signal, not a wasted
run.

Run: python3 training-data/scripts/pipeline_chain_builder.py [options]
  --list              Print every candidate recipe (pathway, verified
                       status, target) and exit without running anything.
  --limit N            Run at most N recipes this invocation.
  --filter SUBSTRING   Only run recipes whose template_id contains this.
  --verified-only       Only run templates marked verified=True.
  --shuffle             Randomize recipe order (useful when farming the
                        same candidate list out across multiple machines
                        so they don't all start with the same subset).
  --out PATH            Write to a different output file than the default
                        (e.g. a per-machine file to merge later with
                        merge_pipeline_chain_outputs.py).
"""
import argparse
import json
import os
import random
import re
import sys
from dotenv import load_dotenv


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from config import CONFIG, ConfigError  # noqa: E402
from tools import ToolExecutor  # noqa: E402

sys.path.insert(0, os.path.dirname(__file__))
from dataset_taxonomy import tag_row  # noqa: E402
from pipeline_recipes import all_recipes  # noqa: E402

HERE = os.path.dirname(__file__)
DEFAULT_OUT_PATH = os.path.join(HERE, "..", "pipeline_chains_generated.jsonl")
# Not committed (gitignored, like .env) -- each machine's own copy, absent
# by default so the main checkout's docker-lab targets keep working with
# zero setup. See pipeline_targets.example.json.
DEFAULT_TARGETS_FILE = os.path.join(HERE, "pipeline_targets.json")

load_dotenv()

def _goal_for_stage1(recipe):
    return f"Target: {recipe['target']}. Identify open ports and known vulnerabilities."


def _goal_for_stage2(recipe, stage1_summary):
    condition_check = recipe.get("condition_check")
    if condition_check:
        authorization_note = (
            f"SCOPE: exploit_conditional -- authorized ONLY because stage 1's real output "
            f"matched the required condition ({condition_check!r}); this is not a blanket "
            "go-ahead, the same recipe with a different stage-1 result would have stayed "
            "recon_only."
        )
    else:
        authorization_note = (
            "SCOPE: exploit_authorized (ALLOW_FULL_PIPELINE_CHAINS) -- proceed to stage 2 "
            "(craft/deploy the exploit the stage-1 identification pointed at)."
        )
    return (
        f"Target: {recipe['target']}. Stage-1 identification complete:\n{stage1_summary}\n\n"
        f"{authorization_note}"
    )


def _summarize(step, result):
    if result.get("status") == "success":
        body = result.get("stdout", "")
    else:
        body = f"{result.get('error_type')}: {result.get('message', '')}"
    return f"  [{step['tool']}] {result.get('status')}: {body[:300]}"


def run_recipe(recipe, executor):
    """Returns (rows_to_write, all_step_results) for one recipe."""
    rows = []
    stage1_results = []
    for step in recipe["stage_1"]:
        params = {k: v for k, v in step.items() if k != "tool"}
        result = executor.execute_tool(step["tool"], params)
        stage1_results.append((step, result))

    stage1_summary = "\n".join(_summarize(s, r) for s, r in stage1_results)
    stage1_failed = any(r.get("status") != "success" for _, r in stage1_results)
    row1 = {
        "goal": _goal_for_stage1(recipe),
        "chain": recipe["stage_1"],
        "scope": "recon_only",
        "pathway": recipe["pathway"],
        "turn": 1,
        "source": "pipeline_chain_builder",
        "template_id": recipe.get("template_id"),
        "template_verified": recipe.get("verified"),
    }
    if stage1_failed:
        # Kept in the output file (real negative signal -- a wrong-syntax
        # or unexpected-output attempt is worth reviewing, e.g. for
        # failure_recovery.jsonl-style pairing), but excluded from the
        # trusted merge -- see merge_scripts_format.py's SOURCES handling.
        row1["stage_1_failed"] = True
    rows.append(row1)

    if stage1_failed or not recipe.get("stage_2"):
        return rows, stage1_results

    if not CONFIG.ALLOW_FULL_PIPELINE_CHAINS:
        row1["stage_2_blocked_pending_override"] = True
        print(
            f"[{recipe['pathway']}] stage 1 complete, stage 2 BLOCKED "
            "(ALLOW_FULL_PIPELINE_CHAINS=false) -- set it true in .env to run this live."
        )
        return rows, stage1_results

    # exploit_conditional (vs. plain exploit_authorized): a recipe can set
    # `condition_check` to a regex that must match stage 1's REAL captured
    # output -- e.g. "a specific CVE ID appeared" or "a credential string
    # was found" -- not just "the override flag happens to be set". This
    # is the one piece of exploit_conditional that CAN be enforced
    # deterministically (unlike recon_only's full tool-level gate): it
    # only works because the condition here is a simple pattern match
    # against real text, not an open-ended judgment call. A recipe author
    # writing a `condition_check` that doesn't actually correspond to
    # something meaningful in stage 1's output defeats the point -- this
    # is a narrow mechanism, not a general policy engine.
    condition_check = recipe.get("condition_check")
    scope = "exploit_conditional" if condition_check else "exploit_authorized"
    if condition_check and not re.search(condition_check, stage1_summary):
        row1["stage_2_blocked_pending_override"] = True
        row1["stage_2_blocked_reason"] = "condition_check did not match stage-1 output"
        print(
            f"[{recipe['pathway']}] stage 1 complete, stage 2 BLOCKED -- "
            f"condition_check {condition_check!r} did not match real stage-1 output "
            "(override was set, but the specific condition this recipe requires wasn't met)."
        )
        return rows, stage1_results

    stage2_results = []
    for step in recipe["stage_2"]:
        params = {k: v for k, v in step.items() if k != "tool"}
        result = executor.execute_tool(step["tool"], params)
        stage2_results.append((step, result))
    stage2_failed = any(r.get("status") != "success" for _, r in stage2_results)
    row2 = {
        "goal": _goal_for_stage2(recipe, stage1_summary),
        "chain": recipe["stage_2"],
        "scope": scope,
        "pathway": recipe["pathway"],
        "turn": 2,
        "source": "pipeline_chain_builder",
        "template_id": recipe.get("template_id"),
        "template_verified": recipe.get("verified"),
    }
    if stage2_failed:
        row2["stage_1_failed"] = True  # reuses the same merge-exclusion flag name deliberately
    rows.append(row2)
    return rows, stage1_results + stage2_results


def parse_args():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--list", action="store_true")
    p.add_argument("--limit", type=int, default=None)
    p.add_argument("--filter", type=str, default=None)
    p.add_argument("--verified-only", action="store_true")
    p.add_argument("--shuffle", action="store_true")
    p.add_argument("--out", type=str, default=DEFAULT_OUT_PATH)
    p.add_argument(
        "--targets-file", type=str, default=DEFAULT_TARGETS_FILE,
        help=(
            "JSON file mapping {template_id}__v{n} -> {field: override_value}, "
            "applied before template substitution. Lets a per-machine copy "
            "remap this repo's docker-lab IPs to whatever that machine can "
            "actually reach, without editing pipeline_recipes.py. See "
            "pipeline_targets.example.json."
        ),
    )
    return p.parse_args()


def _load_target_overrides(path):
    if not path or not os.path.exists(path):
        return {}
    with open(path) as f:
        data = json.load(f)
    return {k: v for k, v in data.items() if not k.startswith("_")}


def main():
    args = parse_args()
    target_overrides = _load_target_overrides(args.targets_file)
    if target_overrides:
        print(f"Loaded {len(target_overrides)} target override(s) from {args.targets_file}")
    recipes = all_recipes(target_overrides)

    if args.filter:
        recipes = [r for r in recipes if args.filter in r["template_id"]]
    if args.verified_only:
        recipes = [r for r in recipes if r["verified"] is True]
    if args.shuffle:
        random.shuffle(recipes)
    if args.limit:
        recipes = recipes[: args.limit]

    if args.list:
        print(f"{len(recipes)} candidate recipes:")
        for r in recipes:
            print(f"  {r['pathway']:45s} verified={r['verified']!s:15s} target={r['target']}")
        return

    try:
        CONFIG.validate()
    except ConfigError as e:
        print(f"Configuration error -- fix .env before running this harness:\n{e}")
        sys.exit(1)

    print(
        f"ALLOW_FULL_PIPELINE_CHAINS={CONFIG.ALLOW_FULL_PIPELINE_CHAINS} "
        f"(EXEC_MODE={CONFIG.EXEC_MODE}, DOCKER_CONTAINER={CONFIG.DOCKER_CONTAINER})\n"
        f"Running {len(recipes)} recipe(s), writing to {args.out}"
    )

    executor = ToolExecutor()
    all_rows = []
    ok_count = 0
    fail_count = 0
    for recipe in recipes:
        print(f"\n=== {recipe['pathway']} (target={recipe['target']}) ===")
        rows, results = run_recipe(recipe, executor)
        for step, result in results:
            ok = result.get("status") == "success"
            print(f"  [{step['tool']}] {'OK' if ok else 'FAILED: ' + str(result.get('error_type'))}")
        if any(r.get("stage_1_failed") for r in rows):
            fail_count += 1
        else:
            ok_count += 1
        all_rows.extend(rows)

    with open(args.out, "a") as f:
        for row in all_rows:
            enriched = dict(row)
            enriched["_tags"] = tag_row(row)
            f.write(json.dumps(enriched, ensure_ascii=False) + "\n")

    print(
        f"\nAppended {len(all_rows)} rows to {args.out} "
        f"({ok_count} recipes clean, {fail_count} had a real failure -- "
        "both kept for review, only clean ones are merge-eligible)."
    )


if __name__ == "__main__":
    main()
