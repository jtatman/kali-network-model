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

A "recipe" is a plain dict:
{
    "pathway": <name, used as the pathway field>,
    "target": <host/IP>,
    "stage_1": [{"tool": ..., <params>}, ...],   # one or more chain steps,
                                                  # always executed for real
    "stage_2": [{"tool": ..., <params>}, ...],   # only executed if the
                                                  # override is set; [] means
                                                  # this recipe is
                                                  # identification-only by
                                                  # design (e.g. naabu->nuclei)
}

Recipes live in PIPELINE_RECIPES below -- add more there as new chains get
validated against the lab (a background agent's job, per the user's
request, is exactly this: keep adding/running recipes and confirming
positive results). Output rows are appended to
training-data/pipeline_chains_generated.jsonl in the same schema as
combined_scripts_format.jsonl (goal/chain/scope/pathway/turn/source) plus
an extra `_tags` object from dataset_taxonomy.tag_row and, on a blocked
stage-1-only row, `stage_2_blocked_pending_override: true` -- so a later
curation/merge pass can tell "legitimately no stage 2" apart from
"stage 2 existed but was gated". These rows are NOT auto-merged into
combined_scripts_format.jsonl -- review them (real command outputs can
still be wrong/misleading) and run merge_scripts_format.py's SOURCES list
to pick them up once satisfied. Underrepresented tools per the fork
evaluation that ran during this session (run_masscan, run_naabu,
run_netstat, run_nikto, read_file, run_ncrack, run_medusa, run_setoolkit,
run_katana all have zero or near-zero structured examples in the merged
corpus) should be prioritized when adding new recipes.

Run: python3 training-data/scripts/pipeline_chain_builder.py
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from config import CONFIG, ConfigError  # noqa: E402
from tools import ToolExecutor  # noqa: E402

sys.path.insert(0, os.path.dirname(__file__))
from dataset_taxonomy import tag_row  # noqa: E402

HERE = os.path.dirname(__file__)
OUT_PATH = os.path.join(HERE, "..", "pipeline_chains_generated.jsonl")

# Seed recipe: naabu piped into nuclei is identification-only (both tools
# are stage 1 -- see dataset_taxonomy.STAGE handling), so it's a safe
# always-runs example regardless of the override. Add stage_2 recipes here
# once you have a specific, real exploit to pair with a real stage-1
# finding on a currently-up lab container (check `docker ps` first --
# container IPs/names drift between sessions).
PIPELINE_RECIPES = [
    {
        "pathway": "naabu_nuclei_pipe_live",
        "target": "172.17.0.12",
        "stage_1": [
            {
                "tool": "run_command",
                "command": (
                    "naabu -host 172.17.0.12 -silent | tee naabu_out.txt "
                    "| nuclei -silent -severity critical,high,medium -t http/"
                ),
            },
        ],
        "stage_2": [],
    },
    {
        # masscan and searchsploit are never used back-to-back in the
        # original 10 pathways -- this chains them anyway (per explicit
        # request) via a multi-host masscan sweep -> awk-massaged
        # host:port list -> per-host nmap -sV service ID -> a second
        # awk/sed normalization pass -> searchsploit, all as ONE
        # run_command pipe/&& string. Every stage tested live one at a
        # time against the real InfoSecWarrior stack (172.25.0.2-.7)
        # before being chained -- see training-data/README.md's "Real
        # massaging gotchas found this pass" for what each transform is
        # actually working around and why it's needed (masscan's -oG
        # format puts one port per line, not comma-joined like nmap's;
        # nmap's raw version string needs the OS-in-parens and daemon-
        # name suffix stripped before searchsploit returns anything).
        # Entirely stage-1/identification (masscan, nmap -sV, and
        # searchsploit's plain lookup mode are all recon-tier) -- no
        # stage_2 here, this recipe never needs the override.
        "pathway": "masscan_nmap_searchsploit_chain",
        "target": "172.25.0.2-172.25.0.7",
        "stage_1": [
            {
                "tool": "run_command",
                "command": (
                    "masscan -p21,22,25,53,80,110,143,3306,8080 172.25.0.2-172.25.0.7 "
                    "--rate 1000 --wait 0 -oG /tmp/masscan_out.txt >/dev/null 2>&1 && "
                    "grep '^Timestamp' /tmp/masscan_out.txt | "
                    "awk -F'\\t' '{host=$2; sub(/^Host: /,\"\",host); sub(/ \\(\\)$/,\"\",host); "
                    "port=$3; sub(/^Ports: /,\"\",port); split(port,pp,\"/\"); print host\":\"pp[1]}' "
                    "| tee /tmp/massaged_targets.txt >/dev/null && "
                    "while IFS=: read -r host port; do "
                    "nmap -sV -p\"$port\" --open -oG - \"$host\" 2>/dev/null | grep 'Ports:'; "
                    "done < /tmp/massaged_targets.txt | "
                    "awk -F'\\t' '{n=split($2,f,\"/\"); if (f[7] != \"\") print f[7]}' | "
                    "sed -E 's/ \\(.*\\)//; s/ (httpd|smtpd|pop3d|imapd)( |$)/ /' | "
                    "sort -u | tee /tmp/versions_normalized.txt >/dev/null && "
                    "while read -r v; do echo \"--- $v ---\"; searchsploit \"$v\" 2>&1; done "
                    "< /tmp/versions_normalized.txt"
                ),
            },
        ],
        "stage_2": [],
    },
]


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
    row1 = {
        "goal": _goal_for_stage1(recipe),
        "chain": recipe["stage_1"],
        "scope": "recon_only",
        "pathway": recipe["pathway"],
        "turn": 1,
        "source": "pipeline_chain_builder",
    }
    rows.append(row1)

    if not recipe.get("stage_2"):
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
    row2 = {
        "goal": _goal_for_stage2(recipe, stage1_summary),
        "chain": recipe["stage_2"],
        "scope": scope,
        "pathway": recipe["pathway"],
        "turn": 2,
        "source": "pipeline_chain_builder",
    }
    rows.append(row2)
    return rows, stage1_results + stage2_results


def main():
    try:
        CONFIG.validate()
    except ConfigError as e:
        print(f"Configuration error -- fix .env before running this harness:\n{e}")
        sys.exit(1)

    print(
        f"ALLOW_FULL_PIPELINE_CHAINS={CONFIG.ALLOW_FULL_PIPELINE_CHAINS} "
        f"(EXEC_MODE={CONFIG.EXEC_MODE}, DOCKER_CONTAINER={CONFIG.DOCKER_CONTAINER})"
    )

    executor = ToolExecutor()
    all_rows = []
    for recipe in PIPELINE_RECIPES:
        print(f"\n=== {recipe['pathway']} (target={recipe['target']}) ===")
        rows, results = run_recipe(recipe, executor)
        for step, result in results:
            ok = result.get("status") == "success"
            print(f"  [{step['tool']}] {'OK' if ok else 'FAILED: ' + str(result.get('error_type'))}")
        all_rows.extend(rows)

    with open(OUT_PATH, "a") as f:
        for row in all_rows:
            enriched = dict(row)
            enriched["_tags"] = tag_row(row)
            f.write(json.dumps(enriched, ensure_ascii=False) + "\n")

    print(f"\nAppended {len(all_rows)} rows to {OUT_PATH} (review before merging -- not auto-merged).")


if __name__ == "__main__":
    main()
