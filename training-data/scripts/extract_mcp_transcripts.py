#!/usr/bin/env python3
"""Extracts native tool-calling fine-tune data ("Split B" -- see
kali-network-model-nrk) from raven-engage sessions, into
{"messages": [...]} JSONL rows -- the standard multi-turn tool-calling SFT
shape, directly re-playable through the same Ollama /api/chat mechanism
raven_agent.py already uses.

Two sources, clearly kept apart:

1. **Primary, full-fidelity**: logs/raven_transcripts/raven_*.json --
   written by raven_agent.py's own _save_transcript() (added alongside
   this script) directly from the real in-memory `messages` list every
   run produces from now on. Nothing to reconstruct; this is the actual
   wire conversation.

2. **Secondary, best-effort reconstruction**: legacy logs/session_*.json
   files from raven-engage runs that predate _save_transcript() (this
   repo's first four raven-engage tests, 2026-09-26, before this script
   existed). AgentLogger's own JSON log is LOSSY for this purpose -- it
   records tool_call/decision EVENTS (tool name, parameters, result
   text), not the raw messages list, so this rebuilds an approximation:
   one assistant tool_calls turn per logged tool_call event (matches
   every session inspected by hand so far -- each round issued exactly
   one tool call), the current raven_agent.SYSTEM_PROMPT standing in for
   whatever the actual system prompt was at the time (not recoverable --
   it has since changed, e.g. the launch_scan guidance added after the
   first four runs). Rows from this path are tagged "_reconstructed":
   true so they're never silently blended with genuine wire transcripts.

Most of logs/session_*.json predates raven-engage entirely (this repo's
much older engage/recon sessions, driving tools.py's completely different
tool vocabulary via CHAIN_JSON_SCHEMA) -- those must NOT be mistaken for
raven-engage data. Detected and skipped by checking for at least one
tool_call event using a tool name that only exists in raven-nest-mcp's
vocabulary, never in tools.SUPPORTED_TOOLS (confirmed no overlap: e.g.
ping_target/http_request/save_finding/generate_report/list_targets/
set_engagement/launch_scan/get_scan_status/get_scan_results/msf_search).

Usage:
    python3 training-data/scripts/extract_mcp_transcripts.py --out training-data/mcp_transcripts.jsonl
    python3 training-data/scripts/extract_mcp_transcripts.py --legacy-only --out /tmp/legacy_only.jsonl
"""

import argparse
import glob
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import raven_agent  # noqa: E402  (path insert must come first)

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
TRANSCRIPT_DIR = raven_agent.TRANSCRIPT_DIR
LEGACY_LOG_DIR = os.path.join(REPO_ROOT, "logs")

# Tool names that only exist in raven-nest-mcp's 46-tool vocabulary, never
# in tools.SUPPORTED_TOOLS -- presence of any one of these in a legacy
# session log's tool_call events is how a raven-engage session is told
# apart from this repo's much older engage/recon sessions (which share some
# tool NAMES, e.g. run_nmap/run_sqlmap/run_hydra/run_httpx, but never these).
RAVEN_ONLY_MARKERS = {
    "ping_target", "http_request", "save_finding", "get_finding",
    "list_findings", "list_findings_by_scan", "delete_finding",
    "generate_report", "set_engagement", "list_engagements",
    "get_target_info", "list_targets", "diff_scans", "launch_scan",
    "get_scan_status", "get_scan_results", "cancel_scan", "list_scans",
    "msf_search", "msf_module_info", "msf_exploit", "msf_auxiliary",
    "msf_sessions", "msf_post", "run_whatweb", "run_feroxbuster",
    "run_dnsrecon", "run_wpscan", "run_dalfox", "run_gitleaks",
    "run_trufflehog", "run_testssl", "run_enum4linux_ng", "run_netexec",
}


def _extract_primary(path):
    """A logs/raven_transcripts/raven_*.json file -- already the exact
    real `messages` list, no reconstruction needed."""
    with open(path) as f:
        data = json.load(f)
    return {
        "messages": data["messages"],
        "_source": os.path.basename(path),
        "_session_id": data.get("session_id"),
        "_target": data.get("target"),
        "_outcome": data.get("outcome"),
        "_model": data.get("model"),
        "_reconstructed": False,
    }


def _is_raven_session(events):
    return any(
        e.get("event_type") == "tool_call" and e.get("data", {}).get("tool") in RAVEN_ONLY_MARKERS
        for e in events
    )


def _reconstruct_legacy(path):
    """A logs/session_*.json AgentLogger file from before _save_transcript()
    existed. Returns None if this isn't a raven-engage session at all (the
    much more common case -- most of logs/ predates raven-engage)."""
    with open(path) as f:
        session = json.load(f)
    events = session.get("events", [])
    if not _is_raven_session(events):
        return None

    messages = [{"role": "system", "content": raven_agent.SYSTEM_PROMPT}]
    goal = None
    final_content = None
    for e in events:
        data = e.get("data", {})
        if e.get("event_type") == "tool_call":
            tool = data.get("tool")
            params = data.get("parameters", {})
            result = data.get("result", "")
            if goal is None:
                # First tool_call event implies a user turn preceded it in
                # the real conversation; the real goal text isn't in this
                # event, only recoverable from the session's final decision
                # event below -- inserted once goal is known, see below.
                pass
            messages.append({
                "role": "assistant",
                "content": "",
                "tool_calls": [{"function": {"name": tool, "arguments": params}}],
            })
            messages.append({"role": "tool", "content": result if isinstance(result, str) else json.dumps(result)})
        elif e.get("event_type") == "decision":
            goal = data.get("reasoning")
            chosen = data.get("chosen_action", {})
            final_content = chosen.get("final") if isinstance(chosen, dict) else None

    # goal is only known from the (last) decision event, logged once at
    # the very end in raven_agent.py -- insert the user turn at position 1
    # now that it's recoverable, rather than leaving it out entirely.
    messages.insert(1, {"role": "user", "content": goal or "(goal not recorded in this legacy log)"})
    if final_content:
        messages.append({"role": "assistant", "content": final_content})

    session_id = session.get("session_id")
    return {
        "messages": messages,
        "_source": os.path.basename(path),
        "_session_id": session_id,
        "_target": None,
        "_outcome": "final_answer" if final_content else "unknown",
        "_model": None,
        "_reconstructed": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, help="Output JSONL path")
    parser.add_argument("--legacy-only", action="store_true", help="Only reconstruct from legacy logs/session_*.json, skip primary transcripts")
    parser.add_argument("--primary-only", action="store_true", help="Only use logs/raven_transcripts/, skip legacy reconstruction")
    args = parser.parse_args()

    rows = []
    primary_session_ids = set()
    excluded_session_ids = set()
    skipped_infra_failures = 0
    if not args.legacy_only:
        for path in sorted(glob.glob(os.path.join(TRANSCRIPT_DIR, "raven_*.json"))):
            row = _extract_primary(path)
            # A session killed mid-engagement by an infra fault (most often
            # the shared Ollama host timing out under concurrent load, see
            # kali-network-model-2yd) is not a real model decision trace --
            # its last turn is a truncation artifact, not a genuine stop/
            # give-up. Excluded (and NOT allowed to fall through to a legacy
            # reconstruction below, which would hit the exact same truncated
            # events) so the corpus doesn't learn "this is what a negative
            # outcome looks like" from an engagement that never really got a
            # chance to run.
            if row["_outcome"] == "model_call_failed":
                skipped_infra_failures += 1
                excluded_session_ids.add(row["_session_id"])
                continue
            rows.append(row)
            primary_session_ids.add(row["_session_id"])

    if not args.primary_only:
        skipped_dupes = 0
        for path in sorted(glob.glob(os.path.join(LEGACY_LOG_DIR, "session_*.json"))):
            row = _reconstruct_legacy(path)
            if row is None:
                continue
            # A primary (full-fidelity) transcript for this exact session
            # already exists -- e.g. _save_transcript() ran successfully
            # for a session whose logs/session_*.json ALSO predates it in
            # this same extraction pass. Never emit both for one session.
            if row["_session_id"] in primary_session_ids:
                skipped_dupes += 1
                continue
            if row["_session_id"] in excluded_session_ids:
                skipped_infra_failures += 1
                continue
            rows.append(row)
        if skipped_dupes:
            print(f"Skipped {skipped_dupes} legacy reconstruction(s) already covered by a primary transcript")

    if skipped_infra_failures:
        print(f"Skipped {skipped_infra_failures} transcript(s)/reconstruction(s) with outcome=model_call_failed (infra timeout, not real model behavior)")

    with open(args.out, "w") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")

    n_primary = sum(1 for r in rows if not r["_reconstructed"])
    n_legacy = sum(1 for r in rows if r["_reconstructed"])
    print(f"Wrote {len(rows)} row(s) to {args.out} ({n_primary} primary, {n_legacy} reconstructed-legacy)")


if __name__ == "__main__":
    main()
