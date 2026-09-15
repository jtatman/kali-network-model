"""Minimal Markdown pentest report generator, sourced from an AgentLogger
JSON session file (see logger.py). Replaces the old exit handler's call to a
report_generator.py that was gitignored and never actually existed in this
repo -- this one is real and is called in-process from agent.py.
"""

import json
import os
import re

from config import CONFIG


def _extract_ports(output):
    """Mirrors agent.py's extract_ports. Duplicated rather than imported to
    avoid a circular import (agent.py imports this module to trigger
    generation on exit)."""
    ports = re.findall(r'(\d+)/tcp\s+open|(\d+)/udp\s+open|port\s+(\d+)|open port (\d+)', output, re.IGNORECASE)
    found = []
    for match in ports:
        port = next(p for p in match if p)
        if port not in found:
            found.append(port)
    return found


def generate(log_file_path, output_dir=None):
    """Reads an AgentLogger JSON session file and writes a Markdown pentest
    report summarizing targets, open ports found, and every tool call's
    outcome. Returns the path to the written report.
    """
    output_dir = output_dir or CONFIG.REPORT_DIR
    os.makedirs(output_dir, exist_ok=True)

    with open(log_file_path) as f:
        session = json.load(f)

    session_id = session.get("session_id", "unknown")
    started_at = session.get("started_at", "?")
    ended_at = session.get("ended_at", "?")
    events = session.get("events", [])

    tool_calls = [e for e in events if e.get("event_type") == "tool_call"]
    decisions = [e for e in events if e.get("event_type") == "decision"]
    errors = [e for e in events if e.get("event_type") == "error"]

    ports_found = []
    for e in tool_calls:
        data = e.get("data", {})
        if data.get("tool") in ("run_masscan", "run_nmap"):
            stdout = data.get("result", {}).get("stdout", "")
            for p in _extract_ports(stdout):
                if p not in ports_found:
                    ports_found.append(p)

    targets = []
    for e in tool_calls:
        target = e.get("data", {}).get("parameters", {}).get("target")
        if target and target not in targets:
            targets.append(target)

    successful = [e for e in tool_calls if e.get("data", {}).get("result", {}).get("status") == "success"]
    failed = [e for e in tool_calls if e.get("data", {}).get("result", {}).get("status") != "success"]

    lines = [
        f"# Pentest Session Report — {session_id}",
        "",
        f"- **Started:** {started_at}",
        f"- **Ended:** {ended_at}",
        f"- **Targets:** {', '.join(targets) if targets else '(none recorded)'}",
        f"- **Open ports found:** {', '.join(ports_found) if ports_found else '(none recorded)'}",
        f"- **Tool calls:** {len(tool_calls)} total, {len(successful)} succeeded, {len(failed)} failed",
        "",
        "## Tool Chain Summary",
        "",
        "| # | Tool | Params | Status | Output preview |",
        "|---|------|--------|--------|-----------------|",
    ]

    for i, e in enumerate(tool_calls, 1):
        data = e.get("data", {})
        tool = data.get("tool", "?")
        params = data.get("parameters", {})
        result = data.get("result", {})
        status = result.get("status", "?")
        preview = (result.get("stdout") or result.get("message") or "")[:120].replace("\n", " ").replace("|", "\\|")
        params_str = ", ".join(f"{k}={v}" for k, v in params.items()).replace("|", "\\|")
        lines.append(f"| {i} | {tool} | {params_str} | {status} | {preview} |")

    lines.append("")

    if errors:
        lines.append("## Errors")
        lines.append("")
        for e in errors:
            data = e.get("data", {})
            lines.append(f"- `{e.get('timestamp', '?')}` **{data.get('tool', '?')}**: {data.get('error', '?')}")
        lines.append("")

    lines.append(f"## Model Decisions ({len(decisions)})")
    lines.append("")
    for e in decisions:
        data = e.get("data", {})
        reasoning = str(data.get("reasoning", ""))[:200]
        lines.append(f"- `{e.get('timestamp', '?')}`: {reasoning}")

    report_path = os.path.join(output_dir, f"report_{session_id}.md")
    with open(report_path, "w") as f:
        f.write("\n".join(lines) + "\n")

    return report_path


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        print(generate(sys.argv[1]))
    else:
        print("Usage: python3 report_generator.py logs/session_TIMESTAMP.json")
