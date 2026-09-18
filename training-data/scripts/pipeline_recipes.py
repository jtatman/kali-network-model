#!/usr/bin/env python3
"""Recipe TEMPLATES for pipeline_chain_builder.py, separated from the
runner so the recipe list can grow into the hundreds without touching
execution logic. This is the "more optimal way" than hand-authoring one
concrete recipe at a time: each template is ONE validated (or
candidate-for-validation) skeleton plus a `variations` list of parameter
substitutions, expanded at runtime into many concrete recipes.

A template's `stage_1`/`stage_2`/`condition_check` fields may contain
`{placeholder}` tokens in any string value (recursively, including nested
dict/list values) -- `expand_templates()` substitutes them per-variation
using Python's str.format(). This produces STRUCTURED tool calls (real
run_hydra/run_gobuster/etc. params, not just run_command shell strings)
wherever the underlying tool has one -- directly addresses the tool-
imbalance gap (see README's Known Gaps), unlike the shell-pipe-only
recipes needed for tools with no structured multi-step story (masscan/
naabu piping into nuclei/searchsploit).

`verified` on a template is honesty bookkeeping, not a gate:
  - True: this exact chained command was run live and confirmed working
    this session (see README's massaging-gotchas notes).
  - "components_only": every individual step has been verified live
    (elsewhere, e.g. exports_transcript2_extracted.jsonl's real WordPress
    hydra run), but this EXACT chained sequence hasn't been re-run as one
    harness invocation yet.
  - False: a candidate combination, plausible from documented tool
    syntax, not yet run against a real target at all. This is
    deliberately included, not withheld -- pipeline_chain_builder.py now
    tracks and records real failures (wrong syntax, tool not installed,
    unexpected output shape) as legitimate negative training signal
    rather than silently discarding them, so an unverified template
    "failing informatively" when actually run is itself useful, not a
    wasted attempt. This is the mechanism that makes farming this out
    across multiple machines/sessions productive without every template
    needing hand-verification first.

Run `python3 pipeline_chain_builder.py --list` to see the full expanded
candidate count before running anything.
"""

# --- Single-stage (stage-1/identification only) templates ------------------
# These never touch stage 2 and never need CONFIG.ALLOW_FULL_PIPELINE_CHAINS.
SINGLE_STAGE_TEMPLATES = [
    {
        "template_id": "naabu_nuclei_pipe",
        "verified": True,
        "stage_1": [
            {
                "tool": "run_command",
                "command": (
                    "naabu -host {target} -silent | tee /tmp/naabu_out.txt "
                    "| nuclei -silent -severity {severity} -t {template_path}"
                ),
            },
        ],
        "variations": [
            {"target": "172.17.0.12", "severity": "critical,high,medium", "template_path": "http/"},
            {"target": "172.17.0.12", "severity": "critical,high", "template_path": "http/exposures/"},
            {"target": "172.17.0.12", "severity": "critical,high,medium,low", "template_path": "http/misconfiguration/"},
            {"target": "172.25.0.3", "severity": "critical,high,medium", "template_path": "http/"},
            {"target": "172.25.0.4", "severity": "critical,high,medium", "template_path": "http/"},
            {"target": "172.25.0.6", "severity": "critical,high,medium", "template_path": "http/"},
            {"target": "172.26.0.3", "severity": "critical,high,medium", "template_path": "http/"},
            {"target": "172.26.0.3", "severity": "critical,high,medium,low", "template_path": "http/exposures/"},
        ],
    },
    {
        "template_id": "naabu_nuclei_pipe_dast",
        # -dast is real (confirmed running cleanly this session per
        # exports/master.md) but a genuinely different template category
        # (dast/) -- a distinct variation axis, not a flag tweak on the
        # above.
        "verified": False,
        "stage_1": [
            {
                "tool": "run_command",
                "command": (
                    "naabu -host {target} -silent | tee /tmp/naabu_out.txt "
                    "| nuclei -silent -dast -t dast/{dast_category}/"
                ),
            },
        ],
        "variations": [
            {"target": "172.17.0.12", "dast_category": "http"},
            {"target": "172.26.0.3", "dast_category": "http"},
        ],
    },
    {
        "template_id": "masscan_nmap_searchsploit_chain",
        "verified": True,
        "stage_1": [
            {
                "tool": "run_command",
                "command": (
                    "masscan -p{ports} {target} --rate {rate} --wait 0 "
                    "-oG /tmp/masscan_out.txt >/dev/null 2>&1 && "
                    "grep '^Timestamp' /tmp/masscan_out.txt | "
                    "awk -F'\\t' '{{host=$2; sub(/^Host: /,\"\",host); sub(/ \\(\\)$/,\"\",host); "
                    "port=$3; sub(/^Ports: /,\"\",port); split(port,pp,\"/\"); print host\":\"pp[1]}}' "
                    "| tee /tmp/massaged_targets.txt >/dev/null && "
                    "while IFS=: read -r host port; do "
                    "nmap -sV -p\"$port\" --open -oG - \"$host\" 2>/dev/null | grep 'Ports:'; "
                    "done < /tmp/massaged_targets.txt | "
                    "awk -F'\\t' '{{n=split($2,f,\"/\"); if (f[7] != \"\") print f[7]}}' | "
                    "sed -E 's/ \\(.*\\)//; s/ (httpd|smtpd|pop3d|imapd)( |$)/ /' | "
                    "sort -u | tee /tmp/versions_normalized.txt >/dev/null && "
                    "while read -r v; do echo \"--- $v ---\"; searchsploit \"$v\" 2>&1; done "
                    "< /tmp/versions_normalized.txt"
                ),
            },
        ],
        "variations": [
            {"target": "172.25.0.2-172.25.0.7", "ports": "21,22,25,53,80,110,143,3306,8080", "rate": "1000"},
            {"target": "172.26.0.2-172.26.0.4", "ports": "21,22,80,3306,8080", "rate": "500"},
            {"target": "172.23.0.0/24", "ports": "21,22,80,443,8080", "rate": "500"},
        ],
    },
    {
        # httpx-toolkit -> nuclei confirmed live this session (URL
        # normalization on a bare host:port works fine into nuclei's
        # input format) -- a genuinely different discovery-stage tool
        # than naabu, same downstream pipe shape.
        "template_id": "httpx_nuclei_pipe",
        "verified": "components_only",
        "stage_1": [
            {
                "tool": "run_command",
                "command": (
                    "echo '{target}:{port}' | httpx-toolkit -silent | tee /tmp/httpx_out.txt "
                    "| nuclei -silent -severity {severity} -t {template_path}"
                ),
            },
        ],
        "variations": [
            {"target": "172.17.0.12", "port": "80", "severity": "critical,high,medium", "template_path": "http/"},
            {"target": "172.26.0.3", "port": "80", "severity": "critical,high,medium", "template_path": "http/"},
            {"target": "172.25.0.4", "port": "8080", "severity": "critical,high,medium", "template_path": "http/"},
        ],
    },
    {
        # A different massaging chain than masscan's: nmap's own NSE vuln
        # scripts already surface CVE-looking strings in free text, not a
        # clean field -- massaging is a grep for the CVE-nnnn-nnnn shape,
        # deduped, piped to searchsploit. Live-verified against DVWA
        # (172.17.0.12) this pass: ran clean end to end via the real
        # harness (ToolExecutor -> tools.py -> remote_exec.py); whether it
        # actually surfaces a CVE depends on the target, same as any real
        # recon -- the syntax/pipe itself is confirmed sound.
        "template_id": "nmap_vuln_script_searchsploit",
        "verified": True,
        "stage_1": [
            {
                "tool": "run_command",
                "command": (
                    "nmap -sV --script vuln,http-enum -p{port} {target} 2>/dev/null "
                    "| tee /tmp/nmap_vuln_out.txt | grep -oE 'CVE-[0-9]{{4}}-[0-9]+' "
                    "| sort -u | tee /tmp/cves_found.txt | "
                    "while read -r cve; do echo \"--- $cve ---\"; searchsploit --cve \"$cve\" 2>&1; done"
                ),
            },
        ],
        "variations": [
            {"target": "172.17.0.12", "port": "80"},
            {"target": "172.26.0.3", "port": "80"},
            {"target": "172.25.0.3", "port": "80"},
        ],
    },
]

# --- Two-stage (stage-1 -> stage-2) templates -------------------------------
# Use STRUCTURED tool calls wherever tools.py has one (run_hydra/
# run_gobuster/run_sqlmap/...) rather than a run_command shell string --
# this is what actually closes the tool-imbalance gap. Every one of these
# needs CONFIG.ALLOW_FULL_PIPELINE_CHAINS=true (or a matching
# condition_check) to reach stage 2 when actually run.
TWO_STAGE_TEMPLATES = [
    {
        # Every sub-step here (gobuster finding login.php, curl
        # establishing a session, hydra's exact http-post-form field
        # order) was individually proven live earlier this session
        # (playbook_dvwa.jsonl / exports_transcript2) -- not yet re-run as
        # ONE harness invocation against a currently-up target.
        "template_id": "web_login_discovery_hydra_chain",
        "verified": "components_only",
        "stage_1": [
            {"tool": "run_gobuster", "target": "http://{target}", "mode": "dir"},
            {"tool": "run_curl", "url": "http://{target}/{login_path}", "method": "GET"},
        ],
        "stage_2": [
            {
                "tool": "run_hydra",
                "target": "{target}",
                "service": "http-post-form",
                "username": "{username}",
                "wordlist": "{wordlist}",
                "path": "/{login_path}",
                "body": "{form_body}",
                "failure_string": "{failure_string}",
            },
        ],
        "variations": [
            {
                "target": "172.26.0.3", "login_path": "wp-login.php", "username": "admin",
                "wordlist": "/usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt",
                "form_body": "log=^USER^&pwd=^PASS^&wp-submit=Log+In",
                "failure_string": "incorrect",
            },
            {
                "target": "172.17.0.12", "login_path": "login.php", "username": "admin",
                "wordlist": "/usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt",
                "form_body": "username=^USER^&password=^PASS^&Login=Login",
                "failure_string": "incorrect",
            },
        ],
    },
    # NOTE: an "authenticated_sqli_dump_chain" template (gobuster -> login
    # -> sqlmap with the resulting session cookie) was drafted and
    # DELIBERATELY REMOVED here, not shipped -- it needs a real PHPSESSID
    # captured from stage 1's actual login response passed into stage 2's
    # run_sqlmap `cookie` param, and this template system has no mechanism
    # for passing a dynamically-captured value between two separate
    # STRUCTURED tool calls (unlike the run_command shell-string chains
    # above, where `$host`/`$port` capture works because it's all one
    # shell invocation). A static `variations` entry can't fake this --
    # it would silently produce a literal, useless cookie string rather
    # than erroring. This is a real, currently-unaddressed architectural
    # gap for any future two-stage template that needs a stage-1-captured
    # dynamic value (a session cookie, a CSRF token, a discovered
    # credential) fed into a structured stage-2 tool call -- see README's
    # Known Gaps.
]


def _substitute(obj, variables):
    if isinstance(obj, str):
        return obj.format(**variables)
    if isinstance(obj, dict):
        return {k: _substitute(v, variables) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_substitute(v, variables) for v in obj]
    return obj


def expand_templates(templates):
    """Cross-products each template's stage_1/stage_2/condition_check
    against its own `variations` list, returning concrete recipes in the
    shape pipeline_chain_builder.run_recipe() expects
    ({"pathway", "target", "stage_1", "stage_2", "condition_check"}).
    `pathway` is `{template_id}__v{n}` so every concrete recipe has a
    distinct, traceable name back to its template and variation index."""
    recipes = []
    for template in templates:
        for i, variation in enumerate(template["variations"]):
            recipe = {
                "pathway": f"{template['template_id']}__v{i}",
                "template_id": template["template_id"],
                "verified": template["verified"],
                "target": variation.get("target", ""),
                "stage_1": _substitute(template["stage_1"], variation),
                "stage_2": _substitute(template.get("stage_2", []), variation),
            }
            if template.get("condition_check"):
                recipe["condition_check"] = _substitute(template["condition_check"], variation)
            recipes.append(recipe)
    return recipes


def all_recipes():
    return expand_templates(SINGLE_STAGE_TEMPLATES) + expand_templates(TWO_STAGE_TEMPLATES)
