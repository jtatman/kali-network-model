"""Shared danger-level / safeguard taxonomy for the standard (ChatML) export.

This taxonomy is NOT used by combined_scripts_format.jsonl (that format stays
exactly what agent.py's own prompts produce -- goal/chain/scope/pathway/turn/
source, nothing extra, since that's the "prefix each module expects" shape
tools.py/agent.py actually consume). It exists so a *different* consumer
(a general-purpose or public fine-tune, a dataset audit, a red-team-content
filter) can decide per-example whether to include something, without having
to re-derive "is this a credential brute force or a rootkit" from raw text.

Tagging here is a first-pass, rule-based heuristic over (scope, chain tool
names, chain param values, pathway name, source, goal/response text) -- NOT
a per-example hand review. Treat danger_level/safeguards as a starting point
to refine, not ground truth; see training-data/README.md's "Danger-level
taxonomy" section for the exact rules and known mis-tag risks.
"""
import re

# --- danger_level -----------------------------------------------------------
# 0 = passive_recon        -- read-only network/service discovery, no auth,
#                              no state change on the target.
# 1 = active_enumeration   -- noisier/intrusive but still read-only probing
#                              (dir/vhost brute force, NSE vuln scripts,
#                              searchsploit/metasploit *search* only).
# 2 = authenticated_access -- uses a found/derived credential or session to
#                              reach a protected resource; no destructive
#                              payload (logging in with real creds, reading
#                              an authenticated page, an FTP download).
# 3 = active_exploitation  -- code execution, injection with data
#                              modification, credential brute force/
#                              cracking, webshell upload (hydra/john/ncrack/
#                              medusa, sqlmap --dump/--os-shell/--os-pwn,
#                              metasploit use/run/exploit, RCE payloads).
# 4 = destructive_or_evasive -- malware/ransomware/keylogger/rootkit
#                              authoring, persistence, anti-forensics, EDR
#                              evasion, data destruction.
DANGER_LEVEL_NAMES = {
    0: "passive_recon",
    1: "active_enumeration",
    2: "authenticated_access",
    3: "active_exploitation",
    4: "destructive_or_evasive",
}

_LEVEL0_TOOLS = {"run_masscan", "run_nmap", "run_naabu", "run_netstat"}
_LEVEL1_TOOLS = {
    "run_nikto", "run_gobuster", "run_enum4linux", "run_subfinder",
    "run_nuclei", "run_katana", "run_ffuf", "run_httpx", "run_searchsploit",
}
_LEVEL3_TOOLS = {"run_hydra", "run_john", "run_ncrack", "run_medusa"}

# Payload/flag markers that push a normally-benign tool (run_curl, run_sqlmap,
# run_command, run_metasploit, run_setoolkit) up to level 3. Matched against
# the JSON-serialized chain, case-insensitive.
_EXPLOIT_MARKER_RE = re.compile(
    r"--dump\b|--os-shell|--os-cmd|--os-pwn|"
    r"\bsystem\s*\(|\beval\s*\(|\bexec\s*\(|"
    r"functions\.php|theme-editor|webshell|"
    r"\bshellshock\b|\(\)\s*\{\s*:;\s*\}|"  # shellshock payload shape
    r"\buse\s+exploit|\brun\s*$|\bexploit\s*$",  # metasploit use/run/exploit
    re.IGNORECASE,
)

# Level-4 content: only ever expected from raw_kali_pentest_data.jsonl's
# ~117 deliberately-kept tradecraft rows (see README's "Known gaps" --
# kept per an explicit user decision for this closed authorized lab, NOT
# filtered like the Farsi/non-English rows were). Any OTHER source hitting
# this is worth a second look, not an automatic level-4 tag.
_TRADECRAFT_RE = re.compile(
    r"\bransomware\b|\bkeylogger\b|\brootkit\b|\bworm\b|\bbackdoor\b|"
    r"\bpersistence\b|\banti-forensic|\bedr\s*evasion|\bevade\s+(?:edr|av|"
    r"antivirus)|\bwiper\b|\bdata\s+destruction\b|\bself[- ]replicat",
    re.IGNORECASE,
)


def _chain_tool_names(chain):
    return {step.get("tool") for step in chain if isinstance(step, dict)}


def classify_danger_level(row):
    """Returns (danger_level:int, matched_rule:str) for a single merged-
    corpus row (goal/chain/scope/pathway/source shape). Best-effort --
    see module docstring."""
    chain = row.get("chain") or []
    tools = _chain_tool_names(chain)
    blob = " ".join([row.get("goal", ""), row.get("source", "")] + [
        str(step) for step in chain
    ])

    # Tradecraft keywords are checked against every source, not just
    # baseline_cleaned -- the ~117-row deliberate exception documented in
    # README.md lives there, but a mis-tagged source is worse than an
    # unexpected hit anywhere else, so this is not source-gated.
    if _TRADECRAFT_RE.search(blob):
        return 4, "tradecraft_keyword"

    if tools & _LEVEL3_TOOLS:
        return 3, "credential_attack_tool"
    if _EXPLOIT_MARKER_RE.search(blob):
        return 3, "exploit_payload_marker"
    if row.get("scope") == "exploit_authorized" and any(
        step.get("tool") in ("run_curl", "run_sqlmap") and step.get("cookie")
        for step in chain if isinstance(step, dict)
    ):
        return 2, "authenticated_cookie_session_access"
    if tools & _LEVEL1_TOOLS:
        return 1, "active_enumeration_tool"
    if tools & _LEVEL0_TOOLS or not tools:
        return 0, "passive_recon_tool"
    # run_curl/run_wget/run_command/write_file/read_file/run_metasploit(search)
    # with none of the above markers -- default to the scope-implied floor.
    if row.get("scope") == "exploit_authorized":
        return 2, "exploit_authorized_scope_default"
    return 1, "unclassified_default"


# --- safeguards ---------------------------------------------------------
_CRED_MATERIAL_RE = re.compile(
    r"wordpress_logged_in_|PHPSESSID=|_wpnonce=|Cookie:|password=|pwd=|"
    r"[0-9a-f]{32,}",  # long hex tokens (session ids, nonces, hashes)
    re.IGNORECASE,
)


def classify_safeguards(row):
    """Returns a sorted list[str] of safeguard tags for one merged-corpus
    row. Additive, not exclusive -- a row can carry several."""
    tags = set()
    chain = row.get("chain") or []
    blob = " ".join([row.get("goal", "")] + [str(step) for step in chain])

    tags.add("authorized_lab_only")  # true of every source in this corpus today

    if row.get("source") in ("exports", "logs"):
        tags.add("live_verified")

    if row.get("reviewed") is False:
        tags.add("unverified_outcome")

    if "restore" in row.get("goal", "").lower() or "cleanly restore" in blob.lower():
        tags.add("requires_cleanup_step")

    if _CRED_MATERIAL_RE.search(blob):
        tags.add("credential_material")

    level, _ = classify_danger_level(row)
    if level == 4:
        tags.add("tradecraft_sensitive")

    return sorted(tags)


def tag_row(row):
    level, rule = classify_danger_level(row)
    return {
        "danger_level": level,
        "danger_level_name": DANGER_LEVEL_NAMES[level],
        "danger_rule": rule,
        "safeguards": classify_safeguards(row),
    }
