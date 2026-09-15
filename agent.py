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

AVAILABLE TOOLS:
- run_masscan: Fast port scanner
- run_nmap: Detailed port scanner
- run_sqlmap: SQL injection testing (params: target, level, risk)
- run_nikto: Web vulnerability scanner
- run_hydra: Credential brute forcing (params: target, service, username, wordlist)
- run_searchsploit: Find exploits
- run_command: Execute any shell command
- write_file: Write content to files
- read_file: Read file contents
- run_john: Hash cracking (needs hash_file param)
- run_gobuster: Web directory brute forcing
- run_enum4linux: SMB/Samba enumeration (params: target)
- run_medusa: Fast credential brute forcing
- run_ncrack: Network authentication cracking (params: target, service, wordlist)

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

SEARCHSPLOIT: always use "keyword" param with service name only e.g. "vsftpd 2.3.4"

Respond with a tool chain: {"chain": [{"tool": "tool_name", "param1": "value1"}]}"""

# Constrains chain[].tool to a real, current tool name -- the model can no
# longer hallucinate a nonexistent tool, which is the direct fix for the
# SUPPORTED_TOOLS/SYSTEM_PROMPT/README drift this repo had before. Ollama
# enforces this via the request's "format" field, so parse_model_response no
# longer has to defensively parse untrusted free-text JSON.
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
            },
        }
    },
    "required": ["chain"],
}

log = None
agent_logger = None
executor = tools.ToolExecutor()


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
            "temperature": 0.1,
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


def run_recon(target, memory):
    log.info(f"[SCAN] Starting recon on {target}")
    goal = f"Scan {target} with masscan then nmap to find all open ports and services."
    data = call_model(goal)
    for step in data.get("chain", []):
        output, ok = execute_step(step)
        if output:
            ports = extract_ports(output)
            if ports:
                memory.add_ports(ports)
                log.info(f"[SCAN] 🎉😄 Found {len(ports)} open ports: {ports}")
            else:
                log.warning("[SCAN] 😤💀 No ports found in output")


def run_attack_loop(target, memory, cache=None):
    log.info(f"[ATTACK] Starting attack loop on {target}")
    while memory.has_untried_ports():
        port = memory.next_untried_port()
        log.info(f"[ATTACK] ⚔️  Targeting port {port}")
        goal = (
            f"Target: {target} Port: {port}. "
            f"Failed ports: {memory.recent_failed_attacks()}. "
            f"Exploit this port with any available tool. Try multiple tools if needed."
        )
        data = call_model(goal)
        chain = data.get("chain", [])
        if not chain:
            log.warning(f"[FAIL] 😤💀 No attack chain generated for port {port}")
            memory.mark_tried(port, success=False)
            continue
        success = False
        for step in chain:
            if cache and not cache.should_attempt(step):
                log.warning(f"[MEMORY] 🚫 Skipping permanently blocked step: {step.get('tool')}")
                continue
            output, ok = execute_step(step)
            if ok and output and any(x in output.lower() for x in
                                      ["password", "login", "session", "shell", "success", "found", "valid"]):
                success = True
                if cache:
                    cache.record_success(step)
                memory.add_finding(port, step.get("tool"), output)
            elif not ok:
                if cache:
                    reason = f"tool={step.get('tool')} port={port} output_empty={not bool(output)}"
                    cache.record_failure(step, reason=reason)
        memory.mark_tried(port, success=success)
    log.info("[ATTACK] Attack loop complete")
    summary = memory.summary()
    log.info(f"[MEMORY] Final summary: {summary}")
    if memory.successful_attacks:
        log.info(f"[SUCCESS] 🎉😄 BREACHED ports: {memory.successful_attacks}")
    else:
        log.warning("[FAIL] 😤💀 No successful breaches this session")


def run_full_engagement(target):
    memory = AgentMemory()
    cache = NegativeCache()
    log.info(f"[ENGAGE] 💣 Full engagement started on {target}")
    run_recon(target, memory)
    if memory.open_ports:
        run_attack_loop(target, memory, cache)
    else:
        log.warning("[FAIL] 😤💀 No open ports found — aborting engagement")
    return memory


def execute_chain(chain, cache=None):
    for i, step in enumerate(chain, 1):
        log.info(f"[CHAIN] 🔗 Step {i} of {len(chain)}: {step.get('tool')}")
        if cache and not cache.should_attempt(step):
            log.warning(f"[MEMORY] 🚫 Skipping permanently blocked step: {step.get('tool')}")
            continue
        output, ok = execute_step(step)
        if not ok and cache:
            cache.record_failure(step, reason=f"manual chain failure, step {i}")


def main():
    log_file = bootstrap()
    cache = NegativeCache()
    log.info("[START] 🚀 AUTONOMOUS SECURITY AGENT ONLINE")
    print("=" * 60)
    print("⚔️   AUTONOMOUS SECURITY AGENT")
    print("=" * 60)
    print("Commands:")
    print("  engage <target>  - full recon + attack loop")
    print("  <any goal>       - single model query")
    print("  exit             - quit")
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
                target = goal.replace("engage ", "").strip()
                run_full_engagement(target)
                log.info("[REPORT] 📝 Engagement complete — generating report")
            else:
                data = call_model(goal)
                chain = data.get("chain", [])
                if chain:
                    execute_chain(chain, cache=cache)
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
