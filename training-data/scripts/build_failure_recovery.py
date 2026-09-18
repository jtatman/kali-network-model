#!/usr/bin/env python3
"""Hand-curated "explicit failure -> correct recovery" examples, sourced from
real error messages found by classifying logs_extracted_UNREVIEWED.jsonl's
95 rows by real_outcomes.error_type (33 all_success, 29 no_outcomes, 27
mixed, 6 all_error). Unlike extract_logs.py's raw dump, every example here
IS reviewed and IS ready to train on: each pairs a REAL captured error
message with a manually-verified correct fix, not a guess.

These are multi-turn ROUND 2 examples: the goal includes the real round-1
failure verbatim (matching exactly how run_attack_loop's own round-N
continuation prompt embeds prior real tool output), and the target chain is
the corrected action -- teaching the model to recognize and recover from
these specific, now-understood mistake classes, not just to avoid them
outright (avoidance alone doesn't teach WHAT to do once they've already
happened, which is the realistic runtime situation this represents).

Five real, repeated (not one-off) mistake classes found in the logs:
1. run_curl/run_ffuf called with param name "target" instead of the real
   "url" -- confirmed 7+ separate occurrences across sessions, the single
   most common failure in the whole log set.
2. Hallucinated/nonexistent wordlist paths for gobuster/ncrack/hydra (made-
   up subdirectories like "Discovery/gobuster/v3.0/" or "Gobuster/urls/",
   or the wrong rockyou.txt location -- it's under /usr/share/wordlists/,
   not /usr/share/seclists/, despite SYSTEM_PROMPT already saying so).
3. run_gobuster's wordlist field stuffed with invented flag text instead of
   a real file path (a hallucinated command fragment, not a wordlist).
4. run_hydra called with required params (username, wordlist) missing
   entirely, despite SYSTEM_PROMPT explicitly saying never to leave them
   blank.
5. run_john referencing a hash file that was never actually created via
   write_file first -- the model invented a plausible-sounding filename
   instead of using a real one.

Run: python3 training-data/scripts/build_failure_recovery.py
Writes: training-data/failure_recovery.jsonl
"""
import json
import os

OUT_PATH = os.path.join(os.path.dirname(__file__), "..", "failure_recovery.jsonl")


def roundN_goal(base_goal, round_num, failure_line):
    return (
        f"{base_goal}\n\n"
        f"You have already tried {round_num - 1} round(s) on this port with no "
        f"breach yet:\nRound {round_num - 1}:\n{failure_line}\n\n"
        f"Build on these REAL results -- e.g. if a directory or file was "
        f"discovered, fetch or inspect it (run_curl/run_command); if a login "
        f"form or endpoint was found, attack it directly. Do NOT repeat a "
        f"tool+target you already ran that produced no new lead. If you "
        f"genuinely have nothing further to try, respond with an empty "
        f'chain: {{"chain": []}}.'
    )


def attack_base_goal(target, port):
    return (
        f"Target: {target} Port: {port}. Failed ports: []. "
        f"Exploit this port with any available tool. Try multiple tools if needed."
    )


examples = []


def add(mistake_class, target, port, wrong_step, real_error, correct_chain):
    base = attack_base_goal(target, port)
    failure_line = f"  [{wrong_step['tool']}] FAILED: {real_error}"
    examples.append({
        "goal": roundN_goal(base, 2, failure_line),
        "chain": correct_chain,
        "scope": "exploit_authorized",
        "pathway": f"failure_recovery_{mistake_class}",
        "turn": 2,
        "source": "logs_failure_recovery",
        "reviewed": True,
        "wrong_attempt": wrong_step,  # kept for reference, not part of the training pair itself
    })


# 1. curl/ffuf: "target" instead of "url" -- the single most common real
# mistake found (7+ occurrences across multiple sessions).
add("wrong_param_name_curl", "172.17.0.12", "80",
    {"tool": "run_curl", "target": "http://172.17.0.12/config/config.inc.php.bak", "method": "GET"},
    "No URL specified for curl",
    [{"tool": "run_curl", "url": "http://172.17.0.12/config/config.inc.php.bak", "method": "GET"}])

add("wrong_param_name_ffuf", "172.17.0.10", "3000",
    {"tool": "run_ffuf", "target": "http://172.17.0.10:3000",
     "wordlist": "/usr/share/seclists/Ffuf/wordlists/common.txt", "param": "FUZZ"},
    "No URL specified",
    [{"tool": "run_ffuf", "url": "http://172.17.0.10:3000",
      "wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt", "param": "FUZZ"}])

# 2. Hallucinated/wrong wordlist paths.
add("wrong_wordlist_path_gobuster", "172.17.0.10", "80",
    {"tool": "run_gobuster", "target": "172.17.0.10",
     "wordlist": "/usr/share/seclists/Discovery/gobuster/v3.0/common.txt", "mode": "dir"},
    'wordlist file "/usr/share/seclists/Discovery/gobuster/v3.0/common.txt" does not exist',
    [{"tool": "run_gobuster", "target": "http://172.17.0.10",
      "wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt", "mode": "dir"}])

add("wrong_wordlist_path_rockyou", "172.17.0.12", "80",
    {"tool": "run_hydra", "target": "172.17.0.12", "service": "http-post-form",
     "path": "/login.php", "body": "username=^USER^&password=^PASS^&Login=Submit",
     "wordlist": "/usr/share/seclists/rockyou.txt", "threads": 16},
    "File for passwords not found: /usr/share/seclists/rockyou.txt",
    [{"tool": "run_hydra", "target": "172.17.0.12", "service": "http-post-form",
      "path": "/login.php", "body": "username=^USER^&password=^PASS^&Login=Submit",
      "wordlist": "/usr/share/wordlists/rockyou.txt", "threads": 16}])

# 3. Wordlist field stuffed with invented flag text instead of a real path.
add("hallucinated_wordlist_value", "172.17.0.12", "80",
    {"tool": "run_gobuster", "target": "http://172.17.0.12/docs/",
     "wordlist": "/usr/share/seclists/Discovery/Web-Content/gobust.py --ext=php,txt,jsp,aspx,html,js,css,bak,inc,dist"},
    "flag provided but not defined: -ext",
    [{"tool": "run_gobuster", "target": "http://172.17.0.12/docs/",
      "wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt", "mode": "dir"}])

# 4. hydra missing required params entirely.
add("hydra_missing_required_params", "172.17.0.10", "22",
    {"tool": "run_hydra", "target": "172.17.0.10", "service": "ssh"},
    "Missing parameters: target, service, username, and wordlist are required",
    [{"tool": "run_hydra", "target": "172.17.0.10", "service": "ssh", "username": "root",
      "wordlist": "/usr/share/seclists/Passwords/Common-Credentials/darkweb2017_top-1000.txt"}])

# 5. john referencing a hash file that was never actually written.
add("john_nonexistent_hash_file", "172.17.0.12", "80",
    {"tool": "run_john", "hash_file": "leaked_credentials.txt",
     "wordlist": "/usr/share/seclists/Passwords/Common-Credentials/darkweb2017_top-1000.txt"},
    "stat: leaked_credentials.txt: No such file or directory",
    [{"tool": "write_file", "filename": "/tmp/leaked_credentials.txt",
      "content": "admin:5f4dcc3b5aa765d61d8327deb882cf99"},
     {"tool": "run_john", "hash_file": "/tmp/leaked_credentials.txt",
      "wordlist": "/usr/share/seclists/Passwords/Common-Credentials/darkweb2017_top-1000.txt",
      "format": "Raw-MD5"}])

if __name__ == "__main__":
    with open(OUT_PATH, "w") as f:
        for ex in examples:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")
    print(f"Wrote {len(examples)} failure-recovery examples to {OUT_PATH}")
