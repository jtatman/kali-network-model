"""Tool dispatch and command-building for the pentest agent.

Extracted from mcp_server.py's ToolExecutor -- the per-tool command strings
(hydra service names, wordlist defaults, sqlmap flags, etc.) are unchanged.
The only thing that changed is _execute_command's transport: it used to run
subprocess.run(command, shell=True) locally; it now calls remote_exec.run(),
which executes the same command string on the configured remote target
(direct SSH or SSH+docker exec, per CONFIG.EXEC_MODE). There is no longer a
Flask app/route here -- mcp_server.py as a standalone listening service is
retired; agent.py calls ToolExecutor.execute_tool() directly, in-process.
"""

import re
import shlex

import remote_exec
from config import CONFIG

# Models occasionally fold masscan's separate `ports` field into `target`
# using CIDR-slash notation, e.g. "10.50.0.5/20-65535" instead of
# target="10.50.0.5", ports="20-65535" -- a real IPv4 CIDR suffix is 0-32,
# so anything else (a bare number outside that range, or an "N-M" range) is
# almost certainly a misplaced port spec rather than a subnet mask.
_MASSCAN_TARGET_PORT_LEAK_RE = re.compile(r'^(?P<host>.+)/(?P<suffix>\d+-\d+|\d+)$')

SUPPORTED_TOOLS = [
    "run_command", "run_masscan", "run_nmap", "run_naabu", "run_netstat",
    "run_sqlmap", "run_nikto", "run_hydra", "run_searchsploit",
    "run_curl", "run_wget", "write_file", "read_file",
    "run_john", "run_ncrack", "run_gobuster", "run_enum4linux", "run_medusa", "run_setoolkit",
    "run_subfinder", "run_nuclei", "run_katana", "run_ffuf", "run_httpx", "run_metasploit",
    "run_dirb", "run_commix",
]


class ToolExecutor:
    """Builds tool commands and dispatches them to the remote target."""

    def execute_tool(self, tool, params):
        if tool == "run_command":
            return self._run_command(params.get("command", ""))
        elif tool == "run_masscan":
            return self._run_masscan(
                params.get("target", ""), params.get("ports", "1-65535"), params.get("rate", "1000")
            )
        elif tool == "run_nmap":
            return self._run_nmap(params.get("target", ""), params.get("flags", "-sV"))
        elif tool == "run_naabu":
            return self._run_naabu(
                params.get("host", ""), params.get("ports", ""), params.get("top_ports", ""),
                params.get("rate", ""),
            )
        elif tool == "run_netstat":
            return self._run_netstat(params.get("flags", "-tuln"))
        elif tool == "run_sqlmap":
            return self._run_sqlmap(
                params.get("target", ""), params.get("technique", "B"), params.get("dbms", ""),
                params.get("level", "1"), params.get("risk", "1"), params.get("cookie", ""),
            )
        elif tool == "run_nikto":
            return self._run_nikto(params.get("target", ""), params.get("port", "80"), params.get("ssl", False))
        elif tool == "run_hydra":
            return self._run_hydra(
                params.get("target", ""), params.get("service", "ssh"), params.get("username", ""),
                params.get("wordlist", "/usr/share/seclists/Passwords/Common-Credentials/darkweb2017_top-1000.txt"),
                params.get("threads", "16"), params.get("path", ""), params.get("body", ""),
                params.get("cookie", ""), params.get("success_string", ""), params.get("failure_string", ""),
            )
        elif tool == "run_searchsploit":
            return self._run_searchsploit(params.get("keyword", ""), params.get("type", ""))
        elif tool == "run_curl":
            return self._run_curl(
                params.get("url", ""), params.get("method", "GET"), params.get("headers", ""),
                params.get("data", ""), params.get("cookie", ""),
            )
        elif tool == "run_wget":
            return self._run_wget(params.get("url", ""), params.get("output", ""), params.get("recursive", False))
        elif tool == "write_file":
            return self._write_file(params.get("filename", ""), params.get("content", ""))
        elif tool == "read_file":
            return self._read_file(params.get("filename", ""))
        elif tool == "run_john":
            return self._run_john(params.get("hash_file", ""), params.get("wordlist", ""), params.get("format", ""))
        elif tool == "run_ncrack":
            return self._run_ncrack(
                params.get("target", ""), params.get("service", "ssh"), params.get("users", ""),
                params.get("wordlist", ""),
            )
        elif tool == "run_setoolkit":
            return self._run_setoolkit(params.get("attack_type", "1"), params.get("target", ""))
        elif tool == "run_subfinder":
            return self._run_subfinder(params.get("domain", ""), params.get("silent", True))
        elif tool == "run_nuclei":
            return self._run_nuclei(
                params.get("target", ""), params.get("templates", ""), params.get("severity", ""),
                params.get("rate_limit", ""),
            )
        elif tool == "run_katana":
            return self._run_katana(params.get("target", ""), params.get("depth", "3"))
        elif tool == "run_ffuf":
            return self._run_ffuf(
                params.get("url", ""), params.get("wordlist", ""), params.get("param", "FUZZ"),
                params.get("rate", ""), params.get("threads", ""),
            )
        elif tool == "run_httpx":
            return self._run_httpx(params.get("target", ""), params.get("flags", ""))
        elif tool == "run_gobuster":
            return self._run_gobuster(
                params.get("target", ""), params.get("wordlist", ""), params.get("mode", "dir"),
                params.get("threads", ""), params.get("delay", ""),
            )
        elif tool == "run_enum4linux":
            return self._run_enum4linux(params.get("target", ""))
        elif tool == "run_medusa":
            return self._run_medusa(
                params.get("target", ""), params.get("service", "ssh"), params.get("username", ""),
                params.get("wordlist", ""),
            )
        elif tool == "run_metasploit":
            return self._run_metasploit(params.get("commands", ""))
        elif tool == "run_dirb":
            return self._run_dirb(
                params.get("target", ""), params.get("wordlist", ""), params.get("extensions", ""),
                params.get("delay_ms", ""),
            )
        elif tool == "run_commix":
            return self._run_commix(
                params.get("target", ""), params.get("param", ""), params.get("data", ""),
                params.get("technique", ""), params.get("os_cmd", ""), params.get("msf_path", ""),
                params.get("cookie", ""),
            )
        else:
            return {
                "status": "error",
                "error_type": "unsupported_tool",
                "message": f"Tool '{tool}' not supported",
                "recovery_suggestion": f"Use one of: {', '.join(SUPPORTED_TOOLS)}",
            }

    def _execute_command(self, command, timeout=None, retry_with_sudo=False):
        return remote_exec.run(command, timeout=timeout, retry_with_sudo=retry_with_sudo)

    def _run_command(self, command):
        if not command:
            return {"status": "error", "error_type": "invalid_params", "message": "No command provided"}
        return self._execute_command(command)

    def _run_masscan(self, target, ports, rate):
        if not target:
            return {"status": "error", "error_type": "invalid_params", "message": "No target specified for masscan"}
        target, ports = self._recover_masscan_target_ports(target, ports)
        command = f"masscan {target} -p {ports} --rate {rate}"
        return self._execute_command(command)

    @staticmethod
    def _recover_masscan_target_ports(target, ports):
        """Split a model-hallucinated "target/portrange" string back into
        real target + ports, recovering the model's evident intent instead
        of either failing outright or silently dropping the requested ports
        in favor of the "1-65535" default. See _MASSCAN_TARGET_PORT_LEAK_RE.
        """
        match = _MASSCAN_TARGET_PORT_LEAK_RE.match(target)
        if not match:
            return target, ports
        suffix = match.group("suffix")
        is_real_cidr = suffix.isdigit() and 0 <= int(suffix) <= 32
        if is_real_cidr:
            return target, ports
        return match.group("host"), suffix

    def _run_nmap(self, target, flags):
        if not target:
            return {"status": "error", "error_type": "invalid_params", "message": "No target specified for nmap"}
        command = f"nmap {flags} {target}"
        return self._execute_command(command)

    def _run_naabu(self, host, ports, top_ports, rate):
        if not host:
            return {"status": "error", "error_type": "invalid_params", "message": "No host specified for naabu"}
        # Unlike nmap/masscan/hydra, naabu has NO positional target argument
        # at all -- confirmed live: a bare "naabu <host>" hard-fails instantly
        # with "[FTL] Program exiting: no input list provided". -host (or
        # -list) is mandatory. -silent gives bare "host:port" output lines,
        # one per line -- deliberately the exact input shape run_nuclei's
        # target list (or nuclei's own stdin ingestion via run_command) wants,
        # which is naabu's actual value: it's a pipe-friendly port-discovery
        # stage, not a general-purpose replacement for nmap/masscan.
        command = f"naabu -host {shlex.quote(host)} -silent"
        if ports:
            command += f" -p {shlex.quote(ports)}"
        elif top_ports:
            command += f" -top-ports {shlex.quote(top_ports)}"
        if rate:
            command += f" -rate {rate}"
        return self._execute_command(command)

    def _run_netstat(self, flags):
        command = f"netstat {flags}"
        result = self._execute_command(command)
        if result["status"] != "success":
            ss_result = self._execute_command(f"ss {flags}")
            if ss_result["status"] == "success":
                ss_result["note"] = "Used 'ss' (modern netstat replacement)"
            return ss_result
        return result

    def _run_sqlmap(self, target, technique, dbms, level, risk, cookie=None):
        if not target:
            return {"status": "error", "error_type": "invalid_params", "message": "No target URL specified for sqlmap"}
        # target is almost always a URL with a query string ("?id=1&Submit=Submit")
        # -- unquoted, the remote shell treats "&" as a background-job
        # separator and silently truncates the command after the first
        # param, which then fails on whatever's left over as a bogus
        # command name. Confirmed the hard way against a real DVWA target.
        command = f"sqlmap -u {shlex.quote(target)} --technique={technique} --level={level} --risk={risk}"
        if dbms:
            command += f" --dbms={dbms}"
        if cookie:
            # Needed for any endpoint gated behind a login (kali-network-model-z7s:
            # e.g. DVWA's own SQLi pages 404/redirect without a real PHPSESSID +
            # security=low cookie pair -- confirmed real via
            # playbooks/dvwa_full_chain.sh). Pass the exact Cookie header value
            # (e.g. "PHPSESSID=abc123; security=low"), not just a session id.
            command += f' --cookie="{cookie}"'
        command += " --batch"
        return self._execute_command(command)

    def _run_commix(self, target, param, data, technique, os_cmd, msf_path, cookie=None):
        if not target:
            return {"status": "error", "error_type": "invalid_params", "message": "No target URL specified for commix"}
        # Same shlex-quote reasoning as run_sqlmap's target -- commix's -u
        # is also almost always a URL with a "&"-separated query string,
        # unquoted "&" gets read as a shell background-job separator by
        # the remote shell. --batch matches sqlmap's own "never block on
        # an interactive prompt" requirement for unattended execution.
        #
        # --ignore-stdin is NOT optional despite being undocumented in
        # `commix --help`'s printed output (confirmed present in
        # src/utils/menu.py, just not shown under the printed headings) --
        # live-tested and confirmed REQUIRED under this harness's execution
        # model: commix's own startup logic (src/core/main.py) checks
        # `sys.stdin.isatty()` and, whenever stdin is not a real terminal
        # (true for every docker-exec/SSH non-interactive invocation this
        # tool ever runs under), silently sets STDIN_PARSING=True and
        # ignores -u ENTIRELY, printing only "Using 'stdin' for parsing
        # targets list." and exiting -- no error, no traceback, just a
        # no-op. Confirmed exactly this failure live against DVWA before
        # finding --ignore-stdin in the source and confirming it fixes it.
        command = f"commix -u {shlex.quote(target)} --batch --ignore-stdin"
        if param:
            command += f" -p {shlex.quote(param)}"
        if data:
            # POST body, e.g. "username=admin&injectable_field=test" --
            # same quoting need as `target`, same reason.
            command += f" --data={shlex.quote(data)}"
        if cookie:
            # Same requirement as run_sqlmap's/run_hydra's cookie param --
            # a login-gated injectable page (e.g. DVWA's Command Injection
            # module) is unreachable without the real session cookie pair
            # (e.g. "PHPSESSID=abc123; security=low"), live-confirmed
            # against DVWA's own /vulnerabilities/exec/ page.
            command += f" --cookie={shlex.quote(cookie)}"
        if technique:
            command += f" --technique={shlex.quote(technique)}"
        if os_cmd:
            # Single-command verification mode (e.g. "id", "whoami") once
            # an injection point is already confirmed. LIVE-TESTED REAL BUG
            # (confirmed via source inspection, src/core/injections/
            # controller/checks.py's enable_shell()): after a confirmed
            # injection AND after --os-cmd's own command runs successfully,
            # commix unconditionally asks "...Do you want to spawn a
            # pseudo-terminal shell? [Y/n]" and, because --ignore-stdin
            # (required above, see that flag's own comment) makes
            # STDIN_PARSING False, its default answer flips to "Y" -- it
            # then tries to open an interactive shell against this
            # harness's non-interactive stdin, hits EOF, and LOOPS
            # FOREVER retrying the same read (confirmed live: 5+ minutes
            # of 80% CPU, hundreds of thousands of log lines, no further
            # network requests). --batch does NOT suppress this specific
            # prompt. The real fix, found in common.py's read_input():
            # --answers matches by substring against the prompt text, so
            # 'shell=N' answers it "N" and the process exits cleanly
            # immediately after printing --os-cmd's real result.
            #
            # A run that falls through to commix's semi-blind file-based
            # technique (rather than the faster results-based classic
            # technique landing first) hits THREE MORE interactive
            # prompts the single shell=N answer doesn't cover: "Do you
            # want to use a random file '<X>.txt'...? [Y/n]" (answer Y --
            # accept it), "Do you want to use the URL 'http://.../<X>.txt'
            # ...? [Y/n]" (answer Y), and "Insufficient permissions on
            # directory '<web_root>'. Do you want to use '/tmp/' instead?
            # [Y/n]" (answer Y) -- there's also a FOURTH, free-text prompt
            # ("Enter a writable directory to use for file operations
            # (e.g. '/var/www/html/') > ") that must NOT be answered at
            # all; it has its own sensible default and forcing any value
            # into it breaks the flow (see the mistake below).
            #
            # REAL BUG FOUND AND FIXED in an earlier version of this
            # answers string: --answers matches by SUBSTRING against the
            # live prompt text (src/utils/common.py's read_input()), so a
            # key must be unique to only its intended prompt. An earlier
            # attempt used 'directory=N' as a key intending to skip past
            # something -- but "directory" is ALSO a substring of the
            # free-text "Enter a writable directory..." prompt above, so
            # that prompt got force-fed the literal string "N" as its
            # answer, i.e. commix tried to write output files into a
            # directory literally named "N" (confirmed live: "Attempting
            # to create a file in directory 'N'..."), which naturally
            # then failed every subsequent technique. Fixed by using
            # longer, verified-unique substrings ('random', 'use the URL',
            # 'Insufficient') and deliberately NOT supplying a key for the
            # free-text directory prompt, letting it fall through to its
            # own default. This same mistake was ALSO the reason a real
            # exploit chain appeared to succeed 2 times then mysteriously
            # fail on a 3rd identical-looking attempt earlier in testing
            # -- that specific failure's actual root cause turned out to
            # be a SEPARATE bug in the test harness's own login/cookie
            # capture (not carrying one session's cookie through both the
            # GET and the login POST, see dvwa_commix_exec_chain's own
            # extensive comment in pipeline_recipes.py), not commix's
            # detection being nondeterministic -- worth remembering if a
            # future run seems to "randomly" fail: check login/session
            # correctness before suspecting commix itself.
            command += (
                f" --os-cmd={shlex.quote(os_cmd)} "
                "--answers='shell=N,random=Y,use the URL=Y,Insufficient=Y'"
            )
        if msf_path:
            # The actual "integrates directly with Metasploit" hook: once
            # commix confirms an injection point, pointing it at a real
            # local msf install (e.g. /usr/share/metasploit-framework) lets
            # it hand off to msfvenom/msfconsole for payload generation/
            # delivery through that same confirmed injection point, rather
            # than commix's own more limited built-in shell.
            command += f" --msf-path={shlex.quote(msf_path)}"
        return self._execute_command(command)

    def _run_nikto(self, target, port, ssl):
        if not target:
            return {"status": "error", "error_type": "invalid_params", "message": "No target specified for nikto"}
        target = target.replace("http://", "").replace("https://", "").rstrip("/")
        command = f"nikto -h {target} -p {port} -Format txt"
        return self._execute_command(command)

    @staticmethod
    def _split_host_port_path(target):
        """hydra's http-post-form/http-get-form modes take a bare host (or
        host:port) as their own positional target and expect the URL path
        (with query string, for a GET form) as a separate field inside the
        form-string -- unlike every other hydra service, which takes
        host[:port] directly. This lets a caller still pass a full URL for
        `target` (as every other tool in this file expects) and have the
        host/port/path split out automatically."""
        t = target
        if "://" in t:
            t = t.split("://", 1)[1]
        if "/" in t:
            host_port, path = t.split("/", 1)
            path = "/" + path
        else:
            host_port, path = t, ""
        if ":" in host_port:
            host, port = host_port.split(":", 1)
        else:
            host, port = host_port, None
        return host, port, path

    def _run_hydra(self, target, service, username, wordlist, threads,
                    path=None, body=None, cookie=None, success_string=None, failure_string=None):
        if not target or not service:
            return {
                "status": "error",
                "error_type": "invalid_params",
                "message": "Missing parameters: target and service are required",
            }
        # Same defaulting pattern _run_ncrack already uses for its username
        # equivalent ("users") -- the model reliably omits username/wordlist
        # for credential tools despite explicit prompt instructions not to
        # (confirmed repeatedly against a real model), so don't depend on it.
        username = username or "admin"
        wordlist = wordlist or "/usr/share/seclists/Passwords/Common-Credentials/darkweb2017_top-1000.txt"

        if service in ("http-post-form", "http-get-form"):
            # kali-network-model-zmm: a web LOGIN FORM is not a network
            # service like ssh/mysql -- hydra needs its own dedicated
            # form-string syntax to brute-force one at all. Before this,
            # every web-login brute-force attempt in this session's manual
            # baseline was impossible through the scripted tool, and the
            # live model (confirmed against a real target) fell back to
            # guessing "mysql" as the service against an http:// target,
            # which cannot work.
            host, url_port, url_path = self._split_host_port_path(target)
            form_path = path or url_path
            if not host or not form_path or not body:
                return {
                    "status": "error",
                    "error_type": "invalid_params",
                    "message": (
                        f"{service} requires: target (host, or a full URL to derive host/path "
                        f"from), path (e.g. '/login.php' -- falls back to any path already in "
                        f"target), and body (the exact form field string with ^USER^/^PASS^ "
                        f"placeholders, e.g. 'username=^USER^&password=^PASS^&Login=Login')"
                    ),
                }
            # H= MUST come before F=/S= in hydra's own field order, or hydra
            # silently misparses the whole string -- this exact bug was
            # found and fixed the hard way building
            # playbooks/dvwa_full_chain.sh (a real hydra http-get-form run
            # against DVWA's brute-force page).
            form_parts = [form_path, body]
            if cookie:
                form_parts.append(f"H=Cookie\\: {cookie}")
            form_parts.append(f"S={success_string}" if success_string else f"F={failure_string or 'incorrect'}")
            form_string = ":".join(form_parts)
            port_flag = f"-s {url_port} " if url_port else ""
            command = f'hydra -l {username} -P {wordlist} -t {threads} {port_flag}{host} {service} "{form_string}"'
            return self._execute_command(command)

        command = f"hydra -l {username} -P {wordlist} -t {threads} -I {service}://{target}"
        return self._execute_command(command)

    def _run_searchsploit(self, keyword, type_filter):
        if not keyword:
            return {"status": "error", "error_type": "invalid_params", "message": "No keyword specified for searchsploit"}
        command = f"searchsploit {keyword}"
        if type_filter:
            command += f" -t {type_filter}"
        return self._execute_command(command)

    def _run_curl(self, url, method, headers, data, cookie=None):
        if not url:
            return {"status": "error", "error_type": "invalid_params", "message": "No URL specified for curl"}
        command = f'curl -X {method} "{url}"'
        if headers:
            command += f' -H "{headers}"'
        if cookie:
            # kali-network-model-z7s: without this, every authenticated
            # endpoint (a page behind a login, e.g. DVWA's own vuln pages)
            # is unreachable through this tool -- confirmed real via
            # playbooks/dvwa_full_chain.sh, which needed a live PHPSESSID
            # cookie for 5 of 10 techniques. Pass the exact Cookie header
            # value (e.g. "PHPSESSID=abc123; security=low"), not just a bare
            # session id -- most apps (DVWA included) also gate behavior on
            # a second cookie (a security-level flag, a CSRF-adjacent value).
            command += f' -b "{cookie}"'
        if data and method in ["POST", "PUT", "PATCH"]:
            command += f" -d '{data}'"
        command += " -v"
        return self._execute_command(command)

    def _run_wget(self, url, output, recursive):
        if not url:
            return {"status": "error", "error_type": "invalid_params", "message": "No URL specified for wget"}
        command = f'wget "{url}"'
        if output:
            command += f" -O {output}"
        if recursive:
            command += " -r"
        return self._execute_command(command)

    def _write_file(self, filename, content):
        if not filename:
            return {"status": "error", "error_type": "invalid_params", "message": "No filename provided"}
        if CONFIG.REMOTE_WRITE_MODE == "local":
            return self._write_file_local(filename, content)

        # `tee`, not `cat > file`: with shell redirection the target file is
        # opened by the *invoking* (non-root) shell before sudo ever runs, so
        # a retried `sudo cat > file` still fails on a root-owned path.
        # `sudo tee file` elevates the process that actually opens the file.
        heredoc = f"tee {shlex.quote(filename)} > /dev/null << 'EOF_AGENT_WRITE'\n{content}\nEOF_AGENT_WRITE"
        result = self._execute_command(heredoc)
        if result["status"] == "success":
            return {
                "status": "success",
                "message": f"File written to {filename}",
                "filename": filename,
                "bytes_written": len(content),
            }
        return result

    def _read_file(self, filename):
        if not filename:
            return {"status": "error", "error_type": "invalid_params", "message": "No filename provided"}
        if CONFIG.REMOTE_WRITE_MODE == "local":
            return self._read_file_local(filename)

        result = self._execute_command(f"cat {shlex.quote(filename)}")
        if result["status"] == "success":
            return {
                "status": "success",
                "filename": filename,
                "content": result["stdout"],
                "bytes_read": len(result["stdout"]),
            }

        message = result.get("message", "")
        if "no such file" in message.lower():
            return {
                "status": "error",
                "error_type": "file_not_found",
                "message": f"File not found: {filename}",
                "recovery_suggestion": "Check file path and ensure file exists on the remote target.",
            }
        if result.get("error_type") == "permission_denied":
            return {
                "status": "error",
                "error_type": "permission_denied",
                "message": f"Permission denied reading {filename}",
                "recovery_suggestion": "Check file permissions or use sudo.",
            }
        return result

    def _write_file_local(self, filename, content):
        """REMOTE_WRITE_MODE=local escape hatch: stage content on the orchestrator's own filesystem."""
        try:
            with open(filename, "w") as f:
                f.write(content)
            return {
                "status": "success",
                "message": f"File written to {filename}",
                "filename": filename,
                "bytes_written": len(content),
            }
        except PermissionError as e:
            return {
                "status": "error",
                "error_type": "permission_denied",
                "message": f"Cannot write to {filename}: {e}",
                "recovery_suggestion": "Check directory permissions or use a different path.",
            }
        except Exception as e:
            return {
                "status": "error",
                "error_type": "file_write_error",
                "message": str(e),
                "recovery_suggestion": "Check file path and permissions.",
            }

    def _read_file_local(self, filename):
        try:
            with open(filename, "r") as f:
                content = f.read()
            return {"status": "success", "filename": filename, "content": content, "bytes_read": len(content)}
        except FileNotFoundError:
            return {
                "status": "error",
                "error_type": "file_not_found",
                "message": f"File not found: {filename}",
                "recovery_suggestion": "Check file path and ensure file exists.",
            }
        except PermissionError:
            return {
                "status": "error",
                "error_type": "permission_denied",
                "message": f"Permission denied reading {filename}",
                "recovery_suggestion": "Check file permissions or use sudo.",
            }
        except Exception as e:
            return {
                "status": "error",
                "error_type": "file_read_error",
                "message": str(e),
                "recovery_suggestion": "Check file path and permissions.",
            }

    def _run_john(self, hash_file, wordlist, format):
        if not hash_file:
            return {"status": "error", "error_type": "invalid_params", "message": "No hash file specified"}
        wordlist = wordlist or "/usr/share/seclists/Passwords/Common-Credentials/darkweb2017_top-1000.txt"
        command = f"john {hash_file} --wordlist={wordlist}"
        if format:
            command += f" --format={format}"
        return self._execute_command(command)

    def _run_gobuster(self, target, wordlist, mode, threads=None, delay=None):
        if not target:
            return {"status": "error", "error_type": "invalid_params", "message": "No target specified"}
        wordlist = wordlist or "/usr/share/seclists/Discovery/Web-Content/common.txt"
        # threads/delay are optional throttling for a target that can't
        # absorb the default -t 20 concurrency without falling over (e.g.
        # an under-resourced Node backend hitting its own memory/event-loop
        # limits under load -- a real WAF/production target would more
        # likely respond to the same overload pattern with an IP ban
        # instead of a crash, which is its own separate failure mode this
        # doesn't address, see run_ffuf's/run_dirb's own comments on the
        # distinction). --delay takes a duration string (e.g. "500ms",
        # "1s"), confirmed via `gobuster dir --help`; passed straight
        # through, not converted from a bare number, so a recipe/model
        # calling this must supply the unit.
        command = f"gobuster {mode} -u {target} -w {wordlist} -t {threads or 20}"
        if delay:
            command += f" --delay {delay}"
        return self._execute_command(command)

    def _run_dirb(self, target, wordlist, extensions, delay_ms=None):
        if not target:
            return {"status": "error", "error_type": "invalid_params", "message": "No target specified for dirb"}
        # NOTE: DirBuster (the actual Java/Swing tool) was tried first and
        # rejected -- its headless mode (-H) throws a real
        # java.lang.NullPointerException on startup in the Kali package
        # (1.0-RC1: Manager.start() unconditionally touches a GUI panel
        # object that's never initialized headless), confirmed reproducible
        # twice against two different targets. dirb is a different,
        # unrelated CLI tool that fills the same directory-brute role and
        # actually works headless -- confirmed live end-to-end against DVWA
        # (172.17.0.12): 4612 words scanned, 6 real findings including a
        # listable /config/ directory. -S (silent) suppresses per-request
        # noise, matching gobuster's own -q. dirb recurses into found
        # directories by default (no -r/-R flag needed for that, unlike
        # DirBuster) but a directory dirb finds already-LISTABLE it
        # correctly skips scanning further, per its own WARNING output.
        wordlist = wordlist or "/usr/share/wordlists/dirb/common.txt"
        command = f"dirb {shlex.quote(target)} {shlex.quote(wordlist)} -S"
        if extensions:
            # dirb's -X takes ONE suffix string (e.g. ".php"), not a
            # comma-list like gobuster's -x -- do not pass multiple
            # extensions here, only the single most relevant one.
            command += f" -X {shlex.quote(extensions)}"
        if delay_ms:
            # dirb's own throttle: "-z <millisecs>: Add a milliseconds
            # delay to not cause excessive Flood" (its own --help wording)
            # -- a bare integer, not a duration string like gobuster's
            # --delay, confirmed via `dirb --help`.
            command += f" -z {delay_ms}"
        return self._execute_command(command)

    def _run_enum4linux(self, target):
        if not target:
            return {"status": "error", "error_type": "invalid_params", "message": "No target specified"}
        command = f"enum4linux -a {target}"
        return self._execute_command(command)

    def _run_medusa(self, target, service, username, wordlist):
        if not target:
            return {"status": "error", "error_type": "invalid_params", "message": "No target specified"}
        # See _run_hydra's comment -- same defaulting pattern as _run_ncrack.
        username = username or "admin"
        wordlist = wordlist or "/usr/share/seclists/Passwords/Common-Credentials/darkweb2017_top-1000.txt"
        command = f"medusa -h {target} -u {username} -P {wordlist} -M {service} -t 4"
        return self._execute_command(command)

    def _run_ncrack(self, target, service, users, wordlist):
        if not target:
            return {"status": "error", "error_type": "invalid_params", "message": "No target specified"}
        wordlist = wordlist or "/usr/share/seclists/Passwords/Common-Credentials/darkweb2017_top-1000.txt"
        users = users or "root,admin,administrator"
        users_file = "/tmp/agent_ncrack_users.txt"
        # Must land on the same host ncrack itself runs on -- write via the
        # tool dispatch (not local open()) so it goes through the same
        # remote-vs-local routing as every other file operation.
        write_result = self._write_file(users_file, users.replace(",", "\n"))
        if write_result["status"] != "success":
            return write_result
        command = f"ncrack {service}://{target} -U {users_file} -P {wordlist}"
        return self._execute_command(command)

    def _run_setoolkit(self, attack_type, target):
        if not target:
            return {"status": "error", "error_type": "invalid_params", "message": "No target specified"}
        command = f"echo '{attack_type}\n2\n{target}' | sudo setoolkit"
        return self._execute_command(command)

    def _run_subfinder(self, domain, silent):
        if not domain:
            return {"status": "error", "error_type": "invalid_params", "message": "No domain specified"}
        command = f"subfinder -d {domain}"
        if silent:
            command += " -silent"
        return self._execute_command(command)

    def _run_nuclei(self, target, templates, severity, rate_limit=None):
        if not target:
            return {"status": "error", "error_type": "invalid_params", "message": "No target specified"}
        command = f"nuclei -u {target}"
        # "all"/"*" isn't a real -t value -- nuclei has no such alias and
        # errors with "no templates provided for scan". Omitting -t entirely
        # is what actually means "scan with the full default template set",
        # which is what a model asking for "all" almost always means.
        if templates and templates.strip().lower() not in ("all", "*", "any"):
            command += f" -t {templates}"
        if severity:
            command += f" -severity {severity}"
        if rate_limit:
            # -rl caps requests/second (default 150) -- nuclei's own
            # concurrency defaults (-c 25 templates in parallel, -bs 25
            # hosts in parallel per template) are tuned for a normal
            # production target and can meaningfully stress a fragile
            # backend (e.g. a Node app with a small heap ceiling) well
            # before the target would ever return an HTTP-level rate-
            # limit response -- passing a lower -rl here doesn't change
            # -c/-bs themselves, it caps the aggregate request rate
            # across all of them.
            command += f" -rl {rate_limit}"
        command += " -silent"
        return self._execute_command(command)

    def _run_katana(self, target, depth):
        if not target:
            return {"status": "error", "error_type": "invalid_params", "message": "No target specified"}
        command = f"katana -u {target} -depth {depth} -silent"
        return self._execute_command(command)

    def _run_ffuf(self, url, wordlist, param, rate=None, threads=None):
        if not url:
            return {"status": "error", "error_type": "invalid_params", "message": "No URL specified"}
        wordlist = wordlist or "/usr/share/seclists/Discovery/Web-Content/common.txt"
        if param not in url:
            url = url + f"/{param}"
        # -s, not -silent -- confirmed against the real installed ffuf binary
        # (`ffuf -h`); the old flag name was rejected outright at runtime.
        command = f"ffuf -u {url} -w {wordlist} -mc 200,301,302,403 -s"
        if threads:
            command += f" -t {threads}"
        if rate:
            # -rate is requests/second and, per ffuf's own --help, takes
            # priority over -t/-p when both are set -- a genuine target-
            # side throttle rather than just fewer concurrent workers.
            command += f" -rate {rate}"
        return self._execute_command(command)

    def _run_httpx(self, target, flags):
        if not target:
            return {"status": "error", "error_type": "invalid_params", "message": "No target specified"}
        command = f"{CONFIG.HTTPX_BIN} -u {target}"
        if flags:
            command += f" {flags}"
        else:
            command += " -status-code -title -tech-detect -silent"
        return self._execute_command(command, timeout=60)

    def _run_metasploit(self, commands):
        """Runs raw msfconsole commands non-interactively via `-q -x`.

        The model supplies real msfconsole commands (search/use/set/run/
        exploit, etc.) as one ";"-separated string -- there's no attempt at
        a structured module/RHOSTS/RPORT param interface, since that would
        just be a second, narrower copy of what msfconsole itself already
        accepts. `exit -y` is appended (if not already present) so the
        console always terminates instead of hanging on stdin.

        The exec target has no init system (no systemd), so postgresql
        doesn't come back up on its own after a container restart --
        `service postgresql start` is prepended defensively on every call
        (it's a no-op, not an error, if already running) so db-backed
        `search`/workspace/session tracking stays available without a
        separate provisioning step.
        """
        if not commands:
            return {"status": "error", "error_type": "invalid_params", "message": "No msfconsole commands specified"}
        script = commands.strip().rstrip(";").strip()
        if not script.endswith("exit") and "exit -y" not in script:
            script += "; exit -y"
        command = f"service postgresql start >/dev/null 2>&1; msfconsole -q -x {shlex.quote(script)}"
        return self._execute_command(command)
