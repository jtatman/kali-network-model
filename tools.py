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

import shlex

import remote_exec
from config import CONFIG

SUPPORTED_TOOLS = [
    "run_command", "run_masscan", "run_nmap", "run_netstat",
    "run_sqlmap", "run_nikto", "run_hydra", "run_searchsploit",
    "run_curl", "run_wget", "write_file", "read_file",
    "run_john", "run_ncrack", "run_gobuster", "run_enum4linux", "run_medusa", "run_setoolkit",
    "run_subfinder", "run_nuclei", "run_katana", "run_ffuf", "run_httpx",
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
        elif tool == "run_netstat":
            return self._run_netstat(params.get("flags", "-tuln"))
        elif tool == "run_sqlmap":
            return self._run_sqlmap(
                params.get("target", ""), params.get("technique", "B"), params.get("dbms", ""),
                params.get("level", "1"), params.get("risk", "1"),
            )
        elif tool == "run_nikto":
            return self._run_nikto(params.get("target", ""), params.get("port", "80"), params.get("ssl", False))
        elif tool == "run_hydra":
            return self._run_hydra(
                params.get("target", ""), params.get("service", "ssh"), params.get("username", ""),
                params.get("wordlist", "/usr/share/seclists/Passwords/Common-Credentials/darkweb2017_top-1000.txt"),
                params.get("threads", "16"),
            )
        elif tool == "run_searchsploit":
            return self._run_searchsploit(params.get("keyword", ""), params.get("type", ""))
        elif tool == "run_curl":
            return self._run_curl(
                params.get("url", ""), params.get("method", "GET"), params.get("headers", ""), params.get("data", "")
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
            return self._run_nuclei(params.get("target", ""), params.get("templates", ""), params.get("severity", ""))
        elif tool == "run_katana":
            return self._run_katana(params.get("target", ""), params.get("depth", "3"))
        elif tool == "run_ffuf":
            return self._run_ffuf(params.get("url", ""), params.get("wordlist", ""), params.get("param", "FUZZ"))
        elif tool == "run_httpx":
            return self._run_httpx(params.get("target", ""), params.get("flags", ""))
        elif tool == "run_gobuster":
            return self._run_gobuster(params.get("target", ""), params.get("wordlist", ""), params.get("mode", "dir"))
        elif tool == "run_enum4linux":
            return self._run_enum4linux(params.get("target", ""))
        elif tool == "run_medusa":
            return self._run_medusa(
                params.get("target", ""), params.get("service", "ssh"), params.get("username", ""),
                params.get("wordlist", ""),
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
        command = f"masscan {target} -p {ports} --rate {rate}"
        return self._execute_command(command)

    def _run_nmap(self, target, flags):
        if not target:
            return {"status": "error", "error_type": "invalid_params", "message": "No target specified for nmap"}
        command = f"nmap {flags} {target}"
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

    def _run_sqlmap(self, target, technique, dbms, level, risk):
        if not target:
            return {"status": "error", "error_type": "invalid_params", "message": "No target URL specified for sqlmap"}
        command = f"sqlmap -u {target} --technique={technique} --level={level} --risk={risk}"
        if dbms:
            command += f" --dbms={dbms}"
        command += " --batch"
        return self._execute_command(command)

    def _run_nikto(self, target, port, ssl):
        if not target:
            return {"status": "error", "error_type": "invalid_params", "message": "No target specified for nikto"}
        target = target.replace("http://", "").replace("https://", "").rstrip("/")
        command = f"nikto -h {target} -p {port} -Format txt"
        return self._execute_command(command)

    def _run_hydra(self, target, service, username, wordlist, threads):
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
        command = f"hydra -l {username} -P {wordlist} -t {threads} -I {service}://{target}"
        return self._execute_command(command)

    def _run_searchsploit(self, keyword, type_filter):
        if not keyword:
            return {"status": "error", "error_type": "invalid_params", "message": "No keyword specified for searchsploit"}
        command = f"searchsploit {keyword}"
        if type_filter:
            command += f" -t {type_filter}"
        return self._execute_command(command)

    def _run_curl(self, url, method, headers, data):
        if not url:
            return {"status": "error", "error_type": "invalid_params", "message": "No URL specified for curl"}
        command = f'curl -X {method} "{url}"'
        if headers:
            command += f' -H "{headers}"'
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

    def _run_gobuster(self, target, wordlist, mode):
        if not target:
            return {"status": "error", "error_type": "invalid_params", "message": "No target specified"}
        wordlist = wordlist or "/usr/share/seclists/Discovery/Web-Content/common.txt"
        command = f"gobuster {mode} -u {target} -w {wordlist} -t 20"
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

    def _run_nuclei(self, target, templates, severity):
        if not target:
            return {"status": "error", "error_type": "invalid_params", "message": "No target specified"}
        command = f"nuclei -u {target}"
        if templates:
            command += f" -t {templates}"
        if severity:
            command += f" -severity {severity}"
        command += " -silent"
        return self._execute_command(command)

    def _run_katana(self, target, depth):
        if not target:
            return {"status": "error", "error_type": "invalid_params", "message": "No target specified"}
        command = f"katana -u {target} -depth {depth} -silent"
        return self._execute_command(command)

    def _run_ffuf(self, url, wordlist, param):
        if not url:
            return {"status": "error", "error_type": "invalid_params", "message": "No URL specified"}
        wordlist = wordlist or "/usr/share/seclists/Discovery/Web-Content/common.txt"
        if param not in url:
            url = url + f"/{param}"
        # -s, not -silent -- confirmed against the real installed ffuf binary
        # (`ffuf -h`); the old flag name was rejected outright at runtime.
        command = f"ffuf -u {url} -w {wordlist} -mc 200,301,302,403 -s"
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
