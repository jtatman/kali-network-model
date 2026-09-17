"""Remote command execution over SSH, either directly on the target host's
shell or via `docker exec` into a container running on that host.

Returns the same result-dict shape mcp_server.py's local _execute_command
used to return, so tools.py's _run_* methods need no changes: {"status":
"success"/"error", "stdout", "stderr", "error_type"?, "recovery_suggestion"?}.

Adds a second error axis that only makes sense for a network transport --
"ssh_timeout" / "ssh_connection_failed" (SSH's own exit-code-255 convention
for connection-level failures) -- kept distinct from a remote command's own
failure (command_not_found / timeout / command_failed / permission_denied),
so "Kali box unreachable" and "nmap isn't installed" don't look identical.
"""

import os
import shlex
import subprocess

from config import CONFIG

# Pentest targets are typically new or freshly re-imaged hosts the operator
# has never SSH'd to interactively -- the default StrictHostKeyChecking
# policy (effectively "ask", which BatchMode turns into an immediate
# "Host key verification failed") would reject every first-time connection.
# accept-new trusts an unseen host's key on first contact but still refuses
# (and correctly surfaces as a real failure) if a previously-seen host's key
# ever changes, which is the actual MITM/target-swap case worth catching.
# A dedicated known_hosts file (not the operator's ~/.ssh/known_hosts) means
# re-imaging a target/container doesn't require manually editing the
# operator's personal SSH state.
_KNOWN_HOSTS_FILE = os.path.join(CONFIG.CACHE_DIR, "known_hosts")


def _base_ssh_argv():
    return [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", f"UserKnownHostsFile={_KNOWN_HOSTS_FILE}",
        "-o", f"ConnectTimeout={CONFIG.SSH_CONNECT_TIMEOUT_SECONDS}",
        "-i", CONFIG.SSH_KEY_PATH,
        "-p", str(CONFIG.SSH_PORT),
        f"{CONFIG.SSH_USER}@{CONFIG.SSH_HOST}",
    ]


def _build_remote_command(command, retry_with_sudo):
    if retry_with_sudo and not command.strip().startswith("sudo"):
        command = f"sudo {command}"

    if CONFIG.EXEC_MODE == "docker":
        # sudo (if any) must apply inside the container, so it's baked into
        # `command` above before wrapping in docker exec, not after.
        return f"docker exec {CONFIG.DOCKER_CONTAINER} sh -c {shlex.quote(command)}"

    return command


def _run_local_docker(command, timeout, retry_with_sudo):
    """local_docker mode: `docker exec` straight from this machine's own
    Docker CLI/socket, no SSH, no network route to the container's IP
    needed -- see config.py's EXEC_MODE comment for why this exists."""
    if retry_with_sudo and not command.strip().startswith("sudo"):
        command = f"sudo {command}"
    argv = ["docker", "exec", CONFIG.DOCKER_CONTAINER, "sh", "-c", command]
    exec_timeout = timeout if timeout is not None else CONFIG.EXEC_TIMEOUT_SECONDS

    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=exec_timeout)
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "error_type": "ssh_timeout",  # same bucket as the SSH path's timeout -- callers treat it identically
            "message": f"docker exec timed out after {exec_timeout}s",
            "recovery_suggestion": "Reduce scan scope/timeout, or check the container isn't hung.",
        }
    except Exception as e:
        return {
            "status": "error",
            "error_type": "ssh_client_error",
            "message": str(e),
            "recovery_suggestion": "Check that the local `docker` binary is installed and on PATH.",
        }

    if result.returncode == 0:
        return {"status": "success", "stdout": result.stdout.strip(), "stderr": result.stderr.strip()}

    # Docker's own errors (container missing/not running/daemon unreachable)
    # are always prefixed this way and happen before the command inside the
    # container ever runs -- distinct from the inner shell's own failure.
    if "error response from daemon" in result.stderr.lower() or "cannot connect to the docker daemon" in result.stderr.lower():
        return {
            "status": "error",
            "error_type": "ssh_connection_failed",  # same bucket as the SSH path's connection failure
            "message": result.stderr.strip(),
            "recovery_suggestion": (
                f"Check DOCKER_CONTAINER={CONFIG.DOCKER_CONTAINER!r} exists and is running "
                "(`docker ps`), and that the Docker daemon is reachable."
            ),
        }

    return _classify_failure(result, command, retry_with_sudo, timeout)


def run(command, timeout=None, retry_with_sudo=False):
    """Execute `command` on the configured remote target (CONFIG.EXEC_MODE:
    "direct" runs it on the Kali box's own shell, "docker" runs it inside
    CONFIG.DOCKER_CONTAINER on that box via SSH, "local_docker" runs it in
    CONFIG.DOCKER_CONTAINER via this machine's own `docker exec`, no SSH).
    """
    if CONFIG.EXEC_MODE == "local_docker":
        return _run_local_docker(command, timeout, retry_with_sudo)

    remote_command = _build_remote_command(command, retry_with_sudo)
    argv = _base_ssh_argv() + [remote_command]

    exec_timeout = timeout if timeout is not None else CONFIG.EXEC_TIMEOUT_SECONDS
    total_timeout = CONFIG.SSH_CONNECT_TIMEOUT_SECONDS + exec_timeout

    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=total_timeout)
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "error_type": "ssh_timeout",
            "message": f"SSH command timed out after {total_timeout}s",
            "recovery_suggestion": "Reduce scan scope/timeout, or check the remote host isn't hung.",
        }
    except Exception as e:
        return {
            "status": "error",
            "error_type": "ssh_client_error",
            "message": str(e),
            "recovery_suggestion": "Check that the local `ssh` binary is installed and on PATH.",
        }

    if result.returncode == 0:
        return {"status": "success", "stdout": result.stdout.strip(), "stderr": result.stderr.strip()}

    # OpenSSH's own convention: exit 255 means the connection/auth itself
    # failed, as opposed to the remote command running and failing on its own.
    if result.returncode == 255:
        return {
            "status": "error",
            "error_type": "ssh_connection_failed",
            "message": result.stderr.strip() or "SSH connection failed (exit 255)",
            "recovery_suggestion": (
                "Check SSH_HOST/SSH_USER/SSH_KEY_PATH/SSH_PORT and network reachability -- "
                "this is a connection failure, not a tool failure."
            ),
        }

    return _classify_failure(result, command, retry_with_sudo, timeout)


def _classify_failure(result, command, retry_with_sudo, timeout):
    stderr = result.stderr.lower()

    # BatchMode=yes means there is no terminal for an interactive sudo
    # password prompt -- without this fast-fail it would hang to the full
    # timeout instead of failing in milliseconds.
    if "a password is required" in stderr or "a terminal is required" in stderr:
        target = (
            f"container {CONFIG.DOCKER_CONTAINER!r}"
            if CONFIG.EXEC_MODE == "local_docker"
            else f"{CONFIG.SSH_USER} on {CONFIG.SSH_HOST}"
        )
        return {
            "status": "error",
            "error_type": "sudo_requires_password",
            "message": result.stderr.strip(),
            "recovery_suggestion": (
                f"Configure NOPASSWD sudo (or run as root) for {target} -- "
                "no terminal is available for an interactive sudo password prompt."
            ),
        }

    if "permission denied" in stderr or "operation not permitted" in stderr:
        if not retry_with_sudo:
            return run(command, timeout=timeout, retry_with_sudo=True)
        return {
            "status": "error",
            "error_type": "permission_denied",
            "message": result.stderr.strip(),
            "recovery_suggestion": "Check if the tool is installed or requires elevated privileges.",
        }

    if "not found" in stderr or "command not found" in stderr:
        return {
            "status": "error",
            "error_type": "command_not_found",
            "message": result.stderr.strip(),
            "recovery_suggestion": f"Install the tool or check spelling. Command was: {command}",
        }

    if "timed out" in stderr or "timeout" in stderr:
        return {
            "status": "error",
            "error_type": "timeout",
            "message": "Remote command reported a timeout",
            "recovery_suggestion": "Reduce scan scope or increase EXEC_TIMEOUT_SECONDS.",
        }

    return {
        "status": "error",
        "error_type": "command_failed",
        "message": result.stderr.strip() if result.stderr else result.stdout.strip(),
        "recovery_suggestion": "Check command syntax and parameters.",
    }
