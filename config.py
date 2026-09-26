"""Centralized environment-variable configuration.

Every module that needs a config value imports CONFIG from here instead of
reading os.environ directly. agent.py calls CONFIG.validate() once at process
startup so misconfiguration fails immediately, not mid-engagement.
"""

import os

# Loads .env into the process environment if present (searches upward from
# the current working directory) -- explicit os.environ values still win,
# so `FOO=bar python3 agent.py` continues to override .env. Previously
# nothing loaded .env at all; every entry point (agent.py, the
# training-data/scripts/ harnesses) required manually exporting it into
# the shell first (`set -a && source .env && set +a`), which is easy to
# forget and produces a CONFIG.validate() error that looks like missing
# values rather than an unloaded file. python-dotenv is now in
# requirements.txt, but fall back to the old manual-export behavior
# (rather than a hard ImportError) if it isn't installed yet in whatever
# environment is running this -- config.py failing to import at all would
# be a worse regression than just not auto-loading .env.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


class ConfigError(Exception):
    """Raised by Config.validate() when required settings are missing or invalid."""


def _get(key, default=None):
    return os.environ.get(key, default)


def _get_int(key, default):
    value = os.environ.get(key)
    return int(value) if value else default


def _get_bool(key, default):
    value = os.environ.get(key)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


class Config:
    def __init__(self):
        # Ollama (native /api/chat, not the OpenAI-compat shim)
        self.OLLAMA_HOST = _get("OLLAMA_HOST")
        self.OLLAMA_MODEL = _get("OLLAMA_MODEL")
        self.OLLAMA_NUM_CTX = _get_int("OLLAMA_NUM_CTX", 4096)

        # raven-nest-mcp integration (kali-network-model-nrk) -- a SEPARATE
        # model from OLLAMA_MODEL. pentest-agent's own Modelfile overrides
        # the base template with a stripped-down one that never renders
        # .Tools, so it silently can't do native Ollama tool-calling at all
        # (confirmed via `ollama show pentest-agent` -- the active TEMPLATE
        # has no .Tools/.ToolCalls reference). raven-nest-mcp's own
        # extensive local-model benchmarking (docs/LOCAL_AI_INTEGRATION.md)
        # rates the Qwen3 dense family highest for real tool-calling
        # reliability (zero param hallucination at 8B) -- default here is
        # qwen3:4b since that's what's already on the shared Ollama host
        # without pulling anything new; bump to qwen3:8b if/when available.
        self.RAVEN_OLLAMA_MODEL = _get("RAVEN_OLLAMA_MODEL", "qwen3:4b")
        # Path to the raven-server binary and its config INSIDE
        # DOCKER_CONTAINER (built on the orchestrator via `cargo build
        # --release` from a local ~/raven-nest-mcp checkout, then `docker
        # cp`'d in -- glibc-compatible since both are x86_64 linux/amd64).
        self.RAVEN_BINARY_PATH = _get("RAVEN_BINARY_PATH", "/opt/raven-server/raven-server")
        self.RAVEN_CONFIG_PATH = _get("RAVEN_CONFIG_PATH", "/opt/raven-server/config.toml")

        # Logging / cache / reports (safe local defaults so a fresh clone works with zero config)
        self.LOG_DIR = _get("LOG_DIR", "./logs")
        self.CACHE_DIR = _get("CACHE_DIR", "./.cache")
        self.REPORT_DIR = _get("REPORT_DIR", "./reports")

        # Remote execution: EXEC_MODE selects "direct" SSH, SSH + "docker" exec,
        # or "local_docker" -- `docker exec` run straight from this machine's
        # own Docker CLI/socket, no SSH at all. local_docker exists because
        # Docker Desktop (Windows/WSL2 backend) does not route the orchestrator
        # host's network stack into container-internal IPs -- only published
        # ports and the Docker API/socket are reachable, and `docker exec`
        # already goes through the latter. See remote_exec.py.
        self.EXEC_MODE = _get("EXEC_MODE")
        self.SSH_HOST = _get("SSH_HOST")
        self.SSH_USER = _get("SSH_USER")
        self.SSH_KEY_PATH = _get("SSH_KEY_PATH")
        self.SSH_PORT = _get_int("SSH_PORT", 22)
        self.DOCKER_CONTAINER = _get("DOCKER_CONTAINER")
        self.EXEC_TIMEOUT_SECONDS = _get_int("EXEC_TIMEOUT_SECONDS", 7200)
        self.SSH_CONNECT_TIMEOUT_SECONDS = _get_int("SSH_CONNECT_TIMEOUT_SECONDS", 15)
        self.REMOTE_WRITE_MODE = _get("REMOTE_WRITE_MODE", "remote")

        # Tool binaries
        # Kali packages ProjectDiscovery's httpx as "httpx-toolkit", not
        # "httpx" -- that name is taken by the unrelated python3-httpx HTTP
        # client CLI, which is commonly already installed and would
        # otherwise silently shadow the real tool (confirmed on a real box:
        # different flags entirely, "-h" isn't even valid).
        self.HTTPX_BIN = _get("HTTPX_BIN", "httpx-toolkit")

        # Training-data pipeline-chain-building safety gate. False by
        # default: training-data/scripts/pipeline_chain_builder.py must stop
        # at the stage-1 (recon/enumeration/identification) -> stage-2
        # (credential attack / exploit-craft / exploit-deploy) boundary and
        # report the stage-1 lead instead of auto-continuing into stage 2,
        # unless this is explicitly set true. Deliberately NOT read
        # anywhere in agent.py's live engage/run_attack_loop path -- by
        # design (see kali-network-model bd issue), that path's existing
        # recon-then-attack-loop behavior against an authorized target is
        # unchanged; this only gates the separate offline harness used to
        # generate more multi-turn fine-tune examples against the lab.
        self.ALLOW_FULL_PIPELINE_CHAINS = _get_bool("ALLOW_FULL_PIPELINE_CHAINS", False)

    def validate(self):
        errors = []

        if not self.OLLAMA_HOST:
            errors.append("OLLAMA_HOST is required (e.g. http://192.168.1.50:11434)")
        if not self.OLLAMA_MODEL:
            errors.append("OLLAMA_MODEL is required (must match a model registered via 'ollama create')")

        if self.EXEC_MODE not in ("direct", "docker", "local_docker"):
            errors.append("EXEC_MODE must be 'direct', 'docker', or 'local_docker'")
        if self.EXEC_MODE in ("direct", "docker"):
            if not self.SSH_HOST:
                errors.append("SSH_HOST is required")
            if not self.SSH_USER:
                errors.append("SSH_USER is required")
            if not self.SSH_KEY_PATH:
                errors.append("SSH_KEY_PATH is required")
        if self.EXEC_MODE in ("docker", "local_docker") and not self.DOCKER_CONTAINER:
            errors.append(f"DOCKER_CONTAINER is required when EXEC_MODE={self.EXEC_MODE}")

        if self.REMOTE_WRITE_MODE not in ("remote", "local"):
            errors.append("REMOTE_WRITE_MODE must be 'remote' or 'local'")

        if errors:
            raise ConfigError("Invalid configuration:\n" + "\n".join(f"  - {e}" for e in errors))

        for path in (self.LOG_DIR, self.CACHE_DIR, self.REPORT_DIR):
            os.makedirs(path, exist_ok=True)


CONFIG = Config()
