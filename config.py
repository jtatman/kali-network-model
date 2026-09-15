"""Centralized environment-variable configuration.

Every module that needs a config value imports CONFIG from here instead of
reading os.environ directly. agent.py calls CONFIG.validate() once at process
startup so misconfiguration fails immediately, not mid-engagement.
"""

import os


class ConfigError(Exception):
    """Raised by Config.validate() when required settings are missing or invalid."""


def _get(key, default=None):
    return os.environ.get(key, default)


def _get_int(key, default):
    value = os.environ.get(key)
    return int(value) if value else default


class Config:
    def __init__(self):
        # Ollama (native /api/chat, not the OpenAI-compat shim)
        self.OLLAMA_HOST = _get("OLLAMA_HOST")
        self.OLLAMA_MODEL = _get("OLLAMA_MODEL")
        self.OLLAMA_NUM_CTX = _get_int("OLLAMA_NUM_CTX", 4096)

        # Logging / cache / reports (safe local defaults so a fresh clone works with zero config)
        self.LOG_DIR = _get("LOG_DIR", "./logs")
        self.CACHE_DIR = _get("CACHE_DIR", "./.cache")
        self.REPORT_DIR = _get("REPORT_DIR", "./reports")

        # Remote execution: EXEC_MODE selects "direct" SSH or SSH + "docker" exec
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
        self.HTTPX_BIN = _get("HTTPX_BIN", "httpx")

    def validate(self):
        errors = []

        if not self.OLLAMA_HOST:
            errors.append("OLLAMA_HOST is required (e.g. http://192.168.1.50:11434)")
        if not self.OLLAMA_MODEL:
            errors.append("OLLAMA_MODEL is required (must match a model registered via 'ollama create')")

        if self.EXEC_MODE not in ("direct", "docker"):
            errors.append("EXEC_MODE must be 'direct' or 'docker'")
        if not self.SSH_HOST:
            errors.append("SSH_HOST is required")
        if not self.SSH_USER:
            errors.append("SSH_USER is required")
        if not self.SSH_KEY_PATH:
            errors.append("SSH_KEY_PATH is required")
        if self.EXEC_MODE == "docker" and not self.DOCKER_CONTAINER:
            errors.append("DOCKER_CONTAINER is required when EXEC_MODE=docker")

        if self.REMOTE_WRITE_MODE not in ("remote", "local"):
            errors.append("REMOTE_WRITE_MODE must be 'remote' or 'local'")

        if errors:
            raise ConfigError("Invalid configuration:\n" + "\n".join(f"  - {e}" for e in errors))

        for path in (self.LOG_DIR, self.CACHE_DIR, self.REPORT_DIR):
            os.makedirs(path, exist_ok=True)


CONFIG = Config()
