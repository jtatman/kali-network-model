"""Shared emoji-annotated logging setup.

agent_loop.py and mcp_server.py used to each define a byte-for-byte similar
EmojiFormatter/setup_logger() (two processes, two log files). Now there's
one process, so this is a straightforward extraction, not a design change.
"""

import logging
import os
from datetime import datetime

from config import CONFIG

ICONS = {
    "SCAN":    "🔍",
    "ATTACK":  "⚔️ ",
    "SUCCESS": "🎉😄",
    "FAIL":    "😤💀",
    "ERROR":   "😭🔥",
    "TOOL":    "✅👍",
    "MEMORY":  "🧠",
    "MODEL":   "🤖",
    "CHAIN":   "🔗",
    "REPORT":  "📝",
    "ENGAGE":  "💣",
    "GOAL":    "🎯",
    "START":   "🚀",
    "FILE":    "📁",
    "WEB":     "🌐",
    "CREDS":   "🔑",
}


class EmojiFormatter(logging.Formatter):
    def format(self, record):
        time = datetime.now().strftime("%H:%M:%S")
        msg = record.getMessage()
        icon = "ℹ️ "
        for key, emoji in ICONS.items():
            if f"[{key}]" in msg:
                icon = emoji
                msg = msg.replace(f"[{key}]", "").strip()
                break
        if record.levelno == logging.WARNING:
            icon = "😤💀"
        if record.levelno == logging.ERROR:
            icon = "😭🔥"
        return f"[{time}] {icon}  {msg}"


def setup_logger(name="agent", session_id=None):
    """Creates the named logger, writing to CONFIG.LOG_DIR/session_<id>.log
    and stderr, both formatted with EmojiFormatter.

    Returns (logger, log_file_path, session_id) -- callers that also need a
    structured JSON log (see logger.AgentLogger) should reuse the returned
    session_id so the two files correlate.
    """
    session_id = session_id or datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(CONFIG.LOG_DIR, f"session_{session_id}.log")

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    logger.handlers = []

    fmt = EmojiFormatter()
    fh = logging.FileHandler(log_file)
    fh.setFormatter(fmt)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    logger.addHandler(fh)
    logger.addHandler(sh)

    return logger, log_file, session_id
