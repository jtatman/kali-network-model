import json
import os
from datetime import datetime

from config import CONFIG


class AgentLogger:
    def __init__(self, session_id=None):
        # Reuse the caller's session_id (e.g. from logging_setup.setup_logger())
        # when given, so the JSON log and the emoji text log correlate.
        session_id = session_id or datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = os.path.join(CONFIG.LOG_DIR, f"session_{session_id}.json")
        self.session = {
            "session_id": session_id,
            "started_at": datetime.now().isoformat(),
            "events": []
        }
        self._save()

    def log(self, event_type, data):
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "data": data
        }
        self.session["events"].append(event)
        self._save()

    def log_tool_call(self, tool_name, parameters, result):
        self.log("tool_call", {
            "tool": tool_name,
            "parameters": parameters,
            "result": result
        })

    def log_decision(self, reasoning, chosen_action):
        self.log("decision", {
            "reasoning": reasoning,
            "chosen_action": chosen_action
        })

    def log_error(self, tool_name, error_message):
        self.log("error", {
            "tool": tool_name,
            "error": error_message
        })

    def close(self):
        self.session["ended_at"] = datetime.now().isoformat()
        self._save()
        print(f"[LOGGER] Session saved to {self.log_file}")

    def _save(self):
        with open(self.log_file, "w") as f:
            json.dump(self.session, f, indent=2)


def replay(log_file):
    with open(log_file, "r") as f:
        session = json.load(f)
    print(f"\n=== REPLAY: Session {session['session_id']} ===")
    print(f"Started: {session['started_at']}")
    for event in session["events"]:
        print(f"\n[{event['timestamp']}] {event['event_type'].upper()}")
        print(json.dumps(event["data"], indent=2))
    print(f"\nEnded: {session.get('ended_at', 'N/A')}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        replay(sys.argv[1])
    else:
        print("Usage: python3 logger.py logs/session_TIMESTAMP.json")

