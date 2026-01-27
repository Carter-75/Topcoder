import json
import os
from datetime import datetime
from typing import Dict, Any

AUDIT_LOG_PATH = os.environ.get("AUDIT_LOG_PATH", "audit_log.jsonl")

def write_audit_log(entry: Dict[str, Any]):
    entry["timestamp"] = datetime.utcnow().isoformat() + "Z"
    with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

# For exporting logs (simple API or CLI can read the file)
def export_audit_log() -> list:
    if not os.path.exists(AUDIT_LOG_PATH):
        return []
    with open(AUDIT_LOG_PATH, "r", encoding="utf-8") as f:
        return [json.loads(line) for line in f]
