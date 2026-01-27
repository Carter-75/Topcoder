import json
import os
import uuid
from datetime import datetime
from typing import Dict, Any

AUDIT_LOG_PATH = os.environ.get("AUDIT_LOG_PATH", "audit_log.jsonl")
AUDIT_LOG_ENABLED = os.environ.get("AUDIT_LOG_ENABLED", "true").lower() == "true"
AUDIT_LOG_STORE_OUTPUT = os.environ.get("AUDIT_LOG_STORE_OUTPUT", "true").lower() == "true"

def write_audit_log(entry: Dict[str, Any]) -> str | None:
    if not AUDIT_LOG_ENABLED:
        return None
    entry["timestamp"] = datetime.utcnow().isoformat() + "Z"
    entry.setdefault("audit_id", str(uuid.uuid4()))
    try:
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        return None
    return entry.get("audit_id")

def write_resolution(audit_id: str, resolution: str, actor: str | None = None) -> None:
    if not AUDIT_LOG_ENABLED:
        return
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "audit_id": audit_id,
        "event": "resolution",
        "resolution": resolution,
        "actor": actor,
    }
    try:
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass

# For exporting logs (simple API or CLI can read the file)
def export_audit_log() -> list:
    if not os.path.exists(AUDIT_LOG_PATH):
        return []
    with open(AUDIT_LOG_PATH, "r", encoding="utf-8") as f:
        return [json.loads(line) for line in f]
