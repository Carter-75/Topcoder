import json
import os
import uuid
import hmac
import hashlib
from datetime import datetime
from typing import Dict, Any

AUDIT_LOG_PATH = os.environ.get("AUDIT_LOG_PATH", "/tmp/audit_log.jsonl")
AUDIT_LOG_ENABLED = os.environ.get("AUDIT_LOG_ENABLED", "true").lower() == "true"
AUDIT_LOG_STORE_OUTPUT = os.environ.get("AUDIT_LOG_STORE_OUTPUT", "true").lower() == "true"
AUDIT_LOG_MAX_BYTES = int(os.environ.get("AUDIT_LOG_MAX_BYTES", "5000000"))
AUDIT_LOG_MAX_FILES = int(os.environ.get("AUDIT_LOG_MAX_FILES", "5"))
AUDIT_LOG_HMAC_KEY = os.environ.get("AUDIT_LOG_HMAC_KEY", "").encode("utf-8")
_LAST_HASH: str | None = None


def _load_last_hash() -> str | None:
    global _LAST_HASH
    if _LAST_HASH:
        return _LAST_HASH
    if not os.path.exists(AUDIT_LOG_PATH):
        return None
    try:
        last_line = ""
        with open(AUDIT_LOG_PATH, "r", encoding="utf-8") as f:
            for line in f:
                last_line = line
        if not last_line:
            return None
        data = json.loads(last_line)
        value = data.get("hash")
        if isinstance(value, str) and value:
            _LAST_HASH = value
            return value
    except Exception:
        return None
    return None


def _compute_hash(entry: Dict[str, Any]) -> str | None:
    if not AUDIT_LOG_HMAC_KEY:
        return None
    prev_hash = _load_last_hash()
    payload = json.dumps({**entry, "prev_hash": prev_hash}, sort_keys=True).encode("utf-8")
    digest = hmac.new(AUDIT_LOG_HMAC_KEY, payload, hashlib.sha256).hexdigest()
    return digest


def _rotate_if_needed() -> None:
    if AUDIT_LOG_MAX_BYTES <= 0:
        return
    if not os.path.exists(AUDIT_LOG_PATH):
        return
    try:
        if os.path.getsize(AUDIT_LOG_PATH) < AUDIT_LOG_MAX_BYTES:
            return
    except OSError:
        return
    for idx in range(AUDIT_LOG_MAX_FILES - 1, 0, -1):
        src = f"{AUDIT_LOG_PATH}.{idx}"
        dst = f"{AUDIT_LOG_PATH}.{idx + 1}"
        if os.path.exists(src):
            try:
                os.replace(src, dst)
            except OSError:
                continue
    try:
        os.replace(AUDIT_LOG_PATH, f"{AUDIT_LOG_PATH}.1")
    except OSError:
        return
    global _LAST_HASH
    _LAST_HASH = None

def write_audit_log(entry: Dict[str, Any]) -> str | None:
    if not AUDIT_LOG_ENABLED:
        return None
    _rotate_if_needed()
    entry["timestamp"] = datetime.utcnow().isoformat() + "Z"
    entry.setdefault("audit_id", str(uuid.uuid4()))
    digest = _compute_hash(entry)
    if digest:
        entry["hash"] = digest
        entry["prev_hash"] = _load_last_hash()
    try:
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        if digest:
            global _LAST_HASH
            _LAST_HASH = digest
    except Exception:
        return None
    return entry.get("audit_id")

def write_resolution(audit_id: str, resolution: str, actor: str | None = None) -> None:
    if not AUDIT_LOG_ENABLED:
        return
    _rotate_if_needed()
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "audit_id": audit_id,
        "event": "resolution",
        "resolution": resolution,
        "actor": actor,
    }
    digest = _compute_hash(entry)
    if digest:
        entry["hash"] = digest
        entry["prev_hash"] = _load_last_hash()
    try:
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        if digest:
            global _LAST_HASH
            _LAST_HASH = digest
    except Exception:
        pass

# For exporting logs (simple API or CLI can read the file)
def export_audit_log() -> list:
    if not os.path.exists(AUDIT_LOG_PATH):
        return []
    with open(AUDIT_LOG_PATH, "r", encoding="utf-8") as f:
        return [json.loads(line) for line in f]
