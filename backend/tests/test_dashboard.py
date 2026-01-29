import sys
import os
import importlib
from fastapi.testclient import TestClient
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

def _load_app():
    import main as main_module
    importlib.reload(main_module)
    return main_module.app

def test_dashboard_route(monkeypatch, tmp_path):
    # Create a fake audit log
    log_path = tmp_path / "audit_log.jsonl"
    entries = [
        {"timestamp": "2026-01-28T12:00:00Z", "policy": "blocking", "output": {"issues": [1,2]}, "override_allowed": True},
        {"timestamp": "2026-01-28T12:01:00Z", "policy": "advisory", "output": {"issues": []}, "override_allowed": False}
    ]
    with open(log_path, "w", encoding="utf-8") as f:
        for entry in entries:
            import json
            f.write(json.dumps(entry) + "\n")
    monkeypatch.setenv("AUDIT_LOG_PATH", str(log_path))
    app = _load_app()
    client = TestClient(app)
    resp = client.get("/dashboard")
    assert resp.status_code == 200
    assert "Guardrails Audit Dashboard" in resp.text
    assert "Total Analyses: <b>2</b>" in resp.text
    assert "blocking" in resp.text and "advisory" in resp.text
