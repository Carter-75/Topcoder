import sys
import os
import importlib

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def _load_app():
    import main as main_module
    importlib.reload(main_module)
    return main_module.app


def test_analyze_without_token_required(monkeypatch):
    monkeypatch.setenv("GUARDRAILS_API_TOKEN", "")
    monkeypatch.setenv("REQUIRE_AI_REVIEW", "false")
    app = _load_app()
    client = TestClient(app)
    response = client.post("/analyze", json={
        "code": "print('ok')",
        "repo_path": ".",
        "require_ai_review": False,
    })
    assert response.status_code == 200


def test_analyze_requires_token_when_configured(monkeypatch):
    monkeypatch.setenv("GUARDRAILS_API_TOKEN", "test-token")
    monkeypatch.setenv("REQUIRE_AI_REVIEW", "false")
    app = _load_app()
    client = TestClient(app)
    blocked = client.post("/analyze", json={
        "code": "print('ok')",
        "repo_path": ".",
        "require_ai_review": False,
    })
    assert blocked.status_code == 401
    allowed = client.post(
        "/analyze",
        headers={"Authorization": "Bearer test-token"},
        json={
            "code": "print('ok')",
            "repo_path": ".",
            "require_ai_review": False,
        },
    )
    assert allowed.status_code == 200


def test_admin_token_protects_audit_export(monkeypatch):
    monkeypatch.setenv("GUARDRAILS_ADMIN_TOKEN", "admin-token")
    app = _load_app()
    client = TestClient(app)
    blocked = client.get("/audit/export")
    assert blocked.status_code == 401
    allowed = client.get("/audit/export", headers={"Authorization": "Bearer admin-token"})
    assert allowed.status_code == 200