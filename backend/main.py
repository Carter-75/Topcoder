
from fastapi import FastAPI, Request, BackgroundTasks, Response as FastAPIResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse, Response, FileResponse
import sys
import os
import re
import uuid
import time
import threading
from typing import Dict, Any, List
from pydantic import BaseModel, Field
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import security_rules
import ai_review
import coding_standards
import license_ip
import policy
import audit_log
import config_loader
import rule_engine
import guidelines
import settings_store

# Import dashboard endpoint
import dashboard

app = FastAPI(title="Guardrails Backend API", docs_url=None, redoc_url=None)
JOB_STORE: Dict[str, Dict[str, Any]] = {}
APP_SETTINGS: Dict[str, Any] = {
    "openai_api_key": settings_store.load_api_key(),
    "require_ai_review_default": settings_store.load_require_ai_review_default(),
    "autofix_default": settings_store.load_autofix_default(),
    "fix_mode_default": settings_store.load_fix_mode_default(),
    "ai_model": settings_store.load_ai_model(),
    "ai_review_max_chars": settings_store.load_ai_review_max_chars(),
}

RATE_LIMIT_RPS = int(os.environ.get("RATE_LIMIT_RPS", "10"))
RATE_LIMIT_BURST = int(os.environ.get("RATE_LIMIT_BURST", "20"))
RATE_LIMIT_WINDOW = int(os.environ.get("RATE_LIMIT_WINDOW", "10"))
RATE_LIMIT_ENABLED = os.environ.get("RATE_LIMIT_ENABLED", "true").lower() == "true"
SECURE_COOKIES = os.environ.get("SECURE_COOKIES", "false").lower() == "true"

_RATE_LIMIT_STORE: Dict[str, List[float]] = {}
_RATE_LIMIT_LOCK = threading.Lock()


class CodeFile(BaseModel):
    path: str
    code: str
    patch: str | None = None
    language: str | None = None


class AnalyzeRequest(BaseModel):
    code: str = ""
    sector: str | None = None
    repo_path: str = "."
    policy: dict | None = None
    ai_generated: bool = False
    ai_api_key: str | None = None
    require_ai_review: bool | None = None
    ai_model: str | None = None
    ai_review_max_chars: int | None = None
    path: str | None = None
    language: str | None = None
    patch: str | None = None
    repo: str | None = None
    pr_number: int | None = None
    commit: str | None = None
    repo_license_texts: List[Dict[str, str]] | None = None


class AnalyzeBatchRequest(BaseModel):
    files: List[CodeFile] = Field(default_factory=list)
    sector: str | None = None
    repo_path: str = "."
    policy: dict | None = None
    ai_generated: bool = False
    ai_api_key: str | None = None
    require_ai_review: bool | None = None
    ai_model: str | None = None
    ai_review_max_chars: int | None = None
    repo: str | None = None
    pr_number: int | None = None
    commit: str | None = None
    repo_license_texts: List[Dict[str, str]] | None = None


class AsyncScanRequest(AnalyzeBatchRequest):
    user_key: str | None = None


class RulepackUploadRequest(BaseModel):
    name: str
    rules: List[Dict[str, Any]] = Field(default_factory=list)


class AuditResolveRequest(BaseModel):
    audit_id: str
    resolution: str
    actor: str | None = None


class AutofixFullRequest(BaseModel):
    code: str
    path: str | None = "unknown"
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    repo_path: str | None = None
    ai_model: str | None = None
    ai_api_key: str | None = None


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    if not RATE_LIMIT_ENABLED:
        return await call_next(request)
    key = _get_client_ip(request)
    now = time.time()
    window = max(1, RATE_LIMIT_WINDOW)
    max_requests = (RATE_LIMIT_RPS * window) + RATE_LIMIT_BURST
    with _RATE_LIMIT_LOCK:
        timestamps = _RATE_LIMIT_STORE.get(key, [])
        timestamps = [ts for ts in timestamps if now - ts < window]
        if len(timestamps) >= max_requests:
            return JSONResponse({"error": "Rate limit exceeded."}, status_code=429)
        timestamps.append(now)
        _RATE_LIMIT_STORE[key] = timestamps
    return await call_next(request)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    csp = " ".join([
        "default-src 'self';",
        "img-src 'self' data:;",
        "font-src 'self' data: https://r2cdn.perplexity.ai;",
        "style-src 'self' 'unsafe-inline' https://unpkg.com;",
        "script-src 'self' 'unsafe-inline' https://unpkg.com;",
        "connect-src 'self';",
        "frame-ancestors 'none';",
    ])
    response.headers["Content-Security-Policy"] = csp
    if SECURE_COOKIES or request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


cors_origins_env = os.environ.get("CORS_ALLOW_ORIGINS", "").strip()
if cors_origins_env:
    origins = [item.strip() for item in cors_origins_env.split(",") if item.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"]
    )

def _resolve_sector(data: dict, repo_path: str) -> str:
    if data.get("sector"):
        return data["sector"]
    config = config_loader.load_config(repo_path)
    return config.get("sector", "finance")

def _resolve_policy_override(data: dict, repo_path: str) -> dict | None:
    if data.get("policy"):
        return data["policy"]
    if data.get("ai_generated"):
        base = policy.get_policy(repo_path)
        base["copilot_generated_code"] = "blocking"
        return base
    return None

def _sanitize_audit_input(data: dict) -> dict:
    sanitized = dict(data)
    if "code" in sanitized:
        sanitized["code"] = "<redacted>"
    if "ai_api_key" in sanitized:
        sanitized["ai_api_key"] = "<redacted>"
    if "repo_license_texts" in sanitized:
        sanitized["repo_license_texts"] = "<redacted>"
    if "files" in sanitized:
        sanitized["files"] = [{"path": f.get("path"), "size": len(f.get("code", ""))} for f in sanitized["files"]]
    return sanitized

def _get_user_scope_key(request: Request) -> str | None:
    scope = os.environ.get("SETTINGS_SCOPE", "global").lower()
    if scope == "ip":
        return request.headers.get("x-guardrails-user") or (request.client.host if request.client else None)
    if scope == "user":
        return request.headers.get("x-guardrails-user") or request.cookies.get("guardrails_user")
    return None


def _is_global_scope() -> bool:
    return os.environ.get("SETTINGS_SCOPE", "global").lower() == "global"


def _get_request_ai_key(request: Request, data: dict) -> str | None:
    header_key = request.headers.get("x-openai-api-key") or request.headers.get("x-openai-key")
    user_key = _get_user_scope_key(request)
    stored_key = settings_store.load_api_key(user_key)
    if _is_global_scope():
        return header_key or data.get("ai_api_key") or stored_key or APP_SETTINGS.get("openai_api_key") or os.environ.get("OPENAI_API_KEY")
    return header_key or data.get("ai_api_key") or stored_key

def _require_settings_token(request: Request) -> str | None:
    token = os.environ.get("SETTINGS_TOKEN")
    if not token:
        return None
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer ") and auth.split(" ", 1)[1] == token:
        return None
    return "Missing or invalid settings token."


def _require_api_token(request: Request, env_name: str, header_name: str) -> str | None:
    token = os.environ.get(env_name, "").strip()
    if not token:
        return None
    auth = request.headers.get("authorization", "")
    provided = auth.split(" ", 1)[1] if auth.lower().startswith("bearer ") else None
    if not provided:
        provided = request.headers.get(header_name)
    if provided == token:
        return None
    return "Missing or invalid API token."

def _resolve_require_ai_review(data: dict, request: Request | None = None) -> bool:
    if "require_ai_review" in data and isinstance(data.get("require_ai_review"), bool):
        return data["require_ai_review"]
    if request is not None:
        user_key = _get_user_scope_key(request)
        stored = settings_store.load_require_ai_review_default(user_key)
        if isinstance(stored, bool):
            return stored
    if isinstance(APP_SETTINGS.get("require_ai_review_default"), bool) and _is_global_scope():
        return APP_SETTINGS["require_ai_review_default"]
    if _is_global_scope():
        return os.environ.get("REQUIRE_AI_REVIEW", "true").lower() == "true"
    return os.environ.get("REQUIRE_AI_REVIEW_DEFAULT", "false").lower() == "true"

def _resolve_ai_model(data: dict, request: Request | None = None) -> str | None:
    if isinstance(data.get("ai_model"), str) and data.get("ai_model").strip():
        return data.get("ai_model").strip()
    if request is not None:
        user_key = _get_user_scope_key(request)
        stored = settings_store.load_ai_model(user_key)
        if stored:
            return stored
    if isinstance(APP_SETTINGS.get("ai_model"), str) and _is_global_scope():
        return APP_SETTINGS["ai_model"]
    return os.environ.get("OPENAI_MODEL")

def _resolve_ai_review_max_chars(data: dict, request: Request | None = None) -> int | None:
    value = data.get("ai_review_max_chars")
    if isinstance(value, int) and value > 0:
        return value
    if request is not None:
        user_key = _get_user_scope_key(request)
        stored = settings_store.load_ai_review_max_chars(user_key)
        if isinstance(stored, int) and stored > 0:
            return stored
    stored_app = APP_SETTINGS.get("ai_review_max_chars")
    if isinstance(stored_app, int) and stored_app > 0 and _is_global_scope():
        return stored_app
    env_value = os.environ.get("AI_REVIEW_MAX_CHARS")
    if env_value and env_value.isdigit():
        return int(env_value)
    return None

def _summarize_output(output: dict) -> dict:
    return {
        "policy": output.get("policy"),
        "override_allowed": output.get("override_allowed"),
        "counts": {
            "issues": len(output.get("issues", [])),
            "coding": len(output.get("coding_issues", [])),
            "license_ip": len(output.get("license_ip_issues", [])),
            "sector": len(output.get("sector_issues", [])),
            "ai": len(output.get("ai_suggestions", [])),
            "repo_license": len(output.get("repo_license_issues", [])),
        },
    }

def _sanitize_issue(issue: dict) -> dict:
    if not isinstance(issue, dict):
        return {}
    sanitized = dict(issue)
    for key in ["match", "pattern", "snippet", "patch", "code", "diff", "raw", "original_file"]:
        if key in sanitized:
            sanitized.pop(key, None)
    return sanitized

def _sanitize_audit_output(output: dict) -> dict:
    if not isinstance(output, dict):
        return {}
    sanitized = dict(output)
    for key in ["issues", "coding_issues", "license_ip_issues", "sector_issues", "ai_suggestions", "repo_license_issues"]:
        if isinstance(sanitized.get(key), list):
            sanitized[key] = [_sanitize_issue(item) for item in sanitized[key]]
    if isinstance(sanitized.get("findings"), dict):
        findings = {}
        for path, result in sanitized["findings"].items():
            if not isinstance(result, dict):
                continue
            findings[path] = _sanitize_audit_output(result)
        sanitized["findings"] = findings
    return sanitized

def _apply_guidelines(analysis: dict) -> None:
    for group in [
        "issues",
        "coding_issues",
        "license_ip_issues",
        "sector_issues",
    ]:
        for issue in analysis.get(group, []):
            link = guidelines.get_guideline_link(issue.get("type", ""))
            if link:
                issue["guideline_url"] = link

def _enforce_data_residency(repo_path: str) -> str | None:
    config = config_loader.load_config(repo_path)
    desired = config.get("data_residency")
    enforced = os.environ.get("DATA_RESIDENCY")
    if desired and enforced and desired != enforced:
        return f"Repository requires data residency '{desired}', but server is '{enforced}'."
    return None

def _collect_repo_license_issues(repo_path: str, license_texts: List[Dict[str, str]] | None = None) -> List[Dict[str, Any]]:
    if not repo_path or not os.path.isdir(repo_path):
        if not license_texts:
            return []
    config = config_loader.load_config(repo_path)
    restricted = config.get("restricted_licenses", ["GPL", "AGPL", "SSPL", "Elastic-2.0", "Commons-Clause"])
    if license_texts:
        detected = license_ip.scan_license_texts(license_texts)
    else:
        detected = license_ip.scan_repo_licenses(repo_path)
    issues = []
    for license_name in detected:
        issues.append({
            "type": "repo_license_detected",
            "license": license_name,
            "message": f"Repository license detected: {license_name}.",
            "severity": "warning",
        })
        if isinstance(restricted, list) and any(license_name.lower() == item.lower() for item in restricted):
            issues.append({
                "type": "restricted_license",
                "license": license_name,
                "message": f"Restricted license detected in repository: {license_name}.",
                "severity": "blocking",
            })
    return issues


def _guess_language(file_path: str) -> str:
    ext = os.path.splitext(file_path)[1].lower()
    return {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".jsx": "javascript",
        ".tsx": "typescript",
        ".java": "java",
        ".cs": "csharp",
        ".go": "go",
        ".rs": "rust",
        ".cpp": "cpp",
        ".c": "c",
        ".h": "c",
        ".hpp": "cpp",
        ".html": "html",
        ".css": "css",
        ".scss": "scss",
        ".json": "json",
        ".yml": "yaml",
        ".yaml": "yaml",
        ".toml": "toml",
        ".ini": "ini",
        ".md": "markdown",
        ".sh": "shell",
        ".ps1": "powershell",
    }.get(ext, "text")

def _analyze_code(
    code: str,
    sector: str,
    repo_path: str,
    policy_override: dict | None = None,
    ai_key: str | None = None,
    require_ai_review: bool | None = None,
    ai_generated: bool = False,
    ai_context: dict | None = None,
    language: str | None = None,
    extra_license_ip_issues: List[Dict[str, Any]] | None = None,
    repo_license_issues: List[Dict[str, Any]] | None = None,
    ai_model: str | None = None,
    ai_review_max_chars: int | None = None,
    user_key: str | None = None,
) -> dict:
    issues = security_rules.run_security_rules(code, ai_generated=ai_generated)
    coding_issues = coding_standards.run_coding_standards_rules(code, repo_path=repo_path, language=language)
    license_ip_issues = license_ip.run_license_ip_checks(code, repo_path=repo_path)
    if extra_license_ip_issues:
        license_ip_issues.extend(extra_license_ip_issues)
    ai_suggestions = ai_review.ai_review(
        code,
        api_key_override=ai_key,
        require_ai_override=require_ai_review,
        context=ai_context,
        model_override=ai_model,
        max_chars_override=ai_review_max_chars,
    )
    if any(suggestion.get("type") == "ai_review_missing_key" for suggestion in ai_suggestions):
        issues.append({
            "type": "ai_review_missing_key",
            "message": "OPENAI_API_KEY is required for AI review.",
            "explanation": "Set OPENAI_API_KEY in the environment to enable AI review for all scans.",
            "severity": "blocking",
        })
    rules = rule_engine.load_rulepack(sector)
    sector_issues = rule_engine.apply_rulepack_rules(code, rules)
    policy_mode = policy.evaluate_policy(
        issues,
        coding_issues,
        license_ip_issues + sector_issues + (repo_license_issues or []),
        repo_path=repo_path,
        policy_override=policy_override,
    )
    override_allowed = policy.is_override_allowed(repo_path, user_key=user_key) if policy_mode == "blocking" else False
    return {
        "issues": issues,
        "coding_issues": coding_issues,
        "license_ip_issues": license_ip_issues,
        "sector_issues": sector_issues,
        "ai_suggestions": ai_suggestions,
        "policy": policy_mode,
        "override_allowed": override_allowed,
    }

@app.get("/dashboard")
def dashboard_view():
    return dashboard.dashboard()

@app.get("/health", include_in_schema=False)
def health():
    return {"status": "ok"}

@app.get("/")
def root():
    return dashboard.dashboard()

@app.get("/favicon.ico")
def favicon():
    icon_path = os.path.join(os.path.dirname(__file__), "static", "favicon.svg")
    if os.path.exists(icon_path):
        return FileResponse(icon_path, media_type="image/svg+xml")
    return Response(status_code=204)

@app.get("/docs", include_in_schema=False)
def docs_ui():
    html = """
    <!doctype html>
    <html>
    <head>
        <title>Guardrails API Docs</title>
        <meta name='viewport' content='width=device-width, initial-scale=1'>
        <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
        <style>
            :root {
                --bg: #0b1020;
                --surface: #121933;
                --card: #151f3d;
                --text: #e2e8f0;
                --muted: #94a3b8;
                --primary: #60a5fa;
                --primary-strong: #3b82f6;
                --success: #22c55e;
                --warning: #f59e0b;
                --danger: #ef4444;
                --border: #243158;
                --shadow: 0 12px 30px rgba(2, 6, 23, 0.45);
                --glow: 0 0 0 3px rgba(96, 165, 250, 0.25);
            }
            body {
                margin: 0;
                background: radial-gradient(circle at top, #141b3a 0%, #0b1020 55%, #070b16 100%);
                color: var(--text);
                font-family: 'Segoe UI', Arial, sans-serif;
            }
            .swagger-ui {
                max-width: 1100px;
                margin: 2rem auto;
                padding: 1rem 1.5rem 2rem;
                background: linear-gradient(160deg, rgba(21,31,61,0.98), rgba(16,25,48,0.96));
                border-radius: 18px;
                box-shadow: var(--shadow);
                border: 1px solid var(--border);
            }
            .swagger-ui .topbar {
                background: transparent;
                border-bottom: 1px solid var(--border);
            }
            .swagger-ui .topbar .download-url-wrapper input[type=text] {
                background: #0f172a;
                color: var(--text);
                border: 1px solid var(--border);
            }
            .swagger-ui .info .title,
            .swagger-ui .opblock-tag,
            .swagger-ui .opblock-tag small {
                color: var(--text);
            }
            .swagger-ui .opblock {
                background: rgba(15, 23, 42, 0.7);
                border: 1px solid var(--border);
                box-shadow: none;
            }
            .swagger-ui .opblock .opblock-summary {
                border-bottom: 1px solid var(--border);
            }
            .swagger-ui .btn {
                background: var(--primary-strong);
                color: #fff;
                border: none;
                border-radius: 999px;
                box-shadow: none;
            }
            .swagger-ui .btn:hover {
                background: var(--primary);
            }
            .swagger-ui .model-box,
            .swagger-ui .parameters-col_description input,
            .swagger-ui .parameters-col_description textarea,
            .swagger-ui .responses-wrapper,
            .swagger-ui .response-content-type {
                background: #0f172a;
                color: var(--text);
                border: 1px solid var(--border);
            }
            .swagger-ui .parameter__name,
            .swagger-ui .parameter__type,
            .swagger-ui .response-col_status,
            .swagger-ui .response-col_description {
                color: var(--text);
            }
            .swagger-ui .opblock-description-wrapper,
            .swagger-ui .opblock-external-docs-wrapper,
            .swagger-ui .opblock-title_normal {
                color: var(--muted);
            }
            .swagger-ui .scheme-container {
                background: transparent;
                box-shadow: none;
                border: none;
            }
            .swagger-ui select {
                background: #0f172a;
                color: var(--text);
                border: 1px solid var(--border);
            }
        </style>
    </head>
    <body>
        <div id="swagger-ui"></div>
        <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
        <script>
            window.ui = SwaggerUIBundle({
                url: '/openapi.json',
                dom_id: '#swagger-ui',
                deepLinking: true,
                docExpansion: 'list',
                filter: true,
                tryItOutEnabled: true
            });
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html)

@app.get("/settings")
def get_settings(request: Request, response: FastAPIResponse):
    user_key = _get_user_scope_key(request)
    if os.environ.get("SETTINGS_SCOPE", "global").lower() == "user" and not user_key:
        user_key = uuid.uuid4().hex
        response.set_cookie("guardrails_user", user_key, httponly=True, samesite="Lax", secure=SECURE_COOKIES)
    require_ai = _resolve_require_ai_review({}, request=request)
    stored_key = settings_store.load_api_key(user_key)
    stored_ai = settings_store.load_require_ai_review_default(user_key)
    stored_autofix = settings_store.load_autofix_default(user_key)
    stored_fix_mode = settings_store.load_fix_mode_default(user_key)
    stored_model = settings_store.load_ai_model(user_key)
    stored_max_chars = settings_store.load_ai_review_max_chars(user_key)
    stored_override_allowed = settings_store.load_override_allowed_default(user_key)
    return {
        "openai_api_key_set": bool(stored_key) if not _is_global_scope() else bool(stored_key or APP_SETTINGS.get("openai_api_key") or os.environ.get("OPENAI_API_KEY")),
        "require_ai_review": require_ai,
        "require_ai_review_default": stored_ai,
        "autofix_default": stored_autofix,
        "fix_mode_default": stored_fix_mode,
        "override_allowed_default": stored_override_allowed,
        "ai_model": stored_model or (APP_SETTINGS.get("ai_model") if _is_global_scope() else None) or os.environ.get("OPENAI_MODEL") or "gpt-4o-mini",
        "ai_review_max_chars": stored_max_chars or (APP_SETTINGS.get("ai_review_max_chars") if _is_global_scope() else None) or int(os.environ.get("AI_REVIEW_MAX_CHARS", "12000")),
        "persistent_enabled": bool(os.environ.get("SETTINGS_ENC_KEY") or os.environ.get("SETTINGS_KEY_PATH")),
        "settings_scope": os.environ.get("SETTINGS_SCOPE", "global"),
        "user_key_present": bool(user_key),
    }

@app.post("/settings/token")
def issue_user_token(request: Request, response: FastAPIResponse):
    previous_key = _get_user_scope_key(request)
    user_key = uuid.uuid4().hex
    if previous_key and previous_key != user_key:
        settings_store.clone_user_settings(previous_key, user_key)
    response.set_cookie("guardrails_user", user_key, httponly=True, samesite="Lax", secure=SECURE_COOKIES)
    return {"user_token": user_key}


@app.get("/settings/token/current")
def current_user_token(request: Request):
    user_key = _get_user_scope_key(request)
    return {"user_token": user_key}


@app.post("/settings/token/assign")
async def assign_user_token(request: Request, response: FastAPIResponse):
    auth_error = _require_settings_token(request)
    if auth_error:
        return JSONResponse({"error": auth_error}, status_code=401)
    data = await request.json()
    token = data.get("user_token")
    if not isinstance(token, str) or not token.strip():
        return JSONResponse({"error": "user_token is required."}, status_code=400)
    response.set_cookie("guardrails_user", token.strip(), httponly=True, samesite="Lax", secure=SECURE_COOKIES)
    return {"user_token": token.strip()}

@app.get("/settings/ui")
def settings_ui():
    html = """
    <html>
    <head>
        <title>Guardrails Settings</title>
        <meta name='viewport' content='width=device-width, initial-scale=1'>
        <style>
            :root {
                --bg: #0b1020;
                --surface: #121933;
                --card: #151f3d;
                --text: #e2e8f0;
                --muted: #94a3b8;
                --primary: #60a5fa;
                --primary-strong: #3b82f6;
                --success: #22c55e;
                --warning: #f59e0b;
                --danger: #ef4444;
                --border: #243158;
                --shadow: 0 12px 30px rgba(2, 6, 23, 0.45);
                --glow: 0 0 0 3px rgba(96, 165, 250, 0.25);
            }
            * { box-sizing: border-box; }
            body { margin: 0; font-family: 'Segoe UI', Arial, sans-serif; background: radial-gradient(circle at top, #141b3a 0%, #0b1020 55%, #070b16 100%); color: var(--text); }
            .container { max-width: 980px; margin: 2.5rem auto; padding: 0 1.25rem; }
            .panel { background: linear-gradient(160deg, rgba(21,31,61,0.98), rgba(16,25,48,0.96)); border-radius: 18px; box-shadow: var(--shadow); padding: 2.2rem; border: 1px solid var(--border); }
            h1 { margin: 0 0 0.4rem 0; font-size: 1.7rem; letter-spacing: 0.2px; }
            p { margin: 0.4rem 0 0 0; color: var(--muted); }
            label { display: block; font-weight: 600; margin: 1rem 0 0.4rem 0; color: var(--text); }
            input { width: 100%; padding: 0.75rem 0.85rem; border: 1px solid var(--border); border-radius: 12px; font-size: 0.98rem; background: #0f172a; color: var(--text); }
            input:focus { outline: none; border-color: var(--primary); box-shadow: var(--glow); }
            .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 1rem; margin-top: 1.6rem; }
            .card { padding: 1rem; background: rgba(15, 23, 42, 0.7); border-radius: 14px; border: 1px solid var(--border); }
            .section-title { font-weight: 600; margin-bottom: 0.4rem; color: var(--text); }
            .actions { margin-top: 1.1rem; display: flex; gap: 0.6rem; flex-wrap: wrap; }
            .btn { background: var(--primary-strong); color: #fff; border: 1px solid transparent; padding: 0.65rem 1rem; border-radius: 999px; font-size: 0.92rem; cursor: pointer; font-weight: 600; }
            .btn.secondary { background: #111827; border-color: #1f2937; }
            .btn.alt { background: var(--success); }
            .btn.warning { background: var(--warning); }
            .btn.ghost { background: transparent; color: var(--text); border-color: var(--border); }
            .btn:disabled { background: #475569; cursor: not-allowed; }
            .btn { transition: transform 0.15s ease, box-shadow 0.15s ease, background 0.2s ease, color 0.2s ease, border 0.2s ease; }
            .btn:hover { transform: translateY(-1px); box-shadow: 0 10px 20px rgba(15, 23, 42, 0.4); }
            .btn:active { transform: translateY(0); box-shadow: none; }
            .btn.selected { border-color: var(--primary); box-shadow: var(--glow); }
            .btn.selected::after { content: "Active"; margin-left: 0.5rem; background: rgba(15, 23, 42, 0.8); color: #fff; padding: 0.15rem 0.5rem; border-radius: 999px; font-size: 0.72rem; }
            .pulse { animation: pulse 0.6s ease; }
            @keyframes pulse { 0% { box-shadow: 0 0 0 0 rgba(96, 165, 250, 0.35); } 100% { box-shadow: 0 0 0 12px transparent; } }
            .status { margin-top: 0.8rem; font-size: 0.95rem; }
            .success { color: var(--success); }
            .error { color: var(--danger); }
            .muted { color: var(--muted); }
        </style>
    </head>
    <body>
        <div class='container'>
            <div class='panel'>
                <h1>Guardrails Settings</h1>
                <p class='muted'>Configure your AI review and fix preferences.</p>

                <div class='grid'>
                    <div class='card'>
                        <div class='section-title'>Status</div>
                        <div id='current-status' class='status muted'>Checking current status...</div>
                        <div id='enc-status' class='status muted'></div>
                    </div>
                    <div class='card'>
                        <div class='section-title'>User token</div>
                        <div id='token-value' class='status muted'>Loading token...</div>
                        <div class='actions'>
                            <button id='copyTokenBtn' type='button' class='btn ghost'>Copy token</button>
                            <button id='regenTokenBtn' type='button' class='btn warning'>Regenerate token</button>
                        </div>
                        <label for='tokenInput' style='margin-top: 0.9rem;'>Set token manually</label>
                        <input id='tokenInput' type='text' placeholder='Paste token from CLI' />
                        <div class='actions'>
                            <button id='setTokenBtn' type='button' class='btn'>Use this token</button>
                        </div>
                        <div class='status muted'>Use this token with <code>--user</code> or <code>X-Guardrails-User</code>.</div>
                    </div>
                    <div class='card'>
                        <div class='section-title'>Developer</div>
                        <div class='actions'>
                            <a class='btn ghost' href='/docs'>API Docs</a>
                            <a class='btn ghost' href='/health'>Health</a>
                        </div>
                        <div class='status muted'>Developer-only endpoints.</div>
                    </div>
                    <div class='card'>
                        <div class='section-title'>AI mode</div>
                        <div id='ai-mode-status' class='status muted'>Loading AI mode...</div>
                        <div class='actions'>
                            <button id='aiOnBtn' type='button' class='btn warning' aria-pressed='false'>Require AI</button>
                            <button id='aiOffBtn' type='button' class='btn ghost' aria-pressed='false'>Allow non-AI</button>
                        </div>
                    </div>
                    <div class='card'>
                        <div class='section-title'>Fix mode</div>
                        <div id='fixmode-status' class='status muted'>Loading fix mode...</div>
                        <div class='actions'>
                            <button id='fixFullBtn' type='button' class='btn alt' aria-pressed='false'>Full fix</button>
                            <button id='fixSafeBtn' type='button' class='btn' aria-pressed='false'>Safe fix</button>
                            <button id='fixNoneBtn' type='button' class='btn ghost' aria-pressed='false'>No fix</button>
                        </div>
                        <div class='status muted'>Full fix uses AI rewrite. Safe fix applies safe local fixes only.</div>
                    </div>
                    <div class='card'>
                        <div class='section-title'>Override blocking policy</div>
                        <div id='override-status' class='status muted'>Loading override settings...</div>
                        <div class='actions'>
                            <button id='overrideOnBtn' type='button' class='btn alt' aria-pressed='false'>Allow override</button>
                            <button id='overrideOffBtn' type='button' class='btn ghost' aria-pressed='false'>Disallow override</button>
                        </div>
                        <div class='status muted'>When enabled, blocking results can be overridden (for GitHub, apply the override label).</div>
                    </div>
                    <div class='card'>
                        <div class='section-title'>AI model</div>
                        <div id='ai-model-status' class='status muted'>Loading model...</div>
                        <input id='aiModelInput' type='text' placeholder='gpt-4o-mini' />
                        <div class='actions'>
                            <button id='saveModelBtn' type='button' class='btn'>Save model</button>
                        </div>
                    </div>
                    <div class='card'>
                        <div class='section-title'>AI review max chars</div>
                        <div id='ai-max-status' class='status muted'>Loading limit...</div>
                        <input id='aiMaxInput' type='number' min='1000' step='500' placeholder='12000' />
                        <div class='actions'>
                            <button id='saveMaxBtn' type='button' class='btn'>Save limit</button>
                        </div>
                    </div>
                </div>

                <label for='apiKey'>OpenAI API Key</label>
                <input id='apiKey' type='password' placeholder='sk-...' />

                <label for='settingsToken'>Settings Token (optional)</label>
                <input id='settingsToken' type='password' placeholder='Bearer token if required' />


                <div class='actions'>
                    <button id='saveBtn' class='btn'>Save Key</button>
                </div>
                <div id='result' class='status'></div>
            </div>
        </div>

        <script>
            const statusEl = document.getElementById('current-status');
            const encStatusEl = document.getElementById('enc-status');
            const aiModeEl = document.getElementById('ai-mode-status');
            const fixModeEl = document.getElementById('fixmode-status');
            const overrideEl = document.getElementById('override-status');
            const tokenValueEl = document.getElementById('token-value');
            const resultEl = document.getElementById('result');
            const saveBtn = document.getElementById('saveBtn');
            const aiOnBtn = document.getElementById('aiOnBtn');
            const aiOffBtn = document.getElementById('aiOffBtn');
            const fixFullBtn = document.getElementById('fixFullBtn');
            const fixSafeBtn = document.getElementById('fixSafeBtn');
            const fixNoneBtn = document.getElementById('fixNoneBtn');
            const overrideOnBtn = document.getElementById('overrideOnBtn');
            const overrideOffBtn = document.getElementById('overrideOffBtn');
            const copyTokenBtn = document.getElementById('copyTokenBtn');
            const regenTokenBtn = document.getElementById('regenTokenBtn');
            const tokenInput = document.getElementById('tokenInput');
            const setTokenBtn = document.getElementById('setTokenBtn');
            const aiModelStatus = document.getElementById('ai-model-status');
            const aiMaxStatus = document.getElementById('ai-max-status');
            const aiModelInput = document.getElementById('aiModelInput');
            const aiMaxInput = document.getElementById('aiMaxInput');
            const saveModelBtn = document.getElementById('saveModelBtn');
            const saveMaxBtn = document.getElementById('saveMaxBtn');
            let currentToken = '';

            async function fetchCurrentToken() {
                try {
                    const res = await fetch('/settings/token/current');
                    const data = await res.json();
                    if (data.user_token) {
                        currentToken = data.user_token;
                        tokenValueEl.textContent = data.user_token;
                        return data.user_token;
                    }
                } catch (err) {
                    // ignore
                }
                return '';
            }

            async function issueToken() {
                const res = await fetch('/settings/token', { method: 'POST' });
                const data = await res.json();
                if (data.user_token) {
                    currentToken = data.user_token;
                    tokenValueEl.textContent = data.user_token;
                    return data.user_token;
                }
                return '';
            }

            async function ensureUserToken() {
                const existing = await fetchCurrentToken();
                if (existing) {
                    return existing;
                }
                return await issueToken();
            }

            async function regenerateToken() {
                return await issueToken();
            }

            copyTokenBtn.addEventListener('click', async () => {
                if (!currentToken) {
                    return;
                }
                try {
                    await navigator.clipboard.writeText(currentToken);
                    copyTokenBtn.classList.add('pulse');
                    setTimeout(() => copyTokenBtn.classList.remove('pulse'), 650);
                } catch (err) {
                    // ignore
                }
            });

            regenTokenBtn.addEventListener('click', async () => {
                await regenerateToken();
                regenTokenBtn.classList.add('pulse');
                setTimeout(() => regenTokenBtn.classList.remove('pulse'), 650);
            });

            setTokenBtn.addEventListener('click', async () => {
                const value = tokenInput.value.trim();
                if (!value) {
                    resultEl.textContent = 'Token is required.';
                    resultEl.className = 'status error';
                    return;
                }
                const token = document.getElementById('settingsToken').value.trim();
                try {
                    const res = await fetch('/settings/token/assign', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            ...(token ? { 'Authorization': `Bearer ${token}` } : {})
                        },
                        body: JSON.stringify({ user_token: value })
                    });
                    const data = await res.json();
                    if (!res.ok) {
                        throw new Error(data.error || 'Failed to assign token.');
                    }
                    currentToken = data.user_token || value;
                    tokenValueEl.textContent = currentToken;
                    tokenInput.value = '';
                    resultEl.textContent = 'Token updated.';
                    resultEl.className = 'status success';
                    await refreshStatus();
                } catch (err) {
                    resultEl.textContent = err.message || 'Failed to assign token.';
                    resultEl.className = 'status error';
                }
            });

            async function refreshStatus() {
                try {
                    const res = await fetch('/settings');
                    const data = await res.json();
                    statusEl.textContent = data.openai_api_key_set
                        ? 'API key is configured.'
                        : 'API key is not configured.';
                    if (!data.persistent_enabled) {
                        encStatusEl.textContent = 'Persistence is off. Set SETTINGS_ENC_KEY or SETTINGS_KEY_PATH to keep settings across restarts.';
                        encStatusEl.className = 'status error';
                    } else {
                        encStatusEl.textContent = 'Persistence is enabled.';
                        encStatusEl.className = 'status success';
                    }
                    if (data.settings_scope === 'user') {
                        statusEl.textContent += data.user_key_present ? ' (User scoped)' : ' (User scoped: missing token)';
                    }
                    if (typeof data.require_ai_review_default === 'boolean') {
                        aiModeEl.textContent = data.require_ai_review
                            ? 'AI review is required by default.'
                            : 'Non-AI mode is allowed by default.';
                        aiOnBtn.classList.toggle('selected', !!data.require_ai_review);
                        aiOffBtn.classList.toggle('selected', !data.require_ai_review);
                        aiOnBtn.setAttribute('aria-pressed', data.require_ai_review ? 'true' : 'false');
                        aiOffBtn.setAttribute('aria-pressed', data.require_ai_review ? 'false' : 'true');
                    } else {
                        aiModeEl.textContent = 'AI mode default is not set.';
                        aiOnBtn.classList.remove('selected');
                        aiOffBtn.classList.remove('selected');
                        aiOnBtn.setAttribute('aria-pressed', 'false');
                        aiOffBtn.setAttribute('aria-pressed', 'false');
                    }
                    if (typeof data.fix_mode_default === 'string') {
                        fixModeEl.textContent = `Fix mode default: ${data.fix_mode_default}`;
                        fixFullBtn.classList.toggle('selected', data.fix_mode_default === 'full');
                        fixSafeBtn.classList.toggle('selected', data.fix_mode_default === 'safe');
                        fixNoneBtn.classList.toggle('selected', data.fix_mode_default === 'none');
                        fixFullBtn.setAttribute('aria-pressed', data.fix_mode_default === 'full' ? 'true' : 'false');
                        fixSafeBtn.setAttribute('aria-pressed', data.fix_mode_default === 'safe' ? 'true' : 'false');
                        fixNoneBtn.setAttribute('aria-pressed', data.fix_mode_default === 'none' ? 'true' : 'false');
                    } else {
                        fixModeEl.textContent = 'Fix mode default is not set.';
                        fixFullBtn.classList.remove('selected');
                        fixSafeBtn.classList.remove('selected');
                        fixNoneBtn.classList.remove('selected');
                        fixFullBtn.setAttribute('aria-pressed', 'false');
                        fixSafeBtn.setAttribute('aria-pressed', 'false');
                        fixNoneBtn.setAttribute('aria-pressed', 'false');
                    }
                    if (typeof data.override_allowed_default === 'boolean') {
                        overrideEl.textContent = data.override_allowed_default
                            ? 'Override is allowed for blocking policy.'
                            : 'Override is disabled for blocking policy.';
                        overrideOnBtn.classList.toggle('selected', !!data.override_allowed_default);
                        overrideOffBtn.classList.toggle('selected', !data.override_allowed_default);
                        overrideOnBtn.setAttribute('aria-pressed', data.override_allowed_default ? 'true' : 'false');
                        overrideOffBtn.setAttribute('aria-pressed', data.override_allowed_default ? 'false' : 'true');
                    } else {
                        overrideEl.textContent = 'Override default is not set.';
                        overrideOnBtn.classList.remove('selected');
                        overrideOffBtn.classList.remove('selected');
                        overrideOnBtn.setAttribute('aria-pressed', 'false');
                        overrideOffBtn.setAttribute('aria-pressed', 'false');
                    }
                    if (data.ai_model) {
                        aiModelStatus.textContent = `Current model: ${data.ai_model}`;
                        aiModelInput.value = data.ai_model;
                    } else {
                        aiModelStatus.textContent = 'AI model is not set.';
                    }
                    if (data.ai_review_max_chars) {
                        aiMaxStatus.textContent = `Current limit: ${data.ai_review_max_chars} chars`;
                        aiMaxInput.value = data.ai_review_max_chars;
                    } else {
                        aiMaxStatus.textContent = 'AI review max chars not set.';
                    }
                } catch (err) {
                    statusEl.textContent = 'Unable to load status.';
                    aiModeEl.textContent = 'Unable to load AI mode.';
                    overrideEl.textContent = 'Unable to load override settings.';
                    aiModelStatus.textContent = 'Unable to load AI model.';
                    aiMaxStatus.textContent = 'Unable to load AI limit.';
                }
            }

            saveBtn.addEventListener('click', async () => {
                resultEl.textContent = '';
                resultEl.className = 'status';
                const apiKey = document.getElementById('apiKey').value.trim();
                const token = document.getElementById('settingsToken').value.trim();
                if (!apiKey) {
                    resultEl.textContent = 'API key is required.';
                    resultEl.classList.add('error');
                    return;
                }
                saveBtn.disabled = true;
                try {
                    const res = await fetch('/settings/api-key', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            ...(token ? { 'Authorization': `Bearer ${token}` } : {})
                        },
                        body: JSON.stringify({ api_key: apiKey })
                    });
                    const data = await res.json();
                    if (!res.ok) {
                        throw new Error(data.error || 'Failed to save key.');
                    }
                    resultEl.textContent = 'Saved successfully.';
                    resultEl.classList.add('success');
                    document.getElementById('apiKey').value = '';
                    await refreshStatus();
                } catch (err) {
                    resultEl.textContent = err.message || 'Failed to save key.';
                    resultEl.classList.add('error');
                } finally {
                    saveBtn.disabled = false;
                }
            });

            async function setAiMode(value) {
                resultEl.textContent = '';
                resultEl.className = 'status';
                const token = document.getElementById('settingsToken').value.trim();
                try {
                    const res = await fetch('/settings/ai-mode', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            ...(token ? { 'Authorization': `Bearer ${token}` } : {})
                        },
                        body: JSON.stringify({ require_ai_review: value })
                    });
                    const data = await res.json();
                    if (!res.ok) {
                        throw new Error(data.error || 'Failed to update AI mode.');
                    }
                    resultEl.textContent = 'AI mode updated.';
                    resultEl.classList.add('success');
                    (value ? aiOnBtn : aiOffBtn).classList.add('pulse');
                    setTimeout(() => (value ? aiOnBtn : aiOffBtn).classList.remove('pulse'), 650);
                    await refreshStatus();
                } catch (err) {
                    resultEl.textContent = err.message || 'Failed to update AI mode.';
                    resultEl.classList.add('error');
                }
            }

            aiOnBtn.addEventListener('click', () => setAiMode(true));
            aiOffBtn.addEventListener('click', () => setAiMode(false));

            async function setFixMode(value) {
                resultEl.textContent = '';
                resultEl.className = 'status';
                const token = document.getElementById('settingsToken').value.trim();
                try {
                    const res = await fetch('/settings/fix-mode', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            ...(token ? { 'Authorization': `Bearer ${token}` } : {})
                        },
                        body: JSON.stringify({ fix_mode_default: value })
                    });
                    const data = await res.json();
                    if (!res.ok) {
                        throw new Error(data.error || 'Failed to update fix mode.');
                    }
                    resultEl.textContent = 'Fix mode updated.';
                    resultEl.classList.add('success');
                    if (value === 'full') {
                        fixFullBtn.classList.add('pulse');
                        setTimeout(() => fixFullBtn.classList.remove('pulse'), 650);
                    } else if (value === 'safe') {
                        fixSafeBtn.classList.add('pulse');
                        setTimeout(() => fixSafeBtn.classList.remove('pulse'), 650);
                    } else {
                        fixNoneBtn.classList.add('pulse');
                        setTimeout(() => fixNoneBtn.classList.remove('pulse'), 650);
                    }
                    await refreshStatus();
                } catch (err) {
                    resultEl.textContent = err.message || 'Failed to update fix mode.';
                    resultEl.classList.add('error');
                }
            }

            fixFullBtn.addEventListener('click', () => setFixMode('full'));
            fixSafeBtn.addEventListener('click', () => setFixMode('safe'));
            fixNoneBtn.addEventListener('click', () => setFixMode('none'));

            async function setOverrideAllowed(value) {
                resultEl.textContent = '';
                resultEl.className = 'status';
                const token = document.getElementById('settingsToken').value.trim();
                try {
                    const res = await fetch('/settings/override-allowed', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            ...(token ? { 'Authorization': `Bearer ${token}` } : {})
                        },
                        body: JSON.stringify({ override_allowed_default: value })
                    });
                    const data = await res.json();
                    if (!res.ok) {
                        throw new Error(data.error || 'Failed to update override setting.');
                    }
                    resultEl.textContent = 'Override setting updated.';
                    resultEl.classList.add('success');
                    (value ? overrideOnBtn : overrideOffBtn).classList.add('pulse');
                    setTimeout(() => (value ? overrideOnBtn : overrideOffBtn).classList.remove('pulse'), 650);
                    await refreshStatus();
                } catch (err) {
                    resultEl.textContent = err.message || 'Failed to update override setting.';
                    resultEl.classList.add('error');
                }
            }

            overrideOnBtn.addEventListener('click', () => setOverrideAllowed(true));
            overrideOffBtn.addEventListener('click', () => setOverrideAllowed(false));

            async function setAiModel() {
                resultEl.textContent = '';
                resultEl.className = 'status';
                const token = document.getElementById('settingsToken').value.trim();
                const value = aiModelInput.value.trim();
                if (!value) {
                    resultEl.textContent = 'AI model is required.';
                    resultEl.classList.add('error');
                    return;
                }
                saveModelBtn.disabled = true;
                try {
                    const res = await fetch('/settings/ai-model', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            ...(token ? { 'Authorization': `Bearer ${token}` } : {})
                        },
                        body: JSON.stringify({ ai_model: value })
                    });
                    const data = await res.json();
                    if (!res.ok) {
                        throw new Error(data.error || 'Failed to update AI model.');
                    }
                    resultEl.textContent = 'AI model updated.';
                    resultEl.classList.add('success');
                    await refreshStatus();
                } catch (err) {
                    resultEl.textContent = err.message || 'Failed to update AI model.';
                    resultEl.classList.add('error');
                } finally {
                    saveModelBtn.disabled = false;
                }
            }

            async function setAiMaxChars() {
                resultEl.textContent = '';
                resultEl.className = 'status';
                const token = document.getElementById('settingsToken').value.trim();
                const raw = aiMaxInput.value.trim();
                const value = Number(raw);
                if (!raw || Number.isNaN(value) || value <= 0) {
                    resultEl.textContent = 'AI review max chars must be a positive number.';
                    resultEl.classList.add('error');
                    return;
                }
                saveMaxBtn.disabled = true;
                try {
                    const res = await fetch('/settings/ai-max-chars', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            ...(token ? { 'Authorization': `Bearer ${token}` } : {})
                        },
                        body: JSON.stringify({ ai_review_max_chars: value })
                    });
                    const data = await res.json();
                    if (!res.ok) {
                        throw new Error(data.error || 'Failed to update AI limit.');
                    }
                    resultEl.textContent = 'AI review limit updated.';
                    resultEl.classList.add('success');
                    await refreshStatus();
                } catch (err) {
                    resultEl.textContent = err.message || 'Failed to update AI limit.';
                    resultEl.classList.add('error');
                } finally {
                    saveMaxBtn.disabled = false;
                }
            }

            saveModelBtn.addEventListener('click', setAiModel);
            saveMaxBtn.addEventListener('click', setAiMaxChars);

            ensureUserToken().then(refreshStatus);
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html)

@app.post("/settings/api-key")
async def set_api_key(request: Request):
    auth_error = _require_settings_token(request)
    if auth_error:
        return JSONResponse({"error": auth_error}, status_code=401)
    user_key = _get_user_scope_key(request)
    if not _is_global_scope() and not user_key:
        return JSONResponse({"error": "User scope required. Set X-Guardrails-User header."}, status_code=400)
    data = await request.json()
    key = data.get("api_key")
    if not key:
        return JSONResponse({"error": "api_key is required."}, status_code=400)
    APP_SETTINGS["openai_api_key"] = key if not user_key else APP_SETTINGS.get("openai_api_key")
    persisted = settings_store.save_api_key(key, user_key=user_key)
    if not persisted:
        return JSONResponse({
            "result": "saved",
            "persistent": False,
            "warning": "SETTINGS_ENC_KEY not set; key stored in memory only.",
        })
    return JSONResponse({"result": "saved", "persistent": True})

@app.post("/settings/ai-mode")
async def set_ai_mode(request: Request):
    auth_error = _require_settings_token(request)
    if auth_error:
        return JSONResponse({"error": auth_error}, status_code=401)
    user_key = _get_user_scope_key(request)
    if not _is_global_scope() and not user_key:
        return JSONResponse({"error": "User scope required. Set X-Guardrails-User header."}, status_code=400)
    data = await request.json()
    value = data.get("require_ai_review")
    if not isinstance(value, bool):
        return JSONResponse({"error": "require_ai_review must be a boolean."}, status_code=400)
    if not user_key:
        APP_SETTINGS["require_ai_review_default"] = value
    persisted = settings_store.save_require_ai_review_default(value, user_key=user_key)
    if not persisted:
        return JSONResponse({
            "result": "saved",
            "persistent": False,
            "warning": "SETTINGS_ENC_KEY not set; setting stored in memory only.",
        })
    return JSONResponse({"result": "saved", "persistent": True})

@app.post("/settings/autofix-mode")
async def set_autofix_mode(request: Request):
    auth_error = _require_settings_token(request)
    if auth_error:
        return JSONResponse({"error": auth_error}, status_code=401)
    user_key = _get_user_scope_key(request)
    if not _is_global_scope() and not user_key:
        return JSONResponse({"error": "User scope required. Set X-Guardrails-User header."}, status_code=400)
    data = await request.json()
    value = data.get("autofix_default")
    if not isinstance(value, bool):
        return JSONResponse({"error": "autofix_default must be a boolean."}, status_code=400)
    if not user_key:
        APP_SETTINGS["autofix_default"] = value
        if value:
            APP_SETTINGS["fix_mode_default"] = "safe"
        else:
            APP_SETTINGS["fix_mode_default"] = "none"
    persisted = settings_store.save_autofix_default(value, user_key=user_key)
    settings_store.save_fix_mode_default("safe" if value else "none", user_key=user_key)
    if not persisted:
        return JSONResponse({
            "result": "saved",
            "persistent": False,
            "warning": "SETTINGS_ENC_KEY not set; setting stored in memory only.",
        })
    return JSONResponse({"result": "saved", "persistent": True})


@app.post("/settings/fix-mode")
async def set_fix_mode(request: Request):
    auth_error = _require_settings_token(request)
    if auth_error:
        return JSONResponse({"error": auth_error}, status_code=401)
    user_key = _get_user_scope_key(request)
    if not _is_global_scope() and not user_key:
        return JSONResponse({"error": "User scope required. Set X-Guardrails-User header."}, status_code=400)
    data = await request.json()
    value = data.get("fix_mode_default")
    if not isinstance(value, str) or value not in {"full", "safe", "none"}:
        return JSONResponse({"error": "fix_mode_default must be one of full|safe|none."}, status_code=400)
    if not user_key:
        APP_SETTINGS["fix_mode_default"] = value
        APP_SETTINGS["autofix_default"] = value in {"safe", "full"}
    persisted = settings_store.save_fix_mode_default(value, user_key=user_key)
    settings_store.save_autofix_default(value in {"safe", "full"}, user_key=user_key)
    if not persisted:
        return JSONResponse({
            "result": "saved",
            "persistent": False,
            "warning": "SETTINGS_ENC_KEY not set; setting stored in memory only.",
        })
    return JSONResponse({"result": "saved", "persistent": True})


@app.post("/autofix/full")
async def full_fix_rewrite(payload: AutofixFullRequest, request: Request):
    auth_error = _require_api_token(request, "GUARDRAILS_API_TOKEN", "x-guardrails-token")
    if auth_error:
        return JSONResponse({"error": auth_error}, status_code=401)
    user_key = _get_user_scope_key(request)
    if not _is_global_scope() and not user_key:
        return JSONResponse({"error": "User scope required. Set X-Guardrails-User header."}, status_code=400)
    data = payload.model_dump()
    code = data.get("code")
    path = data.get("path", "unknown")
    findings = data.get("findings", [])
    if not isinstance(code, str) or not code.strip():
        return JSONResponse({"error": "code is required."}, status_code=400)
    if not isinstance(findings, list):
        return JSONResponse({"error": "findings must be a list."}, status_code=400)
    ai_key = _get_request_ai_key(request, data)
    if not ai_key:
        return JSONResponse({"error": "AI API key not configured for this user."}, status_code=400)
    model = data.get("ai_model") or _resolve_ai_model({}, request=request)
    context = {
        "path": path,
        "language": _guess_language(path),
        "repo": data.get("repo_path"),
    }
    try:
        updated = ai_review.ai_rewrite(
            code,
            findings,
            api_key_override=ai_key,
            context=context,
            model_override=model,
        )
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)
    return JSONResponse({"code": updated})

@app.post("/settings/ai-model")
async def set_ai_model(request: Request):
    auth_error = _require_settings_token(request)
    if auth_error:
        return JSONResponse({"error": auth_error}, status_code=401)
    user_key = _get_user_scope_key(request)
    if not _is_global_scope() and not user_key:
        return JSONResponse({"error": "User scope required. Set X-Guardrails-User header."}, status_code=400)
    data = await request.json()
    value = data.get("ai_model")
    if not isinstance(value, str) or not value.strip():
        return JSONResponse({"error": "ai_model must be a non-empty string."}, status_code=400)
    if not user_key:
        APP_SETTINGS["ai_model"] = value.strip()
    persisted = settings_store.save_ai_model(value.strip(), user_key=user_key)
    if not persisted:
        return JSONResponse({
            "result": "saved",
            "persistent": False,
            "warning": "SETTINGS_ENC_KEY not set; setting stored in memory only.",
        })
    return JSONResponse({"result": "saved", "persistent": True})

@app.post("/settings/ai-max-chars")
async def set_ai_max_chars(request: Request):
    auth_error = _require_settings_token(request)
    if auth_error:
        return JSONResponse({"error": auth_error}, status_code=401)
    user_key = _get_user_scope_key(request)
    if not _is_global_scope() and not user_key:
        return JSONResponse({"error": "User scope required. Set X-Guardrails-User header."}, status_code=400)
    data = await request.json()
    value = data.get("ai_review_max_chars")
    if not isinstance(value, int) or value <= 0:
        return JSONResponse({"error": "ai_review_max_chars must be a positive integer."}, status_code=400)
    if not user_key:
        APP_SETTINGS["ai_review_max_chars"] = value
    persisted = settings_store.save_ai_review_max_chars(value, user_key=user_key)
    if not persisted:
        return JSONResponse({
            "result": "saved",
            "persistent": False,
            "warning": "SETTINGS_ENC_KEY not set; setting stored in memory only.",
        })
    return JSONResponse({"result": "saved", "persistent": True})

@app.post("/settings/override-allowed")
async def set_override_allowed(request: Request):
    auth_error = _require_settings_token(request)
    if auth_error:
        return JSONResponse({"error": auth_error}, status_code=401)
    user_key = _get_user_scope_key(request)
    if not _is_global_scope() and not user_key:
        return JSONResponse({"error": "User scope required. Set X-Guardrails-User header."}, status_code=400)
    data = await request.json()
    value = data.get("override_allowed_default")
    if not isinstance(value, bool):
        return JSONResponse({"error": "override_allowed_default must be a boolean."}, status_code=400)
    persisted = settings_store.save_override_allowed_default(value, user_key=user_key)
    if not persisted:
        return JSONResponse({
            "result": "saved",
            "persistent": False,
            "warning": "SETTINGS_ENC_KEY not set; setting stored in memory only.",
        })
    return JSONResponse({"result": "saved", "persistent": True})

@app.post("/analyze")
async def analyze(payload: AnalyzeRequest, request: Request):
    auth_error = _require_api_token(request, "GUARDRAILS_API_TOKEN", "x-guardrails-token")
    if auth_error:
        return JSONResponse({"error": auth_error}, status_code=401)
    data = payload.model_dump()
    if not _is_global_scope() and not _get_user_scope_key(request):
        return JSONResponse({"error": "User scope required. Set X-Guardrails-User header."}, status_code=400)
    code = data.get("code", "")
    repo_path = data.get("repo_path", ".")
    residency_error = _enforce_data_residency(repo_path)
    if residency_error:
        return JSONResponse({"error": residency_error}, status_code=400)
    license_texts = data.get("repo_license_texts") if isinstance(data.get("repo_license_texts"), list) else None
    repo_license_issues = _collect_repo_license_issues(repo_path, license_texts=license_texts)
    sector = _resolve_sector(data, repo_path)
    policy_override = _resolve_policy_override(data, repo_path)
    ai_key = _get_request_ai_key(request, data)
    require_ai_review = _resolve_require_ai_review(data, request=request)
    ai_model = _resolve_ai_model(data, request=request)
    ai_review_max_chars = _resolve_ai_review_max_chars(data, request=request)
    user_key = _get_user_scope_key(request)
    ai_context = {
        "path": data.get("path"),
        "language": data.get("language") or _guess_language(data.get("path") or ""),
        "patch": data.get("patch"),
        "repo": data.get("repo"),
        "pr_number": data.get("pr_number"),
        "commit": data.get("commit"),
        "ai_generated": bool(data.get("ai_generated")),
    }
    analysis = _analyze_code(
        code,
        sector,
        repo_path,
        policy_override=policy_override,
        ai_key=ai_key,
        require_ai_review=require_ai_review,
        ai_generated=bool(data.get("ai_generated")),
        ai_context=ai_context,
        language=ai_context.get("language"),
        repo_license_issues=repo_license_issues,
        ai_model=ai_model,
        ai_review_max_chars=ai_review_max_chars,
        user_key=user_key,
    )
    _apply_guidelines(analysis)
    request_id = str(uuid.uuid4())
    result = {
        "result": "analyzed",
        "request_id": request_id,
        "repo_license_issues": repo_license_issues,
        **analysis,
    }
    # Write audit log
    audit_entry = {
        "request_id": request_id,
        "input": _sanitize_audit_input(data),
        "output": _sanitize_audit_output(result) if audit_log.AUDIT_LOG_STORE_OUTPUT else _summarize_output(result),
        "policy": analysis["policy"],
        "override_allowed": analysis["override_allowed"],
        "resolution": "unresolved",
    }
    audit_id = audit_log.write_audit_log(audit_entry)
    if audit_id:
        result["audit_id"] = audit_id
    return JSONResponse(result)

@app.post("/analyze-batch")
async def analyze_batch(payload: AnalyzeBatchRequest, request: Request):
    auth_error = _require_api_token(request, "GUARDRAILS_API_TOKEN", "x-guardrails-token")
    if auth_error:
        return JSONResponse({"error": auth_error}, status_code=401)
    data = payload.model_dump()
    if not _is_global_scope() and not _get_user_scope_key(request):
        return JSONResponse({"error": "User scope required. Set X-Guardrails-User header."}, status_code=400)
    files = data.get("files", [])
    repo_path = data.get("repo_path", ".")
    residency_error = _enforce_data_residency(repo_path)
    if residency_error:
        return JSONResponse({"error": residency_error}, status_code=400)
    license_texts = data.get("repo_license_texts") if isinstance(data.get("repo_license_texts"), list) else None
    repo_license_issues = _collect_repo_license_issues(repo_path, license_texts=license_texts)
    sector = _resolve_sector(data, repo_path)
    policy_override = _resolve_policy_override(data, repo_path)
    ai_key = _get_request_ai_key(request, data)
    require_ai_review = _resolve_require_ai_review(data, request=request)
    ai_model = _resolve_ai_model(data, request=request)
    ai_review_max_chars = _resolve_ai_review_max_chars(data, request=request)
    user_key = _get_user_scope_key(request)

    config = config_loader.load_config(repo_path)
    ip_min_lines = int(config.get("ip_min_lines", 6) or 6)
    ip_min_chars = int(config.get("ip_min_chars", 240) or 240)
    file_map = {item.get("path", "unknown"): item.get("code", "") for item in files}
    cross_file_issues = license_ip.detect_cross_file_duplicates(
        file_map,
        min_lines=ip_min_lines,
        min_chars=ip_min_chars,
    )

    findings = {}
    policy_mode = "advisory"
    override_allowed = False
    for item in files:
        path = item.get("path", "unknown")
        code = item.get("code", "")
        language = item.get("language") or _guess_language(path)
        ai_context = {
            "path": path,
            "language": language,
            "patch": item.get("patch"),
            "repo": data.get("repo"),
            "pr_number": data.get("pr_number"),
            "commit": data.get("commit"),
            "ai_generated": bool(data.get("ai_generated")),
        }
        analysis = _analyze_code(
            code,
            sector,
            repo_path,
            policy_override=policy_override,
            ai_key=ai_key,
            require_ai_review=require_ai_review,
            ai_generated=bool(data.get("ai_generated")),
            ai_context=ai_context,
            language=language,
            extra_license_ip_issues=cross_file_issues.get(path, []),
            repo_license_issues=repo_license_issues,
            ai_model=ai_model,
            ai_review_max_chars=ai_review_max_chars,
            user_key=user_key,
        )
        _apply_guidelines(analysis)
        findings[path] = {
            "result": "analyzed",
            **analysis,
        }
        if analysis["policy"] == "blocking":
            policy_mode = "blocking"
        elif analysis["policy"] == "warning" and policy_mode != "blocking":
            policy_mode = "warning"
        override_allowed = override_allowed or analysis["override_allowed"]

    request_id = str(uuid.uuid4())
    result = {
        "result": "analyzed",
        "request_id": request_id,
        "files_scanned": len(files),
        "findings": findings,
        "policy": policy_mode,
        "override_allowed": override_allowed,
        "repo_license_issues": repo_license_issues,
    }
    audit_entry = {
        "request_id": request_id,
        "input": _sanitize_audit_input(data),
        "output": _sanitize_audit_output(result) if audit_log.AUDIT_LOG_STORE_OUTPUT else _summarize_output(result),
        "policy": policy_mode,
        "override_allowed": override_allowed,
        "resolution": "unresolved",
    }
    audit_id = audit_log.write_audit_log(audit_entry)
    if audit_id:
        result["audit_id"] = audit_id
    return JSONResponse(result)

@app.get("/report/summary")
def report_summary(request: Request):
    auth_error = _require_api_token(request, "GUARDRAILS_ADMIN_TOKEN", "x-guardrails-admin")
    if auth_error:
        return JSONResponse({"error": auth_error}, status_code=401)
    entries = audit_log.export_audit_log()
    summary = {
        "total_requests": len(entries),
        "policy_counts": {"advisory": 0, "warning": 0, "blocking": 0},
        "issue_counts": {"issues": 0, "coding": 0, "license_ip": 0, "sector": 0, "ai": 0, "repo_license": 0},
    }
    for entry in entries:
        policy_mode = entry.get("policy", "advisory")
        if policy_mode in summary["policy_counts"]:
            summary["policy_counts"][policy_mode] += 1
        output = entry.get("output", {})
        summary["issue_counts"]["issues"] += len(output.get("issues", []))
        summary["issue_counts"]["coding"] += len(output.get("coding_issues", []))
        summary["issue_counts"]["license_ip"] += len(output.get("license_ip_issues", []))
        summary["issue_counts"]["sector"] += len(output.get("sector_issues", []))
        summary["issue_counts"]["ai"] += len(output.get("ai_suggestions", []))
        summary["issue_counts"]["repo_license"] += len(output.get("repo_license_issues", []))
    return JSONResponse(summary)

@app.get("/report/trends")
def report_trends(request: Request):
    auth_error = _require_api_token(request, "GUARDRAILS_ADMIN_TOKEN", "x-guardrails-admin")
    if auth_error:
        return JSONResponse({"error": auth_error}, status_code=401)
    entries = audit_log.export_audit_log()
    trends: Dict[str, Any] = {}
    for entry in entries:
        ts = entry.get("timestamp", "")
        day = ts[:10] if ts else "unknown"
        bucket = trends.setdefault(day, {"advisory": 0, "warning": 0, "blocking": 0})
        policy_mode = entry.get("policy", "advisory")
        if policy_mode in bucket:
            bucket[policy_mode] += 1
    return JSONResponse({"trends": trends})

@app.get("/rulepacks")
def list_rulepacks():
    rulepack_dir = os.path.join(os.path.dirname(__file__), "rulepacks")
    names = []
    for filename in os.listdir(rulepack_dir):
        if filename.endswith((".yml", ".yaml")):
            names.append(os.path.splitext(filename)[0])
    return JSONResponse({"rulepacks": sorted(names)})

@app.post("/rulepacks")
async def upload_rulepack(payload: RulepackUploadRequest, request: Request):
    auth_error = _require_api_token(request, "GUARDRAILS_ADMIN_TOKEN", "x-guardrails-admin")
    if auth_error:
        return JSONResponse({"error": auth_error}, status_code=401)
    data = payload.model_dump()
    name = data.get("name", "")
    rules = data.get("rules", [])
    if not re.match(r"^[a-zA-Z0-9_-]+$", name):
        return JSONResponse({"error": "Invalid rulepack name."}, status_code=400)
    if not isinstance(rules, list):
        return JSONResponse({"error": "Rules must be a list."}, status_code=400)
    rulepack_dir = os.path.join(os.path.dirname(__file__), "rulepacks")
    os.makedirs(rulepack_dir, exist_ok=True)
    path = os.path.join(rulepack_dir, f"{name}.yml")
    import yaml
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump({"rules": rules}, f)
    return JSONResponse({"result": "saved", "name": name})

@app.get("/audit/export")
def export_audit(request: Request):
    auth_error = _require_api_token(request, "GUARDRAILS_ADMIN_TOKEN", "x-guardrails-admin")
    if auth_error:
        return JSONResponse({"error": auth_error}, status_code=401)
    return JSONResponse({"entries": audit_log.export_audit_log()})

@app.post("/audit/resolve")
async def resolve_audit(payload: AuditResolveRequest, request: Request):
    auth_error = _require_api_token(request, "GUARDRAILS_ADMIN_TOKEN", "x-guardrails-admin")
    if auth_error:
        return JSONResponse({"error": auth_error}, status_code=401)
    data = payload.model_dump()
    audit_id = data.get("audit_id")
    resolution = data.get("resolution")
    actor = data.get("actor")
    if not audit_id or not resolution:
        return JSONResponse({"error": "audit_id and resolution are required."}, status_code=400)
    audit_log.write_resolution(audit_id, resolution, actor=actor)
    return JSONResponse({"result": "recorded", "audit_id": audit_id, "resolution": resolution})

def _run_async_scan(job_id: str, payload: dict) -> None:
    JOB_STORE[job_id]["status"] = "running"
    files = payload.get("files", [])
    repo_path = payload.get("repo_path", ".")
    sector = _resolve_sector(payload, repo_path)
    policy_override = _resolve_policy_override(payload, repo_path)
    ai_key = payload.get("ai_api_key") or APP_SETTINGS.get("openai_api_key") or os.environ.get("OPENAI_API_KEY")
    require_ai_review = _resolve_require_ai_review(payload, request=None)
    ai_model = _resolve_ai_model(payload, request=None)
    ai_review_max_chars = _resolve_ai_review_max_chars(payload, request=None)
    license_texts = payload.get("repo_license_texts") if isinstance(payload.get("repo_license_texts"), list) else None
    repo_license_issues = _collect_repo_license_issues(repo_path, license_texts=license_texts)
    user_key = payload.get("user_key")
    findings = {}
    policy_mode = "advisory"
    override_allowed = False
    for item in files:
        path = item.get("path", "unknown")
        code = item.get("code", "")
        ai_context = {
            "path": path,
            "language": item.get("language"),
            "patch": item.get("patch"),
            "repo": payload.get("repo"),
            "pr_number": payload.get("pr_number"),
            "commit": payload.get("commit"),
            "ai_generated": bool(payload.get("ai_generated")),
        }
        analysis = _analyze_code(
            code,
            sector,
            repo_path,
            policy_override=policy_override,
            ai_key=ai_key,
            require_ai_review=require_ai_review,
            ai_generated=bool(payload.get("ai_generated")),
            ai_context=ai_context,
            repo_license_issues=repo_license_issues,
            ai_model=ai_model,
            ai_review_max_chars=ai_review_max_chars,
            user_key=user_key,
        )
        _apply_guidelines(analysis)
        findings[path] = {"result": "analyzed", **analysis}
        if analysis["policy"] == "blocking":
            policy_mode = "blocking"
        elif analysis["policy"] == "warning" and policy_mode != "blocking":
            policy_mode = "warning"
        override_allowed = override_allowed or analysis["override_allowed"]
    result = {
        "result": "analyzed",
        "files_scanned": len(files),
        "findings": findings,
        "policy": policy_mode,
        "override_allowed": override_allowed,
    }
    JOB_STORE[job_id]["status"] = "completed"
    JOB_STORE[job_id]["result"] = result

@app.post("/scan/async")
async def scan_async(payload: AsyncScanRequest, request: Request, background_tasks: BackgroundTasks):
    auth_error = _require_api_token(request, "GUARDRAILS_API_TOKEN", "x-guardrails-token")
    if auth_error:
        return JSONResponse({"error": auth_error}, status_code=401)
    data = payload.model_dump()
    repo_path = data.get("repo_path", ".")
    residency_error = _enforce_data_residency(repo_path)
    if residency_error:
        return JSONResponse({"error": residency_error}, status_code=400)
    job_id = str(uuid.uuid4())
    JOB_STORE[job_id] = {"status": "queued"}
    background_tasks.add_task(_run_async_scan, job_id, data)
    return JSONResponse({"job_id": job_id, "status": "queued"})

@app.get("/scan/status/{job_id}")
def scan_status(job_id: str):
    if job_id not in JOB_STORE:
        return JSONResponse({"error": "Job not found."}, status_code=404)
    return JSONResponse(JOB_STORE[job_id])
