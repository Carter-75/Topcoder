
from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import JSONResponse, HTMLResponse, Response
import sys
import os
import re
import uuid
from typing import Dict, Any
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
from cryptography.fernet import Fernet

# Import dashboard endpoint
import dashboard

app = FastAPI(title="Guardrails Backend API")
JOB_STORE: Dict[str, Dict[str, Any]] = {}
APP_SETTINGS: Dict[str, Any] = {
    "openai_api_key": settings_store.load_api_key(),
    "require_ai_review_default": settings_store.load_require_ai_review_default(),
    "autofix_default": settings_store.load_autofix_default(),
}

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
    if "files" in sanitized:
        sanitized["files"] = [{"path": f.get("path"), "size": len(f.get("code", ""))} for f in sanitized["files"]]
    return sanitized

def _get_request_ai_key(request: Request, data: dict) -> str | None:
    header_key = request.headers.get("x-openai-api-key") or request.headers.get("x-openai-key")
    return header_key or data.get("ai_api_key") or APP_SETTINGS.get("openai_api_key") or os.environ.get("OPENAI_API_KEY")

def _require_settings_token(request: Request) -> str | None:
    token = os.environ.get("SETTINGS_TOKEN")
    if not token:
        return None
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer ") and auth.split(" ", 1)[1] == token:
        return None
    return "Missing or invalid settings token."

def _resolve_require_ai_review(data: dict) -> bool:
    if "require_ai_review" in data and isinstance(data.get("require_ai_review"), bool):
        return data["require_ai_review"]
    if isinstance(APP_SETTINGS.get("require_ai_review_default"), bool):
        return APP_SETTINGS["require_ai_review_default"]
    return os.environ.get("REQUIRE_AI_REVIEW", "true").lower() == "true"

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
        },
    }

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

def _analyze_code(
    code: str,
    sector: str,
    repo_path: str,
    policy_override: dict | None = None,
    ai_key: str | None = None,
    require_ai_review: bool | None = None,
) -> dict:
    issues = security_rules.run_security_rules(code)
    coding_issues = coding_standards.run_coding_standards_rules(code)
    license_ip_issues = license_ip.run_license_ip_checks(code)
    ai_suggestions = ai_review.ai_review(code, api_key_override=ai_key, require_ai_override=require_ai_review)
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
        license_ip_issues + sector_issues,
        repo_path=repo_path,
        policy_override=policy_override,
    )
    override_allowed = policy.is_override_allowed() if policy_mode == "blocking" else False
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

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/")
def root():
    return dashboard.dashboard()

@app.get("/favicon.ico")
def favicon():
    return Response(status_code=204)

@app.get("/settings")
def get_settings():
    require_ai = _resolve_require_ai_review({})
    return {
        "openai_api_key_set": bool(APP_SETTINGS.get("openai_api_key") or os.environ.get("OPENAI_API_KEY")),
        "require_ai_review": require_ai,
        "require_ai_review_default": APP_SETTINGS.get("require_ai_review_default"),
        "autofix_default": APP_SETTINGS.get("autofix_default"),
        "persistent_enabled": bool(os.environ.get("SETTINGS_ENC_KEY")),
    }

@app.get("/settings/ui")
def settings_ui():
    html = """
    <html>
    <head>
        <title>Guardrails Settings</title>
        <meta name='viewport' content='width=device-width, initial-scale=1'>
        <style>
            body { font-family: 'Segoe UI', Arial, sans-serif; background: #f7f9fa; margin: 0; }
            .container { max-width: 720px; margin: 3rem auto; background: #fff; border-radius: 12px; box-shadow: 0 2px 8px #0001; padding: 2rem; }
            h1 { color: #1a237e; margin-top: 0; }
            label { display: block; font-weight: 600; margin-top: 1rem; }
            input { width: 100%; padding: 0.65rem; border: 1px solid #d0d7de; border-radius: 8px; font-size: 1rem; }
            button { margin-top: 1.2rem; background: #3949ab; color: #fff; border: 0; padding: 0.8rem 1.2rem; border-radius: 8px; font-size: 1rem; cursor: pointer; }
            button:disabled { background: #9fa8da; cursor: not-allowed; }
            .status { margin-top: 1rem; font-size: 0.95rem; }
            .success { color: #2e7d32; }
            .error { color: #c62828; }
            .muted { color: #6b7280; }
            .card { margin-top: 1.5rem; padding: 1rem; background: #f5f7ff; border-radius: 8px; }
        </style>
    </head>
    <body>
        <div class='container'>
            <h1>Guardrails Settings</h1>
            <p class='muted'>Store your OpenAI API key for all Guardrails scans. If <b>SETTINGS_TOKEN</b> is configured on the server, include it below. Use the AI mode buttons to require AI or allow non-AI by default.</p>

            <div class='card'>
                <div id='current-status' class='status muted'>Checking current status...</div>
            </div>

            <div class='card'>
                <div style='font-weight:600;margin-bottom:0.4rem;'>AI mode</div>
                <div id='ai-mode-status' class='status muted'>Loading AI mode...</div>
                <div style='margin-top:0.8rem; display:flex; gap:0.6rem; flex-wrap:wrap;'>
                    <button id='aiOnBtn' type='button'>Require AI</button>
                    <button id='aiOffBtn' type='button' style='background:#546e7a;'>Allow non-AI</button>
                </div>
            </div>

            <div class='card'>
                <div style='font-weight:600;margin-bottom:0.4rem;'>Auto-fix default</div>
                <div id='autofix-status' class='status muted'>Loading auto-fix...</div>
                <div style='margin-top:0.8rem; display:flex; gap:0.6rem; flex-wrap:wrap;'>
                    <button id='autofixOnBtn' type='button'>Enable auto-fix</button>
                    <button id='autofixOffBtn' type='button' style='background:#546e7a;'>Disable auto-fix</button>
                </div>
            </div>

            <label for='apiKey'>OpenAI API Key</label>
            <input id='apiKey' type='password' placeholder='sk-...' />

            <label for='settingsToken'>Settings Token (optional)</label>
            <input id='settingsToken' type='password' placeholder='Bearer token if required' />

            <div style='margin-top:1.2rem; display:flex; gap:0.6rem; flex-wrap:wrap;'>
                <button id='saveBtn'>Save Key</button>
                <button id='genKeyBtn' type='button' style='background:#546e7a;'>Generate Settings Key</button>
            </div>
            <div id='result' class='status'></div>
            <div id='genResult' class='status'></div>
        </div>

        <script>
            const statusEl = document.getElementById('current-status');
            const aiModeEl = document.getElementById('ai-mode-status');
            const autofixEl = document.getElementById('autofix-status');
            const resultEl = document.getElementById('result');
            const saveBtn = document.getElementById('saveBtn');
            const genResultEl = document.getElementById('genResult');
            const genKeyBtn = document.getElementById('genKeyBtn');
            const aiOnBtn = document.getElementById('aiOnBtn');
            const aiOffBtn = document.getElementById('aiOffBtn');
            const autofixOnBtn = document.getElementById('autofixOnBtn');
            const autofixOffBtn = document.getElementById('autofixOffBtn');

            async function refreshStatus() {
                try {
                    const res = await fetch('/settings');
                    const data = await res.json();
                    statusEl.textContent = data.openai_api_key_set
                        ? 'API key is configured.'
                        : 'API key is not configured.';
                    aiModeEl.textContent = data.require_ai_review
                        ? 'AI review is required by default.'
                        : 'Non-AI mode is allowed by default.';
                    if (typeof data.autofix_default === 'boolean') {
                        autofixEl.textContent = data.autofix_default
                            ? 'Auto-fix is enabled by default.'
                            : 'Auto-fix is disabled by default.';
                    } else {
                        autofixEl.textContent = 'Auto-fix default is not set.';
                    }
                } catch (err) {
                    statusEl.textContent = 'Unable to load status.';
                    aiModeEl.textContent = 'Unable to load AI mode.';
                    autofixEl.textContent = 'Unable to load auto-fix.';
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

            genKeyBtn.addEventListener('click', async () => {
                genResultEl.textContent = '';
                genResultEl.className = 'status';
                const token = document.getElementById('settingsToken').value.trim();
                genKeyBtn.disabled = true;
                try {
                    const res = await fetch('/settings/generate-key', {
                        method: 'POST',
                        headers: {
                            ...(token ? { 'Authorization': `Bearer ${token}` } : {})
                        }
                    });
                    const data = await res.json();
                    if (!res.ok) {
                        throw new Error(data.error || 'Failed to generate key.');
                    }
                    genResultEl.textContent = `Generated key: ${data.key}`;
                    genResultEl.classList.add('success');
                } catch (err) {
                    genResultEl.textContent = err.message || 'Failed to generate key.';
                    genResultEl.classList.add('error');
                } finally {
                    genKeyBtn.disabled = false;
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
                    await refreshStatus();
                } catch (err) {
                    resultEl.textContent = err.message || 'Failed to update AI mode.';
                    resultEl.classList.add('error');
                }
            }

            aiOnBtn.addEventListener('click', () => setAiMode(true));
            aiOffBtn.addEventListener('click', () => setAiMode(false));

            async function setAutofixMode(value) {
                resultEl.textContent = '';
                resultEl.className = 'status';
                const token = document.getElementById('settingsToken').value.trim();
                try {
                    const res = await fetch('/settings/autofix-mode', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            ...(token ? { 'Authorization': `Bearer ${token}` } : {})
                        },
                        body: JSON.stringify({ autofix_default: value })
                    });
                    const data = await res.json();
                    if (!res.ok) {
                        throw new Error(data.error || 'Failed to update auto-fix.');
                    }
                    resultEl.textContent = 'Auto-fix updated.';
                    resultEl.classList.add('success');
                    await refreshStatus();
                } catch (err) {
                    resultEl.textContent = err.message || 'Failed to update auto-fix.';
                    resultEl.classList.add('error');
                }
            }

            autofixOnBtn.addEventListener('click', () => setAutofixMode(true));
            autofixOffBtn.addEventListener('click', () => setAutofixMode(false));

            refreshStatus();
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html)

@app.post("/settings/generate-key")
async def generate_settings_key(request: Request):
    auth_error = _require_settings_token(request)
    if auth_error:
        return JSONResponse({"error": auth_error}, status_code=401)
    key = Fernet.generate_key().decode("utf-8")
    return JSONResponse({"key": key})

@app.post("/settings/api-key")
async def set_api_key(request: Request):
    auth_error = _require_settings_token(request)
    if auth_error:
        return JSONResponse({"error": auth_error}, status_code=401)
    data = await request.json()
    key = data.get("api_key")
    if not key:
        return JSONResponse({"error": "api_key is required."}, status_code=400)
    APP_SETTINGS["openai_api_key"] = key
    persisted = settings_store.save_api_key(key)
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
    data = await request.json()
    value = data.get("require_ai_review")
    if not isinstance(value, bool):
        return JSONResponse({"error": "require_ai_review must be a boolean."}, status_code=400)
    APP_SETTINGS["require_ai_review_default"] = value
    persisted = settings_store.save_require_ai_review_default(value)
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
    data = await request.json()
    value = data.get("autofix_default")
    if not isinstance(value, bool):
        return JSONResponse({"error": "autofix_default must be a boolean."}, status_code=400)
    APP_SETTINGS["autofix_default"] = value
    persisted = settings_store.save_autofix_default(value)
    if not persisted:
        return JSONResponse({
            "result": "saved",
            "persistent": False,
            "warning": "SETTINGS_ENC_KEY not set; setting stored in memory only.",
        })
    return JSONResponse({"result": "saved", "persistent": True})

@app.post("/analyze")
async def analyze(request: Request):
    data = await request.json()
    code = data.get("code", "")
    repo_path = data.get("repo_path", ".")
    residency_error = _enforce_data_residency(repo_path)
    if residency_error:
        return JSONResponse({"error": residency_error}, status_code=400)
    sector = _resolve_sector(data, repo_path)
    policy_override = _resolve_policy_override(data, repo_path)
    ai_key = _get_request_ai_key(request, data)
    require_ai_review = _resolve_require_ai_review(data)
    analysis = _analyze_code(
        code,
        sector,
        repo_path,
        policy_override=policy_override,
        ai_key=ai_key,
        require_ai_review=require_ai_review,
    )
    _apply_guidelines(analysis)
    result = {
        "result": "analyzed",
        **analysis,
    }
    # Write audit log
    audit_entry = {
        "input": _sanitize_audit_input(data),
        "output": result if audit_log.AUDIT_LOG_STORE_OUTPUT else _summarize_output(result),
        "policy": analysis["policy"],
        "override_allowed": analysis["override_allowed"],
    }
    audit_log.write_audit_log(audit_entry)
    return JSONResponse(result)

@app.post("/analyze-batch")
async def analyze_batch(request: Request):
    data = await request.json()
    files = data.get("files", [])
    repo_path = data.get("repo_path", ".")
    residency_error = _enforce_data_residency(repo_path)
    if residency_error:
        return JSONResponse({"error": residency_error}, status_code=400)
    sector = _resolve_sector(data, repo_path)
    policy_override = _resolve_policy_override(data, repo_path)
    ai_key = _get_request_ai_key(request, data)
    require_ai_review = _resolve_require_ai_review(data)

    findings = {}
    policy_mode = "advisory"
    override_allowed = False
    for item in files:
        path = item.get("path", "unknown")
        code = item.get("code", "")
        analysis = _analyze_code(
            code,
            sector,
            repo_path,
            policy_override=policy_override,
            ai_key=ai_key,
            require_ai_review=require_ai_review,
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

    result = {
        "result": "analyzed",
        "files_scanned": len(files),
        "findings": findings,
        "policy": policy_mode,
        "override_allowed": override_allowed,
    }
    audit_entry = {
        "input": _sanitize_audit_input(data),
        "output": result if audit_log.AUDIT_LOG_STORE_OUTPUT else _summarize_output(result),
        "policy": policy_mode,
        "override_allowed": override_allowed,
    }
    audit_log.write_audit_log(audit_entry)
    return JSONResponse(result)

@app.get("/report/summary")
def report_summary():
    entries = audit_log.export_audit_log()
    summary = {
        "total_requests": len(entries),
        "policy_counts": {"advisory": 0, "warning": 0, "blocking": 0},
        "issue_counts": {"issues": 0, "coding": 0, "license_ip": 0, "sector": 0, "ai": 0},
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
    return JSONResponse(summary)

@app.get("/rulepacks")
def list_rulepacks():
    rulepack_dir = os.path.join(os.path.dirname(__file__), "rulepacks")
    names = []
    for filename in os.listdir(rulepack_dir):
        if filename.endswith((".yml", ".yaml")):
            names.append(os.path.splitext(filename)[0])
    return JSONResponse({"rulepacks": sorted(names)})

@app.post("/rulepacks")
async def upload_rulepack(request: Request):
    data = await request.json()
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
def export_audit():
    return JSONResponse({"entries": audit_log.export_audit_log()})

def _run_async_scan(job_id: str, payload: dict) -> None:
    JOB_STORE[job_id]["status"] = "running"
    files = payload.get("files", [])
    repo_path = payload.get("repo_path", ".")
    sector = _resolve_sector(payload, repo_path)
    policy_override = _resolve_policy_override(payload, repo_path)
    ai_key = payload.get("ai_api_key") or APP_SETTINGS.get("openai_api_key") or os.environ.get("OPENAI_API_KEY")
    require_ai_review = _resolve_require_ai_review(payload)
    findings = {}
    policy_mode = "advisory"
    override_allowed = False
    for item in files:
        path = item.get("path", "unknown")
        code = item.get("code", "")
        analysis = _analyze_code(
            code,
            sector,
            repo_path,
            policy_override=policy_override,
            ai_key=ai_key,
            require_ai_review=require_ai_review,
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
async def scan_async(request: Request, background_tasks: BackgroundTasks):
    data = await request.json()
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
