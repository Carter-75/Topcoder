
from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import JSONResponse
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

# Import dashboard endpoint
import dashboard

app = FastAPI(title="Guardrails Backend API")
JOB_STORE: Dict[str, Dict[str, Any]] = {}

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
    if "files" in sanitized:
        sanitized["files"] = [{"path": f.get("path"), "size": len(f.get("code", ""))} for f in sanitized["files"]]
    return sanitized

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

def _analyze_code(code: str, sector: str, repo_path: str, policy_override: dict | None = None) -> dict:
    issues = security_rules.run_security_rules(code)
    coding_issues = coding_standards.run_coding_standards_rules(code)
    license_ip_issues = license_ip.run_license_ip_checks(code)
    ai_suggestions = ai_review.ai_review(code)
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
    analysis = _analyze_code(code, sector, repo_path, policy_override=policy_override)
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

    findings = {}
    policy_mode = "advisory"
    override_allowed = False
    for item in files:
        path = item.get("path", "unknown")
        code = item.get("code", "")
        analysis = _analyze_code(code, sector, repo_path, policy_override=policy_override)
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
    findings = {}
    policy_mode = "advisory"
    override_allowed = False
    for item in files:
        path = item.get("path", "unknown")
        code = item.get("code", "")
        analysis = _analyze_code(code, sector, repo_path, policy_override=policy_override)
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
