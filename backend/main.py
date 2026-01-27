from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import security_rules
import ai_review
import coding_standards
import license_ip
import policy
import audit_log
import config_loader
import rule_engine

app = FastAPI(title="Guardrails Backend API")

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/analyze")
async def analyze(request: Request):
    data = await request.json()
    code = data.get("code", "")
    sector = data.get("sector", "finance")  # default to finance for demo
    repo_path = data.get("repo_path", ".")
    issues = security_rules.run_security_rules(code)
    coding_issues = coding_standards.run_coding_standards_rules(code)
    license_ip_issues = license_ip.run_license_ip_checks(code)
    ai_suggestions = ai_review.ai_review_stub(code)
    # Apply sector rule pack
    rules = rule_engine.load_rulepack(sector)
    sector_issues = rule_engine.apply_rulepack_rules(code, rules)
    policy_mode = policy.evaluate_policy(issues, coding_issues, license_ip_issues + sector_issues, repo_path=repo_path)
    override_allowed = policy.is_override_allowed() if policy_mode == "blocking" else False
    result = {
        "result": "analyzed",
        "issues": issues,
        "coding_issues": coding_issues,
        "license_ip_issues": license_ip_issues,
        "sector_issues": sector_issues,
        "ai_suggestions": ai_suggestions,
        "policy": policy_mode,
        "override_allowed": override_allowed
    }
    # Write audit log
    audit_log.write_audit_log({
        "input": data,
        "output": result,
        "policy": policy_mode,
        "override_allowed": override_allowed
    })
    return JSONResponse(result)
