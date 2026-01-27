from typing import List, Dict, Any
import re

SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "aws_access_key_id"),
    (r"(?i)aws_secret_access_key\s*[:=]\s*['\"][0-9a-zA-Z/+=]{40}['\"]", "aws_secret_key"),
    (r"ghp_[A-Za-z0-9]{36}", "github_token"),
    (r"xox[baprs]-[0-9a-zA-Z-]{10,48}", "slack_token"),
    (r"AIza[0-9A-Za-z_-]{35}", "google_api_key"),
    (r"sk-[0-9A-Za-z]{20,}", "openai_api_key"),
    (r"(?i)api[_-]?key\s*[:=]\s*['\"][^'\"]{8,}['\"]", "generic_api_key"),
    (r"(?i)password\s*[:=]\s*['\"][^'\"]{8,}['\"]", "hardcoded_password"),
]

def detect_hardcoded_secrets(code: str) -> List[Dict[str, Any]]:
    issues = []
    for pat, label in SECRET_PATTERNS:
        for m in re.finditer(pat, code):
            issues.append({
                "type": "hardcoded_secret",
                "category": "security",
                "label": label,
                "pattern": pat,
                "match": m.group(0),
                "start": m.start(),
                "end": m.end(),
                "message": "Potential hardcoded secret detected.",
                "suggestion": "Move secrets to environment variables or a secret manager.",
                "cwe": "CWE-798",
                "owasp": "A02:2021",
                "severity": "blocking",
            })
    return issues

def detect_sql_injection(code: str) -> List[Dict[str, Any]]:
    patterns = [
        r"execute\s*\(.*\+.*\)",
        r"SELECT\s+.*\s+FROM\s+.*\+",
        r"INSERT\s+INTO\s+.*\+",
        r"UPDATE\s+.*\+\s+SET",
        r"DELETE\s+FROM\s+.*\+",
    ]
    issues = []
    for pat in patterns:
        for m in re.finditer(pat, code, re.IGNORECASE):
            issues.append({
                "type": "sql_injection_risk",
                "pattern": pat,
                "match": m.group(0),
                "start": m.start(),
                "end": m.end(),
                "message": "Possible SQL injection via string concatenation.",
                "suggestion": "Use parameterized queries or ORM bindings.",
                "cwe": "CWE-89",
                "owasp": "A03:2021",
                "severity": "blocking",
            })
    return issues

def detect_insecure_deserialization(code: str) -> List[Dict[str, Any]]:
    patterns = [
        r"pickle\.loads\(",
        r"eval\(",
        r"yaml\.load\(",
        r"marshal\.loads\(",
    ]
    issues = []
    for pat in patterns:
        for m in re.finditer(pat, code):
            issues.append({
                "type": "insecure_deserialization",
                "pattern": pat,
                "match": m.group(0),
                "start": m.start(),
                "end": m.end(),
                "message": "Potentially unsafe deserialization call.",
                "suggestion": "Use safe loaders or avoid deserializing untrusted data.",
                "cwe": "CWE-502",
                "owasp": "A08:2021",
                "severity": "warning",
            })
    return issues

def detect_unsafe_exec(code: str) -> List[Dict[str, Any]]:
    patterns = [
        r"os\.system\(",
        r"subprocess\.Popen\(",
        r"subprocess\.run\(",
        r"exec\(",
        r"os\.popen\(",
    ]
    issues = []
    for pat in patterns:
        for m in re.finditer(pat, code):
            issues.append({
                "type": "unsafe_execution",
                "pattern": pat,
                "match": m.group(0),
                "start": m.start(),
                "end": m.end(),
                "message": "Potential unsafe command execution.",
                "suggestion": "Avoid shell execution or strictly validate inputs.",
                "cwe": "CWE-78",
                "owasp": "A01:2021",
                "severity": "warning",
            })
    return issues

def detect_path_traversal(code: str) -> List[Dict[str, Any]]:
    patterns = [
        r"open\(.*\+.*\)",
        r"readFile\(.*\+.*\)",
        r"path\.join\(.*request.*\)",
    ]
    issues = []
    for pat in patterns:
        for m in re.finditer(pat, code, re.IGNORECASE):
            issues.append({
                "type": "path_traversal_risk",
                "pattern": pat,
                "match": m.group(0),
                "start": m.start(),
                "end": m.end(),
                "message": "Possible path traversal via user input.",
                "suggestion": "Normalize paths and restrict to a safe base directory.",
                "cwe": "CWE-22",
                "owasp": "A01:2021",
                "severity": "warning",
            })
    return issues

def detect_unsafe_file_operations(code: str) -> List[Dict[str, Any]]:
    patterns = [
        r"open\(.*(request|input|argv|sys\.argv|params|query|payload).*\)",
        r"os\.remove\(.*(request|input|argv|sys\.argv|params|query|payload).*\)",
        r"os\.unlink\(.*(request|input|argv|sys\.argv|params|query|payload).*\)",
        r"shutil\.rmtree\(.*(request|input|argv|sys\.argv|params|query|payload).*\)",
        r"Path\(.*(request|input|argv|sys\.argv|params|query|payload).*\)\.unlink\(\)",
        r"Path\(.*(request|input|argv|sys\.argv|params|query|payload).*\)\.write_text\(",
    ]
    issues = []
    for pat in patterns:
        for m in re.finditer(pat, code, re.IGNORECASE):
            issues.append({
                "type": "unsafe_file_operation",
                "pattern": pat,
                "match": m.group(0),
                "start": m.start(),
                "end": m.end(),
                "message": "Potential unsafe file operation using untrusted input.",
                "suggestion": "Validate and normalize file paths and restrict to an allowlist base directory.",
                "cwe": "CWE-73",
                "owasp": "A01:2021",
                "severity": "warning",
            })
    return issues

def detect_insecure_crypto(code: str) -> List[Dict[str, Any]]:
    patterns = [
        r"md5\(",
        r"sha1\(",
        r"DES\.new\(",
        r"RC4\(",
    ]
    issues = []
    for pat in patterns:
        for m in re.finditer(pat, code, re.IGNORECASE):
            issues.append({
                "type": "insecure_crypto",
                "pattern": pat,
                "match": m.group(0),
                "start": m.start(),
                "end": m.end(),
                "message": "Weak or deprecated cryptographic primitive detected.",
                "suggestion": "Use modern algorithms like SHA-256 or AES-GCM.",
                "cwe": "CWE-327",
                "owasp": "A02:2021",
                "severity": "warning",
            })
    return issues

def detect_copilot_generated_code_segments(code: str) -> List[Dict[str, Any]]:
    copilot_patterns = [
        r"(?i)generated by copilot",
        r"(?i)copilot suggestion",
        r"(?i)copyright github copilot",
        r"(?i)AI-generated code",
        r"(?i)Created with Copilot",
    ]
    segments = []
    for pat in copilot_patterns:
        for m in re.finditer(pat, code):
            segments.append({
                "start": m.start(),
                "end": m.end(),
                "pattern": pat,
                "match": m.group(0)
            })
    return segments

def run_security_rules(code: str, ai_generated: bool = False) -> List[Dict[str, Any]]:
    issues = []
    copilot_segments = detect_copilot_generated_code_segments(code)
    is_copilot = bool(copilot_segments) or ai_generated
    issues.extend(detect_hardcoded_secrets(code))
    issues.extend(detect_sql_injection(code))
    issues.extend(detect_insecure_deserialization(code))
    issues.extend(detect_unsafe_exec(code))
    issues.extend(detect_path_traversal(code))
    issues.extend(detect_unsafe_file_operations(code))
    issues.extend(detect_insecure_crypto(code))
    issues.extend([
        {
            "type": "copilot_generated_code",
            "pattern": seg["pattern"],
            "match": seg["match"],
            "start": seg["start"],
            "end": seg["end"],
            "message": "Likely Copilot-generated code segment.",
            "note": "Likely Copilot-generated code segment",
            "severity": "warning",
        } for seg in copilot_segments
    ])
    if is_copilot:
        for issue in issues:
            issue["copilot_strict"] = True
            issue["copilot_generated"] = True
        for issue in issues:
            if issue.get("type") in {"copilot_generated_code", "copilot_insecure_suggestion"}:
                continue
            if issue.get("severity") in {"warning", "blocking"}:
                issues.append({
                    "type": "copilot_insecure_suggestion",
                    "message": "Copilot-generated code triggered a security guardrail.",
                    "related_issue": issue.get("type"),
                    "start": issue.get("start"),
                    "end": issue.get("end"),
                    "severity": "warning",
                    "copilot_generated": True,
                })
    return issues
