import re
from typing import List, Dict, Any

def detect_license_headers(code: str) -> List[Dict[str, Any]]:
    # Heuristic: Look for common open source license headers
    licenses = [
        (r"MIT License", "MIT"),
        (r"Apache License, Version 2.0", "Apache-2.0"),
        (r"GNU GENERAL PUBLIC LICENSE", "GPL"),
        (r"Mozilla Public License", "MPL"),
        (r"BSD License", "BSD"),
    ]
    issues = []
    for pat, name in licenses:
        if re.search(pat, code, re.IGNORECASE):
            issues.append({
                "type": "license_detected",
                "license": name,
                "message": f"Detected {name} license header in code.",
            })
    return issues

def detect_ip_duplication(code: str) -> List[Dict[str, Any]]:
    # Heuristic: Look for long repeated lines (possible copy-paste)
    lines = code.splitlines()
    seen = {}
    issues = []
    for i, line in enumerate(lines):
        key = line.strip()
        if key:
            if key in seen:
                issues.append({
                    "type": "ip_duplication",
                    "message": "Possible duplicate or copied code detected.",
                    "line": i + 1,
                    "original_line": seen[key] + 1,
                    "snippet": key[:60] + ("..." if len(key) > 60 else "")
                })
            else:
                seen[key] = i
    return issues

def run_license_ip_checks(code: str) -> List[Dict[str, Any]]:
    issues = []
    issues.extend(detect_license_headers(code))
    issues.extend(detect_ip_duplication(code))
    return issues
