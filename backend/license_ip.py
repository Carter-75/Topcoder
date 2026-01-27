import re
from typing import List, Dict, Any

import config_loader

def detect_license_headers(code: str) -> List[Dict[str, Any]]:
    # Heuristic: Look for common open source license headers
    licenses = [
        (r"MIT License", "MIT"),
        (r"Apache License, Version 2.0", "Apache-2.0"),
        (r"GNU GENERAL PUBLIC LICENSE", "GPL"),
        (r"GNU AFFERO GENERAL PUBLIC LICENSE", "AGPL"),
        (r"Server Side Public License", "SSPL"),
        (r"Business Source License", "BUSL"),
        (r"Elastic License", "Elastic-2.0"),
        (r"Commons Clause", "Commons-Clause"),
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
                "severity": "warning",
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
                    "snippet": key[:60] + ("..." if len(key) > 60 else ""),
                    "severity": "warning",
                })
            else:
                seen[key] = i
    return issues

def detect_near_duplicate_blocks(code: str, min_lines: int = 6, min_chars: int = 240) -> List[Dict[str, Any]]:
    lines = [line.rstrip() for line in code.splitlines()]
    blocks: Dict[str, int] = {}
    issues: List[Dict[str, Any]] = []
    for i in range(0, max(0, len(lines) - min_lines + 1)):
        window = "\n".join(lines[i:i + min_lines]).strip()
        if len(window) < min_chars:
            continue
        fingerprint = hash(window)
        if fingerprint in blocks:
            issues.append({
                "type": "ip_near_duplicate",
                "message": "Possible near-duplicate code block detected.",
                "line": i + 1,
                "original_line": blocks[fingerprint] + 1,
                "snippet": window[:80] + ("..." if len(window) > 80 else ""),
                "severity": "warning",
            })
        else:
            blocks[fingerprint] = i
    return issues

def detect_restricted_licenses(code: str, restricted: list[str]) -> List[Dict[str, Any]]:
    issues = []
    for license_name in restricted:
        if re.search(re.escape(license_name), code, re.IGNORECASE):
            issues.append({
                "type": "restricted_license",
                "license": license_name,
                "message": f"Restricted license detected: {license_name}.",
                "severity": "blocking",
            })
    return issues

def run_license_ip_checks(code: str, repo_path: str = ".") -> List[Dict[str, Any]]:
    issues = []
    config = config_loader.load_config(repo_path)
    restricted = config.get("restricted_licenses", ["GPL", "AGPL", "SSPL", "Elastic-2.0", "Commons-Clause"])
    ip_min_lines = int(config.get("ip_min_lines", 6) or 6)
    ip_min_chars = int(config.get("ip_min_chars", 240) or 240)
    issues.extend(detect_license_headers(code))
    issues.extend(detect_restricted_licenses(code, restricted if isinstance(restricted, list) else []))
    issues.extend(detect_ip_duplication(code))
    issues.extend(detect_near_duplicate_blocks(code, min_lines=ip_min_lines, min_chars=ip_min_chars))
    return issues
