import os
import re
from typing import List, Dict, Any

import config_loader

LICENSE_PATTERNS = [
    (r"SPDX-License-Identifier:\s*([A-Za-z0-9\.-]+)", "spdx"),
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

LICENSE_FILES = {
    "LICENSE",
    "LICENSE.txt",
    "LICENSE.md",
    "COPYING",
    "COPYING.txt",
    "NOTICE",
    "NOTICE.txt",
}

def detect_license_headers(code: str) -> List[Dict[str, Any]]:
    # Heuristic: Look for common open source license headers and SPDX identifiers
    issues = []
    for pat, name in LICENSE_PATTERNS:
        for match in re.finditer(pat, code, re.IGNORECASE):
            license_name = name
            if name == "spdx":
                license_name = match.group(1)
            issues.append({
                "type": "license_detected",
                "license": license_name,
                "message": f"Detected {license_name} license identifier in code.",
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

def scan_repo_licenses(repo_path: str) -> List[str]:
    if not repo_path or not os.path.isdir(repo_path):
        return []
    detected: List[str] = []
    for root, _, files in os.walk(repo_path):
        for name in files:
            if name not in LICENSE_FILES:
                continue
            path = os.path.join(root, name)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                for pat, lic in LICENSE_PATTERNS:
                    for match in re.finditer(pat, content, re.IGNORECASE):
                        license_name = lic
                        if lic == "spdx":
                            license_name = match.group(1)
                        if license_name not in detected:
                            detected.append(license_name)
            except Exception:
                continue
    return detected

def detect_cross_file_duplicates(
    file_map: Dict[str, str],
    min_lines: int = 6,
    min_chars: int = 240,
) -> Dict[str, List[Dict[str, Any]]]:
    issues: Dict[str, List[Dict[str, Any]]] = {}
    fingerprints: Dict[int, tuple[str, int, str]] = {}
    for path, code in file_map.items():
        lines = [line.rstrip() for line in code.splitlines()]
        for i in range(0, max(0, len(lines) - min_lines + 1)):
            window = "\n".join(lines[i:i + min_lines]).strip()
            if len(window) < min_chars:
                continue
            fingerprint = hash(window)
            if fingerprint in fingerprints:
                other_path, other_line, snippet = fingerprints[fingerprint]
                if other_path == path:
                    continue
                issue = {
                    "type": "ip_cross_file_duplicate",
                    "message": "Possible duplicated code block across files.",
                    "line": i + 1,
                    "original_file": other_path,
                    "original_line": other_line,
                    "snippet": snippet,
                    "severity": "warning",
                }
                issues.setdefault(path, []).append(issue)
            else:
                fingerprints[fingerprint] = (path, i + 1, window[:80] + ("..." if len(window) > 80 else ""))
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
