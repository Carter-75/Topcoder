import re
from typing import List, Dict, Any

import config_loader

def check_naming_conventions(code: str) -> List[Dict[str, Any]]:
    # Simple check: function names should be snake_case (Python)
    issues = []
    for m in re.finditer(r'def\s+([A-Z][A-Za-z0-9_]*)\s*\(', code):
        issues.append({
            "type": "naming_convention",
            "message": f"Function '{m.group(1)}' should be snake_case.",
            "suggestion": "Rename to snake_case.",
            "start": m.start(1),
            "end": m.end(1)
        })
    return issues

def check_logging_practices(code: str) -> List[Dict[str, Any]]:
    # Discourage print(), encourage logging
    issues = []
    for m in re.finditer(r'print\(', code):
        issues.append({
            "type": "logging_practice",
            "message": "Use logging instead of print().",
            "suggestion": "Replace print() with logging calls.",
            "start": m.start(),
            "end": m.end()
        })
    return issues

def check_error_handling(code: str) -> List[Dict[str, Any]]:
    # Discourage bare except and except Exception
    issues = []
    for m in re.finditer(r'except\s*:', code):
        issues.append({
            "type": "error_handling",
            "message": "Avoid bare except; catch specific exceptions.",
            "suggestion": "Specify the exception type.",
            "start": m.start(),
            "end": m.end()
        })
    for m in re.finditer(r'except\s+Exception\s*:', code):
        issues.append({
            "type": "error_handling",
            "message": "Avoid catching broad Exception; catch specific exceptions.",
            "suggestion": "Catch only the exceptions you expect.",
            "start": m.start(),
            "end": m.end()
        })
    return issues

def _load_custom_coding_rules(repo_path: str) -> List[Dict[str, Any]]:
    config = config_loader.load_config(repo_path)
    rules = config.get("coding_standards", [])
    return rules if isinstance(rules, list) else []

def _apply_custom_coding_rules(code: str, rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    issues: List[Dict[str, Any]] = []
    for rule in rules:
        pattern = rule.get("pattern")
        if not pattern:
            continue
        patterns = pattern if isinstance(pattern, list) else [pattern]
        for pat in patterns:
            for m in re.finditer(pat, code, re.MULTILINE):
                issues.append({
                    "type": rule.get("type", "coding_standard"),
                    "message": rule.get("message", "Coding standard violation."),
                    "suggestion": rule.get("suggestion"),
                    "start": m.start(),
                    "end": m.end(),
                    "severity": rule.get("severity", "warning"),
                    "rule_id": rule.get("id"),
                })
    return issues

def run_coding_standards_rules(code: str, repo_path: str = ".") -> List[Dict[str, Any]]:
    issues = []
    config = config_loader.load_config(repo_path)
    builtins = config.get("coding_standards_builtin", {
        "naming": True,
        "logging": True,
        "error_handling": True,
    })
    if builtins.get("naming", True):
        issues.extend(check_naming_conventions(code))
    if builtins.get("logging", True):
        issues.extend(check_logging_practices(code))
    if builtins.get("error_handling", True):
        issues.extend(check_error_handling(code))
    issues.extend(_apply_custom_coding_rules(code, _load_custom_coding_rules(repo_path)))
    return issues
