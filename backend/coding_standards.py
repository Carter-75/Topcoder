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

def check_js_ts_naming(code: str) -> List[Dict[str, Any]]:
    issues = []
    patterns = [
        r"function\s+([a-z]+_[a-z0-9_]+)\s*\(",
        r"const\s+([a-z]+_[a-z0-9_]+)\s*=\s*(?:async\s*)?\(",
        r"let\s+([a-z]+_[a-z0-9_]+)\s*=\s*(?:async\s*)?\(",
    ]
    for pat in patterns:
        for m in re.finditer(pat, code):
            issues.append({
                "type": "naming_convention",
                "message": f"Identifier '{m.group(1)}' should be camelCase in JavaScript/TypeScript.",
                "suggestion": "Rename to camelCase.",
                "start": m.start(1),
                "end": m.end(1),
            })
    return issues

def check_java_naming(code: str) -> List[Dict[str, Any]]:
    issues = []
    for m in re.finditer(r"\b([a-z]+_[a-z0-9_]+)\s*\(", code):
        issues.append({
            "type": "naming_convention",
            "message": f"Method '{m.group(1)}' should be camelCase in Java.",
            "suggestion": "Rename to camelCase.",
            "start": m.start(1),
            "end": m.end(1),
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

def check_js_ts_logging(code: str) -> List[Dict[str, Any]]:
    issues = []
    for m in re.finditer(r"console\.(log|warn|error|debug|info)\(", code):
        issues.append({
            "type": "logging_practice",
            "message": "Use structured logging instead of console.* in production code.",
            "suggestion": "Replace console.* with your logging utility.",
            "start": m.start(),
            "end": m.end(),
        })
    return issues

def check_java_logging(code: str) -> List[Dict[str, Any]]:
    issues = []
    for m in re.finditer(r"System\.out\.println\(", code):
        issues.append({
            "type": "logging_practice",
            "message": "Use a logger instead of System.out.println().",
            "suggestion": "Replace with a logging framework (e.g., SLF4J).",
            "start": m.start(),
            "end": m.end(),
        })
    return issues

def check_go_logging(code: str) -> List[Dict[str, Any]]:
    issues = []
    for m in re.finditer(r"\bfmt\.(Print|Printf|Println)\(", code):
        issues.append({
            "type": "logging_practice",
            "message": "Use structured logging instead of fmt.Print* in production code.",
            "suggestion": "Replace fmt.Print* with a logger.",
            "start": m.start(),
            "end": m.end(),
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

def check_js_ts_error_handling(code: str) -> List[Dict[str, Any]]:
    issues = []
    for m in re.finditer(r"catch\s*\(\s*\w+\s*\)\s*\{\s*\}", code):
        issues.append({
            "type": "error_handling",
            "message": "Avoid empty catch blocks; handle or rethrow the error.",
            "suggestion": "Log and rethrow or handle the error explicitly.",
            "start": m.start(),
            "end": m.end(),
        })
    return issues

def check_java_error_handling(code: str) -> List[Dict[str, Any]]:
    issues = []
    for m in re.finditer(r"catch\s*\(\s*Exception\s+\w+\s*\)", code):
        issues.append({
            "type": "error_handling",
            "message": "Avoid catching broad Exception; catch specific exceptions.",
            "suggestion": "Catch only the exceptions you expect.",
            "start": m.start(),
            "end": m.end(),
        })
    for m in re.finditer(r"catch\s*\([^\)]*\)\s*\{\s*\}", code):
        issues.append({
            "type": "error_handling",
            "message": "Avoid empty catch blocks; handle or rethrow the error.",
            "suggestion": "Log and rethrow or handle the error explicitly.",
            "start": m.start(),
            "end": m.end(),
        })
    return issues

def check_go_error_handling(code: str) -> List[Dict[str, Any]]:
    issues = []
    for m in re.finditer(r"_\s*=\s*[A-Za-z0-9_]+\(", code):
        issues.append({
            "type": "error_handling",
            "message": "Possible ignored error return value detected.",
            "suggestion": "Capture and handle the error explicitly.",
            "start": m.start(),
            "end": m.end(),
        })
    for m in re.finditer(r"\bpanic\(", code):
        issues.append({
            "type": "error_handling",
            "message": "Avoid panic in application code; return errors instead.",
            "suggestion": "Return an error and handle it upstream.",
            "start": m.start(),
            "end": m.end(),
        })
    return issues

def check_ts_any_usage(code: str) -> List[Dict[str, Any]]:
    issues = []
    for m in re.finditer(r"\bany\b", code):
        issues.append({
            "type": "coding_standard",
            "message": "Avoid using 'any' in TypeScript; prefer specific types.",
            "suggestion": "Use explicit interfaces or generics.",
            "start": m.start(),
            "end": m.end(),
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

def _resolve_builtin_config(config: dict, language: str | None) -> Dict[str, bool]:
    default_builtin = {"naming": True, "logging": True, "error_handling": True}
    builtins = config.get("coding_standards_builtin", default_builtin)
    if isinstance(builtins, dict) and any(key in builtins for key in ["naming", "logging", "error_handling"]):
        return {
            "naming": bool(builtins.get("naming", True)),
            "logging": bool(builtins.get("logging", True)),
            "error_handling": bool(builtins.get("error_handling", True)),
            "typing": bool(builtins.get("typing", True)),
        }
    if isinstance(builtins, dict) and language and language in builtins:
        lang_cfg = builtins.get(language) if isinstance(builtins.get(language), dict) else {}
        return {
            "naming": bool(lang_cfg.get("naming", True)),
            "logging": bool(lang_cfg.get("logging", True)),
            "error_handling": bool(lang_cfg.get("error_handling", True)),
            "typing": bool(lang_cfg.get("typing", True)),
        }
    if isinstance(builtins, dict) and "default" in builtins and isinstance(builtins.get("default"), dict):
        lang_cfg = builtins.get("default", {})
        return {
            "naming": bool(lang_cfg.get("naming", True)),
            "logging": bool(lang_cfg.get("logging", True)),
            "error_handling": bool(lang_cfg.get("error_handling", True)),
            "typing": bool(lang_cfg.get("typing", True)),
        }
    return default_builtin

def run_coding_standards_rules(code: str, repo_path: str = ".", language: str | None = None) -> List[Dict[str, Any]]:
    issues = []
    config = config_loader.load_config(repo_path)
    builtins = _resolve_builtin_config(config, language)
    lang = (language or "").lower()

    if lang in {"javascript", "typescript"}:
        if builtins.get("naming", True):
            issues.extend(check_js_ts_naming(code))
        if builtins.get("logging", True):
            issues.extend(check_js_ts_logging(code))
        if builtins.get("error_handling", True):
            issues.extend(check_js_ts_error_handling(code))
        if lang == "typescript" and builtins.get("typing", True):
            issues.extend(check_ts_any_usage(code))
    elif lang == "java":
        if builtins.get("naming", True):
            issues.extend(check_java_naming(code))
        if builtins.get("logging", True):
            issues.extend(check_java_logging(code))
        if builtins.get("error_handling", True):
            issues.extend(check_java_error_handling(code))
    elif lang == "go":
        if builtins.get("logging", True):
            issues.extend(check_go_logging(code))
        if builtins.get("error_handling", True):
            issues.extend(check_go_error_handling(code))
    else:
        if builtins.get("naming", True):
            issues.extend(check_naming_conventions(code))
        if builtins.get("logging", True):
            issues.extend(check_logging_practices(code))
        if builtins.get("error_handling", True):
            issues.extend(check_error_handling(code))

    issues.extend(_apply_custom_coding_rules(code, _load_custom_coding_rules(repo_path)))
    return issues
