import re
from typing import List, Dict, Any

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

def run_coding_standards_rules(code: str) -> List[Dict[str, Any]]:
    issues = []
    issues.extend(check_naming_conventions(code))
    issues.extend(check_logging_practices(code))
    issues.extend(check_error_handling(code))
    return issues
