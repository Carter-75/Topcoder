import random
from typing import List, Dict, Any

def ai_review_stub(code: str) -> List[Dict[str, Any]]:
    # Simulate AI review with random or simple heuristics
    suggestions = []
    if "print(" in code:
        suggestions.append({
            "type": "performance",
            "message": "Consider using logging instead of print for production code.",
            "explanation": "Logging provides better control and is more suitable for enterprise environments.",
            "suggestion": "Replace print() with logging calls.",
            "severity": "advisory"
        })
    if "except Exception" in code:
        suggestions.append({
            "type": "maintainability",
            "message": "Avoid catching broad Exception; catch specific exceptions.",
            "explanation": "Catching all exceptions can hide bugs and make debugging harder.",
            "suggestion": "Catch only the exceptions you expect.",
            "severity": "warning"
        })
    # Add a random security suggestion for demo
    if random.random() < 0.2:
        suggestions.append({
            "type": "security",
            "message": "Review input validation for user-controlled data.",
            "explanation": "Unvalidated input can lead to security vulnerabilities.",
            "suggestion": "Add input validation and sanitization.",
            "severity": "advisory"
        })
    return suggestions
