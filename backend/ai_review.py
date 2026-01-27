
import os
import random
from typing import List, Dict, Any

import requests

def ai_review(code: str, api_key_override: str | None = None) -> List[Dict[str, Any]]:
    api_key = api_key_override or os.environ.get("OPENAI_API_KEY")
    require_ai = os.environ.get("REQUIRE_AI_REVIEW", "true").lower() == "true"
    if api_key:
        # Use OpenAI API for real AI review
        try:
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            }
            data = {
                "model": "gpt-4",
                "messages": [
                    {"role": "system", "content": "You are a secure code reviewer. Analyze the following code for security, performance, and maintainability. List issues, explanations, and suggestions as JSON."},
                    {"role": "user", "content": code}
                ],
                "max_tokens": 512,
                "temperature": 0.2
            }
            resp = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=data, timeout=20)
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"]
            # Try to parse JSON from the response
            import json
            try:
                suggestions = json.loads(content)
                if isinstance(suggestions, dict) and "suggestions" in suggestions:
                    return suggestions["suggestions"]
                if isinstance(suggestions, list):
                    return suggestions
            except Exception:
                # Fallback: return as a single suggestion
                return [{"type": "ai_review", "message": content, "severity": "advisory"}]
        except Exception as e:
            return [{"type": "ai_review_error", "message": str(e), "severity": "warning"}]
    if require_ai:
        return [{
            "type": "ai_review_missing_key",
            "message": "OPENAI_API_KEY is required for AI review.",
            "explanation": "Set OPENAI_API_KEY in the environment to enable AI review for all scans.",
            "severity": "blocking",
        }]
    # Fallback to stub if no API key and AI review is not required
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
    if random.random() < 0.2:
        suggestions.append({
            "type": "security",
            "message": "Review input validation for user-controlled data.",
            "explanation": "Unvalidated input can lead to security vulnerabilities.",
            "suggestion": "Add input validation and sanitization.",
            "severity": "advisory"
        })
    return suggestions
