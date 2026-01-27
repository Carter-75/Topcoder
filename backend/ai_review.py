
import os
import json
import re
from typing import List, Dict, Any

import requests

ALLOWED_SEVERITIES = {"advisory", "warning", "blocking"}
ALLOWED_CATEGORIES = {"security", "performance", "maintainability", "reliability", "compliance"}
MAX_CODE_CHARS = int(os.environ.get("AI_REVIEW_MAX_CHARS", "12000"))

def _normalize_severity(value: str | None) -> str:
    if not value:
        return "advisory"
    lowered = value.strip().lower()
    return lowered if lowered in ALLOWED_SEVERITIES else "advisory"

def _normalize_category(value: str | None) -> str:
    if not value:
        return "maintainability"
    lowered = value.strip().lower()
    return lowered if lowered in ALLOWED_CATEGORIES else "maintainability"

def _extract_json(content: str) -> Any:
    text = content.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(json)?\s*", "", text)
        text = re.sub(r"```\s*$", "", text)
    try:
        return json.loads(text)
    except Exception:
        pass
    start = min((idx for idx in [text.find("["), text.find("{")] if idx != -1), default=-1)
    if start == -1:
        raise ValueError("No JSON found in response.")
    end_candidates = [text.rfind("]"), text.rfind("}")]
    end = max(end_candidates)
    if end == -1:
        raise ValueError("No JSON end found in response.")
    return json.loads(text[start:end + 1])

def _sanitize_findings(findings: Any) -> List[Dict[str, Any]]:
    if isinstance(findings, dict) and "findings" in findings:
        findings = findings["findings"]
    if not isinstance(findings, list):
        return []
    sanitized: List[Dict[str, Any]] = []
    for item in findings:
        if not isinstance(item, dict):
            continue
        sanitized.append({
            "type": item.get("type", "ai_review"),
            "category": _normalize_category(item.get("category")),
            "severity": _normalize_severity(item.get("severity")),
            "message": item.get("message", "AI review finding."),
            "explanation": item.get("explanation", ""),
            "suggestion": item.get("suggestion", ""),
            "references": item.get("references", []) if isinstance(item.get("references", []), list) else [],
            "line": item.get("line"),
        })
    return sanitized

def _build_prompt(code: str, context: dict | None, max_chars: int) -> str:
    context = context or {}
    truncated = False
    limit = max_chars if max_chars > 0 else MAX_CODE_CHARS
    if len(code) > limit:
        code = code[:limit]
        truncated = True
    file_path = context.get("path", "unknown")
    language = context.get("language", "unknown")
    patch = context.get("patch")
    pr_number = context.get("pr_number")
    commit = context.get("commit")
    repo = context.get("repo")
    ai_generated = bool(context.get("ai_generated"))

    header = [
        "You are an enterprise secure code reviewer.",
        "Return ONLY a JSON array of findings.",
        "Each finding must include: type, category (security|performance|maintainability|reliability|compliance), severity (advisory|warning|blocking), message, explanation, suggestion, references (array of URLs), and optional line.",
        "Focus on issues with clear evidence and explain why they matter.",
        "Prefer findings that reference the diff if provided.",
        f"Repo: {repo}",
        f"File: {file_path}",
        f"Language: {language}",
        f"PR: {pr_number}" if pr_number is not None else "",
        f"Commit: {commit}" if commit else "",
        f"Copilot suspected: {ai_generated}",
    ]
    header_text = "\n".join([line for line in header if line])
    if truncated:
        header_text += "\nNote: File content truncated for analysis."
    if patch:
        return f"{header_text}\n\nDiff:\n{patch}\n\nFull file content (for context):\n{code}"
    return f"{header_text}\n\nFile content:\n{code}"

def ai_review(
    code: str,
    api_key_override: str | None = None,
    require_ai_override: bool | None = None,
    context: dict | None = None,
    model_override: str | None = None,
    max_chars_override: int | None = None,
) -> List[Dict[str, Any]]:
    api_key = api_key_override or os.environ.get("OPENAI_API_KEY")
    require_ai = os.environ.get("REQUIRE_AI_REVIEW", "true").lower() == "true"
    if require_ai_override is not None:
        require_ai = require_ai_override
    if not require_ai:
        return []
    if not api_key:
        return [{
            "type": "ai_review_missing_key",
            "message": "OPENAI_API_KEY is required for AI review.",
            "explanation": "Set OPENAI_API_KEY in the environment to enable AI review for all scans.",
            "severity": "blocking",
        }]
    model = model_override or os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
    max_chars = max_chars_override if isinstance(max_chars_override, int) else MAX_CODE_CHARS
    prompt = _build_prompt(code, context, max_chars)
    try:
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a secure code reviewer. Return a JSON array of findings only. "
                        "Do not wrap in markdown or add commentary."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "max_tokens": 900,
            "temperature": 0.1,
        }
        resp = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload, timeout=25)
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]
        parsed = _extract_json(content)
        return _sanitize_findings(parsed)
    except Exception as exc:
        return [{
            "type": "ai_review_error",
            "category": "reliability",
            "message": "AI review failed.",
            "explanation": str(exc),
            "suggestion": "Retry the scan or disable AI review for this run.",
            "severity": "warning",
        }]


def ai_rewrite(
    code: str,
    findings: List[Dict[str, Any]],
    api_key_override: str | None = None,
    context: dict | None = None,
    model_override: str | None = None,
) -> str:
    api_key = api_key_override or os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("OPENAI_API_KEY is required for AI rewrite.")
    model = model_override or os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
    ctx = context or {}
    file_path = ctx.get("path", "unknown")
    language = ctx.get("language", "unknown")
    issues_text = json.dumps(findings, ensure_ascii=False)
    prompt = (
        "You are a senior engineer. Rewrite the file to fix all findings and warnings. "
        "Preserve behavior unless a finding requires a change. Use best practices. "
        "Return ONLY the full updated file contents, no markdown or code fences.\n\n"
        f"File: {file_path}\nLanguage: {language}\nFindings: {issues_text}\n\n"
        f"Original file:\n{code}"
    )
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "Rewrite the code to fix the findings. Return only the full file contents."},
            {"role": "user", "content": prompt},
        ],
        "max_tokens": 2048,
        "temperature": 0.1,
    }
    resp = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload, timeout=60)
    resp.raise_for_status()
    content = resp.json()["choices"][0]["message"]["content"]
    if content.startswith("```"):
        content = re.sub(r"^```[a-zA-Z]*\s*", "", content)
        content = re.sub(r"```\s*$", "", content)
    return content.strip("\n")
