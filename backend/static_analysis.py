import json
import os
import tempfile
import subprocess
from typing import List, Dict, Any

SEMGREP_ENABLED = os.environ.get("SEMGREP_ENABLED", "false").lower() == "true"
SEMGREP_TIMEOUT = int(os.environ.get("SEMGREP_TIMEOUT", "20"))

_LANGUAGE_EXT = {
    "python": ".py",
    "javascript": ".js",
    "typescript": ".ts",
    "java": ".java",
    "go": ".go",
    "rust": ".rs",
    "csharp": ".cs",
    "cpp": ".cpp",
    "c": ".c",
    "html": ".html",
    "css": ".css",
    "scss": ".scss",
    "yaml": ".yml",
    "json": ".json",
    "toml": ".toml",
    "ini": ".ini",
    "markdown": ".md",
    "shell": ".sh",
    "powershell": ".ps1",
}


def _map_severity(value: str | None) -> str:
    if not value:
        return "warning"
    normalized = value.strip().lower()
    if normalized in {"error", "critical", "high"}:
        return "blocking"
    if normalized in {"medium", "warning"}:
        return "warning"
    return "advisory"


def _extract_metadata(meta: dict) -> dict:
    cwe = None
    owasp = None
    refs = []
    if isinstance(meta, dict):
        if isinstance(meta.get("cwe"), list) and meta.get("cwe"):
            cwe = str(meta.get("cwe")[0])
        if isinstance(meta.get("owasp"), list) and meta.get("owasp"):
            owasp = str(meta.get("owasp")[0])
        refs = meta.get("references", []) if isinstance(meta.get("references"), list) else []
    return {"cwe": cwe, "owasp": owasp, "references": refs}


def run_semgrep(code: str, language: str | None) -> List[Dict[str, Any]]:
    if not SEMGREP_ENABLED:
        return []
    ext = _LANGUAGE_EXT.get((language or "").lower(), ".txt")
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, f"scan{ext}")
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(code)
            result = subprocess.run(
                ["semgrep", "--config", "auto", "--json", file_path],
                capture_output=True,
                text=True,
                timeout=SEMGREP_TIMEOUT,
            )
            if result.returncode not in {0, 1}:
                return []
            payload = json.loads(result.stdout or "{}")
            findings = []
            for item in payload.get("results", []):
                message = item.get("extra", {}).get("message") or item.get("check_id") or "Static analysis finding."
                severity = _map_severity(item.get("extra", {}).get("severity"))
                meta = _extract_metadata(item.get("extra", {}).get("metadata", {}))
                findings.append({
                    "type": "static_analysis",
                    "category": "security",
                    "message": message,
                    "suggestion": "Review static analysis finding and remediate.",
                    "line": item.get("start", {}).get("line"),
                    "severity": severity,
                    "cwe": meta.get("cwe"),
                    "owasp": meta.get("owasp"),
                    "references": meta.get("references", []),
                })
            return findings
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return []


def run_static_analysis(code: str, language: str | None) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    findings.extend(run_semgrep(code, language))
    return findings
