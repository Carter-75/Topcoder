import argparse
import json
import os
from typing import Dict, List, Any

import requests

DEFAULT_EXCLUDE_DIRS = {
    ".git",
    ".venv",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    ".next",
    ".cache",
}

DEFAULT_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".java",
    ".go",
    ".rs",
    ".cs",
    ".cpp",
    ".c",
    ".h",
    ".hpp",
    ".html",
    ".css",
    ".scss",
    ".md",
    ".yml",
    ".yaml",
    ".json",
    ".toml",
    ".ini",
    ".sh",
    ".ps1",
}


def iter_files(root: str, extensions: set[str], exclude_dirs: set[str]) -> List[str]:
    matches: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
        for filename in filenames:
            _, ext = os.path.splitext(filename)
            if extensions and ext.lower() not in extensions:
                continue
            matches.append(os.path.join(dirpath, filename))
    return matches


def analyze_file(api_url: str, path: str, sector: str, repo_path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        code = f.read()
    payload = {
        "code": code,
        "sector": sector,
        "repo_path": repo_path,
    }
    resp = requests.post(f"{api_url.rstrip('/')}/analyze", json=payload, timeout=30)
    resp.raise_for_status()
    return resp.json()


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan a repository using the Guardrails API.")
    parser.add_argument("repo", help="Path to the repository root")
    parser.add_argument("--api", default="http://127.0.0.1:8000", help="Guardrails API base URL")
    parser.add_argument("--sector", default="finance", help="Sector rulepack to apply")
    parser.add_argument("--output", default="scan_results.json", help="Output JSON file")
    parser.add_argument("--max-files", type=int, default=0, help="Limit the number of files scanned (0 = no limit)")
    parser.add_argument("--extensions", default=",".join(sorted(DEFAULT_EXTENSIONS)), help="Comma-separated file extensions")
    parser.add_argument("--exclude-dirs", default=",".join(sorted(DEFAULT_EXCLUDE_DIRS)), help="Comma-separated directory names to skip")
    args = parser.parse_args()

    repo_path = os.path.abspath(args.repo)
    extensions = {ext.strip().lower() for ext in args.extensions.split(",") if ext.strip()}
    exclude_dirs = {d.strip() for d in args.exclude_dirs.split(",") if d.strip()}

    files = iter_files(repo_path, extensions, exclude_dirs)
    if args.max_files > 0:
        files = files[: args.max_files]

    results: Dict[str, Any] = {
        "repo": repo_path,
        "api": args.api,
        "sector": args.sector,
        "files_scanned": 0,
        "findings": {},
        "errors": {},
    }

    for path in files:
        rel_path = os.path.relpath(path, repo_path)
        try:
            findings = analyze_file(args.api, path, args.sector, repo_path)
            results["findings"][rel_path] = findings
            results["files_scanned"] += 1
        except Exception as exc:
            results["errors"][rel_path] = str(exc)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
