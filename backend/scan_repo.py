import argparse
import json
import os
from typing import Dict, List, Any, Tuple

import requests

import autofix
import settings_store

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


def analyze_batch(
    api_url: str,
    files: List[Tuple[str, str]],
    sector: str,
    repo_path: str,
    api_key: str | None,
    require_ai_review: bool | None,
    ai_model: str | None,
    ai_review_max_chars: int | None,
    user_key: str | None,
) -> Dict[str, Any]:
    payload = {
        "files": [{"path": path, "code": code} for path, code in files],
        "sector": sector,
        "repo_path": repo_path,
        "require_ai_review": require_ai_review,
        "ai_model": ai_model,
        "ai_review_max_chars": ai_review_max_chars,
    }
    headers = {}
    if api_key:
        headers["X-OpenAI-API-Key"] = api_key
    if user_key:
        headers["X-Guardrails-User"] = user_key
    resp = requests.post(f"{api_url.rstrip('/')}/analyze-batch", json=payload, headers=headers, timeout=60)
    resp.raise_for_status()
    return resp.json()


def _write_backup(backup_root: str, repo_root: str, rel_path: str, code: str) -> None:
    backup_path = os.path.join(backup_root, rel_path)
    os.makedirs(os.path.dirname(backup_path), exist_ok=True)
    with open(backup_path, "w", encoding="utf-8") as f:
        f.write(code)


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan a repository using the Guardrails API.")
    parser.add_argument("repo", nargs="?", default=".", help="Path to the repository root (defaults to current directory)")
    parser.add_argument("--api", default=os.environ.get("GUARDRAILS_API_URL", "https://topcoder-production.up.railway.app"), help="Guardrails API base URL")
    parser.add_argument("--sector", default="finance", help="Sector rulepack to apply")
    parser.add_argument("--output", default="scan_results.json", help="Output JSON file")
    parser.add_argument("--max-files", type=int, default=0, help="Limit the number of files scanned (0 = no limit)")
    parser.add_argument("--extensions", default=",".join(sorted(DEFAULT_EXTENSIONS)), help="Comma-separated file extensions")
    parser.add_argument("--exclude-dirs", default=",".join(sorted(DEFAULT_EXCLUDE_DIRS)), help="Comma-separated directory names to skip")
    parser.add_argument("--api-key", default=os.environ.get("OPENAI_API_KEY", ""), help="OpenAI API key (or set OPENAI_API_KEY)")
    parser.add_argument("--ai-model", default=os.environ.get("OPENAI_MODEL", ""), help="AI model override (or set OPENAI_MODEL)")
    parser.add_argument("--ai-max-chars", type=int, default=0, help="AI review max chars override (or set AI_REVIEW_MAX_CHARS)")
    parser.add_argument("--user", default=os.environ.get("GUARDRAILS_USER", ""), help="User token for scoped settings")
    parser.add_argument("--chunk-size", type=int, default=25, help="Number of files per batch request")
    parser.add_argument("--autofix", action="store_true", help="Apply safe autofixes to local files")
    parser.add_argument("--no-autofix", action="store_true", help="Disable autofix explicitly")
    parser.add_argument("--no-backup", action="store_true", help="Disable autofix backups")
    parser.add_argument("--no-ai", action="store_true", help="Disable AI review for this run")
    args = parser.parse_args(argv)

    repo_path = os.path.abspath(args.repo)
    api_key = args.api_key.strip()
    ai_model = args.ai_model.strip()
    ai_review_max_chars = args.ai_max_chars if args.ai_max_chars > 0 else 0
    user_key = args.user.strip() or None
    require_ai_review = None

    if args.no_ai:
        require_ai_review = False
    elif not api_key and os.isatty(0):
        try:
            answer = input("No API key detected. Enter key to enable AI review, or press Enter to run in non-AI mode: ").strip()
            if answer:
                api_key = answer
                settings_store.save_api_key(api_key, user_key=user_key)
            else:
                require_ai_review = False
        except Exception:
            require_ai_review = False

    if args.autofix:
        autofix_enabled = True
    elif args.no_autofix:
        autofix_enabled = False
    else:
        autofix_enabled = None
        try:
            settings_headers = {"X-Guardrails-User": user_key} if user_key else None
            settings_res = requests.get(
                f"{args.api.rstrip('/')}/settings",
                headers=settings_headers,
                timeout=10,
            )
            if settings_res.ok:
                data = settings_res.json()
                if data.get("settings_scope") == "user" and not user_key:
                    if os.isatty(0):
                        prompt = "User token required. Paste your token or press Enter to generate one: "
                        entered = input(prompt).strip()
                        if entered:
                            user_key = entered
                        else:
                            user_key = os.urandom(16).hex()
                            print(f"Generated user token: {user_key}")
                        settings_headers = {"X-Guardrails-User": user_key}
                        settings_res = requests.get(
                            f"{args.api.rstrip('/')}/settings",
                            headers=settings_headers,
                            timeout=10,
                        )
                        data = settings_res.json() if settings_res.ok else data
                    else:
                        raise RuntimeError("Missing user token for user-scoped settings.")
                if isinstance(data.get("autofix_default"), bool):
                    autofix_enabled = data["autofix_default"]
                if not ai_model and isinstance(data.get("ai_model"), str):
                    ai_model = data["ai_model"]
                if ai_review_max_chars <= 0 and isinstance(data.get("ai_review_max_chars"), int):
                    ai_review_max_chars = data["ai_review_max_chars"]
        except Exception:
            autofix_enabled = None
        if autofix_enabled is None:
            if os.isatty(0):
                try:
                    answer = input("Apply safe autofixes? [y/N]: ").strip().lower()
                    autofix_enabled = answer in {"y", "yes"}
                except Exception:
                    autofix_enabled = False
            else:
                autofix_enabled = False
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

    autofix_changes: Dict[str, List[str]] = {}
    backup_root = os.path.join(repo_path, ".guardrails_backup")

    batch: List[Tuple[str, str]] = []
    batch_paths: List[str] = []
    for path in files:
        rel_path = os.path.relpath(path, repo_path)
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                code = f.read()
            if autofix_enabled:
                updated, changes = autofix.apply_autofix(path, code)
                if changes and not args.no_backup:
                    _write_backup(backup_root, repo_path, rel_path, code)
                if updated != code:
                    with open(path, "w", encoding="utf-8") as f:
                        f.write(updated)
                if changes:
                    autofix_changes[rel_path] = changes
                code = updated
            batch.append((rel_path, code))
            batch_paths.append(rel_path)
            if len(batch) >= args.chunk_size:
                findings = analyze_batch(
                    args.api,
                    batch,
                    args.sector,
                    repo_path,
                    api_key or None,
                    require_ai_review,
                    ai_model or None,
                    ai_review_max_chars if ai_review_max_chars > 0 else None,
                    user_key,
                )
                for file_path, file_findings in findings.get("findings", {}).items():
                    results["findings"][file_path] = file_findings
                    results["files_scanned"] += 1
                batch = []
                batch_paths = []
        except Exception as exc:
            results["errors"][rel_path] = str(exc)

    if batch:
        try:
            findings = analyze_batch(
                args.api,
                batch,
                args.sector,
                repo_path,
                api_key or None,
                require_ai_review,
                ai_model or None,
                ai_review_max_chars if ai_review_max_chars > 0 else None,
                user_key,
            )
            for file_path, file_findings in findings.get("findings", {}).items():
                results["findings"][file_path] = file_findings
                results["files_scanned"] += 1
        except Exception as exc:
            for file_path in batch_paths:
                results["errors"][file_path] = str(exc)

    if autofix_changes:
        results["autofix"] = {
            "applied": True,
            "backup_dir": None if args.no_backup else ".guardrails_backup",
            "changes": autofix_changes,
        }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
