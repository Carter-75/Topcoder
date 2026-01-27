import argparse
import os
from typing import List

import requests
from cryptography.fernet import Fernet

from guardrails_cli import scan_repo


def main() -> int:
    parser = argparse.ArgumentParser(prog="guardrails", description="Guardrails CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a repository")
    scan.add_argument("repo", nargs="?", default=".", help="Path to the repository root (defaults to current directory)")
    scan.add_argument("--api", default=os.environ.get("GUARDRAILS_API_URL", "https://topcoder-production.up.railway.app"), help="Guardrails API base URL")
    scan.add_argument("--sector", default="finance", help="Sector rulepack to apply")
    scan.add_argument("--output", default="scan_results.json", help="Output JSON file")
    scan.add_argument("--max-files", type=int, default=0, help="Limit the number of files scanned (0 = no limit)")
    scan.add_argument("--extensions", default=",".join(sorted(scan_repo.DEFAULT_EXTENSIONS)), help="Comma-separated file extensions")
    scan.add_argument("--exclude-dirs", default=",".join(sorted(scan_repo.DEFAULT_EXCLUDE_DIRS)), help="Comma-separated directory names to skip")
    scan.add_argument("--api-key", default=os.environ.get("OPENAI_API_KEY", ""), help="OpenAI API key (or set OPENAI_API_KEY)")
    scan.add_argument("--chunk-size", type=int, default=25, help="Number of files per batch request")
    scan.add_argument("--autofix", action="store_true", help="Apply safe autofixes to local files")
    scan.add_argument("--no-autofix", action="store_true", help="Disable autofix explicitly")
    scan.add_argument("--no-backup", action="store_true", help="Disable autofix backups")
    scan.add_argument("--no-ai", action="store_true", help="Disable AI review for this run")
    scan.add_argument("--user", default=os.environ.get("GUARDRAILS_USER", ""), help="User token for scoped settings")

    settings = sub.add_parser("settings", help="Manage Guardrails settings")
    settings.add_argument("--api", default=os.environ.get("GUARDRAILS_API_URL", "https://topcoder-production.up.railway.app"), help="Guardrails API base URL")
    settings.add_argument("--token", default=os.environ.get("SETTINGS_TOKEN", ""), help="Settings token for protected endpoints")
    settings.add_argument("--user", default=os.environ.get("GUARDRAILS_USER", ""), help="Optional user identifier for scoped settings")
    settings.add_argument("--set-api-key", default="", help="Set API key in hosted settings")
    settings.add_argument("--ai-mode", choices=["require", "allow"], help="Set default AI mode (require or allow non-AI)")
    settings.add_argument("--autofix-mode", choices=["on", "off"], help="Set default auto-fix mode")
    settings.add_argument("--issue-user-token", action="store_true", help="Generate a user token and print it")
    settings.add_argument("--generate-local-key", action="store_true", help="Generate a local settings encryption key")
    settings.add_argument("--verify", action="store_true", help="Verify settings sync with the server")

    args = parser.parse_args()
    if args.command == "scan":
        argv: List[str] = [
            args.repo,
            "--api",
            args.api,
            "--sector",
            args.sector,
            "--output",
            args.output,
            "--max-files",
            str(args.max_files),
            "--extensions",
            args.extensions,
            "--exclude-dirs",
            args.exclude_dirs,
            "--api-key",
            args.api_key,
            "--chunk-size",
            str(args.chunk_size),
            "--user",
            args.user,
        ]
        if args.autofix:
            argv.append("--autofix")
        if args.no_autofix:
            argv.append("--no-autofix")
        if args.no_backup:
            argv.append("--no-backup")
        if args.no_ai:
            argv.append("--no-ai")
        return scan_repo.main(argv)
    if args.command == "settings":
        headers = {}
        if args.token:
            headers["Authorization"] = f"Bearer {args.token}"
        if args.user:
            headers["X-Guardrails-User"] = args.user
        api_base = args.api.rstrip("/")
        if args.generate_local_key:
            print(Fernet.generate_key().decode("utf-8"))
            return 0
        if args.issue_user_token:
            res = requests.post(f"{api_base}/settings/token", timeout=15)
            res.raise_for_status()
            data = res.json()
            token = data.get("user_token")
            if token:
                print(token)
                return 0
            print("Failed to generate user token.")
            return 1
        if args.set_api_key:
            res = requests.post(
                f"{api_base}/settings/api-key",
                headers={"Content-Type": "application/json", **headers},
                json={"api_key": args.set_api_key},
                timeout=15,
            )
            res.raise_for_status()
            print(res.json())
            return 0
        if args.verify:
            res = requests.get(f"{api_base}/settings", headers=headers, timeout=15)
            res.raise_for_status()
            print(res.json())
            return 0
        if args.ai_mode:
            value = args.ai_mode == "require"
            res = requests.post(
                f"{api_base}/settings/ai-mode",
                headers={"Content-Type": "application/json", **headers},
                json={"require_ai_review": value},
                timeout=15,
            )
            res.raise_for_status()
            print(res.json())
            return 0
        if args.autofix_mode:
            value = args.autofix_mode == "on"
            res = requests.post(
                f"{api_base}/settings/autofix-mode",
                headers={"Content-Type": "application/json", **headers},
                json={"autofix_default": value},
                timeout=15,
            )
            res.raise_for_status()
            print(res.json())
            return 0
        print("No settings action provided.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
