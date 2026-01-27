import argparse
import os
from typing import List

from backend import scan_repo


def main() -> int:
    parser = argparse.ArgumentParser(prog="guardrails", description="Guardrails CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a repository")
    scan.add_argument("repo", help="Path to the repository root")
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
        ]
        if args.autofix:
            argv.append("--autofix")
        if args.no_autofix:
            argv.append("--no-autofix")
        if args.no_backup:
            argv.append("--no-backup")
        return scan_repo.main(argv)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
