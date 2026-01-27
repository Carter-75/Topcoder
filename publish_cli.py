import argparse
import os
import shutil
import subprocess
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
PYPROJECT = PROJECT_ROOT / "pyproject.toml"
WATCH_PATHS = [PROJECT_ROOT / "src" / "guardrails_cli", PYPROJECT]


def _run(cmd: list[str]) -> None:
    subprocess.run(cmd, cwd=PROJECT_ROOT, check=True)


def _read_version() -> str:
    content = PYPROJECT.read_text(encoding="utf-8")
    for line in content.splitlines():
        if line.strip().startswith("version"):
            return line.split("=", 1)[1].strip().strip('"')
    raise RuntimeError("Version not found in pyproject.toml")


def _write_version(new_version: str) -> None:
    content = PYPROJECT.read_text(encoding="utf-8")
    lines = []
    for line in content.splitlines():
        if line.strip().startswith("version"):
            lines.append(f'version = "{new_version}"')
        else:
            lines.append(line)
    PYPROJECT.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _bump_patch(version: str) -> str:
    parts = version.split(".")
    if len(parts) != 3:
        raise RuntimeError("Version must be in MAJOR.MINOR.PATCH format")
    major, minor, patch = parts
    return f"{major}.{minor}.{int(patch) + 1}"


def _get_latest_mtime() -> float:
    mtimes = []
    for path in WATCH_PATHS:
        if path.is_dir():
            for file in path.rglob("*"):
                if file.is_file():
                    mtimes.append(file.stat().st_mtime)
        elif path.exists():
            mtimes.append(path.stat().st_mtime)
    return max(mtimes) if mtimes else 0.0


def publish() -> None:
    old_version = _read_version()
    new_version = _bump_patch(old_version)
    _write_version(new_version)
    dist_path = PROJECT_ROOT / "dist"
    build_path = PROJECT_ROOT / "build"
    if dist_path.exists():
        shutil.rmtree(dist_path)
    if build_path.exists():
        shutil.rmtree(build_path)
    _run(["python", "-m", "build"])
    _run(["python", "-m", "twine", "upload", "--skip-existing", "dist/*"])


def main() -> int:
    parser = argparse.ArgumentParser(description="Publish guardrails-cli to PyPI")
    parser.add_argument("--watch", action="store_true", help="Watch for changes and auto-publish")
    parser.add_argument("--interval", type=int, default=5, help="Watch interval in seconds")
    args = parser.parse_args()

    if args.watch:
        last_mtime = _get_latest_mtime()
        while True:
            time.sleep(args.interval)
            current_mtime = _get_latest_mtime()
            if current_mtime > last_mtime:
                publish()
                last_mtime = _get_latest_mtime()
        return 0

    publish()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
