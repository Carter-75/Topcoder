import os
import shutil
import sys
from pathlib import Path


BIN_DIR = Path.home() / ".guardrails" / "bin"
TARGET = BIN_DIR / "guardrails.py"
SOURCE = Path(__file__).resolve().parent / "guardrails.py"


def _ensure_path_windows(bin_dir: Path) -> None:
    try:
        import winreg
    except Exception:
        return
    key_path = r"Environment"
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ) as key:
        try:
            current = winreg.QueryValueEx(key, "Path")[0]
        except OSError:
            current = ""
    paths = [p for p in current.split(";") if p]
    if str(bin_dir) in paths:
        return
    paths.append(str(bin_dir))
    new_path = ";".join(paths)
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, new_path)


def _ensure_path_posix(bin_dir: Path) -> None:
    profile_candidates = [Path.home() / ".profile", Path.home() / ".bashrc", Path.home() / ".zshrc"]
    export_line = f'export PATH="{bin_dir}:$PATH"\n'
    for profile in profile_candidates:
        try:
            if profile.exists():
                content = profile.read_text(encoding="utf-8")
                if str(bin_dir) in content:
                    return
            profile.write_text((profile.read_text(encoding="utf-8") if profile.exists() else "") + export_line, encoding="utf-8")
            return
        except Exception:
            continue


def main() -> int:
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    shutil.copy2(SOURCE, TARGET)
    if sys.platform.startswith("win"):
        _ensure_path_windows(BIN_DIR)
    else:
        _ensure_path_posix(BIN_DIR)
    print(f"Installed guardrails CLI to {TARGET}")
    print("Restart your terminal to use 'guardrails'.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
