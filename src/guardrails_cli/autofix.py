from __future__ import annotations

import os
from typing import Tuple, List


def _find_header_end(lines: List[str]) -> int:
    idx = 0
    if idx < len(lines) and lines[idx].startswith("#!/"):
        idx += 1
    if idx < len(lines) and "coding" in lines[idx]:
        idx += 1
    while idx < len(lines) and lines[idx].strip() == "":
        idx += 1
    if idx < len(lines) and lines[idx].lstrip().startswith(("\"\"\"", "'''")):
        quote = "\"\"\"" if "\"\"\"" in lines[idx] else "'''"
        if lines[idx].count(quote) >= 2:
            idx += 1
        else:
            idx += 1
            while idx < len(lines):
                if quote in lines[idx]:
                    idx += 1
                    break
                idx += 1
    return idx


def _ensure_logging_setup(code: str) -> str:
    lines = code.splitlines(keepends=True)
    header_end = _find_header_end(lines)

    has_logging_import = any(line.strip() == "import logging" for line in lines)
    if not has_logging_import:
        lines.insert(header_end, "import logging\n")
        header_end += 1

    has_logger = any("logging.getLogger(__name__)" in line for line in lines)
    if not has_logger:
        import_end = header_end
        for i in range(header_end, len(lines)):
            stripped = lines[i].strip()
            if stripped.startswith("import ") or stripped.startswith("from "):
                import_end = i + 1
                continue
            if stripped == "":
                continue
            break
        lines.insert(import_end, "\nlogger = logging.getLogger(__name__)\n")
    return "".join(lines)


def apply_autofix(path: str, code: str) -> Tuple[str, List[str]]:
    changes: List[str] = []
    ext = os.path.splitext(path)[1].lower()
    updated = code
    if ext == ".py" and "print(" in updated:
        updated = updated.replace("print(", "logger.info(")
        if updated != code:
            updated = _ensure_logging_setup(updated)
            changes.append("replace_print_with_logger")
    return updated, changes
