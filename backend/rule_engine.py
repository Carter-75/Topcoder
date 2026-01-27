import os
import re
import yaml
from typing import List, Dict, Any

RULEPACKS_DIR = os.path.join(os.path.dirname(__file__), "rulepacks")

# Loads rules from a sector rule pack YAML file

def load_rulepack(sector: str) -> List[Dict[str, Any]]:
    path = os.path.join(RULEPACKS_DIR, f"{sector}.yml")
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
        return data.get("rules", [])

# Applies loaded rules to code (simple pattern match)
def apply_rulepack_rules(code: str, rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    issues = []
    for rule in rules:
        pattern_value = rule.get("pattern")
        if not pattern_value:
            continue

        patterns = pattern_value if isinstance(pattern_value, list) else [pattern_value]
        for pattern in patterns:
            if not pattern:
                continue
            if re.search(pattern, code):
                issues.append({
                    "type": rule["type"],
                    "message": rule["message"],
                    "severity": rule["severity"],
                    "rule_id": rule["id"],
                    "pattern": pattern
                })
    return issues
