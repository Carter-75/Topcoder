import os
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
        for match in yaml.safe_load(f"- {rule['pattern']}") if isinstance(rule['pattern'], str) else rule['pattern']:
            if match and match in code:
                issues.append({
                    "type": rule["type"],
                    "message": rule["message"],
                    "severity": rule["severity"],
                    "rule_id": rule["id"],
                    "pattern": match
                })
    return issues
