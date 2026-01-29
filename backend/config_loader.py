import os
import yaml
import json
from typing import Any, Dict

# Loads config from .guardrails/config.yml or config.json in repo root

def _load_config_file(path: str) -> Dict[str, Any]:
    if not path or not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        if path.endswith((".yml", ".yaml")):
            data = yaml.safe_load(f)
            return data if isinstance(data, dict) else {}
        data = json.load(f)
        return data if isinstance(data, dict) else {}

def _merge_dicts(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _merge_dicts(merged[key], value)
        else:
            merged[key] = value
    return merged

def load_config(repo_path: str = ".") -> Dict[str, Any]:
    org_path = os.environ.get("GUARDRAILS_ORG_CONFIG") or os.environ.get("GUARDRAILS_ORG_CONFIG_PATH")
    org_config = _load_config_file(org_path) if org_path else {}
    config_paths = [
        os.path.join(repo_path, ".guardrails", "config.yml"),
        os.path.join(repo_path, ".guardrails", "config.yaml"),
        os.path.join(repo_path, ".guardrails", "config.json"),
    ]
    for path in config_paths:
        if os.path.exists(path):
            repo_config = _load_config_file(path)
            return _merge_dicts(org_config, repo_config)
    return org_config  # Default: org config or empty
