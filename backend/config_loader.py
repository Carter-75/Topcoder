import os
import yaml
import json
from typing import Any, Dict

# Loads config from .guardrails/config.yml or config.json in repo root

def load_config(repo_path: str = ".") -> Dict[str, Any]:
    config_paths = [
        os.path.join(repo_path, ".guardrails", "config.yml"),
        os.path.join(repo_path, ".guardrails", "config.yaml"),
        os.path.join(repo_path, ".guardrails", "config.json"),
    ]
    for path in config_paths:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                if path.endswith(('.yml', '.yaml')):
                    return yaml.safe_load(f)
                else:
                    return json.load(f)
    return {}  # Default: empty config
