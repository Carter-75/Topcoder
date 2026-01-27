from typing import List, Dict, Any
import config_loader

# Example policy config (could be loaded from YAML/JSON in future)
DEFAULT_POLICY = {
    "hardcoded_secret": "blocking",
    "sql_injection_risk": "blocking",
    "insecure_deserialization": "warning",
    "unsafe_execution": "warning",
    "path_traversal_risk": "warning",
    "insecure_crypto": "warning",
    "copilot_generated_code": "warning",
    "ai_review_missing_key": "blocking",
    "naming_convention": "advisory",
    "logging_practice": "advisory",
    "error_handling": "warning",
    "license_detected": "warning",
    "restricted_license": "blocking",
    "ip_duplication": "warning",
    "ip_near_duplicate": "warning",
}

def get_policy(repo_path: str = ".", policy_override: dict | None = None) -> dict:
    if policy_override:
        return policy_override
    config = config_loader.load_config(repo_path)
    return config.get("policy", DEFAULT_POLICY)

def evaluate_policy(
    issues: List[Dict[str, Any]],
    coding_issues: List[Dict[str, Any]],
    license_ip_issues: List[Dict[str, Any]],
    repo_path: str = ".",
    policy_override: dict | None = None,
) -> str:
    all_issues = issues + coding_issues + license_ip_issues
    policy_cfg = get_policy(repo_path, policy_override)
    config = config_loader.load_config(repo_path)
    copilot_strict = config.get("copilot_strict", True)
    mode = "advisory"
    for issue in all_issues:
        rule = issue.get("type")
        level = policy_cfg.get(rule, "advisory")
        if copilot_strict and issue.get("copilot_strict"):
            if level == "advisory":
                level = "warning"
            elif level == "warning":
                level = "blocking"
        issue["policy_level"] = level
        if level == "blocking":
            mode = "blocking"
        elif level == "warning" and mode != "blocking":
            mode = "warning"
    return mode

def is_override_allowed() -> bool:
    return True
