from typing import Dict

GUIDELINE_LINKS: Dict[str, str] = {
    "hardcoded_secret": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    "sql_injection_risk": "https://owasp.org/Top10/A03_2021-Injection/",
    "insecure_deserialization": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
    "unsafe_execution": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    "copilot_generated_code": "https://github.com/features/copilot",
    "naming_convention": "https://peps.python.org/pep-0008/",
    "logging_practice": "https://docs.python.org/3/library/logging.html",
    "error_handling": "https://docs.python.org/3/tutorial/errors.html",
    "license_detected": "https://choosealicense.com/",
    "ip_duplication": "https://opensource.guide/legal/",
}


def get_guideline_link(rule_type: str) -> str | None:
    return GUIDELINE_LINKS.get(rule_type)
