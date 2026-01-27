import json
import os
from typing import Optional, Dict, Any

from cryptography.fernet import Fernet, InvalidToken


def _get_fernet() -> Optional[Fernet]:
    key = os.environ.get("SETTINGS_ENC_KEY")
    if not key:
        return None
    return Fernet(key.encode("utf-8"))


def load_settings() -> Dict[str, Any]:
    store_path = os.environ.get("SETTINGS_STORE_PATH", "settings.enc")
    fernet = _get_fernet()
    if not fernet:
        return {}
    if not os.path.exists(store_path):
        return {}
    try:
        with open(store_path, "rb") as f:
            encrypted = f.read()
        decrypted = fernet.decrypt(encrypted).decode("utf-8")
        try:
            data = json.loads(decrypted)
            if isinstance(data, dict):
                return data
        except Exception:
            return {"openai_api_key": decrypted}
    except (OSError, InvalidToken):
        return {}
    return {}


def save_settings(settings: Dict[str, Any]) -> bool:
    store_path = os.environ.get("SETTINGS_STORE_PATH", "settings.enc")
    fernet = _get_fernet()
    if not fernet:
        return False
    payload = json.dumps(settings).encode("utf-8")
    encrypted = fernet.encrypt(payload)
    with open(store_path, "wb") as f:
        f.write(encrypted)
    return True


def load_api_key() -> Optional[str]:
    settings = load_settings()
    return settings.get("openai_api_key")


def save_api_key(api_key: str) -> bool:
    settings = load_settings()
    settings["openai_api_key"] = api_key
    return save_settings(settings)


def load_require_ai_review_default() -> Optional[bool]:
    settings = load_settings()
    value = settings.get("require_ai_review_default")
    if isinstance(value, bool):
        return value
    return None


def save_require_ai_review_default(value: bool) -> bool:
    settings = load_settings()
    settings["require_ai_review_default"] = value
    return save_settings(settings)


def load_autofix_default() -> Optional[bool]:
    settings = load_settings()
    value = settings.get("autofix_default")
    if isinstance(value, bool):
        return value
    return None


def save_autofix_default(value: bool) -> bool:
    settings = load_settings()
    settings["autofix_default"] = value
    return save_settings(settings)
