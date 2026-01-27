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


def load_user_settings(user_key: str | None) -> Dict[str, Any]:
    settings = load_settings()
    if not user_key:
        return settings
    users = settings.get("users")
    if isinstance(users, dict):
        value = users.get(user_key)
        if isinstance(value, dict):
            return value
    return {}


def save_user_settings(user_key: str | None, user_settings: Dict[str, Any]) -> bool:
    settings = load_settings()
    if not user_key:
        return save_settings({**settings, **user_settings})
    users = settings.get("users")
    if not isinstance(users, dict):
        users = {}
    users[user_key] = user_settings
    settings["users"] = users
    return save_settings(settings)


def load_api_key(user_key: str | None = None) -> Optional[str]:
    settings = load_user_settings(user_key)
    return settings.get("openai_api_key")


def save_api_key(api_key: str, user_key: str | None = None) -> bool:
    settings = load_user_settings(user_key)
    settings["openai_api_key"] = api_key
    return save_user_settings(user_key, settings)


def load_require_ai_review_default(user_key: str | None = None) -> Optional[bool]:
    settings = load_user_settings(user_key)
    value = settings.get("require_ai_review_default")
    if isinstance(value, bool):
        return value
    return None


def save_require_ai_review_default(value: bool, user_key: str | None = None) -> bool:
    settings = load_user_settings(user_key)
    settings["require_ai_review_default"] = value
    return save_user_settings(user_key, settings)


def load_autofix_default(user_key: str | None = None) -> Optional[bool]:
    settings = load_user_settings(user_key)
    value = settings.get("autofix_default")
    if isinstance(value, bool):
        return value
    return None


def save_autofix_default(value: bool, user_key: str | None = None) -> bool:
    settings = load_user_settings(user_key)
    settings["autofix_default"] = value
    return save_user_settings(user_key, settings)
