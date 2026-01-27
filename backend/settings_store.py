import json
import os
from typing import Optional, Dict, Any

from cryptography.fernet import Fernet, InvalidToken

_MEMORY_SETTINGS: Dict[str, Any] = {}


def _get_fernet() -> Optional[Fernet]:
    key = os.environ.get("SETTINGS_ENC_KEY")
    if key:
        return Fernet(key.encode("utf-8"))
    key_path = os.environ.get("SETTINGS_KEY_PATH")
    if not key_path:
        return None
    try:
        if os.path.exists(key_path):
            with open(key_path, "r", encoding="utf-8") as f:
                file_key = f.read().strip()
            if file_key:
                return Fernet(file_key.encode("utf-8"))
        os.makedirs(os.path.dirname(key_path), exist_ok=True)
        generated = Fernet.generate_key().decode("utf-8")
        with open(key_path, "w", encoding="utf-8") as f:
            f.write(generated)
        return Fernet(generated.encode("utf-8"))
    except OSError:
        return None


def load_settings() -> Dict[str, Any]:
    store_path = os.environ.get("SETTINGS_STORE_PATH", "settings.enc")
    fernet = _get_fernet()
    if not fernet:
        return dict(_MEMORY_SETTINGS)
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
        _MEMORY_SETTINGS.clear()
        _MEMORY_SETTINGS.update(settings)
        return True
    try:
        parent = os.path.dirname(store_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        payload = json.dumps(settings).encode("utf-8")
        encrypted = fernet.encrypt(payload)
        with open(store_path, "wb") as f:
            f.write(encrypted)
        return True
    except OSError:
        return False


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


def load_ai_model(user_key: str | None = None) -> Optional[str]:
    settings = load_user_settings(user_key)
    value = settings.get("ai_model")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def save_ai_model(value: str, user_key: str | None = None) -> bool:
    settings = load_user_settings(user_key)
    settings["ai_model"] = value.strip()
    return save_user_settings(user_key, settings)


def load_ai_review_max_chars(user_key: str | None = None) -> Optional[int]:
    settings = load_user_settings(user_key)
    value = settings.get("ai_review_max_chars")
    if isinstance(value, int) and value > 0:
        return value
    return None


def save_ai_review_max_chars(value: int, user_key: str | None = None) -> bool:
    settings = load_user_settings(user_key)
    settings["ai_review_max_chars"] = value
    return save_user_settings(user_key, settings)


def load_override_allowed_default(user_key: str | None = None) -> Optional[bool]:
    settings = load_user_settings(user_key)
    value = settings.get("override_allowed_default")
    if isinstance(value, bool):
        return value
    return None


def save_override_allowed_default(value: bool, user_key: str | None = None) -> bool:
    settings = load_user_settings(user_key)
    settings["override_allowed_default"] = value
    return save_user_settings(user_key, settings)
