#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/app"
KEY_FILE="$APP_DIR/.settings_key"

if [ -z "${SETTINGS_ENC_KEY:-}" ]; then
  if [ -f "$KEY_FILE" ]; then
    SETTINGS_ENC_KEY="$(cat "$KEY_FILE")"
    export SETTINGS_ENC_KEY
  else
    SETTINGS_ENC_KEY="$(python - <<'PY'
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode("utf-8"))
PY
)"
    export SETTINGS_ENC_KEY
    printf "%s" "$SETTINGS_ENC_KEY" > "$KEY_FILE"
  fi
fi

if [ "${PUBLISH_CLI:-}" = "true" ] && [ -f "/app/publish_cli.py" ] && [ -f "/app/pyproject.toml" ]; then
  python /app/publish_cli.py
fi

exec python -m uvicorn main:app --host 0.0.0.0 --port "${PORT:-8000}"
