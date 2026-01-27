#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/backend"
python -m pip install -r requirements.txt
exec python -m uvicorn main:app --host 0.0.0.0 --port "${PORT:-8000}"