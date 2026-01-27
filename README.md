# Topcoder Guardrails Backend 

## Overview
This project is a secure, modular backend for code analysis, policy enforcement, and audit logging. It uses FastAPI and includes endpoints for code analysis, health checks, and a dashboard for audit logs.

## Features
- REST API for code analysis (`/analyze`)
- Health check endpoint (`/health`)
- Audit dashboard (`/dashboard`)
- Modular rulepacks for different sectors
- Security, coding standards, license/IP, and AI review checks

## Requirements
- Python 3.9+
- See `backend/requirements.txt` for all dependencies

## Installation
1. Clone the repository.
2. Navigate to the backend directory:
   ```sh
   cd Topcoder/backend
   ```
3. (Recommended) Create a virtual environment:
   ```sh
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```
4. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```

## Configuration
- Copy `.env.example` to `.env` and set your API key:
  ```sh
  cp .env.example .env
  # Edit .env and set API_KEY=your-key-here
  ```
- The API key (`OPENAI_API_KEY`) is required for AI review; by default, scans are blocked if it is missing.
- Optional: set `REQUIRE_AI_REVIEW=false` to allow stubbed AI suggestions in local/dev.

Audit logging:
- `AUDIT_LOG_ENABLED` (default: true)
- `AUDIT_LOG_PATH` (default: audit_log.jsonl)
- `AUDIT_LOG_STORE_OUTPUT` (default: true) — store full results in audit log

Data residency:
- `DATA_RESIDENCY` (optional) — reject requests when repo config requires a different residency

Persistent settings (encrypted):
- `SETTINGS_ENC_KEY` (required for persistence) — a Fernet key used to encrypt stored settings
- `SETTINGS_STORE_PATH` (optional) — file path for encrypted storage (default: `settings.enc`)
- `SETTINGS_SCOPE` (optional) — `user` (recommended) or `global` (shared)
- `REQUIRE_AI_REVIEW_DEFAULT` (optional) — default AI mode when user settings are not set (default: false)

## Running the Server
From the `Topcoder/backend` directory:
```sh
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

## GitHub App Integration
The GitHub app scans PRs and posts a Guardrails report plus a check run, with inline PR review comments for findings in the diff.
It also scans push events and reports results on the latest commit.

Environment variables:
- `BACKEND_URL` (required): Guardrails API base URL
- `OVERRIDE_LABEL` (optional): label name that allows blocking overrides (default: `guardrails-override`)
- `MAX_FILES` (optional): maximum files per PR to scan (default: 100)
- `MAX_FILE_BYTES` (optional): max file size in bytes (default: 200000)
- `USE_ASYNC_SCAN` (optional): enable async scan flow (default: false)

The app reads `.guardrails/config.yml|yaml|json` from the repo when available to apply `sector` and `policy` overrides.

## Hosted usage (no repo cloning)
If you deploy the backend as a hosted service, users can supply their own OpenAI key without cloning or installing anything:

- Set a server-wide key once (main app settings):
   - `POST /settings/api-key` with JSON `{ "api_key": "..." }`
   - Optional protection: set `SETTINGS_TOKEN` and call with `Authorization: Bearer <token>`
- Or send per-request keys from any client:
   - Header: `X-OpenAI-API-Key: <key>` (or `X-OpenAI-Key`)
   - Body: `ai_api_key` also supported for API clients

This enables scanning any connected GitHub repo via the app, or calling the API directly from external tools.

Settings UI:
- Website (main app): https://topcoder-production.up.railway.app
- Open `/settings/ui` on the website to store the key in the main app.
- Auto-fix default and AI mode can be set in the UI and used by the CLI.
- When `SETTINGS_SCOPE=user`, the UI generates a per-user token and stores it locally.

## CLI usage (scan any local repo)
Use the lightweight CLI wrapper to scan any repo from its root:
- Run the CLI in this repo via `python guardrails.py scan <repo-path>`
- Provide the hosted API URL and API key via flags or environment
- Default hosted URL is `https://topcoder-production.up.railway.app`
- Set `GUARDRAILS_API_URL` to override the default and avoid passing `--api` every time
- Optional `--autofix` applies safe local fixes and stores backups in `.guardrails_backup`
- If no API key is detected, the CLI prompts for a key or lets you run in non-AI mode
- Use `--no-ai` to explicitly disable AI review for that run
- If `SETTINGS_ENC_KEY` is set locally, the CLI saves the entered key to encrypted storage
- For `SETTINGS_SCOPE=user`, pass `--user <token>` or set `GUARDRAILS_USER` to match the UI token

One-time install (cross-platform, Python only):
- Run `python install-cli.py` from this repo to add `guardrails` to your PATH
- After that, run `guardrails scan <repo-path>` from any folder

## CLI settings (no website required)
You can manage the same settings from the CLI:
- Generate a server key: `python guardrails.py settings --generate-key`
- Generate a local key: `python guardrails.py settings --generate-local-key`
- Set API key: `python guardrails.py settings --set-api-key <key>`
- Set AI mode: `python guardrails.py settings --ai-mode require|allow`
- Set auto-fix default: `python guardrails.py settings --autofix-mode on|off`
- Verify settings sync: `python guardrails.py settings --verify`

Optional flags:
- `--api` to target a different backend URL
- `--token` if SETTINGS_TOKEN is enabled on the server
- `--user` to set `X-Guardrails-User` for scoped settings (useful behind shared IPs)

## GitHub App endpoint
Use the same deployment for the webhook URL:
- Webhook URL: https://topcoder-production.up.railway.app

## Scan an entire repository
From the `Topcoder/backend` directory, run:
```sh
python scan_repo.py .. --api https://topcoder-production.up.railway.app --sector finance --output scan_results.json
```

Notes:
- The scan writes a JSON report to `scan_results.json`.
- Adjust `--api` for local (`http://127.0.0.1:8000`) or hosted usage.
- Use `--max-files` to limit large repos.

## API Endpoints
- `GET /health` — Health check
- `POST /analyze` — Analyze code (JSON: `{ "code": "..." }`)
- `POST /analyze-batch` — Analyze multiple files
- `POST /scan/async` — Queue an asynchronous scan
- `GET /scan/status/{job_id}` — Check async scan status
- `GET /dashboard` — View audit dashboard
- `GET /audit/export` — Export audit log
- `GET /report/summary` — Audit summary counts
- `GET /rulepacks` — List rulepacks
- `POST /rulepacks` — Upload a rulepack
- `GET /docs` — Interactive API docs (Swagger UI)

## Testing
Run all backend tests:
```sh
pytest
```

## Notes
- All dependencies are listed in `requirements.txt`.
- The dashboard reads from `audit_log.jsonl`.
- For production, set environment variables securely and use HTTPS.

## Changelog
- 2026-01-26: Full test and endpoint verification, requirements and documentation updated.
