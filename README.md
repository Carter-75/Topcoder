# Topcoder Guardrails Backend 

## Overview
This project is a secure, modular backend for code analysis, policy enforcement, and audit logging. It uses FastAPI and includes endpoints for code analysis, health checks, and a dashboard for audit logs.

## Features
- REST API for code analysis (`/analyze`)
- Health check endpoint (`/health`)
- Audit dashboard (`/dashboard`)
- Modular rulepacks for different sectors
- Security, coding standards, license/IP, and AI review checks
- Repo license detection (local scans)
- Cross-file duplicate code detection (batch scans)
- AI review with PR/commit context when available

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
This app is **per-user**, not global. Settings are scoped by user token when `SETTINGS_SCOPE=user`.

Local-only (optional):
- Set `OPENAI_API_KEY` only if you are running locally and want AI review without using the settings UI/CLI.
# Guardrails Backend

FastAPI-based service that analyzes code, applies policy/rulepacks, and reports results for PRs, commits, and local scans. It ships with a settings UI, audit logging, and a lightweight CLI for scanning any repository.

## What it does
- Analyzes code via REST endpoints and returns structured findings.
- Enforces security, coding standards, license/IP, sector rules, and AI review policy.
- Stores audit logs and provides summaries.
- Supports rulepacks and repo-level overrides.
- Integrates with a GitHub App for PR and push scans.

## Challenge requirement coverage
- Secure coding guardrails with OWASP/CWE mappings.
- Copilot-aware flagging and stricter handling for AI-generated code.
- Configurable coding standards (YAML/JSON in repo config).
- AI-assisted review with explainable findings.
- License/IP checks with restricted license detection.
- Policy-based enforcement (advisory/warning/blocking) with override label.
- PR/commit scanning via GitHub App with inline comments and summaries.
- Traceability with audit IDs, export, and resolution events.
- Async scan flow for large PRs.
- Pluggable rulepacks per industry (finance, healthcare, public sector, telecom, government).

## How people use it
Website-only:
1) Open `/settings/ui` on your deployment.
2) Save your OpenAI API key.
3) Set AI mode and auto-fix defaults.
4) Use the GitHub App integration or call the API directly.

CLI (most common):
1) `pip install guardrails-cli`
2) Open `/settings/ui` once and save your API key.
3) Copy `guardrails_user_token` from browser local storage if `SETTINGS_SCOPE=user`.
4) `guardrails scan <repo-path> --user <token>`

## Project layout
- backend/ — FastAPI service and rule engine
- github-app/ — GitHub App integration
- src/guardrails_cli/ — Published CLI package
- docs/ — Architecture notes

## Requirements
- Python 3.9+
- Dependencies in backend/requirements.txt

## Local setup
```sh
cd Topcoder/backend
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Run the server
```sh
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

## Configuration (environment variables)
Core settings:
- OPENAI_API_KEY (optional) — used when no per-user key exists
- SETTINGS_SCOPE (default: global) — global | user | ip
- SETTINGS_TOKEN (optional) — protects settings endpoints
- SETTINGS_ENC_KEY (recommended) — encrypts persisted settings
- SETTINGS_STORE_PATH (default: settings.enc) — encrypted settings file
- REQUIRE_AI_REVIEW_DEFAULT (default: false)

Audit logging:
- AUDIT_LOG_ENABLED (default: true)
- AUDIT_LOG_PATH (default: audit_log.jsonl)
- AUDIT_LOG_STORE_OUTPUT (default: true)

Data residency:
- DATA_RESIDENCY (optional)

## GitHub App integration
The GitHub App scans PRs and pushes, posts comments/checks, and reads repo overrides from .guardrails/config.yml|yaml|json.

Environment variables:
- BACKEND_URL (required)
- OVERRIDE_LABEL (optional, default: guardrails-override)
- MAX_FILES (optional, default: 100)
- MAX_FILE_BYTES (optional, default: 200000)
- USE_ASYNC_SCAN (optional, default: false)

## CLI usage
Install:
```sh
pip install guardrails-cli
```

Scan:
```sh
guardrails scan <repo-path> --user <token>
```

Notes:
- Default hosted URL is https://topcoder-production.up.railway.app
- Override with GUARDRAILS_API_URL or --api
- Use --autofix to apply safe local fixes
- Use --no-ai to disable AI review for a run

## CLI settings (no UI required)
```sh
python guardrails.py settings --generate-local-key
python guardrails.py settings --set-api-key <key>
python guardrails.py settings --ai-mode require|allow
python guardrails.py settings --autofix-mode on|off
python guardrails.py settings --verify
```

## API endpoints
- GET /health
- GET /
- GET /dashboard
- GET /settings
- POST /settings/token
- GET /settings/ui
- POST /settings/api-key
- POST /settings/ai-mode
- POST /settings/autofix-mode
- POST /analyze
- POST /analyze-batch
- POST /scan/async
- GET /scan/status/{job_id}
- GET /report/summary
- GET /report/trends
- GET /rulepacks
- POST /rulepacks
- GET /audit/export
- POST /audit/resolve
- GET /docs

## Testing
```sh
pytest
```
- `GET /report/summary` — Audit summary counts
