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
- The API key is required for some AI review features.

Audit logging:
- `AUDIT_LOG_ENABLED` (default: true)
- `AUDIT_LOG_PATH` (default: audit_log.jsonl)
- `AUDIT_LOG_STORE_OUTPUT` (default: true) — store full results in audit log

Data residency:
- `DATA_RESIDENCY` (optional) — reject requests when repo config requires a different residency

## Running the Server
From the `Topcoder/backend` directory:
```sh
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

## GitHub App Integration
The GitHub app scans PRs and posts a Guardrails report plus a check run.
It also scans push events and reports results on the latest commit.

Environment variables:
- `BACKEND_URL` (required): Guardrails API base URL
- `OVERRIDE_LABEL` (optional): label name that allows blocking overrides (default: `guardrails-override`)
- `MAX_FILES` (optional): maximum files per PR to scan (default: 100)
- `MAX_FILE_BYTES` (optional): max file size in bytes (default: 200000)
- `USE_ASYNC_SCAN` (optional): enable async scan flow (default: false)

The app reads `.guardrails/config.yml|yaml|json` from the repo when available to apply `sector` and `policy` overrides.

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
