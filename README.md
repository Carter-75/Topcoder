# Topcoder Guardrails

Enterprise-grade guardrails for GitHub Copilot workflows: a FastAPI backend, GitHub App integration, and CLI that enforce security, policy, and licensing standards with explainable AI + static analysis.

## Deployed URL
https://topcoder-production.up.railway.app

## What this delivers
- Hybrid analysis engine: rule-based static checks + AI review with explanations.
- Copilot awareness: stricter handling for AI-generated code paths.
- Policy-based enforcement: advisory, warning, blocking, with override label support.
- License/IP compliance: SPDX/license detection and duplication heuristics.
- GitHub PR + commit integration: check runs, inline comments, and summaries.
- Auditability: audit log export, resolution events, and dashboards.
- Extensible rulepacks: sector-specific YAML rulepacks and repo overrides.

## Challenge requirement coverage
- Secure coding guardrails with OWASP/CWE mappings.
- Copilot-aware flagging and stricter enforcement for AI-generated code.
- Configurable coding standards via YAML/JSON repo config.
- AI-assisted review with explanations and suggested fixes.
- License/IP checks (restricted licenses + duplication heuristics).
- Policy-based enforcement modes with override label.
- PR/commit scanning via GitHub App (check runs + inline comments).
- Traceability with audit IDs, export, and resolution events.
- Async scan flow for large PRs.
- Pluggable rulepacks per industry (finance, healthcare, public sector, telecom, government).

## Architecture
- backend/ — FastAPI service, rule engine, AI review, audit logging
- github-app/ — GitHub App integration (PR + commit scanning)
- src/guardrails_cli/ — CLI package for local repo scans
- docs/ — Architecture notes

## Security & data handling
- No source code retention beyond analysis. Audit logs store sanitized output only.
- Settings storage is encrypted when a key is configured.
- Data residency can be enforced via repo config + environment variable.

## Requirements
- Python 3.9+
- See backend/requirements.txt for dependencies

## Local setup (backend)
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

## Configuration (backend)
Core settings:
- OPENAI_API_KEY (optional) — used when no per-user key exists
- GUARDRAILS_API_TOKEN (optional) — bearer token required for analysis/scan endpoints when set
- GUARDRAILS_ADMIN_TOKEN (optional) — bearer token required for admin endpoints (audit export, rulepack upload)
- SETTINGS_SCOPE (default: global) — global | user | ip
- SETTINGS_TOKEN (optional) — protects settings endpoints
- SETTINGS_ENC_KEY (recommended) — encrypts persisted settings
- SETTINGS_KEY_PATH (optional) — path to a persistent encryption key file (auto-created when missing)
- SETTINGS_STORE_PATH (default: settings.enc) — encrypted settings file
- REQUIRE_AI_REVIEW_DEFAULT (default: false)
- SECURE_COOKIES (default: false) — set true behind HTTPS to secure cookies

Security & access:
- CORS_ALLOW_ORIGINS (optional) — comma-separated allowlist for CORS
- RATE_LIMIT_ENABLED (default: true)
- RATE_LIMIT_RPS (default: 10)
- RATE_LIMIT_BURST (default: 20)
- RATE_LIMIT_WINDOW (default: 10 seconds)

Audit logging:
- AUDIT_LOG_ENABLED (default: true)
- AUDIT_LOG_PATH (default: audit_log.jsonl)
- AUDIT_LOG_STORE_OUTPUT (default: true)
  - Stored output is sanitized to avoid retaining code snippets or patches
- AUDIT_LOG_MAX_BYTES (default: 5000000)
- AUDIT_LOG_MAX_FILES (default: 5)
- AUDIT_LOG_HMAC_KEY (optional) — enables tamper-evident hash chaining

Data residency:
- DATA_RESIDENCY (optional)

## GitHub App integration
The GitHub App scans PRs and pushes, posts comments/checks, and reads repo overrides from .guardrails/config.yml|yaml|json.

Environment variables:
- BACKEND_URL (required)
- BACKEND_TOKEN (optional) — bearer token for secured backend endpoints
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
# Or, from inside your repo:
guardrails scan --user <token>
```

If the backend enforces API tokens:
```sh
guardrails scan <repo-path> --user <token> --api-token <backend-token>
```

Fix modes:
- Full fix (AI rewrite + safe fixes): `guardrails scan --full-fix --user <token>`
- Safe fix only: `guardrails scan --safe-fix --user <token>`
- No fixes: `guardrails scan --no-fix --user <token>`

Notes:
- Hosted URL: https://topcoder-production.up.railway.app
- Override with GUARDRAILS_API_URL or --api
- Use --autofix to apply safe local fixes
- Use --no-ai to disable AI review for a run

## CLI settings (no UI required)
```sh
python guardrails.py settings --generate-local-key
python guardrails.py settings --set-api-key <key>
python guardrails.py settings --ai-mode require|allow
python guardrails.py settings --fix-mode full|safe|none
guardrails settings --issue-user-token
python guardrails.py settings --verify
```

## API endpoints
- GET /health
- GET /
- GET /dashboard
- GET /settings
- POST /settings/token
- GET /settings/token/current
- POST /settings/token/assign
- GET /settings/ui
- POST /settings/api-key
- POST /settings/ai-mode
- POST /settings/autofix-mode
- POST /settings/override-allowed
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

## Deployment notes
Railway containers use an ephemeral filesystem on redeploys. If you rely on the settings UI/CLI to store the API key, it will be lost unless you persist the settings file.

Fix: attach a volume at /data, then set:
- SETTINGS_KEY_PATH=/data/settings.key
- SETTINGS_STORE_PATH=/data/settings.enc

If you do not want to persist a file, set OPENAI_API_KEY as an environment variable in Railway so the key is always present after redeploys.

## Testing
```sh
pytest
```
- GET /report/summary — Audit summary counts
