# Topcoder Guardrails

Enterprise-grade guardrails for GitHub Copilot workflows: a FastAPI backend, GitHub App integration, and CLI that enforce security, policy, and licensing standards with explainable AI + static analysis.

## Deployed URL
https://topcoder-production.up.railway.app

## Quick start (hosted)
1. Open the deployed URL.
2. Go to /settings/ui.
3. Paste your OpenAI API key and save.
4. Create or update a PR in a repo where the GitHub App is installed. Guardrails posts comments/checks automatically.

That is all most users need.

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
- AI-assisted PR review with explanations and suggested fixes (security, performance, maintainability).
- License/IP checks (restricted licenses + duplication heuristics).
- Policy-based enforcement modes (advisory, warning, blocking) with override support.
- PR and commit scanning via GitHub App (check runs + inline comments + summaries).
- Traceability with audit IDs, export, and resolution events.
- Async scan flow for large PRs.
- Pluggable rulepacks per industry (finance, healthcare, public sector, telecom, government) and custom uploads.

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
### CLI
- Python 3.9+

## Configuration (backend)
Core settings:
- OPENAI_API_KEY (optional) — used when no per-user key exists
- GUARDRAILS_API_TOKEN (optional) — bearer token required for analysis/scan endpoints when set
- GUARDRAILS_ADMIN_TOKEN (optional) — bearer token required for admin endpoints (audit export, rulepack upload)
- SETTINGS_SCOPE (default: global) — global | user | ip
- SETTINGS_TOKEN (optional) — protects settings endpoints
- REQUIRE_AI_REVIEW_DEFAULT (default: false)

Additional backend settings:
- OPENAI_MODEL (default: gpt-4o-mini)
- AI_REVIEW_MAX_CHARS (default: 12000)
- REQUIRE_AI_REVIEW (default: true)
- CORS_ALLOW_ORIGINS (optional, comma-separated)
- DATA_RESIDENCY (optional, must match repo config if set)
- SECURE_COOKIES (default: false)
- RATE_LIMIT_ENABLED (default: true)
- RATE_LIMIT_RPS (default: 10)
- RATE_LIMIT_BURST (default: 20)
- RATE_LIMIT_WINDOW (default: 10)
- SETTINGS_ENC_KEY (optional, used to encrypt settings)
- SETTINGS_KEY_PATH (optional, generates key if not set)
- SETTINGS_STORE_PATH (default: settings.enc)
- AUDIT_LOG_ENABLED (default: true)
- AUDIT_LOG_STORE_OUTPUT (default: true)
- AUDIT_LOG_PATH (default: /tmp/audit_log.jsonl)
- AUDIT_LOG_MAX_BYTES (default: 5000000)
- AUDIT_LOG_MAX_FILES (default: 5)
- AUDIT_LOG_HMAC_KEY (optional)
- GUARDRAILS_ORG_CONFIG (optional, path to org-level YAML/JSON config)
- SEMGREP_ENABLED (optional, set to true to enable Semgrep static analysis)
- SEMGREP_TIMEOUT (optional, default: 20)

## GitHub App integration
The GitHub App scans PRs and pushes, posts comments/checks, and reads repo overrides from .guardrails/config.yml|yaml|json.

Environment variables:
- BACKEND_URL (required)
- BACKEND_TOKEN (optional) — bearer token for secured backend endpoints
- OVERRIDE_LABEL (optional, default: guardrails-override)
- MAX_FILES (optional, default: 100)
- MAX_FILE_BYTES (optional, default: 200000)
- USE_ASYNC_SCAN (optional, default: false)
- LOG_LEVEL (optional, default: info)
- AI_GENERATED (optional, set to true to force AI-generated mode)

GitHub App hosting environment (Probot runtime):
- APP_ID (required for webhook-hosted app)
- PRIVATE_KEY (required for webhook-hosted app)
- WEBHOOK_SECRET (required for webhook-hosted app)

GitHub Action environment (recommended for most users):
- GITHUB_TOKEN (required, provided by GitHub Actions)

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

Before scanning, save your OpenAI API key in the hosted settings UI (/settings/ui). The CLI uses the hosted backend by default.

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

## What users must do
- Provide their own OpenAI API key via /settings/ui (hosted).
- Install the CLI only if they want local scans.

## Self-hosting
### Backend API + Settings UI (Railway or Render)
The backend serves the API and the settings UI at /settings/ui. It is the "main website" that stores configuration and audit logs.

1. Deploy the Dockerfile in the repository root (recommended for Railway/Render).
2. Ensure a persistent volume is mounted for settings.enc and audit logs (see railway.json).
3. Set environment variables listed in the backend configuration section above.
4. Expose PORT (defaults to 8000).

### GitHub integration options
You can integrate via GitHub Actions or by hosting a GitHub App webhook server.

Option A: GitHub Actions (no webhook)
1. Copy the workflow in .github/workflows/guardrails.yml into the target repository.
2. Set BACKEND_URL to your hosted backend.
3. If you protect endpoints with GUARDRAILS_API_TOKEN, set BACKEND_TOKEN in the workflow env.
4. No webhook configuration is required.

Recommended non-heuristic AI detection (best option):
1. Add an explicit PR label (e.g., ai-generated or copilot-generated).
2. Configure the label list in .guardrails/config.yml using ai_generated_labels.
3. The GitHub integration will treat labeled PRs as AI-generated without relying on commit message heuristics.

Option B: GitHub App (webhook hosted)
1. Create a GitHub App in your organization settings.
2. Set the webhook URL to https://your-app-host/api/github/webhooks and create a WEBHOOK_SECRET.
3. Permissions: Checks (write), Pull Requests (write), Issues (write), Contents (read).
4. Subscribe to events: pull_request, push.
5. Deploy github-app/ as a Probot app using npm run build and npm run start.
6. Set APP_ID, PRIVATE_KEY, WEBHOOK_SECRET, BACKEND_URL, and BACKEND_TOKEN in the app host.

## Non-heuristic AI detection (recommended)
Preferred approach: explicit labels + repo config.

1. Add a PR label in GitHub (e.g., ai-generated).
2. Add this to your repo config file:

```yaml
ai_generated_labels:
	- ai-generated
	- copilot-generated
```

Optional overrides:
- Force AI mode for all scans by adding ai_generated: true in the repo config.
- Force AI mode in CI by setting AI_GENERATED=true in the workflow env.

## Org-level configuration (optional)
Set GUARDRAILS_ORG_CONFIG to point to a YAML/JSON file. Repo-level .guardrails/config.yml overrides org settings.

Example org config:
```yaml
policy:
	hardcoded_secret: blocking
	sql_injection_risk: blocking
coding_standards_builtin:
	default:
		naming: true
		logging: true
		error_handling: true
```

## Optional Semgrep integration
If Semgrep is installed on the backend host, set SEMGREP_ENABLED=true to run Semgrep with the auto ruleset.

## Local development and testing
Backend local run:
1. cd backend
2. pip install -r requirements.txt
3. uvicorn main:app --reload --host 0.0.0.0 --port 8000

GitHub App local run (webhook mode):
1. cd github-app
2. npm install
3. npm run build
4. APP_ID=... PRIVATE_KEY=... WEBHOOK_SECRET=... BACKEND_URL=http://localhost:8000 npm run start

## CLI settings (optional)
```sh
guardrails settings --issue-user-token
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

## Testing
```sh
pytest backend/tests
```
- GET /report/summary — Audit summary counts
