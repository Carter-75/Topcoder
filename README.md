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
pytest
```
- GET /report/summary — Audit summary counts
