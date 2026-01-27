# AI Powered Enterprise Guardrails for GitHub Copilot

## Overview
This project is a prototype for an enterprise-grade guardrails solution that integrates with GitHub and GitHub Copilot workflows. It enforces security, compliance, and coding standards on both AI-generated and human-written code before merge.

## Architecture
- **Backend (Python/FastAPI):** Receives PR/commit code, runs static and AI-style analysis, applies sector rule packs, evaluates policy, and logs all actions.
- **GitHub App/Action (TypeScript/Probot):** Listens to PR/commit events, sends code and metadata to backend, posts comments and statuses based on results.
- **Config:** YAML/JSON config in `.guardrails/` for org/repo-level policy and rule customization.
- **Audit Log:** All analysis and enforcement actions are logged for compliance.

## Features
- Secure coding guardrails (secrets, SQLi, deserialization, unsafe exec)
- Copilot-generated code awareness and stricter rules
- Coding standards enforcement (naming, logging, error handling)
- License/IP compliance heuristics
- Policy-based enforcement (advisory, warning, blocking, override)
- Sector rule packs (finance, healthcare, public sector)
- PR/commit integration (comments, status checks)
- Audit logging and exportable logs
- Configurable via YAML/JSON

## Setup & Deployment
### Backend
1. `cd backend`
2. `pip install -r requirements.txt`
3. `uvicorn main:app --reload`

### GitHub App/Action
1. `cd github-app`
2. `npm install`
3. Configure as a Probot app or GitHub Action (see `.github/workflows/guardrails.yml`)

### Configuration
- Place `.guardrails/config.yml` in repo root for custom policy/rules.
- Example sector rule packs in `backend/rulepacks/`.

### Testing
- Backend: `pytest backend/tests/`
- GitHub App: `npm test` in `github-app/`


## Usage

### 1. Start the Backend API
```
cd backend
pip install -r requirements.txt
uvicorn main:app --reload
```

### 2. Run the GitHub App/Action
```
cd github-app
npm install
npm start
```
Or configure as a GitHub Action using `.github/workflows/guardrails.yml`.

### 3. Configure Policies and Rules
- Place a `.guardrails/config.yml` in your repo root to customize rules and policies (see example in `.guardrails/config.yml`).
- Example sector rule packs are in `backend/rulepacks/`.

### 4. Analyze PRs and Commits
- On PR or commit, the GitHub App sends code to the backend for analysis.
- Results are posted as PR comments and status checks.
- Violations, policy level, and suggestions are visible to developers in the PR UI.

### 5. Audit Log and Dashboard/Reporting
- All analysis and enforcement actions are logged in `audit_log.jsonl` (in the backend directory by default).
- For reporting, export this log and analyze with external tools (Excel, Python, etc.).
- See `docs/dashboard.md` for dashboard/reporting stub and future extensibility notes.

---

## Extensibility
- Add new rules or sector packs in `backend/rulepacks/`.
- Extend backend endpoints or GitHub App event handlers as needed.

## Security & Compliance
- No code is retained beyond analysis.
- All secrets/tokens handled via environment variables or GitHub Secrets.
- Audit log is exportable for compliance review.

## Limitations
- Some features (async processing, dashboard) are stubbed for MVP.
- AI review is simulated.

## License
MIT (for prototype)
