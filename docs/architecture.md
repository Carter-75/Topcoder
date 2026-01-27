# Architecture Overview

## System Components

### 1. Backend Service (Python)
- Exposes REST API endpoints (e.g., /analyze, /health).
- Receives PR/commit diffs and metadata from GitHub App/Action.
- Runs hybrid analysis: static rules (regex, AST) + AI-style review (stub/sim).
- Applies security, coding standards, license/IP, Copilot-awareness, and policy logic.
- Returns structured results (violations, explanations, suggestions, policy level).
- Writes audit logs (file or lightweight DB).
- Loads config/rule packs (YAML/JSON, sector-specific, repo overrides).

### 2. GitHub App/Action (TypeScript)
- Listens to PR and commit events.
- Collects changed files, diffs, and metadata (author, branch, etc.).
- Calls backend /analyze endpoint with payload.
- Posts inline and summary comments, and sets GitHub Checks/statuses based on backend results.
- Loads config (YAML/JSON) and supports repo-level overrides.

### 3. Configuration & Rule Packs
- Central config file (e.g., .guardrails/config.yml) for org/repo policies.
- Rule packs for sectors (finance, healthcare, public sector).
- Policy modes: advisory, warning, blocking (with override path).

### 4. Audit Logging & Traceability
- Backend logs all violations, decisions, and enforcement actions.
- Exportable audit log (JSON/CSV or simple API).

### 5. Optional: Dashboard/Reporting
- (Stretch) Simple dashboard for org-level insights, rule hits, and trends.

## Data Flow
1. Developer opens/updates PR or pushes commit in GitHub.
2. GitHub App/Action triggers on event, collects diffs and metadata.
3. App/Action sends payload to backend /analyze endpoint.
4. Backend analyzes code, applies rules, returns results.
5. App/Action posts comments, sets status/checks in PR/commit.
6. Backend logs all analysis and enforcement actions for audit.

## Extensibility
- Pluggable rule engine (add new rules, languages, compliance packs).
- Configurable policies and sector rule packs.
- Modular backend and GitHub integration.

## Security & Scale
- Secure token/secret handling (env vars, GitHub Secrets).
- No code retention beyond analysis.
- Designed for large PRs and async/offline processing if needed.

---

See TODO.md for incremental implementation plan.
