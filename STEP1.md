# Topcoder Challenge: AI Powered Enterprise Guardrails for GitHub Copilot

## Step 1 – Restate the Challenge

### 1. Challenge Restatement
This project is a prototype for an enterprise-grade guardrails solution that integrates with GitHub and GitHub Copilot workflows. The goal is to enforce security, compliance, and coding standards on both AI-generated and human-written code before merge. The solution must:
- Detect and flag insecure code patterns (e.g., secrets, SQL injection, unsafe execution).
- Enforce organization coding standards (naming, logging, error handling) with configurable rules.
- Provide AI-style code review with explanations and suggestions.
- Detect license/IP compliance issues.
- Support policy-based enforcement (advisory, warning, blocking).
- Integrate with GitHub PRs/commits, surfacing results as comments and status checks.
- Log all violations and decisions for audit/compliance.
- Be secure, scalable, and extensible (pluggable rules, new languages, etc.).
- Differentiate Copilot-generated code and optionally apply stricter rules.
- Deliver as a Python backend and a TypeScript GitHub App/Action.

### 2. Key Functional Requirements
- Secure coding guardrails (detect secrets, SQLi, deserialization, unsafe exec).
- Copilot-generated code awareness and stricter rules.
- Map issues to OWASP/CWE.
- Enforce coding standards (configurable, repo-level overrides).
- AI-assisted review (security, performance, maintainability, explanations, suggestions).
- License/IP compliance checks.
- Policy-based enforcement (advisory, warning, blocking, override path).
- GitHub PR/commit integration (comments, checks, statuses).
- Audit logging and exportable logs.
- Secure handling of tokens/secrets, no unnecessary code retention.
- Handle large PRs, async/offline processing.
- Extensible architecture (pluggable rules, new languages, compliance packs).
- Hybrid engine: static analysis + AI-style reasoning.
- Enterprise rule packs (e.g., finance, healthcare).
- Developer-friendly feedback (inline comments, rationale, doc links).
- Optional dashboard/reporting.

### 3. Key Non-Functional Requirements
- Security: secure token handling, no code retention.
- Scalability: handle large PRs, async processing.
- Extensibility: pluggable rules, new languages, compliance packs.
- Usability: clear, actionable feedback for developers.

### 4. Assumptions & Open Questions
- Copilot-generated code can be heuristically identified (e.g., comment markers, patterns).
- AI-style review can be simulated/stubbed for prototype.
- Policy config will be YAML/JSON, with repo-level overrides.
- Audit log can be file-based or simple DB for prototype.
- License/IP checks will be basic heuristics for MVP.
- Dashboard/reporting is optional and may be stubbed.
- GitHub App/Action will use REST API to call backend.
- Prototype will focus on Python and TypeScript codebases.

**STOPPED: Awaiting 'continue' before proceeding to Step 2 (TODO.md creation).**
