# TODO.md – Project Plan & Status

This file is the single source of truth for the Topcoder “AI Powered Enterprise Guardrails for GitHub Copilot” challenge. All work is tracked here in small, concrete steps. See checkpoints for review gates.

---

## Architecture & Design
- [x] Define high-level system architecture (design)
- [x] Document architecture in docs/architecture.md (design)
- [x] CHECKPOINT: Review architecture with user before implementing rules

## Backend (Python) Service
- [x] Scaffold backend/ directory and Python project (MVP)
- [x] Implement /health endpoint (MVP)
- [x] Implement /analyze endpoint (stub) (MVP)
- [x] Add requirements.txt or pyproject.toml (MVP)
- [x] Add config file loader (YAML/JSON) (MVP)
- [x] Implement rule engine core (MVP)
- [x] Implement security rules (secrets, SQLi, deserialization, exec) (MVP)
- [x] Implement coding standards rules (MVP)
- [x] Implement license/IP heuristics (MVP)
- [x] Implement Copilot awareness logic (MVP)
- [x] Implement policy evaluation (advisory/warning/blocking) (MVP)
- [x] Implement audit log writer (MVP)
- [x] Add sector rule packs (finance, healthcare, public sector) (MVP)
- [x] Add tests/sample payloads (MVP)
- [x] CHECKPOINT: Review backend API and rule engine

## GitHub App/Action (TypeScript)
- [x] Scaffold github-app/ or .github/actions/guardrails (MVP)
- [x] Implement event handler for PR/push (MVP)
- [x] Implement backend API call (stub) (MVP)
- [x] Post comments/checks based on backend results (MVP)
- [x] Add config loader (YAML/JSON) (MVP)
- [x] Add tests/sample events (MVP)
- [x] CHECKPOINT: Review GitHub integration and feedback

## Security Guardrails & Static Rules
- [x] Implement hardcoded secret detection (MVP)
- [x] Implement SQL injection detection (MVP)
- [x] Implement insecure deserialization detection (MVP)
- [x] Implement unsafe file/command execution detection (MVP)
- [x] Map issues to OWASP/CWE (MVP)
- [x] Flag Copilot-generated insecure suggestions (MVP)
- [x] CHECKPOINT: Review static rule coverage

## AI-Assisted Review / “AI” Logic
- [x] Implement AI-style review stub (MVP)
- [x] Generate explanations and suggestions (MVP)
- [x] CHECKPOINT: Review AI review output

## Copilot Awareness Logic
- [x] Implement Copilot code detection heuristic (MVP)
- [x] Apply stricter rules to Copilot code (MVP)
- [x] CHECKPOINT: Review Copilot awareness logic

## Coding Standards & Rule Packs
- [x] Implement naming convention checks (MVP)
- [x] Implement logging practice checks (MVP)
- [x] Implement error-handling pattern checks (MVP)
- [x] Make rules configurable (YAML/JSON, repo override) (MVP)
- [x] Add sector rule packs (MVP)
- [x] CHECKPOINT: Review coding standards and config

## License & IP Compliance
- [x] Implement license detection (MVP)
- [x] Implement IP/duplication heuristics (MVP)
- [x] CHECKPOINT: Review license/IP logic

## Policy & Enforcement Modes
- [x] Implement advisory/warning/blocking modes (MVP)
- [x] Implement override path for blocking (MVP)
- [x] Make policies configurable (org/repo) (MVP)
- [x] CHECKPOINT: Review enforcement modes

## PR/Commit Integration & Feedback
- [x] Integrate with PR/commit events (MVP)
- [x] Post inline/summary comments (MVP)
- [x] Set check run/status (MVP)
- [x] CHECKPOINT: Review PR/commit integration

## Audit Logging & Traceability
- [x] Log each violation/decision (MVP)
- [x] Provide exportable audit log (JSON/CSV/API) (MVP)
- [x] CHECKPOINT: Review audit log

## Performance & Scalability Considerations
- [x] Design for large PRs (MVP)  # Note: Backend and GitHub App are stateless, can be horizontally scaled. For large PRs, recommend chunked analysis and async processing (stubbed for MVP).
- [x] Support async/offline processing (MVP)  # Note: Backend can be extended to queue jobs and return results via webhook or polling.
- [x] CHECKPOINT: Review performance/scalability

## Configuration & Deployment
- [x] Example config file (.guardrails/config.yml) (MVP)
- [x] Document deployment steps (README) (MVP)
- [x] CHECKPOINT: Review config/deployment

## Documentation & README
- [x] Write README with overview, architecture, setup, usage (MVP)
- [x] CHECKPOINT: Final review before packaging submission

## Optional: Dashboard & Reporting
- [x] Design dashboard/reporting stub (stretch)
- [x] Implement minimal dashboard/reporting (stretch)
- [x] CHECKPOINT: Review dashboard/reporting (if implemented)

---

## Assumptions & Open Questions
- [x] List and update assumptions as needed (docs/assumptions.md)

---

## CHECKPOINTS
- [x] Architecture review
- [x] Backend API/rule engine review
- [x] GitHub integration/feedback review
- [x] Static rule coverage review
- [x] AI review output review
- [x] Copilot awareness logic review
- [x] Coding standards/config review
- [x] License/IP logic review
- [x] Enforcement modes review
- [x] PR/commit integration review
- [x] Audit log review
- [x] Performance/scalability review
- [x] Config/deployment review
- [x] Final review before submission
- [x] Dashboard/reporting review (if implemented)
