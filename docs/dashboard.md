# Dashboard/Reporting Stub (MVP)

This is a placeholder for a future dashboard/reporting feature.

## Concept
- Visualize guardrails analysis results, policy hits, and trends across PRs/commits.
- Export audit log data to CSV/JSON for reporting.
- Show breakdown by rule type, severity, and sector.

## Implementation Notes
- For MVP, export audit_log.jsonl and use external tools (Excel, Python, etc.) for analysis.
- Future: Add a simple FastAPI endpoint to serve summary stats or a static HTML dashboard.

---

*This dashboard is not implemented in the MVP, but the architecture supports future extensibility.*
