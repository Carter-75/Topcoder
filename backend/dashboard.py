from fastapi.responses import HTMLResponse
import os
import json

def dashboard():
    log_path = os.environ.get("AUDIT_LOG_PATH", "audit_log.jsonl")
    entries = []
    try:
        if os.path.exists(log_path):
            with open(log_path, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        entries.append(json.loads(line))
                    except Exception:
                        continue
    except Exception:
        entries = []
    html = """
    <html>
    <head>
        <title>Guardrails Dashboard</title>
        <meta name='viewport' content='width=device-width, initial-scale=1'>
        <style>
            body { font-family: 'Segoe UI', Arial, sans-serif; background: #f7f9fa; margin: 0; }
            .container { max-width: 900px; margin: 2rem auto; background: #fff; border-radius: 12px; box-shadow: 0 2px 8px #0001; padding: 2rem; }
            h1 { color: #1a237e; }
            table { width: 100%; border-collapse: collapse; margin-top: 1.5rem; }
            th, td { padding: 0.7rem 1rem; border-bottom: 1px solid #e0e0e0; }
            th { background: #e3eafc; color: #1a237e; }
            tr:hover { background: #f1f6ff; }
            .severity-blocking { color: #d32f2f; font-weight: bold; }
            .severity-warning { color: #fbc02d; font-weight: bold; }
            .severity-advisory { color: #1976d2; font-weight: bold; }
            .policy { font-size: 0.95em; padding: 0.2em 0.6em; border-radius: 6px; }
            .policy-blocking { background: #ffd6d6; color: #b71c1c; }
            .policy-warning { background: #fff9c4; color: #f57c00; }
            .policy-advisory { background: #e3f2fd; color: #1565c0; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Guardrails Audit Dashboard</h1>
            <div style='margin: 1rem 0 1.5rem 0; display: flex; gap: 0.6rem; flex-wrap: wrap;'>
                <a href='/settings/ui' style='background:#3949ab;color:#fff;padding:0.6rem 1rem;border-radius:8px;text-decoration:none;'>Settings</a>
                <a href='/docs' style='background:#5c6bc0;color:#fff;padding:0.6rem 1rem;border-radius:8px;text-decoration:none;'>API Docs</a>
                <a href='/health' style='background:#7e57c2;color:#fff;padding:0.6rem 1rem;border-radius:8px;text-decoration:none;'>Health</a>
            </div>
            <p>Total Analyses: <b>{count}</b></p>
            <table>
                <tr>
                    <th>Timestamp</th>
                    <th>Policy</th>
                    <th>Issues</th>
                    <th>Override Allowed</th>
                </tr>
    """
    for entry in entries[-100:][::-1]:
        policy = entry.get("policy", "").lower()
        policy_class = f"policy policy-{policy}" if policy else ""
        issues = entry.get("output", {}).get("issues", [])
        issue_count = len(issues)
        override = "Yes" if entry.get("override_allowed") else "No"
        html += f"<tr>"
        html += f"<td>{entry.get('timestamp','')}</td>"
        html += f"<td class='{policy_class}'>{policy.title()}</td>"
        html += f"<td>{issue_count}</td>"
        html += f"<td>{override}</td>"
        html += "</tr>"
    html += """
            </table>
            <p style='margin-top:2rem;color:#888;font-size:0.95em;'>Showing last 100 analyses. For full export, see audit_log.jsonl.</p>
        </div>
    </body>
    </html>
    """.format(count=len(entries))
    return HTMLResponse(content=html)
