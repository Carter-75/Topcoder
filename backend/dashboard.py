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
            :root {
                --bg: #f6f8fb;
                --card: #ffffff;
                --text: #0f172a;
                --muted: #64748b;
                --primary: #3b4cca;
                --border: #e2e8f0;
            }
            * { box-sizing: border-box; }
            body { font-family: 'Segoe UI', Arial, sans-serif; background: var(--bg); margin: 0; color: var(--text); }
            .container { max-width: 1000px; margin: 2.5rem auto; padding: 0 1.25rem; }
            .panel { background: var(--card); border-radius: 16px; box-shadow: 0 10px 30px #0f172a12; padding: 2rem; border: 1px solid var(--border); }
            h1 { color: var(--text); margin: 0 0 0.35rem 0; }
            .actions { margin: 1rem 0 1.5rem 0; display: flex; gap: 0.6rem; flex-wrap: wrap; }
            .actions a { background: var(--primary); color: #fff; padding: 0.55rem 1rem; border-radius: 10px; text-decoration: none; font-size: 0.95rem; }
            .summary { color: var(--muted); }
            table { width: 100%; border-collapse: collapse; margin-top: 1.2rem; border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }
            th, td { padding: 0.75rem 1rem; border-bottom: 1px solid var(--border); }
            th { background: #eef2ff; color: #1e1b4b; text-align: left; }
            tr:hover { background: #f8fafc; }
            .policy { font-size: 0.9em; padding: 0.2em 0.6em; border-radius: 999px; }
            .policy-blocking { background: #fee2e2; color: #991b1b; }
            .policy-warning { background: #fef3c7; color: #92400e; }
            .policy-advisory { background: #e0f2fe; color: #075985; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="panel">
                <h1>Guardrails Audit Dashboard</h1>
                <div class="actions">
                    <a href='/settings/ui'>Settings</a>
                    <a href='/docs'>API Docs</a>
                    <a href='/health'>Health</a>
                </div>
                <p class="summary">Total Analyses: <b>{count}</b></p>
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
                <p style='margin-top:2rem;color:#64748b;font-size:0.95em;'>Showing last 100 analyses. For full export, see audit_log.jsonl.</p>
            </div>
        </div>
    </body>
    </html>
    """.format(count=len(entries))
    return HTMLResponse(content=html)
