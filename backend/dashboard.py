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
                --bg: #0b1020;
                --surface: #121933;
                --card: #151f3d;
                --text: #e2e8f0;
                --muted: #94a3b8;
                --primary: #60a5fa;
                --border: #243158;
            }
            * { box-sizing: border-box; }
            body { margin: 0; font-family: 'Segoe UI', Arial, sans-serif; background: radial-gradient(circle at top, #141b3a 0%, #0b1020 55%, #070b16 100%); color: var(--text); }
            .container { max-width: 1000px; margin: 2.5rem auto; padding: 0 1.25rem; }
            .panel { background: linear-gradient(160deg, rgba(21,31,61,0.98), rgba(16,25,48,0.96)); border-radius: 18px; box-shadow: 0 12px 30px rgba(2, 6, 23, 0.45); padding: 2rem; border: 1px solid var(--border); }
            h1 { margin: 0 0 0.35rem 0; }
            .actions { margin: 1rem 0 1.5rem 0; display: flex; gap: 0.6rem; flex-wrap: wrap; }
            .actions a { background: var(--primary); color: #0f172a; padding: 0.55rem 1rem; border-radius: 999px; text-decoration: none; font-size: 0.95rem; font-weight: 600; }
            .summary { color: var(--muted); }
            table { width: 100%; border-collapse: collapse; margin-top: 1.2rem; border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }
            th, td { padding: 0.75rem 1rem; border-bottom: 1px solid var(--border); }
            th { background: #1e2a52; color: #c7d2fe; text-align: left; }
            tr:hover { background: #0f172a; }
            .policy { font-size: 0.9em; padding: 0.2em 0.6em; border-radius: 999px; }
            .policy-blocking { background: #7f1d1d; color: #fee2e2; }
            .policy-warning { background: #7c2d12; color: #fde68a; }
            .policy-advisory { background: #0c4a6e; color: #bae6fd; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="panel">
                <h1>Guardrails Audit Dashboard</h1>
                <div class="actions">
                    <a href='/settings/ui'>Settings</a>
                </div>
                <p class="summary">Total Analyses: <b>__COUNT__</b></p>
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
    """
    html = html.replace("__COUNT__", str(len(entries)))
    return HTMLResponse(content=html)
