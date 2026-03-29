"""
dashboard.py — Flask Web Dashboard

HOW IT WORKS:
  Flask is a lightweight Python web framework. When you run this file,
  it starts a small web server on your machine. You access it by opening
  a browser and going to: http://127.0.0.1:5000

  The dashboard reads all alerts from alerts.db and displays them in a
  color-coded table. Each row shows: time, alert type, source IP,
  location, AbuseIPDB score, severity, and the AI verdict.

SECURITY NOTES:
  - Bound to 127.0.0.1 (localhost) ONLY — not reachable from other
    machines on the network. Never change this to 0.0.0.0.
  - Protected by HTTP Basic Auth — username/password from .env.
    Without correct credentials, the browser shows a 401 login prompt.
  - Flask's secret key (from .env) is used to sign session cookies.
  - Debug mode is OFF in production — never run Flask with debug=True
    on a machine accessible to others (it exposes a code executor).

HOW TO RUN:
  python dashboard.py
  Then open: http://127.0.0.1:5000
"""

import functools
import logging
from flask import Flask, request, Response
import db
import config

logger = logging.getLogger(__name__)
app = Flask(__name__)
app.secret_key = config.FLASK_SECRET_KEY


# ── HTTP Basic Auth ───────────────────────────────────────────────────────────

def require_auth(f):
    """
    Decorator that enforces HTTP Basic Auth on a route.
    If the browser doesn't send correct credentials, we return a 401
    response which causes the browser to show a login dialog.
    """
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.authorization
        if (
            not auth
            or auth.username != config.DASHBOARD_USERNAME
            or auth.password != config.DASHBOARD_PASSWORD
        ):
            return Response(
                "Unauthorized — valid credentials required.",
                401,
                {"WWW-Authenticate": 'Basic realm="SOC Dashboard"'},
            )
        return f(*args, **kwargs)
    return wrapper


# ── HTML Template ─────────────────────────────────────────────────────────────

def _severity_color(severity: str) -> str:
    return {
        "High":     "#ffe0e0",   # light red
        "Medium":   "#fff3cd",   # light yellow
        "Low":      "#d4edda",   # light green
        "Critical": "#f8d7da",   # red
    }.get(severity, "#ffffff")


def _render_dashboard(alerts: list[dict]) -> str:
    rows = ""
    for a in alerts:
        color = _severity_color(a.get("severity", "Low"))
        verdict = a.get("ai_verdict", "") or "—"
        # Truncate long verdicts in the table cell
        verdict_display = verdict[:120] + "..." if len(verdict) > 120 else verdict

        rows += f"""
        <tr style="background:{color}">
            <td>{a.get('id', '')}</td>
            <td style="white-space:nowrap">{a.get('timestamp', '')[:19].replace('T',' ')}</td>
            <td><strong>{a.get('alert_type', '')}</strong></td>
            <td><code>{a.get('indicator_ip', '')}</code></td>
            <td>{a.get('geo_city', '')}, {a.get('geo_country', '')}</td>
            <td>{a.get('isp', '')}</td>
            <td>{a.get('abuse_score', 0)}/100</td>
            <td>{a.get('packet_count', 0)}</td>
            <td><strong>{a.get('severity', '')}</strong></td>
            <td style="font-size:0.85em">{verdict_display}</td>
        </tr>"""

    total = len(alerts)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SOC Dashboard</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f8f9fa; }}
        h1   {{ color: #333; border-bottom: 2px solid #dc3545; padding-bottom: 8px; }}
        .stats {{ margin: 12px 0; font-size: 0.95em; color: #555; }}
        table {{ border-collapse: collapse; width: 100%; background: white;
                 box-shadow: 0 1px 4px rgba(0,0,0,0.1); }}
        th    {{ background: #343a40; color: white; padding: 10px 8px;
                 text-align: left; font-size: 0.85em; }}
        td    {{ padding: 8px; border-bottom: 1px solid #dee2e6;
                 font-size: 0.85em; vertical-align: top; max-width: 300px;
                 overflow-wrap: break-word; }}
        tr:hover td {{ filter: brightness(0.96); }}
        .legend {{ margin-top: 12px; font-size: 0.8em; color: #777; }}
        .legend span {{ display: inline-block; width: 12px; height: 12px;
                        margin-right: 4px; vertical-align: middle; }}
    </style>
</head>
<body>
    <h1>SOC Alert Dashboard</h1>
    <div class="stats">
        Showing <strong>{total}</strong> alert(s) — newest first &nbsp;|&nbsp;
        <a href="/">Refresh</a>
    </div>

    {'<p style="color:#28a745;font-weight:bold">No alerts recorded yet.</p>' if total == 0 else ''}

    {f'''<table>
        <thead>
            <tr>
                <th>#</th><th>Time (UTC)</th><th>Alert Type</th><th>Source IP</th>
                <th>Location</th><th>ISP</th><th>Abuse Score</th>
                <th>Count</th><th>Severity</th><th>AI Verdict</th>
            </tr>
        </thead>
        <tbody>{rows}</tbody>
    </table>''' if total > 0 else ''}

    <div class="legend">
        Severity:
        <span style="background:#f8d7da"></span>Critical &nbsp;
        <span style="background:#ffe0e0"></span>High &nbsp;
        <span style="background:#fff3cd"></span>Medium &nbsp;
        <span style="background:#d4edda"></span>Low
    </div>
</body>
</html>"""


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
@require_auth
def index():
    db.init_db()
    alerts = db.get_all_alerts()
    return _render_dashboard(alerts)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    db.init_db()
    print("[+] Dashboard running at http://127.0.0.1:5000")
    print("[+] Press Ctrl+C to stop.")
    # debug=False and host=127.0.0.1 are intentional — see security notes above
    app.run(host="127.0.0.1", port=5000, debug=False)
