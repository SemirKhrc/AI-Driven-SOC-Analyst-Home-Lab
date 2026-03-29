"""
db.py — Step 4: Persistent Alert Storage (SQLite)

HOW IT WORKS:
  SQLite is a file-based database — no server to install or configure.
  Python has built-in support for it via the `sqlite3` module.
  All alerts are stored in alerts.db in the project directory.

  Think of it like a spreadsheet that code can query with SQL.
  Each row is one alert. The dashboard reads from this same file.

  Schema:
    alerts table — one row per alert, all enrichment data included.

SECURITY NOTES:
  - alerts.db should be chmod 600 (only owner can read/write).
    Run: chmod 600 alerts.db  after the first run creates it.
  - We use parameterized queries (?  placeholders) everywhere.
    This prevents SQL injection — user-supplied data is never
    concatenated into SQL strings.
"""

import sqlite3
import uuid
import logging
import config

logger = logging.getLogger(__name__)


def _connect() -> sqlite3.Connection:
    """Open a connection to the SQLite database file."""
    conn = sqlite3.connect(config.DB_FILE)
    conn.row_factory = sqlite3.Row   # Rows behave like dicts
    return conn


def init_db() -> None:
    """
    Create the alerts table if it doesn't already exist.
    Safe to call on every run — IF NOT EXISTS means it's a no-op
    when the table is already there.
    """
    with _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id       TEXT    NOT NULL,
                timestamp      TEXT    NOT NULL,
                alert_type     TEXT    NOT NULL,
                indicator_ip   TEXT    NOT NULL,
                packet_count   INTEGER NOT NULL,
                geo_country    TEXT,
                geo_city       TEXT,
                isp            TEXT,
                abuse_score    INTEGER,
                abuse_reports  INTEGER,
                ai_verdict     TEXT,
                severity       TEXT
            )
        """)
    logger.info("Database initialized.")


def save_alert(alert: dict, ai_verdict: str = "") -> str:
    """
    Insert one alert into the database.

    We generate a unique alert_id here (SOC-XXXXXXXX) so every alert
    is traceable across logs, Telegram messages, and the dashboard.

    Returns the generated alert_id.
    """
    alert_id = f"SOC-{uuid.uuid4().hex[:8].upper()}"

    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO alerts
                (alert_id, timestamp, alert_type, indicator_ip, packet_count,
                 geo_country, geo_city, isp, abuse_score, abuse_reports,
                 ai_verdict, severity)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert_id,
                alert.get("timestamp", ""),
                alert.get("alert_type", ""),
                alert.get("indicator_ip", ""),
                alert.get("packet_count", 0),
                alert.get("geo_country", ""),
                alert.get("geo_city", ""),
                alert.get("isp", ""),
                alert.get("abuse_score", 0),
                alert.get("abuse_reports", 0),
                ai_verdict,
                alert.get("severity", "Low"),
            ),
        )

    logger.info(f"Alert saved to DB: {alert_id}")
    return alert_id


def get_all_alerts(limit: int = 200) -> list[dict]:
    """
    Retrieve alerts from the database, newest first.
    Used by the Flask dashboard to display the alert table.
    """
    with _connect() as conn:
        cursor = conn.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
        )
        return [dict(row) for row in cursor.fetchall()]


# ── Self-test ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import logging as _logging
    _logging.basicConfig(level=_logging.INFO, format="%(levelname)s %(message)s")

    init_db()
    test_alert = {
        "timestamp":    "2026-01-01T00:00:00+00:00",
        "alert_type":   "ICMP Flood",
        "indicator_ip": "1.2.3.4",
        "packet_count": 99,
        "geo_country":  "Testland",
        "geo_city":     "Test City",
        "isp":          "Test ISP",
        "abuse_score":  85,
        "abuse_reports": 42,
        "severity":     "High",
    }
    alert_id = save_alert(test_alert, ai_verdict="Test verdict from AI.")
    print(f"\n[+] Saved test alert: {alert_id}")

    alerts = get_all_alerts()
    print(f"[+] Total alerts in DB: {len(alerts)}")
    print(f"[+] Latest: {alerts[0]}")
