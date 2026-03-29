"""
main.py — Pipeline Orchestrator

HOW IT WORKS:
  This is the entry point. It calls each module in the correct order
  and wires the outputs of one step into the inputs of the next.

  Full pipeline:
    1. capture.py  → capture traffic + convert to CSV
    2. analyze.py  → detect ICMP floods, port scans, SSH brute force
    3. enrich.py   → add geolocation + AbuseIPDB score to each alert
    4. airia.py    → send enriched alert to Airia, get AI verdict
    5. db.py       → save everything to SQLite
    6. notifier.py → send Telegram message

  If no suspicious activity is found, the pipeline exits cleanly with
  a "nothing to report" log message and no notification is sent.

  If any step raises an unexpected exception, it is caught at the top
  level and logged before the process exits with a non-zero code
  (important for cron to detect failures).

HOW TO RUN MANUALLY:
  python main.py

HOW TO SCHEDULE (cron — runs every 5 minutes):
  crontab -e
  Add:
    */5 * * * * /usr/bin/python3 /path/to/main.py >> /var/log/soc_pipeline.log 2>&1

AFTER FIRST RUN — set file permissions:
  chmod 600 .env
  chmod 600 alerts.db
"""

import sys
import logging
import config   # import first — validates .env before anything else runs
import capture
import analyze
import enrich
import airia
import db
import notifier


# ── Logging setup ─────────────────────────────────────────────────────────────
# Writes timestamped logs to both the console AND a log file.
# The log file creates an audit trail for the cron runs.

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(config.LOG_FILE, mode="a"),
    ],
)
logger = logging.getLogger(__name__)


# ── Pipeline ──────────────────────────────────────────────────────────────────

def run():
    logger.info("=" * 60)
    logger.info("SOC Pipeline starting")
    logger.info("=" * 60)

    # Step 1 — Capture
    logger.info("[Step 1] Capturing traffic...")
    capture.capture_traffic()
    capture.convert_to_csv()

    # Step 2 — Analyze
    logger.info("[Step 2] Analyzing traffic...")
    alerts = analyze.analyze_traffic()

    if not alerts:
        logger.info("No suspicious activity detected. Pipeline complete.")
        return

    logger.info(f"[!] {len(alerts)} alert(s) detected. Processing...")

    # Step 3–6 — Enrich, AI verdict, save, notify each alert
    db.init_db()

    for raw_alert in alerts:
        ip = raw_alert["indicator_ip"]
        atype = raw_alert["alert_type"]
        logger.info(f"Processing: {atype} from {ip}")

        # Step 3 — Enrich with geo + threat intel
        logger.info("[Step 3] Enriching alert...")
        enriched = enrich.enrich_alert(raw_alert)

        # Step 4 — Get AI verdict from Airia
        logger.info("[Step 4] Requesting AI verdict...")
        verdict = airia.get_ai_verdict(enriched)

        # Step 5 — Save to database
        logger.info("[Step 5] Saving to database...")
        alert_id = db.save_alert(enriched, ai_verdict=verdict)

        # Step 6 — Send Telegram notification
        logger.info("[Step 6] Sending Telegram notification...")
        notifier.send_alert(enriched, alert_id=alert_id, ai_verdict=verdict)

        logger.info(f"Alert {alert_id} fully processed.")

    logger.info("=" * 60)
    logger.info("SOC Pipeline complete.")
    logger.info("=" * 60)


if __name__ == "__main__":
    try:
        run()
    except Exception as e:
        logger.exception(f"Pipeline failed with unhandled error: {e}")
        sys.exit(1)
