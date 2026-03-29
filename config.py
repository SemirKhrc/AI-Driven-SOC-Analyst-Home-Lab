"""
config.py — Central configuration loader.

Reads all settings from the .env file using python-dotenv.
Validates that every required key is present at startup so the
pipeline fails immediately with a clear error rather than crashing
mid-run when a key is first used.

HOW IT WORKS:
  load_dotenv() reads the .env file and injects the values into the
  process environment. os.getenv() then retrieves them. This means
  API keys and passwords never appear in source code.
"""

import os
from dotenv import load_dotenv

# Load the .env file from the same directory as this script.
load_dotenv()


def _require(key: str) -> str:
    """Return the value of an environment variable or raise a clear error."""
    value = os.getenv(key)
    if not value:
        raise EnvironmentError(
            f"Missing required config: '{key}' is not set in your .env file.\n"
            f"Copy .env.example to .env and fill in the value."
        )
    return value


# ── Airia ─────────────────────────────────────────────────────────────────────
AIRIA_API_URL = _require("AIRIA_API_URL")
AIRIA_API_KEY = _require("AIRIA_API_KEY")

# ── Threat Intel ──────────────────────────────────────────────────────────────
ABUSEIPDB_API_KEY = _require("ABUSEIPDB_API_KEY")

# ── Telegram ──────────────────────────────────────────────────────────────────
TELEGRAM_BOT_TOKEN = _require("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID   = _require("TELEGRAM_CHAT_ID")

# ── Monitored Server ──────────────────────────────────────────────────────────
DESTINATION_IP   = _require("DESTINATION_IP")
DESTINATION_HOST = _require("DESTINATION_HOST")

# ── Flask Dashboard ───────────────────────────────────────────────────────────
FLASK_SECRET_KEY    = _require("FLASK_SECRET_KEY")
DASHBOARD_USERNAME  = _require("DASHBOARD_USERNAME")
DASHBOARD_PASSWORD  = _require("DASHBOARD_PASSWORD")

# ── Detection Thresholds (have sensible defaults) ─────────────────────────────
CAPTURE_DURATION  = int(os.getenv("CAPTURE_DURATION", "100"))   # seconds
ICMP_THRESHOLD    = int(os.getenv("ICMP_THRESHOLD", "40"))       # packets
PORTSCAN_THRESHOLD = int(os.getenv("PORTSCAN_THRESHOLD", "10")) # unique ports
SSH_THRESHOLD     = int(os.getenv("SSH_THRESHOLD", "5"))         # failed logins

# ── Network Interface ─────────────────────────────────────────────────────────
INTERFACE = os.getenv("INTERFACE", "eth0")

# ── File Paths ────────────────────────────────────────────────────────────────
PCAP_FILE  = "traffic.pcap"
CSV_FILE   = "traffic.csv"
DB_FILE    = "alerts.db"
LOG_FILE   = "/var/log/soc_pipeline.log"
AUTH_LOG   = "/var/log/auth.log"


# ── Self-test: run this file directly to verify your .env is complete ─────────
if __name__ == "__main__":
    print("[+] config.py loaded successfully. All required keys are present.")
    print(f"    Monitoring:  {DESTINATION_HOST} ({DESTINATION_IP})")
    print(f"    Interface:   {INTERFACE}")
    print(f"    Capture:     {CAPTURE_DURATION}s")
    print(f"    Thresholds:  ICMP>{ICMP_THRESHOLD} | Ports>{PORTSCAN_THRESHOLD} | SSH>{SSH_THRESHOLD}")
