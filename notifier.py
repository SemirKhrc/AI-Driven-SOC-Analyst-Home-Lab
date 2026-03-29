"""
notifier.py — Step 5: Telegram Notification

HOW IT WORKS:
  Telegram lets you create a bot for free via @BotFather.
  Once created, your bot gets a TOKEN. You can send messages to any
  Telegram chat (including a private chat with yourself) by making an
  HTTPS POST request to Telegram's Bot API.

  SETUP (one-time steps):
    1. Open Telegram, search for @BotFather
    2. Send: /newbot
    3. Follow prompts — you'll receive a BOT_TOKEN
    4. Start a chat with your new bot (just send any message)
    5. Visit in browser:
         https://api.telegram.org/bot{YOUR_TOKEN}/getUpdates
       Look for "chat": {"id": 123456789} — that is your CHAT_ID
    6. Add both to your .env file

  The message uses Telegram's Markdown formatting for readability.

SECURITY NOTES:
  - Bot token comes from .env, never hardcoded
  - All calls use HTTPS — Telegram's API enforces this
  - SSL verification is always on (default behavior of requests)
  - Timeout is set to avoid hanging the pipeline
"""

import logging
import requests
import config

logger = logging.getLogger(__name__)

TELEGRAM_TIMEOUT = 10   # seconds


def _severity_emoji(severity: str) -> str:
    """Map severity level to a visual indicator in the Telegram message."""
    return {"High": "🔴", "Medium": "🟡", "Low": "🟢"}.get(severity, "⚪")


def send_alert(alert: dict, alert_id: str, ai_verdict: str = "") -> None:
    """
    Send a formatted Telegram message for a security alert.

    The message is formatted in Telegram's MarkdownV2 so the user
    gets a nicely structured notification on their phone.
    """
    sev      = alert.get("severity", "Low")
    emoji    = _severity_emoji(sev)
    ip       = alert.get("indicator_ip", "N/A")
    atype    = alert.get("alert_type", "N/A")
    city     = alert.get("geo_city", "N/A")
    country  = alert.get("geo_country", "N/A")
    isp      = alert.get("isp", "N/A")
    packets  = alert.get("packet_count", 0)
    score    = alert.get("abuse_score", 0)
    reports  = alert.get("abuse_reports", 0)

    # Telegram MarkdownV2 requires escaping certain characters.
    # We keep the message simple to avoid escaping complexity.
    message = (
        f"{emoji} *SOC ALERT — {atype}*\n"
        f"ID: `{alert_id}`\n"
        f"Severity: *{sev}*\n\n"
        f"*Attacker IP:* `{ip}`\n"
        f"*Location:* {city}, {country}\n"
        f"*ISP:* {isp}\n"
        f"*Evidence:* {packets} packets/attempts\n"
        f"*AbuseIPDB:* {score}/100 ({reports} reports)\n"
    )

    if ai_verdict:
        # Truncate if very long to keep the notification readable
        verdict_short = ai_verdict[:400] + "..." if len(ai_verdict) > 400 else ai_verdict
        message += f"\n*AI Verdict:*\n{verdict_short}"

    url = f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id":    config.TELEGRAM_CHAT_ID,
        "text":       message,
        "parse_mode": "Markdown",
    }

    try:
        response = requests.post(url, json=payload, timeout=TELEGRAM_TIMEOUT)
        response.raise_for_status()
        logger.info(f"Telegram notification sent for alert {alert_id}")
    except requests.RequestException as e:
        # Notification failure should NOT stop the pipeline — log and continue
        logger.error(f"Telegram notification failed: {e}")


# ── Self-test ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import logging as _logging
    _logging.basicConfig(level=_logging.INFO, format="%(levelname)s %(message)s")

    print("[+] Sending test Telegram message...")
    send_alert(
        alert={
            "alert_type":    "Test Alert",
            "indicator_ip":  "1.2.3.4",
            "geo_city":      "Test City",
            "geo_country":   "Testland",
            "isp":           "Test ISP",
            "packet_count":  99,
            "abuse_score":   85,
            "abuse_reports": 10,
            "severity":      "High",
        },
        alert_id="SOC-TEST0001",
        ai_verdict="This is a test verdict. Pipeline is working correctly.",
    )
    print("[+] Done. Check your Telegram.")
