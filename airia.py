"""
airia.py — Step 6: AI Verdict via Airia

HOW IT WORKS:
  Instead of dumping raw JSON at Airia (like the original script did),
  we send a structured prompt that gives the AI a role, context, and
  clear instructions on what to respond with.

  Good prompt engineering = better, more consistent AI output.

  The prompt tells Airia:
    - WHO it is (SOC analyst for a small business)
    - WHAT happened (the alert details in plain language)
    - WHAT to produce (severity, cause, recommended action)

  The response is returned as a plain string and stored in the database
  alongside the alert. It also appears in the Telegram notification and
  on the Flask dashboard.

SECURITY NOTES:
  - API key comes from .env, never hardcoded
  - HTTPS enforced by the URL (Airia API is always HTTPS)
  - SSL verification is always on (default)
  - Timeout is set to avoid hanging the pipeline
"""

import json
import logging
import requests
import config

logger = logging.getLogger(__name__)

AIRIA_TIMEOUT = 100   # seconds — AI calls can be slow, keep original timeout


def _build_prompt(alert: dict) -> str:
    """
    Build a structured natural-language prompt from alert data.

    WHY THIS MATTERS:
      The original script sent a raw JSON blob. That works, but asking
      the AI to act as a specific role and respond in a specific format
      produces far more useful and consistent output.
    """
    return (
        "You are a SOC (Security Operations Center) analyst for a small business network.\n"
        "A security alert has been triggered on the network. Analyze it and respond with EXACTLY:\n"
        "1. Severity: (Low / Medium / High / Critical)\n"
        "2. Likely cause: (one sentence)\n"
        "3. Recommended action: (one to two sentences)\n\n"
        "Alert details:\n"
        f"- Alert type:       {alert.get('alert_type', 'Unknown')}\n"
        f"- Source IP:        {alert.get('indicator_ip', 'Unknown')} "
        f"({alert.get('geo_city', 'Unknown')}, {alert.get('geo_country', 'Unknown')})\n"
        f"- ISP:              {alert.get('isp', 'Unknown')}\n"
        f"- Evidence:         {alert.get('packet_count', 0)} packets/attempts "
        f"in {config.CAPTURE_DURATION} seconds\n"
        f"- AbuseIPDB score:  {alert.get('abuse_score', 0)}/100 "
        f"({alert.get('abuse_reports', 0)} prior reports)\n"
        f"- Destination:      {config.DESTINATION_HOST} ({config.DESTINATION_IP})\n"
        f"- Current severity: {alert.get('severity', 'Low')} (from AbuseIPDB score)\n\n"
        "Provide your analysis:"
    )


def get_ai_verdict(alert: dict) -> str:
    """
    Send the enriched alert to Airia and return the AI's verdict as a string.
    Returns an empty string if the call fails — the pipeline continues either way.
    """
    prompt = _build_prompt(alert)

    headers = {
        "Content-Type": "application/json",
        "X-API-KEY":    config.AIRIA_API_KEY,
    }

    payload = {
        "userInput":   prompt,
        "asyncOutput": False,
    }

    logger.info(f"Sending alert to Airia for: {alert.get('indicator_ip')}")

    try:
        response = requests.post(
            config.AIRIA_API_URL,
            headers=headers,
            json=payload,
            timeout=AIRIA_TIMEOUT,
        )
        response.raise_for_status()
        logger.info(f"Airia responded with status {response.status_code}")

        # Airia may return JSON or plain text — handle both
        try:
            data = response.json()
            # Try common response field names
            verdict = (
                data.get("output")
                or data.get("response")
                or data.get("result")
                or data.get("message")
                or json.dumps(data, indent=2)
            )
        except ValueError:
            verdict = response.text

        logger.info("AI verdict received.")
        return str(verdict).strip()

    except requests.RequestException as e:
        logger.error(f"Airia API call failed: {e}")
        return ""


# ── Self-test ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import logging as _logging
    _logging.basicConfig(level=_logging.INFO, format="%(levelname)s %(message)s")

    test_alert = {
        "alert_type":    "SSH Brute Force",
        "indicator_ip":  "1.2.3.4",
        "geo_city":      "Moscow",
        "geo_country":   "Russia",
        "isp":           "Example ISP",
        "packet_count":  150,
        "abuse_score":   92,
        "abuse_reports": 300,
        "severity":      "High",
    }

    print("[+] Sending test alert to Airia...\n")
    verdict = get_ai_verdict(test_alert)
    print("AI Verdict:")
    print(verdict)
