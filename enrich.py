"""
enrich.py — Step 3: Threat Intelligence Enrichment

HOW IT WORKS:
  After detecting a suspicious IP, we gather extra context from two
  free external services before sending the alert to Airia. This makes
  the AI's verdict much more accurate and the alert much more useful.

  Service 1 — ip-api.com (no account needed, free):
    Send the IP, get back: country, city, ISP, organization.
    We SKIP private/internal IPs because they don't exist on the internet
    and ip-api.com would return nothing useful.
    URL: http://ip-api.com/json/{ip}
    Note: Free tier is HTTP only. We never send private IPs to it.

  Service 2 — AbuseIPDB (free account + API key):
    A community database where security researchers report malicious IPs.
    We get back: abuseConfidenceScore (0-100) and how many times the IP
    has been reported. A score of 0 = clean, 100 = known attacker.
    URL: https://api.abuseipdb.com/api/v2/check

SECURITY NOTES:
  - All external calls use HTTPS (except ip-api.com free tier, noted above)
  - SSL verification is always on (never verify=False)
  - Timeouts are set on all requests to avoid hanging the pipeline
  - Private IPs are never sent to external services
  - time.sleep(1) between calls to respect rate limits
"""

import time
import logging
import requests
import config
from analyze import is_private_ip

logger = logging.getLogger(__name__)

IPAPI_TIMEOUT    = 10   # seconds
ABUSEIPDB_TIMEOUT = 15  # seconds


def _get_geolocation(ip: str) -> dict:
    """
    Query ip-api.com for geographic info about a public IP.
    Returns a dict with country, city, isp. Returns empty dict on failure.
    """
    if is_private_ip(ip):
        logger.info(f"Skipping geolocation for private IP: {ip}")
        return {"geo_country": "Internal", "geo_city": "N/A", "isp": "N/A"}

    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=IPAPI_TIMEOUT,
        )
        response.raise_for_status()
        data = response.json()

        if data.get("status") == "success":
            return {
                "geo_country": data.get("country", "Unknown"),
                "geo_city":    data.get("city", "Unknown"),
                "isp":         data.get("isp", "Unknown"),
            }
        else:
            logger.warning(f"ip-api.com returned non-success for {ip}: {data.get('message')}")
    except requests.RequestException as e:
        logger.warning(f"Geolocation lookup failed for {ip}: {e}")

    return {"geo_country": "Unknown", "geo_city": "Unknown", "isp": "Unknown"}


def _get_abuse_score(ip: str) -> dict:
    """
    Query AbuseIPDB to check if the IP is known to be malicious.
    Returns abuse_score (0-100) and abuse_reports count.
    """
    if is_private_ip(ip):
        logger.info(f"Skipping AbuseIPDB lookup for private IP: {ip}")
        return {"abuse_score": 0, "abuse_reports": 0}

    headers = {
        "Key":    config.ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }
    params = {
        "ipAddress":    ip,
        "maxAgeInDays": "90",   # Only look at reports from the last 90 days
    }

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params=params,
            timeout=ABUSEIPDB_TIMEOUT,
        )
        response.raise_for_status()
        data = response.json().get("data", {})

        return {
            "abuse_score":   data.get("abuseConfidenceScore", 0),
            "abuse_reports": data.get("totalReports", 0),
        }
    except requests.RequestException as e:
        logger.warning(f"AbuseIPDB lookup failed for {ip}: {e}")

    return {"abuse_score": 0, "abuse_reports": 0}


def enrich_alert(alert: dict) -> dict:
    """
    Add geolocation and abuse intel to an alert dict.
    Returns a new dict with all original fields plus enrichment data.

    Also derives a severity level:
      abuse_score >= 75 → High
      abuse_score >= 25 → Medium
      otherwise         → Low
    """
    ip = alert["indicator_ip"]
    logger.info(f"Enriching alert for IP: {ip}")

    geo   = _get_geolocation(ip)
    time.sleep(1)   # Rate limit — be a good citizen to free APIs
    abuse = _get_abuse_score(ip)

    score = abuse["abuse_score"]
    if score >= 75:
        severity = "High"
    elif score >= 25:
        severity = "Medium"
    else:
        severity = "Low"

    enriched = {**alert, **geo, **abuse, "severity": severity}

    logger.info(
        f"Enrichment complete: {ip} | {geo['geo_city']}, {geo['geo_country']} | "
        f"AbuseScore={score} | Severity={severity}"
    )
    return enriched


# ── Self-test ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    import json
    import logging as _logging
    _logging.basicConfig(level=_logging.INFO, format="%(levelname)s %(message)s")

    test_ip = sys.argv[2] if len(sys.argv) > 2 else "8.8.8.8"
    print(f"\nTesting enrichment for IP: {test_ip}\n")
    result = enrich_alert({
        "alert_type":   "Test",
        "indicator_ip": test_ip,
        "packet_count": 1,
        "timestamp":    "2026-01-01T00:00:00+00:00",
    })
    print(json.dumps(result, indent=2))
