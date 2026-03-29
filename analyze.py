"""
analyze.py — Step 2: Threat Detection

HOW IT WORKS:
  We analyze the CSV produced by capture.py and also read the system's
  SSH authentication log to detect three distinct threat types:

  1. ICMP Flood
     An IP sends more than ICMP_THRESHOLD ping packets in the capture
     window. This could be a DoS attempt or aggressive network scanner.

  2. Port Scan
     An IP sends TCP SYN packets (connection attempts) to more than
     PORTSCAN_THRESHOLD different destination ports. Attackers do this
     to discover which services are running on your server.

  3. SSH Brute Force
     We read /var/log/auth.log and count "Failed password" lines per
     source IP. More than SSH_THRESHOLD failures means someone is
     trying many passwords to guess credentials.

  Each detected threat is returned as a dict that flows into the rest
  of the pipeline (enrich → alert → notify → AI verdict).

SECURITY NOTE:
  All IPs extracted from the CSV are passed through validate_ip() before
  any further use. This prevents injection if tshark output is malformed.
"""

import csv
import re
import ipaddress
import logging
from collections import Counter, defaultdict
from datetime import datetime, timezone

import config

logger = logging.getLogger(__name__)


# ── IP validation ─────────────────────────────────────────────────────────────

def validate_ip(ip: str) -> str:
    """
    Ensure the string is a valid IP address before using it anywhere.
    Raises ValueError on invalid input — never silently passes bad data.
    """
    try:
        return str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        raise ValueError(f"Invalid IP address in capture data: '{ip}'")


def is_private_ip(ip: str) -> bool:
    """Return True for RFC1918 private addresses (192.168.x.x, 10.x.x.x, etc.)"""
    return ipaddress.ip_address(ip).is_private


# ── CSV analysis ──────────────────────────────────────────────────────────────

def _parse_csv():
    """
    Read traffic.csv and return:
      icmp_counter  — {src_ip: packet_count} for ICMP packets
      syn_ports     — {src_ip: set_of_destination_ports} for TCP SYN packets
    """
    icmp_counter = Counter()
    syn_ports = defaultdict(set)

    with open(config.CSV_FILE, newline="") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            raw_src = (row.get("ip.src") or "").strip().strip('"')
            proto   = (row.get("ip.proto") or "").strip().strip('"')
            flags   = (row.get("tcp.flags") or "").strip().strip('"')
            dst_port = (row.get("tcp.dstport") or "").strip().strip('"')

            if not raw_src:
                continue

            try:
                src_ip = validate_ip(raw_src)
            except ValueError as e:
                logger.warning(e)
                continue

            # Protocol 1 = ICMP
            if proto == "1":
                icmp_counter[src_ip] += 1

            # TCP SYN: flags field = 0x0002 (pure SYN, no ACK)
            # tshark reports flags as hex string e.g. "0x00000002"
            if proto == "6" and dst_port:
                try:
                    flag_int = int(flags, 16) if flags.startswith("0x") else int(flags)
                    # SYN bit is set, ACK bit is not (pure SYN = scanner behavior)
                    if (flag_int & 0x002) and not (flag_int & 0x010):
                        syn_ports[src_ip].add(dst_port)
                except (ValueError, TypeError):
                    pass

    return icmp_counter, syn_ports


# ── SSH log analysis ──────────────────────────────────────────────────────────

def _parse_auth_log():
    """
    Scan /var/log/auth.log for SSH brute force attempts.
    Returns {src_ip: failure_count}.

    Example log line:
      Mar 25 10:01:23 server sshd[1234]: Failed password for root from 1.2.3.4 port 54321 ssh2
    """
    ssh_counter = Counter()
    pattern = re.compile(r"Failed password for .+ from (\d+\.\d+\.\d+\.\d+)")

    try:
        with open(config.AUTH_LOG, "r", errors="replace") as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    raw_ip = match.group(1)
                    try:
                        ip = validate_ip(raw_ip)
                        ssh_counter[ip] += 1
                    except ValueError as e:
                        logger.warning(e)
    except FileNotFoundError:
        logger.warning(f"Auth log not found at {config.AUTH_LOG} — skipping SSH analysis.")
    except PermissionError:
        logger.warning(f"Permission denied reading {config.AUTH_LOG} — skipping SSH analysis.")

    return ssh_counter


# ── Main analysis function ────────────────────────────────────────────────────

def analyze_traffic() -> list[dict]:
    """
    Run all three detectors and return a list of alert dicts.
    Each dict contains everything needed by enrich.py and airia.py.
    Returns an empty list if nothing suspicious is found.
    """
    alerts = []
    timestamp = datetime.now(timezone.utc).isoformat()

    icmp_counter, syn_ports = _parse_csv()
    ssh_counter = _parse_auth_log()

    # ── 1. ICMP Flood ─────────────────────────────────────────────────────────
    logger.info("Checking for ICMP floods...")
    for ip, count in icmp_counter.items():
        logger.info(f"  {ip}: {count} ICMP packets")
        if count > config.ICMP_THRESHOLD:
            logger.warning(f"[!] ICMP Flood detected from {ip} ({count} packets)")
            alerts.append({
                "alert_type": "ICMP Flood",
                "indicator_ip": ip,
                "packet_count": count,
                "timestamp": timestamp,
            })

    # ── 2. Port Scan ──────────────────────────────────────────────────────────
    logger.info("Checking for port scans...")
    for ip, ports in syn_ports.items():
        unique_ports = len(ports)
        logger.info(f"  {ip}: SYN to {unique_ports} unique ports")
        if unique_ports > config.PORTSCAN_THRESHOLD:
            logger.warning(f"[!] Port Scan detected from {ip} ({unique_ports} ports)")
            alerts.append({
                "alert_type": "Port Scan",
                "indicator_ip": ip,
                "packet_count": unique_ports,   # repurposed: # of ports scanned
                "timestamp": timestamp,
            })

    # ── 3. SSH Brute Force ────────────────────────────────────────────────────
    logger.info("Checking for SSH brute force...")
    for ip, count in ssh_counter.items():
        logger.info(f"  {ip}: {count} SSH failures")
        if count > config.SSH_THRESHOLD:
            logger.warning(f"[!] SSH Brute Force from {ip} ({count} failures)")
            alerts.append({
                "alert_type": "SSH Brute Force",
                "indicator_ip": ip,
                "packet_count": count,
                "timestamp": timestamp,
            })

    if not alerts:
        logger.info("No suspicious activity detected.")

    return alerts
