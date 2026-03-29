"""
capture.py — Step 1: Traffic Capture

HOW IT WORKS:
  tshark is the command-line version of Wireshark. It listens on a
  network interface and saves matching packets to a .pcap file.

  We run it TWICE with different filters to capture two threat types:

  1. ICMP packets  → detects ping floods aimed at your server
  2. TCP SYN-only  → detects port scans (SYN = first step of TCP handshake;
                     a scanner sends SYN to many ports but never completes
                     the handshake)

  Both captures write to the same CSV via convert_to_csv() in analyze.py.

SECURITY NOTE:
  tshark should NOT run as root. Run this once to grant it only the
  network capture capability it needs:
      sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tshark
"""

import os
import logging
import subprocess
import config

logger = logging.getLogger(__name__)


def _remove_if_exists(path: str) -> None:
    if os.path.exists(path):
        os.remove(path)
        logger.info(f"Removed old file: {path}")


def capture_traffic() -> None:
    """
    Capture ICMP and TCP SYN packets destined for the monitored server.
    Saves raw packet data to PCAP_FILE.
    """
    _remove_if_exists(config.PCAP_FILE)

    # Filter explanation:
    #   icmp and dst host X   → ping packets to your server (flood detection)
    #   tcp[tcpflags]...      → TCP SYN packets (port scan detection)
    #   We combine them with 'or' so one capture catches both.
    packet_filter = (
        f"(icmp and dst host {config.DESTINATION_IP}) or "
        f"(tcp[tcpflags] & tcp-syn != 0 and dst host {config.DESTINATION_IP})"
    )

    cmd = [
        "tshark",
        "-i", config.INTERFACE,
        "-f", packet_filter,
        "-a", f"duration:{config.CAPTURE_DURATION}",
        "-w", config.PCAP_FILE,
    ]

    logger.info(f"Starting capture on {config.INTERFACE} for {config.CAPTURE_DURATION}s")
    subprocess.run(cmd, check=True)

    if not os.path.exists(config.PCAP_FILE):
        raise RuntimeError("tshark capture failed — PCAP file was not created.")

    logger.info(f"Capture complete: {config.PCAP_FILE}")


def convert_to_csv() -> None:
    """
    Re-read the PCAP and extract key fields into a CSV for easy analysis.

    Fields extracted:
      frame.time_epoch  — Unix timestamp of the packet
      ip.src            — Source IP (who sent it)
      ip.dst            — Destination IP (your server)
      ip.proto          — Protocol number (1=ICMP, 6=TCP)
      tcp.dstport       — Destination port (useful for port scan detection)
      tcp.flags         — TCP flags in hex (we check for SYN=0x002)
      frame.len         — Packet size in bytes
    """
    _remove_if_exists(config.CSV_FILE)

    cmd = [
        "tshark",
        "-r", config.PCAP_FILE,
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "ip.proto",
        "-e", "tcp.dstport",
        "-e", "tcp.flags",
        "-e", "frame.len",
        "-E", "header=y",
        "-E", "separator=,",
        "-E", "quote=d",
    ]

    with open(config.CSV_FILE, "w", newline="") as outfile:
        subprocess.run(cmd, stdout=outfile, check=True)

    logger.info(f"CSV created: {config.CSV_FILE}")
