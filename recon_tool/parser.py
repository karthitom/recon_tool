"""
parser.py — Data Parser Module
================================
Converts raw nmap stdout into a clean list of port-record dicts.

Each record has the shape:
    {
        "port":     int,   # e.g. 80
        "protocol": str,   # "tcp" or "udp"
        "state":    str,   # "open", "closed", "filtered", …
        "service":  str,   # e.g. "http"
        "version":  str,   # e.g. "Apache httpd 2.4.41" (empty if not detected)
    }

The parser also extracts high-level host metadata:
    {
        "host":      str,  # IP / hostname as reported by nmap
        "hostname":  str,  # rDNS name (empty string if not resolved)
        "state":     str,  # "up" or "down"
        "ports":     list  # list of port-record dicts above
    }
"""

import re
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

# Matches the "Nmap scan report for …" header line.
# Captures bare IP or "hostname (IP)" variants.
_HOST_RE = re.compile(
    r"Nmap scan report for\s+"
    r"(?:(?P<hostname>[^\s(]+)\s+\((?P<ip>[^)]+)\)|(?P<bare_ip>\S+))"
)

# Matches a port line such as:
#   80/tcp   open  http    Apache httpd 2.4.41 ((Unix))
#   443/tcp  open  https
#   22/tcp   closed ssh
_PORT_RE = re.compile(
    r"^(?P<port>\d+)/(?P<proto>tcp|udp)\s+"
    r"(?P<state>\S+)\s+"
    r"(?P<service>\S+)"
    r"(?:\s+(?P<version>.+))?$"
)

# Matches the host-state summary line: "Host is up (0.045s latency)."
_HOST_STATE_RE = re.compile(r"Host is\s+(?P<state>up|down)", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_nmap_output(raw_output: str) -> dict:
    """
    Parse raw nmap stdout and return structured scan data.

    Parameters
    ----------
    raw_output : str
        The full stdout string returned by scanner.run_scan().

    Returns
    -------
    dict
        {
            "host":     str,
            "hostname": str,
            "state":    str,   # "up" / "down" / "unknown"
            "ports":    list[dict]
        }
        Returns a dict with empty ports list and state "unknown" when the
        output cannot be parsed (e.g. host down, no ports found).
    """
    if not raw_output:
        logger.warning("parse_nmap_output received empty input.")
        return _empty_result()

    lines = raw_output.splitlines()

    host      = ""
    hostname  = ""
    state     = "unknown"
    ports: list[dict] = []

    for line in lines:
        line = line.strip()

        # ---- Host header ---------------------------------------------------
        host_match = _HOST_RE.search(line)
        if host_match:
            if host_match.group("bare_ip"):
                host     = host_match.group("bare_ip")
                hostname = ""
            else:
                hostname = host_match.group("hostname")
                host     = host_match.group("ip")
            logger.debug("Parsed host: %s (hostname: %s)", host, hostname)
            continue

        # ---- Host state line -----------------------------------------------
        state_match = _HOST_STATE_RE.search(line)
        if state_match:
            state = state_match.group("state").lower()
            continue

        # ---- Port record ---------------------------------------------------
        port_match = _PORT_RE.match(line)
        if port_match:
            record = {
                "port":     int(port_match.group("port")),
                "protocol": port_match.group("proto"),
                "state":    port_match.group("state").lower(),
                "service":  port_match.group("service"),
                "version":  (port_match.group("version") or "").strip(),
            }
            ports.append(record)
            logger.debug("Parsed port record: %s", record)

    if not host:
        logger.warning("Could not extract host information from nmap output.")
        return _empty_result()

    result = {
        "host":     host,
        "hostname": hostname,
        "state":    state,
        "ports":    ports,
    }

    logger.info(
        "Parsed %d port record(s) for host %s (state: %s).",
        len(ports), host, state
    )
    return result


def filter_open_ports(scan_data: dict) -> list[dict]:
    """
    Convenience helper — returns only the open ports from a parsed result.

    Parameters
    ----------
    scan_data : dict
        Output of parse_nmap_output().

    Returns
    -------
    list[dict]
        Port records whose state is "open".
    """
    return [p for p in scan_data.get("ports", []) if p["state"] == "open"]


# ---------------------------------------------------------------------------
# Phase-2 placeholder — state comparison / asset diffing
# ---------------------------------------------------------------------------

def diff_scans(previous: dict, current: dict) -> dict:
    """
    PHASE 2 PLACEHOLDER — Compare two parsed scan results and surface
    newly opened or closed ports since the last scan.

    Parameters
    ----------
    previous : dict
        Output of parse_nmap_output() from a prior scan.
    current : dict
        Output of parse_nmap_output() from the latest scan.

    Returns
    -------
    dict
        {
            "newly_opened":  list[dict],  # ports open now but not before
            "newly_closed":  list[dict],  # ports closed now but were open
            "unchanged":     list[dict],  # ports with same state
        }
    """
    def _port_key(p: dict) -> tuple:
        return (p["port"], p["protocol"])

    prev_open = {_port_key(p): p for p in filter_open_ports(previous)}
    curr_open = {_port_key(p): p for p in filter_open_ports(current)}

    newly_opened = [p for k, p in curr_open.items() if k not in prev_open]
    newly_closed = [p for k, p in prev_open.items() if k not in curr_open]
    unchanged    = [p for k, p in curr_open.items() if k in prev_open]

    return {
        "newly_opened": newly_opened,
        "newly_closed": newly_closed,
        "unchanged":    unchanged,
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _empty_result() -> dict:
    return {"host": "", "hostname": "", "state": "unknown", "ports": []}
