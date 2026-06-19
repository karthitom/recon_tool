"""
reporter.py — Output & Reporting Module
=========================================
Handles two responsibilities:
  1. Render a cyberpunk-styled Rich terminal table from parsed scan data.
  2. Export results to /reports as JSON or CSV when --output is requested.
"""

import csv
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich import box

logger = logging.getLogger(__name__)

# Shared console instance — dark background assumed (standard terminals).
console = Console(highlight=False)

# Directory where exported reports are saved.
REPORTS_DIR = Path(__file__).parent / "reports"


# ---------------------------------------------------------------------------
# Terminal rendering
# ---------------------------------------------------------------------------

def render_table(scan_data: dict) -> None:
    """
    Print a styled Rich table to the terminal.

    Colour rules:
      - open     → bold green
      - closed   → bold red
      - filtered → bold yellow
      - anything else → dim white

    Parameters
    ----------
    scan_data : dict
        Output of parser.parse_nmap_output().
    """
    host     = scan_data.get("host", "unknown")
    hostname = scan_data.get("hostname", "")
    state    = scan_data.get("state", "unknown")
    ports    = scan_data.get("ports", [])

    # ---- Host summary line ------------------------------------------------
    host_label = f"[bold cyan]{host}[/bold cyan]"
    if hostname:
        host_label += f"  [dim]({hostname})[/dim]"
    state_color = "bold green" if state == "up" else "bold red"
    console.print(f"\n  Host : {host_label}   Status : [{state_color}]{state.upper()}[/{state_color}]\n")

    if not ports:
        console.print("  [yellow]No port data found — host may be down or blocking probes.[/yellow]\n")
        return

    # ---- Build table -------------------------------------------------------
    table = Table(
        title=f"[bold magenta]Scan Results — {host}[/bold magenta]",
        box=box.DOUBLE_EDGE,
        border_style="bright_black",
        header_style="bold magenta",
        show_lines=True,
        min_width=72,
    )

    table.add_column("PORT",     style="bold white",  justify="right",  width=8)
    table.add_column("PROTO",    style="cyan",         justify="center", width=7)
    table.add_column("STATE",    justify="center",     width=10)
    table.add_column("SERVICE",  style="bright_white", justify="left",   width=14)
    table.add_column("VERSION",  style="dim white",    justify="left")

    for record in ports:
        port_str    = str(record["port"])
        proto_str   = record["protocol"].upper()
        state_str   = record["state"]
        service_str = record["service"]
        version_str = record["version"] or "—"

        # Colour-code the STATE cell
        state_cell = _state_cell(state_str)

        table.add_row(port_str, proto_str, state_cell, service_str, version_str)

    console.print(table)
    console.print(
        f"\n  [dim]Total ports listed: {len(ports)} | "
        f"Open: {sum(1 for p in ports if p['state'] == 'open')} | "
        f"Scanned at {_now_str()}[/dim]\n"
    )


def _state_cell(state: str) -> Text:
    """Return a rich Text object colour-coded by port state."""
    colour_map = {
        "open":     ("bold green",  "OPEN"),
        "closed":   ("bold red",    "CLOSED"),
        "filtered": ("bold yellow", "FILTERED"),
    }
    style, label = colour_map.get(state.lower(), ("dim white", state.upper()))
    return Text(label, style=style, justify="center")


# ---------------------------------------------------------------------------
# File export
# ---------------------------------------------------------------------------

def export_report(
    scan_data: dict,
    fmt: Literal["json", "csv"],
    target: str,
) -> Path:
    """
    Save parsed scan data to /reports as JSON or CSV.

    Parameters
    ----------
    scan_data : dict
        Output of parser.parse_nmap_output().
    fmt : "json" | "csv"
        Export format.
    target : str
        The scan target (used to name the file).

    Returns
    -------
    Path
        Absolute path to the written file.
    """
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    # Sanitise target for use in a filename (replace dots/colons/slashes)
    safe_target = re.sub(r"[^\w\-]", "_", target)
    timestamp   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename    = f"scan_{safe_target}_{timestamp}.{fmt}"
    filepath    = REPORTS_DIR / filename

    if fmt == "json":
        _export_json(scan_data, filepath)
    else:
        _export_csv(scan_data, filepath)

    console.print(
        f"  [bold green]✔[/bold green]  Report saved → "
        f"[underline cyan]{filepath}[/underline cyan]\n"
    )
    logger.info("Report exported to %s", filepath)
    return filepath


def _export_json(scan_data: dict, filepath: Path) -> None:
    """Write scan_data as pretty-printed JSON."""
    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(scan_data, fh, indent=2, ensure_ascii=False)


def _export_csv(scan_data: dict, filepath: Path) -> None:
    """
    Write port records as CSV rows.

    Columns: host, hostname, host_state, port, protocol, state, service, version
    """
    fieldnames = ["host", "hostname", "host_state",
                  "port", "protocol", "state", "service", "version"]

    host      = scan_data.get("host", "")
    hostname  = scan_data.get("hostname", "")
    host_state = scan_data.get("state", "unknown")
    ports     = scan_data.get("ports", [])

    with open(filepath, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()

        if not ports:
            # Write a single row indicating no port data
            writer.writerow({
                "host": host, "hostname": hostname, "host_state": host_state,
                "port": "", "protocol": "", "state": "", "service": "", "version": "",
            })
            return

        for record in ports:
            writer.writerow({
                "host":       host,
                "hostname":   hostname,
                "host_state": host_state,
                "port":       record["port"],
                "protocol":   record["protocol"],
                "state":      record["state"],
                "service":    record["service"],
                "version":    record["version"],
            })


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# Needed only inside export_report — avoid top-level import bloat.
import re  # noqa: E402  (placed here intentionally)
