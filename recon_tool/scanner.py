"""
scanner.py — Core Scanner Module
=================================
Responsible for safely invoking Nmap via subprocess and returning the raw
string output for downstream parsing. No exploitation, no brute-forcing —
strictly port enumeration and service detection for authorized targets.

Supported scan modes:
  - fast     : nmap -F            (top 100 ports, quick sweep)
  - service  : nmap -sV           (version/service detection, top 1000 ports)
  - full     : nmap -p-           (all 65535 ports, slow but thorough)
"""

import subprocess
import shutil
import logging
from typing import Optional

# ---------------------------------------------------------------------------
# Module-level logger — callers configure the root logger; we just emit.
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Maps a friendly scan-type name to its nmap flag(s).
SCAN_PROFILES: dict[str, list[str]] = {
    "fast":    ["-F"],                    # Top 100 ports
    "service": ["-sV", "--version-light"],# Service/version detection
    "full":    ["-p-", "-sV", "--version-light"],  # All ports + service info
}

# Hard timeout (seconds) before we give up waiting for nmap.
# Adjust upward for large subnets or slow networks.
DEFAULT_TIMEOUT: int = 300  # 5 minutes


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def is_nmap_available() -> bool:
    """
    Check whether nmap is installed and reachable on the system PATH.

    Returns
    -------
    bool
        True if nmap is found, False otherwise.
    """
    found = shutil.which("nmap") is not None
    if not found:
        logger.warning("nmap binary not found on PATH.")
    return found


def run_scan(
    target: str,
    scan_type: str = "fast",
    timeout: int = DEFAULT_TIMEOUT,
    extra_flags: Optional[list[str]] = None,
) -> str:
    """
    Execute an Nmap scan against *target* and return the raw stdout output.

    Parameters
    ----------
    target : str
        A validated IP address or hostname to scan.
    scan_type : str
        One of "fast", "service", or "full". Defaults to "fast".
    timeout : int
        Maximum seconds to wait for nmap to complete. Defaults to 300.
    extra_flags : list[str] | None
        Optional additional nmap flags (e.g., ["-T4"]). Use with care —
        only pass flags that do not enable exploitation or brute-force
        behaviour.

    Returns
    -------
    str
        Raw stdout string from nmap. An empty string is returned on failure.

    Raises
    ------
    SystemExit
        If nmap is not installed (we log the error and exit with code 1 so
        the caller's UI can handle it cleanly).
    """
    # ------------------------------------------------------------------ #
    # 1. Guard: nmap must be present                                       #
    # ------------------------------------------------------------------ #
    if not is_nmap_available():
        logger.error(
            "nmap is not installed or not on PATH. "
            "Install it from https://nmap.org/download.html"
        )
        raise EnvironmentError(
            "nmap not found. Please install nmap and ensure it is on your PATH."
        )

    # ------------------------------------------------------------------ #
    # 2. Resolve the scan profile                                          #
    # ------------------------------------------------------------------ #
    scan_type = scan_type.lower().strip()
    if scan_type not in SCAN_PROFILES:
        logger.warning(
            "Unknown scan_type '%s'. Falling back to 'fast'.", scan_type
        )
        scan_type = "fast"

    profile_flags = SCAN_PROFILES[scan_type]

    # ------------------------------------------------------------------ #
    # 3. Build the command list (never passed through a shell to avoid     #
    #    command-injection risks).                                         #
    # ------------------------------------------------------------------ #
    cmd: list[str] = ["nmap"] + profile_flags

    # Merge any caller-supplied extra flags (validated list, not a string)
    if extra_flags:
        if not all(isinstance(f, str) for f in extra_flags):
            raise TypeError("extra_flags must be a list of strings.")
        cmd.extend(extra_flags)

    # Target is always the final positional argument
    cmd.append(target)

    logger.info("Running scan: %s", " ".join(cmd))

    # ------------------------------------------------------------------ #
    # 4. Execute                                                           #
    # ------------------------------------------------------------------ #
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,   # stdout + stderr captured separately
            text=True,             # decode bytes → str automatically
            timeout=timeout,       # hard wall-clock limit
            shell=False,           # NEVER use shell=True with user input
        )
    except FileNotFoundError:
        # Shouldn't happen after the is_nmap_available() check, but belt-and-
        # suspenders in case the binary disappears mid-run.
        logger.error("nmap binary disappeared during execution.")
        raise EnvironmentError("nmap binary not found during execution.")

    except subprocess.TimeoutExpired:
        logger.error(
            "Scan timed out after %d seconds against target '%s'.",
            timeout,
            target,
        )
        raise TimeoutError(
            f"Nmap scan timed out after {timeout}s. "
            "Try a faster scan profile or increase the timeout."
        )

    except subprocess.SubprocessError as exc:
        logger.error("Subprocess error while running nmap: %s", exc)
        raise RuntimeError(f"Failed to execute nmap: {exc}") from exc

    # ------------------------------------------------------------------ #
    # 5. Check the return code                                             #
    # ------------------------------------------------------------------ #
    if result.returncode != 0:
        # nmap writes diagnostics to stderr on failure
        error_detail = result.stderr.strip() or "No additional detail from nmap."
        logger.error(
            "nmap exited with code %d. Detail: %s",
            result.returncode,
            error_detail,
        )
        raise RuntimeError(
            f"nmap returned a non-zero exit code ({result.returncode}). "
            f"Detail: {error_detail}"
        )

    raw_output = result.stdout.strip()

    if not raw_output:
        logger.warning(
            "nmap produced no output for target '%s'. "
            "The host may be down or blocking probes.",
            target,
        )

    logger.info("Scan completed successfully for target '%s'.", target)
    return raw_output


# ---------------------------------------------------------------------------
# Phase-2 placeholder
# ---------------------------------------------------------------------------

def run_scan_with_metadata(
    target: str,
    scan_type: str = "fast",
    timeout: int = DEFAULT_TIMEOUT,
) -> dict:
    """
    PHASE 2 PLACEHOLDER — Extended scan that returns both raw output and
    metadata (timestamp, scan type, target) in a single dict. This will
    feed the state-comparison / asset-diffing subsystem.

    Parameters
    ----------
    target : str
        Validated IP address or hostname.
    scan_type : str
        Scan profile name.
    timeout : int
        Timeout in seconds.

    Returns
    -------
    dict
        {
            "target": str,
            "scan_type": str,
            "timestamp": str (ISO-8601),
            "raw_output": str,
        }
    """
    import datetime  # local import — only needed in Phase 2

    raw = run_scan(target, scan_type=scan_type, timeout=timeout)

    return {
        "target": target,
        "scan_type": scan_type,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "raw_output": raw,
    }
