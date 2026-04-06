"""Local account verification.

Confirms the user is operating under a local account they own,
not a domain or managed account.
"""

import os
import platform
import subprocess


def scan_account() -> dict:
    """Gather local account and OS information."""
    system = platform.system()
    info = {
        "os": f"{system} {platform.release()}",
        "os_version": platform.version(),
        "arch": platform.machine(),
        "hostname": platform.node(),
        "local_account": _get_username(),
        "account_type": "standard",
    }

    if system == "Darwin":
        info.update(_scan_account_macos())
    elif system == "Windows":
        info.update(_scan_account_windows())

    return info


def _get_username() -> str:
    """Get current username cross-platform."""
    return os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"


def _scan_account_macos() -> dict:
    """macOS-specific account details."""
    result = {}

    # OS marketing version
    try:
        sw = subprocess.run(
            ["sw_vers"],
            capture_output=True, text=True, timeout=5,
        )
        for line in sw.stdout.splitlines():
            if "ProductName" in line:
                result["os"] = line.split(":", 1)[1].strip()
            elif "ProductVersion" in line:
                result["os_version"] = line.split(":", 1)[1].strip()
                result["os"] = f"macOS {result['os_version']}"
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Check if user is admin
    username = _get_username()
    try:
        groups = subprocess.run(
            ["groups", username],
            capture_output=True, text=True, timeout=5,
        )
        if "admin" in groups.stdout.split():
            result["account_type"] = "admin"
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Verify local account (not network directory)
    try:
        dscl = subprocess.run(
            ["dscl", ".", "-read", f"/Users/{username}", "UniqueID"],
            capture_output=True, text=True, timeout=5,
        )
        if dscl.returncode == 0:
            result["account_source"] = "local"
        else:
            result["account_source"] = "unknown"
    except (subprocess.TimeoutExpired, FileNotFoundError):
        result["account_source"] = "unknown"

    return result


def _scan_account_windows() -> dict:
    """Windows-specific account details."""
    result = {}

    # Full whoami output
    try:
        whoami = subprocess.run(
            ["whoami"],
            capture_output=True, text=True, timeout=5,
        )
        full_identity = whoami.stdout.strip()
        result["full_identity"] = full_identity

        # MACHINENAME\user = local, DOMAIN\user = domain
        if "\\" in full_identity:
            domain_part, _ = full_identity.split("\\", 1)
            computername = os.environ.get("COMPUTERNAME", "").lower()
            if domain_part.lower() == computername:
                result["account_source"] = "local"
            else:
                result["account_source"] = "domain"
        else:
            result["account_source"] = "local"
    except (subprocess.TimeoutExpired, FileNotFoundError):
        result["account_source"] = "unknown"

    # Check admin membership
    try:
        net_user = subprocess.run(
            ["net", "localgroup", "Administrators"],
            capture_output=True, text=True, timeout=5,
        )
        username = _get_username().lower()
        if username in net_user.stdout.lower():
            result["account_type"] = "admin"
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Windows edition
    try:
        result["os"] = f"Windows {platform.release()}"
        result["os_version"] = platform.version()
    except Exception:
        pass

    return result
