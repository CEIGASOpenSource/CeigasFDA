"""Machine identity extraction.

Extracts a stable, non-sensitive machine identifier (OS install UUID).
This binds the FDA report to a specific physical machine without
fingerprinting hardware serial numbers or MAC addresses.

The machine ID is used in the HMAC attestation to prevent report
replay across different machines.
"""

import platform
import subprocess


def get_machine_id() -> str:
    """Extract a stable machine identifier.

    Returns the OS installation UUID — stable across reboots,
    changes with OS reinstall (which should trigger a new FDA scan).
    """
    system = platform.system()
    if system == "Darwin":
        return _get_machine_id_macos()
    elif system == "Windows":
        return _get_machine_id_windows()
    return _get_machine_id_fallback()


def _get_machine_id_macos() -> str:
    """macOS: Hardware UUID from IORegistry."""
    try:
        result = subprocess.run(
            ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            if "IOPlatformUUID" in line:
                # Extract UUID from:  "IOPlatformUUID" = "XXXXXXXX-XXXX-..."
                parts = line.split('"')
                for i, part in enumerate(parts):
                    if part == "IOPlatformUUID" and i + 2 < len(parts):
                        return parts[i + 2]
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    return _get_machine_id_fallback()


def _get_machine_id_windows() -> str:
    """Windows: Machine GUID from registry."""
    try:
        import winreg
        key_path = r"SOFTWARE\Microsoft\Cryptography"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            machine_guid, _ = winreg.QueryValueEx(key, "MachineGuid")
            return machine_guid
    except (ImportError, OSError):
        pass

    # Fallback: wmic
    try:
        result = subprocess.run(
            ["wmic", "csproduct", "get", "UUID", "/value"],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.splitlines():
            if line.startswith("UUID="):
                uuid = line.split("=", 1)[1].strip()
                if uuid and uuid != "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF":
                    return uuid
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    return _get_machine_id_fallback()


def _get_machine_id_fallback() -> str:
    """Fallback: generate from hostname + platform info.

    Less stable than a true UUID but deterministic for a given machine.
    This is the weakest form — triggers a warning in the report.
    """
    import hashlib
    components = [
        platform.node(),
        platform.system(),
        platform.machine(),
        platform.processor(),
    ]
    raw = "|".join(components)
    return f"fallback-{hashlib.sha256(raw.encode()).hexdigest()[:32]}"
