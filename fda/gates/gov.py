"""Government/military environment detection.

Detects: PIV/CAC smart card infrastructure, government login banners,
.mil/.gov domain indicators.

Hard gate: government machines have strict security requirements that
preclude third-party automation agents.
"""

import os
import platform
import subprocess


def detect_piv_cac() -> bool:
    """Returns True if PIV/CAC smart card infrastructure is detected."""
    system = platform.system()
    if system == "Darwin":
        return _detect_piv_macos()
    elif system == "Windows":
        return _detect_piv_windows()
    return False


def detect_gov_banner() -> bool:
    """Returns True if government/military login banners are detected."""
    system = platform.system()
    if system == "Darwin":
        return _detect_gov_banner_macos()
    elif system == "Windows":
        return _detect_gov_banner_windows()
    return False


# ── macOS ────────────────────────────────────────────────────

def _detect_piv_macos() -> bool:
    """Detect PIV/CAC smart card services on macOS."""

    # 1. CryptoTokenKit smart card entries
    ctk_dir = "/usr/lib/smartcardservices"
    if os.path.isdir(ctk_dir):
        return True

    # 2. sc_auth paired identities
    try:
        result = subprocess.run(
            ["sc_auth", "list"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    # 3. PIV middleware (OpenSC, CACKey)
    piv_paths = [
        "/Library/OpenSC",
        "/usr/local/lib/opensc-pkcs11.so",
        "/Library/CACKey",
        "/usr/lib/pkcs11/cackey.dylib",
    ]
    for path in piv_paths:
        if os.path.exists(path):
            return True

    # 4. Smart card pairing policy (managed configuration)
    try:
        result = subprocess.run(
            ["security", "smartcardctl", "status"],
            capture_output=True, text=True, timeout=5,
        )
        output = result.stdout.lower()
        if "enabled" in output or "paired" in output:
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    return False


def _detect_gov_banner_macos() -> bool:
    """Detect government login banners on macOS."""

    # 1. Login window policy text
    banner_paths = [
        "/Library/Security/PolicyBanner.txt",
        "/Library/Security/PolicyBanner.rtf",
        "/Library/Security/PolicyBanner.rtfd",
    ]
    for path in banner_paths:
        if os.path.exists(path):
            # Read and check for government keywords
            try:
                if os.path.isfile(path):
                    with open(path, "r", errors="replace") as f:
                        content = f.read(4096).lower()
                    if _has_gov_keywords(content):
                        return True
                elif os.path.isdir(path):
                    # .rtfd is a directory
                    return True
            except (PermissionError, OSError):
                # Banner exists but can't read — conservative: flag it
                return True

    # 2. /etc/motd or /etc/issue
    for path in ["/etc/motd", "/etc/issue"]:
        try:
            with open(path, "r", errors="replace") as f:
                content = f.read(4096).lower()
            if _has_gov_keywords(content):
                return True
        except (FileNotFoundError, PermissionError):
            pass

    return False


# ── Windows ──────────────────────────────────────────────────

def _detect_piv_windows() -> bool:
    """Detect PIV/CAC smart card infrastructure on Windows."""

    # 1. Smart card service
    try:
        result = subprocess.run(
            ["sc", "query", "SCardSvr"],
            capture_output=True, text=True, timeout=5,
        )
        if "running" in result.stdout.lower():
            # Service running is common, but check for PIV middleware too
            pass
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    # 2. PIV middleware (ActivClient, 90Meter, HID)
    piv_paths = [
        os.path.join(os.environ.get("PROGRAMFILES", ""), "ActivIdentity"),
        os.path.join(os.environ.get("PROGRAMFILES", ""), "HID Global"),
        os.path.join(os.environ.get("PROGRAMFILES", ""), "90Meter"),
        os.path.join(os.environ.get("PROGRAMFILES", ""), "Charismathics"),
    ]
    for path in piv_paths:
        if path and os.path.isdir(path):
            return True

    # 3. Registry: smart card credential provider configured for login
    try:
        import winreg
        # PIV logon credential provider GUID
        cp_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{94596C7E-3744-41CE-893E-BBF09122F76A}"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, cp_path):
            return True
    except (ImportError, OSError):
        pass

    # 4. DoD certificates in machine store
    try:
        result = subprocess.run(
            ["certutil", "-store", "Root"],
            capture_output=True, text=True, timeout=10,
        )
        output = result.stdout.lower()
        if "dod" in output or "department of defense" in output:
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    return False


def _detect_gov_banner_windows() -> bool:
    """Detect government login banners on Windows."""

    # Registry: legal notice text shown at logon
    try:
        import winreg
        policy_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, policy_path) as key:
            try:
                caption, _ = winreg.QueryValueEx(key, "legalnoticecaption")
                if caption and _has_gov_keywords(caption.lower()):
                    return True
            except OSError:
                pass
            try:
                text, _ = winreg.QueryValueEx(key, "legalnoticetext")
                if text and _has_gov_keywords(text.lower()):
                    return True
            except OSError:
                pass
    except (ImportError, OSError):
        pass

    return False


# ── Shared ───────────────────────────────────────────────────

def _has_gov_keywords(text: str) -> bool:
    """Check text for government/military use notice keywords."""
    indicators = [
        "department of defense",
        "u.s. government",
        "us government",
        "united states government",
        "dod information system",
        "authorized use only",
        "consent to monitoring",
        "you are accessing a u.s. government",
        ".mil",
        ".gov",
        "controlled unclassified",
        "for official use only",
        "fouo",
        "federal computer",
    ]
    return any(indicator in text for indicator in indicators)
