"""Domain join and SAML/SSO detection.

Detects: Active Directory membership, Azure AD join,
enterprise SSO agents (Okta, Ping, OneLogin).

Hard gate: domain-joined machines are organizationally owned.
SAML/SSO presence indicates enterprise identity management.
"""

import os
import platform
import subprocess


def detect_domain_join() -> bool:
    """Returns True if machine is joined to any domain (AD, Azure AD)."""
    system = platform.system()
    if system == "Darwin":
        return _detect_domain_macos()
    elif system == "Windows":
        return _detect_domain_windows()
    return False


def detect_saml_sso() -> bool:
    """Returns True if enterprise SSO/SAML agents are detected."""
    system = platform.system()
    if system == "Darwin":
        return _detect_sso_macos()
    elif system == "Windows":
        return _detect_sso_windows()
    return False


# ── macOS ────────────────────────────────────────────────────

def _detect_domain_macos() -> bool:
    """Detect AD/directory binding on macOS."""

    # 1. dsconfigad — Active Directory binding
    try:
        result = subprocess.run(
            ["dsconfigad", "-show"],
            capture_output=True, text=True, timeout=10,
        )
        output = result.stdout.lower()
        # If AD is configured, output contains "Active Directory Domain"
        if "active directory" in output and "domain" in output:
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    # 2. dscl — check for network directory nodes
    try:
        result = subprocess.run(
            ["dscl", "-list", "/"],
            capture_output=True, text=True, timeout=10,
        )
        output = result.stdout
        # Network-bound directories beyond Local and Contact
        network_indicators = ["Active Directory", "LDAPv3", "BSD"]
        for indicator in network_indicators:
            if indicator in output:
                return True
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    # 3. Kerberos ticket cache (indicates domain auth)
    try:
        result = subprocess.run(
            ["klist"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and "principal" in result.stdout.lower():
            # Has valid Kerberos tickets — likely domain-authenticated
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    return False


def _detect_sso_macos() -> bool:
    """Detect enterprise SSO agents on macOS."""

    # Known SSO agent application paths
    sso_paths = [
        "/Applications/Okta Verify.app",
        "/Library/Application Support/Okta",
        "/Applications/Microsoft Authenticator.app",
        "/Library/Application Support/com.apple.SSOExtension",
        "/Applications/Ping Identity.app",
        "/Applications/OneLogin.app",
        "/Applications/Duo Mobile.app",
    ]
    for path in sso_paths:
        if os.path.exists(path):
            return True

    # Kerberos SSO extension (Apple Enterprise SSO)
    sso_extension_dir = "/Library/Managed Preferences"
    if os.path.isdir(sso_extension_dir):
        try:
            for entry in os.listdir(sso_extension_dir):
                if "sso" in entry.lower() or "kerberos" in entry.lower():
                    return True
        except PermissionError:
            pass

    # Platform SSO configuration
    try:
        result = subprocess.run(
            ["app-sso", "-l", "--json"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip() not in ("", "[]", "{}"):
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    return False


# ── Windows ──────────────────────────────────────────────────

def _detect_domain_windows() -> bool:
    """Detect AD/Azure AD join on Windows."""

    # 1. dsregcmd — definitive domain join status
    try:
        result = subprocess.run(
            ["dsregcmd", "/status"],
            capture_output=True, text=True, timeout=10,
        )
        output = result.stdout.lower()
        # Check for any domain join type
        if "domainjoined : yes" in output.replace(" ", ""):
            return True
        if "azureadjoined : yes" in output.replace(" ", ""):
            return True
        if "enterprisejoined : yes" in output.replace(" ", ""):
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    # 2. Environment variable check
    userdomain = os.environ.get("USERDOMAIN", "")
    computername = os.environ.get("COMPUTERNAME", "")
    # If USERDOMAIN differs from COMPUTERNAME, machine is domain-joined
    if userdomain and computername and userdomain.upper() != computername.upper():
        return True

    # 3. systeminfo domain field
    try:
        result = subprocess.run(
            ["systeminfo"],
            capture_output=True, text=True, timeout=15,
        )
        for line in result.stdout.splitlines():
            if line.strip().lower().startswith("domain:"):
                domain_value = line.split(":", 1)[1].strip().lower()
                # "WORKGROUP" is the default non-domain value
                if domain_value and domain_value != "workgroup":
                    return True
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    return False


def _detect_sso_windows() -> bool:
    """Detect enterprise SSO agents on Windows."""

    # Registry: credential providers (SSO extensions)
    try:
        import winreg
        cp_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, cp_path) as key:
            subkey_count = winreg.QueryInfoKey(key)[0]
            # Default Windows has a few; enterprise SSO adds more
            if subkey_count > 8:
                return True
    except (ImportError, OSError):
        pass

    # Known SSO agent processes/services
    sso_indicators = [
        "OktaVerify", "okta", "Ping Identity",
        "OneLogin", "CyberArk", "Thales",
    ]
    # Check installed programs
    program_dirs = [
        os.environ.get("PROGRAMFILES", r"C:\Program Files"),
        os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs"),
    ]
    for prog_dir in program_dirs:
        if not prog_dir or not os.path.isdir(prog_dir):
            continue
        try:
            entries = os.listdir(prog_dir)
            for entry in entries:
                entry_lower = entry.lower()
                if any(sso.lower() in entry_lower for sso in sso_indicators):
                    return True
        except PermissionError:
            pass

    return False
