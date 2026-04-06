"""Environment scanning modules — read-only intelligence gathering."""

from .account import scan_account
from .ai_environment import scan_ai_environment
from .drives import scan_drives
from .resources import scan_resources
from .profile import scan_profile
from .tools import scan_tools


def run_full_scan() -> dict:
    """Run all environment scans. Returns combined results."""
    return {
        "platform": scan_account(),
        "drives": scan_drives(),
        "resources": scan_resources(),
        "user_profile": scan_profile(),
        "tools": scan_tools(),
        "ai_environment": scan_ai_environment(),
    }
