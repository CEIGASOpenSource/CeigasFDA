"""Hard gate detectors — structural rejection signals."""

from .mdm import detect_mdm
from .domain import detect_domain_join, detect_saml_sso
from .gov import detect_piv_cac, detect_gov_banner
from .hypervisor import detect_hypervisor


def run_all_gates() -> dict:
    """Run all hard gate checks. Returns dict with each gate result and verdict."""
    gates = {
        "mdm": detect_mdm(),
        "saml_sso": detect_saml_sso(),
        "piv_cac": detect_piv_cac(),
        "gov_banner": detect_gov_banner(),
        "domain_joined": detect_domain_join(),
        "hypervisor": detect_hypervisor(),
    }
    gates["verdict"] = "REJECT" if any(gates.values()) else "CLEAN"
    return gates
