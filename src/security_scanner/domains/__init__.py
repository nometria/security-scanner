"""
Domain registry - discovers and manages scan domains.

Domains can be registered in two ways:

1. **Built-in** - imported directly in this module.
2. **Plugin** - third-party packages declare an entry point under the group
   ``ai_security_scan.domains`` and are discovered at runtime via
   ``importlib.metadata``.
"""

from typing import Dict, List, Optional, Type

from .base import Domain, DomainResult

__all__ = ["Domain", "DomainResult", "register_domain", "get_domain",
           "get_all_domains", "discover_domains"]

_REGISTRY: Dict[str, Type[Domain]] = {}


def register_domain(name: str, cls: Type[Domain]) -> None:
    """Register a domain class under *name*."""
    _REGISTRY[name] = cls


def get_domain(name: str) -> Optional[Domain]:
    """Instantiate and return a domain by name, or *None* if unknown."""
    cls = _REGISTRY.get(name)
    if cls is None:
        return None
    return cls()


def get_all_domains() -> Dict[str, Domain]:
    """Return a dict of ``{name: instance}`` for every registered domain."""
    return {name: cls() for name, cls in _REGISTRY.items()}


def discover_domains() -> List[str]:
    """Load plugin domains from ``ai_security_scan.domains`` entry points.

    Returns the list of newly-discovered domain names.
    """
    discovered: List[str] = []
    try:
        from importlib.metadata import entry_points

        # Python 3.12+ returns SelectableGroups; 3.9 returns a dict
        eps = entry_points()
        if isinstance(eps, dict):
            group = eps.get("ai_security_scan.domains", [])
        else:
            group = eps.select(group="ai_security_scan.domains")

        for ep in group:
            if ep.name not in _REGISTRY:
                cls = ep.load()
                register_domain(ep.name, cls)
                discovered.append(ep.name)
    except Exception:
        pass  # graceful degradation
    return discovered


# ── Register built-in domains ────────────────────────────────────────────────
# Core domains (always registered):
from .builtin import BuiltinSecurityDomain  # noqa: E402
from .lint import LintDomain  # noqa: E402
from .sca import ScaDomain  # noqa: E402

register_domain("security", BuiltinSecurityDomain)
register_domain("lint", LintDomain)
register_domain("sca", ScaDomain)

# Optional domains (registered but only run when tools are available):
from .typecheck import TypeCheckDomain  # noqa: E402
from .sast import SastDomain  # noqa: E402
from .iac import IacDomain  # noqa: E402
from .container import ContainerDomain  # noqa: E402
from .compliance import ComplianceDomain  # noqa: E402

register_domain("typecheck", TypeCheckDomain)
register_domain("sast", SastDomain)
register_domain("iac", IacDomain)
register_domain("container", ContainerDomain)

# Compliance domain (HIPAA / SOC 2 / OWASP / FedRAMP). Always-on like the
# built-in security rules - it has zero external tool deps beyond what's
# already in the scanner package (rich/click/regex/jinja2 are listed in
# pyproject as required for the merged package).
register_domain("compliance", ComplianceDomain)
