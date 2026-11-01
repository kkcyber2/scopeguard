"""scopeguard — authorization before a scan runs.

ForgeGuard's audit found an unauthenticated scan endpoint and a scope check
that trusted a stored host without re-verifying at dispatch. This is the
missing gate: allowlist, ownership proof, and named consent, plus a resolution
screen so a security product cannot be used as an internal port scanner.

Fail-closed by construction: ``ScopeGuard.evaluate`` returns a ``Decision``
whose ``allowed`` is False unless every gate passes, and the reasons list says
which gate failed. There is no "probably fine" path.
"""

from .guard import (
    Consent,
    Decision,
    Deny,
    OwnershipProof,
    ScopeGuard,
    is_ip_literal,
    is_reserved_address,
    normalize_host,
    within_scope,
)
from .store import Store, default_store

__version__ = "1.0.0"

__all__ = [
    "Consent",
    "Decision",
    "Deny",
    "OwnershipProof",
    "ScopeGuard",
    "Store",
    "default_store",
    "is_ip_literal",
    "is_reserved_address",
    "normalize_host",
    "within_scope",
]
