"""Scope guard: may this target be scanned, by this operator, right now?

Three independent gates, all of which must pass. They are deliberately
separate because they fail differently:

1. **Allowlist**  — is the host one we are permitted to touch at all?
2. **Ownership**  — can the operator *prove* they control the host?
3. **Consent**    — did a named human assert, for this target, that they are
                    authorized to test it?

Collapsing these into one check is how a product ends up treating "the user
typed the domain" as authorization. The audit found exactly that shape of
problem: an unauthenticated endpoint and a scope check that trusted a stored
host without re-verifying at dispatch time.

Threat model this addresses:

* A user scans an arbitrary third-party host because nothing stopped them.
* A user scans a host, then changes the target before the job dispatches.
* A host is allowlisted for one tenant and scanned by another.
* DNS rebinding: a name resolves to an internal address after the check.

What it does not do
-------------------
It does not resolve DNS at check time to detect rebinding *during* a run — a
resolution can change between the check and the request. That is why
``evaluate`` returns the resolved addresses it approved, so the caller can pin
them. If the caller ignores them, rebinding is still possible; that is stated
in limitations rather than papered over.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, List, Optional, Sequence, Set, Tuple


class Deny(str, Enum):
    """Why a target was refused. Stable identifiers, safe to log."""

    NOT_ALLOWLISTED = "not_allowlisted"
    INVALID_HOST = "invalid_host"
    IP_LITERAL_FORBIDDEN = "ip_literal_forbidden"
    RESERVED_ADDRESS = "reserved_address"
    NO_OWNERSHIP_PROOF = "no_ownership_proof"
    OWNERSHIP_EXPIRED = "ownership_expired"
    OWNERSHIP_HOST_MISMATCH = "ownership_host_mismatch"
    NO_CONSENT = "no_consent"
    CONSENT_TARGET_MISMATCH = "consent_target_mismatch"
    CONSENT_EXPIRED = "consent_expired"
    CONSENT_POLICY_STALE = "consent_policy_stale"
    PORT_NOT_ALLOWED = "port_not_allowed"


@dataclass(frozen=True)
class OwnershipProof:
    """Evidence the operator controls a host.

    ``method`` records *how* it was proven so a reviewer can judge whether the
    method is adequate for the target — a DNS TXT record is fine for
    example.com and useless for a host whose DNS you do not control.
    """

    host: str
    method: str            # "dns-txt" | "http-file" | "manual-review"
    verified_at: float     # unix seconds
    verified_by: str = ""  # who attested, for manual-review

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "method": self.method,
            "verified_at": self.verified_at,
            "verified_by": self.verified_by,
        }


@dataclass(frozen=True)
class Consent:
    """A named human asserting authorization for one target."""

    signer: str
    signer_email: str
    target: str
    asserted_at: float
    policy_version: str
    # Free-text of what they agreed to. Stored so a dispute has a record.
    statement: str = ""
    # Per-consent validity. 0 means "use the guard's default".
    #
    # This exists because without it a caller could write ``--days 7``, have the
    # CLI print a seven-day expiry, and still get a ninety-day window from the
    # guard's default. A UI that states an expiry the enforcement layer does
    # not honour is worse than no UI at all.
    ttl_s: int = 0

    def to_dict(self) -> dict:
        return {
            "signer": self.signer,
            "signer_email": self.signer_email,
            "target": self.target,
            "asserted_at": self.asserted_at,
            "policy_version": self.policy_version,
            "statement": self.statement,
            "ttl_s": self.ttl_s,
        }


@dataclass
class Decision:
    """The guard's verdict, with every reason it has."""

    allowed: bool
    reasons: List[Deny] = field(default_factory=list)
    detail: str = ""
    resolved: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "reasons": [r.value for r in self.reasons],
            "detail": self.detail,
            "resolved": list(self.resolved),
        }


# Hosts that must never be scan targets regardless of allowlist. Anything that
# resolves inside a private range is included because a security product should
# not be usable as an internal port scanner by a remote customer.
_RESERVED_NETS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

_HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?:\.(?!-)[a-z0-9-]{1,63})*\.?$", re.I
)

DEFAULT_CONSENT_TTL_S = 60 * 60 * 24 * 90   # 90 days
DEFAULT_OWNERSHIP_TTL_S = 60 * 60 * 24 * 30  # 30 days


def normalize_host(value: str) -> Optional[str]:
    """Canonicalise a host. Returns None when it cannot be a valid hostname.

    Mirrors ForgeGuard's own ``normalizeHost`` semantics so the two agree:
    lowercase, strip one trailing dot, strip a leading ``www.``, drop default
    ports. Agreement matters — a guard that normalises differently from the
    scanner is a guard with a bypass.
    """
    raw = (value or "").strip()
    if not raw:
        return None
    if raw.startswith("["):  # bracketed IPv6
        return raw.strip("[]").lower() or None
    # Strip scheme and path if a URL was passed.
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    raw = raw.split("/", 1)[0]
    raw = raw.rsplit("@", 1)[-1]  # drop userinfo
    raw = re.sub(r":(\d+)$", "", raw)  # drop port
    raw = raw.lower().rstrip(".")
    raw = re.sub(r"^www\.", "", raw)
    if not raw:
        return None
    return raw


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def is_reserved_address(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return True  # unparseable is not safe
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
        return True
    return any(ip in net for net in _RESERVED_NETS)


def within_scope(target_host: str, verified_host: str) -> bool:
    """True when ``target_host`` is the verified host or a subdomain of it.

    The ``.`` guard matters: ``notexample.com`` must not match ``example.com``.
    """
    t = normalize_host(target_host)
    v = normalize_host(verified_host)
    if not t or not v:
        return False
    return t == v or t.endswith(f".{v}")


class ScopeGuard:
    """Evaluates the three gates in order and reports every failure."""

    def __init__(
        self,
        *,
        allowlist: Iterable[str] = (),
        allowed_ports: Sequence[int] = (443, 8443),
        consent_ttl_s: int = DEFAULT_CONSENT_TTL_S,
        ownership_ttl_s: int = DEFAULT_OWNERSHIP_TTL_S,
        require_ownership: bool = True,
        require_consent: bool = True,
        policy_version: str = "2026-11",
        forbid_ip_literals: bool = True,
        resolver: Optional[object] = None,
    ) -> None:
        self.allowlist: Set[str] = {h for h in (normalize_host(a) for a in allowlist) if h}
        self.allowed_ports = tuple(allowed_ports)
        self.consent_ttl_s = consent_ttl_s
        self.ownership_ttl_s = ownership_ttl_s
        self.require_ownership = require_ownership
        self.require_consent = require_consent
        self.policy_version = policy_version
        self.forbid_ip_literals = forbid_ip_literals
        # Injectable so tests never touch real DNS.
        self.resolver = resolver or socket.getaddrinfo

    # ------------------------------------------------------------------ #
    # Main entry                                                         #
    # ------------------------------------------------------------------ #

    def evaluate(
        self,
        target: str,
        *,
        port: int = 443,
        now: float,
        ownership: Optional[OwnershipProof] = None,
        consents: Sequence[Consent] = (),
    ) -> Decision:
        """Decide whether the scan may proceed.

        Evaluates *all* gates rather than returning at the first failure, so
        the operator sees everything wrong at once instead of fixing one
        problem per attempt.
        """
        reasons: List[Deny] = []
        host = normalize_host(target)
        if not host or not (_HOST_RE.match(host) or is_ip_literal(host)):
            return Decision(False, [Deny.INVALID_HOST], f"{target!r} is not a valid host")

        if port not in self.allowed_ports:
            reasons.append(Deny.PORT_NOT_ALLOWED)

        # ---- gate 1: allowlist -----------------------------------------
        if is_ip_literal(host) and self.forbid_ip_literals:
            reasons.append(Deny.IP_LITERAL_FORBIDDEN)
        elif not any(within_scope(host, allowed) for allowed in self.allowlist):
            reasons.append(Deny.NOT_ALLOWLISTED)

        # ---- gate 2: ownership -----------------------------------------
        if self.require_ownership:
            if ownership is None:
                reasons.append(Deny.NO_OWNERSHIP_PROOF)
            else:
                if not within_scope(host, ownership.host):
                    reasons.append(Deny.OWNERSHIP_HOST_MISMATCH)
                age = now - ownership.verified_at
                if age > self.ownership_ttl_s or age < 0:
                    reasons.append(Deny.OWNERSHIP_EXPIRED)

        # ---- gate 3: consent -------------------------------------------
        if self.require_consent:
            if not consents:
                reasons.append(Deny.NO_CONSENT)
            else:
                matching = [c for c in consents if within_scope(host, c.target)]
                if not matching:
                    reasons.append(Deny.CONSENT_TARGET_MISMATCH)
                else:
                    live = [
                        c
                        for c in matching
                        if 0 <= (now - c.asserted_at) <= (c.ttl_s or self.consent_ttl_s)
                    ]
                    if not live:
                        reasons.append(Deny.CONSENT_EXPIRED)
                    elif not any(c.policy_version == self.policy_version for c in live):
                        reasons.append(Deny.CONSENT_POLICY_STALE)

        # ---- resolution guard ------------------------------------------
        resolved: List[str] = []
        if not reasons:
            resolved, bad = self._resolve_and_screen(host)
            if bad:
                reasons.append(Deny.RESERVED_ADDRESS)

        if reasons:
            return Decision(
                False,
                sorted(set(reasons), key=lambda r: r.value),
                self._explain(reasons, host),
            )
        return Decision(True, [], f"{host}:{port} is in scope", resolved)

    # ------------------------------------------------------------------ #
    # Helpers                                                            #
    # ------------------------------------------------------------------ #

    def _resolve_and_screen(self, host: str) -> Tuple[List[str], bool]:
        """Resolve and reject if any address is reserved.

        Any bad address is fatal rather than filtering out the good ones: a
        host that resolves to one public and one internal address is exactly
        the rebinding pattern worth refusing.
        """
        if is_ip_literal(host):
            return ([host], is_reserved_address(host))
        try:
            infos = self.resolver(host, 443, type=socket.SOCK_STREAM)
        except (socket.gaierror, OSError):
            # Unresolvable is not a scope failure; the scan will simply fail.
            return ([], False)
        addrs: List[str] = []
        for info in infos:
            try:
                addr = info[4][0]
            except (IndexError, TypeError):
                continue
            if addr not in addrs:
                addrs.append(addr)
        bad = any(is_reserved_address(a) for a in addrs)
        return (addrs, bad)

    @staticmethod
    def _explain(reasons: List[Deny], host: str) -> str:
        parts = []
        for r in sorted(set(reasons), key=lambda x: x.value):
            parts.append(_EXPLAIN.get(r, r.value).format(host=host))
        return " ".join(parts)


_EXPLAIN = {
    Deny.NOT_ALLOWLISTED: "{host} is not on the allowlist for this tenant.",
    Deny.INVALID_HOST: "{host} is not a valid hostname.",
    Deny.IP_LITERAL_FORBIDDEN: (
        "{host} is a bare IP address; scan a hostname so ownership can be proven."
    ),
    Deny.RESERVED_ADDRESS: (
        "{host} resolves to a private, loopback or otherwise reserved address."
    ),
    Deny.NO_OWNERSHIP_PROOF: "{host} has no ownership proof on file.",
    Deny.OWNERSHIP_EXPIRED: "the ownership proof for {host} has expired.",
    Deny.OWNERSHIP_HOST_MISMATCH: (
        "the ownership proof on file is for a different host than {host}."
    ),
    Deny.NO_CONSENT: "no authorization has been asserted for {host}.",
    Deny.CONSENT_TARGET_MISMATCH: (
        "authorization on file covers a different target than {host}."
    ),
    Deny.CONSENT_EXPIRED: "the authorization for {host} has expired.",
    Deny.CONSENT_POLICY_STALE: (
        "the authorization for {host} was given under an older policy version."
    ),
    Deny.PORT_NOT_ALLOWED: "the requested port is not in the allowed set.",
}
