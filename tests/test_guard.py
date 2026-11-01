"""Scope guard tests.

The point of these is not to show the happy path works. It is to show the
refusals hold against a user who is trying to get around them.
"""

from __future__ import annotations

import time

import pytest

from scopeguard.guard import (
    Consent,
    Deny,
    OwnershipProof,
    ScopeGuard,
    is_reserved_address,
    normalize_host,
    within_scope,
)

NOW = 1_800_000_000.0


def _resolver(mapping):
    """A fake getaddrinfo: host -> list of addresses, or raises if absent."""
    import socket

    def _r(host, port, **kw):
        if host not in mapping:
            raise socket.gaierror("NXDOMAIN")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port)) for a in mapping[host]]

    return _r


PUBLIC = _resolver({"app.example.com": ["93.184.216.34"], "example.com": ["93.184.216.34"]})


def _guard(**kw):
    defaults = dict(
        allowlist=["example.com"],
        resolver=PUBLIC,
        policy_version="2026-11",
    )
    defaults.update(kw)
    return ScopeGuard(**defaults)


def _own(host="example.com", at=None, age=3600):
    return OwnershipProof(
        host=host, method="dns-txt", verified_at=(at or NOW) - age
    )


def _consent(target="example.com", at=None, age=3600, policy="2026-11"):
    return Consent(
        signer="A. Client",
        signer_email="a@client.example",
        target=target,
        asserted_at=(at or NOW) - age,
        policy_version=policy,
    )


# --------------------------------------------------------------------------- #
# Normalisation — must agree with ForgeGuard's normalizeHost                  #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("Example.COM", "example.com"),
        ("www.example.com", "example.com"),
        ("example.com.", "example.com"),
        ("https://example.com/path", "example.com"),
        ("example.com:443", "example.com"),
        ("user@example.com", "example.com"),
        ("  example.com  ", "example.com"),
        ("app.example.com", "app.example.com"),
    ],
)
def test_normalize_host(raw, expected):
    assert normalize_host(raw) == expected


def test_normalize_rejects_empty():
    assert normalize_host("") is None
    assert normalize_host("   ") is None


def test_within_scope_rejects_suffix_lookalike():
    # The classic bug: naive endswith matches the attacker's domain.
    assert within_scope("notexample.com", "example.com") is False
    assert within_scope("example.com.evil.com", "example.com") is False


def test_within_scope_accepts_subdomain():
    assert within_scope("app.example.com", "example.com") is True
    assert within_scope("a.b.example.com", "example.com") is True


# --------------------------------------------------------------------------- #
# Gate 1: allowlist                                                           #
# --------------------------------------------------------------------------- #


def test_happy_path_allows():
    d = _guard().evaluate(
        "app.example.com", now=NOW, ownership=_own(), consents=[_consent()]
    )
    assert d.allowed is True
    assert d.reasons == []
    assert d.resolved == ["93.184.216.34"]


def test_unlisted_host_is_refused():
    d = _guard().evaluate(
        "other.test", now=NOW, ownership=_own("other.test"), consents=[_consent("other.test")]
    )
    assert d.allowed is False
    assert Deny.NOT_ALLOWLISTED in d.reasons


def test_subdomain_of_allowlisted_apex_is_allowed():
    d = _guard().evaluate(
        "deep.app.example.com", now=NOW, ownership=_own(), consents=[_consent()]
    )
    # Ownership/consent for the apex cover it; the resolver returns no address
    # for the deep name, which is not a scope failure.
    assert d.allowed is True


def test_bare_ip_is_refused():
    d = _guard().evaluate(
        "93.184.216.34", now=NOW, ownership=_own("93.184.216.34"), consents=[_consent("93.184.216.34")]
    )
    assert d.allowed is False
    assert Deny.IP_LITERAL_FORBIDDEN in d.reasons


def test_invalid_host_is_refused_early():
    d = _guard().evaluate("not a host!", now=NOW)
    assert d.allowed is False
    assert d.reasons == [Deny.INVALID_HOST]


def test_port_outside_allowlist_is_refused():
    d = _guard().evaluate(
        "app.example.com", port=22, now=NOW, ownership=_own(), consents=[_consent()]
    )
    assert d.allowed is False
    assert Deny.PORT_NOT_ALLOWED in d.reasons


# --------------------------------------------------------------------------- #
# Gate 2: ownership                                                           #
# --------------------------------------------------------------------------- #


def test_missing_ownership_refused():
    d = _guard(require_consent=False).evaluate("app.example.com", now=NOW)
    assert d.allowed is False
    assert Deny.NO_OWNERSHIP_PROOF in d.reasons


def test_ownership_for_wrong_host_refused():
    d = _guard(require_consent=False).evaluate(
        "app.example.com", now=NOW, ownership=_own("other.test")
    )
    assert d.allowed is False
    assert Deny.OWNERSHIP_HOST_MISMATCH in d.reasons


def test_expired_ownership_refused():
    # 60 days old against a 30-day TTL.
    d = _guard(require_consent=False).evaluate(
        "app.example.com", now=NOW, ownership=_own(age=60 * 86400)
    )
    assert d.allowed is False
    assert Deny.OWNERSHIP_EXPIRED in d.reasons


def test_future_dated_ownership_refused():
    # A proof dated in the future is a clock problem or a forgery; both refuse.
    d = _guard(require_consent=False).evaluate(
        "app.example.com", now=NOW, ownership=_own(age=-3600)
    )
    assert Deny.OWNERSHIP_EXPIRED in d.reasons


# --------------------------------------------------------------------------- #
# Gate 3: consent                                                             #
# --------------------------------------------------------------------------- #


def test_missing_consent_refused():
    d = _guard(require_ownership=False).evaluate("app.example.com", now=NOW)
    assert d.allowed is False
    assert Deny.NO_CONSENT in d.reasons


def test_consent_for_wrong_target_refused():
    d = _guard(require_ownership=False).evaluate(
        "app.example.com", now=NOW, consents=[_consent("other.test")]
    )
    assert d.allowed is False
    assert Deny.CONSENT_TARGET_MISMATCH in d.reasons


def test_expired_consent_refused():
    d = _guard(require_ownership=False).evaluate(
        "app.example.com", now=NOW, consents=[_consent(age=200 * 86400)]
    )
    assert d.allowed is False
    assert Deny.CONSENT_EXPIRED in d.reasons


def test_stale_policy_version_refused():
    d = _guard(require_ownership=False).evaluate(
        "app.example.com", now=NOW, consents=[_consent(policy="2024-01")]
    )
    assert d.allowed is False
    assert Deny.CONSENT_POLICY_STALE in d.reasons


def test_one_live_consent_among_expired_is_enough():
    d = _guard(require_ownership=False).evaluate(
        "app.example.com",
        now=NOW,
        consents=[_consent(age=200 * 86400), _consent(age=60)],
    )
    # The expired one is ignored; the fresh one carries.
    assert d.allowed is True


# --------------------------------------------------------------------------- #
# Resolution screen — SSRF / rebinding                                        #
# --------------------------------------------------------------------------- #


def test_host_resolving_to_loopback_refused():
    guard = _guard(allowlist=["internal.test"], resolver=_resolver({"internal.test": ["127.0.0.1"]}))
    d = guard.evaluate(
        "internal.test", now=NOW, ownership=_own("internal.test"), consents=[_consent("internal.test")]
    )
    assert d.allowed is False
    assert Deny.RESERVED_ADDRESS in d.reasons


def test_host_resolving_to_rfc1918_refused():
    guard = _guard(allowlist=["internal.test"], resolver=_resolver({"internal.test": ["10.1.2.3"]}))
    d = guard.evaluate(
        "internal.test", now=NOW, ownership=_own("internal.test"), consents=[_consent("internal.test")]
    )
    assert d.allowed is False
    assert Deny.RESERVED_ADDRESS in d.reasons


def test_metadata_endpoint_refused():
    # 169.254.169.254 — the cloud metadata service. The single highest-value
    # SSRF target there is.
    guard = _guard(
        allowlist=["meta.test"], resolver=_resolver({"meta.test": ["169.254.169.254"]})
    )
    d = guard.evaluate(
        "meta.test", now=NOW, ownership=_own("meta.test"), consents=[_consent("meta.test")]
    )
    assert d.allowed is False
    assert Deny.RESERVED_ADDRESS in d.reasons


def test_mixed_public_and_private_refused():
    """Any private address in the answer set is fatal, not filtered out."""
    guard = _guard(
        allowlist=["mixed.test"],
        resolver=_resolver({"mixed.test": ["93.184.216.34", "10.0.0.5"]}),
    )
    d = guard.evaluate(
        "mixed.test", now=NOW, ownership=_own("mixed.test"), consents=[_consent("mixed.test")]
    )
    assert d.allowed is False
    assert Deny.RESERVED_ADDRESS in d.reasons


def test_unresolvable_host_is_not_a_scope_failure():
    d = _guard().evaluate(
        "nx.example.com", now=NOW, ownership=_own(), consents=[_consent()]
    )
    # It is in scope; it just does not resolve. The scan will fail on its own.
    assert d.allowed is True
    assert d.resolved == []


def test_resolution_skipped_when_another_gate_failed():
    """No DNS traffic for a target we already refuse."""
    class _Exploding:
        def __call__(self, *a, **kw):
            raise AssertionError("resolver consulted for an already-refused target")

    d = _guard(resolver=_Exploding()).evaluate("elsewhere.test", now=NOW)
    assert d.allowed is False


@pytest.mark.parametrize(
    "addr",
    ["127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1", "169.254.169.254",
     "0.0.0.0", "::1", "fc00::1", "fe80::1", "224.0.0.1"],
)
def test_reserved_addresses(addr):
    assert is_reserved_address(addr) is True


@pytest.mark.parametrize("addr", ["8.8.8.8", "93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"])
def test_public_addresses(addr):
    assert is_reserved_address(addr) is False


# --------------------------------------------------------------------------- #
# Reporting                                                                   #
# --------------------------------------------------------------------------- #


def test_all_failures_reported_together():
    """An operator should not fix one problem per attempt."""
    d = _guard().evaluate("elsewhere.test", now=NOW)
    assert Deny.NOT_ALLOWLISTED in d.reasons
    assert Deny.NO_OWNERSHIP_PROOF in d.reasons
    assert Deny.NO_CONSENT in d.reasons
    assert len(d.reasons) >= 3


def test_decision_is_serialisable_and_explains_itself():
    d = _guard().evaluate("elsewhere.test", now=NOW)
    payload = d.to_dict()
    assert payload["allowed"] is False
    assert "not_allowlisted" in payload["reasons"]
    assert "allowlist" in d.detail  # human-readable


def test_reasons_are_deduplicated_and_sorted():
    d = _guard().evaluate("bad host!", now=NOW)
    assert d.reasons == sorted(set(d.reasons), key=lambda r: r.value)


# --------------------------------------------------------------------------- #
# Optional gates                                                              #
# --------------------------------------------------------------------------- #


def test_gates_can_be_disabled_for_internal_use():
    g = _guard(require_ownership=False, require_consent=False)
    d = g.evaluate("app.example.com", now=NOW)
    assert d.allowed is True


def test_allowlist_alone_still_blocks_strangers():
    g = _guard(require_ownership=False, require_consent=False)
    assert g.evaluate("stranger.test", now=NOW).allowed is False


class TestPerConsentTTL:
    """A consent's stated expiry must be the expiry that is enforced.

    Regression: the CLI accepted --days 7, printed a seven-day expiry, and the
    guard still used its 90-day default because the value was never stored.
    """

    def test_short_ttl_is_enforced_not_the_default(self):
        now = 1_000_000.0
        c = Consent(
            signer="A", signer_email="a@x", target="example.com",
            asserted_at=now, policy_version="2026-11", ttl_s=7 * 86400,
        )
        g = ScopeGuard(
            allowlist=["example.com"], policy_version="2026-11",
            resolver=lambda *a, **k: [], require_ownership=False,
        )
        # Day 10: past the stated 7-day window, inside the 90-day default.
        d = g.evaluate("example.com", now=now + 10 * 86400, consents=[c])
        assert d.allowed is False
        assert Deny.CONSENT_EXPIRED in d.reasons

    def test_short_ttl_allows_inside_window(self):
        now = 1_000_000.0
        c = Consent(
            signer="A", signer_email="a@x", target="example.com",
            asserted_at=now, policy_version="2026-11", ttl_s=7 * 86400,
        )
        g = ScopeGuard(
            allowlist=["example.com"], policy_version="2026-11",
            resolver=lambda *a, **k: [], require_ownership=False,
        )
        d = g.evaluate("example.com", now=now + 3 * 86400, consents=[c])
        assert d.allowed is True

    def test_zero_ttl_falls_back_to_guard_default(self):
        now = 1_000_000.0
        c = Consent(
            signer="A", signer_email="a@x", target="example.com",
            asserted_at=now, policy_version="2026-11", ttl_s=0,
        )
        g = ScopeGuard(
            allowlist=["example.com"], policy_version="2026-11",
            resolver=lambda *a, **k: [], require_ownership=False,
        )
        assert g.evaluate("example.com", now=now + 30 * 86400, consents=[c]).allowed is True


class TestTTLPersistsThroughStore:
    def test_roundtrip_keeps_ttl(self, tmp_path):
        from scopeguard.store import Store
        s = Store(str(tmp_path / "s.db"))
        now = 1_000_000.0
        s.add_consent("t1", Consent(
            signer="A", signer_email="a@x", target="example.com",
            asserted_at=now, policy_version="2026-11", ttl_s=3600,
        ))
        got = s.live_consents("t1", "example.com")
        assert len(got) == 1
        assert got[0].ttl_s == 3600
        s.close()
