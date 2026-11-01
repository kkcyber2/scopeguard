"""Store tests: tenant isolation, append-only revocation, TTL roundtrip."""

from __future__ import annotations

import time

import pytest

from scopeguard.guard import Consent, ScopeGuard
from scopeguard.store import Store


@pytest.fixture()
def store(tmp_path):
    s = Store(str(tmp_path / "scope.db"))
    yield s
    s.close()


def _consent(target="example.com", ttl_s=0, signer="A. Client"):
    return Consent(
        signer=signer,
        signer_email="a@client.example",
        target=target,
        asserted_at=time.time(),
        policy_version="2026-11",
        statement="We authorize this assessment.",
        ttl_s=ttl_s,
    )


# --------------------------------------------------------------------------- #
# Allowlist                                                                   #
# --------------------------------------------------------------------------- #


def test_allow_and_list(store):
    store.add_allow("acme", "Example.com")
    assert store.allowlist("acme") == ["example.com"]


def test_allow_normalises_and_dedupes(store):
    store.add_allow("acme", "www.example.com")
    store.add_allow("acme", "https://example.com/path")
    assert store.allowlist("acme") == ["example.com"]


def test_allow_rejects_empty_host(store):
    with pytest.raises(ValueError):
        store.add_allow("acme", "   ")


def test_remove_allow(store):
    store.add_allow("acme", "example.com")
    assert store.remove_allow("acme", "example.com") is True
    assert store.allowlist("acme") == []
    assert store.remove_allow("acme", "example.com") is False


# --------------------------------------------------------------------------- #
# Tenant isolation                                                            #
# --------------------------------------------------------------------------- #


def test_allowlist_is_per_tenant(store):
    store.add_allow("acme", "example.com")
    store.add_allow("globex", "globex.test")
    assert store.allowlist("acme") == ["example.com"]
    assert store.allowlist("globex") == ["globex.test"]


def test_consent_is_not_visible_across_tenants(store):
    """The core isolation guarantee: guessing a hostname is not access."""
    store.add_consent("acme", _consent("example.com"))
    assert len(store.live_consents("acme", "example.com")) == 1
    assert store.live_consents("globex", "example.com") == []


def test_ownership_is_not_visible_across_tenants(store):
    store.add_ownership("acme", "example.com", "dns-txt")
    assert store.latest_ownership("acme", "example.com") is not None
    assert store.latest_ownership("globex", "example.com") is None


def test_decisions_are_per_tenant(store):
    store.record_decision("acme", "example.com", False, ["no_consent"])
    assert len(store.decisions("acme")) == 1
    assert store.decisions("globex") == []


# --------------------------------------------------------------------------- #
# Ownership                                                                   #
# --------------------------------------------------------------------------- #


def test_apex_ownership_covers_subdomain(store):
    store.add_ownership("acme", "example.com", "dns-txt", evidence="TXT record")
    proof = store.latest_ownership("acme", "app.example.com")
    assert proof is not None
    assert proof.host == "example.com"


def test_subdomain_ownership_does_not_cover_apex(store):
    store.add_ownership("acme", "app.example.com", "dns-txt")
    assert store.latest_ownership("acme", "example.com") is None


def test_suffix_lookalike_is_not_covered(store):
    store.add_ownership("acme", "example.com", "dns-txt")
    assert store.latest_ownership("acme", "notexample.com") is None


def test_latest_ownership_wins(store):
    store.add_ownership("acme", "example.com", "dns-txt", verified_at=1000.0)
    store.add_ownership("acme", "example.com", "http-file", verified_at=2000.0)
    proof = store.latest_ownership("acme", "example.com")
    assert proof.method == "http-file"
    assert proof.verified_at == 2000.0


# --------------------------------------------------------------------------- #
# Consent: append-only                                                        #
# --------------------------------------------------------------------------- #


def test_revocation_hides_but_keeps_the_row(store):
    cid = store.add_consent("acme", _consent())
    assert len(store.live_consents("acme", "example.com")) == 1
    assert store.revoke_consent("acme", cid) is True
    assert store.live_consents("acme", "example.com") == []
    # The row survives, with revoked_at set — an auditor needs the history.
    row = store._conn.execute("SELECT * FROM consent WHERE id=?", (cid,)).fetchone()
    assert row is not None
    assert row["revoked_at"] is not None
    assert row["signer"] == "A. Client"


def test_revoke_is_idempotent(store):
    cid = store.add_consent("acme", _consent())
    assert store.revoke_consent("acme", cid) is True
    assert store.revoke_consent("acme", cid) is False


def test_cannot_revoke_another_tenants_consent(store):
    cid = store.add_consent("acme", _consent())
    assert store.revoke_consent("globex", cid) is False
    assert len(store.live_consents("acme", "example.com")) == 1


def test_ttl_survives_the_roundtrip(store):
    store.add_consent("acme", _consent(ttl_s=3600))
    got = store.live_consents("acme", "example.com")
    assert got[0].ttl_s == 3600


def test_consent_for_apex_applies_to_subdomain(store):
    store.add_consent("acme", _consent("example.com"))
    assert len(store.live_consents("acme", "app.example.com")) == 1


def test_consent_for_subdomain_does_not_apply_to_apex(store):
    store.add_consent("acme", _consent("app.example.com"))
    assert store.live_consents("acme", "example.com") == []


# --------------------------------------------------------------------------- #
# Audit trail                                                                 #
# --------------------------------------------------------------------------- #


def test_decisions_are_recorded_in_reverse_order(store):
    store.record_decision("acme", "a.test", False, ["no_consent"])
    time.sleep(0.01)
    store.record_decision("acme", "b.test", True, [])
    rows = store.decisions("acme")
    assert [r["target"] for r in rows] == ["b.test", "a.test"]


def test_decision_reasons_roundtrip_as_a_list(store):
    store.record_decision("acme", "a.test", False, ["not_allowlisted", "no_consent"])
    row = store.decisions("acme")[0]
    assert row["reasons"] == ["not_allowlisted", "no_consent"]
    assert row["allowed"] is False


def test_stats_count_what_they_say(store):
    store.add_allow("acme", "example.com")
    store.add_ownership("acme", "example.com", "dns-txt")
    store.add_consent("acme", _consent())
    s = store.stats("acme")
    assert s == {"allowlist": 1, "verified_hosts": 1, "live_consents": 1}


def test_revoked_consent_not_counted_in_stats(store):
    cid = store.add_consent("acme", _consent())
    store.revoke_consent("acme", cid)
    assert store.stats("acme")["live_consents"] == 0


# --------------------------------------------------------------------------- #
# Store + guard together                                                      #
# --------------------------------------------------------------------------- #


def test_end_to_end_refuse_then_allow(store):
    """The whole point: a target goes from refused to allowed only by adding
    the three records."""
    def check():
        guard = ScopeGuard(
            allowlist=store.allowlist("acme"),
            policy_version="2026-11",
            resolver=lambda *a, **k: [],
        )
        return guard.evaluate(
            "app.example.com",
            now=time.time(),
            ownership=store.latest_ownership("acme", "app.example.com"),
            consents=store.live_consents("acme", "app.example.com"),
        )

    assert check().allowed is False
    store.add_allow("acme", "example.com")
    assert check().allowed is False
    store.add_ownership("acme", "example.com", "dns-txt")
    assert check().allowed is False
    store.add_consent("acme", _consent("example.com"))
    assert check().allowed is True


def test_revoking_consent_closes_the_gate_again(store):
    store.add_allow("acme", "example.com")
    store.add_ownership("acme", "example.com", "dns-txt")
    cid = store.add_consent("acme", _consent("example.com"))

    guard = ScopeGuard(
        allowlist=store.allowlist("acme"), policy_version="2026-11",
        resolver=lambda *a, **k: [],
    )
    assert guard.evaluate(
        "app.example.com", now=time.time(),
        ownership=store.latest_ownership("acme", "app.example.com"),
        consents=store.live_consents("acme", "app.example.com"),
    ).allowed is True

    store.revoke_consent("acme", cid)
    assert guard.evaluate(
        "app.example.com", now=time.time(),
        ownership=store.latest_ownership("acme", "app.example.com"),
        consents=store.live_consents("acme", "app.example.com"),
    ).allowed is False
