"""CLI for scope administration and pre-flight checks.

    scopeguard init --db scope.db --tenant acme
    scopeguard allow --db scope.db --tenant acme --host example.com
    scopeguard own   --db scope.db --tenant acme --host example.com --method dns-txt
    scopeguard consent --db scope.db --tenant acme --target example.com \\
        --signer "A. Client" --email a@client.example --days 90
    scopeguard check --db scope.db --tenant acme --target app.example.com

``check`` exits 0 when allowed and 2 when refused, so it drops straight into a
Makefile or a CI step in front of anything that touches a network.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import List, Optional

from .guard import Consent, ScopeGuard
from .store import default_store


def _print(obj) -> None:
    json.dump(obj, sys.stdout, indent=2)
    sys.stdout.write("\n")


def cmd_init(a) -> int:
    with default_store(a.db) as s:
        s.add_allow(a.tenant, "__placeholder__.invalid", "created by init")
        s.remove_allow(a.tenant, "__placeholder__.invalid")
        _print({"ok": True, "db": a.db, "tenant": a.tenant, "stats": s.stats(a.tenant)})
    return 0


def cmd_allow(a) -> int:
    with default_store(a.db) as s:
        s.add_allow(a.tenant, a.host, a.note or "")
        _print({"ok": True, "allowlist": s.allowlist(a.tenant)})
    return 0


def cmd_disallow(a) -> int:
    with default_store(a.db) as s:
        removed = s.remove_allow(a.tenant, a.host)
        _print({"removed": removed, "allowlist": s.allowlist(a.tenant)})
    return 0 if removed else 2


def cmd_own(a) -> int:
    with default_store(a.db) as s:
        s.add_ownership(a.tenant, a.host, a.method, a.by or "", a.evidence or "")
        proof = s.latest_ownership(a.tenant, a.host)
        _print({"ok": True, "ownership": proof.to_dict() if proof else None})
    return 0


def cmd_consent(a) -> int:
    now = time.time()
    with default_store(a.db) as s:
        cid = s.add_consent(
            a.tenant,
            Consent(
                signer=a.signer,
                signer_email=a.email,
                target=a.target,
                asserted_at=now,
                policy_version=a.policy,
                statement=a.statement or "",
                ttl_s=a.days * 86400,
            ),
        )
        _print({"ok": True, "consent_id": cid, "expires_at": now + a.days * 86400})
    return 0


def cmd_revoke(a) -> int:
    with default_store(a.db) as s:
        ok = s.revoke_consent(a.tenant, a.consent_id)
        _print({"revoked": ok})
    return 0 if ok else 2


def cmd_check(a) -> int:
    with default_store(a.db) as s:
        allowed = s.allowlist(a.tenant)
        guard = ScopeGuard(
            allowlist=allowed,
            policy_version=a.policy,
            require_ownership=not a.no_ownership,
            require_consent=not a.no_consent,
        )
        decision = guard.evaluate(
            a.target,
            port=a.port,
            now=time.time(),
            ownership=s.latest_ownership(a.tenant, a.target),
            consents=s.live_consents(a.tenant, a.target),
        )
        s.record_decision(
            a.tenant, a.target, decision.allowed, [r.value for r in decision.reasons]
        )
        _print(decision.to_dict())
    return 0 if decision.allowed else 2


def cmd_audit(a) -> int:
    with default_store(a.db) as s:
        _print(
            {
                "tenant": a.tenant,
                "stats": s.stats(a.tenant),
                "recent_decisions": s.decisions(a.tenant, a.limit),
            }
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="scopeguard", description="Scan authorization: allowlist, ownership, consent."
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--db", default="scope.db")
        sp.add_argument("--tenant", required=True)

    s = sub.add_parser("init", help="create the database")
    common(s)
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("allow", help="allowlist a host")
    common(s)
    s.add_argument("--host", required=True)
    s.add_argument("--note")
    s.set_defaults(func=cmd_allow)

    s = sub.add_parser("disallow", help="remove a host from the allowlist")
    common(s)
    s.add_argument("--host", required=True)
    s.set_defaults(func=cmd_disallow)

    s = sub.add_parser("own", help="record an ownership proof")
    common(s)
    s.add_argument("--host", required=True)
    s.add_argument("--method", required=True)
    s.add_argument("--by")
    s.add_argument("--evidence")
    s.set_defaults(func=cmd_own)

    s = sub.add_parser("consent", help="record an authorization assertion")
    common(s)
    s.add_argument("--target", required=True)
    s.add_argument("--signer", required=True)
    s.add_argument("--email", required=True)
    s.add_argument("--days", type=int, default=90)
    s.add_argument("--policy", default="2026-11")
    s.add_argument("--statement")
    s.set_defaults(func=cmd_consent)

    s = sub.add_parser("revoke", help="revoke a consent record")
    common(s)
    s.add_argument("--consent-id", type=int, required=True)
    s.set_defaults(func=cmd_revoke)

    s = sub.add_parser("check", help="decide whether a target may be scanned")
    common(s)
    s.add_argument("--target", required=True)
    s.add_argument("--port", type=int, default=443)
    s.add_argument("--policy", default="2026-11")
    s.add_argument("--no-ownership", action="store_true")
    s.add_argument("--no-consent", action="store_true")
    s.set_defaults(func=cmd_check)

    s = sub.add_parser("audit", help="show stats and recent decisions")
    common(s)
    s.add_argument("--limit", type=int, default=50)
    s.set_defaults(func=cmd_audit)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
