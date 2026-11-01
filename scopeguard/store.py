"""Persistence for scope records.

SQLite, no ORM. The schema is deliberately append-only for consent: a
revocation is a new row with ``revoked_at`` set, never an edit, because a
compliance reviewer needs to know what was asserted when, not what the current
state happens to be.

Every table carries ``tenant_id``. The guard itself is tenant-agnostic; the
store is where tenant isolation lives, so a caller cannot load another
tenant's consent by guessing a hostname.
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .guard import Consent, OwnershipProof, normalize_host

SCHEMA = """
CREATE TABLE IF NOT EXISTS allowlist (
    tenant_id   TEXT NOT NULL,
    host        TEXT NOT NULL,
    note        TEXT NOT NULL DEFAULT '',
    added_at    REAL NOT NULL,
    PRIMARY KEY (tenant_id, host)
);

CREATE TABLE IF NOT EXISTS ownership (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id   TEXT NOT NULL,
    host        TEXT NOT NULL,
    method      TEXT NOT NULL,
    verified_at REAL NOT NULL,
    verified_by TEXT NOT NULL DEFAULT '',
    evidence    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ownership_tenant_host
    ON ownership (tenant_id, host, verified_at DESC);

CREATE TABLE IF NOT EXISTS consent (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id      TEXT NOT NULL,
    signer         TEXT NOT NULL,
    signer_email   TEXT NOT NULL,
    target         TEXT NOT NULL,
    asserted_at    REAL NOT NULL,
    policy_version TEXT NOT NULL,
    statement      TEXT NOT NULL DEFAULT '',
    revoked_at     REAL
);
CREATE INDEX IF NOT EXISTS consent_tenant_target
    ON consent (tenant_id, target, asserted_at DESC);

CREATE TABLE IF NOT EXISTS decisions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id  TEXT NOT NULL,
    target     TEXT NOT NULL,
    allowed    INTEGER NOT NULL,
    reasons    TEXT NOT NULL,
    decided_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS decisions_tenant_time
    ON decisions (tenant_id, decided_at DESC);
"""


@dataclass
class Store:
    """Thin SQLite wrapper. One instance per process is fine."""

    path: str = ":memory:"

    def __post_init__(self) -> None:
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    # -- lifecycle --------------------------------------------------------

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- allowlist --------------------------------------------------------

    def add_allow(self, tenant_id: str, host: str, note: str = "") -> None:
        h = normalize_host(host)
        if not h:
            raise ValueError(f"invalid host: {host!r}")
        self._conn.execute(
            "INSERT OR REPLACE INTO allowlist (tenant_id, host, note, added_at)"
            " VALUES (?,?,?,?)",
            (tenant_id, h, note, time.time()),
        )
        self._conn.commit()

    def remove_allow(self, tenant_id: str, host: str) -> bool:
        h = normalize_host(host)
        cur = self._conn.execute(
            "DELETE FROM allowlist WHERE tenant_id=? AND host=?", (tenant_id, h)
        )
        self._conn.commit()
        return cur.rowcount > 0

    def allowlist(self, tenant_id: str) -> List[str]:
        rows = self._conn.execute(
            "SELECT host FROM allowlist WHERE tenant_id=? ORDER BY host", (tenant_id,)
        ).fetchall()
        return [r["host"] for r in rows]

    # -- ownership --------------------------------------------------------

    def add_ownership(
        self,
        tenant_id: str,
        host: str,
        method: str,
        verified_by: str = "",
        evidence: str = "",
        verified_at: Optional[float] = None,
    ) -> None:
        h = normalize_host(host)
        if not h:
            raise ValueError(f"invalid host: {host!r}")
        self._conn.execute(
            "INSERT INTO ownership (tenant_id, host, method, verified_at, verified_by,"
            " evidence) VALUES (?,?,?,?,?,?)",
            (tenant_id, h, method, verified_at or time.time(), verified_by, evidence),
        )
        self._conn.commit()

    def latest_ownership(self, tenant_id: str, host: str) -> Optional[OwnershipProof]:
        h = normalize_host(host)
        if not h:
            return None
        # Exact host first, then walk parents so a verified apex covers subs.
        candidates = [h]
        parts = h.split(".")
        for i in range(1, len(parts) - 1):
            candidates.append(".".join(parts[i:]))
        for cand in candidates:
            row = self._conn.execute(
                "SELECT * FROM ownership WHERE tenant_id=? AND host=?"
                " ORDER BY verified_at DESC LIMIT 1",
                (tenant_id, cand),
            ).fetchone()
            if row:
                return OwnershipProof(
                    host=row["host"],
                    method=row["method"],
                    verified_at=row["verified_at"],
                    verified_by=row["verified_by"],
                )
        return None

    # -- consent ----------------------------------------------------------

    def add_consent(
        self,
        tenant_id: str,
        consent: Consent,
    ) -> int:
        cur = self._conn.execute(
            "INSERT INTO consent (tenant_id, signer, signer_email, target, asserted_at,"
            " policy_version, statement) VALUES (?,?,?,?,?,?,?)",
            (
                tenant_id,
                consent.signer,
                consent.signer_email,
                normalize_host(consent.target) or consent.target,
                consent.asserted_at,
                consent.policy_version,
                consent.statement,
            ),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def revoke_consent(self, tenant_id: str, consent_id: int) -> bool:
        cur = self._conn.execute(
            "UPDATE consent SET revoked_at=? WHERE id=? AND tenant_id=? AND revoked_at IS NULL",
            (time.time(), consent_id, tenant_id),
        )
        self._conn.commit()
        return cur.rowcount > 0

    def live_consents(self, tenant_id: str, target: str) -> List[Consent]:
        h = normalize_host(target) or target
        candidates = [h]
        parts = h.split(".")
        for i in range(1, len(parts) - 1):
            candidates.append(".".join(parts[i:]))
        placeholders = ",".join("?" for _ in candidates)
        rows = self._conn.execute(
            f"SELECT * FROM consent WHERE tenant_id=? AND target IN ({placeholders})"
            " AND revoked_at IS NULL ORDER BY asserted_at DESC",
            (tenant_id, *candidates),
        ).fetchall()
        return [
            Consent(
                signer=r["signer"],
                signer_email=r["signer_email"],
                target=r["target"],
                asserted_at=r["asserted_at"],
                policy_version=r["policy_version"],
                statement=r["statement"],
            )
            for r in rows
        ]

    # -- audit ------------------------------------------------------------

    def record_decision(
        self, tenant_id: str, target: str, allowed: bool, reasons: List[str]
    ) -> None:
        self._conn.execute(
            "INSERT INTO decisions (tenant_id, target, allowed, reasons, decided_at)"
            " VALUES (?,?,?,?,?)",
            (tenant_id, target, int(allowed), json.dumps(reasons), time.time()),
        )
        self._conn.commit()

    def decisions(self, tenant_id: str, limit: int = 50) -> List[dict]:
        rows = self._conn.execute(
            "SELECT * FROM decisions WHERE tenant_id=? ORDER BY decided_at DESC LIMIT ?",
            (tenant_id, limit),
        ).fetchall()
        return [
            {
                "target": r["target"],
                "allowed": bool(r["allowed"]),
                "reasons": json.loads(r["reasons"]),
                "decided_at": r["decided_at"],
            }
            for r in rows
        ]

    def stats(self, tenant_id: str) -> dict:
        allow = len(self.allowlist(tenant_id))
        own = self._conn.execute(
            "SELECT COUNT(DISTINCT host) c FROM ownership WHERE tenant_id=?", (tenant_id,)
        ).fetchone()["c"]
        cons = self._conn.execute(
            "SELECT COUNT(*) c FROM consent WHERE tenant_id=? AND revoked_at IS NULL",
            (tenant_id,),
        ).fetchone()["c"]
        return {"allowlist": allow, "verified_hosts": own, "live_consents": cons}


def default_store(path: Optional[str] = None) -> Store:
    """Open the store, creating the parent directory if needed."""
    if not path:
        return Store(":memory:")
    if path != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    return Store(path)
