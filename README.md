# scopeguard

Authorization before a scan runs: an allowlist, a proof the operator controls
the host, and a named human who asserted they are authorized to test it.

Built for the gap the ForgeGuard audit found — an unauthenticated scan endpoint,
and a scope check that trusted a stored host without re-verifying at dispatch.

```
target ──> normalise ──> gate 1: allowlist ──> gate 2: ownership ──> gate 3: consent
                                  │                    │                    │
                                  └────────────────────┴────────────────────┘
                                                       │
                                            resolve + screen for
                                            private/loopback/metadata
                                                       │
                                              Decision(allowed, reasons)
```

## Three gates, deliberately separate

They fail differently, so they are not collapsed into one check. Collapsing them
is how a product ends up treating *"the user typed the domain"* as
authorization.

1. **Allowlist** — is this host permitted at all, for this tenant?
2. **Ownership** — can the operator prove they control it? A DNS TXT record is
   adequate for a domain you own and useless for a host whose DNS you don't, so
   the *method* is recorded and reviewable.
3. **Consent** — did a named human assert, for this target, that they are
   authorized, under a known policy version, recently enough?

All three are evaluated even when an early one fails, so the operator sees every
problem at once instead of fixing one per attempt.

## The resolution screen

After the gates pass, the target is resolved and **any** private, loopback,
link-local or metadata address is fatal:

```
$ scopeguard check --db scope.db --tenant acme --target localhost
{
  "allowed": false,
  "reasons": ["reserved_address"],
  "detail": "localhost resolves to a private, loopback or otherwise reserved address."
}
```

Any bad address in the answer set fails the whole check rather than filtering
out the good ones — a host resolving to one public and one internal address is
the DNS-rebinding pattern worth refusing. `169.254.169.254` is on the list
because a security product that can be pointed at the cloud metadata service is
an SSRF proxy with a compliance badge.

## Install

```bash
pip install -e .
```

Zero dependencies — stdlib `sqlite3` and `ipaddress`. Python 3.9+.

## Use

```bash
scopeguard init    --db scope.db --tenant acme
scopeguard allow   --db scope.db --tenant acme --host example.com
scopeguard own     --db scope.db --tenant acme --host example.com \
                   --method dns-txt --evidence "TXT at _forgeguard.example.com"
scopeguard consent --db scope.db --tenant acme --target example.com \
                   --signer "A. Client" --email a@client.example --days 90
scopeguard check   --db scope.db --tenant acme --target app.example.com
```

`check` exits `0` when allowed, `2` when refused — so it drops into a Makefile,
a CI step, or a pre-flight hook in front of anything that touches a network.

Real output, in order:

```
# before consent exists
{ "allowed": false, "reasons": ["no_consent"],
  "detail": "no authorization has been asserted for app.example.com." }   EXIT=2

# after consent, resolving to real public addresses
{ "allowed": true, "reasons": [], "detail": "example.com:443 is in scope",
  "resolved": ["104.20.23.154", "172.66.147.243", "2606:4700:10::6814:179a"] }  EXIT=0

# the bypass attempt: allowlist localhost, verify it, consent to it
{ "allowed": false, "reasons": ["reserved_address"],
  "detail": "localhost resolves to a private, loopback or otherwise reserved address." }  EXIT=2
```

That last one is the point: allowlisting and consenting to an internal host does
not make it scannable.

## As a library

```python
from scopeguard import ScopeGuard, Store

store = Store("scope.db")
guard = ScopeGuard(allowlist=store.allowlist("acme"), policy_version="2026-11")

decision = guard.evaluate(
    "app.example.com",
    now=time.time(),
    ownership=store.latest_ownership("acme", "app.example.com"),
    consents=store.live_consents("acme", "app.example.com"),
)
if not decision.allowed:
    raise PermissionError(decision.detail)
# decision.resolved holds the addresses it approved — pin them.
```

## Tenant isolation

Every table carries `tenant_id`. The guard is tenant-agnostic; the store is
where isolation lives, so a caller cannot load another tenant's consent by
guessing a hostname. There are tests for that specifically.

## Append-only consent

A revocation sets `revoked_at`; it never deletes. A compliance reviewer needs to
know what was asserted and when, not what the current state happens to be. Tests
assert the row survives revocation.

## Tests

```bash
python -m pytest -q
```

**78 passing** (54 guard + 24 store). Host normalisation (agrees with ForgeGuard's
`normalizeHost`, because a guard that normalises differently from the scanner is
a guard with a bypass), the `.` boundary that stops `notexample.com` matching
`example.com`, every gate individually, expiry in both directions, stale policy
version, the private-address matrix, per-consent TTL enforcement, and tenant
isolation.

## Limitations

- **DNS rebinding is only partly addressed.** `evaluate` returns the resolved
  addresses it approved, but a resolution can change between the check and the
  HTTP request. **If the caller ignores `decision.resolved` and resolves again,
  rebinding still works.** Pinning is the caller's responsibility and this
  library cannot enforce it.
- **No signature on consent.** A consent row is an assertion in your database,
  not a cryptographically signed artifact. Anyone with DB write access can
  insert one. A real deployment wants a signed record or an e-sign integration.
- **TTLs are per-consent or per guard instance.** Each `Consent` carries its own
  `ttl_s` (0 means "use the guard default"), so `--days 7` really does expire in
  seven days. There is still no per-target policy override.
- **Assumes a single policy version is current.** Multiple concurrent policies
  would need a resolver.
- **No wildcard allowlist entries.** Every host or its exact parent must be
  listed. Deliberate — wildcards are how scope quietly becomes "everything".

## Legal

This is a control, not an authorizer. It refuses targets that fail the gates;
it cannot make scanning a system you are not authorized to test lawful. The
consent record is an accountability artifact, not a license.

MIT licensed.
