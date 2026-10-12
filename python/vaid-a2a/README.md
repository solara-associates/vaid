# vaid-a2a

Reference verifier for the VAID [A2A](https://a2a-protocol.org) extension
specified in [`docs/a2a/v1/extension.md`](../../docs/a2a/v1/extension.md)
(**draft**).

A2A lets agents delegate work to agents. [a2aproject/A2A#2028](https://github.com/a2aproject/A2A/issues/2028)
proposes `actorChain`, a caller-supplied record of who acted for whom, and is
explicit that a self-reported chain can narrow perfectly while proving no
actual authority. This extension supplies one concrete, offline-checkable
proof a hop can point at to fill that gap: a VAID — a signed, attenuated,
revocable delegation document this repo already mints and verifies in three
languages.

This package does not implement the extension's wire format; it implements
the **verification side**: given an A2A `Message` (as a plain `dict`) and a
trust configuration, it extracts any VAID(s) carried under the extension's
metadata keys and runs the ordered check the spec defines, returning a typed
allow/deny result with a reason — never a bare boolean, so a caller can log,
alert, or retry the right thing.

## Install

```sh
pip install -e python/vaid-pop -e python/vaid-mint -e python/vaid-a2a
```

(No published release yet — this is a draft extension on a feature branch.
See `docs/a2a/drafts/a2a-2028-reply.md` and the branch's `REPORT-306.md`.)

## Use

```python
from datetime import datetime, timezone

from vaid_mint.revocation import InMemoryRevocationList
from vaid_a2a import verify_a2a_message, METADATA_VAID_KEY

trust_config = {
    "trustedIssuers": [
        {"trustDomain": "vaid.example", "kernelPublicKey": "<base64url, raw 32 bytes>"}
    ]
}

message = {
    "metadata": {
        METADATA_VAID_KEY: leaf_vaid_document,       # a dict, as produced by vaid_mint
        # METADATA_CHAIN_KEY: [ancestor_vaid_1, ...],  # optional, for chain checks
    }
}

result = verify_a2a_message(
    message,
    trust_config=trust_config,
    # A plain, never-populated InMemoryRevocationList() is UNAVAILABLE by
    # design (R.4.5/R.4.6), so this example as written DENIES EVERY REQUEST
    # with VerifyCode.INDETERMINATE, however valid the VAID is. That is
    # deliberate: a copy-pasted revocation seam with nothing wired to it
    # must fail closed, never read as "nothing is revoked". See "Configuring
    # real revocation" below for what plugging in an actual store takes.
    revocation=InMemoryRevocationList(),
    requested_action="data.acme.orders",
    now=datetime.now(timezone.utc),
)

if result.allowed:
    ...  # proceed
else:
    ...  # result.code (a VerifyCode) and result.reason explain why
```

**Valid requests are refused as `indeterminate` until a real
`RevocationCheck` is configured.** This is not a bug to work around; it is
the fail-closed default R.4.5 requires. The copy-paste path above stays
closed on purpose, so a deployment cannot go live by accident with
revocation silently assumed clean.

See `examples/guard.py` for use as a guard in front of a request handler.

### Configuring real revocation

Implement `vaid_mint.revocation.RevocationCheck` against whatever actually
tracks revoked VAIDs in your deployment (a database table, a feed, a cache
in front of either) and pass an instance of it instead of
`InMemoryRevocationList()`:

```python
from vaid_mint.revocation import RevocationCheck, RevocationStatus

class DatabaseRevocationCheck:
    """Minimal real RevocationCheck: ask the database once per lineage."""

    def __init__(self, db):
        self._db = db

    def check_lineage(self, lineage: list[str]) -> RevocationStatus:
        try:
            revoked_ids = self._db.revoked_vaid_ids(lineage)
        except Exception:
            return RevocationStatus.UNAVAILABLE  # fail closed, not NOT_REVOKED
        if revoked_ids:
            return RevocationStatus.REVOKED
        return RevocationStatus.NOT_REVOKED

result = verify_a2a_message(
    message,
    trust_config=trust_config,
    revocation=DatabaseRevocationCheck(db),
    requested_action="data.acme.orders",
    now=datetime.now(timezone.utc),
)
```

`check_lineage` receives the full ordered lineage (root first, leaf last)
that `verify_a2a_message` already assembled; it is never asked to resolve
ancestry itself (R.4.1). `RevocationStatus` is three-valued on purpose: a
database error or an unreachable feed must report `UNAVAILABLE`, never
`NOT_REVOKED`.

### Local demo only, never production

`InMemoryRevocationList.assume_nothing_revoked()` exists for local demos and
tests that have no revocation source to wire up and want to exercise the
rest of the check (signature, expiry, chain, scope) without every call
denying on revocation. It is **never** appropriate outside a local demo: it
makes every lineage read as not-revoked, unconditionally, regardless of
whether anything actually was.

```python
# LOCAL DEMO ONLY, NEVER PRODUCTION.
from vaid_mint.revocation import InMemoryRevocationList

demo_result = verify_a2a_message(
    message,
    trust_config=trust_config,
    revocation=InMemoryRevocationList.assume_nothing_revoked(),
    requested_action="data.acme.orders",
    now=datetime.now(timezone.utc),
)
```

## What this checks, and in what order

Exactly the order `docs/a2a/v1/extension.md` §5 specifies — signature, leaf
expiry, chain integrity, per-hop attenuation, requested-action scope,
revocation — fail closed at the first failing step. See the module docstring
in `vaid_a2a/verifier.py` for the full reasoning behind the order; it mirrors
`vaid_mint.verify` and `vaid_mint.chain`, which this package delegates to
rather than reimplements.

| step | delegates to |
|---|---|
| 1. signature / authenticity | `vaid_mint.verify.verify_vaid_authenticity_graded` |
| 2. leaf expiry | `vaid_mint.document.is_expired_at` |
| 3. chain integrity | `vaid_mint.chain.verify_chain_at` |
| 4. per-hop attenuation | `vaid_mint.chain.verify_chain_at` (same call) |
| 5. requested action in leaf scope | `vaid_mint.document.is_in_scope` |
| 6. revocation over the full lineage | the caller's own `vaid_mint.revocation.RevocationCheck` |

## Test vectors

`tests/test_vectors.py` runs every vector in `docs/a2a/v1/vectors/*.json` and
asserts the expected result. Regenerate the vectors from `vaid-mint` tooling
with `docs/a2a/v1/vectors/generate_vectors.py`; see that directory's own README.

## Non-goals

- Does not depend on `a2a-python` or any A2A SDK — `Message` is accepted as a
  plain `dict`, so this works against any A2A server or client.
- Does not mint VAIDs (`vaid_mint.mint.MintService`) or implement revocation
  transport (`docs/spec/revocation.md` R.1) — both out of scope here, as they
  are for the extension itself.
- Does not implement `actorChain` (#2028) or require it to be present; see
  the spec's §4.1 for how the two compose when both are active.
