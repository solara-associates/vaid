# vaid-spiffe

Mint a VAID over a verified SPIFFE X.509-SVID. SPIFFE answers **who is
calling** - a workload identity rooted in an X.509 chain of trust, typically
issued by [SPIRE](https://github.com/spiffe/spire). VAID carries **the
delegation** - scope- and capability-attenuated authority, chained across
hops. This package is the bridge between the two.

```python
from vaid_mint import InMemoryAudit, MintService, ReferenceIssuer, VaidSeed, prefix_entry
from vaid_spiffe import SpiffeMint, SvidPresentation

issuer = ReferenceIssuer.ephemeral(1, "vaid.example").assuming_nothing_revoked()
audit = InMemoryAudit()
mint = SpiffeMint(
    MintService(issuer, audit),
    audit,
    trust_bundle=[root_ca_der],              # the SPIFFE trust domain's CA cert(s), DER
    expected_trust_domain="example.org",
)

seed = VaidSeed(
    agent_class="runner", version="1.0.0", tenant_id="acme",
    scope_boundary=[prefix_entry("data.acme")], capability_set=["read"],
    public_key_der=operating_public_key,     # the VAID's OWN Ed25519 key - see "Scope" below
)
result = mint.mint_root_with_svid(seed, SvidPresentation(leaf_der, [], possession), pop)

assert issuer.verify_vaid(result.vaid)
assert result.spiffe_id == "spiffe://example.org/agent/researcher"
```

## Install

```
pip install vaid-spiffe
```

**Local dev only** - from a repo checkout:

```
pip install -e python/vaid-mint
pip install -e python/vaid-spiffe[test]
```

## How it mints: bind by reference, not by key reuse

An SVID's key is whatever its issuer chose - SPIRE defaults to ECDSA P-256,
and RSA and Ed25519 SVIDs both exist too. VAID's holder-supplied ("BYO-key")
mint path is Ed25519-only, so an ECDSA or RSA SVID's key cannot sit in the
VAID's `public_key_der` field directly. `mint_root_with_svid` therefore binds
the two **by reference**, in this fail-closed order:

1. The presented SVID chain is verified against a supplied trust bundle:
   RFC 5280 path validation to a trusted root, every certificate within its
   validity window, exactly one `spiffe://` URI SAN on the leaf, and that
   SPIFFE ID's trust domain matches the one you configured the mint with.
2. The caller proves it holds the SVID's **private** key - a one-time,
   replay-protected challenge signed in the SVID's own algorithm (ECDSA, RSA,
   or Ed25519), binding the VAID operating key being registered. A
   certificate chain alone is not proof of possession: the same bytes that
   cross a TLS handshake could be observed and replayed by someone who never
   held the key.
3. The caller's separate Ed25519 **operating key** - the key the VAID
   actually operates under - goes through the unmodified `vaid_mint`
   BYO-key proof-of-possession and root-mint path. Nothing about this step
   is specific to SPIFFE.
4. The result carries the VAID document (byte-identical to what
   `MintService.mint_root` would have produced on its own) plus the
   `spiffe://` ID it was bound to, and a second audit event records that
   binding through the same `AuditSink` the mint itself writes to.

Every check before step 3 fails closed: a bad SVID or a failed possession
proof never reaches the mint, so no PoP nonce is consumed and no VAID is
issued.

## Scope - read this before relying on it

- **SPIFFE → VAID only.** This package lets a SPIFFE/SPIRE deployment mint a
  VAID. The reverse - a SPIFFE-only system accepting a VAID as if it were an
  SVID - is not built and is not what "bind by reference" means.
- **The spiffe:// ID is not inside the signed VAID document.** The open VAID
  document format (`vaid_mint`) has no field for it, and this package does
  not add one - changing the open spec or the mint's document shape is out
  of scope for an adapter. The binding is recorded next to the signed VAID
  (`SpiffeMintResult.spiffe_id`, and a second audit event), not inside the
  bytes `issuer.verify_vaid` checks. **Practically: a verifier that only
  holds the VAID bytes can confirm the VAID is valid, but cannot itself
  recover or confirm which SPIFFE identity it was minted for - that requires
  trusting whoever ran the mint (and its audit trail), not the document
  alone.** See `docs/SPEC-GAP.md` for the open-spec change that would close
  this, and why it is a proposal rather than something this package does
  unilaterally.
- **Revocation is the issuing platform's job, not this package's.**
  `vaid_mint`'s standalone chain verification does not check revocation
  ([vaid#76](https://github.com/solara-associates/vaid/issues/76)); SVID
  revocation (e.g. via SPIRE re-attestation) is likewise outside what a
  presented certificate chain can tell a standalone verifier. The VAID's
  short lifetime, not a revocation check, is the outer bound an outside
  verifier gets for free.
- **No live SPIRE client.** There is no Workload API fetch here - the trust
  bundle and the presented SVID chain are both supplied by the caller. Get
  them from your own SPIRE agent (or `spiffe.workloadapi`) however you
  already do.
- **No claim beyond what the tests prove.** The test suite covers: a valid
  SVID mints and the result verifies under `vaid_mint` and carries the
  correct `spiffe://` ID; an expired SVID, a chain that does not anchor to
  the trust bundle, a leaf with zero or more than one URI SAN, and a SPIFFE
  ID in the wrong trust domain are all refused; and that an ordinary
  `mint_child` delegation from an SVID-rooted VAID still attenuates scope and
  capabilities exactly as it would from any other root.

## Related

- [`vaid-mint`](../vaid-mint) - the reference mint this package mints
  through, unmodified.
- [`spiffe`](https://github.com/spiffe/py-spiffe) - the SPIFFE project's own
  Python library; this package uses its SPIFFE ID / trust domain parsing and
  does not reimplement the SPIFFE ID grammar.
