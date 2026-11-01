# Live SPIRE proof (not part of the package)

This directory is not shipped in the `vaid-spiffe` wheel or sdist. It exists
to prove the bind-by-reference path in `vaid_spiffe` end to end against a
real SPIRE server and agent, instead of the local test CA the package's own
tests and `examples/quickstart.py` use. The package itself is unchanged;
this only supplies real inputs (a trust bundle and an SVID chain fetched
through the real SPIFFE Workload API) to the same public functions the
README documents.

## What it does

1. Runs a real SPIRE server (`ghcr.io/spiffe/spire-server`) and SPIRE agent
   (`ghcr.io/spiffe/spire-agent`) in Docker, joined by a one-time join token
   (`NodeAttestor "join_token"`), with one registration entry for a
   workload selector (`unix:uid:0`).
2. `live_spire_proof.py` runs as that workload, in a container sharing the
   agent's Workload API socket. It calls `spiffe.workloadapi.WorkloadApiClient.fetch_x509_context()`
   to fetch a **real, SPIRE-issued** X.509-SVID and trust bundle - no
   `cryptography`-generated stand-in certificate anywhere in this step.
3. It DER-encodes the fetched leaf, any intermediates, and the trust bundle,
   builds an `SvidPresentation` and a `VaidSeed` exactly as
   `examples/quickstart.py` does, and calls
   `SpiffeMint.mint_root_with_svid` - the unmodified package function.
4. It checks the result verifies under `vaid_mint`, carries the SPIFFE ID
   the real SPIRE agent assigned; that mis-configuring the mint's
   `expected_trust_domain` against the same real SVID is refused; and that
   a possession proof signed by a key other than the SVID's own private
   key is refused, even though the certificate chain presented is genuine
   and currently valid.
5. With `--rotation`, also waits for the live SPIRE agent to rotate the
   X.509-SVID (the server in this run sets a short `default_x509_svid_ttl`,
   see below) and confirms a VAID minted before rotation still verifies,
   and that minting again against the post-rotation SVID also verifies.

## Running it

Requires Docker. From this directory:

```
./run.sh
```

Tears down and recreates the SPIRE server/agent containers each run, then
runs the proof container and prints its output. Exit code 0 means every
check that ran passed against the live SPIRE deployment.

Pass `--rotation` to also run the rotation check above. It waits for a real
rotation to happen, so it takes a few minutes; omit it for the fast path
(the mint and two refusal checks only).

### SVID TTL used by this harness

The server in `run.sh` sets `default_x509_svid_ttl = "5m"`, deliberately
short so the rotation check does not have to wait out SPIRE 1.9.6's
documented default of `1h`. For reference, confirmed from the pinned
version's own config and docs:

- `default_x509_svid_ttl` default: `1h` (confirmed empirically too - the
  fast-path run's leaf `not_valid_after` is exactly one hour out when this
  override is not set).
- `default_jwt_svid_ttl` default: `5m`.
- No minimum TTL is documented or enforced by the 1.9.6 server: an
  empirical test with `default_x509_svid_ttl = "10s"` was accepted and
  issued a usable SVID (SPIRE backdates the `not_before` by a fixed ~10s
  margin, so the actual validity window was ~20s, not 10s). `5m` here is a
  practical choice for a bounded rotation wait, not a documented floor.

## Scope

This proves the package's documented contract holds against a real SPIRE
issuer. It does not add a Workload API client to `vaid_spiffe` - the
package's "No live SPIRE client" scope statement in its README is unchanged;
this harness is the caller that fetches from SPIRE and hands the bytes to
the package, same as any real integration would.
