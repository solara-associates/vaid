#!/usr/bin/env bash
# Byte agreement for the DETACHED CONSENT ATTESTATION format, across Rust, Python
# and TypeScript.
#
# This stands in for a frozen vector, deliberately. The attestation is a new signed
# object, and freezing its canonicalization is the one decision in this work that is
# expensive to unwind — so the format stays reviewable until it has been reviewed.
# Nothing here is vendored into any package; there is no chain_v1-style artifact to
# drift against. What this proves is exactly the property a vector would prove: given
# the same attestation, all three implementations canonicalize to the same digest and
# produce the same Ed25519 signature.
#
# When the format is approved, this becomes a vector and this script is replaced by
# the usual three-way `cmp` plus per-language gates.
#
# Exits non-zero on ANY byte difference.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

echo "==> Rust"
(cd "$REPO_ROOT" && cargo run -q -p vaid-mint --example emit_attestation_digest) \
  > "$OUT/rust.json"

echo "==> Python"
(cd "$REPO_ROOT/python/vaid-mint" && python3 scripts/emit_attestation_digest.py) \
  > "$OUT/python.json"

echo "==> TypeScript"
(cd "$REPO_ROOT/typescript/vaid-mint" && npm run --silent build >/dev/null \
  && node scripts/emit-attestation-digest.mjs) > "$OUT/typescript.json"

echo
echo "==> diff Rust vs Python"
diff -u "$OUT/rust.json" "$OUT/python.json"
echo "==> diff Rust vs TypeScript"
diff -u "$OUT/rust.json" "$OUT/typescript.json"

echo
echo "BYTE AGREEMENT: Rust == Python == TypeScript"
grep -E '"(digest_sha256_hex|signature_hex)"' "$OUT/rust.json"
