#!/usr/bin/env bash
# Cross-language agreement on the UNRECOGNISED SCOPE KIND verdict, across Rust,
# Python and TypeScript (spec docs/spec/scope.md S.10, ADR-0009).
#
# WHAT THIS ADDS OVER THE VECTORS
#
# Each language already checks its own verdict against `verdict_v1.json` and
# `scope_kinds_v1.json`, and all three agreeing with the vector implies they agree
# with each other. That implication is only as good as the three test harnesses
# being equivalent, and S.10 is precisely where they are most likely not to be:
#
#   - Rust gets its boundary shape gate from `serde` (a typed struct plus
#     `deny_unknown_fields`);
#   - Python and TypeScript hand-roll theirs, because a plain map has no such gate;
#   - and the whole point of S.10 is a document that PARSES in all three and is
#     then refused by a VERDICT rather than by the parser.
#
# An implementation that refused an unknown kind at parse time would return
# `unparseable` where the others return `unknown_scope_kind`. Both are refusals,
# both booleans are false, and only the reason differs — which is the divergence
# class this whole surface exists to prevent. A single artifact, diffed, is a
# direct reading of it rather than three indirect ones.
#
# The inputs are read from the frozen vectors rather than constructed per language,
# and CI `cmp`s the three copies of every vector, so all three are provably
# answering about the same bytes.
#
# POSTURE: exits non-zero on ANY difference. Each emitter also refuses to print a
# result over zero inputs, so three emitters that all found nothing cannot diff
# clean and report agreement.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

echo "==> Rust"
(cd "$REPO_ROOT" && cargo run -q -p vaid-mint --example emit_unknown_scope_kind_verdict) \
  > "$OUT/rust.json"

echo "==> Python"
(cd "$REPO_ROOT/python/vaid-mint" \
  && PYTHONPATH=".:../vaid-pop" python3 scripts/emit_unknown_scope_kind_verdict.py) \
  > "$OUT/python.json"

echo "==> TypeScript"
# Build from the WORKSPACE ROOT, not from vaid-mint. vaid-mint imports vaid-pop,
# whose declarations only exist once vaid-pop is built, so `npm run build` inside
# vaid-mint fails from a clean checkout with "Cannot find module 'vaid-pop'". The
# root script builds in dependency order.
#
# The build output goes to a file and is PRINTED ON FAILURE rather than discarded.
# Sending it to /dev/null is what made the first CI failure of this script
# undiagnosable: tsc writes its errors to stdout, so the job reported exit 2 with
# nothing to read.
if ! npm run --silent build --prefix "$REPO_ROOT/typescript" > "$OUT/tsbuild.log" 2>&1; then
  echo "TypeScript build FAILED:" >&2
  cat "$OUT/tsbuild.log" >&2
  exit 1
fi
(cd "$REPO_ROOT/typescript/vaid-mint" && node scripts/emit-unknown-scope-kind-verdict.mjs) \
  > "$OUT/typescript.json"

echo
echo "==> diff Rust vs Python"
diff -u "$OUT/rust.json" "$OUT/python.json"
echo "==> diff Rust vs TypeScript"
diff -u "$OUT/rust.json" "$OUT/typescript.json"

echo
echo "UNKNOWN-SCOPE-KIND AGREEMENT: Rust == Python == TypeScript"
grep -c '"unknown_scope_kind"' "$OUT/rust.json" | sed 's/^/  refusals asserted: /'
