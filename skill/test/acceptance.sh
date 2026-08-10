#!/usr/bin/env bash
# End-to-end acceptance for the `vaid` CLI, run as separate processes.
#
# Every process boundary here is deliberate. The claim is that a VAID minted by
# one program can be checked by another that shares no memory with it, so a test
# that verifies in the same process as it mints proves nothing about the claim.
#
# Controls run FIRST. A verifier that accepts everything passes the happy path, so
# the happy path is only evidence once the negatives are observed to fail.
#
# Run: bash test/acceptance.sh
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
VAID="node src/cli.mjs"

export VAID_HOME
VAID_HOME="$(mktemp -d)"
trap 'rm -rf "$VAID_HOME"' EXIT

pass=0; fail=0
ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$1"; fail=$((fail+1)); }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected $3, got $2)"; fi; }

printf '\n\033[1mCONTROLS — these must fail before any pass means anything\033[0m\n\n'

# A verifier that never rejects is the failure mode this whole file exists to
# rule out, so it is ruled out before anything else runs.
$VAID verify 'not a vaid at all' >/dev/null 2>&1
check "garbage is refused (exit 4)" "$?" "4"

$VAID verify 'vaid1:aGVsbG8' >/dev/null 2>&1
check "a vaid1: token holding junk is refused" "$?" "4"

# A real production VAID, minted by the deployed substrate, checked against the
# anchor this package ships. It is a year past its one-hour life, so the honest
# answer is EXPIRED — exit 1, not exit 0.
$VAID verify test/vectors/production-vaid.json >/dev/null 2>&1
check "the real substrate VAID is EXPIRED today (exit 1)" "$?" "1"

# ...and at its own issue time it is accepted. Same bytes, same anchor, different
# clock: proof the exit code above is about expiry and not about failure to parse.
$VAID verify test/vectors/production-vaid.json --at "$(node -p "require('./test/vectors/production-vaid.json').issued_at")" >/dev/null 2>&1
check "the same document at its issue time is accepted (exit 0)" "$?" "0"

printf '\n\033[1mACCEPTANCE ONE — mint here, verify in another process\033[0m\n\n'

ROOT=$($VAID mint --class orchestrator --tenant acme --scope data.acme --caps read,write --ttl 24 --quiet 2>/dev/null)
[ -n "$ROOT" ] && ok "minted a root VAID" || bad "mint produced nothing"

case "$ROOT" in vaid1:*) ok "output is a single-line vaid1: envelope" ;; *) bad "output is not a vaid1: envelope" ;; esac
case "$ROOT" in *[[:space:]]*) bad "envelope contains whitespace" ;; *) ok "envelope contains no whitespace" ;; esac

# The local issuer is not in the shipped anchor, so an untrusted verifier MUST
# reject it. This is the correct answer and the test asserts it rather than
# treating it as an obstacle.
env VAID_HOME="$(mktemp -d)" node src/cli.mjs verify "$ROOT" >/dev/null 2>&1
check "a fresh machine rejects it — unknown issuer key" "$?" "1"

# With the issuer key supplied out of band, the same fresh machine accepts it.
KEYLINE=$($VAID mint --quiet --json 2>/dev/null | node -p "JSON.parse(require('fs').readFileSync(0,'utf8')).issuer")
OTHER_HOME="$(mktemp -d)"
env VAID_HOME="$OTHER_HOME" node src/cli.mjs verify "$ROOT" --trust "$KEYLINE" >/dev/null 2>&1
check "the same envelope is accepted once the key is trusted out of band" "$?" "0"
rm -rf "$OTHER_HOME"

printf '\n\033[1mACCEPTANCE TWO — the artifact can leave the machine\033[0m\n\n'

# Anyone can read the document with no tooling from us. If this breaks, the
# envelope has become opaque and the recipient is dependent on our software.
#
# The `=` padding loop is not incidental, and the reason is worse than it looks.
# base64url is UNPADDED, and `base64 -d` does NOT reject unpadded input: it
# accepts it and SILENTLY DROPS the final partial group, returning a document
# short by one or two bytes, with no error and nothing on stderr. What comes back
# is JSON missing its last brace — so the failure presents as "your credential is
# invalid JSON" when the credential is perfectly intact and the command is wrong.
#
# Measured on this machine: without the padding loop, 27 of 40 freshly minted
# envelopes decoded to truncated JSON. Envelope length varies run to run (the
# signature is an array of 1-to-3-digit numbers), and only length ≡ 0 mod 4
# survives — so it works often enough to look like an intermittent bug in the
# credential rather than a constant bug in the instructions.
#
# This is the exact recipe printed in README.md and SKILL.md; keep them in step.
B64=$(printf '%s' "${ROOT#vaid1:}" | tr '_-' '/+')
while [ $(( ${#B64} % 4 )) -ne 0 ]; do B64="${B64}="; done
DECODED=$(printf '%s' "$B64" | base64 -d 2>/dev/null | node -p "JSON.parse(require('fs').readFileSync(0,'utf8')).vaid.tenant_id" 2>/dev/null)
check "the envelope decodes with base64 + no VAID tooling" "$DECODED" "acme"

# Mangled the way a mail client mangles a long line.
MANGLED=$(printf '%s' "$ROOT" | fold -w 76 | sed 's/^/   /')
$VAID present "$MANGLED" --quiet >/dev/null 2>&1
check "a reflowed, re-indented paste still parses" "$?" "0"

# Truncation must be caught here rather than at the far end.
$VAID present "${ROOT:0:${#ROOT}-40}" >/dev/null 2>&1
check "a truncated paste is caught (non-zero)" "$([ $? -ne 0 ] && echo nonzero || echo zero)" "nonzero"

printf '\n\033[1mDELEGATION\033[0m\n\n'

CHILD=$($VAID mint --class worker --tenant acme --scope data.acme --caps read --parent "$ROOT" --quiet 2>/dev/null)
[ -n "$CHILD" ] && ok "minted an attenuated child" || bad "child mint produced nothing"

# The mint must refuse to widen authority. If this passes, attenuation is a
# comment rather than a rule.
$VAID mint --class rogue --tenant acme --scope data.acme --caps read,write,admin --parent "$ROOT" --quiet >/dev/null 2>&1
check "CONTROL — widening capabilities is refused" "$?" "1"

$VAID mint --class rogue --tenant victim --caps read --parent "$ROOT" --quiet >/dev/null 2>&1
check "CONTROL — cross-tenant delegation is refused" "$?" "1"

OTHER_HOME="$(mktemp -d)"
env VAID_HOME="$OTHER_HOME" node src/cli.mjs verify "$CHILD" --trust "$KEYLINE" >/dev/null 2>&1
check "the child verifies end to end with its chain presented" "$?" "0"

CHILD_JSON=$(env VAID_HOME="$OTHER_HOME" node src/cli.mjs verify "$CHILD" --json 2>/dev/null)
ATT=$(printf '%s' "$CHILD_JSON" | node -p "JSON.parse(require('fs').readFileSync(0,'utf8')).findings.find(f=>f.id==='attenuation').state")
check "the delegation finding is a pass, not a caveat" "$ATT" "pass"

# The leaf presented WITHOUT its ancestors must not read as attenuated.
LEAF_ONLY=$(printf '%s' "$CHILD" | node -e "
  const {parseEnvelope,packEnvelope}=require('./src/envelope.mjs');
  let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{
    const p=parseEnvelope(s.trim());process.stdout.write(packEnvelope(p.vaid));});" 2>/dev/null)
ALONE=$(env VAID_HOME="$OTHER_HOME" node src/cli.mjs verify "$LEAF_ONLY" --json 2>/dev/null \
  | node -p "JSON.parse(require('fs').readFileSync(0,'utf8')).findings.find(f=>f.id==='attenuation').state")
check "CONTROL — the leaf alone reports attenuation as a caveat, never a pass" "$ALONE" "caveat"
rm -rf "$OTHER_HOME"

printf '\n\033[1mTRUST PERSISTENCE IS VISIBLE\033[0m\n\n'

# --trust is a standing decision, so it must be listable. A stored trust decision
# nobody can enumerate is one nobody can review or withdraw.
H3="$(mktemp -d)"
env VAID_HOME="$H3" node src/cli.mjs verify --trusted 2>/dev/null | grep -q "(none)"
check "--trusted lists nothing on a fresh machine" "$?" "0"

env VAID_HOME="$H3" node src/cli.mjs verify "$ROOT" --trust "$KEYLINE" >/dev/null 2>&1
# The key must still be accepted on a LATER run that passes no --trust at all —
# that is what "persists" means, and it is the part worth asserting.
env VAID_HOME="$H3" node src/cli.mjs verify "$ROOT" >/dev/null 2>&1
check "a --trust key is still accepted on a later run without --trust" "$?" "0"

env VAID_HOME="$H3" node src/cli.mjs verify --trusted 2>/dev/null | grep -q "Added on this machine"
check "--trusted shows the added key" "$?" "0"

env VAID_HOME="$H3" node src/cli.mjs verify --trust "$KEYLINE" 2>&1 | grep -qi "PERSISTS"
check "--trust says at the point of use that it persists" "$?" "0"
rm -rf "$H3"

printf '\n\033[1mREVOCATION HONESTY\033[0m\n\n'

RID=$(printf '%s' "$ROOT" | node -e "
  const {parseEnvelope}=require('./src/envelope.mjs');
  let s='';process.stdin.on('data',d=>s+=d).on('end',()=>process.stdout.write(parseEnvelope(s.trim()).vaid.vaid_id));" 2>/dev/null)
$VAID revoke "$RID" --reason "acceptance test" >/dev/null 2>&1
check "revoke writes locally" "$?" "0"

# Revoking locally must NOT change the verdict, because no third party can see it.
REV=$($VAID verify "$ROOT" --trust "$KEYLINE" --json 2>/dev/null \
  | node -p "JSON.parse(require('fs').readFileSync(0,'utf8')).findings.find(f=>f.id==='revocation').state")
check "revocation is still reported NOT CHECKED after a local revoke" "$REV" "not_checked"

printf '\n'
if [ "$fail" -eq 0 ]; then
  printf '\033[32m%s passed, 0 failed\033[0m\n\n' "$pass"; exit 0
else
  printf '\033[31m%s passed, %s FAILED\033[0m\n\n' "$pass" "$fail"; exit 1
fi
