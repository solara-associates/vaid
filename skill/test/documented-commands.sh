#!/usr/bin/env bash
# Do the commands we DOCUMENT actually work, exactly as written?
#
# This file exists because the rest of the suite did not ask that question, and a
# broken instruction shipped twice as a result.
#
# `npx vaid-skill-install` was the first command in the README of 0.1.0 and 0.1.1.
# It always 404'd: `npx <name>` resolves <name> as a PACKAGE and then runs the bin
# matching it, and there is no package by that name — only a bin. Every existing
# test invoked the installer as `node install.mjs` or through `./node_modules/.bin`,
# so all of them passed while the published instruction was unrunnable. The suite
# tested the program and never the instruction.
#
# So the rules here are different from every other test in this repo:
#
#   1. Commands run **verbatim** as documented, including `npx`, including `-p`.
#      No relative paths, no ./node_modules/.bin. If the docs say `npx vaid-skill`,
#      that is the string that runs.
#   2. Against the **published package** by default, not this checkout. What a
#      stranger installs is the thing under test. Point it at a local tarball with
#      VAID_SKILL_SPEC=/path/to/vaid-skill-x.y.z.tgz to gate a release before
#      publishing.
#   3. From a **clean HOME and cache**, so a package cached by earlier work cannot
#      make an unresolvable name look resolvable.
#
# It also greps the shipped docs for command strings and asserts every one it finds
# is covered below, so a newly documented command cannot go untested silently.
#
# Run: bash test/documented-commands.sh
#      VAID_SKILL_SPEC=../vaid-skill-0.1.3.tgz bash test/documented-commands.sh
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
PKGDIR="$PWD"

# What to resolve. A bare name goes to the registry, which is the point.
SPEC="${VAID_SKILL_SPEC:-vaid-skill}"

# A clean HOME means a clean npm and npx cache, so resolution is really tested.
FAKEHOME="$(mktemp -d)"
WORK="$(mktemp -d)"
trap 'rm -rf "$FAKEHOME" "$WORK"' EXIT
export HOME="$FAKEHOME"
export npm_config_cache="$FAKEHOME/.npm"
export VAID_HOME="$WORK/.vaid"
export NO_COLOR=1

# The five agents are detected by directory, so a realistic project has them.
# Without this, `--global` correctly reports "nothing detected" and exits 1, and
# the test would be measuring an empty HOME rather than the command.
mkdir -p "$WORK/.claude" "$WORK/.codex" "$WORK/.cursor" "$WORK/.github"
mkdir -p "$FAKEHOME/.claude" "$FAKEHOME/.codex"
cd "$WORK" || exit 1

pass=0; fail=0
ok()  { printf '  \033[32m✓\033[0m %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  \033[31m✗\033[0m %s\n' "$1"; fail=$((fail+1)); }

# Are we resolving from the registry, or from a local tarball?
#
# This distinction is load-bearing, not cosmetic. `npx vaid-skill` works because
# npx resolves `vaid-skill` as a PACKAGE NAME on the registry — that resolution IS
# the thing that was broken, and a tarball path cannot exercise it. So the literal
# install command can only be fully verified AFTER publishing.
#
# In tarball mode the same binaries are still run, via the `-p <tarball> <bin>`
# equivalent, which gates everything except name resolution. The script says which
# mode it is in and what that mode cannot prove, rather than reporting a pass that
# means less than it looks.
case "$SPEC" in
  *.tgz|*/*) MODE="tarball"; RESOLVES_NAMES=0 ;;
  *)         MODE="registry"; RESOLVES_NAMES=1 ;;
esac

# Run a documented command verbatim and assert its exit code.
doc() {
  local want="$1" desc="$2"; shift 2
  local -a cmd=()
  for a in "$@"; do cmd+=("${a//vaid-skill-SPEC/$SPEC}"); done
  "${cmd[@]}" >/dev/null 2>&1
  local got=$?
  if [ "$got" = "$want" ]; then ok "$desc"; else bad "$desc — exit $got, expected $want"; fi
}

# A documented command whose literal form depends on npx resolving a PACKAGE NAME.
# Run verbatim against the registry; run the `-p` equivalent against a tarball, and
# label it so nobody reads it as having confirmed the literal string.
docname() {
  local want="$1" desc="$2" bin="$3"; shift 3
  if [ "$RESOLVES_NAMES" = "1" ]; then
    doc "$want" "$desc" npx --yes "$bin" "$@"
  else
    npx --yes -p "$SPEC" "$bin" "$@" >/dev/null 2>&1
    local got=$?
    if [ "$got" = "$want" ]; then
      ok "$desc  [tarball mode: ran via -p; literal name resolution NOT covered]"
    else
      bad "$desc — exit $got, expected $want  [tarball mode]"
    fi
  fi
}

printf '\n\033[1mDOCUMENTED COMMANDS, VERBATIM\033[0m  (%s: %s)\n' "$MODE" "$SPEC"
[ "$RESOLVES_NAMES" = "1" ] || printf '  \033[33mtarball mode — npx PACKAGE-NAME resolution is not exercised.\n  The literal `npx vaid-skill` can only be confirmed against the registry.\033[0m\n'
printf '\n'

# --- the install path: the command the site and README lead with ---------------
docname 0 "npx vaid-skill                    (the install command)" vaid-skill --dry-run
docname 0 "npx vaid-skill --global"                                 vaid-skill --global --dry-run
docname 0 "npx vaid-skill --agent claude"                           vaid-skill --agent claude --dry-run
docname 0 "npx vaid-skill --help"                                   vaid-skill --help

# --- the CLI over npx: needs -p, which is the whole trap ------------------------
doc 0 "npx -p vaid-skill vaid --help"        npx --yes -p vaid-skill-SPEC vaid --help
doc 0 "npx -p vaid-skill vaid mint …"        npx --yes -p vaid-skill-SPEC vaid mint --class orchestrator --tenant acme --scope data.acme --caps read --ttl 24 --quiet
doc 0 "npx -p vaid-skill vaid revoke --list" npx --yes -p vaid-skill-SPEC vaid revoke --list
doc 0 "npx -p vaid-skill vaid verify --trusted" npx --yes -p vaid-skill-SPEC vaid verify --trusted

# --- CONTROLS: the shapes that must NOT work -----------------------------------
# These two are about REGISTRY NAME RESOLUTION and are meaningless in tarball
# mode, where they would fail for the wrong reason (no such file) and read as
# passes. Skipped explicitly rather than silently.
if [ "$RESOLVES_NAMES" = "1" ]; then
  # The original defect, pinned so it cannot come back under another name.
  doc 1 "CONTROL npx vaid-skill-install is NOT resolvable"  npx --yes vaid-skill-install --dry-run
  # npx without -p cannot reach a bin whose name is not the package's.
  doc 1 "CONTROL npx vaid (no -p) does not resolve"         npx --yes vaid --help
else
  printf '  \033[2m·\033[0m %s\n' "SKIPPED in tarball mode: the two name-resolution controls"
fi
# The installer and the CLI are one flag apart.
docname 2 "CONTROL npx vaid-skill verify … is refused"    vaid-skill verify vaid1:xxx

printf '\n\033[1mTHE DOCUMENTED LOOP, END TO END THROUGH npx\033[0m\n\n'

ENVL=$(npx --yes -p "$SPEC" vaid mint --class orchestrator --tenant acme --scope data.acme --caps read --ttl 24 --quiet 2>/dev/null)
case "$ENVL" in vaid1:*) ok "mint emits a single vaid1: line" ;; *) bad "mint emitted nothing usable" ;; esac

KEY=$(npx --yes -p "$SPEC" vaid mint --quiet --json 2>/dev/null | node -p "JSON.parse(require('fs').readFileSync(0,'utf8')).issuer" 2>/dev/null)
case "$KEY" in urn:ietf:*=*) ok "mint --json exposes the issuer key line" ;; *) bad "no issuer line from mint --json" ;; esac

OTHER="$(mktemp -d)"
env VAID_HOME="$OTHER" npx --yes -p "$SPEC" vaid verify "$ENVL" >/dev/null 2>&1
[ $? -eq 1 ] && ok "a second machine rejects it — issuer not trusted yet" || bad "an untrusted issuer was accepted"

env VAID_HOME="$OTHER" npx --yes -p "$SPEC" vaid verify "$ENVL" --trust "$KEY" >/dev/null 2>&1
[ $? -eq 0 ] && ok "accepted once the issuer key is supplied out of band" || bad "verify rejected a good VAID"

env VAID_HOME="$OTHER" npx --yes -p "$SPEC" vaid verify 'not a vaid' >/dev/null 2>&1
[ $? -eq 4 ] && ok "CONTROL garbage refused (exit 4)" || bad "garbage was not refused"
rm -rf "$OTHER"

printf '\n\033[1mTHE DOCUMENTED DECODE RECIPE, COPIED FROM README.md\033[0m\n\n'

# Copied character for character from the README/SKILL.md block. If they diverge,
# the coverage check below fails and points at it.
ENVELOPE="$ENVL"
b=${ENVELOPE#vaid1:}; b=$(printf '%s' "$b" | tr '_-' '/+')
while [ $(( ${#b} % 4 )) -ne 0 ]; do b="$b="; done
TEN=$(printf '%s' "$b" | base64 -d 2>/dev/null | node -p "JSON.parse(require('fs').readFileSync(0,'utf8')).vaid.tenant_id" 2>/dev/null)
[ "$TEN" = "acme" ] && ok "the recipe decodes to readable JSON with no VAID tooling" \
                    || bad "the documented decode recipe failed (got '$TEN')"

printf '\n\033[1mCOVERAGE — every command in the shipped docs is exercised above\033[0m\n\n'

# A command added to the docs and not to this file is the exact failure this suite
# exists to prevent, so absence of coverage is itself a failure.
UNCOVERED=$(grep -rhoE 'npx (--yes )?(-p vaid-skill )?[a-z-]+' \
              "$PKGDIR/README.md" "$PKGDIR/skills/vaid/SKILL.md" 2>/dev/null \
            | sed 's/--yes //' | sort -u \
            | grep -vE '^npx (vaid-skill|-p vaid-skill vaid)$' || true)
if [ -z "$UNCOVERED" ]; then
  ok "no documented npx command outside the two covered forms"
else
  bad "documented but not covered by this file:"
  printf '      %s\n' $UNCOVERED
fi

printf '\n'
if [ "$fail" -eq 0 ]; then
  printf '\033[32m%s passed, 0 failed\033[0m\n\n' "$pass"; exit 0
else
  printf '\033[31m%s passed, %s FAILED\033[0m\n\n' "$pass" "$fail"; exit 1
fi
