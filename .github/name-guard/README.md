# name-guard

`terms.sha256.json` is a list of **salted SHA-256 hashes of normalised terms**. It
holds no words. It exists so that CI can refuse a diff that adds a client,
prospect, partner or employer name to this repository, without that list of names
ever being published.

The checker is [`scripts/verify-no-guarded-terms.mjs`](../../scripts/verify-no-guarded-terms.mjs);
its header carries the full rationale. The short version:

- **This repository is public.** A plaintext term list committed here would *be*
  the exposure it exists to prevent — and the file in question is a
  name-to-euphemism mapping, which is worse to publish than a bare mention. A
  plaintext checker would also match itself.
- **The salt is committed on purpose.** A fork's pull request receives no secrets,
  and a check that silently skips exactly the traffic it most needs to see is worse
  than no check. The consequence is that this is **obfuscation, not secrecy**:
  anyone with this repository and an ordinary name dictionary can recover the
  entries offline, cheaply. That is accepted, because the threat model is *us*
  reintroducing a name by accident, not an adversary recovering the list.
- **Failures name the file and line, never the term.** CI logs on a public
  repository are public.

## If CI fails on this check

Open each reported file and line and replace the name with the role. The mapping is
the right-hand side of `docs/archive/purge-2026-08-23/syn-replacements.txt` in the
**private** `solara` repository.

Do not add the term to an allowlist, and do not paste the term into the pull
request or an issue while asking about it.

## Changing the list

The plaintext never enters this repository, so entries are not edited here.
Regenerate the file from the canonical list in the private `solara` repository and
commit only the result. Changing the salt invalidates every entry, so change both
together or neither.

## Scope

`vaid` only, deliberately. It goes no further until it has run here — this is the
one public repository, so it is both the highest-value place for the control and
the only place where the hashed design is strictly required. Rollout order after
that is recorded in
`docs/findings/the-refs-a-rewrite-cannot-reach-and-the-two-attestations-that-bind-it.md`
in the private `solara` repository.
