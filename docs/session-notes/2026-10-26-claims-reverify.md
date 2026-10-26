# Claims-register re-verification, 2026-10-26 (session s447)

Re-verification of `framework-governance-demonstrated` against today's `origin/main`
of this repo and of `forge-agents`, triggered by `scripts/verify-claims.mjs` failing
on `date_last_verified: 2026-07-28` (90 days old, at the FAIL budget).

## What the claim says and where it is backed

The claim cites three pieces of evidence: the ADK and OpenAI live conformance
harnesses in `forge-agents/harness/`, and the published `vaid-langchain` package
in this repo.

## What was re-checked

**1. `vaid-langchain` (published, conformance-tested): HOLDS.**

```
curl -s https://pypi.org/pypi/vaid-langchain/json | python3 -c "..."
-> vaid-langchain 0.1.0, releases: ['0.1.0']
```

```
python3 -m venv /tmp/vaid-venv-test
pip install -e python/vaid-langchain -e python/vaid-pop langchain-core pytest
python -m pytest python/vaid-langchain/tests -v
-> 14 passed in 0.27s
```

Fourteen tests pass against this checkout's current `main`
(`4cc6bc3439ef7d926ee780cd7f85f61577d5f953`), including the request-signing,
PoP-verification and path-convention suites that back "identity and attenuated
request-signing, demonstrated for the LangChain adapter."

**2. ADK and OpenAI live conformance (`forge-agents/harness/phase1e_*_conformance.py`):
NOT re-verifiable from this evidence, and the dated artifact it points at predates
a relevant fix.**

The cited artifact, `forge-agents/harness/artifacts/phase1e-conformance-2026-07-28.md`,
and its 2026-07-29 rerun (`phase1e-conformance-2026-07-29.md`, rerun for an unrelated
substrate release, same harness image `:6267345`, same forge-agents SHA `62673455`),
both ran before `forge-agents` commit `a001dac6b9c1f6c72be52ba75cbf0570dbeca986`
(2026-07-30, "fix(agent-mvp): resolve the remaining 39 ruff findings; one was a real
fail-open"). That commit fixed `Response.denied()` in all three governed-agent
templates' `transport.py`: an unparseable 200-body was read as **not denied**
(fail-open), in the exact function the harnesses' over-envelope-denial checks
(checks 4, 4.handoff, 4.agent_tool) depend on. The recorded runs were not corrupted
by this, the body parsed and the deny was explicit in both, but the harness code
backing the dated artifact is not the harness code on `forge-agents` `main` today,
and no conformance run has been recorded since the fix landed.

The 2026-07-29 artifact also carries its own coverage note (added 2026-08-21):
both harnesses attest single-child delegation only, and a since-fixed bug in how
the check selects the record it inspects would have silently passed a two-child
run while examining only one entry. Not corrected by a rerun either.

No live rerun was performed in this session: triggering `phase1e-conformance`
against `synthera-substrate-prod` mints real VAIDs under the production operator
KMS key and is a production action, not something to trigger unilaterally while
re-verifying a documentation check. Decided with the repository owner: narrow the
claim rather than trigger a live rerun.

## Outcome

The claim is narrowed, not retracted outright: the LangChain portion is reverified
today against current `main`. The ADK/OpenAI portion is withdrawn from the claim
until a fresh live run exists. See `docs/claims-register.json`'s
`needs_reverification` field on this entry for exactly what that rerun must show.
