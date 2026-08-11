# What VAID claims, and where it stops

This document states the boundary of what VAID does. It is here because a
credential format is only worth as much as the precision of its claims, and
because the fastest way to find out whether a security claim is real is to ask
what it excludes. A claim with no stated boundary is not a strong claim; it is an
unfalsifiable one.

Everything below is a scope decision. Each names a thing VAID does not attempt,
and the reason it does not attempt it. None of them is a roadmap item waiting to
be closed.

---

## Tamper-evident, not tamper-proof

A VAID is a signed document. The signature covers every identity-bearing field,
and a verifier holding the issuer's public key can determine whether the document
in front of it is the document that was signed.

That is **detection**, and detection is the whole of it. Nothing in VAID prevents
a party from altering a document, presenting a fabricated one, copying one, or
declining to present one at all. What it guarantees is that alteration and
fabrication do not survive a verification — the modified document simply stops
verifying, and the verifier can say so without consulting the issuer.

The distinction is not pedantry. "Tamper-proof" implies a custodian enforcing
integrity at rest, which would mean a trusted intermediary, which is precisely
the dependency VAID exists to remove. A verifier that must ask someone whether a
document was tampered with has replaced cryptographic evidence with a phone call.
Tamper-evidence is the weaker property and the one that holds without a
custodian, which is why it is the one claimed.

The corollary is that possession of a valid VAID is not proof of authorisation to
present it. A stolen credential verifies. Binding a credential to its holder is a
proof-of-possession question, answered separately by asking the presenter to sign
a fresh challenge with the key the document names; a VAID on its own answers only
"was this issued, and to whom".

## Revocation is a refusal at the next check

Revoking a VAID means that the next verifier to consult revocation state will
refuse it, and every verifier after that.

It does not reach out and stop an agent that is already running. There is no
callback, no kill signal, and no channel from the issuer to a workload in
progress. An agent holding a revoked credential and mid-task continues until it
next needs to prove who it is — and it is that moment, not the moment of
revocation, when the refusal happens.

This is deliberate. Remote termination requires a control channel from the issuer
into every workload, which means an issuer that can reach into environments it
does not own, and a verification path that fails whenever that channel is
unavailable. VAID is designed so that verification works offline, at the edge,
and in environments the issuer has no route into. Those two properties are
mutually exclusive: you can have verification that needs nothing, or you can have
remote termination, and this project chose the first.

What this buys is a bound you can reason about. The exposure after revocation is
the interval to the next verification, which is set by how often relying parties
check and by credential lifetime — both of which are yours to choose, and neither
of which depends on the issuer being reachable. A short lifetime is the lever
here. An operator who needs a tighter bound tightens it by shortening lifetimes
and verifying more often, not by waiting for a signal that may not arrive.

Revocation state is also something a verifier can fail to reach, and VAID treats
that as its own answer rather than folding it into either "fine" or "revoked".
A verifier that cannot determine revocation status says exactly that, and the
document does not verify. Unavailable never reads as valid.

## A hash-chained log proves integrity, not completeness

A hash-chained audit log proves that the entries it contains have not been
altered and have not been reordered. Each entry commits to its predecessor, so
changing or moving one breaks every link after it.

It does not prove that the entries it contains are all the entries there were.

An agent that simply never writes a record leaves a chain that is intact,
verifiable, and silent about the thing it omitted. The chain has no way to
represent an absence: there is no gap to detect, because a record that was never
written leaves nothing behind. This is a property of hash chaining itself, not a
defect in any particular implementation, and **it applies to VAID exactly as it
applies to everyone else who ships one.** Anyone claiming a hash-chained log
gives them a complete record of what an agent did is claiming something the
construction cannot deliver.

Saying so first is worth more than being quiet about it. The completeness
question is real, it is unsolved by chaining, and an operator who believes
otherwise will build a control on a foundation that does not bear the weight.
Completeness needs a different mechanism — an independent observer on the path
that records the interaction whether or not the agent cooperates — and where that
observer exists, it is the observer, not the chain, doing the work.

What the chain is good for is what it actually proves: given a record, that it
has not been rewritten since. That is the property that matters when the dispute
is about whether a log was edited after the fact, which is a common dispute and
one that chaining settles cleanly.

## Where VAID is the right answer, and where it is not

The honest wedge is narrow and worth naming precisely.

**VAID earns its place when the verifier and the issuer are not in the same trust
domain.** Specifically:

- **Agent-to-agent across organisations.** Two agents belonging to different
  companies need to establish who the other is, with delegation and scope
  intact, and there is no shared control plane to ask. The credential has to
  carry its own evidence because there is no third party both sides already
  trust.
- **Offline and edge verification.** The verifier has the issuer's public key and
  nothing else — no network path back, or no willingness to depend on one.
  Verification that requires a call to the issuer is not verification in this
  setting; it is availability coupling.
- **Post-hoc proof where the gateway operator is not a neutral party.** When the
  question is "what did this agent present, and under whose authority", an
  attestation produced by the same party whose conduct is in question is not
  evidence anyone should have to accept. A signature the operator could not have
  forged is.

**VAID is not the right answer for a buyer already inside one cloud with one
gateway.** If every agent, every workload and every verifier sits behind a single
gateway operated by a party everyone already trusts, that gateway can attribute
every call authoritatively — it sees them all, it is already in the path, and it
is already trusted. Adding a portable credential to that picture buys very little
and costs integration work. A buyer in that position who says gateway attribution
is sufficient is reading their own situation correctly, and it would be dishonest
to tell them otherwise.

The threshold is the second trust domain. The moment a verifier appears that the
gateway does not speak for — a partner's agent, a regulator asking after the
fact, a workload at the edge of the network — attribution has to travel with the
credential, because there is no longer one party positioned to vouch for
everyone. That is the boundary. Below it, gateway attribution; above it,
portable evidence.

## Prior art

VAID is not the first attempt at agent identity, and the problem is not ours
alone. Work we have read and taken seriously:

- **Prakash** — on agent identity and delegation, and on the difficulty of
  attributing action to a principal through layers of automation.
- **Singla** — on authentication and provenance for autonomous agents.
- **DIF KYA-OS** — the Decentralized Identity Foundation's Know-Your-Agent work,
  which addresses the identity-establishment problem from the verifiable-credential
  direction and shares much of this document's framing about what a credential can
  and cannot settle.
- **ANS** — Agent Name Service, addressing discovery and naming, which is the
  layer beneath the question VAID answers and a genuine dependency for anything
  operating at scale.

Where these overlap with VAID they are worth comparing on the merits rather than
on marketing. Where they solve something VAID does not, that is not a gap in this
document — it is the ecosystem working as it should.

---

## How to read a claim about this project

If a statement about VAID is not supported by something in this repository that
can be executed, treat it as marketing rather than as a specification. The
conformance vectors, the cross-language checks and the packaged verification
tools exist so that claims about behaviour can be settled by running something
rather than by reading a page. That standard applies to this document too: where
the prose here and the code disagree, the code is what ships, and the prose is
what needs fixing.
