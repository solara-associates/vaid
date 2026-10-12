#!/usr/bin/env python3
"""VAID in five minutes: mint, delegate, verify, and watch three denials happen.

Run it:

    pip install 'vaid-mint>=0.9,<0.10'
    python examples/quickstart/quickstart.py

Nothing is written to disk and no network call is made. The signing keys are
generated in memory and discarded when the process exits, so this is safe to run
anywhere, including a throwaway notebook.

What you will see, in order:

    1. a root identity minted for an orchestrator agent
    2. a narrower child identity delegated to a worker agent
    3. a third party verifying the whole chain with only the public key
    4. three denials, each with the reason it was denied
    5. a revoked identity denied through the RevocationCheck seam

It exits non-zero if any step does not behave as described, so CI can run it as a
test of the published package rather than as documentation nobody executes.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vaid_pop import canonical_request_signing_bytes

from vaid_mint import (
    ChainVerification,
    InMemoryAudit,
    MintService,
    MintPop,
    PresentedBundle,
    ReferenceIssuer,
    RevocationStatus,
    VaidSeed,
    VaidVerdict,
    build_mint_pop_payload,
    has_capability,
    is_in_scope,
    verify_chain,
    verify_vaid_authenticity,
    verify_vaid_standing,
)
from vaid_mint.error import UnauthorizedError

failures: list[str] = []


def check(label: str, condition: bool) -> None:
    """Record, rather than print, so the narrative below stays readable."""
    if not condition:
        failures.append(label)


def rule(title: str) -> None:
    print()
    print(title)
    print("-" * len(title))


def holder_keypair() -> tuple[Ed25519PrivateKey, bytes]:
    """A key the agent itself holds. The mint never sees the private half."""
    private = Ed25519PrivateKey.generate()
    public_raw = private.public_key().public_bytes_raw()
    return private, public_raw


def prove_possession(seed: VaidSeed, private: Ed25519PrivateKey, public_raw: bytes) -> MintPop:
    """Sign the mint's proof-of-possession challenge with the holder's own key.

    A delegated child always registers a key it holds, and the mint will not take
    the registration on trust: the holder signs a canonical payload naming the key
    and the exact attributes being requested, and the mint rebuilds the same bytes
    and checks the signature. Both sides go through build_mint_pop_payload so the
    bytes cannot drift apart.
    """
    nonce = f"quickstart-{id(private):x}"
    issued_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = build_mint_pop_payload(
        seed, public_key_der=public_raw, nonce=nonce, issued_at=issued_at
    )
    signature = private.sign(canonical_request_signing_bytes(payload))
    return MintPop(nonce=nonce, issued_at=issued_at, signature=signature)


print("VAID in five minutes: mint, delegate, verify, and watch three denials happen.")

# ---------------------------------------------------------------------------
rule("Step 0: stand up a mint")

issuer = ReferenceIssuer.ephemeral(24, "vaid.example").assuming_nothing_revoked()
mint = MintService(issuer, InMemoryAudit())
kernel_key = issuer.kernel_public_key()

print(
    "A mint holds one signing key, called the kernel key, and stamps its trust\n"
    "domain into everything it issues. This one is ephemeral: the key exists only\n"
    "for the life of this process. Its PUBLIC half is the only thing a third party\n"
    "needs in order to check anything below, and that is what makes VAID offline:\n"
    "no callback to the issuer, ever."
)
print()
print("  trust domain      : vaid.example")
print(f"  kernel public key : {kernel_key.hex()[:32]}... ({len(kernel_key)} bytes)")
print()
print(
    "  Read that .assuming_nothing_revoked() before you copy this line anywhere.\n"
    "  A fresh issuer has no revocation store it can vouch for, so out of the box it\n"
    "  answers 'unavailable' and issuer.verify_vaid() DENIES everything, including\n"
    "  documents it just minted. That is deliberate: a revocation answer you could\n"
    "  not obtain must not read as 'nothing is revoked'. The call above opts into the\n"
    "  fail-OPEN posture by name, which is correct for a quickstart on a laptop and\n"
    "  wrong for anything that has to survive a restart."
)

# ---------------------------------------------------------------------------
rule("Step 1: mint a root identity")

orchestrator_key, orchestrator_pub = holder_keypair()
root_seed = VaidSeed(
    agent_class="orchestrator",
    version="1.0.0",
    tenant_id="acme",
    scope_boundary=["data.acme"],
    capability_set=["read", "write"],
    public_key_der=orchestrator_pub,
)
root = mint.mint_root(root_seed, prove_possession(root_seed, orchestrator_key, orchestrator_pub))

print(
    "A VAID is a signed statement about one agent: who it is, which tenant it acts\n"
    "for, which resources it may touch (its scope boundary), what it may do to them\n"
    "(its capability set), and when that authority runs out. This root is the widest\n"
    "authority in the example. Everything after it can only be narrower."
)
print()
print(f"  vaid_id        : {root['vaid_id']}")
print(f"  agent_class    : {root['agent_class']}")
print(f"  tenant_id      : {root['tenant_id']}")
print(f"  scope_boundary : {root['scope_boundary']}")
print(f"  capability_set : {root['capability_set']}")
print(f"  expires_at     : {root['expires_at']}")
check("root verifies under its own issuer", issuer.verify_vaid(root))
check("root is authentic under the kernel key", verify_vaid_authenticity(kernel_key, root))

# ---------------------------------------------------------------------------
rule("Step 2: delegate a narrower child")

worker_key, worker_pub = holder_keypair()
child_seed = VaidSeed(
    agent_class="report-worker",
    version="1.0.0",
    tenant_id="acme",
    parent_vaid=root["vaid_id"],
    scope_boundary=["data.acme.reports"],
    capability_set=["read"],
    public_key_der=worker_pub,
)
child_response = mint.mint_child(
    child_seed, root, prove_possession(child_seed, worker_key, worker_pub)
)
child = child_response.vaid

print(
    "The orchestrator hands part of its authority to a worker. The mint checks that\n"
    "the request is a subset of what the parent holds on every axis at once: same\n"
    "tenant, scope inside the parent's scope, capabilities the parent actually has,\n"
    "and a lifetime that cannot outlast the parent's. The child below can read one\n"
    "branch of the data the parent could read and write to all of."
)
print()
print(f"  vaid_id                  : {child['vaid_id']}")
print(f"  parent_vaid              : {child['parent_vaid']}")
print(f"  scope_boundary           : {child['scope_boundary']}  (was {root['scope_boundary']})")
print(f"  capability_set           : {child['capability_set']}  (was {root['capability_set']})")
print(f"  expires_at               : {child['expires_at']}")
print(f"  expiry_bounded_by_parent : {child_response.expiry_bounded_by_parent}")
print(f"  parent_expires_at        : {child_response.parent_expires_at}")
check("child verifies under its own issuer", issuer.verify_vaid(child))
check("child never outlives its parent", child["expires_at"] <= root["expires_at"])

# ---------------------------------------------------------------------------
rule("Step 3: verify the chain as a stranger would")

bundle = PresentedBundle([root, child])
verdict = verify_chain(kernel_key, child, bundle)

print(
    "A child carries its own scope and capabilities, not its ancestors'. So checking\n"
    "the signature alone cannot answer whether the authority was legitimately derived;\n"
    "for that, the holder presents the ancestor documents alongside the leaf and the\n"
    "verifier walks the chain, re-checking tenant, scope, capabilities and expiry at\n"
    "every hop. Below, that walk is done with the public key and the two documents and\n"
    "nothing else: no network, no cooperation from the mint."
)
print()
print(f"  documents presented : {len(bundle)}")
print(f"  verdict             : {verdict.name}  (code '{verdict.value}')")
print(f"  attenuation proved  : {verdict.is_attenuated()}")
print()
print(
    "The verdict is an enum, not a boolean, so that 'attenuation satisfied' can never\n"
    "be confused with 'attenuation unverifiable'. The other values it can take are\n"
    + ", ".join(
        sorted(v.value for v in ChainVerification if v is not ChainVerification.ATTENUATED)
    )
    + "."
)
check("chain verifies as attenuated", verdict is ChainVerification.ATTENUATED)

# ---------------------------------------------------------------------------
rule("Step 4: three denials, with the reason for each")

print(
    "Minting is the easy half. What makes an identity useful is what it refuses, so\n"
    "here are the three refusals you will meet first. The first two are decisions your\n"
    "own code makes at the moment it is about to act; the third is the mint refusing to\n"
    "issue at all."
)

# 4a. Out of scope.
out_of_scope_resource = "data.acme.payroll"
allowed = is_in_scope(child, out_of_scope_resource)
print()
print("  (1) The worker reaches for a resource outside its scope boundary.")
print(f"      resource     : {out_of_scope_resource}")
print(f"      held scope   : {child['scope_boundary']}")
print(f"      decision     : {'ALLOWED' if allowed else 'DENIED'}")
print("      reason       : out_of_scope")
print(
    "      Containment is segment bounded, not a text prefix, so a sibling branch is\n"
    "      never inside its neighbour. Note that the PARENT could reach this resource;\n"
    "      the child gave that up when it was delegated."
)
check("out-of-scope resource denied", not allowed)
check("parent could still reach it", is_in_scope(root, out_of_scope_resource))

# 4b. Missing capability.
missing_capability = "write"
held = has_capability(child, missing_capability)
print()
print("  (2) The worker tries an action it holds no capability for.")
print(f"      capability   : {missing_capability}")
print(f"      held caps    : {child['capability_set']}")
print(f"      decision     : {'ALLOWED' if held else 'DENIED'}")
print("      reason       : missing_capability")
print(
    "      Scope answers WHICH resource, capabilities answer WHAT TO IT. Both have to\n"
    "      say yes, and they are checked separately because they fail for different\n"
    "      reasons and need different fixes."
)
check("missing capability denied", not held)
check("parent holds that capability", has_capability(root, missing_capability))

# 4c. A child trying to widen its parent.
grandchild_key, grandchild_pub = holder_keypair()
widening_seed = VaidSeed(
    agent_class="over-reaching-worker",
    version="1.0.0",
    tenant_id="acme",
    parent_vaid=child["vaid_id"],
    scope_boundary=["data.acme"],
    capability_set=["read"],
    public_key_der=grandchild_pub,
)
print()
print("  (3) The worker tries to delegate MORE than it holds.")
print(f"      requested scope : {widening_seed.scope_boundary}")
print(f"      worker's scope  : {child['scope_boundary']}")
denied_message = None
try:
    mint.mint_child(
        widening_seed,
        child,
        prove_possession(widening_seed, grandchild_key, grandchild_pub),
    )
    print("      decision        : ALLOWED")
except UnauthorizedError as exc:
    denied_message = str(exc)
    print("      decision        : DENIED (UnauthorizedError)")
    print("      reason          : scope_exceeds_parent")
    print(f"      message         : {denied_message}")
print(
    "      This one is refused before any key work happens, so a rejected delegation\n"
    "      leaves no trace and burns nothing. The same containment rule is applied\n"
    "      again by the chain verifier in step 3, which is the part that matters: a\n"
    "      widened document minted by some other, laxer mint still fails verification\n"
    "      at the hop that widened, as NOT_ATTENUATED."
)
check("widening delegation denied", denied_message is not None)

# ---------------------------------------------------------------------------
rule("Step 5: a revoked identity, through the RevocationCheck seam")

issuer.revoke(child["vaid_id"])
status = issuer.revocation_status(child)
standing = verify_vaid_standing(kernel_key, child, status)

print(
    "Revocation is deliberately NOT part of the offline check, because an offline\n"
    "verifier has nothing to consult. It is a seam: you plug in something that answers\n"
    "revoked, not revoked, or unavailable, and verification uses that answer. The\n"
    "in-memory store opted into in step 0 is enough to see the shape. Three states and\n"
    "not two, because 'I could not reach the list' must not read as 'nothing is\n"
    "revoked', and an unavailable answer fails closed."
)
print()
print(f"  revoked              : {child['vaid_id']}")
print(f"  revocation status    : {status.value}")
print(f"  standing verdict     : {standing.name}  (code '{standing.value}')")
print(f"  still authentic?     : {verify_vaid_authenticity(kernel_key, child)}")
print(
    "\n  Note the last two lines together. The document is still authentic: it was\n"
    "  genuinely issued and its signature is intact, and revoking it cannot change\n"
    "  that. Authenticity and standing are different questions. Read a signature\n"
    "  check as 'genuinely issued', never as 'currently authorised'."
)
print()
print("  Revoking a parent revokes everything attenuated from it, so you do not have")
print("  to enumerate a delegation tree to shut it down.")
check("revocation status is revoked", status is RevocationStatus.REVOKED)
check("standing verdict is revoked", standing is VaidVerdict.REVOKED)
check("revoked document is still authentic", verify_vaid_authenticity(kernel_key, child))

# ---------------------------------------------------------------------------
rule("Done")

if failures:
    print(f"{len(failures)} step(s) did not behave as described:")
    for f in failures:
        print(f"  FAILED: {f}")
    sys.exit(1)

print(
    "Every step above behaved as described. You have minted a root identity,\n"
    "delegated a narrower one, verified the chain with nothing but a public key,\n"
    "seen three denials with their reasons, and seen revocation handled as a\n"
    "separate question from authenticity.\n"
    "\n"
    "Where to go next:\n"
    "  * docs/spec/encoding.md   the rules that decide the signed bytes\n"
    "  * docs/spec/scope.md      how scope containment is decided\n"
    "  * docs/spec/revocation.md the RevocationCheck seam, and why it sits outside\n"
    "  * npx vaid-skill          the same four verbs inside a coding agent"
)
