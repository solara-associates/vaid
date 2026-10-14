# Delegation depth

**Prose specification. VAID.**
Revision 1, 13 October 2026. Written alongside `vaid-mint` 0.11.0, which makes
delegation depth a configurable mint policy.

Terminology follows the repo: a **VAID** is the document (`Vaid`); **delegation**
is the `mint_child` act of issuing an attenuated child from an authenticated
parent; a chain's **depth** is the number of delegation hops from its root (a
root is depth 0, a direct child is depth 1, and so on).

---

> **Companion document.** [`revocation.md`](revocation.md) R.1 draws the same
> line for a different concern: this document excludes delegation-depth
> *limiting* from the conformance surface for the same reason revocation is
> excluded — the limit is deployment policy, not a document-format rule — while
> leaving the *document format* (`parent_vaid`, lineage hashing) exactly where
> [`encoding.md`](encoding.md) already specifies it, unchanged.

## D.1 Delegation depth is mint policy, not a protocol rule

An issuer MAY limit how many delegation hops it will mint. This is **issuer /
mint policy**, decided by whoever operates the mint, not a rule of the VAID
document format or of verification.

The reference mint (`vaid-mint` 0.11.0) enforces a **configurable maximum
delegation depth, defaulting to 1**: by default it mints a child from a root but
refuses to mint a grandchild. An issuer MAY configure a deeper limit. There is no
configuration value meaning "unlimited" — an issuer needing deeper chains sets a
concrete number, bounded by the implementation's lineage-depth bound (the same
defensive bound `revocation.md` R.4's lineage assembly already uses to stop a
cyclic or implausibly deep chain, rather than a second limit of its own).

## D.2 Verifiers MUST NOT reject a chain on depth alone

A **verifier** MUST NOT reject an otherwise well-formed delegation chain solely
because of its depth, unless the verifier's own deployment has configured a
depth limit for that purpose. Depth-limiting is something a mint applies when
*issuing* a chain, and something a verifier's deployment MAY separately choose
to apply when *accepting* one; neither is implied by the other, and the VAID
document format carries no field that states a limit.

A chain's depth is not itself evidence of anything beyond its own length: a
longer chain is not less authentic, and every hop still attenuates its parent
exactly as `encoding.md` and the attenuation rules require regardless of depth.

## D.3 Conformance vectors are unaffected

Delegation-depth limiting is excluded from the frozen conformance vectors. A
vector that exercises a multi-hop chain — including a depth-2 chain — continues
to exercise the document format and verification rules only; it says nothing
about what any particular mint was configured to allow, and no vector is
changed, added, or reinterpreted by this document. An implementation that mints
a vector's chain in a test or example configures its depth limit however the
test needs it to; the vector itself never carries, and never acquires, an
opinion on the subject.
