# Security Policy

VAID is a cryptographic interoperability standard (RFC 8785 JCS → SHA-256 →
Ed25519). We take vulnerabilities — especially any that could let a forged or
malformed VAID be accepted by a conforming verifier — seriously.

## Supported versions

VAID is pre-1.0. Security fixes are applied to the latest `main` and the most
recent published release of each SDK (`vaid-pop`, `vaid-client`). Older
pre-release versions are not maintained.

| Component | Supported |
|---|---|
| `main` (latest) | ✅ |
| Latest published `0.1.x` SDK release | ✅ |
| Anything older | ❌ |

## Reporting a vulnerability

**Do not open a public GitHub issue for security reports.**

Email **info@solara.associates** with:

- a description of the issue and its impact,
- a minimal reproduction (ideally a vector or signed payload that is wrongly
  accepted/rejected), and
- the affected component(s) and version(s).

You can expect an acknowledgement within **3 business days** and a triage
assessment within **10 business days**. We will coordinate a disclosure timeline
with you and credit reporters who wish to be credited.

## Scope

In scope: signature forgery or bypass, canonicalization ambiguities that break
cross-verifier agreement, key-handling flaws in the reference SDKs, and
denial-of-service in the PoP path.

Out of scope: issues in downstream applications that merely *use* VAID, and
theoretical weaknesses in the underlying primitives (Ed25519, SHA-256, JCS)
absent a concrete attack on this implementation.
