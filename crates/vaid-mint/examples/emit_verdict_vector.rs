//! Generator for the frozen negative-path vector (`verdict_v1.json`).
//!
//! Run with `cargo run -p vaid-mint --example emit_verdict_vector` to print the
//! vector JSON.
//!
//! Written for the v4 re-freeze (ADR-0009). Until then this vector had no
//! generator: 32 signed documents, several of them deliberately forged in
//! specific ways, could only be re-frozen by hand. That is how a signature gets
//! edited into agreement with bytes nobody recomputed, and how a case that was
//! meant to be a forgery quietly becomes authentic.
//!
//! # The pre-sign / post-sign split is the whole design
//!
//! Every case starts from ONE base document. A case's `pre_sign` overrides are
//! applied BEFORE signing, so the signature covers them: that is how `expired`,
//! `malformed_trust_domain` and `lineage_inconsistent` stay AUTHENTIC documents
//! that fail for their own stated reason rather than for being forgeries. A
//! case's `post_sign` overrides are applied AFTER signing, so the signature does
//! NOT cover them: that is what makes the tampering cases tampering.
//!
//! Putting an override on the wrong side of signing changes a case's verdict
//! while leaving its name and its `why` intact, which is the one failure mode a
//! reader of the JSON cannot see. The table below is therefore the artifact to
//! review, and `tests/verdict_conformance.rs` is what proves it: every case
//! asserts a REASON, so a misplaced override fails the suite rather than
//! silently weakening the vector.
//!
//! This table was not written by hand. It was DERIVED from the v3 vector by
//! searching, for each case, the subset of its diff-from-base whose signature
//! over the resulting bytes reproduced the committed signature exactly. 31 of the
//! 32 cases were reproduced byte-for-byte that way; the 32nd is
//! `payload valid, signature tampered`, whose signature is a corrupted literal
//! and is expressed here as `tamper_signature` rather than as a frozen byte
//! string, because a literal from v3 would be meaningless over v4 bytes.

use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::ser::{SerializeMap, Serializer};
use serde::Serialize;
use serde_json::{json, Value};

use vaid_mint::issuer_identity::kernel_key_thumbprint;
use vaid_mint::{canonical_vaid_signing_bytes, Vaid};

const KERNEL_SEED_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const FOREIGN_SEED_HEX: &str = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";

/// The base document, in VAID struct member order.
///
/// Order matters here and nowhere else in the repo: `serde_json::Map` is a
/// `BTreeMap` without the `preserve_order` feature, so going through `Value`
/// would sort the members alphabetically and change every `document_json` text in
/// the file. [`Ordered`] below writes entries as given instead.
const BASE_FIELDS: &[(&str, &str)] = &[
        ("sig_version", "4"),
        ("vaid_id", "\"c0000000-0000-4000-8000-000000000001\""),
        ("agent_id", "\"c0000000-0000-4000-8000-000000000001\""),
        ("agent_class", "\"verdict\""),
        ("version", "\"1.0.0\""),
        ("tenant_id", "\"acme\""),
        ("issued_at", "\"2020-01-01T00:00:00Z\""),
        ("expires_at", "\"2999-01-01T00:00:00Z\""),
        ("public_key_der", "[3, 161, 7, 191, 243, 206, 16, 190, 29, 112, 221, 24, 231, 75, 192, 153, 103, 228, 214, 48, 155, 165, 13, 95, 29, 220, 134, 100, 18, 85, 49, 184]"),
        ("kernel_signature", "[]"),
        ("parent_vaid", "null"),
        ("scope_boundary", "[{\"kind\": \"prefix\", \"value\": \"data.acme\"}]"),
        ("lineage_hash", "\"8f89c127be8d6e98aa288873e5b6413b9b84e6b92b1a8b99a4627f91390f16af\""),
        ("capability_set", "[\"read\"]"),
        ("trust_domain", "\"vaid.example\""),
        ("kernel_key_thumbprint", "\"urn:ietf:params:oauth:jwk-thumbprint:sha-256:1IG2tMH7J2wbJZnOf8LJzQitKf7LMvoAElsuDMVM54Y\"")
];

/// Which key signs a case's bytes.
#[derive(Clone, Copy)]
enum Signer {
    Kernel,
    /// A second, unrelated signer. Without it, "signed by a non-kernel key"
    /// cannot be expressed, and the two ways a forgery presents (a broken
    /// signature, versus a stranger's perfectly valid one) cannot be told apart.
    Foreign,
}

/// What TEXT a case presents. Half the point of this vector is input that is not
/// a document at all, and a case whose bytes cannot be expressed as a JSON object
/// cannot be written any other way.
enum TextShape {
    /// Pretty-printed from the case's members.
    Document,
    /// The document text, cut immediately after `tenant_id`. Derived rather than
    /// frozen at a byte offset, so the cut stays mid-document when the bytes move.
    TruncatedAfterTenant,
    /// `tenant_id` repeated as the FIRST member, before the document's own.
    DuplicateLeadingTenant,
    /// A duplicate member name nested inside an extension object, which is the
    /// case a top-level-only duplicate check misses (E.7a: "at any depth").
    NestedDuplicateExtension,
    /// Bytes given verbatim.
    Literal(&'static str),
}

struct StandingCase {
    name: &'static str,
    why: &'static str,
    /// Member overrides applied BEFORE signing. `None` removes the member.
    pre_sign: &'static [(&'static str, Option<&'static str>)],
    signer: Signer,
    /// Member overrides applied AFTER signing. `None` removes the member.
    post_sign: &'static [(&'static str, Option<&'static str>)],
    /// Corrupt the first signature byte after signing.
    tamper_signature: bool,
    text: TextShape,
    revocation: &'static str,
    expected_reason: &'static str,
    expected_valid: bool,
}

struct AttenuationCase {
    name: &'static str,
    why: &'static str,
    parent_scope: &'static str,
    child_scope: &'static str,
    expected_valid: bool,
    expected_reason: &'static str,
}

const STANDING_CASES: &[StandingCase] = &[
    StandingCase {
        name: "control: authentic, unexpired, revocation clean",
        why: "THE CONTROL. Without at least one case that must return valid, an implementation that rejects everything passes this entire vector. Every negative below is only meaningful because this one is here.",
        pre_sign: &[],
        signer: Signer::Kernel,
        post_sign: &[],
        tamper_signature: false,
        text: TextShape::Document,
        revocation: "not_revoked",
        expected_reason: "valid",
        expected_valid: true,
    },
    StandingCase {
        name: "expired: past its TTL",
        why: "authentic and correctly signed, and past expires_at. The signature is real, so an implementation reporting inauthentic here is confusing 'no longer usable' with 'never genuine' — different accusations about different parties.",
        pre_sign: &[("expires_at", Some("\"2020-01-01T00:00:00Z\""))],
        signer: Signer::Kernel,
        post_sign: &[],
        tamper_signature: false,
        text: TextShape::Document,
        revocation: "not_revoked",
        expected_reason: "expired",
        expected_valid: false,
    },
    StandingCase {
        name: "revoked: the store reported a revoked lineage",
        why: "authentic and unexpired; the caller's RevocationCheck said Revoked (R.4.4).",
        pre_sign: &[],
        signer: Signer::Kernel,
        post_sign: &[],
        tamper_signature: false,
        text: TextShape::Document,
        revocation: "revoked",
        expected_reason: "revoked",
        expected_valid: false,
    },
    StandingCase {
        name: "indeterminate: the revocation store could not be consulted",
        why: "THE FAIL-CLOSED CASE. An absent InMemoryRevocationList reports Unavailable, which is neither 'clean' nor 'revoked'. It MUST NOT read as valid, and it MUST NOT be collapsed into revoked: accusing a holder of revocation because a store was unreachable is a false accusation, and reporting clean is a fail-open. It is its own state.",
        pre_sign: &[],
        signer: Signer::Kernel,
        post_sign: &[],
        tamper_signature: false,
        text: TextShape::Document,
        revocation: "unavailable",
        expected_reason: "indeterminate",
        expected_valid: false,
    },
    StandingCase {
        name: "signature valid, payload tampered",
        why: "the signature is a genuine kernel signature — over DIFFERENT bytes. A scope entry was added after signing. An implementation that reported valid here would be honouring an escalation the kernel never authorised.",
        pre_sign: &[],
        signer: Signer::Kernel,
        post_sign: &[("scope_boundary", Some("[{\"kind\": \"prefix\", \"value\": \"data.acme\"}, {\"kind\": \"prefix\", \"value\": \"data.everything\"}]"))],
        tamper_signature: false,
        text: TextShape::Document,
        revocation: "not_revoked",
        expected_reason: "inauthentic",
        expected_valid: false,
    },
    StandingCase {
        name: "payload valid, signature tampered",
        why: "the other direction: untouched document, one flipped signature byte.",
        pre_sign: &[],
        signer: Signer::Kernel,
        post_sign: &[],
        tamper_signature: true,
        text: TextShape::Document,
        revocation: "not_revoked",
        expected_reason: "inauthentic",
        expected_valid: false,
    },
    StandingCase {
        name: "signed by a non-kernel key, thumbprint left as the kernel's",
        why: "a forger who signs with their own key but does not touch the commitment. The thumbprint still corresponds to the key we hold, so the key-commitment check passes and the SIGNATURE is what refuses. Reason: inauthentic.",
        pre_sign: &[],
        signer: Signer::Foreign,
        post_sign: &[],
        tamper_signature: false,
        text: TextShape::Document,
        revocation: "not_revoked",
        expected_reason: "inauthentic",
        expected_valid: false,
    },
    StandingCase {
        name: "signed by a non-kernel key, thumbprint rewritten to match it",
        why: "THE SHARP CASE, and the reason a graded verdict earns its keep. This document is internally consistent: signed by the foreign key, and committing to the foreign key. Nothing about it is self-contradictory. It is simply not OUR issuer, and the key-commitment check is what says so — BEFORE the signature check, which would have passed against the foreign key had anyone asked it. Both this and the case above are refusals; a boolean cannot tell you that one is a broken signature and the other is a stranger's valid one.",
        pre_sign: &[("kernel_key_thumbprint", Some("\"urn:ietf:params:oauth:jwk-thumbprint:sha-256:WeVHjIQTOLKu-P74oC-WL-MNn_sLM5CvrzuMjDFC3-s\""))],
        signer: Signer::Foreign,
        post_sign: &[],
        tamper_signature: false,
        text: TextShape::Document,
        revocation: "not_revoked",
        expected_reason: "issuer_mismatch",
        expected_valid: false,
    },
    StandingCase {
        name: "lineage_hash does not recompute",
        why: "signed over the bad lineage_hash, so the kernel signature is VALID and only the explicit lineage check refuses. This is why lineage is checked in its own right rather than left to the signature: a mint that signs a malformed lineage produces a document the signature happily vouches for.",
        pre_sign: &[("lineage_hash", Some("\"0000000000000000000000000000000000000000000000000000000000000000\""))],
        signer: Signer::Kernel,
        post_sign: &[],
        tamper_signature: false,
        text: TextShape::Document,
        revocation: "not_revoked",
        expected_reason: "lineage_inconsistent",
        expected_valid: false,
    },
    StandingCase {
        name: "sig_version 2 — a downgrade",
        why: "correctly signed as a v2 document. There is no dual-version acceptance (ADR-0004); accepting both would recreate the downgrade surface that signing sig_version exists to close.",
        pre_sign: &[("sig_version", Some("2"))],
        signer: Signer::Kernel,
        post_sign: &[],
        tamper_signature: false,
        text: TextShape::Document,
        revocation: "not_revoked",
        expected_reason: "unsupported_sig_version",
        expected_valid: false,
    },
    StandingCase {
        name: "sig_version absent entirely",
        why: "must PARSE and then be refused at verify, not be reported unparseable: the Rust field carries #[serde(default)] precisely so this document deserializes to 0 and gets a verdict about its version rather than about its syntax.",
        pre_sign: &[("sig_version", None)],
        signer: Signer::Kernel,
        post_sign: &[],
        tamper_signature: false,
        text: TextShape::Document,
        revocation: "not_revoked",
        expected_reason: "unsupported_sig_version",
        expected_valid: false,
    },
    StandingCase {
        name: "trust_domain is not well-formed",
        why: "correctly signed, and names an issuer nobody can look up (ADR-0004). A thumbprint is a commitment, not a key; without a well-formed domain to look it up under there is nothing to select within.",
        pre_sign: &[("trust_domain", Some("\"not a domain\""))],
        signer: Signer::Kernel,
        post_sign: &[],
        tamper_signature: false,
        text: TextShape::Document,
        revocation: "not_revoked",
        expected_reason: "malformed_trust_domain",
        expected_valid: false,
    },
    StandingCase {
        name: "truncated: cut mid-document",
        why: "the first 200 bytes of a genuine document. Rust cannot construct a Vaid from this at all; Python and TypeScript would happily hand a partial map to a verifier if nothing gated it. All three must say the same thing: there is no document here to have an opinion about.",
        pre_sign: &[],
        signer: Signer::Kernel,
        post_sign: &[],
        tamper_signature: false,
        text: TextShape::TruncatedAfterTenant,
        revocation: "not_revoked",
        expected_reason: "unparseable",
        expected_valid: false,
    },
    StandingCase {
        name: "malformed: not JSON at all",
        why: "arbitrary bytes. A refusal, never a raised exception or a panic.",
        pre_sign: &[],
        signer: Signer::Kernel,
        post_sign: &[],
        tamper_signature: false,
        text: TextShape::Literal("this is not a VAID"),
        revocation: "not_revoked",
        expected_reason: "unparseable",
        expected_valid: false,
    },
    StandingCase {
        name: "malformed: empty input",
        why: "zero bytes. The degenerate case, which is exactly the one a hand-rolled parser forgets.",
        pre_sign: &[],
        signer: Signer::Kernel,
        post_sign: &[],
        tamper_signature: false,
        text: TextShape::Literal(""),
        revocation: "not_revoked",
        expected_reason: "unparseable",
        expected_valid: false,
    },
    StandingCase {
        name: "malformed: valid JSON, but an array",
        why: "well-formed JSON that is not a document. Parseable as JSON is not the same question as parseable as a VAID.",
        pre_sign: &[],
        signer: Signer::Kernel,
        post_sign: &[],
        tamper_signature: false,
        text: TextShape::Literal("[]"),
        revocation: "not_revoked",
        expected_reason: "unparseable",
        expected_valid: false,
    },
    StandingCase {
        name: "malformed: a required member is absent",
        why: "every member of the Rust struct except sig_version and parent_vaid is required. A map missing one is not a VAID, and the untyped implementations must refuse it for the same reason the typed one does rather than proceeding with a hole in the document.",
        pre_sign: &[],
        signer: Signer::Kernel,
        post_sign: &[("tenant_id", None)],
        tamper_signature: false,
        text: TextShape::Document,
        revocation: "not_revoked",
        expected_reason: "unparseable",
        expected_valid: false,
    },
    StandingCase {
        name: "malformed: a member of the wrong type",
        why: "scope_boundary as a bare string rather than a list. In Python and JavaScript a string is iterable, so an ungated implementation would silently treat this as a boundary of ten single-character entries.",
        pre_sign: &[],
        signer: Signer::Kernel,
        post_sign: &[("scope_boundary", Some("\"data.acme\""))],
        tamper_signature: false,
        text: TextShape::Document,
        revocation: "not_revoked",
        expected_reason: "unparseable",
        expected_valid: false,
    },
    StandingCase {
        name: "order: expired AND revoked",
        why: "both are true. Expiry is reported, because it is determinable from the document itself while revocation is an answer from elsewhere.",
        pre_sign: &[("expires_at", Some("\"2020-01-01T00:00:00Z\""))],
        signer: Signer::Kernel,
        post_sign: &[],
        tamper_signature: false,
        text: TextShape::Document,
        revocation: "revoked",
        expected_reason: "expired",
        expected_valid: false,
    },
    StandingCase {
        name: "order: expired AND revocation unavailable",
        why: "a definite answer must not be displaced by 'I could not tell'. Reporting indeterminate about a document we can positively see has expired discards information we already hold.",
        pre_sign: &[("expires_at", Some("\"2020-01-01T00:00:00Z\""))],
        signer: Signer::Kernel,
        post_sign: &[],
        tamper_signature: false,
        text: TextShape::Document,
        revocation: "unavailable",
        expected_reason: "expired",
        expected_valid: false,
    },
    StandingCase {
        name: "order: forged AND expired",
        why: "authenticity wins. Reporting 'expired' about a forgery invites a renewal, and renewing a forged document hands the forger a fresh valid one.",
        pre_sign: &[("expires_at", Some("\"2020-01-01T00:00:00Z\""))],
        signer: Signer::Kernel,
        post_sign: &[("capability_set", Some("[\"read\", \"write\"]"))],
        tamper_signature: false,
        text: TextShape::Document,
        revocation: "not_revoked",
        expected_reason: "inauthentic",
        expected_valid: false,
    },
    StandingCase {
        name: "order: unsupported sig_version AND malformed trust_domain",
        why: "two structural faults; sig_version is reported because it is checked first. Pinning this is what stops an implementation from reordering the cheap checks and changing every reason code while every boolean stays identical.",
        pre_sign: &[("sig_version", Some("2")), ("trust_domain", Some("\"not a domain\""))],
        signer: Signer::Kernel,
        post_sign: &[],
        tamper_signature: false,
        text: TextShape::Document,
        revocation: "not_revoked",
        expected_reason: "unsupported_sig_version",
        expected_valid: false,
    },
    StandingCase {
        name: "vaid_id rewritten to uppercase after signing",
        why: "the SAME uuid, spelled differently. A verifier that parses to a UUID and re-renders it canonicalizes the spelling away, reproduces the signed bytes and calls a document altered after signing authentic. Rust did exactly that; the presented form is now what is canonicalized, so the signature refuses it.",
        pre_sign: &[],
        signer: Signer::Kernel,
        post_sign: &[("vaid_id", Some("\"C0000000-0000-4000-8000-000000000001\""))],
        tamper_signature: false,
        text: TextShape::Document,
        revocation: "not_revoked",
        expected_reason: "inauthentic",
        expected_valid: false,
    },
    StandingCase {
        name: "vaid_id rewritten to braced form after signing",
        why: "the same uuid inside curly braces, which every uuid parser in this standard accepts. B7 listed this class among the eight the three implementations disagreed on, and the vector did not carry it — so the agreement held by construction rather than by contract. It fails for the same reason as the other spellings: the presented bytes are what the signature covers, and these are not the bytes that were signed.",
        pre_sign: &[],
        signer: Signer::Kernel,
        post_sign: &[("vaid_id", Some("\"{c0000000-0000-4000-8000-000000000001}\""))],
        tamper_signature: false,
        text: TextShape::Document,
        revocation: "not_revoked",
        expected_reason: "inauthentic",
        expected_valid: false,
    },
    StandingCase {
        name: "vaid_id rewritten to urn:uuid: form after signing",
        why: "the same defect through a different spelling the uuid parsers accept. Parsing stays permissive on purpose — a stricter grammar would make one implementation report unparseable where the others report inauthentic, which is the same refusal for a different reason.",
        pre_sign: &[],
        signer: Signer::Kernel,
        post_sign: &[("vaid_id", Some("\"urn:uuid:c0000000-0000-4000-8000-000000000001\""))],
        tamper_signature: false,
        text: TextShape::Document,
        revocation: "not_revoked",
        expected_reason: "inauthentic",
        expected_valid: false,
    },
    StandingCase {
        name: "vaid_id rewritten to hyphenless form after signing",
        why: "the same uuid with its hyphens stripped — the last of the five altered-after-signing spellings, and the one furthest from the canonical form while still parsing everywhere. Parsing stays permissive on purpose: a grammar that refused this here would report unparseable where the others report inauthentic, which is the same refusal for a different stated reason and is itself the divergence class this vector polices.",
        pre_sign: &[],
        signer: Signer::Kernel,
        post_sign: &[("vaid_id", Some("\"c0000000000040008000000000000001\""))],
        tamper_signature: false,
        text: TextShape::Document,
        revocation: "not_revoked",
        expected_reason: "inauthentic",
        expected_valid: false,
    },
    StandingCase {
        name: "parent_vaid deleted after signing",
        why: "ABSENT is not the same as PRESENT-NULL. A verifier holding a two-state optional cannot tell them apart and renders the missing member back as null, reproducing the signed bytes for a document whose key set was changed. E.7 requires a root to carry a present null; deleting it must therefore break the signature rather than be quietly repaired.",
        pre_sign: &[],
        signer: Signer::Kernel,
        post_sign: &[("parent_vaid", None)],
        tamper_signature: false,
        text: TextShape::Document,
        revocation: "not_revoked",
        expected_reason: "inauthentic",
        expected_valid: false,
    },
    StandingCase {
        name: "control: numeric-offset expiry, signed as presented",
        why: "+00:00 is valid RFC 3339 and NOT the E.6 profile. It must still verify: the signature covers the bytes as presented, and a verifier that re-renders the timestamp into the profile computes a different digest and rejects a document its signer genuinely signed. E.6 binds PRODUCERS; it is not a verifier's licence to rewrite what it was handed.",
        pre_sign: &[("expires_at", Some("\"2999-01-01T00:00:00+00:00\""))],
        signer: Signer::Kernel,
        post_sign: &[],
        tamper_signature: false,
        text: TextShape::Document,
        revocation: "not_revoked",
        expected_reason: "valid",
        expected_valid: true,
    },
    StandingCase {
        name: "control: sub-second expiry, signed as presented",
        why: "the same rule against the form that actually occurs: JavaScript's toISOString() emits .000Z by default, so this is what a caller who lets the platform format a timestamp produces. It must verify everywhere.",
        pre_sign: &[("expires_at", Some("\"2999-01-01T00:00:00.000Z\""))],
        signer: Signer::Kernel,
        post_sign: &[],
        tamper_signature: false,
        text: TextShape::Document,
        revocation: "not_revoked",
        expected_reason: "valid",
        expected_valid: true,
    },
    StandingCase {
        name: "unreadable expiry, signed as presented — fails CLOSED",
        why: "authentic, and its expiry cannot be read. A document whose expiry is unreadable is not a document that can be shown to be unexpired, so it is EXPIRED rather than unparseable: it still has an identity, and the failure is a verdict about its standing rather than about its syntax.",
        pre_sign: &[("expires_at", Some("\"not-a-timestamp\""))],
        signer: Signer::Kernel,
        post_sign: &[],
        tamper_signature: false,
        text: TextShape::Document,
        revocation: "not_revoked",
        expected_reason: "expired",
        expected_valid: false,
    },
    StandingCase {
        name: "duplicate member name",
        why: "THE PARSER DIFFERENTIAL. serde refuses a repeated struct field; json.loads and JSON.parse both keep the LAST and discard the earlier silently. A signed document is a statement about a specific byte string, so quietly choosing between two competing values means the reader and the signer may disagree about what was signed with nothing in the verdict to show it. Rejecting is the safe direction and is now normative (E.7a).",
        pre_sign: &[],
        signer: Signer::Kernel,
        post_sign: &[],
        tamper_signature: false,
        text: TextShape::DuplicateLeadingTenant,
        revocation: "not_revoked",
        expected_reason: "unparseable",
        expected_valid: false,
    },
    StandingCase {
        name: "duplicate member name, nested inside an extension",
        why: "the rule applies at every depth, not only to members the verifier recognises — a duplicate inside an additive extension is resolved by last-wins just as silently.",
        pre_sign: &[],
        signer: Signer::Kernel,
        // The extension members live in the TEXT mutation below, not here: a
        // nested duplicate cannot be expressed as a parsed member, and adding
        // them on both paths would emit each one twice.
        post_sign: &[],
        tamper_signature: false,
        text: TextShape::NestedDuplicateExtension,
        revocation: "not_revoked",
        expected_reason: "unparseable",
        expected_valid: false,
    },
    StandingCase {
        name: "the previous wire form: a v3 document with a bare-string scope_boundary",
        why: "NO LEGACY ACCEPTANCE, pinned. This is a real v3 credential, carried verbatim from the vector this one replaces, signature and all. A v4 verifier refuses it as UNPARSEABLE and not as an unsupported sig_version, because the boundary fails the shape gate of S.8 before the version is ever read. That ordering is worth freezing: it is the reason a holder presenting a stale credential sees 'not a document' rather than 'wrong version', and an implementation that checked the version first would report a different reason for the same bytes.",
        pre_sign: &[],
        signer: Signer::Kernel,
        post_sign: &[],
        tamper_signature: false,
        text: TextShape::Literal("{\n  \"sig_version\": 3,\n  \"vaid_id\": \"c0000000-0000-4000-8000-000000000001\",\n  \"agent_id\": \"c0000000-0000-4000-8000-000000000001\",\n  \"agent_class\": \"verdict\",\n  \"version\": \"1.0.0\",\n  \"tenant_id\": \"acme\",\n  \"issued_at\": \"2020-01-01T00:00:00Z\",\n  \"expires_at\": \"2999-01-01T00:00:00Z\",\n  \"public_key_der\": [\n    3,\n    161,\n    7,\n    191,\n    243,\n    206,\n    16,\n    190,\n    29,\n    112,\n    221,\n    24,\n    231,\n    75,\n    192,\n    153,\n    103,\n    228,\n    214,\n    48,\n    155,\n    165,\n    13,\n    95,\n    29,\n    220,\n    134,\n    100,\n    18,\n    85,\n    49,\n    184\n  ],\n  \"kernel_signature\": [\n    26,\n    148,\n    104,\n    49,\n    172,\n    135,\n    233,\n    237,\n    93,\n    130,\n    0,\n    250,\n    158,\n    68,\n    201,\n    40,\n    18,\n    41,\n    238,\n    242,\n    164,\n    63,\n    179,\n    92,\n    24,\n    142,\n    34,\n    208,\n    44,\n    189,\n    33,\n    231,\n    149,\n    227,\n    150,\n    192,\n    207,\n    104,\n    57,\n    162,\n    212,\n    126,\n    239,\n    197,\n    142,\n    197,\n    125,\n    10,\n    223,\n    13,\n    9,\n    66,\n    8,\n    95,\n    45,\n    152,\n    28,\n    98,\n    176,\n    169,\n    121,\n    92,\n    30,\n    6\n  ],\n  \"parent_vaid\": null,\n  \"scope_boundary\": [\n    \"data.acme\"\n  ],\n  \"lineage_hash\": \"8f89c127be8d6e98aa288873e5b6413b9b84e6b92b1a8b99a4627f91390f16af\",\n  \"capability_set\": [\n    \"read\"\n  ],\n  \"trust_domain\": \"vaid.example\",\n  \"kernel_key_thumbprint\": \"urn:ietf:params:oauth:jwk-thumbprint:sha-256:1IG2tMH7J2wbJZnOf8LJzQitKf7LMvoAElsuDMVM54Y\"\n}"),
        revocation: "not_revoked",
        expected_reason: "unparseable",
        expected_valid: false,
    },
    StandingCase {
        name: "unknown scope kind: authentic and unexpired, boundary kind not recognised",
        why: "THE FAIL-CLOSED CASE for S.10. Authentic, unexpired, revocation clean, and refused anyway because its scope_boundary names a kind this verifier cannot evaluate. Distinct from unparseable: the entry's shape is well formed and the document's signature verifies, so collapsing the two would report an authentic future-version credential as malformed bytes. Distinct from a scope escalation: the verifier has formed no opinion about width, it cannot read the boundary at all.",
        pre_sign: &[("scope_boundary", Some("[{\"kind\": \"amount\", \"value\": 100}]"))],
        signer: Signer::Kernel,
        post_sign: &[],
        tamper_signature: false,
        text: TextShape::Document,
        revocation: "not_revoked",
        expected_reason: "unknown_scope_kind",
        expected_valid: false,
    },
    StandingCase {
        name: "order: expired AND an unknown scope kind",
        why: "Pins where the new check sits. Both faults hold; the reason is expired, because expiry is the cheaper and more actionable fact and is evaluated first. An implementation that checked the boundary before expiry agrees on every boolean in this vector and disagrees here.",
        pre_sign: &[("scope_boundary", Some("[{\"kind\": \"amount\", \"value\": 100}]")), ("expires_at", Some("\"2020-01-01T00:00:00Z\""))],
        signer: Signer::Kernel,
        post_sign: &[],
        tamper_signature: false,
        text: TextShape::Document,
        revocation: "not_revoked",
        expected_reason: "expired",
        expected_valid: false,
    },
];

const ATTENUATION_CASES: &[AttenuationCase] = &[
    AttenuationCase {
        name: "control: child within parent",
        why: "THE CONTROL for this surface. Without it, an implementation that refuses every delegation passes every escalation case below.",
        parent_scope: "[{\"kind\": \"prefix\", \"value\": \"data.acme\"}]",
        child_scope: "[{\"kind\": \"prefix\", \"value\": \"data.acme.reports\"}]",
        expected_valid: true,
        expected_reason: "attenuated",
    },
    AttenuationCase {
        name: "escalation: child names a resource outside the parent",
        why: "the plain case: a parent restricted to data.acme cannot delegate data.other.",
        parent_scope: "[{\"kind\": \"prefix\", \"value\": \"data.acme\"}]",
        child_scope: "[{\"kind\": \"prefix\", \"value\": \"data.other\"}]",
        expected_valid: false,
        expected_reason: "scope_escalation",
    },
    AttenuationCase {
        name: "escalation: empty child scope under a restricted parent",
        why: "THE SUBTLE ONE. An empty scope means UNRESTRICTED, so a naive all() over zero entries is vacuously true and mints an unrestricted child under a restricted parent — strictly broader than its parent, by way of an empty list. The empty-child guard is the only thing standing between this vector and a privilege escalation that reads like a no-op.",
        parent_scope: "[{\"kind\": \"prefix\", \"value\": \"data.acme\"}]",
        child_scope: "[]",
        expected_valid: false,
        expected_reason: "scope_escalation",
    },
    AttenuationCase {
        name: "control: empty child under an unrestricted parent",
        why: "the guard must not overfire: a parent that is itself unrestricted may delegate unrestricted. Without this case the guard could be 'reject every empty child' and still pass.",
        parent_scope: "[]",
        child_scope: "[]",
        expected_valid: true,
        expected_reason: "attenuated",
    },
    AttenuationCase {
        name: "escalation: sibling capture by bare prefix",
        why: "data.acme-secret is not under data.acme. Bare prefix matching accepts it; segment-bounded containment (ADR-0005) does not. Carried here as well as in scope_v1.json because a regression in the matcher must fail the ATTENUATION surface too — the two vectors reach the rule by different call paths.",
        parent_scope: "[{\"kind\": \"prefix\", \"value\": \"data.acme\"}]",
        child_scope: "[{\"kind\": \"prefix\", \"value\": \"data.acme-secret\"}]",
        expected_valid: false,
        expected_reason: "scope_escalation",
    },
    AttenuationCase {
        name: "undecidable: an unknown kind in the CHILD",
        why: "A child claiming authority of a kind the verifier cannot read cannot be shown to be within its parent. The reason is unknown_scope_kind and NOT scope_escalation: the verifier is not saying the delegation is wider, it is saying it cannot tell. Carried here as well as in scope_kinds_v1.json because the two vectors reach the rule by different call paths.",
        parent_scope: "[{\"kind\": \"prefix\", \"value\": \"data.acme\"}]",
        child_scope: "[{\"kind\": \"amount\", \"value\": 100}]",
        expected_valid: false,
        expected_reason: "unknown_scope_kind",
    },
    AttenuationCase {
        name: "undecidable: an unknown kind in the PARENT",
        why: "The direction an implementation guarding only its input loses. A parent boundary the verifier cannot read bounds nothing it can compute, so no child is provably within it.",
        parent_scope: "[{\"kind\": \"amount\", \"value\": 100}]",
        child_scope: "[{\"kind\": \"prefix\", \"value\": \"data.acme\"}]",
        expected_valid: false,
        expected_reason: "unknown_scope_kind",
    },
];

/// A JSON object that serializes in INSERTION order rather than sorted order.
struct Ordered(Vec<(String, Value)>);

impl Serialize for Ordered {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (k, v) in &self.0 {
            map.serialize_entry(k, v)?;
        }
        map.end()
    }
}

impl Ordered {
    fn base() -> Self {
        Ordered(
            BASE_FIELDS
                .iter()
                .map(|(k, v)| {
                    (
                        k.to_string(),
                        serde_json::from_str(v).expect("base member is JSON"),
                    )
                })
                .collect(),
        )
    }

    fn apply(&mut self, overrides: &[(&str, Option<&str>)]) {
        for (key, value) in overrides {
            match value {
                Some(text) => {
                    let v: Value = serde_json::from_str(text).expect("override is JSON");
                    match self.0.iter_mut().find(|(k, _)| k == key) {
                        Some(slot) => slot.1 = v,
                        None => self.0.push((key.to_string(), v)),
                    }
                }
                None => self.0.retain(|(k, _)| k != key),
            }
        }
    }

    fn set(&mut self, key: &str, value: Value) {
        match self.0.iter_mut().find(|(k, _)| k == key) {
            Some(slot) => slot.1 = value,
            None => self.0.push((key.to_string(), value)),
        }
    }

    fn text(&self) -> String {
        serde_json::to_string_pretty(self).expect("document serializes")
    }
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Sign the canonical bytes of `doc`.
///
/// Routed through `Vaid` so what is signed is what the SHIPPED canonicalizer
/// produces over the presented members, unknown ones included (ADR-0006). A case
/// whose pre-sign overrides make the document unparseable has nothing to sign;
/// those cases carry no authentic signature by construction and the empty vector
/// below is what they get.
fn sign(key: &Ed25519KeyPair, doc: &Ordered) -> Vec<u8> {
    match serde_json::from_str::<Vaid>(&doc.text()) {
        Ok(parsed) => key
            .sign(&canonical_vaid_signing_bytes(&parsed))
            .as_ref()
            .to_vec(),
        Err(_) => Vec::new(),
    }
}

fn truncate_after_tenant(text: &str) -> String {
    let needle = "\"tenant_id\"";
    let start = text.find(needle).expect("the document carries tenant_id");
    let end = text[start..]
        .find('\n')
        .map(|i| start + i)
        .expect("tenant_id is not the last line");
    // Drop the trailing comma so the cut reads as an interrupted document rather
    // than a document missing one member.
    text[..end].trim_end_matches(',').to_string()
}

fn main() {
    let kernel = Ed25519KeyPair::from_seed_unchecked(&unhex(KERNEL_SEED_HEX))
        .expect("deterministic kernel key");
    let foreign = Ed25519KeyPair::from_seed_unchecked(&unhex(FOREIGN_SEED_HEX))
        .expect("deterministic foreign key");
    let kernel_pub = kernel.public_key().as_ref().to_vec();
    let foreign_pub = foreign.public_key().as_ref().to_vec();

    let mut cases: Vec<Value> = Vec::new();

    for case in STANDING_CASES {
        let document_json = match &case.text {
            TextShape::Literal(text) => (*text).to_string(),
            shape => {
                let mut doc = Ordered::base();
                doc.apply(case.pre_sign);
                let key = match case.signer {
                    Signer::Kernel => &kernel,
                    Signer::Foreign => &foreign,
                };
                let mut signature = sign(key, &doc);
                if case.tamper_signature {
                    // One byte, flipped. Expressed as a transform rather than as
                    // a frozen literal so it stays a corruption of THIS version's
                    // signature rather than of a previous version's.
                    if let Some(first) = signature.first_mut() {
                        *first ^= 0xFF;
                    }
                }
                doc.set("kernel_signature", json!(signature));
                doc.apply(case.post_sign);
                let text = doc.text();
                match shape {
                    TextShape::TruncatedAfterTenant => truncate_after_tenant(&text),
                    TextShape::DuplicateLeadingTenant => {
                        // `tenant_id` repeated as the FIRST member. Both occurrences
                        // are present in the bytes; every parser here resolves the
                        // collision before returning, which is why E.7a is checked
                        // on the raw text.
                        format!("{{\"tenant_id\": \"acme\", {}", &text[1..])
                    }
                    TextShape::NestedDuplicateExtension => {
                        let trimmed = text.trim_end();
                        let body = trimmed
                            .strip_suffix('}')
                            .expect("the document text ends in a brace");
                        format!(
                            "{},\n  \"x_ext\": {{\n    \"k\": 1\n  }},\n  \"x_ext2\": {{\"k\": 1, \"k\": 2}}\n}}",
                            body.trim_end()
                        )
                    }
                    _ => text,
                }
            }
        };
        cases.push(json!({
            "name": case.name,
            "why": case.why,
            "surface": "standing",
            "document_json": document_json,
            "revocation": case.revocation,
            "expected_valid": case.expected_valid,
            "expected_reason": case.expected_reason,
        }));
    }

    for case in ATTENUATION_CASES {
        cases.push(json!({
            "name": case.name,
            "why": case.why,
            "surface": "attenuation",
            "parent_scope": serde_json::from_str::<Value>(case.parent_scope).expect("JSON"),
            "child_scope": serde_json::from_str::<Value>(case.child_scope).expect("JSON"),
            "expected_valid": case.expected_valid,
            "expected_reason": case.expected_reason,
        }));
    }

    let vector = json!({
        "_comment": "Negative-path conformance vector (v1). Nine happy-path vectors prove the three implementations MINT identically; none of them proves they FAIL identically. A verifier that accepts an expired VAID in one language and rejects it in another is a worse defect than a mint mismatch, and nothing in the suite would have caught it. ADR-0006 found exactly this class by accident — Python and Rust disagreed on a real production document because one preserved an unknown member and the other dropped it, and no vector covered the path. This one covers the path. SHAPE: a predicate vector, following roundtrip_v1.json and scope_v1.json — it pins A VERDICT OVER GIVEN BYTES rather than bytes over a given input, which is the only shape that catches cross-implementation disagreement. It carries no digest of its own: the assertion is the verdict. mint_v1, mint_pop_v1, chain_v1, attestation_v1, scope_v1 and roundtrip_v1 are untouched and NOT re-frozen. EACH CASE ASSERTS A REASON, NOT MERELY A BOOLEAN. Three implementations that reject the same document for three different reasons agree on every boolean and disagree about what happened; that disagreement is the defect this vector exists to make visible, and it is invisible to a vector that only pins true/false. DOCUMENTS ARE CARRIED AS TEXT, not as objects, because half the point is input that is not a document at all — truncated, empty, or not JSON. A case whose bytes cannot be expressed as a JSON object cannot be written any other way, and starting every case from text means the malformed cases travel the same code path as the well-formed ones instead of a special one written just for them.",
        "rule": {
            "statement": "A conforming implementation MUST, for each standing case, evaluate the case's document_json text together with the given revocation status and return both expected_valid and expected_reason. For each attenuation case it MUST evaluate scope containment of child_scope within parent_scope and return both. The reason is normative, not advisory.",
            "order": "Standing is evaluated in exactly this order, and the FIRST fault found is the one reported: (1) parse; (2) sig_version; (3) trust_domain; (4) kernel_key_thumbprint correspondence; (5) lineage_hash; (6) kernel signature; (7) expiry; (8) revocation. Steps 2-6 are the pre-existing authenticity order, unchanged. Reordering any step changes which reason a document receives while leaving every boolean identical, which is precisely the divergence class this vector polices.",
            "unavailable_is_not_a_negative": "A revocation status of 'unavailable' yields 'indeterminate' — its own state, never collapsed into 'revoked' and never into 'valid'. It fails CLOSED: expected_valid is false. This is the same rule already carried by the three-state RevocationCheck, the four-valued chain verdict, and the packaged firewall's refusal to report PASS over zero vectors.",
            "authenticity_is_not_standing": "expected_valid is true only for a document that is authentic AND unexpired AND affirmatively not revoked. The pre-existing authenticity predicate answers a narrower question and is unchanged by this vector.",
            "expiry_is_pinned_by_distance_not_by_a_clock": "Expiring cases use a timestamp two decades past and unexpired cases one nine centuries hence, so no verdict here depends on when the suite runs. This is deliberate: the Rust and Python expiry predicates read the wall clock and accept no 'now' argument, so a vector pinned against a near boundary would be a vector with an expiry date of its own.",
            "presentation_is_preserved": "A verifier canonicalizes the member VALUES it was presented, not its own re-rendering of them (ADR-0006 Requirement 3). A UUID may be presented in any spelling the uuid parsers accept and a timestamp in any valid RFC 3339 form; both are canonicalized exactly as written, so rewriting one after signing breaks the signature instead of being silently repaired. An ABSENT member and a member present as JSON null are different documents. Parsing is permissive and verification is strict, on purpose: it puts the refusal on the signature, which is the same in all implementations, rather than on separately-written grammars.",
            "e6_binds_producers_not_verifiers": "The whole-second Z profile (E.6) is normative on PRODUCERS. A verifier MUST NOT rewrite a non-conforming timestamp into the profile: doing so computes a different digest and rejects a document its signer genuinely signed. Conformance is asked separately, and a document that fails the profile still verifies if its signature covers what it carries.",
            "duplicate_member_names_are_not_a_document": "A repeated member name at any depth is UNPARSEABLE (E.7a). The parsers disagree by default — one refuses, two silently keep the last — so the rule is stated rather than inherited. Last-wins would let a reader and a signer disagree about what was signed with nothing in the verdict to indicate it.",
            "an_unreadable_expiry_is_expired": "A timestamp that cannot be parsed makes the document EXPIRED, not unparseable: it still has an identity, and 'cannot be shown to be unexpired' is a statement about standing. Fails closed in all three.",
            "controls_are_load_bearing": "This file contains positive controls on BOTH surfaces. An implementation that refuses every input satisfies every negative case here; only a case that must succeed catches it. A checker that drops the controls has disarmed the vector without changing a single negative."
        },
        "reasons": {
            "standing": ["valid", "unparseable", "unsupported_sig_version", "malformed_trust_domain", "issuer_mismatch", "lineage_inconsistent", "inauthentic", "expired", "revoked", "indeterminate", "unknown_scope_kind"],
            "attenuation": ["attenuated", "scope_escalation", "unknown_scope_kind"],
        },
        "revocation_states": ["not_revoked", "revoked", "unavailable"],
        "ed25519": {
            "kernel_private_key_seed_hex": KERNEL_SEED_HEX,
            "kernel_public_key_hex": to_hex(&kernel_pub),
            "kernel_key_thumbprint": kernel_key_thumbprint(&kernel_pub),
            "_foreign_comment": "A second, unrelated key standing in for 'somebody else's signer'. Without it, 'signed by a non-kernel key' cannot be expressed, and the two ways that forgery presents — a broken signature versus a stranger's perfectly valid one — cannot be told apart.",
            "foreign_private_key_seed_hex": FOREIGN_SEED_HEX,
            "foreign_public_key_hex": to_hex(&foreign_pub),
            "foreign_key_thumbprint": kernel_key_thumbprint(&foreign_pub),
        },
        "cases": cases,
    });

    println!("{}", serde_json::to_string_pretty(&vector).unwrap());
}
