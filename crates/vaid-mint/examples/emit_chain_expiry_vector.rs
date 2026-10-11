//! Generator for the frozen chain-expiry vector (`chain_expiry_v1.json`).
//!
//! Run with `cargo run -p vaid-mint --example emit_chain_expiry_vector` to print
//! the vector JSON. Every document in every case is signed by ONE deterministic
//! kernel key: this vector's subject is expiry and attenuation, so a second key
//! would only add a variable the cases do not vary.
//!
//! Written for the v4 re-freeze (ADR-0009). Until then this vector had no
//! generator, and 18 signed documents could only be re-frozen by hand, which is
//! how a signature gets edited into agreement with bytes nobody recomputed.
//!
//! # Shape
//!
//! Six cases, each a three-hop chain root -> intermediate -> leaf. The hops are
//! IDENTICAL across cases except for `expires_at` and the identities, so the only
//! thing a case can be testing is the expiry arrangement named in its `why`.
//! Identities are `e0000000-...-0000000000GH` for group `G` and hop `H`, which is
//! what keeps 18 documents readable in a diff.
//!
//! The kernel seed is the same RFC 8032 test seed `mint_v1.json` and
//! `chain_v1.json` use.

use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::json;
use uuid::Uuid;

use vaid_mint::issuer_identity::kernel_key_thumbprint;
use vaid_mint::{
    canonical_vaid_signing_bytes, compute_lineage_hash, AgentClass, AgentId, ScopeBoundaryEntry,
    TenantId, Vaid, VaidId, VAID_SIG_VERSION_V4,
};

const KERNEL_SEED_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

/// Every case is asserted AT this instant and not at the runner's clock. The
/// far-future and long-past expiries are what make the verdicts stable; the
/// instant is what makes them reproducible.
const VERIFICATION_INSTANT: &str = "2026-06-04T18:00:00Z";

const ISSUED_AT: &str = "2026-06-04T12:00:00Z";
const TENANT: &str = "aifactory";
const TRUST_DOMAIN: &str = "vaid.example";
const VERSION: &str = "1.0.0";

/// Per-hop attributes, fixed across all six cases: role, agent class, scope,
/// capabilities. Varying them would make a failing case ambiguous between an
/// expiry rule and an attenuation rule.
const HOPS: [(&str, &str, &str, &[&str]); 3] = [
    ("root", "orchestrator", "data.aifactory", &["read", "write"]),
    ("intermediate", "planner", "data.aifactory.sub", &["read"]),
    ("leaf", "worker", "data.aifactory.sub.task", &["read"]),
];

struct ExpiryCase {
    group: u8,
    name: &'static str,
    why: &'static str,
    /// Root, intermediate, leaf.
    expires_at: [&'static str; 3],
    expected_verification: &'static str,
}

const CASES: &[ExpiryCase] = &[
    ExpiryCase {
        group: 1,
        name: "control: a chain live at the instant, every expiry contained",
        why: "THE POSITIVE CONTROL. Every negative below is only meaningful because this one must return `attenuated`: an implementation that refused every chain would satisfy all of them and none of this. Expiries narrow strictly down the chain, as scope and capabilities already do.",
        expires_at: ["2999-01-01T00:00:00Z", "2998-01-01T00:00:00Z", "2997-01-01T00:00:00Z"],
        expected_verification: "attenuated",
    },
    ExpiryCase {
        group: 2,
        name: "boundary control: a child expiring at EXACTLY its parent's expires_at",
        why: "Containment is `child <= parent`, not `child < parent`. A child that ends at the same instant as its parent holds authority for no instant in which its parent holds none, so it is contained. The three implementations must agree on the boundary and not merely on the interior; vaid#79 asked for this case by name.",
        expires_at: ["2999-01-01T00:00:00Z", "2999-01-01T00:00:00Z", "2999-01-01T00:00:00Z"],
        expected_verification: "attenuated",
    },
    ExpiryCase {
        group: 3,
        name: "an expired ROOT makes the chain expired",
        why: "The defect vaid#79 was filed for. Every document is authentic, the chain assembles, and authority is contained at every hop - and the authority at the top of it ran out before the verification instant. The three expiries are EQUAL here so containment holds and the lapse is the only fault, which is what makes the verdict unambiguous.",
        expires_at: ["2006-01-02T00:00:00Z", "2006-01-02T00:00:00Z", "2006-01-02T00:00:00Z"],
        expected_verification: "expired",
    },
    ExpiryCase {
        group: 4,
        name: "an expired INTERMEDIATE makes the chain expired",
        why: "A lapse anywhere above the leaf, not only at the root. The root is live nine centuries out and the leaf is contained by its parent, so the only fault is the middle hop - the one a presenter is most likely to hope nobody walks.",
        expires_at: ["2999-01-01T00:00:00Z", "2006-01-02T00:00:00Z", "2006-01-02T00:00:00Z"],
        expected_verification: "expired",
    },
    ExpiryCase {
        group: 5,
        name: "a child outliving its parent is not attenuated, at any instant",
        why: "Nothing here has lapsed: every document is live at the instant and stays live for centuries. The fault is structural - the leaf ends AFTER the intermediate it derives from, so it was never built consistently. This is the half of vaid#79 that a mint-time-only fix would leave in documents already issued, and it is why the rule is enforced at both ends.",
        expires_at: ["2999-01-01T00:00:00Z", "2997-01-01T00:00:00Z", "2998-01-01T00:00:00Z"],
        expected_verification: "not_attenuated",
    },
    ExpiryCase {
        group: 6,
        name: "boundary, NOT an endorsement: an expired LEAF with live ancestors still verifies",
        why: "The leaf's own standing - its expiry and its revocation - is NOT consulted by chain verification. That is vaid#76, open, and wider than this vector. It is pinned here only so the three implementations draw the boundary in the same place rather than each choosing; it records where the line currently is, and a reader must not take it as a statement that this is where the line belongs. When #76 lands, this case changes and this vector is re-frozen.",
        expires_at: ["2999-01-01T00:00:00Z", "2999-01-01T00:00:00Z", "2006-01-02T00:00:00Z"],
        expected_verification: "attenuated",
    },
];

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// `e0000000-0000-0000-0000-0000000000GH`.
fn id_for(group: u8, hop: u8) -> Uuid {
    Uuid::parse_str(&format!("e0000000-0000-0000-0000-0000000000{group}{hop}"))
        .expect("the identity template is a UUID")
}

fn rfc3339(s: &str) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(s)
        .expect("vector timestamps are RFC 3339")
        .with_timezone(&chrono::Utc)
}

fn main() {
    let seed = unhex(KERNEL_SEED_HEX);
    let kernel_kp = Ed25519KeyPair::from_seed_unchecked(&seed).expect("deterministic kernel key");
    let kernel_pub = kernel_kp.public_key().as_ref().to_vec();
    let thumbprint = kernel_key_thumbprint(&kernel_pub);
    let public_key_der: Vec<u8> = (0u8..32).collect();

    let mut cases = Vec::new();
    for case in CASES {
        let mut chain = Vec::new();
        for (hop_index, (role, agent_class, scope, caps)) in HOPS.iter().enumerate() {
            let hop = hop_index as u8 + 1;
            let uuid = id_for(case.group, hop);
            let parent_uuid = if hop_index == 0 {
                None
            } else {
                Some(id_for(case.group, hop - 1))
            };
            let parent_vaid = parent_uuid.map(VaidId::from_uuid);
            let agent_id = AgentId::from_uuid(uuid);
            let lineage_hash = compute_lineage_hash(parent_vaid, &agent_id);
            let scope_boundary = vec![ScopeBoundaryEntry::prefix(*scope)];
            let capability_set: Vec<String> = caps.iter().map(|c| c.to_string()).collect();
            let expires_at = case.expires_at[hop_index];

            // `with_lineage` sets `vaid_id` from `agent_id`, which is why the two
            // are equal in every document here.
            let unsigned = Vaid::with_lineage(
                agent_id,
                AgentClass::new(*agent_class),
                VERSION.to_string(),
                TenantId::new(TENANT),
                rfc3339(ISSUED_AT),
                rfc3339(expires_at),
                public_key_der.clone(),
                Vec::new(), // unsigned
                parent_vaid,
                scope_boundary.clone(),
                lineage_hash.clone(),
                capability_set.clone(),
                TRUST_DOMAIN.to_string(),
                thumbprint.clone(),
            );
            let digest = canonical_vaid_signing_bytes(&unsigned);
            let signature = kernel_kp.sign(&digest);

            chain.push(json!({
                "_role": role,
                "digest_sha256_hex": to_hex(&digest),
                "signature_hex": to_hex(signature.as_ref()),
                "document": {
                    "sig_version": VAID_SIG_VERSION_V4,
                    "vaid_id": uuid.to_string(),
                    "agent_id": uuid.to_string(),
                    "agent_class": agent_class,
                    "version": VERSION,
                    "tenant_id": TENANT,
                    "issued_at": ISSUED_AT,
                    "expires_at": expires_at,
                    "public_key_der": public_key_der,
                    "kernel_signature": signature.as_ref().to_vec(),
                    "parent_vaid": parent_uuid.map(|u| u.to_string()),
                    "scope_boundary": scope_boundary,
                    "lineage_hash": lineage_hash,
                    "capability_set": capability_set,
                    "trust_domain": TRUST_DOMAIN,
                    "kernel_key_thumbprint": thumbprint,
                }
            }));
        }
        cases.push(json!({
            "name": case.name,
            "why": case.why,
            "verification_instant": VERIFICATION_INSTANT,
            "chain": chain,
            "expected_verification": case.expected_verification,
        }));
    }

    let vector = json!({
        "_comment": "Expiry-containment conformance vector (v1). Session 240, closing vaid#79: `mint_child` never compared a child's expiry to its parent's, so a child could outlive the authority it derived from, and `verify_chain` returned `attenuated` over a chain whose root had already expired. SHAPE: a PREDICATE vector, following scope_v1.json, roundtrip_v1.json and verdict_v1.json - it pins VERDICTS over given bytes rather than bytes over a given input, which is the only shape that catches cross-implementation disagreement. It carries no digest of its own; the assertion is the verdict, and the freeze check pins it on the SHA-256 of its own file bytes. ADDITIVE to every byte-pinning vector: mint_v1, mint_pop_v1, attestation_v1 and roundtrip_v1 are untouched and NOT re-frozen, no new signed field is introduced, and `sig_version` is unchanged. chain_v1 IS touched by the same change, but only to state the instant its verdict is asserted at - no document in it moved and no per-hop digest or signature moved. TWO SURFACES, because the invariant is enforced at two places from ONE matcher and a vector covering only one of them would let the two drift: `expiry_containment` is the matcher itself, as the mint applies it to a delegation it has not yet issued; `chain` is the same matcher plus the lapse check, as a third-party verifier applies them to documents it was handed. EVERY CHAIN CASE STATES ITS OWN `verification_instant` and MUST be evaluated at it - a case pinned against the suite's clock asserts whatever the calendar happens to say on the day it runs, which is exactly how chain_v1 came to pin `attenuated` over three documents that had been dead since June. `trust_domain` is `vaid.example`, RESERVED BY DESIGN: this vector publishes its own kernel private seed - the same seed as mint_v1 and chain_v1 - so anyone can sign documents under it, and a real trust domain here would be a published forgery generator for that deployment. RFC 2606 reserves `.example`. Any drift is a break. SELF-CONSISTENT within this repo only (Decision B) - NOT conformant against the closed VAID format.",
        "rule": {"an_unreadable_expiry_contains_nothing": "An absent or unparseable `expires_at` on EITHER side is `refused`, never `permitted`. This is the same fail-closed posture verdict_v1 states for standing, where an unreadable expiry makes a document expired rather than unparseable.", "containment_is_not_equality_of_ttl": "The rule bounds the child's EXPIRY by the parent's, not the child's TTL by the parent's. Two documents minted minutes apart under one 24-hour policy have identical TTLs and the later one still outlives the earlier. Comparing TTLs would report containment for exactly the continuous case vaid#79 describes.", "controls_are_load_bearing": "Both surfaces carry positive controls. An implementation that refuses everything satisfies every negative case here and no positive one. A checker that drops the controls has disarmed the vector without changing a single negative.", "distance_not_a_clock": "Live documents expire nine centuries hence and lapsed ones two decades past, so no verdict here changes with the calendar. The stated `verification_instant` makes each case reproducible; the distance makes it robust even to an implementation that ignores the instant on the standing predicate (BACKLOG B9).", "equality_is_contained": "`child <= parent`. A child ending at the same instant as its parent holds authority for no instant in which its parent holds none.", "lapse_is_checked_over_ANCESTORS_only": "`expired` is returned when a document ABOVE the leaf has passed its own `expires_at` at the verification instant. The leaf's own standing - expiry and revocation - is not consulted; that is vaid#76, open. The boundary is pinned by a case so that all three implementations draw it in the same place, NOT because it is where the line belongs.", "order_of_faults_is_normative": "Where a chain breaks more than one rule, the FIRST fault found is the one reported, and the order is: authenticity, then assembly, then ANCESTOR LAPSE, then hop containment (tenant, scope, capabilities, expiry), then cross-key consent. Three verifiers that reject the same chain for three different reasons agree on every boolean and disagree about what happened - the divergence class verdict_v1 exists to police, applied here.", "statement": "A conforming implementation MUST, for each `expiry_containment` case, evaluate whether a child whose `expires_at` is `child_expires_at` is contained by a parent whose `expires_at` is `parent_expires_at`, and return `expected`. It MUST, for each `chain` case, verify the leaf (the last entry) against the other entries presented as a detached bundle, AT the case's `verification_instant`, and return `expected_verification`."},
        "mint_rule": {"an_expired_parent_is_the_one_case_a_clamp_cannot_answer": "The ceiling would be in the past, so the child would be issued already expired. That is refused rather than issued, BEFORE the proof-of-possession, so the refusal burns no nonce and a caller that renews the parent and retries is not denied for the wrong reason. An unreadable parent expiry is expired, and is refused by the same rule.", "clamp_not_refuse_and_why": "Decided in Session 240, after measuring the alternative. Refusing an over-long child instead of clamping it makes delegation impossible for any issuer with a fixed TTL: `expires = now + ttl` is re-evaluated at every mint, so a child minted one second after its parent outlives it by one second and is refused. Measured against the reference mint with one 24-hour issuer: delegation succeeded at a 0.0s delay and was refused at 1.1s. A rule whose correct implementation cannot delegate is not a rule anyone will keep.", "roots_are_not_clamped": "A root has no parent to be contained by, so its TTL is the issuer's alone. A clamp applied indiscriminately would silently shorten every root mint.", "statement": "At mint, `mint_child` MUST bound the child's `expires_at` by the authenticated parent's: the child is issued with the EARLIER of the issuer's own TTL and the parent's expiry. A delegation from a parent that has ALREADY expired MUST be refused with the same unauthorized-delegation error the other containment refusals raise, and the refusal MUST name the parent's expiry.", "the_ceiling_is_an_instruction_the_mint_still_checks": "The issuer is a seam a deployment supplies. An issuer that ignores the ceiling - one written before this rule, or one that gets it wrong - would emit a child outliving its parent that nothing downstream could distinguish from a legitimate one. So the mint applies the SAME matcher to the document actually issued and withholds it if it fails. A cap the issuer may ignore is not a guarantee."},
        "verdicts": {"chain": ["attenuated", "inauthentic", "unverifiable", "not_attenuated", "expired", "consent_expired"], "expiry_containment": ["permitted", "refused"]},
        "ed25519": {
            "_comment": "Deterministic kernel key - the SAME RFC 8032 seed as mint_v1.json and chain_v1.json. Every document in every case is signed by this ONE key: these chains are single-trust-domain, so no consent attestation is required or consulted and expiry is the only variable.",
            "kernel_private_key_seed_hex": KERNEL_SEED_HEX,
            "kernel_public_key_hex": to_hex(&kernel_pub),
            "kernel_key_thumbprint": thumbprint,
        },
        "expiry_containment": [{"child_expires_at": "2026-06-05T11:00:00Z", "expected": "permitted", "name": "control: a child ending before its parent is contained", "parent_expires_at": "2026-06-05T12:00:00Z", "why": "THE POSITIVE CONTROL on this surface. Without it, an implementation whose predicate returns false unconditionally passes every negative below."}, {"child_expires_at": "2026-06-05T12:00:00Z", "expected": "permitted", "name": "equality is contained", "parent_expires_at": "2026-06-05T12:00:00Z", "why": "`child <= parent`. The mint MUST NOT refuse a delegation that ends exactly when its parent does."}, {"child_expires_at": "2026-06-05T12:00:01Z", "expected": "refused", "name": "one second later is refused", "parent_expires_at": "2026-06-05T12:00:00Z", "why": "The smallest representable overrun under the E.6 whole-second profile. A rule that only fires on a gross overrun would pass a suite of hours-long cases and still let the continuous form of the defect through - a child minted seconds after its parent under one TTL outlives it by exactly the delegation delay."}, {"child_expires_at": "2026-06-05T12:00:00Z", "expected": "permitted", "name": "the comparison is by INSTANT, not by string", "parent_expires_at": "2026-06-05T13:00:00+01:00", "why": "The same instant, written two ways. An implementation comparing the timestamps as text reads '2026-06-05T12:00:00Z' > '2026-06-05T13:00:00+01:00' as false only by luck of the alphabet, and the next offset form breaks it. ADR-0006: a verifier canonicalizes the values it was PRESENTED, and a presented timestamp may be in any valid RFC 3339 form, so the comparison must parse."}, {"child_expires_at": "2026-06-05T13:00:01+01:00", "expected": "refused", "name": "an offset form that really is later is refused", "parent_expires_at": "2026-06-05T12:00:00Z", "why": "The negative twin of the case above. Without it, an implementation could pass the previous case by parsing nothing and returning `permitted` whenever the forms differ."}, {"child_expires_at": "2026-06-05T11:00:00Z", "expected": "refused", "name": "an unreadable parent expiry is refused", "parent_expires_at": "not a timestamp", "why": "FAIL CLOSED, and the same rule verdict_v1 states for standing: an expiry that cannot be read is not an expiry that can be shown to contain anything. A rule that cannot be evaluated must never report that it passed."}, {"child_expires_at": "2026-06-05T11:00:00Z", "expected": "refused", "name": "an absent parent expiry is refused", "parent_expires_at": null, "why": "Absence and unreadability fail the same way. A missing member is not a permissive one."}, {"child_expires_at": null, "expected": "refused", "name": "an absent child expiry is refused", "parent_expires_at": "2026-06-05T12:00:00Z", "why": "The fail-closed rule is symmetric. A child whose own expiry cannot be read cannot be shown to end before its parent."}, {"child_expires_at": "2026-06-05T11:00:00Z", "expected": "refused", "name": "a naive timestamp is not RFC 3339 and is refused", "parent_expires_at": "2026-06-05T12:00:00", "why": "RFC 3339 requires an offset. Guessing UTC would invent a value the signer never wrote - the same rule the standing parser already applies."}],
        "cases": cases,
    });

    println!("{}", serde_json::to_string_pretty(&vector).unwrap());
}
