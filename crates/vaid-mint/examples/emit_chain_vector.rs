//! Generator for the frozen cross-language **chain-presentation** vector
//! (`chain_v1.json`), per ADR-0003 §3.
//!
//! Run with `cargo run -p vaid-mint --example emit_chain_vector` to print the
//! vector JSON.
//!
//! ADR-0003 §3: a conformance artifact for chain presentation is a **new** vector.
//! New vectors are additive; they do not invalidate existing ones. Nothing here
//! touches `mint_v1.json` or `mint_pop_v1.json`, and this vector introduces no new
//! signed field and no new encoding rule inside signed bytes — every document in
//! it is an ordinary v3 VAID over the existing canonicalization.
//!
//! What the vector pins is the part that was previously unpinned: given the same
//! three documents, every conforming implementation must assemble the same ordered
//! lineage and reach the same verification verdict. Three hops is the smallest
//! chain that exercises a *transitive* subset relation — with two, a leaf-only
//! check is indistinguishable from a full walk.
//!
//! The kernel seed is the same RFC 8032 test seed `mint_v1.json` uses, so the
//! kernel public key and its thumbprint are already known quantities.

use ring::signature::{Ed25519KeyPair, KeyPair};
use uuid::Uuid;

use vaid_mint::issuer_identity::kernel_key_thumbprint;
use vaid_mint::{
    canonical_vaid_signing_bytes, compute_lineage_hash, AgentClass, AgentId, TenantId, Vaid,
    VaidId, VAID_SIG_VERSION_V3,
};

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// One fully-specified hop of the frozen chain.
struct Hop {
    role: &'static str,
    agent_uuid: &'static str,
    agent_class: &'static str,
    parent_uuid: Option<&'static str>,
    scope_boundary: Vec<String>,
    capability_set: Vec<String>,
}

fn main() {
    // ── Fixed inputs (deterministic) ──
    const KERNEL_SEED_HEX: &str =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const ROOT_UUID: &str = "c0000000-0000-0000-0000-000000000001";
    const MID_UUID: &str = "c0000000-0000-0000-0000-000000000002";
    const LEAF_UUID: &str = "c0000000-0000-0000-0000-000000000003";

    let version = "1.0.0";
    // ONE tenant across every hop. Cross-tenant delegation is denied at mint, so a
    // conforming chain cannot change tenant mid-walk; pinning that here keeps the
    // vector valid under a verifier that also checks tenant containment.
    let tenant_id = "aifactory";
    let issued_at = "2026-06-04T12:00:00Z";
    let expires_at = "2026-06-05T12:00:00Z";
    // A fixed 32-byte "registered key" — bytes 0x00..0x1f, as in `mint_v1.json`.
    let public_key_der: Vec<u8> = (0u8..32).collect();
    // RESERVED BY DESIGN, for the same reason as `mint_v1.json`: this vector
    // publishes its own kernel private seed, so anyone can sign documents under
    // it. RFC 2606 reserves `.example`, so the issuer is unbindable by rule.
    let trust_domain = "vaid.example";

    // Authority narrows strictly at every hop, in BOTH dimensions: scope by prefix
    // extension, capabilities by removal. A chain that narrowed only one dimension
    // would leave the other's verify-time check unexercised by the vector.
    let hops = vec![
        Hop {
            role: "root",
            agent_uuid: ROOT_UUID,
            agent_class: "orchestrator",
            parent_uuid: None,
            scope_boundary: vec!["data.aifactory".to_string()],
            capability_set: vec!["read".to_string(), "write".to_string()],
        },
        Hop {
            role: "intermediate",
            agent_uuid: MID_UUID,
            agent_class: "planner",
            parent_uuid: Some(ROOT_UUID),
            scope_boundary: vec!["data.aifactory.sub".to_string()],
            capability_set: vec!["read".to_string()],
        },
        Hop {
            role: "leaf",
            agent_uuid: LEAF_UUID,
            agent_class: "worker",
            parent_uuid: Some(MID_UUID),
            scope_boundary: vec!["data.aifactory.sub.task".to_string()],
            capability_set: vec!["read".to_string()],
        },
    ];

    // The deterministic kernel key is derived BEFORE any document is built,
    // because v3 stamps its thumbprint INTO the document.
    let kernel_kp = Ed25519KeyPair::from_seed_unchecked(&unhex(KERNEL_SEED_HEX)).unwrap();
    let kernel_pub = kernel_kp.public_key().as_ref().to_vec();
    let kernel_thumbprint = kernel_key_thumbprint(&kernel_pub);

    let mut chain_json = Vec::new();

    for hop in &hops {
        let agent_uuid = Uuid::parse_str(hop.agent_uuid).unwrap();
        let agent_id = AgentId::from_uuid(agent_uuid);
        let parent_vaid: Option<VaidId> = hop
            .parent_uuid
            .map(|p| VaidId::from_uuid(Uuid::parse_str(p).unwrap()));

        let lineage_hash = compute_lineage_hash(parent_vaid, &agent_id);

        let unsigned = Vaid::with_lineage(
            agent_id,
            AgentClass::new(hop.agent_class),
            version.to_string(),
            TenantId::new(tenant_id),
            chrono::DateTime::parse_from_rfc3339(issued_at)
                .unwrap()
                .with_timezone(&chrono::Utc),
            chrono::DateTime::parse_from_rfc3339(expires_at)
                .unwrap()
                .with_timezone(&chrono::Utc),
            public_key_der.clone(),
            Vec::new(), // empty kernel_signature (unsigned)
            parent_vaid,
            hop.scope_boundary.clone(),
            lineage_hash.clone(),
            hop.capability_set.clone(),
            trust_domain.to_string(),
            kernel_thumbprint.clone(),
        );

        let digest = canonical_vaid_signing_bytes(&unsigned);
        let signature = kernel_kp.sign(&digest);

        chain_json.push(serde_json::json!({
            "_role": hop.role,
            "digest_sha256_hex": to_hex(&digest),
            "signature_hex": to_hex(signature.as_ref()),
            "document": {
                "sig_version": VAID_SIG_VERSION_V3,
                "vaid_id": hop.agent_uuid,
                "agent_id": hop.agent_uuid,
                "agent_class": hop.agent_class,
                "version": version,
                "tenant_id": tenant_id,
                "issued_at": issued_at,
                "expires_at": expires_at,
                "public_key_der": public_key_der,
                "kernel_signature": [],
                "parent_vaid": hop.parent_uuid,
                "scope_boundary": hop.scope_boundary,
                "lineage_hash": lineage_hash,
                "capability_set": hop.capability_set,
                "trust_domain": trust_domain,
                "kernel_key_thumbprint": kernel_thumbprint,
            }
        }));
    }

    let vector = serde_json::json!({
        "_comment": "Chain-presentation conformance vector (v1), per ADR-0003 §3. ADDITIVE: it \
                     introduces no new signed field and no new encoding rule inside signed bytes. \
                     `mint_v1.json` and `mint_pop_v1.json` are untouched and are NOT re-frozen by \
                     this vector's existence. Each entry of `chain` is an ordinary v3 VAID document, \
                     UNSIGNED (`kernel_signature` empty); a conforming implementation MUST reproduce \
                     each `digest_sha256_hex` by nulling `kernel_signature`, canonicalizing per JCS \
                     (RFC 8785) and SHA-256, and MUST reproduce each `signature_hex` from the kernel \
                     seed. What this vector pins BEYOND mint_v1 is the walk: presented with these \
                     three documents (the leaf plus the two ancestors as a detached bundle), a \
                     conforming verifier MUST assemble exactly `expected.assembled_lineage` — \
                     ORDERED ROOT FIRST, LEAF LAST — and MUST reach `expected.verification`. \
                     Authority narrows strictly at every hop in BOTH dimensions (scope by prefix \
                     extension, capabilities by removal), and `tenant_id` and `trust_domain` are \
                     constant across the chain, because cross-tenant delegation is denied at mint. \
                     Revocation and expiry are NOT consulted by chain verification and are not \
                     represented here. `trust_domain` is `vaid.example`, RESERVED BY DESIGN: this \
                     vector publishes its own kernel private seed, so anyone can sign documents \
                     under it — a real trust domain here would be a published forgery generator for \
                     that deployment. RFC 2606 reserves `.example`. Any drift is a break. \
                     SELF-CONSISTENT within this repo only (Decision B) — NOT conformant against \
                     the closed VAID format.",
        "ed25519": {
            "_comment": "Deterministic kernel key (same RFC 8032 seed as mint_v1.json and \
                         operator_pop_v1.json). EVERY hop is signed by this ONE key: the chain is \
                         single-trust-domain, which is what the shipped verifier supports.",
            "kernel_private_key_seed_hex": KERNEL_SEED_HEX,
            "kernel_public_key_hex": to_hex(&kernel_pub),
            "kernel_key_thumbprint": kernel_thumbprint,
        },
        "chain": chain_json,
        "expected": {
            "_comment": "`assembled_lineage` is the output of assembling the leaf's ancestry \
                         against a bundle holding the other two documents: root first, leaf last. \
                         `verification` is the verdict of full chain verification — authenticate \
                         every document, pin each hop against the signed `parent_vaid`, then check \
                         containment at every hop.",
            "assembled_lineage": [ROOT_UUID, MID_UUID, LEAF_UUID],
            "verification": "attenuated",
        },
    });

    println!("{}", serde_json::to_string_pretty(&vector).unwrap());
}
