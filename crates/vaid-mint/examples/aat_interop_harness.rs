//! s442: property-level interop harness against the AAT -02 JWS test suite
//! (`draft-niyikiza-oauth-attenuating-agent-tokens`, tenuo-ai/tenuo
//! `tests/vectors/aat-jws-vectors.json`).
//!
//! WHAT THIS DOES NOT DO: it does not parse a JWS compact string, does not
//! implement AAT's Section 8 algorithm, and does not reimplement any AAT
//! check-predicate semantics. For every AAT vector this program can faithfully
//! express, it builds a NATIVE VAID delegation chain (real `Vaid` documents,
//! really Ed25519-signed by a kernel keypair this program generates) whose
//! structure mirrors the AAT scenario, then calls VAID's real, unmodified
//! public verifier (`vaid_mint::verify_chain_at`, `Vaid::has_capability`,
//! `Vaid::is_expired_at`, `vaid_mint::verify::verify_vaid_standing_from_json`)
//! and records whatever verdict comes back. Nothing here copies an
//! `expected.verdict` out of the vectors file into a result.
//!
//! WHY most vectors are SKIP, not a guess: AAT's wire format is a JWS chain
//! where each hop is signed by the PREVIOUS hop's holder key (`cnf.jwk`),
//! carries a rich per-argument constraint algebra (`all`/`any`/`one_of`/
//! `not_one_of`/`exact`, closed-world argument checking), JOSE headers, and
//! JSON-level number-admissibility/canonicalization rules. VAID's delegation
//! model is a single kernel authority that signs every hop of a chain and
//! narrows a flat `capability_set` / prefix `scope_boundary`; it has no
//! per-hop distinct-signer check, no per-argument constraint map, no JOSE
//! header, and no byte-level JSON-number-admissibility rule. Translating
//! those scenarios would mean inventing a VAID check that does not exist, so
//! this program emits `SKIP` with a specific reason instead.
//!
//! Usage: `cargo run -p vaid-mint --example aat_interop_harness -- <vectors.json> <results.json>`

use std::collections::BTreeMap;
use std::env;
use std::fs;

use chrono::{DateTime, TimeZone, Utc};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};

use vaid_mint::chain::{verify_chain_at, ChainVerification, PresentedBundle, SingleKernelKey};
use vaid_mint::document::{AgentClass, AgentId, ScopeBoundaryEntry, TenantId, Vaid, VaidId};
use vaid_mint::revocation::RevocationStatus;
use vaid_mint::verify::verify_vaid_standing_from_json;
use vaid_mint::{attestation::AttestationBundle, canonical_vaid_signing_bytes};

/// Fixed trust domain for every document this harness builds. Well-formed per
/// `issuer_identity::is_valid_trust_domain` (two labels, lowercase, non-numeric
/// final label).
const TRUST_DOMAIN: &str = "aat-harness.example.test";
const TENANT: &str = "aat-harness-tenant";

struct Kernel {
    kp: Ed25519KeyPair,
    public_key: Vec<u8>,
    thumbprint: String,
}

impl Kernel {
    fn new() -> Self {
        // Fixed, non-secret seed: this key signs only documents this harness
        // builds in-process for a single run, never anything presented to a
        // third party, so a fixed seed costs nothing and makes a run
        // reproducible.
        let seed = [0x51u8; 32];
        let kp = Ed25519KeyPair::from_seed_unchecked(&seed).expect("valid Ed25519 seed");
        let public_key = kp.public_key().as_ref().to_vec();
        let thumbprint = vaid_mint::issuer_identity::kernel_key_thumbprint(&public_key);
        Self {
            kp,
            public_key,
            thumbprint,
        }
    }

    fn sign(&self, bytes: &[u8]) -> Vec<u8> {
        self.kp.sign(bytes).as_ref().to_vec()
    }
}

fn ts(secs: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(secs, 0).single().expect("valid unix time")
}

/// Build and sign one VAID document directly (never through `MintService`):
/// this harness constructs ADVERSARIAL as well as valid chains, and
/// `MintService::mint_child` would refuse to mint an attenuation-violating
/// child in the first place. Building documents directly and handing them to
/// the real third-party verifier (`verify_chain_at`) is the faithful
/// presenter/verifier split the AAT vectors themselves use.
#[allow(clippy::too_many_arguments)]
fn build_doc(
    kernel: &Kernel,
    parent: Option<&Vaid>,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    capability_set: Vec<String>,
) -> Vaid {
    let agent_id = AgentId::new();
    let parent_vaid_id: Option<VaidId> = parent.map(|p| p.vaid_id());
    let lineage_hash = vaid_mint::document::compute_lineage_hash(parent_vaid_id, &agent_id);
    let unsigned = Vaid::with_lineage(
        agent_id,
        AgentClass::new("aat-harness-agent"),
        "1.0.0".to_string(),
        TenantId::new(TENANT),
        issued_at,
        expires_at,
        vec![0u8; 32], // holder public key placeholder; not consulted by verify_chain_at
        Vec::new(),    // kernel_signature attached below
        parent_vaid_id,
        Vec::<ScopeBoundaryEntry>::new(), // unrestricted scope boundary (top)
        lineage_hash,
        capability_set,
        TRUST_DOMAIN.to_string(),
        kernel.thumbprint.clone(),
    );
    let sig = kernel.sign(&canonical_vaid_signing_bytes(&unsigned));
    unsigned.with_kernel_signature(sig)
}

#[derive(Debug, Clone, serde::Serialize)]
struct ResultEntry {
    verdict: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

fn permit() -> ResultEntry {
    ResultEntry {
        verdict: "PERMIT".into(),
        reason: None,
    }
}
fn deny() -> ResultEntry {
    ResultEntry {
        verdict: "DENY".into(),
        reason: None,
    }
}
fn skip(reason: &str) -> ResultEntry {
    ResultEntry {
        verdict: "SKIP".into(),
        reason: Some(reason.to_string()),
    }
}

/// Compose VAID's actual published verification surface the way its own docs
/// tell a caller to: `verify_chain_at` (authenticity + attenuation; it
/// deliberately does not check the LEAF's own expiry, by design -- see
/// `chain.rs`), plus `Vaid::is_expired_at` (the caller's own responsibility),
/// plus `Vaid::has_capability` (the tool-authorization predicate). All three
/// are real, unmodified VAID functions.
fn chain_verdict(
    kernel: &Kernel,
    leaf: &Vaid,
    ancestors: &[Vaid],
    now: DateTime<Utc>,
    tool: &str,
) -> ResultEntry {
    let bundle = PresentedBundle::new(ancestors.iter().cloned());
    let keys = SingleKernelKey::new(&kernel.public_key);
    let verification = verify_chain_at(&keys, leaf, &bundle, &AttestationBundle::default(), now);
    let attenuated = matches!(verification, ChainVerification::Attenuated);
    let leaf_live = !leaf.is_expired_at(now);
    let authorized = leaf.has_capability(tool);
    if attenuated && leaf_live && authorized {
        permit()
    } else {
        deny()
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: aat_interop_harness <vectors.json> <results.json>");
        std::process::exit(2);
    }
    let vectors_path = &args[1];
    let results_path = &args[2];

    let raw = fs::read_to_string(vectors_path).expect("read vectors file");
    let suite: Value = serde_json::from_str(&raw).expect("parse vectors JSON");
    let vectors = suite["vectors"].as_array().expect("vectors array");

    let kernel = Kernel::new();
    let mut results: BTreeMap<String, ResultEntry> = BTreeMap::new();

    for v in vectors {
        let id = v["id"].as_str().expect("vector id").to_string();
        let group = id
            .split('.')
            .nth(1)
            .expect("vector id has a group component")
            .to_string();
        let tool = v["tool"].as_str().unwrap_or("read_file").to_string();
        let now = ts(v["now"].as_i64().unwrap_or(1704067500));

        let entry = match (group.as_str(), id.as_str()) {
            // J.1 -- minimal valid root token, single-token (root == leaf) chain.
            ("1", _) => {
                let root = build_doc(
                    &kernel,
                    None,
                    ts(now.timestamp() - 300),
                    ts(now.timestamp() + 3600),
                    vec![tool.clone()],
                );
                chain_verdict(&kernel, &root, &[], now, &tool)
            }
            // J.3 -- valid 3-level chain: root -> mid -> leaf, each hop narrowing.
            ("3", _) => {
                let root = build_doc(
                    &kernel,
                    None,
                    ts(now.timestamp() - 600),
                    ts(now.timestamp() + 7200),
                    vec![tool.clone(), "search_index".to_string()],
                );
                let mid = build_doc(
                    &kernel,
                    Some(&root),
                    ts(now.timestamp() - 300),
                    ts(now.timestamp() + 3600),
                    vec![tool.clone()],
                );
                let leaf = build_doc(
                    &kernel,
                    Some(&mid),
                    ts(now.timestamp() - 60),
                    ts(now.timestamp() + 1800),
                    vec![tool.clone()],
                );
                chain_verdict(&kernel, &leaf, &[root, mid], now, &tool)
            }
            // J.5 -- expired root token.
            ("5", _) => {
                let root = build_doc(
                    &kernel,
                    None,
                    ts(now.timestamp() - 7200),
                    ts(now.timestamp() - 3600),
                    vec![tool.clone()],
                );
                chain_verdict(&kernel, &root, &[], now, &tool)
            }
            // J.9.3 -- tool granted at root is dropped before the leaf: leaf
            // cannot invoke it. Uses the real Vaid::has_capability predicate.
            ("9", "J.9.3") => {
                let root = build_doc(
                    &kernel,
                    None,
                    ts(now.timestamp() - 600),
                    ts(now.timestamp() + 3600),
                    vec![tool.clone(), "other_tool".to_string()],
                );
                let leaf = build_doc(
                    &kernel,
                    Some(&root),
                    ts(now.timestamp() - 60),
                    ts(now.timestamp() + 1800),
                    vec!["other_tool".to_string()],
                );
                chain_verdict(&kernel, &leaf, &[root], now, &tool)
            }
            // J.9.4 -- prefix presentation: an intermediate hop of a valid
            // chain, presented as its OWN leaf (its descendant withheld), must
            // still verify.
            ("9", "J.9.4") => {
                let root = build_doc(
                    &kernel,
                    None,
                    ts(now.timestamp() - 600),
                    ts(now.timestamp() + 7200),
                    vec![tool.clone()],
                );
                let mid = build_doc(
                    &kernel,
                    Some(&root),
                    ts(now.timestamp() - 300),
                    ts(now.timestamp() + 3600),
                    vec![tool.clone()],
                );
                // mid presented as the leaf; the deeper hop is simply never built.
                chain_verdict(&kernel, &mid, &[root], now, &tool)
            }
            // J.9.6 -- a tool is named only by a claim VAID's model has no
            // concept of (AAT's RFC 8693 `scope` string). This harness never
            // reads such a claim at all: capability_set is the only grant
            // VAID recognises, so the tool is correctly absent from it.
            ("9", "J.9.6") => {
                let root = build_doc(
                    &kernel,
                    None,
                    ts(now.timestamp() - 600),
                    ts(now.timestamp() + 3600),
                    vec!["read_file".to_string(), "search_index".to_string()],
                );
                let leaf = build_doc(
                    &kernel,
                    Some(&root),
                    ts(now.timestamp() - 60),
                    ts(now.timestamp() + 1800),
                    vec!["read_file".to_string()],
                );
                chain_verdict(&kernel, &leaf, &[root], now, &tool)
            }
            ("9", _) => skip(
                "closed-world per-argument constraint evaluation / duplicate JSON \
                 member in invocation args: VAID's authorization surface is flat \
                 capability-string containment (Vaid::has_capability) and prefix \
                 scope matching; it does not evaluate a tool call's arguments \
                 against a per-argument constraint map, so this scenario has no \
                 VAID check to exercise",
            ),
            // J.13 -- I3: derived exp beyond parent's exp. verify_chain_at's
            // expiry_attenuates check is exercised directly by presenting an
            // adversarial child whose expires_at exceeds its parent's.
            ("13", "J.13") => {
                let root = build_doc(
                    &kernel,
                    None,
                    ts(now.timestamp() - 600),
                    ts(now.timestamp() + 1800),
                    vec![tool.clone()],
                );
                let leaf = build_doc(
                    &kernel,
                    Some(&root),
                    ts(now.timestamp() - 60),
                    ts(now.timestamp() + 3600), // beyond the parent's expiry
                    vec![tool.clone()],
                );
                chain_verdict(&kernel, &leaf, &[root], now, &tool)
            }
            // J.13.c -- derived token expired while its parent is still valid.
            // verify_chain_at deliberately does not check the LEAF's own
            // expiry (chain.rs: "THE LEAF IS DELIBERATELY NOT CHECKED HERE");
            // this harness composes it with the real Vaid::is_expired_at,
            // exactly as VAID's own module docs tell a caller to.
            ("13", "J.13.c") => {
                let root = build_doc(
                    &kernel,
                    None,
                    ts(now.timestamp() - 600),
                    ts(now.timestamp() + 3600),
                    vec![tool.clone()],
                );
                let leaf = build_doc(
                    &kernel,
                    Some(&root),
                    ts(now.timestamp() - 300),
                    ts(now.timestamp() - 60), // already expired at `now`
                    vec![tool.clone()],
                );
                chain_verdict(&kernel, &leaf, &[root], now, &tool)
            }
            ("13", _) => skip(
                "iat-ordering / MAX_IAT_SKEW / zero-lifetime (exp == iat) \
                 invariants (AAT steps 4j-4l): VAID's verify_chain_at consults \
                 only expires_at attenuation between hops, never issued_at \
                 ordering or a freshness-skew bound at verify time, so this \
                 specific numeric invariant has no VAID check behind it",
            ),
            // J.14 -- invalid signature: one bit flipped in the root signature.
            ("14", "J.14") => {
                let root = build_doc(
                    &kernel,
                    None,
                    ts(now.timestamp() - 300),
                    ts(now.timestamp() + 3600),
                    vec![tool.clone()],
                );
                let mut tampered_sig = root.kernel_signature().to_vec();
                tampered_sig[0] ^= 0x01;
                let tampered = root.with_kernel_signature(tampered_sig);
                chain_verdict(&kernel, &tampered, &[], now, &tool)
            }
            ("14", _) => skip(
                "JOSE header rule (alg:none rejection, header-supplied jwk \
                 ignored): VAID's wire format carries no JOSE header at all \
                 (signature-scheme is the `sig_version` field, inside the \
                 signed document), so there is no header for a VAID verifier \
                 to read or reject",
            ),
            // J.23.1 -- empty chain: zero tokens presented. There is no VAID
            // Vaid document to call verify_chain_at with at all (the function
            // requires a leaf); no credential presented is DENY under any
            // authorization model by construction, not a borrowed verdict.
            ("23", "J.23.1") => deny(),
            ("23", "J.23.2") | ("23", "J.23.3") => skip(
                "MAX_TOKEN_SIZE / MAX_CHAIN_SIZE byte-size limits: VAID defines \
                 no analogous size cap anywhere in its verification surface \
                 (grep of vaid-mint/src finds no such constant), so this is not \
                 a check VAID can run",
            ),
            // J.23.4 -- duplicate member name in the signed claims object. VAID
            // has exactly this check, over raw JSON text, before any struct
            // exists to inspect: `has_duplicate_member_names`, consulted by
            // `verify_vaid_standing_from_json`.
            ("23", "J.23.4") => {
                let root = build_doc(
                    &kernel,
                    None,
                    ts(now.timestamp() - 300),
                    ts(now.timestamp() + 3600),
                    vec![tool.clone()],
                );
                let good_json = serde_json::to_string(&root).expect("serialize Vaid");
                // Splice a duplicate top-level member into the raw text. The
                // document is otherwise byte-identical and validly signed;
                // the only fault is the duplicate member name, exactly as the
                // AAT vector's fault is isolated.
                assert!(good_json.ends_with('}'));
                let tampered_json = format!(
                    "{}, \"tenant_id\":\"{}\"}}",
                    &good_json[..good_json.len() - 1],
                    TENANT
                );
                let verdict = verify_vaid_standing_from_json(
                    &kernel.public_key,
                    &tampered_json,
                    RevocationStatus::NotRevoked,
                );
                if verdict.is_valid() {
                    permit()
                } else {
                    deny()
                }
            }
            ("23", _) => skip("unrecognised J.23 sub-vector"),
            // J.27.1 -- unrecognized claims are ignored. Build a document,
            // round-trip an extra unknown top-level member through it (caught
            // by Vaid's own `#[serde(flatten)] unknown_fields`), sign the
            // document THAT carries the extra member, and confirm it still
            // verifies and attenuates -- exercising VAID's real
            // forward-compatible field, not a hand-written expectation.
            ("27", "J.27.1") => {
                let unsigned = build_doc(
                    &kernel,
                    None,
                    ts(now.timestamp() - 300),
                    ts(now.timestamp() + 3600),
                    vec![tool.clone()],
                );
                let mut value = serde_json::to_value(&unsigned).expect("Vaid to Value");
                value["x_harness_unrecognized_claim"] = json!("ignored-by-a-conforming-verifier");
                let with_unknown: Vaid =
                    serde_json::from_value(value).expect("Vaid round-trips an unknown member");
                let sig = kernel.sign(&canonical_vaid_signing_bytes(&with_unknown));
                let signed = with_unknown.with_kernel_signature(sig);
                chain_verdict(&kernel, &signed, &[], now, &tool)
            }
            ("27", _) => skip(
                "non-JCS-canonical byte attack, same-holder-key derivation, aud \
                 array/mismatch, or JOSE-header JWK member shape: each is a \
                 property of the JWS/JOSE wire encoding or the holder-of-key \
                 PoP chain that VAID's native chain/document model does not \
                 carry at all",
            ),
            // Every remaining group: documented, group-level reasons for why
            // AAT's construct has no VAID analogue. See the harness module
            // docs and the s442 report for the full rationale per group.
            ("2", _) => skip(
                "duplicate-jti cycle detection over a presented chain (AAT step \
                 2c): VAID's PresentedBundle dedupes a repeated vaid_id by \
                 last-write-wins rather than rejecting the reuse outright, and \
                 its real cycle detection (inside assemble_lineage) only fires \
                 on an actual parent-pointer cycle, which this scenario (two \
                 sibling entries sharing one identifier) does not construct; \
                 translating it would fabricate a rejection VAID's real API \
                 does not perform"
            ),
            ("4", _) | ("20", _) | ("21", _) | ("12", _) => skip(
                "holder-of-key per-hop signing / par_hash binding: AAT's chain \
                 is signed hop-by-hop by the PREVIOUS hop's own holder key \
                 (cnf.jwk), with par_hash binding a hop to a specific parent \
                 presentation. VAID's entire chain is signed by one issuer's \
                 kernel key (KernelKeyResolver selects by key thumbprint only; \
                 trust_domain is checked only for well-formedness, never \
                 cross-checked against which trust anchor's key verified). \
                 VAID has no per-hop distinct-signer check and no concept of \
                 selecting among multiple named trust anchors by issuer \
                 identity, so there is no VAID code path this group's scenario \
                 (including J.21.22 and J.21.23, the second-trust-anchor \
                 vectors) can exercise"
            ),
            ("6", _) => skip(
                "per-invocation, audience-bound PoP: AAT's PoP is signed fresh \
                 by the current holder's cnf key at call time and checked \
                 against an enforcement-point audience. VAID's PoP (vaid-pop) \
                 is a mint-time BYO-key possession proof with no per-call, \
                 audience-bound presentation step at all"
            ),
            ("7", _) => skip(
                "JOSE header well-formedness (typ/alg/jwk parameters): VAID's \
                 wire format carries no JOSE header"
            ),
            ("8", _) => skip(
                "per-argument constraint-map structure, including the \
                 empty-parent-map / constraint-key-introduction invariant (step \
                 4p2): VAID's capability_set is a flat list of opaque strings \
                 and scope_boundary is prefix matching over a single resource \
                 string; neither carries a keyed map of per-argument \
                 constraints a derived token can narrow or introduce"
            ),
            ("10", _) => skip(
                "del_depth/del_max_depth consistency between hops (AAT I2): \
                 Vaid carries no del_depth/del_max_depth field at all. VAID's \
                 only depth concept, validate_max_delegation_depth, is MINT-TIME \
                 issuer policy (how deep an issuer will mint), never re-derived \
                 or re-checked from a presented chain's claims at verify time"
            ),
            ("11", _) | ("15", _) | ("16", _) | ("17", _) | ("18", _) | ("19", _) | ("26", _) => skip(
                "AAT check-predicate algebra (all/any/one_of/not_one_of/exact, \
                 and the S4.5 subsumption table over them): VAID has no \
                 constraint-predicate language at all. Containment is tested \
                 only by flat capability-string membership and resource-prefix \
                 matching, which cannot express set-algebra widening/narrowing \
                 over named constraint values"
            ),
            ("22", _) => skip(
                "optional/unnamed invocation arguments: part of AAT's \
                 per-argument constraint evaluation against a tool call, which \
                 VAID does not perform (see group 8/9's reason)"
            ),
            ("24", _) => skip(
                "number-admissibility / type rules on a JWS claim (e.g. jti not \
                 a string): VAID's documents are typed Rust structs deserialized \
                 by serde directly from the presented JSON; a vector here \
                 constructs raw JWS claim bytes this harness does not parse, \
                 since it builds native Vaid documents rather than an AAT JWS \
                 parser"
            ),
            ("25", _) => skip(
                "authorization_details entries of a type other than \
                 attenuating_agent_token, or more/fewer than one such entry: \
                 VAID's document has no 'entries' or 'type' concept at all -- \
                 capability_set is the sole, singular grant list"
            ),
            (g, _) => skip(&format!("group {g}: unclassified by this harness; treated as unrepresentable in VAID's native chain/document model pending a specific mapping")),
        };

        results.insert(id, entry);
    }

    let out = serde_json::to_string_pretty(&results).expect("serialize results");
    fs::write(results_path, out).expect("write results file");

    let permit_n = results.values().filter(|r| r.verdict == "PERMIT").count();
    let deny_n = results.values().filter(|r| r.verdict == "DENY").count();
    let skip_n = results.values().filter(|r| r.verdict == "SKIP").count();
    println!(
        "wrote {} results to {}: {} PERMIT, {} DENY, {} SKIP",
        results.len(),
        results_path,
        permit_n,
        deny_n,
        skip_n
    );
}
