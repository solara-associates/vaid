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

use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs;

use chrono::{DateTime, TimeZone, Utc};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};

use vaid_mint::chain::{
    verify_chain_at, ChainVerification, KernelKeyMap, PresentedBundle, SingleKernelKey,
};
use vaid_mint::document::{AgentClass, AgentId, ScopeBoundaryEntry, TenantId, Vaid, VaidId};
use vaid_mint::revocation::RevocationStatus;
use vaid_mint::verify::{verify_vaid_standing_from_json, VaidVerdict};
use vaid_mint::{attestation::AttestationBundle, canonical_vaid_signing_bytes};

/// Fixed trust domain for every document this harness builds. Well-formed per
/// `issuer_identity::is_valid_trust_domain` (two labels, lowercase, non-numeric
/// final label).
const TRUST_DOMAIN: &str = "aat-harness.example.test";
/// A SECOND trust domain, bound to a second kernel key, for J.21.22/J.21.23 --
/// VAID's own hand-written interop vector 12 needs two legitimately trusted
/// issuers to construct its scenario (a key trusted for one domain, used on a
/// document claiming the other).
const TRUST_DOMAIN_2: &str = "aat-harness-second.example.test";
const TENANT: &str = "aat-harness-tenant";

struct Kernel {
    kp: Ed25519KeyPair,
    public_key: Vec<u8>,
    thumbprint: String,
}

impl Kernel {
    fn new() -> Self {
        Self::from_seed(0x51)
    }

    /// A second, independent kernel keypair -- for the untrusted-key vectors
    /// (J.14.c) and the two-trust-anchor vectors (J.21.22/J.21.23). Fixed,
    /// non-secret seed, same reasoning as `new()`.
    fn from_seed(byte: u8) -> Self {
        let seed = [byte; 32];
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
    build_doc_ex(
        kernel,
        parent,
        issued_at,
        expires_at,
        capability_set,
        Vec::<ScopeBoundaryEntry>::new(),
        TRUST_DOMAIN,
    )
}

/// Full form of [`build_doc`]: also sets `scope_boundary` and `trust_domain`
/// explicitly, for the vectors that turn on scope attenuation (02, 11) or on
/// which trust domain a document claims (12).
#[allow(clippy::too_many_arguments)]
fn build_doc_ex(
    kernel: &Kernel,
    parent: Option<&Vaid>,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    capability_set: Vec<String>,
    scope_boundary: Vec<ScopeBoundaryEntry>,
    trust_domain: &str,
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
        scope_boundary,
        lineage_hash,
        capability_set,
        trust_domain.to_string(),
        kernel.thumbprint.clone(),
    );
    let sig = kernel.sign(&canonical_vaid_signing_bytes(&unsigned));
    unsigned.with_kernel_signature(sig)
}

/// A trusted-issuer registry that binds each accepted kernel key to exactly
/// one trust domain -- the fix shipped for GHSA-hfjh-v2x2-r58v in
/// `python/vaid-a2a/vaid_a2a/verifier.py`'s `_TrustedIssuerMap`, transliterated
/// here because bare `vaid_mint::chain::KernelKeyResolver` deliberately does
/// not carry this binding (see `mint.rs`'s `tenant_attenuates` docs: the
/// domain-to-key binding is out-of-band and is the caller's responsibility).
/// This harness is the caller, for the one AAT group (J.21.22/J.21.23) that
/// needs the binding VAID's a2a/adk/jwt-bridge integration layers already
/// ship. Mirrors `trust_domain_for` exactly: look up by thumbprint, compare
/// against the document's own claimed `trust_domain`, fail closed on either a
/// miss or a mismatch -- never derive an answer without running this check.
struct TrustedIssuerMap {
    by_thumbprint: HashMap<String, (Vec<u8>, String)>,
}

impl TrustedIssuerMap {
    fn new(entries: &[(&Kernel, &str)]) -> Self {
        let by_thumbprint = entries
            .iter()
            .map(|(k, domain)| (k.thumbprint.clone(), (k.public_key.clone(), domain.to_string())))
            .collect();
        Self { by_thumbprint }
    }

    /// `Some(domain)` this thumbprint is bound to, or `None` if it is not an
    /// accepted key at all.
    fn trust_domain_for(&self, thumbprint: &str) -> Option<&str> {
        self.by_thumbprint.get(thumbprint).map(|(_, d)| d.as_str())
    }

    /// `true` iff `doc`'s claimed `trust_domain` is EXACTLY the domain this
    /// registry bound to the key `doc` claims it was signed by. An untrusted
    /// key (no entry at all) and a trusted key used outside its bound domain
    /// are both refused here -- the same `issuer_mismatch` outcome VAID's own
    /// vector 12 and the a2a verifier both give, for the same reason: in the
    /// domain it is claiming, this signer is exactly as unauthorized as a
    /// signer this registry has never heard of.
    fn binds(&self, doc: &Vaid) -> bool {
        self.trust_domain_for(doc.kernel_key_thumbprint()) == Some(doc.trust_domain())
    }

    fn as_key_map(&self) -> KernelKeyMap {
        KernelKeyMap::new(self.by_thumbprint.values().map(|(k, _)| k.clone()))
    }
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

/// Like [`chain_verdict`], but authenticates against a [`TrustedIssuerMap`]
/// instead of one [`SingleKernelKey`]: the leaf's resolved key must ALSO be
/// bound to the trust domain the leaf claims (and the same for every
/// ancestor), checked before `verify_chain_at` ever runs. A bound-domain
/// mismatch or an unaccepted key is `issuer_mismatch` -- the same DENY
/// `verify_chain_at`'s own authentication step gives for a key the resolver
/// does not accept at all, because that is exactly what an unbound domain
/// claim is.
fn chain_verdict_with_binding(
    trust: &TrustedIssuerMap,
    leaf: &Vaid,
    ancestors: &[Vaid],
    now: DateTime<Utc>,
    tool: &str,
) -> ResultEntry {
    if !trust.binds(leaf) || ancestors.iter().any(|a| !trust.binds(a)) {
        return deny();
    }
    let bundle = PresentedBundle::new(ancestors.iter().cloned());
    let keys = trust.as_key_map();
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
    // An untrusted key, for J.14.c ("header-supplied key is not used"): a
    // document that is internally self-consistent -- its own
    // kernel_key_thumbprint really does correspond to the key that signed it
    // -- but whose key the verifier's trust set does not contain at all.
    let untrusted_kernel = Kernel::from_seed(0x52);
    // A second trusted kernel/trust-domain pair, for the two-trust-anchor
    // vectors (J.21.22/J.21.23 / VAID's own vector 12).
    let kernel2 = Kernel::from_seed(0x53);
    let trust_map = TrustedIssuerMap::new(&[
        (&kernel, TRUST_DOMAIN),
        (&kernel2, TRUST_DOMAIN_2),
    ]);
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
            // J.14.c -- "header-supplied key is not used" (VAID vector 06,
            // unknown root key): a document that is internally self-consistent
            // -- signed by `untrusted_kernel`, whose own thumbprint it
            // correctly names -- but the verifier's resolver does not accept
            // that key at all. `chain_verdict` authenticates against `kernel`
            // only, so `resolve_key` returns `None` and `verify_chain_at`
            // returns `Inauthentic` for a reason that has nothing to do with
            // the signature bytes being wrong.
            ("14", "J.14.c") => {
                let root = build_doc(
                    &untrusted_kernel,
                    None,
                    ts(now.timestamp() - 300),
                    ts(now.timestamp() + 3600),
                    vec![tool.clone()],
                );
                chain_verdict(&kernel, &root, &[], now, &tool)
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
            // J.21.22 -- "root iss names another trust anchor's issuer" (VAID
            // vector 12: trust domain not bound to the signing key). The root
            // is signed, genuinely, by kernel2's key -- which the registry
            // trusts for TRUST_DOMAIN_2 -- but the document claims
            // TRUST_DOMAIN (kernel's domain). `chain_verdict_with_binding`
            // runs the transliterated `_TrustedIssuerMap.trust_domain_for`
            // check from the already-fixed GHSA-hfjh-v2x2-r58v before calling
            // `verify_chain_at` at all, exactly mirroring what VAID's own
            // a2a/adk/jwt-bridge verifiers do in production.
            ("21", "J.21.22") => {
                let root = build_doc_ex(
                    &kernel2,
                    None,
                    ts(now.timestamp() - 300),
                    ts(now.timestamp() + 3600),
                    vec![tool.clone()],
                    Vec::<ScopeBoundaryEntry>::new(),
                    TRUST_DOMAIN, // claims the OTHER trusted issuer's domain
                );
                chain_verdict_with_binding(&trust_map, &root, &[], now, &tool)
            }
            // J.21.23 -- "root signed by the second trust anchor's key",
            // presented honestly: kernel2 signs, and the document correctly
            // claims TRUST_DOMAIN_2 (kernel2's own bound domain). Exercises
            // the same binding check on its PERMIT side: a second, properly
            // bound trust anchor must still verify.
            ("21", "J.21.23") => {
                let root = build_doc_ex(
                    &kernel2,
                    None,
                    ts(now.timestamp() - 300),
                    ts(now.timestamp() + 3600),
                    vec![tool.clone()],
                    Vec::<ScopeBoundaryEntry>::new(),
                    TRUST_DOMAIN_2,
                );
                chain_verdict_with_binding(&trust_map, &root, &[], now, &tool)
            }
            ("4", _) | ("20", _) | ("21", _) | ("12", _) => skip(
                "holder-of-key per-hop signing / par_hash binding: AAT's chain \
                 is signed hop-by-hop by the PREVIOUS hop's own holder key \
                 (cnf.jwk), with par_hash binding a hop to a specific parent \
                 presentation. VAID's entire chain is signed by one issuer's \
                 kernel key, and bare vaid-mint's KernelKeyResolver selects by \
                 key thumbprint only, with no cross-check against which trust \
                 anchor's key verified -- that binding is deliberately \
                 out-of-band for vaid-mint and lives in the a2a/adk/jwt-bridge \
                 integration layers instead (GHSA-hfjh-v2x2-r58v, already \
                 fixed; see J.21.22/J.21.23 above, which this harness DOES \
                 translate using that binding). VAID still has no per-hop \
                 distinct-signer check or par_hash concept, so the rest of \
                 this group's scenarios remain unrepresentable"
            ),
            ("6", _) => skip(
                "per-invocation, audience-bound PoP: VAID DOES have per-request \
                 proof of possession -- vaid-client signs every request into \
                 the four x-synthera-* headers (auth.rs). What this pass did \
                 not do is translate AAT's invocation-time PoP presentation \
                 (a fresh signature over the current holder's cnf key and an \
                 enforcement-point audience, bound to the specific tool call) \
                 into that model. This is a gap in this pass's translation, \
                 not an absence of the underlying mechanism in VAID"
            ),
            ("7", _) => skip(
                "JOSE header well-formedness (typ/alg/jwk parameters): VAID's \
                 wire format carries no JOSE header"
            ),
            // J.8.3/J.8.5 -- "unknown constraint_type is fail-closed" (VAID
            // vector 13, unknown scope kind): a document whose scope_boundary
            // carries a `kind` VAID's own matcher (document.rs's
            // RECOGNISED_SCOPE_KINDS) does not recognise. `verify_vaid` /
            // `verify_vaid_standing` has exactly this check, at step S.10:
            // `boundary_is_evaluable` fails and the verdict is
            // `UnknownScopeKind`, fail-closed, regardless of whether the
            // unrecognised entry is ever consulted by the invoked tool
            // (covers J.8.5's "on a tool that is not invoked" too -- the
            // check does not look at which tool was called).
            ("8", "J.8.3") | ("8", "J.8.5") => {
                let unknown_kind_entry = ScopeBoundaryEntry::new(
                    "future-constraint-kind-v99",
                    json!("whatever-value"),
                )
                .expect("an unrecognised kind parses structurally (S.10)");
                let leaf = build_doc_ex(
                    &kernel,
                    None,
                    ts(now.timestamp() - 300),
                    ts(now.timestamp() + 3600),
                    vec![tool.clone()],
                    vec![unknown_kind_entry],
                    TRUST_DOMAIN,
                );
                // `verify_vaid_standing` checks expiry against the REAL wall
                // clock (`Vaid::is_expired`), not an injected `now` -- fine
                // for a live caller, wrong for a reproducible vector run
                // against a fixed `now` in the past. Composed here exactly as
                // `verify_vaid_standing` itself composes it (authenticity,
                // then `boundary_is_evaluable`), but with `is_expired_at(now)`
                // in place of the real-clock `is_expired()`.
                let verdict = {
                    use vaid_mint::document::boundary_is_evaluable;
                    use vaid_mint::verify::verify_vaid_authenticity_graded;
                    let authenticity = verify_vaid_authenticity_graded(&kernel.public_key, &leaf);
                    if !authenticity.is_valid() {
                        authenticity
                    } else if leaf.is_expired_at(now) {
                        VaidVerdict::Expired
                    } else if !boundary_is_evaluable(leaf.scope_boundary()) {
                        VaidVerdict::UnknownScopeKind
                    } else {
                        VaidVerdict::Valid
                    }
                };
                if verdict == VaidVerdict::UnknownScopeKind {
                    deny()
                } else {
                    // Any other outcome would mean this harness's unknown-kind
                    // entry was somehow evaluable after all -- a harness bug,
                    // not a verdict to report, so fail loudly rather than
                    // silently recording the wrong thing.
                    panic!("{id}: expected UnknownScopeKind, got {verdict:?}")
                }
            }
            ("8", _) => skip(
                "per-argument constraint-map structure, including the \
                 empty-parent-map / constraint-key-introduction invariant (step \
                 4p2): VAID's capability_set is a flat list of opaque strings \
                 and scope_boundary is prefix matching over a single resource \
                 string; neither carries a keyed map of per-argument \
                 constraints a derived token can narrow or introduce. (J.8.3 \
                 and J.8.5 are handled above via the unknown-scope-kind \
                 verdict, which is a real VAID analogue for \"unrecognised \
                 constraint_type\"; the rest of this group is per-argument \
                 constraint evaluation VAID does not perform at all.)"
            ),
            ("10", _) => skip(
                "del_depth/del_max_depth consistency between hops (AAT I2): \
                 Vaid carries no del_depth/del_max_depth field at all. VAID's \
                 only depth concept, validate_max_delegation_depth, is MINT-TIME \
                 issuer policy (how deep an issuer will mint), never re-derived \
                 or re-checked from a presented chain's claims at verify time"
            ),
            // J.11 -- "I4 violation: one_of widened" and J.19.11 -- "range:
            // derived min below the parent's" (VAID vector 02: child scope
            // wider than parent). Both AAT vectors test the same property
            // through a different constraint kind (an enumerated `one_of` set
            // and a numeric `range`, respectively); VAID has neither
            // constraint kind, but it has the one property both are
            // instances of -- a child claiming authority the parent does not
            // hold -- and `scope_attenuates` (consulted by `verify_chain_at`)
            // is exactly that check. The child's scope_boundary prefix here
            // is NOT a sub-prefix of the parent's, so it is wider, the same
            // shape of violation both AAT vectors assert, translated through
            // VAID's own containment predicate rather than reproduced.
            ("11", "J.11") | ("19", "J.19.11") => {
                let root = build_doc_ex(
                    &kernel,
                    None,
                    ts(now.timestamp() - 600),
                    ts(now.timestamp() + 3600),
                    vec![tool.clone()],
                    vec![ScopeBoundaryEntry::prefix("data.allowed")],
                    TRUST_DOMAIN,
                );
                let leaf = build_doc_ex(
                    &kernel,
                    Some(&root),
                    ts(now.timestamp() - 60),
                    ts(now.timestamp() + 1800),
                    vec![tool.clone()],
                    vec![ScopeBoundaryEntry::prefix("data.")], // wider than the parent's
                    TRUST_DOMAIN,
                );
                chain_verdict(&kernel, &leaf, &[root], now, &tool)
            }
            // J.11.b -- "I4 violation: tool not present in parent" (VAID
            // vector 08: capability not in parent). `caps_attenuate` (also
            // consulted by `verify_chain_at`) is exactly this check: the leaf
            // requests a capability the parent never held at all, as opposed
            // to J.9.3's "held, then dropped before the leaf".
            ("11", "J.11.b") => {
                let root = build_doc(
                    &kernel,
                    None,
                    ts(now.timestamp() - 600),
                    ts(now.timestamp() + 3600),
                    vec!["other_tool".to_string()],
                );
                let leaf = build_doc(
                    &kernel,
                    Some(&root),
                    ts(now.timestamp() - 60),
                    ts(now.timestamp() + 1800),
                    vec![tool.clone()], // never held by the parent
                );
                chain_verdict(&kernel, &leaf, &[root], now, &tool)
            }
            // J.19.15 -- "derived empty map under a closed parent" (VAID
            // vector 11: unrestricted child). An empty child scope_boundary
            // means unrestricted (top); `scope_attenuation_reason`'s
            // empty-child guard refuses it under a non-empty (restricted)
            // parent as `ScopeEscalation`, so `verify_chain_at` is
            // `NotAttenuated` here, never reaching `Attenuated`.
            ("19", "J.19.15") => {
                let root = build_doc_ex(
                    &kernel,
                    None,
                    ts(now.timestamp() - 600),
                    ts(now.timestamp() + 3600),
                    vec![tool.clone()],
                    vec![ScopeBoundaryEntry::prefix("data.allowed")], // closed parent
                    TRUST_DOMAIN,
                );
                let leaf = build_doc_ex(
                    &kernel,
                    Some(&root),
                    ts(now.timestamp() - 60),
                    ts(now.timestamp() + 1800),
                    vec![tool.clone()],
                    Vec::<ScopeBoundaryEntry>::new(), // unrestricted child, under a restricted parent
                    TRUST_DOMAIN,
                );
                chain_verdict(&kernel, &leaf, &[root], now, &tool)
            }
            // J.26.1 -- "one_of rejects a value outside the set" (VAID
            // vector 05, shared with J.9.3: action outside leaf scope). Same
            // mechanism as J.9.3/J.9.6 -- `Vaid::has_capability` -- the leaf
            // simply never holds the invoked tool's capability.
            ("26", "J.26.1") => {
                let root = build_doc(
                    &kernel,
                    None,
                    ts(now.timestamp() - 600),
                    ts(now.timestamp() + 3600),
                    vec!["other_tool".to_string()],
                );
                let leaf = build_doc(
                    &kernel,
                    Some(&root),
                    ts(now.timestamp() - 60),
                    ts(now.timestamp() + 1800),
                    vec!["other_tool".to_string()], // never grants `tool`
                );
                chain_verdict(&kernel, &leaf, &[root], now, &tool)
            }
            ("11", _) | ("15", _) | ("16", _) | ("17", _) | ("18", _) | ("19", _) | ("26", _) => skip(
                "AAT check-predicate algebra (all/any/one_of/not_one_of/exact, \
                 and the S4.5 subsumption table over them): VAID has no \
                 constraint-predicate language at all. Containment is tested \
                 only by flat capability-string membership and resource-prefix \
                 matching, which cannot express set-algebra widening/narrowing \
                 over named constraint values. (J.11, J.11.b, J.19.11, J.19.15 \
                 and J.26.1 are handled above: each is an instance of plain \
                 scope/capability widening or non-membership, which VAID DOES \
                 have a check for, even though it has none of AAT's richer \
                 predicate kinds.)"
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
