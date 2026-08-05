//! Every vector in `tests/vectors/` is covered by a conformance gate.
//!
//! Rust ships no packaged firewall binary for `vaid-mint` — its equivalent is the
//! per-vector conformance tests. That leaves the same hole the Python and
//! TypeScript firewalls had before they started enumerating: a vector file can be
//! added to the directory with no test that reads it, and the suite stays green
//! while ignoring the artifact a release exists to freeze.
//!
//! This test closes it the same way, and fails in BOTH directions:
//!
//! - a vector PRESENT with no registered gate is a hard failure — the
//!   shipped-but-unchecked case;
//! - a gate NAMING a vector that is absent is also a hard failure — a gate that
//!   quietly checks nothing is the same masked-green defect wearing the other hat.
//!
//! It cannot verify a vector nobody has written a gate for; nothing can. What it
//! guarantees is that such a vector cannot land *quietly*.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Every vector file, mapped to the test binary that gates it. Adding a vector
/// without adding a row here fails this test by construction.
const GATED_VECTORS: &[(&str, &str)] = &[
    ("mint_v1.json", "tests/mint_conformance.rs"),
    ("mint_pop_v1.json", "tests/mint_pop_conformance.rs"),
    ("chain_v1.json", "tests/chain_conformance.rs"),
    ("attestation_v1.json", "tests/attestation_conformance.rs"),
    ("scope_v1.json", "tests/scope_conformance.rs"),
];

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

#[test]
fn every_bundled_vector_is_gated() {
    let present: BTreeSet<String> = fs::read_dir(vectors_dir())
        .expect("tests/vectors is readable")
        .map(|e| {
            e.expect("dir entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|n| n.ends_with(".json"))
        .collect();

    let gated: BTreeSet<String> = GATED_VECTORS.iter().map(|(v, _)| v.to_string()).collect();

    let unchecked: Vec<_> = present.difference(&gated).cloned().collect();
    assert!(
        unchecked.is_empty(),
        "vector(s) present in tests/vectors with no registered conformance gate: {unchecked:?} \
         — add the gate and a row to GATED_VECTORS. A vector nothing reads makes a green \
         suite mean less than it appears to."
    );

    let missing: Vec<_> = gated.difference(&present).cloned().collect();
    assert!(
        missing.is_empty(),
        "GATED_VECTORS names vector(s) that are not present: {missing:?} — the file was \
         removed, or the row is stale."
    );
}

/// The gate each row names must actually exist. Without this the registry could be
/// satisfied by a row pointing at a test file nobody ever wrote.
#[test]
fn every_registered_gate_file_exists() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for (vector, gate) in GATED_VECTORS {
        assert!(
            root.join(gate).is_file(),
            "{vector} is registered to gate {gate}, which does not exist"
        );
    }
}

/// The PACKAGED FIREWALL must cover every vector too.
///
/// `tests/` gates and the shipped binary are different audiences: a `#[test]` needs
/// a checkout, the binary is what a `cargo install` consumer runs. A vector gated by
/// a test but absent from `src/bin/conformance.rs` would be verified by us and
/// unverified by them — which is the exact asymmetry the binary was added to remove.
///
/// The binary also fails closed at runtime, but that fires only when someone runs
/// it; this fires in `cargo test`.
#[test]
fn the_packaged_firewall_covers_every_vector() {
    let source =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bin/conformance.rs"))
            .expect("the packaged firewall source is readable");

    let present: BTreeSet<String> = fs::read_dir(vectors_dir())
        .expect("tests/vectors is readable")
        .map(|e| {
            e.expect("dir entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|n| n.ends_with(".json"))
        .collect();

    let uncovered: Vec<_> = present
        .iter()
        .filter(|n| !source.contains(n.as_str()))
        .cloned()
        .collect();
    assert!(
        uncovered.is_empty(),
        "vector(s) not named in the packaged firewall's VECTOR_CHECKS: {uncovered:?} — a \
         cargo-install consumer would not have them checked"
    );
}

/// The gate named for a vector must actually reference it. A gate file that exists
/// but never opens the vector it claims is the exact silent-coverage failure this
/// module is about, one level in.
#[test]
fn every_registered_gate_reads_its_vector() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for (vector, gate) in GATED_VECTORS {
        let source = fs::read_to_string(root.join(gate)).expect("gate file is readable");
        assert!(
            source.contains(vector),
            "{gate} is registered as the gate for {vector} but never mentions it"
        );
    }
}
