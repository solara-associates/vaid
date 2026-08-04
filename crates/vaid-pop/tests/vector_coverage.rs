//! Every vector in `tests/vectors/` is covered by the packaged firewall.
//!
//! Mirror of `crates/vaid-mint/tests/vector_coverage.rs`. The binary already fails
//! closed at runtime when the embedded set and `VECTOR_CHECKS` disagree — but that
//! fires only when someone runs it. This fires in `cargo test`, so a vector added
//! without a checker is caught on the PR that adds it rather than by whoever next
//! happens to run the firewall.
//!
//! Fails in both directions, for the same reason the firewall does: a vector nothing
//! checks makes a PASS mean less than it appears to, and a checker naming an absent
//! vector is that defect wearing the other hat.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn present_vectors() -> BTreeSet<String> {
    fs::read_dir(vectors_dir())
        .expect("tests/vectors is readable")
        .map(|e| {
            e.expect("dir entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|n| n.ends_with(".json"))
        .collect()
}

/// The packaged firewall must name every vector that ships. A vector present in the
/// crate but absent from `VECTOR_CHECKS` would be embedded by `build.rs` and then
/// rejected at runtime — correct, but only discovered by running the binary.
#[test]
fn the_packaged_firewall_covers_every_vector() {
    let source =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bin/conformance.rs"))
            .expect("the packaged firewall source is readable");

    let uncovered: Vec<_> = present_vectors()
        .into_iter()
        .filter(|n| !source.contains(n.as_str()))
        .collect();

    assert!(
        uncovered.is_empty(),
        "vector(s) not named in the packaged firewall's VECTOR_CHECKS: {uncovered:?} — a \
         cargo-install consumer would not have them checked"
    );
}

/// ...and must not name one that does not ship.
#[test]
fn the_packaged_firewall_names_no_absent_vector() {
    let source =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bin/conformance.rs"))
            .expect("the packaged firewall source is readable");

    let present = present_vectors();
    // Every `*_v1.json` literal the firewall mentions must actually exist. Scanning
    // the source rather than importing the table keeps this test independent of the
    // binary's internals — it asserts what a reader would check by eye.
    let named: BTreeSet<String> = source
        .split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '.'))
        .filter(|t| t.ends_with("_v1.json"))
        .map(str::to_string)
        .collect();

    let absent: Vec<_> = named.difference(&present).cloned().collect();
    assert!(
        absent.is_empty(),
        "the packaged firewall names vector(s) that do not ship: {absent:?} — the \
         packaging dropped them, or the check is stale"
    );
}
