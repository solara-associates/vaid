#!/usr/bin/env bash
#
# post_publish_smoke.sh — verify the PUBLISHED artifacts reproduce the frozen
# conformance vectors, using only registry-installed packages (never this repo's
# local/editable/path builds).
#
# DO NOT run before publishing — there is nothing on the registries yet. Run it
# the moment a publish wave completes.
#
# What it does:
#   * Python: a FRESH virtualenv, `pip install` vaid-pop / vaid-mint /
#     vaid-langchain from PyPI BY VERSION (== pins, no path, no editable).
#   * Rust: a FRESH scratch cargo project OUTSIDE this workspace, depending on
#     vaid-pop / vaid-client / vaid-mint from crates.io BY VERSION.
#   * Re-runs each package's CONFORMANCE-VECTOR proof (not the full test suite)
#     against those registry-installed builds:
#       - the installed wheels' vendored vectors must byte-match this repo's
#         frozen truth vectors (catches "published the wrong vector"), and
#       - the installed library code must reproduce each vector's digest +
#         signature (catches "published the wrong code").
#   * Exits non-zero and prints exactly which package/vector failed on mismatch.
#
# Versions default to 0.1.0; override per package via env:
#   VAID_POP_VER=0.1.1 ./scripts/post_publish_smoke.sh
#
set -uo pipefail

VAID_POP_VER="${VAID_POP_VER:-0.1.0}"
VAID_CLIENT_VER="${VAID_CLIENT_VER:-0.1.0}"
VAID_MINT_VER="${VAID_MINT_VER:-0.1.0}"
VAID_LANGCHAIN_VER="${VAID_LANGCHAIN_VER:-0.1.0}"

# Repo root (this script lives in <repo>/scripts). The frozen "truth" vectors are
# read from here as DATA only — no repo source code is imported/compiled.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TRUTH_OPERATOR="$REPO_ROOT/crates/vaid-client/tests/vectors/operator_pop_v1.json"
TRUTH_MINT="$REPO_ROOT/crates/vaid-mint/tests/vectors/mint_v1.json"
TRUTH_PATHQUERY="$REPO_ROOT/crates/vaid-client/tests/vectors/pathquery_v1.json"
TRUTH_COMPLETION="$REPO_ROOT/crates/vaid-pop/tests/vectors/completion_v1.json"

for f in "$TRUTH_OPERATOR" "$TRUTH_MINT" "$TRUTH_PATHQUERY" "$TRUTH_COMPLETION"; do
  [ -f "$f" ] || { echo "FATAL: truth vector missing: $f"; exit 2; }
done

WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

FAILURES=()
note_fail() { FAILURES+=("$1"); echo "  ✗ FAIL: $1"; }

echo "=================================================================="
echo " post-publish smoke test — registry artifacts vs frozen vectors"
echo "   PyPI:      vaid-pop==$VAID_POP_VER  vaid-mint==$VAID_MINT_VER  vaid-langchain==$VAID_LANGCHAIN_VER"
echo "   crates.io: vaid-pop==$VAID_POP_VER  vaid-client==$VAID_CLIENT_VER  vaid-mint==$VAID_MINT_VER"
echo "   scratch dir: $WORK"
echo "=================================================================="

# ─────────────────────────────── PYTHON ───────────────────────────────
echo
echo "### PYTHON (fresh venv, PyPI installs) ###"
if ! python3 -m venv "$WORK/venv"; then
  note_fail "python:venv-create"
else
  PIP="$WORK/venv/bin/pip"
  PY="$WORK/venv/bin/python"
  "$PIP" install --quiet --upgrade pip >/dev/null 2>&1
  if ! "$PIP" install --quiet \
        "vaid-pop==$VAID_POP_VER" \
        "vaid-mint==$VAID_MINT_VER" \
        "vaid-langchain[langchain]==$VAID_LANGCHAIN_VER"; then
    note_fail "python:pip-install (are all three on PyPI at these versions?)"
  else
    # Show what actually got installed (proves it came from the registry).
    "$PIP" show vaid-pop vaid-mint vaid-langchain 2>/dev/null \
      | grep -E "^(Name|Version|Location):" | sed 's/^/    /'

    TRUTH_OPERATOR="$TRUTH_OPERATOR" \
    TRUTH_MINT="$TRUTH_MINT" \
    TRUTH_PATHQUERY="$TRUTH_PATHQUERY" \
    TRUTH_COMPLETION="$TRUTH_COMPLETION" \
    "$PY" - <<'PYEOF'
import json, os, sys
from importlib.resources import files

failures = []

def load(path):
    with open(path) as fh:
        return json.load(fh)

def installed_vector(pkg, name):
    return json.loads(files(pkg).joinpath(f"vectors/{name}").read_text())

def same_bytes(installed_pkg, installed_name, truth_path, label):
    """The wheel's vendored vector must byte-match the repo's frozen truth."""
    inst_txt = files(installed_pkg).joinpath(f"vectors/{installed_name}").read_text()
    with open(truth_path) as fh:
        truth_txt = fh.read()
    if inst_txt != truth_txt:
        failures.append(f"{label}: installed wheel vector != frozen truth (published wrong bytes)")
        return False
    return True

# ---- vaid-pop: operator + completion, via the installed packaged firewall ----
try:
    import vaid_pop.conformance as vpc
    # (a) installed vectors byte-match truth
    same_bytes("vaid_pop", "operator_pop_v1.json", os.environ["TRUTH_OPERATOR"], "vaid-pop/operator")
    same_bytes("vaid_pop", "completion_v1.json", os.environ["TRUTH_COMPLETION"], "vaid-pop/completion")
    # (b) installed code reproduces them
    vpc.check_digest(vpc.load_vector())
    vpc.check_signature(vpc.load_vector())
    vpc.check_request_signer(vpc.load_vector())
    vpc.check_completion(vpc.load_completion_vector())
    print("    ✓ vaid-pop: operator_pop_v1 + completion_v1 reproduced")
except Exception as e:
    failures.append(f"vaid-pop: {e}")
    print(f"    ✗ vaid-pop: {e}")

# ---- vaid-mint: mint_v1, via the installed packaged firewall ----
try:
    import vaid_mint.conformance as vmc
    same_bytes("vaid_mint", "mint_v1.json", os.environ["TRUTH_MINT"], "vaid-mint/mint")
    vmc.run()  # digest + kernel signature + lineage + vaid_id==agent_id
    print("    ✓ vaid-mint: mint_v1 reproduced")
except Exception as e:
    failures.append(f"vaid-mint: {e}")
    print(f"    ✗ vaid-mint: {e}")

# ---- vaid-langchain: pathquery_v1. No packaged firewall of its own, so reuse
#      the installed vaid-pop conformance logic on the installed pathquery vector
#      (it is a RequestAuthPayload vector, same shape as operator). ----
try:
    import vaid_pop.conformance as vpc
    same_bytes("vaid_langchain", "pathquery_v1.json", os.environ["TRUTH_PATHQUERY"], "vaid-langchain/pathquery")
    pq = installed_vector("vaid_langchain", "pathquery_v1.json")
    assert "?" in pq["input"]["path"], "pathquery vector must carry a query string"
    vpc.check_digest(pq)
    vpc.check_signature(pq)
    print("    ✓ vaid-langchain: pathquery_v1 reproduced")
except Exception as e:
    failures.append(f"vaid-langchain: {e}")
    print(f"    ✗ vaid-langchain: {e}")

if failures:
    print("PYTHON FAILURES:")
    for f in failures:
        print("   -", f)
    sys.exit(1)
print("    PYTHON: all registry-installed vectors reproduced.")
PYEOF
    [ $? -eq 0 ] || note_fail "python:conformance"
  fi
fi

# ──────────────────────────────── RUST ────────────────────────────────
echo
echo "### RUST (fresh scratch project, crates.io installs) ###"
PROJ="$WORK/rust_smoke"
mkdir -p "$PROJ/src"

cat > "$PROJ/Cargo.toml" <<EOF
[package]
name = "vaid_post_publish_smoke"
version = "0.0.0"
edition = "2021"
publish = false

# Empty [workspace] table so this scratch project is its OWN workspace root and
# is never absorbed into a parent workspace (isolation from the repo).
[workspace]

[dependencies]
vaid-pop = "=$VAID_POP_VER"
vaid-client = "=$VAID_CLIENT_VER"
vaid-mint = "=$VAID_MINT_VER"
serde_json = "1"
ring = "0.17"
chrono = { version = "0.4", features = ["serde"] }
base64 = "0.22"
EOF

cat > "$PROJ/src/main.rs" <<'RSEOF'
// Reproduces the four frozen vectors using ONLY the registry-installed crates'
// public APIs. Vector file paths are passed as argv (the repo's frozen truth);
// no repo source is compiled. Prints per-vector PASS/FAIL, exits 1 on any miss.
use std::fs;
use base64::Engine as _;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::Value;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn load(p: &str) -> Value {
    serde_json::from_str(&fs::read_to_string(p).expect("read vector")).expect("parse vector")
}

// operator_pop_v1 / pathquery_v1: a RequestAuthPayload vector. Exercises
// vaid-client's RequestSigner (which uses vaid-pop internally) + vaid-pop's digest.
fn check_request_vector(v: &Value, label: &str) -> Result<(), String> {
    use vaid_client::RequestSigner;
    use vaid_pop::request_auth::RequestAuthPayload;
    use vaid_pop::vaid_pop::canonical_request_signing_bytes;

    let payload: RequestAuthPayload =
        serde_json::from_value(v["input"].clone()).map_err(|e| format!("{label}: input: {e}"))?;
    let digest = canonical_request_signing_bytes(&payload);
    if hexs(&digest) != v["digest_sha256_hex"].as_str().unwrap() {
        return Err(format!("{label}: digest mismatch"));
    }
    let seed = unhex(v["ed25519"]["private_key_seed_hex"].as_str().unwrap());
    let kp = Ed25519KeyPair::from_seed_unchecked(&seed).map_err(|e| format!("{label}: seed: {e}"))?;
    let vaid_json = format!(
        r#"{{"vaid_id":"{}","tenant_id":"{}"}}"#,
        v["input"]["vaidId"].as_str().unwrap(),
        v["input"]["tenantId"].as_str().unwrap()
    );
    let signer = RequestSigner::from_vaid_json(vaid_json.as_bytes(), kp)
        .map_err(|e| format!("{label}: signer: {e}"))?;
    let now = chrono::DateTime::parse_from_rfc3339(v["input"]["timestamp"].as_str().unwrap())
        .unwrap()
        .with_timezone(&chrono::Utc);
    let headers = signer
        .sign_headers_at(
            v["input"]["method"].as_str().unwrap(),
            v["input"]["path"].as_str().unwrap(),
            b"",
            now,
            v["input"]["clientNonce"].as_str().unwrap(),
        )
        .map_err(|e| format!("{label}: sign: {e}"))?;
    let sig = base64::engine::general_purpose::STANDARD
        .decode(headers.signature.as_bytes())
        .unwrap();
    if hexs(&sig) != v["ed25519"]["signature_hex"].as_str().unwrap() {
        return Err(format!("{label}: signature mismatch"));
    }
    Ok(())
}

// mint_v1: a VAID document vector. Exercises vaid-mint's canonical_vaid_signing_bytes.
fn check_mint_vector(v: &Value) -> Result<(), String> {
    use vaid_mint::{canonical_vaid_signing_bytes, Vaid};
    let vaid: Vaid =
        serde_json::from_value(v["input"].clone()).map_err(|e| format!("mint: input: {e}"))?;
    let digest = canonical_vaid_signing_bytes(&vaid);
    if hexs(&digest) != v["digest_sha256_hex"].as_str().unwrap() {
        return Err("mint: digest mismatch".into());
    }
    let seed = unhex(v["ed25519"]["kernel_private_key_seed_hex"].as_str().unwrap());
    let kp = Ed25519KeyPair::from_seed_unchecked(&seed).map_err(|e| format!("mint: seed: {e}"))?;
    let sig = kp.sign(&digest);
    if hexs(sig.as_ref()) != v["ed25519"]["signature_hex"].as_str().unwrap() {
        return Err("mint: signature mismatch".into());
    }
    Ok(())
}

// completion_v1: a CompletionRecord vector. Exercises vaid-pop's CompletionRecord.
fn check_completion_vector(v: &Value) -> Result<(), String> {
    use vaid_pop::vaid_pop::canonical_request_signing_bytes;
    use vaid_pop::CompletionRecord;
    let rec: CompletionRecord =
        serde_json::from_value(v["input"].clone()).map_err(|e| format!("completion: input: {e}"))?;
    let digest = canonical_request_signing_bytes(&rec);
    if hexs(&digest) != v["digest_sha256_hex"].as_str().unwrap() {
        return Err("completion: digest mismatch".into());
    }
    let seed = unhex(v["ed25519"]["private_key_seed_hex"].as_str().unwrap());
    let kp = Ed25519KeyPair::from_seed_unchecked(&seed).map_err(|e| format!("completion: seed: {e}"))?;
    let sig = kp.sign(&digest);
    if hexs(sig.as_ref()) != v["ed25519"]["signature_hex"].as_str().unwrap() {
        return Err("completion: signature mismatch".into());
    }
    Ok(())
}

fn main() {
    // argv: operator_path mint_path pathquery_path completion_path
    let a: Vec<String> = std::env::args().collect();
    if a.len() != 5 {
        eprintln!("usage: {} <operator> <mint> <pathquery> <completion>", a[0]);
        std::process::exit(2);
    }
    let checks: Vec<Result<(), String>> = vec![
        check_request_vector(&load(&a[1]), "operator_pop_v1"),
        check_request_vector(&load(&a[3]), "pathquery_v1"),
        check_mint_vector(&load(&a[2])),
        check_completion_vector(&load(&a[4])),
    ];
    let mut failed = false;
    for c in checks {
        match c {
            Ok(()) => {}
            Err(e) => {
                failed = true;
                println!("    ✗ RUST {e}");
            }
        }
    }
    if failed {
        std::process::exit(1);
    }
    println!("    ✓ RUST: operator_pop_v1 + pathquery_v1 + mint_v1 + completion_v1 reproduced");
}
RSEOF

if ! ( cd "$PROJ" && cargo run --quiet -- \
        "$TRUTH_OPERATOR" "$TRUTH_MINT" "$TRUTH_PATHQUERY" "$TRUTH_COMPLETION" ); then
  note_fail "rust:conformance (build or vector reproduction failed)"
fi

# ─────────────────────────────── VERDICT ──────────────────────────────
echo
echo "=================================================================="
if [ ${#FAILURES[@]} -eq 0 ]; then
  echo " SMOKE TEST PASSED — published artifacts reproduce all four frozen vectors."
  echo "=================================================================="
  exit 0
else
  echo " SMOKE TEST FAILED — ${#FAILURES[@]} problem(s):"
  for f in "${FAILURES[@]}"; do echo "   - $f"; done
  echo "=================================================================="
  exit 1
fi
