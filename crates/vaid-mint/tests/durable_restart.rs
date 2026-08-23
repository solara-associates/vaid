//! **The test is a restart, not a 200** — spec `docs/spec/revocation.md` R.4.6.
//!
//! Every existing revocation test in this repository writes and reads back inside
//! one process. `clear_lineage()` *models* a restart; it does not perform one, and
//! a model of a restart cannot catch a store that silently fails to persist. This
//! file spawns real child processes. Nothing crosses between them except bytes on
//! disk: the kernel seed, the lineage map, and the revoked set.
//!
//! ```text
//!   parent test  ──spawn──▶  PHASE 1 (process 2)   mint root A, child B of A,
//!        │                                          root C; revoke C; exit
//!        └───────spawn──▶  PHASE 2 (process 3)   fresh issuer from the seed,
//!                                                 fresh stores from the files
//! ```
//!
//! ## What durability actually has to be, and why one store is not enough
//!
//! R.4.6 durability is **two** stores — the revoked set and the lineage resolver —
//! and persisting exactly one is not a partial win. The two mutation tests below
//! measure both halves of that, and they land on opposite failures:
//!
//! | Persisted | Child credential (B) | Revoked root (C) |
//! |---|---|---|
//! | both (honest) | verifies | refused |
//! | lineage only | verifies | **verifies — the revocation is gone** |
//! | revoked set only | **Unavailable — outage** | refused |
//!
//! So half-done in one direction is a security hole and half-done in the other is
//! an outage that hits *every delegated credential and no root one*, at restart
//! rather than at deploy. Both are asserted here, positively, against real
//! processes — not asserted as "the test goes red", which proves only that an
//! assertion exists.
//!
//! ## What this file is not
//!
//! Not a conformance vector. Revocation is outside the conformance surface (R.1)
//! and this file must never become one.
//!
//! Not a durable backend. Durable hash-chained revocation is deliberately not in
//! the open crate. `FileRevocationList` and `FileLineageStore` below are **test
//! doubles**: JSON files, no locking, no integrity, no concurrency story. They
//! exist to prove the *seam* can carry a durable implementation across a restart,
//! which is the property the crate owes and the only property they demonstrate.

use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use vaid_mint::document::{AgentClass, TenantId, Vaid, VaidId};
use vaid_mint::issuer::{ReferenceIssuer, VaidIssuer};
use vaid_mint::revocation::{
    InMemoryLineageStore, LineageResolver, LineageStore, ParentResolution, RevocationBackend,
    RevocationCheck, RevocationStatus,
};
use vaid_mint::verify::verify_vaid_authenticity;

const PHASE_ENV: &str = "VAID_RESTART_PHASE";
const DIR_ENV: &str = "VAID_RESTART_DIR";
const BREAK_ENV: &str = "VAID_RESTART_BREAK";

// ─────────────────────────────────────────────────────────────────────────────
// The durable test doubles. Two files, because R.4.6 is two stores.
// ─────────────────────────────────────────────────────────────────────────────

/// File-backed revoked set. **A missing file is `Unavailable`, never an empty
/// vouching set** — that distinction is the whole of R.4.6, and getting it wrong
/// is what `mutation_two` below re-creates on purpose.
struct FileRevocationList {
    path: PathBuf,
    /// When true, a missing/unreadable file is treated as "nothing is revoked"
    /// instead of as absent state. This is the `assume_nothing_revoked` mistake
    /// transplanted into a durable store, and it is only ever set by the mutation
    /// test.
    vouch_when_absent: bool,
}

impl FileRevocationList {
    fn new(dir: &Path) -> Self {
        Self {
            path: dir.join("revoked.json"),
            vouch_when_absent: false,
        }
    }

    fn vouching_when_absent(dir: &Path) -> Self {
        Self {
            path: dir.join("revoked.json"),
            vouch_when_absent: true,
        }
    }

    fn load(&self) -> Option<Vec<VaidId>> {
        let text = fs::read_to_string(&self.path).ok()?;
        serde_json::from_str(&text).ok()
    }

    fn revoke(&self, id: VaidId) {
        let mut ids = self.load().unwrap_or_default();
        ids.push(id);
        fs::write(&self.path, serde_json::to_string(&ids).unwrap()).expect("write revoked.json");
    }
}

impl RevocationCheck for FileRevocationList {
    fn check_lineage(&self, lineage: &[VaidId]) -> RevocationStatus {
        match self.load() {
            Some(revoked) => {
                if lineage.iter().any(|id| revoked.contains(id)) {
                    RevocationStatus::Revoked
                } else {
                    RevocationStatus::NotRevoked
                }
            }
            // No file: this store has never been populated in this deployment. It
            // cannot vouch for anything and says so (R.4.6).
            None if !self.vouch_when_absent => RevocationStatus::Unavailable,
            None => RevocationStatus::NotRevoked,
        }
    }
}

/// File-backed lineage store — the half that had no injection point before this
/// change, and therefore the half a self-hoster could not make durable at all.
///
/// Records roots as `None`. A store that omitted roots would answer `Unknown` for
/// every root and turn the entire deployment `Unavailable`; recording them is what
/// keeps `Root` distinguishable from `Unknown` (R.4.2).
struct FileLineageStore {
    path: PathBuf,
}

impl FileLineageStore {
    fn new(dir: &Path) -> Self {
        Self {
            path: dir.join("lineage.json"),
        }
    }

    fn load(&self) -> Option<Vec<(VaidId, Option<VaidId>)>> {
        let text = fs::read_to_string(&self.path).ok()?;
        serde_json::from_str(&text).ok()
    }
}

impl LineageResolver for FileLineageStore {
    fn resolve_parent(&self, vaid_id: &VaidId) -> ParentResolution {
        let entries = match self.load() {
            Some(e) => e,
            // No file: nothing is known, so nothing is a root. `Unknown` (→
            // `Unavailable`) is the only honest answer; `Root` here would be the
            // exact masquerade R.4.2 exists to forbid.
            None => return ParentResolution::Unknown,
        };
        match entries.into_iter().find(|(id, _)| id == vaid_id) {
            Some((_, Some(parent))) => ParentResolution::Parent(parent),
            Some((_, None)) => ParentResolution::Root,
            None => ParentResolution::Unknown,
        }
    }
}

impl LineageStore for FileLineageStore {
    fn record(&self, vaid_id: VaidId, parent: Option<VaidId>) {
        let mut entries = self.load().unwrap_or_default();
        entries.retain(|(id, _)| *id != vaid_id);
        entries.push((vaid_id, parent));
        fs::write(&self.path, serde_json::to_string(&entries).unwrap()).expect("write lineage.json");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phases. Each runs in its own process; the only channel between them is `dir`.
// ─────────────────────────────────────────────────────────────────────────────

fn issuer_for(dir: &Path, seed: &[u8], break_mode: &str) -> ReferenceIssuer {
    let check: Arc<dyn RevocationCheck> = if break_mode == "revocation-vouches-when-absent" {
        Arc::new(FileRevocationList::vouching_when_absent(dir))
    } else {
        Arc::new(FileRevocationList::new(dir))
    };
    // BREAK "lineage": the deployment persisted the revoked set and left the
    // resolver in memory — the half-configuration this whole seam exists to make
    // unreachable by omission. Reached here only by naming it.
    let lineage: Arc<dyn LineageStore> = if break_mode == "lineage" {
        Arc::new(InMemoryLineageStore::new())
    } else {
        Arc::new(FileLineageStore::new(dir))
    };
    ReferenceIssuer::from_seed(seed, 24, "vaid.example")
        .expect("issuer from persisted seed")
        .with_revocation_backend(RevocationBackend::new(check, lineage))
}

fn mint(issuer: &ReferenceIssuer, class: &str, parent: Option<VaidId>) -> Vaid {
    issuer
        .issue_vaid_with_lineage(
            AgentClass::new(class),
            "1.0.0".into(),
            TenantId::new("restart-tenant"),
            parent,
            vec![],
            vec![],
        )
        .expect("mint")
}

/// PHASE 1 — mint into the durable stores, revoke one, then exit. Everything this
/// process learned is now either on disk or gone.
fn phase_mint(dir: &Path, break_mode: &str) {
    fs::create_dir_all(dir).expect("state dir");
    // The kernel key is persisted too. Without it nothing would verify after the
    // restart for a reason that has nothing to do with revocation, and the test
    // would pass for the wrong reason in the mutation runs.
    let seed: Vec<u8> = (0u8..32).collect();
    fs::write(dir.join("seed.bin"), &seed).expect("write seed");

    let issuer = issuer_for(dir, &seed, break_mode);
    let root_a = mint(&issuer, "root-a", None);
    let child_b = mint(&issuer, "child-b", Some(root_a.vaid_id()));
    let root_c = mint(&issuer, "root-c", None);

    // Revoke through the durable store, which is what a real deployment does —
    // `ReferenceIssuer::revoke` writes to the *built-in* store, which is not the
    // one consulted once a backend is injected.
    FileRevocationList::new(dir).revoke(root_c.vaid_id());

    for (name, vaid) in [("root_a", &root_a), ("child_b", &child_b), ("root_c", &root_c)] {
        fs::write(
            dir.join(format!("{name}.json")),
            serde_json::to_string(vaid).unwrap(),
        )
        .expect("write vaid");
    }
}

/// PHASE 2 — a genuinely new process. Rebuild the issuer from the seed and the
/// stores from the files, and report what the restarted deployment believes.
fn phase_verify(dir: &Path, break_mode: &str) -> Observations {
    let seed = fs::read(dir.join("seed.bin")).expect("read seed");
    let issuer = issuer_for(dir, &seed, break_mode);
    let load = |name: &str| -> Vaid {
        serde_json::from_str(&fs::read_to_string(dir.join(format!("{name}.json"))).unwrap()).unwrap()
    };
    let child_b = load("child_b");
    let root_c = load("root_c");

    Observations {
        child_authentic: verify_vaid_authenticity(issuer.kernel_public_key(), &child_b),
        child_status: format!("{:?}", issuer.revocation_status(&child_b)),
        child_verifies: issuer.verify_vaid(&child_b),
        revoked_root_status: format!("{:?}", issuer.revocation_status(&root_c)),
        revoked_root_verifies: issuer.verify_vaid(&root_c),
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct Observations {
    /// Deliberately reported alongside the rest: the misdiagnosis this failure
    /// invites is "a signing or clock problem", and the only way to retire that
    /// guess is to show authenticity passing while standing fails.
    child_authentic: bool,
    child_status: String,
    child_verifies: bool,
    revoked_root_status: String,
    revoked_root_verifies: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// The orchestrator. `cargo test` runs this; the phases run as its children.
// ─────────────────────────────────────────────────────────────────────────────

/// Run one phase in a **new process** by re-executing this test binary with the
/// hidden `restart_phase_child` test selected. `current_exe()` is the compiled
/// test binary, so the child is the same code with none of the parent's memory.
fn spawn_phase(phase: &str, dir: &Path, break_mode: &str) -> String {
    let out = Command::new(env::current_exe().expect("test binary path"))
        .args(["restart_phase_child", "--exact", "--ignored", "--nocapture"])
        .env(PHASE_ENV, phase)
        .env(DIR_ENV, dir)
        .env(BREAK_ENV, break_mode)
        .output()
        .expect("spawn phase");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        out.status.success(),
        "phase {phase} (break={break_mode}) failed\n--- stdout ---\n{stdout}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    stdout
}

/// The child entry point. `#[ignore]` keeps it out of a normal `cargo test` run;
/// it is reached only through [`spawn_phase`], which passes `--ignored`.
#[test]
#[ignore = "child process entry point; driven by spawn_phase, not run directly"]
fn restart_phase_child() {
    let Ok(phase) = env::var(PHASE_ENV) else {
        // Someone ran the whole suite with --ignored. Nothing to do, and nothing
        // to fail: a missing phase means this is not a spawned child.
        return;
    };
    let dir = PathBuf::from(env::var(DIR_ENV).expect("state dir"));
    let break_mode = env::var(BREAK_ENV).unwrap_or_default();
    match phase.as_str() {
        "mint" => phase_mint(&dir, &break_mode),
        "verify" => {
            let obs = phase_verify(&dir, &break_mode);
            println!("OBSERVATIONS {}", serde_json::to_string(&obs).unwrap());
        }
        other => panic!("unknown phase {other}"),
    }
}

fn observations_from(stdout: &str) -> Observations {
    let line = stdout
        .lines()
        .find(|l| l.starts_with("OBSERVATIONS "))
        .unwrap_or_else(|| panic!("no OBSERVATIONS line in child output:\n{stdout}"));
    serde_json::from_str(line.trim_start_matches("OBSERVATIONS ")).expect("parse observations")
}

fn state_dir(name: &str) -> PathBuf {
    // `name` keeps the tests in this binary — which cargo runs in parallel threads
    // of ONE process — from sharing a state directory.
    let dir = env::temp_dir().join(format!("vaid-restart-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    dir
}

/// Run the two phases as separate processes and return what phase 2 saw.
fn restart_cycle(name: &str, mint_break: &str, verify_break: &str) -> Observations {
    let dir = state_dir(name);
    spawn_phase("mint", &dir, mint_break);
    let out = spawn_phase("verify", &dir, verify_break);
    let obs = observations_from(&out);
    let _ = fs::remove_dir_all(&dir);
    obs
}

/// THE TEST. Both stores durable, a real process restart between minting and
/// verifying: the child credential still resolves and the revoked one is still
/// refused.
#[test]
fn both_stores_durable_survive_a_real_process_restart() {
    let obs = restart_cycle("honest", "", "");
    assert_eq!(
        obs,
        Observations {
            child_authentic: true,
            child_status: "NotRevoked".into(),
            child_verifies: true,
            revoked_root_status: "Revoked".into(),
            revoked_root_verifies: false,
        },
        "with both halves durable, a restart must change nothing: the child's \
         ancestry still resolves through the persisted lineage store, and the \
         revocation recorded before the restart is still in force"
    );
}

/// NON-VACUITY 1 — persist the revoked set, leave the resolver in memory.
///
/// This test is also the proof that the harness performs a **real restart**. It
/// can only pass if the in-memory lineage store phase 2 builds is empty, and it
/// can only be empty if phase 2 did not inherit phase 1's memory. Were both
/// phases one process, the child would resolve and this test would go red.
///
/// The outage half. Every child credential goes `Unavailable`; every root keeps
/// working, because a root is trivially complete under R.4.2 and never touches
/// the resolver. Authenticity still passes, which is the assertion that retires
/// the "it must be a signing or clock problem" diagnosis.
#[test]
fn mutation_one_lineage_not_persisted_breaks_every_child_and_no_root() {
    let obs = restart_cycle("break-lineage", "", "lineage");
    assert_eq!(
        obs,
        Observations {
            // Not a signature problem. Not a clock problem.
            child_authentic: true,
            child_status: "Unavailable".into(),
            child_verifies: false,
            // The revoked root is unaffected — it needs no resolution.
            revoked_root_status: "Revoked".into(),
            revoked_root_verifies: false,
        },
        "a durable revoked set with an in-memory resolver must fail closed for \
         every child and leave every root untouched — total for delegated \
         credentials, invisible for root ones"
    );
}

/// NON-VACUITY 2 — persist the lineage, let the revoked set vouch when absent.
///
/// The security half, and the reason `assume_nothing_revoked` must never be the
/// shape a durable store copies: the revocation recorded before the restart is
/// gone, and the revoked credential verifies clean with no indication anything is
/// wrong.
#[test]
fn mutation_two_revoked_set_vouching_when_absent_resurrects_a_revoked_vaid() {
    let dir = state_dir("break-revocation");
    // Phase 1 mints and writes lineage.json, but its revoked.json is removed
    // before the restart — modelling a deployment that persisted one store and
    // not the other.
    spawn_phase("mint", &dir, "");
    fs::remove_file(dir.join("revoked.json")).expect("drop the revoked set");
    let obs = observations_from(&spawn_phase("verify", &dir, "revocation-vouches-when-absent"));
    let _ = fs::remove_dir_all(&dir);
    assert_eq!(
        obs,
        Observations {
            child_authentic: true,
            child_status: "NotRevoked".into(),
            child_verifies: true,
            // The revocation is simply gone, and nothing says so.
            revoked_root_status: "NotRevoked".into(),
            revoked_root_verifies: true,
        },
        "a store that vouches when its state is absent silently un-revokes \
         everything revoked before the restart — R.4.6 exists to forbid exactly \
         this, and an honest store answers Unavailable instead"
    );
}

/// The same absent revoked set, read by a store that reports absence honestly:
/// `Unavailable`, fails closed. This is the control for the mutation above — the
/// two runs differ in nothing but the store's answer to a missing file.
#[test]
fn an_honest_store_reports_an_absent_revoked_set_as_unavailable() {
    let dir = state_dir("absent-honest");
    spawn_phase("mint", &dir, "");
    fs::remove_file(dir.join("revoked.json")).expect("drop the revoked set");
    let obs = observations_from(&spawn_phase("verify", &dir, ""));
    let _ = fs::remove_dir_all(&dir);
    assert_eq!(obs.revoked_root_status, "Unavailable");
    assert!(!obs.revoked_root_verifies);
    assert_eq!(obs.child_status, "Unavailable");
    assert!(obs.child_authentic, "still authentic — only standing failed");
}

/// The paired backend records into the injected store rather than the built-in
/// one. Without a write half (`LineageStore::record`) a durable resolver would be
/// injectable and permanently empty, which is the failure above with extra steps.
#[test]
fn mints_are_recorded_into_the_injected_lineage_store() {
    let dir = state_dir("records");
    fs::create_dir_all(&dir).unwrap();
    let seed: Vec<u8> = (0u8..32).collect();
    let issuer = issuer_for(&dir, &seed, "");
    let root = mint(&issuer, "root", None);
    let child = mint(&issuer, "child", Some(root.vaid_id()));

    let store = FileLineageStore::new(&dir);
    let recorded: HashMap<VaidId, Option<VaidId>> = store.load().unwrap().into_iter().collect();
    assert_eq!(
        recorded.get(&root.vaid_id()),
        Some(&None),
        "a root must be recorded as a KNOWN root, not omitted"
    );
    assert_eq!(recorded.get(&child.vaid_id()), Some(&Some(root.vaid_id())));
    let _ = fs::remove_dir_all(&dir);
}
