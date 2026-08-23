"""**The test is a restart, not a 200** — spec ``docs/spec/revocation.md`` R.4.6.

Every other revocation test in this package writes and reads back inside one
process. ``clear_lineage()`` *models* a restart; it does not perform one, and a
model of a restart cannot catch a store that silently fails to persist. This file
spawns real child interpreters. Nothing crosses between them except bytes on
disk: the kernel seed, the lineage map, and the revoked set.

Mirror of ``crates/vaid-mint/tests/durable_restart.rs`` — same phases, same
observations, same two mutations. There is deliberately no shared vector:
revocation is outside the conformance surface (R.1), and the languages agree by
construction rather than by a frozen artifact.

What durability actually has to be, and why one store is not enough:

============  ======================  =============================
Persisted     Child credential (B)    Revoked root (C)
============  ======================  =============================
both          verifies                refused
lineage only  verifies                **verifies — revocation gone**
revoked only  **UNAVAILABLE — outage**  refused
============  ======================  =============================

Half-done in one direction is a security hole and half-done in the other is an
outage that hits *every delegated credential and no root one*, at restart rather
than at deploy. Both are asserted positively against real processes — not as "the
test goes red", which proves only that an assertion exists.

``FileRevocationList`` and ``FileLineageStore`` are **test doubles**: JSON files,
no locking, no integrity, no concurrency story. Durable hash-chained revocation is
deliberately not in the open package. They exist to prove the *seam* can carry a
durable implementation across a restart, which is the only property they show.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from vaid_mint import (
    InMemoryLineageStore,
    ReferenceIssuer,
    RevocationBackend,
    RevocationStatus,
    verify_vaid_authenticity,
)
from vaid_mint.revocation import ParentResolution

# A fixed 32-byte kernel seed, persisted with the state so the restarted issuer
# signs and verifies with the same key. Without it nothing would verify after the
# restart for a reason that has nothing to do with revocation, and the mutation
# runs would pass for the wrong reason.
SEED = bytes(range(32))


# ── the durable test doubles: two files, because R.4.6 is two stores ──


class FileRevocationList:
    """File-backed revoked set. **A missing file is UNAVAILABLE, never an empty
    vouching set** — that distinction is the whole of R.4.6, and getting it wrong
    is what mutation two re-creates on purpose."""

    def __init__(self, directory: Path, *, vouch_when_absent: bool = False) -> None:
        self.path = directory / "revoked.json"
        self.vouch_when_absent = vouch_when_absent

    def _load(self) -> list[str] | None:
        try:
            return json.loads(self.path.read_text())
        except (OSError, ValueError):
            return None

    def revoke(self, vaid_id: str) -> None:
        ids = self._load() or []
        ids.append(vaid_id)
        self.path.write_text(json.dumps(ids))

    def check_lineage(self, lineage: list[str]) -> RevocationStatus:
        revoked = self._load()
        if revoked is None:
            # No file: this store has never been populated in this deployment. It
            # cannot vouch for anything and says so (R.4.6).
            return (
                RevocationStatus.NOT_REVOKED
                if self.vouch_when_absent
                else RevocationStatus.UNAVAILABLE
            )
        if any(vaid_id in revoked for vaid_id in lineage):
            return RevocationStatus.REVOKED
        return RevocationStatus.NOT_REVOKED


class FileLineageStore:
    """File-backed lineage store — the half that had no injection point before
    this change, and therefore the half a self-hoster could not make durable.

    Records roots as ``None``. A store that omitted roots would answer *unknown*
    for every root and turn the entire deployment UNAVAILABLE; recording them is
    what keeps *root* distinguishable from *unknown* (R.4.2)."""

    def __init__(self, directory: Path) -> None:
        self.path = directory / "lineage.json"

    def _load(self) -> dict[str, str | None] | None:
        try:
            return json.loads(self.path.read_text())
        except (OSError, ValueError):
            return None

    def record(self, vaid_id: str, parent: str | None) -> None:
        entries = self._load() or {}
        entries[vaid_id] = parent
        self.path.write_text(json.dumps(entries))

    def resolve_parent(self, vaid_id: str) -> ParentResolution:
        entries = self._load()
        if entries is None or vaid_id not in entries:
            # Nothing is known, so nothing is a root. *unknown* (→ UNAVAILABLE) is
            # the only honest answer; *root* here would be the exact masquerade
            # R.4.2 exists to forbid.
            return ParentResolution.unknown()
        parent = entries[vaid_id]
        return ParentResolution.root() if parent is None else ParentResolution.of_parent(parent)


# ── phases; each runs in its own interpreter, sharing only ``directory`` ──


def issuer_for(directory: Path, break_mode: str) -> ReferenceIssuer:
    check = FileRevocationList(
        directory, vouch_when_absent=(break_mode == "revocation-vouches-when-absent")
    )
    # BREAK "lineage": the deployment persisted the revoked set and left the
    # resolver in memory — the half-configuration this seam exists to make
    # unreachable by omission. Reached here only by naming it.
    lineage = InMemoryLineageStore() if break_mode == "lineage" else FileLineageStore(directory)
    return ReferenceIssuer.from_seed(SEED, 24, "vaid.example").with_revocation_backend(
        RevocationBackend(check=check, lineage=lineage)
    )


def _mint(issuer: ReferenceIssuer, agent_class: str, parent: str | None) -> dict:
    return issuer.issue_vaid_with_lineage(
        agent_class=agent_class,
        version="1.0.0",
        tenant_id="restart-tenant",
        parent_vaid=parent,
        scope_boundary=[],
        capability_set=[],
    )


def phase_mint(directory: Path, break_mode: str) -> None:
    """PHASE 1 — mint into the durable stores, revoke one, exit. Everything this
    process learned is now either on disk or gone."""
    directory.mkdir(parents=True, exist_ok=True)
    issuer = issuer_for(directory, break_mode)
    root_a = _mint(issuer, "root-a", None)
    child_b = _mint(issuer, "child-b", root_a["vaid_id"])
    root_c = _mint(issuer, "root-c", None)

    # Revoke through the durable store, which is what a real deployment does —
    # ``ReferenceIssuer.revoke`` writes to the *built-in* store, which is not the
    # one consulted once a backend is injected.
    FileRevocationList(directory).revoke(root_c["vaid_id"])

    for name, vaid in (("root_a", root_a), ("child_b", child_b), ("root_c", root_c)):
        (directory / f"{name}.json").write_text(json.dumps(vaid))


def phase_verify(directory: Path, break_mode: str) -> dict:
    """PHASE 2 — a genuinely new interpreter. Rebuild the issuer from the seed and
    the stores from the files, and report what the restarted deployment believes."""
    issuer = issuer_for(directory, break_mode)
    child_b = json.loads((directory / "child_b.json").read_text())
    root_c = json.loads((directory / "root_c.json").read_text())
    return {
        # Reported alongside the rest deliberately: the misdiagnosis this failure
        # invites is "a signing or clock problem", and the only way to retire that
        # guess is to show authenticity passing while standing fails.
        "child_authentic": verify_vaid_authenticity(issuer.kernel_public_key(), child_b),
        "child_status": issuer.revocation_status(child_b).value,
        "child_verifies": issuer.verify_vaid(child_b),
        "revoked_root_status": issuer.revocation_status(root_c).value,
        "revoked_root_verifies": issuer.verify_vaid(root_c),
    }


# ── the orchestrator: pytest runs this, the phases run as its children ──


def spawn_phase(phase: str, directory: Path, break_mode: str = "") -> str:
    """Run one phase in a **new interpreter**. ``-c`` re-imports this module by
    path, so the child is the same code with none of the parent's memory."""
    script = (
        "import json,sys;"
        f"sys.path.insert(0, {str(Path(__file__).parent)!r});"
        "import test_durable_restart as m;"
        "from pathlib import Path;"
        f"d=Path({str(directory)!r});"
        f"phase={phase!r};brk={break_mode!r};"
        "print('OBSERVATIONS ' + json.dumps(m.phase_verify(d, brk)))"
        " if phase == 'verify' else m.phase_mint(d, brk)"
    )
    proc = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    assert proc.returncode == 0, (
        f"phase {phase} (break={break_mode}) failed\n"
        f"--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}"
    )
    return proc.stdout


def observations_from(stdout: str) -> dict:
    for line in stdout.splitlines():
        if line.startswith("OBSERVATIONS "):
            return json.loads(line[len("OBSERVATIONS ") :])
    raise AssertionError(f"no OBSERVATIONS line in child output:\n{stdout}")


def restart_cycle(directory: Path, mint_break: str = "", verify_break: str = "") -> dict:
    spawn_phase("mint", directory, mint_break)
    return observations_from(spawn_phase("verify", directory, verify_break))


HONEST = {
    "child_authentic": True,
    "child_status": "not_revoked",
    "child_verifies": True,
    "revoked_root_status": "revoked",
    "revoked_root_verifies": False,
}


def test_both_stores_durable_survive_a_real_process_restart(tmp_path):
    """THE TEST. Both stores durable, a real process restart between minting and
    verifying: the child credential still resolves and the revoked one is still
    refused."""
    assert restart_cycle(tmp_path) == HONEST, (
        "with both halves durable, a restart must change nothing: the child's "
        "ancestry still resolves through the persisted lineage store, and the "
        "revocation recorded before the restart is still in force"
    )


def test_mutation_one_lineage_not_persisted_breaks_every_child_and_no_root(tmp_path):
    """NON-VACUITY 1 — persist the revoked set, leave the resolver in memory.

    The outage half. Every child credential goes UNAVAILABLE; every root keeps
    working, because a root is trivially complete under R.4.2 and never touches
    the resolver. Authenticity still passes, which is the assertion that retires
    the "it must be a signing or clock problem" diagnosis.

    This test is also the proof that the harness performs a **real restart**: it
    can only pass if the in-memory lineage store phase 2 builds is empty, and it
    can only be empty if phase 2 did not inherit phase 1's memory."""
    assert restart_cycle(tmp_path, verify_break="lineage") == {
        "child_authentic": True,  # not a signature problem, not a clock problem
        "child_status": "unavailable",
        "child_verifies": False,
        "revoked_root_status": "revoked",  # a root needs no resolution
        "revoked_root_verifies": False,
    }, (
        "a durable revoked set with an in-memory resolver must fail closed for "
        "every child and leave every root untouched — total for delegated "
        "credentials, invisible for root ones"
    )


def test_mutation_two_revoked_set_vouching_when_absent_resurrects_a_revoked_vaid(tmp_path):
    """NON-VACUITY 2 — persist the lineage, let the revoked set vouch when absent.

    The security half, and the reason ``assume_nothing_revoked`` must never be the
    shape a durable store copies: the revocation recorded before the restart is
    gone, and the revoked credential verifies clean with no indication anything is
    wrong."""
    spawn_phase("mint", tmp_path)
    (tmp_path / "revoked.json").unlink()
    obs = observations_from(spawn_phase("verify", tmp_path, "revocation-vouches-when-absent"))
    assert obs == {
        "child_authentic": True,
        "child_status": "not_revoked",
        "child_verifies": True,
        # The revocation is simply gone, and nothing says so.
        "revoked_root_status": "not_revoked",
        "revoked_root_verifies": True,
    }, (
        "a store that vouches when its state is absent silently un-revokes "
        "everything revoked before the restart — R.4.6 exists to forbid exactly "
        "this, and an honest store answers UNAVAILABLE instead"
    )


def test_an_honest_store_reports_an_absent_revoked_set_as_unavailable(tmp_path):
    """The control for the mutation above — the two runs differ in nothing but the
    store's answer to a missing file."""
    spawn_phase("mint", tmp_path)
    (tmp_path / "revoked.json").unlink()
    obs = observations_from(spawn_phase("verify", tmp_path))
    assert obs["revoked_root_status"] == "unavailable"
    assert not obs["revoked_root_verifies"]
    assert obs["child_status"] == "unavailable"
    assert obs["child_authentic"], "still authentic — only standing failed"


def test_mints_are_recorded_into_the_injected_lineage_store(tmp_path):
    """The paired backend records into the injected store rather than the built-in
    one. Without a write half (``LineageStore.record``) a durable resolver would be
    injectable and permanently empty, which is the failure above with extra steps."""
    issuer = issuer_for(tmp_path, "")
    root = _mint(issuer, "root", None)
    child = _mint(issuer, "child", root["vaid_id"])

    recorded = json.loads((tmp_path / "lineage.json").read_text())
    assert recorded[root["vaid_id"]] is None, (
        "a root must be recorded as a KNOWN root, not omitted"
    )
    assert recorded[child["vaid_id"]] == root["vaid_id"]
