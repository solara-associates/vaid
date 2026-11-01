"""Opt-in integration test: drives spire-proof/run.sh against a real SPIRE
server and agent in Docker.

Skipped unless VAID_LIVE_SPIRE=1 is set, and does not run in the default
test suite or in CI - it needs Docker, pulls two images on first run, and
takes tens of seconds even on the fast path. See spire-proof/README.md for
what it proves and why it is not a byte-identity vector the way the
package's other conformance checks are.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("VAID_LIVE_SPIRE") != "1",
    reason="live SPIRE integration test: set VAID_LIVE_SPIRE=1 to run (requires Docker)",
)

SPIRE_PROOF_DIR = Path(__file__).resolve().parent.parent / "spire-proof"


def test_live_spire_proof():
    result = subprocess.run(
        [str(SPIRE_PROOF_DIR / "run.sh")],
        cwd=SPIRE_PROOF_DIR,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, (
        f"spire-proof/run.sh exited {result.returncode}\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "LIVE SPIRE PROOF: PASS" in result.stdout
