"""The test environment is itself under test.

``conftest.py`` guarantees the suite runs correctly in a fresh clone, where the
importable ``vaid_pop`` may be older than the ``vaid-pop>=0.2.0`` floor vaid-mint
declares. Two things about that guarantee can rot silently, so both are asserted
here rather than trusted:

1. the floor mirrored in ``conftest.MIN_VAID_POP`` drifting from the one declared
   in ``pyproject.toml``;
2. the resolved ``vaid_pop`` failing to satisfy the floor anyway — which is the
   original defect, and which used to surface as a collection error in an
   unrelated module.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import vaid_pop

from conftest import MIN_VAID_POP, _parse_version

_PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def _declared_vaid_pop_floor() -> tuple[int, ...]:
    """The ``vaid-pop>=X`` floor as actually declared to packaging."""
    metadata = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    for dep in metadata["project"]["dependencies"]:
        normalized = dep.replace(" ", "")
        if normalized.startswith("vaid-pop>="):
            return _parse_version(normalized.removeprefix("vaid-pop>="))
    raise AssertionError("vaid-mint no longer declares a vaid-pop floor")


def test_declared_vaid_pop_floor_matches_this_conftest() -> None:
    """conftest mirrors the floor instead of parsing it, so the copy is pinned by
    this test. If pyproject's floor moves, this fails and names the fix."""
    assert MIN_VAID_POP == _declared_vaid_pop_floor(), (
        "conftest.MIN_VAID_POP has drifted from the vaid-pop floor declared in "
        "pyproject.toml — update the constant in conftest.py to match"
    )


def test_resolved_vaid_pop_satisfies_the_declared_floor() -> None:
    """The original defect, asserted directly. A too-old vaid_pop used to abort
    collection of test_mint_pop_conformance.py with an ImportError; it now fails
    here, in a test that names the problem."""
    resolved = _parse_version(getattr(vaid_pop, "__version__", "0"))
    assert resolved >= MIN_VAID_POP, (
        f"the resolved vaid_pop is {vaid_pop.__file__} at version "
        f"{getattr(vaid_pop, '__version__', 'unknown')}, below the declared floor "
        f"{'.'.join(map(str, MIN_VAID_POP))}"
    )


def test_the_symbol_whose_absence_broke_collection_is_present() -> None:
    """``verify_signed_payload`` is the specific import
    ``vaid_mint.conformance`` makes and the specific name a 0.1.0 vaid_pop
    lacked. Named explicitly so the regression is recognisable rather than
    inferred from a version number."""
    assert hasattr(vaid_pop, "verify_signed_payload")
