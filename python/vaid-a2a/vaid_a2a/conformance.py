"""Packaged A2A-extension conformance check — the firewall, shipped in the wheel.

Mirror of ``vaid_pop.conformance`` / ``vaid_mint.conformance`` /
``vaid_langchain.conformance``. A consumer who has only ``pip install vaid-a2a``
— no repo checkout — can prove the verifier they installed reaches the verdict
the extension specifies for every published vector::

    python -m vaid_a2a.conformance      # exit 0 = PASS, 1 = BLOCKER
    vaid-a2a-conformance                # same, via the console entry point

Programmatically::

    from vaid_a2a.conformance import run
    run()  # raises ConformanceError on any divergence; returns the verdicts on PASS

WHAT THIS PINS, AND WHAT IT DOES NOT. The vaid-pop and vaid-mint firewalls pin
BYTES: a canonical digest and a deterministic signature that must reproduce
hex-for-hex. This one pins VERDICTS — for each vector, ``(allowed, error_code)``
— because that is what ``docs/a2a/v1/extension.md`` section 5 makes normative for
a verifier: the ordered sequence of checks and the specific code the FIRST fault
reported. The same posture as ``verdict_v1.json`` in vaid-mint. It is not a
weaker claim, it is a claim about a different surface, and conflating the two is
how "the conformance check passed" came to be read as more than it said.

The vectors it checks are the ones bundled with the installed package
(``vaid_a2a/vectors/*.json``), vendored byte-identically from
``docs/a2a/v1/vectors/`` — the extension's own vectors, not this package's
private fixtures, so another language's verifier reproduces the same table from
the same bytes. A CI drift-check ``cmp``s the two copies, so a consumer's
firewall runs against the exact bytes this verifier was proven against.

POSITIVE AND NEGATIVE CONTROLS ARE BOTH LOAD-BEARING, and both are asserted
below rather than assumed from the vector set. A verifier that denies everything
satisfies every negative vector here; a verifier that allows everything
satisfies the positive one. Neither passes :func:`run`. Nor does an empty vector
directory: a verdict over no input is not a pass, so the count has a floor.
"""

from __future__ import annotations

import json
from datetime import datetime
from importlib.resources import files

from vaid_mint.revocation import InMemoryRevocationList

from vaid_a2a import METADATA_CHAIN_KEY, METADATA_VAID_KEY, verify_a2a_message

#: The number of vectors the extension publishes. A floor, not a target: left at
#: a stale lower number it stops guarding anything but total absence — with 14
#: vectors bundled, a floor of 6 would let more than half of them vanish from a
#: wheel and still report a clean pass. Raise it when a vector is added.
EXPECTED_VECTOR_COUNT = 14


class ConformanceError(AssertionError):
    """A divergence from the extension's specified verdicts — a hard BLOCKER,
    never ship-anyway."""


def vector_names() -> list[str]:
    """Every vector bundled with the installed package, in file-name order (the
    order the extension numbers them in)."""
    root = files("vaid_a2a").joinpath("vectors")
    return sorted(p.name for p in root.iterdir() if p.name.endswith(".json"))


def load_vector(name: str) -> dict:
    """One bundled vector, by file name."""
    return json.loads(files("vaid_a2a").joinpath(f"vectors/{name}").read_text())


def _verification_time(raw: str) -> datetime:
    """The vector's OWN ``verification_time`` (RFC 3339, ``Z`` suffix), never the
    wall clock — a verdict that moves with the calendar is not a frozen verdict."""
    return datetime.fromisoformat(raw.replace("Z", "+00:00"))


def _revocation_for(revoked_ids: list[str]) -> InMemoryRevocationList:
    store = InMemoryRevocationList()
    if not revoked_ids:
        # An empty revocation list must still VOUCH for "nothing revoked" rather
        # than read as UNAVAILABLE (R.4.5/R.4.6). The named constructor is the
        # explicit way to get that posture instead of relying on an absent store
        # by accident.
        return InMemoryRevocationList.assume_nothing_revoked()
    for vaid_id in revoked_ids:
        store.revoke(vaid_id)
    return store


def check_vector(name: str) -> tuple[bool, str | None]:
    """Replay one vector through :func:`verify_a2a_message` and assert the
    extension's expected verdict. Returns the ``(allowed, code)`` observed."""
    vector = load_vector(name)
    message = {
        "metadata": {
            METADATA_VAID_KEY: vector["inputs"]["leaf"],
            METADATA_CHAIN_KEY: vector["inputs"]["chain"],
        }
    }
    result = verify_a2a_message(
        message,
        trust_config=vector["trust_config"],
        revocation=_revocation_for(vector["revoked_vaid_ids"]),
        requested_action=vector.get("requested_action"),
        now=_verification_time(vector["verification_time"]),
    )

    expected_pass = vector["expected_result"] == "pass"
    if result.allowed is not expected_pass:
        raise ConformanceError(
            f"{name}: verdict diverged from the extension — BLOCKER\n"
            f"  got    = allowed={result.allowed} ({result.code.value}: {result.reason})\n"
            f"  vector = allowed={expected_pass}"
        )
    expected_code = vector.get("expected_error_code")
    if expected_code is not None and result.code.value != expected_code:
        raise ConformanceError(
            f"{name}: error code diverged from the extension — BLOCKER\n"
            f"  got    = {result.code.value!r} ({result.reason})\n"
            f"  vector = {expected_code!r}"
        )
    return result.allowed, result.code.value


def check_vector_set(names: list[str]) -> None:
    """The set itself is the first thing checked: enough vectors, and both
    polarities present. Without this, an empty or one-sided bundle would let the
    loop below report a clean pass over nothing it could fail."""
    if len(names) < EXPECTED_VECTOR_COUNT:
        raise ConformanceError(
            f"only {len(names)} vector(s) bundled with the installed package, "
            f"expected at least {EXPECTED_VECTOR_COUNT} — BLOCKER. A verdict "
            f"over a truncated vector set is not a pass.\n  found = {names}"
        )
    polarities = {load_vector(n)["expected_result"] == "pass" for n in names}
    if True not in polarities:
        raise ConformanceError(
            "no vector expects a PASS — BLOCKER. With negatives only, a verifier "
            "that denies everything would satisfy this firewall."
        )
    if False not in polarities:
        raise ConformanceError(
            "no vector expects a DENIAL — BLOCKER. With positives only, a verifier "
            "that allows everything would satisfy this firewall."
        )


def run() -> dict[str, tuple[bool, str | None]]:
    """Run the firewall over every bundled vector. Raises ConformanceError on any
    divergence; returns the observed verdict table on PASS."""
    names = vector_names()
    check_vector_set(names)
    return {name: check_vector(name) for name in names}


# --- pytest discovery (so `pytest --pyargs vaid_a2a` runs the firewall) ---


def test_packaged_vector_set_has_both_polarities() -> None:
    check_vector_set(vector_names())


def test_packaged_vectors_match_the_extension() -> None:
    for name in vector_names():
        check_vector(name)


def main() -> int:
    try:
        verdicts = run()
    except ConformanceError as exc:
        print(f"A2A EXTENSION FIREWALL: MISMATCH — BLOCKER\n{exc}")
        return 1
    passes = sum(1 for allowed, _ in verdicts.values() if allowed)
    print(
        "A2A EXTENSION FIREWALL: PASS — installed verifier reaches the verdict "
        f"docs/a2a/v1/extension.md specifies for all {len(verdicts)} vector(s)\n"
        f"  {passes} expected pass, {len(verdicts) - passes} expected denial"
    )
    for name, (allowed, code) in verdicts.items():
        print(f"  {'allow ' if allowed else 'deny  '} {code:<22} {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
