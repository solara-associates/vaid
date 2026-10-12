"""The package's own documented examples must RUN, and must name methods that exist.

Both failures this file guards against shipped in 0.9.0 and reached PyPI:

  1. ``vaid_mint.__doc__``'s Usage block ended ``assert issuer.verify_vaid(vaid)``
     after a bare ``ReferenceIssuer.ephemeral(...)``. 0.9.0 moved the default
     revocation posture from fail-OPEN to fail-CLOSED (R.4.5), so a fresh issuer
     answers ``UNAVAILABLE`` and denies a document it has just minted. The assert
     could not pass. The example was correct when written and was not revisited
     when the default moved, which is the whole shape of the problem: flipping a
     default to fail-closed breaks the documented happy path BY CONSTRUCTION,
     because every example was written under the old default.

  2. The same docstring named ``ReferenceIssuer.with_revocation_check`` as the
     injection point. That method was removed in 0.9.0 and replaced by
     ``with_revocation_backend``, which takes both durable halves at once.

Neither is reachable by reading. A newcomer who copies the Usage block gets a
denial and reads it as *I installed this wrong*, and an ``AttributeError`` on a
method named in prose looks like a version mismatch rather than a stale doc.
Nothing in this repository executed a docstring, and ``pytest`` does not collect
them, so both sat green.

**The subjects are DERIVED, not listed.** The example is parsed out of the live
``__doc__`` rather than copied here, so a copy cannot drift from the original, and
the method names are checked against ``dir(ReferenceIssuer)`` rather than against
a second hardcoded list that would go stale the same way the first one did.

Each test asserts it found something before asserting anything about it. An
extractor whose regex stopped matching would otherwise report a clean pass over
zero examples, and read exactly like a real one.
"""

from __future__ import annotations

import inspect
import pathlib
import re
import textwrap

import pytest

import vaid_mint
from vaid_mint import ReferenceIssuer

PACKAGE_ROOT = pathlib.Path(vaid_mint.__file__).parent
README = PACKAGE_ROOT.parent / "README.md"


# ── 1. the Usage block executes ──────────────────────────────────────────────


def usage_blocks(docstring: str) -> list[str]:
    """Every reStructuredText literal block introduced by ``Usage::``.

    Taken from the live ``__doc__`` so there is no second copy to drift.
    """
    blocks = []
    for match in re.finditer(r"^Usage::\n\n((?:(?:[ \t]+.*)?\n)+)", docstring, re.M):
        block = textwrap.dedent(match.group(1)).strip("\n")
        if block.strip():
            blocks.append(block)
    return blocks


def test_module_docstring_has_a_usage_block():
    """The positive control for the two tests below.

    If the docstring is reorganised so ``Usage::`` no longer appears, the
    extractor silently returns an empty list and `all([])` is True, so both
    execution tests below would pass having run nothing at all.
    """
    blocks = usage_blocks(vaid_mint.__doc__ or "")
    assert blocks, (
        "no 'Usage::' block found in vaid_mint.__doc__ — the extractor matched "
        "nothing, so the tests below would pass over zero examples"
    )
    assert any("verify_vaid" in b for b in blocks), (
        "the Usage block no longer verifies anything. Verification is the step "
        "that the fail-closed default broke, so an example that does not call "
        "verify_vaid cannot catch a regression of it"
    )


@pytest.mark.parametrize("block", usage_blocks(vaid_mint.__doc__ or ""))
def test_module_docstring_usage_block_runs(block: str):
    """Execute the documented example exactly as a reader would paste it.

    A bare ``exec`` of the real text: no fixtures, no patching, and no helper the
    reader does not have. If the example needs something the docstring does not
    show, that is the defect.
    """
    exec(compile(block, "<vaid_mint.__doc__ Usage::>", "exec"), {"__name__": "__docstring__"})


# ── 2. every documented ReferenceIssuer method exists ────────────────────────

# `ReferenceIssuer.<name>`, in code and in a Sphinx `:meth:` role alike. The role
# form is the one that shipped wrong: ``:meth:`~vaid_mint.issuer.ReferenceIssuer.
# with_revocation_check``` reads as authoritative and resolves to nothing.
REFERENCE_ISSUER_MEMBER = re.compile(r"ReferenceIssuer\.(\w+)")

# Members named in prose that are deliberately NOT attributes: the class's own
# documentation discusses what callers construct, not only what it exposes.
NOT_A_MEMBER = {
    # `ReferenceIssuer.ephemeral(1, "x")` is a call; `.ephemeral` IS a member, so
    # nothing belongs here today. The set exists so a future exception carries a
    # reason at the point it is added, rather than being silenced by loosening the
    # regex — which is how a check stops seeing the thing it was written for.
}


def documented_sources() -> list[tuple[pathlib.Path, str]]:
    """Every shipped file whose prose a consumer reads: package source and README.

    CHANGELOG.md is deliberately EXCLUDED. It is a historical record and says
    ``with_revocation_check`` many times, correctly, in the past tense: a changelog
    that stopped naming a removed method would be the defect. The rule here is
    about text that describes the CURRENT surface.
    """
    sources = [(p, p.read_text(encoding="utf-8")) for p in sorted(PACKAGE_ROOT.rglob("*.py"))]
    if README.exists():
        sources.append((README, README.read_text(encoding="utf-8")))
    return sources


def test_documented_sources_were_found():
    """Positive control: an empty file list passes every assertion below."""
    sources = documented_sources()
    assert len(sources) >= 5, f"expected the package's modules, found {len(sources)}"
    assert any(p == README for p, _ in sources), f"{README} was not read"
    names = {m for _, text in sources for m in REFERENCE_ISSUER_MEMBER.findall(text)}
    assert names, "no ReferenceIssuer.<member> references found — the regex matched nothing"


def test_every_documented_reference_issuer_member_exists():
    """A method named in shipped prose must be a method on the shipped class."""
    unknown: list[str] = []
    for path, text in documented_sources():
        for line_no, line in enumerate(text.splitlines(), start=1):
            for name in REFERENCE_ISSUER_MEMBER.findall(line):
                if name in NOT_A_MEMBER or hasattr(ReferenceIssuer, name):
                    continue
                rel = path.relative_to(PACKAGE_ROOT.parent)
                unknown.append(f"{rel}:{line_no}  ReferenceIssuer.{name}  |  {line.strip()[:90]}")
    assert not unknown, (
        "shipped prose names ReferenceIssuer member(s) that do not exist:\n  "
        + "\n  ".join(unknown)
        + "\n\nRename to the current method, or if the mention is deliberately "
        "historical, say so in the past tense WITHOUT the `ReferenceIssuer.` "
        "prefix, the way the CHANGELOG does."
    )


# ── 3. every documented ephemeral() call binds against the real signature ────

EPHEMERAL_CALL = re.compile(r"ReferenceIssuer\.ephemeral\(([^)]*)\)")


def test_every_documented_ephemeral_call_binds():
    """``ephemeral`` takes a TTL and a trust domain, and neither has a default.

    Four calls in README.md were written as ``ephemeral(1)`` and raise TypeError
    before reaching the line the example is about. The TypeScript twin gives both
    parameters defaults, so the same text is correct there and wrong here, which
    is exactly why reading one and assuming the other does not work.

    Arity is checked by binding against the live signature rather than by counting
    commas, so adding a default to either parameter makes the shorter form legal
    here automatically.
    """
    signature = inspect.signature(ReferenceIssuer.ephemeral)
    bad: list[str] = []
    found = 0
    for path, text in documented_sources():
        for line_no, line in enumerate(text.splitlines(), start=1):
            for args in EPHEMERAL_CALL.findall(line):
                found += 1
                count = len([a for a in args.split(",") if a.strip()])
                try:
                    signature.bind(*range(count))
                except TypeError as exc:
                    rel = path.relative_to(PACKAGE_ROOT.parent)
                    bad.append(f"{rel}:{line_no}  ephemeral({args})  ->  {exc}")
    assert found, "no ReferenceIssuer.ephemeral(...) calls found — nothing was checked"
    assert not bad, (
        f"documented ReferenceIssuer.ephemeral(...) call(s) that raise, out of {found} checked:\n  "
        + "\n  ".join(bad)
    )
