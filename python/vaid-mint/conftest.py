"""Make the test suite run correctly in a fresh clone.

``vaid-mint`` declares ``vaid-pop>=0.2.0`` in ``pyproject.toml``. CI honours that
floor because it installs the in-repo copy explicitly
(``pip install ./python/vaid-pop``) before running pytest. A developer who clones
the repo and runs ``pytest`` directly gets whatever ``vaid_pop`` happens to be
importable — and an older release, or none at all, produces a **collection error**
rather than a comprehensible message:

    ImportError: cannot import name 'verify_signed_payload' from 'vaid_pop'

That aborts the entire run, including tests that have nothing to do with
proof-of-possession, so the suite reports a failure that is really an environment
problem. A test suite whose red state does not mean "the code is wrong" is worse
than one that does not run at all, because it trains the reader to discount it.

This conftest resolves it in the order a reader would expect:

1. If the importable ``vaid_pop`` satisfies the declared floor, use it untouched —
   including a *newer* release, so testing against a real published wheel still
   works and this file never silently overrides a deliberate choice.
2. Otherwise fall back to the sibling source tree in this repo, which is the copy
   CI installs, and say so loudly via a warning. The fallback is what makes a
   fresh clone work.
3. If neither is usable, fail immediately with an actionable message rather than
   letting an ImportError surface from inside an unrelated test module.

The floor is mirrored as a constant below rather than parsed out of
``pyproject.toml``: parsing needs a TOML read at collection time to save one line
of duplication, and the duplication is guarded by
``test_declared_vaid_pop_floor_matches_this_conftest``.
"""

from __future__ import annotations

import sys
import warnings
from pathlib import Path

# Mirrors the ``vaid-pop>=0.2.0`` floor in pyproject.toml. Kept in sync by a test
# in tests/test_environment.py.
MIN_VAID_POP = (0, 2, 0)

_SIBLING_SOURCE = Path(__file__).resolve().parent.parent / "vaid-pop"


def _parse_version(raw: str) -> tuple[int, ...]:
    """Numeric release segment of a version string. Any pre-release or local
    suffix is dropped, so ``0.2.0rc1`` compares as ``(0, 2, 0)`` — deliberately
    permissive, because this guards an environment, not a release."""
    digits: list[int] = []
    for part in raw.split("."):
        head = ""
        for ch in part:
            if not ch.isdigit():
                break
            head += ch
        if not head:
            break
        digits.append(int(head))
    return tuple(digits)


def _importable_vaid_pop_version() -> tuple[int, ...] | None:
    """The version of whatever ``vaid_pop`` currently imports, or ``None`` if it
    does not import at all."""
    try:
        import vaid_pop
    except ImportError:
        return None
    return _parse_version(getattr(vaid_pop, "__version__", "0"))


def _forget_vaid_pop() -> None:
    """Drop ``vaid_pop`` and its submodules from the module cache, so the
    subsequent import resolves against the amended ``sys.path`` rather than
    returning the already-imported stale package."""
    for name in [
        m for m in sys.modules if m == "vaid_pop" or m.startswith("vaid_pop.")
    ]:
        del sys.modules[name]


def _render(version: tuple[int, ...] | None, absent: str) -> str:
    return absent if version is None else ".".join(map(str, version))


def _ensure_vaid_pop() -> None:
    floor = _render(MIN_VAID_POP, "")
    found = _importable_vaid_pop_version()
    if found is not None and found >= MIN_VAID_POP:
        return  # Satisfies the declared floor — including newer. Leave it alone.

    if not (_SIBLING_SOURCE / "vaid_pop" / "__init__.py").is_file():
        raise RuntimeError(
            f"vaid-mint requires vaid-pop>={floor}, but the importable copy is "
            f"{_render(found, 'absent')} and the in-repo source at {_SIBLING_SOURCE} "
            f"is missing too.\nInstall it with:  pip install ./python/vaid-pop"
        )

    _forget_vaid_pop()
    sys.path.insert(0, str(_SIBLING_SOURCE))
    resolved = _importable_vaid_pop_version()

    if resolved is None or resolved < MIN_VAID_POP:
        raise RuntimeError(
            f"vaid-mint requires vaid-pop>={floor}. The in-repo source at "
            f"{_SIBLING_SOURCE} resolved to {_render(resolved, 'nothing importable')}, "
            f"which does not satisfy it. The repo checkout itself looks wrong."
        )

    warnings.warn(
        f"vaid_pop resolved to {_render(found, 'nothing importable')}, below the "
        f"vaid-pop>={floor} that vaid-mint declares. Falling back to the in-repo "
        f"source at {_SIBLING_SOURCE}; this suite is now testing that copy. To "
        f"silence this, install it:  pip install ./python/vaid-pop",
        RuntimeWarning,
        stacklevel=1,
    )


_ensure_vaid_pop()
