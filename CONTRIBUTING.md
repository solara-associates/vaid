# Contributing to Synthera VAID

Thanks for your interest in VAID — the open standard for verifiable
agent-action identity. VAID is an **interoperability contract**: the most
important property of this repo is that any conforming client produces bytes
that any conforming verifier accepts. Contributions are judged first against
that bar.

## Ground rules

- **The conformance vector is the source of truth.** Both reference SDKs
  (Rust `vaid-pop`/`vaid-client`, Python `vaid-pop`) must reproduce the frozen
  conformance vector **byte-for-byte**. Any change that alters canonicalization,
  hashing, or signing is a **breaking change to the standard** and must be
  proposed and discussed before implementation (open an issue first).
- **No new runtime dependencies or network calls** in the PoP path. The
  canonicalization path is RFC 8785 (JCS) → SHA-256 → Ed25519, and stays that way
  unless the standard itself is versioned.
- **Cross-language parity is mandatory.** A change to one SDK that affects output
  bytes must land in the other in the same PR (or a tracked follow-up that blocks
  release).

## Development

**Rust**
```bash
cargo test --workspace          # unit + conformance tests
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
```

**Python** (`python/vaid-pop`)
```bash
cd python/vaid-pop
uv sync && uv run pytest        # runs the same conformance vectors
```

A PR must keep **both** languages green and reproduce the conformance vector
identically.

## Releasing and version tags

**Each package versions independently.** The Rust crates and the Python packages
are separate, hand-written implementations — not builds of one another — so their
version numbers move on their own schedules and may legitimately diverge. A shared
version number is a coincidence, not a guarantee, even when a change lands in both
(as `vaid-mint` 0.1.2 did).

**Git tags are therefore language-prefixed:**

```
rust-vX.Y.Z      # a crates.io release of the Rust crate
python-vX.Y.Z    # a PyPI release of the Python package
```

Do **not** cut an unprefixed `vX.Y.Z` tag. An unprefixed tag cannot say which
package it releases, and in practice it misleads: the original `v0.1.2` tagged the
Rust 0.1.2 release at a commit where the Python package was still 0.1.1 and had
none of the 0.1.2 changes. It was renamed to `rust-v0.1.2` for exactly that
reason.

Each package keeps its own changelog (`crates/vaid-mint/CHANGELOG.md`,
`python/vaid-mint/CHANGELOG.md`) documenting its own language's behavior. Before
tagging, confirm the package's `Cargo.toml` / `pyproject.toml`, its in-code version
(`__version__` for Python), and its changelog's latest entry all agree.

**Capabilities manifest (release gate).** Before you tag, answer: *does this release
change `docs/capabilities.json`?* There are two cases, and they land at **different
times** — getting this wrong fails CI every time (correctly, but wastefully):

- **Not gated on publication** — a `status_text` fix, a `landed_in` note, or any
  status change whose evidence *already exists* (a `repo_ref` path that resolves, or
  an already-published version): update the manifest **in the same PR** as the change.
- **Gated on a published artifact** — flipping a capability to `shipped` with a
  registry version happens **AFTER the publish, not with the merge**. `shipped` means
  *published*: `verify-capabilities.mjs` requires the version to exist on crates.io /
  PyPI, and **merging a PR publishes nothing**. So the flip is a step in the **release
  checklist, positioned after the registry publish**, and it lands as its **own
  follow-up PR** — which passes because the versions now exist. Flipping to `shipped`
  in the code-merge PR, before publish, fails CI until the packages are pushed.

Concretely, for a version bump the order is: **merge → tag → publish to
crates.io/PyPI → then the manifest-flip PR.** (This is not hypothetical — see
[ADR-0002](docs/adr/0002-capabilities-manifest.md): the check caught a
shipped-but-unpublished flip on its first real use.)

The `capabilities` CI job (`scripts/verify-capabilities.mjs`) enforces it: a
`shipped` version must be published on its registry, and a `roadmap`/`planned`
capability blocked on a merged PR fails — its status should have flipped. See
[ADR-0002](docs/adr/0002-capabilities-manifest.md). Prose (docs, the site) renders
status from this file; do not re-assert status in prose. `status_text` is the one
hand-written field — review it here too.

**Registry parity (every package, not just claimed ones).** The same CI job also
runs `scripts/verify-package-versions.mjs`, which asserts that **every** package's
in-repo version (`crates/*/Cargo.toml`, `python/*/pyproject.toml`) is **published on
its registry** — independent of any capability claim. So a version bump on `main`
that has not been published yet is **red until you publish**: bump and publish are
near-atomic by design. A package deliberately not published to a public registry
opts out via Cargo `publish = false` or the `Private :: Do Not Upload` classifier in
`pyproject`.

## Proposing a change

1. **Open an issue** describing the change and whether it affects on-the-wire
   bytes. Standard-affecting changes need consensus before code.
2. Branch, implement, and ensure Rust + Python both pass.
3. Open a PR linking the issue. Describe byte-level impact explicitly
   ("no wire change" / "wire change — requires standard version bump").

## Developer Certificate of Origin (DCO)

By contributing you certify the [DCO](https://developercertificate.org/). Sign
off each commit:

```bash
git commit -s -m "your message"
```

## Reporting bugs and security issues

- **Functional bugs / interop mismatches:** open a GitHub issue with a minimal
  reproduction (ideally a failing vector).
- **Security vulnerabilities:** do **not** open a public issue — see
  [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE), and you agree to the [Code of
Conduct](CODE_OF_CONDUCT.md).
