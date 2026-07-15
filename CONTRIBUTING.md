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
