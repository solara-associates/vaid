# Changelog

All notable changes to the Rust `vaid-pop` crate are documented here. This project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This crate is a **separate, hand-written Rust implementation — not a build or mirror
of the Python or TypeScript `vaid-pop` packages**. All three are versioned
independently and their numbers legitimately diverge; a shared version number is a
coincidence, not a guarantee. At the time of writing this crate is at 0.2.1, the
Python package at 0.2.0 and the npm package at 0.3.0, and that is correct rather
than drift. Byte-identity between the three is asserted by the frozen conformance
vectors, never by the version number.

**This file starts at 0.2.0.** 0.1.0 (tag `rust-vaid-pop-v0.1.0`) predates it and is
deliberately not reconstructed here: writing entries for a release from the diff
after the fact produces a plausible history rather than a recorded one, which is
worse than an acknowledged gap. `git log rust-vaid-pop-v0.1.0` is the record for
that release.

## [0.2.1]

### Fixed — the packaged firewall named a fixed set of vectors

`vaid-pop-conformance` embedded two literal `include_str!` paths, so it checked
exactly the vectors named in its source and no others. A third vector added to the
crate would have shipped **unverified while the firewall still printed PASS**.

This is not hypothetical. The identical shape in `vaid-mint` 0.4.0 shipped
`chain_v1.json` and `attestation_v1.json` and reported PASS having verified neither
— the two vectors that release existed for. This crate had the same latent defect.

`build.rs` now scans `tests/vectors/` **at build time** and emits one `include_str!`
per file. Build time is the correct analogue of the runtime directory read the
Python and TypeScript firewalls do: an installed binary has no directory left to
read, and `include_str!` takes a literal path. Because `cargo install` compiles from
the tarball the consumer fetched, this enumerates precisely what shipped in *that*
artifact.

The firewall now fails in three ways the previous shape could not:

- a vector embedded in the crate with no entry in `VECTOR_CHECKS` — BLOCKER;
- an entry in `VECTOR_CHECKS` whose vector is not embedded — BLOCKER, because a
  checker that quietly checks nothing is the same defect wearing the other hat;
- no embedded vectors at all — BLOCKER, because a firewall that checked nothing must
  never report PASS.

It cannot verify a vector nobody has written a checker for; nothing can. What it
guarantees is that such a vector cannot ship *quietly*.

`build.rs` never fails the build. It runs for every consumer who merely depends on
the library, so a missing `tests/vectors/` emits an empty table rather than
panicking, and the binary fails closed at runtime where it belongs.

### Changed

- Firewall output now states the vector **count** and names each vector with its
  digest, matching the Python, TypeScript and `vaid-mint` firewalls. What was
  actually checked is answerable from the output rather than from the source.
- `tests/vector_coverage.rs` asserts the same invariant at `cargo test` time. The
  binary fails closed at runtime, but that fires only when someone runs it; this
  fires on the pull request that adds the vector.

### Not changed

No change to the proof-of-possession wire shape. `operator_pop_v1.json` and
`completion_v1.json` are byte-identical to 0.2.0, and no public API moved.

## [0.2.0]

### Added — `vaid-pop-conformance`, the packaged firewall as an installable binary

The Python and TypeScript packages shipped an executable a consumer could run
against the package they installed. Rust did not: its gates were `#[test]`s under
`tests/`, and `cargo test` needs a checkout, so the only Rust answer was "clone our
repository and trust that it is the source your crate was built from" — a strictly
weaker claim than the other two languages make.

```console
$ cargo install vaid-pop
$ vaid-pop-conformance      # exit 0 = PASS, 1 = BLOCKER
```

Because `cargo install` compiles from the published `.crate` tarball, the bytes
checked are the bytes the consumer received from crates.io.

The binary asserts the primitive's contract: the canonical JCS→SHA-256 digest over a
real `RequestAuthPayload`, the deterministic Ed25519 signature and derived public
key, the `CompletionRecord` digest and signature, and the `AssuranceTier`
enum-string drift guard — enum strings travel inside signed bytes, so a rename that
looks cosmetic in one language silently breaks byte-identity with the other two.

The request *signer* lives in `vaid-client`, which depends on this crate, so
checking it from here would invert the dependency; that path is asserted by
`cargo test -p vaid-client --test conformance`. Python's firewall covers both
because its signer ships in the same package — a packaging difference, not a
coverage gap in the standard.

### Added — `operator_pop_v1.json` vendored into this crate

The vector was vendored into `crates/vaid-pop/tests/vectors/` so the binary can
embed it and run with no checkout and no network. It is byte-identical to every
other language's copy; CI `cmp`s all of them.

### Changed

- Formatting only in `src/vaid_pop.rs`, `examples/emit_completion_vector.rs` and
  `tests/completion_conformance.rs` (`cargo fmt`). No behaviour change.

### Not changed

No change to the proof-of-possession wire shape, and the frozen vectors are
untouched.
