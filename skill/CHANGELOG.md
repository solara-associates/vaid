# Changelog

All notable changes to `vaid-skill`. This project follows semantic versioning.

## 0.1.1 — 2026-08-10

### Fixed

- **Corrected the explanation of why the decode recipe needs padding.** 0.1.0's
  `SKILL.md` and `README.md` said `base64 -d` "requires padding" and "rejects
  unpadded input". It does neither. It **accepts** unpadded base64url and
  **silently drops the final partial group**, returning a document short by one or
  two bytes — with no error and nothing on stderr. What comes back is JSON missing
  its last brace, so the failure presents as *your credential is invalid JSON*
  when the credential is intact and the command is wrong.

  Measured on macOS: without the padding loop, 27 of 40 freshly minted envelopes
  decoded to truncated JSON. Only envelopes whose token length is ≡ 0 mod 4
  survive, and that length varies per mint because the signature is an array of
  1-to-3-digit numbers — so it works often enough to look intermittent.

  The recipe printed in 0.1.0 was already correct and is unchanged; the padding
  loop was there. Only the reason given for it was wrong, and it was wrong in the
  file agents read, which would leave a reader with a false model of the failure
  they are most likely to hit.

### Not changed

Nothing executable. Every file under `src/`, plus `install.mjs`,
`trust-anchor.json` and `.claude-plugin/plugin.json`, is **byte-identical** to
0.1.0 — verified by hash against the `vaid-skill-v0.1.0` tag. This release moves
documentation only.

## 0.1.0 — 2026-08-10

Initial release. Four verbs — `mint`, `present`, `verify`, `revoke` — wrapping the
published `vaid-mint` and `vaid-pop` SDKs. No cryptography of its own.

- The single-line `vaid1:` **envelope**, so a VAID can be pasted into a message and
  checked by whoever receives it.
- A **plural verdict** keeping authenticity, expiry, delegation, issuer identity
  and revocation apart. Revocation is always reported NOT CHECKED, on every path
  including rejections: there is no published revocation list to consult.
- A **pinned trust anchor**, byte-checked in CI against the vaid repo's
  `docs/kernel-keys.json`, so `verify` works with the network off.
- An installer covering Claude Code, Codex, Cursor, Gemini CLI and Copilot.
