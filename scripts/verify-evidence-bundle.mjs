#!/usr/bin/env node
/**
 * Verify an `evidence-bundle/v1` offline, as an outside auditor, with no Solara
 * account and nothing to log in to.
 *
 * ## Why this is a script and not a fifth `vaid` verb
 *
 * `skill/src/cli.mjs` says of itself: "mint · present · verify · revoke. Nothing
 * else, and the omissions are the design." That is not decoration — every verb is
 * another thing an agent can call wrongly and another surface that has to stay in
 * step with a standard whose whole value is that three implementations agree byte
 * for byte. An evidence bundle is not a VAID; it is a report that *contains*
 * VAIDs. Verifying it is a different job with a different trust model, so it gets
 * a different program. `vaid verify` continues to do exactly one thing: verify a
 * VAID envelope. This script calls it (via the library, see step 5) for the VAIDs
 * inside the bundle and does the bundle-level work itself.
 *
 * ## Why it lives in this public repo
 *
 * So that an auditor can read it before running it. The auditor-facing page
 * publishes this file's SHA-256; anyone can check the copy they are about to run
 * is the copy that was published:
 *
 *     shasum -a 256 scripts/verify-evidence-bundle.mjs
 *
 * A verifier you have to take on trust from the party being audited is not a
 * verifier. See `scripts/README-verify-evidence-bundle.md`.
 *
 * ## Dependencies, deliberately almost none
 *
 * Steps a–d and f use only Node builtins, so `node scripts/verify-evidence-bundle.mjs
 * bundle.json` works in a bare clone with no `npm install`. Step e (the delegation
 * chain) needs the published `vaid-mint` SDK, because reimplementing VAID chain
 * verification here would be a fourth implementation with no conformance vector
 * holding it in line. If the SDK is not installed that step reports
 * **NOT CHECKED** — never "passed" — and says how to install it.
 *
 * `Finding`'s four states are redeclared here rather than imported from
 * `skill/src/verify-core.mjs` for exactly that reason: importing that module pulls
 * `vaid-mint` in at load time and would make the whole script undeployable in a
 * bare clone. The string values are identical so the two programs' output is
 * directly comparable, and verify-core remains the only implementation of the
 * VAID verdict itself.
 *
 * ## ===== THE CANONICAL FORM — reproduce this by hand ==================
 *
 * `content_hash` is checked by recomputing it. An auditor must be able to get the
 * same bytes with their own tools, so the rule is stated here exactly and is the
 * only canonicalization this script performs:
 *
 *   1. Take the bundle object and REMOVE exactly two top-level keys:
 *      `content_hash` and `signature`. Nothing else is removed, added or
 *      reordered at any other level.
 *   2. Serialize to JSON with:
 *        - object keys sorted ascending by JavaScript's default string sort,
 *          i.e. UTF-16 code-unit order (`Array.prototype.sort()` with no
 *          comparator — the same order `sort` gives in Python on the same
 *          strings for all-ASCII keys, which these are);
 *        - keys sorted RECURSIVELY, at every nesting depth;
 *        - array element order PRESERVED (arrays are ordered data: the audit
 *          chain and the delegation chain both mean something in sequence);
 *        - no whitespace of any kind — no spaces, no newlines, no indentation;
 *        - strings escaped exactly as `JSON.stringify` escapes them
 *          (RFC 8259; non-ASCII emitted literally as UTF-8, not \u-escaped);
 *        - keys whose value is `undefined` dropped, as JSON has no such value.
 *   3. Encode that string as UTF-8.
 *   4. SHA-256 those bytes. Lowercase hex. That is `content_hash`.
 *
 * Equivalent by hand, given a bundle on disk:
 *
 *     jq -S -c 'del(.content_hash, .signature)' bundle.json \
 *       | tr -d '\n' | shasum -a 256
 *
 * (`jq -S` sorts keys recursively; `-c` is compact. jq sorts by byte value, which
 * agrees with UTF-16 code-unit order for ASCII keys.)
 *
 * ## ===== WHERE THE TRUSTED KEY COMES FROM =============================
 *
 * The bundle's signature is verified with the substrate's Ed25519 kernel public
 * key. Taking that key from inside the bundle would establish nothing: whoever
 * could re-sign a tampered bundle could rewrite the key beside it. So the key is
 * obtained from sources OUTSIDE the bundle and cross-checked against each other.
 *
 * The two that matter are both STATIC PUBLICATIONS, reachable by anyone:
 *
 *   1. PINNED — a copy committed to this public repository, in
 *      `scripts/pinned-keys/`, changed only by reviewed pull request.
 *   2. SITE — a plain static JSON asset published on the UAB product's own public
 *      site, served alongside the public `/evidence/verify` auditor page with no
 *      IAM and no authentication (`--site-key-url`).
 *
 * Both must be present and must agree before the key is trusted for the signature
 * check. They are independent publishers: a substitution has to survive a reviewed
 * commit in this repo AND a deploy of the UAB site.
 *
 * The substrate's own live `GET /kernel/public-key` is an OPTIONAL THIRD VOTE
 * (`--kernel-url`), and it is for Solara's own operators, not for an auditor. The
 * substrate's Cloud Run service stays behind IAM permanently — a deliberate
 * product decision, not a gap — so an anonymous auditor can NEVER reach it. Its
 * omission is therefore the NORMAL, EXPECTED case and is reported as such, not as
 * a degradation. If it IS given it must agree with the two static sources; a third
 * source that contradicts them is not outvoted, it is a reason to stop.
 *
 * Disagreement among any sources that answered is a loud FAIL and no signature
 * check runs under any key. There is no majority vote: which key is right is a
 * human's decision.
 *
 * ## ===== THE ENTRY_HASH SCHEME (documented, not assumed) ================
 *
 * `entry_hash` is NOT canonical-JSON-of-the-row — that would be `content_hash`'s
 * scheme, applied to the wrong thing. It is `synthera-audit::hash::compute_entry_hash`
 * (synthera's `crates/synthera-audit/src/hash.rs:16-31`, documented in synthera's
 * `docs/evidence-bundle-v1.md`): a raw concatenation of five fields' bytes, hashed
 * as ONE stream —
 *
 *   sha256( prev_hash_bytes || event_type_bytes || json(agent_id)_bytes ||
 *           details.to_string()_bytes || recorded_at_bytes )
 *
 * `computeEntryHash` below implements exactly this. A `stub: true` row (another
 * tenant's bridging row — see `audit_entries[]` in that doc) carries none of
 * `event_type`/`agent_id`/`details` by construction, so its `entry_hash` cannot be
 * recomputed; that is reported as NOT CHECKED for that row, never a FAIL, and the
 * LINKAGE check (`prev_hash[i] == entry_hash[i-1]`, scheme-independent) still
 * covers it.
 *
 * ## ===== ASSUMPTIONS A REVIEWER MUST CHECK ============================
 *
 * Two things below are NOT pinned by a published contract this script can read.
 * They are named in the output as well as here, so a reviewer can tell at a glance
 * whether they are wrong, and so a reader of the output is never told something
 * was confirmed when it was only assumed:
 *
 *   ASSUMPTION 1 — what the signature covers. The bundle says `content_hash` is
 *   the hash of the content and `signature.sig_b64` is a signature. It does not
 *   say whether Ed25519 signed the 64-character lowercase hex STRING or the 32
 *   raw hash BYTES. This script tries both and reports which one verified. If
 *   neither does, that is a FAIL. Trying both cannot weaken the check: a forger
 *   still needs the private key for either message.
 *
 *   ASSUMPTION 2 — the response shape of both published key documents. The UAB
 *   site asset and `GET /kernel/public-key` are read by the SAME defensive parser:
 *   a bare JWK, a `{keys: {...}}` trust anchor, or an object carrying the key
 *   under one of several plausible names. If none match, that is NOT CHECKED with
 *   the response's top-level keys printed so the shape can be added in one line.
 *   The UAB asset's shape is not yet fixed by a published contract either, which
 *   is why it is parsed defensively rather than against one expected layout.
 *
 * ## Exit codes (documented, never inferred)
 *
 *   0  every check RAN, and none failed. Caveats may still be present and must be
 *      read — a caveat is a check that ran and established less than it looks
 *      like it did, which is not the same as one that did not run. (This matches
 *      `vaid verify`, where VALID WITH CAVEATS also exits 0.)
 *   1  a check RAN and FAILED — the bundle is rejected
 *   2  this script could not start: bad usage, or the file is unreadable
 *   3  nothing failed, but a check COULD NOT RUN. Not a pass. Not a failure.
 *   4  the input is not a well-formed evidence-bundle/v1 (named field reported)
 *
 * Run:
 *   node scripts/verify-evidence-bundle.mjs <bundle.json> \
 *     [--site-key-url https://<uab-site>/kernel-key.json] \
 *     [--pinned-key <path>] \
 *     [--kernel-url https://.../kernel/public-key]   # operators only \
 *     [--trust-anchor <path>] [--at <rfc3339>] [--json]
 */

import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// `store.mjs` imports nothing outside `node:*`, so reusing its base64url pair
// here costs no dependency and keeps one implementation of the encoding.
import { b64u, unb64u } from '../skill/src/store.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, '..');
const PINNED_DIR = join(HERE, 'pinned-keys');
const DEFAULT_ANCHOR = join(REPO, 'skill', 'trust-anchor.json');

const BUNDLE_VERSION = 'evidence-bundle/v1';
const THUMBPRINT_PREFIX = 'urn:ietf:params:oauth:jwk-thumbprint:sha-256:';
const FETCH_TIMEOUT_MS = 10_000;

/**
 * ===== UPDATE THIS ONCE THE REAL UAB DEPLOYMENT EXISTS =====================
 *
 * The second static publication of the kernel key: a plain JSON asset on the UAB
 * product's own public site, served next to the public `/evidence/verify` auditor
 * page with no IAM and no authentication, so an anonymous auditor can fetch it.
 *
 * The production URL is NOT FINALISED. This value is a deliberate placeholder and
 * is the ONE line to change when the real one exists. Two properties of it are
 * load-bearing:
 *
 *   - The `.invalid` TLD is reserved by RFC 2606 and can never resolve, so this
 *     constant can never silently send an auditor's verification run to a host
 *     somebody else controls.
 *   - It is compared by identity before any fetch is attempted (see
 *     `loadSiteKey`), so a run that was never given a real URL says exactly that
 *     instead of surfacing a DNS failure that reads like a site outage.
 *
 * Changing this to a real URL needs no other edit: the flag, the parsing and the
 * cross-check are all already pointed at it.
 */
const UAB_SITE_KEY_URL_PLACEHOLDER = 'https://uab-site-not-yet-deployed.invalid/kernel-key.json';

// --- the four states ---------------------------------------------------------
// Values identical to `skill/src/verify-core.mjs`'s `Finding` on purpose; see the
// header for why this is a redeclaration and not an import.
const Finding = {
  /** The check ran and passed. */
  Pass: 'pass',
  /** The check ran and failed. The bundle is rejected. */
  Fail: 'fail',
  /** The check ran, did not fail, but establishes less than it appears to. */
  Caveat: 'caveat',
  /** The check did not run, and this invocation cannot make it run. Never success. */
  NotChecked: 'not_checked',
};

// --- output ------------------------------------------------------------------
// Colour only when stdout is a TTY, as cli.mjs does: an agent capturing this gets
// clean text, a human gets a verdict readable at a glance.
const tty = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code) => (s) => (tty ? `\u001b[${code}m${s}\u001b[0m` : s);
const bold = c('1');
const dim = c('2');
const green = c('32');
const red = c('31');
const yellow = c('33');

const out = (s = '') => process.stdout.write(`${s}\n`);
const err = (s = '') => process.stderr.write(`${s}\n`);

/** The three states are visually distinct, so "unknown" can never read as "passed". */
const MARK = {
  [Finding.Pass]: () => green('✓ PASS      '),
  [Finding.Fail]: () => red('✗ FAIL      '),
  [Finding.Caveat]: () => yellow('! CAVEAT    '),
  [Finding.NotChecked]: () => dim('· NOT CHECKED'),
};

function die(msg, code = 2) {
  err(`${red('error')}: ${msg}`);
  process.exit(code);
}

function wrap(text, indent) {
  const width = Math.max(40, (process.stdout.columns || 80) - indent.length);
  const lines = [];
  let line = '';
  for (const w of String(text).split(/\s+/)) {
    if (line.length + w.length + 1 > width && line !== '') {
      lines.push(line);
      line = w;
    } else {
      line = line === '' ? w : `${line} ${w}`;
    }
  }
  if (line) lines.push(line);
  return lines.map((l) => indent + l).join('\n');
}

// --- args (same shape as cli.mjs's parser) -----------------------------------
function parseArgs(argv) {
  const flags = {};
  const positional = [];
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--') {
      positional.push(...argv.slice(i + 1));
      break;
    }
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq !== -1) {
        flags[a.slice(2, eq)] = a.slice(eq + 1);
      } else if (i + 1 < argv.length && !argv[i + 1].startsWith('--')) {
        flags[a.slice(2)] = argv[i + 1];
        i += 1;
      } else {
        flags[a.slice(2)] = true;
      }
    } else {
      positional.push(a);
    }
  }
  return { flags, positional };
}

// --- canonicalization --------------------------------------------------------
/**
 * The canonical form documented in the header. Read that comment, not this
 * function, if you are reproducing the hash by hand — and if the two ever
 * disagree, the comment is the contract and this is the bug.
 */
export function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const keys = Object.keys(value)
    .filter((k) => value[k] !== undefined)
    .sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
}

const sha256Hex = (bytes) => createHash('sha256').update(bytes).digest('hex');
const sha256Bytes = (bytes) => new Uint8Array(createHash('sha256').update(bytes).digest());
const utf8 = (s) => new TextEncoder().encode(s);

/** RFC 7638 JWK thumbprint of a raw 32-byte Ed25519 key, as an RFC 9278 URI. */
export function ed25519Thumbprint(raw32) {
  const canonical = `{"crv":"Ed25519","kty":"OKP","x":"${b64u(raw32)}"}`;
  return THUMBPRINT_PREFIX + Buffer.from(createHash('sha256').update(canonical).digest()).toString('base64url');
}

/** Wrap a raw 32-byte Ed25519 public key in the SPKI DER prefix node:crypto wants. */
function ed25519PublicKey(raw32) {
  const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(raw32)]);
  return createPublicKey({ key: spki, format: 'der', type: 'spki' });
}

// --- bundle parsing ----------------------------------------------------------
/**
 * The fields the checks below actually consume. Absence of any of them is
 * reported by NAME and stops the run with exit 4 — gate A5.7, a control that
 * cannot evaluate its subject must not return success. A stack trace would be a
 * worse version of the same refusal, so this is checked before anything is read.
 *
 * `policy_version` is deliberately NOT here: the contract allows it to be `null`,
 * and `null` is information (no policy bundle was in force), not a defect. It is
 * reported as a note. It is covered by `content_hash` either way.
 */
const REQUIRED = [
  'version',
  'scope',
  'tenant_id',
  'generated_at',
  'actor',
  'delegation_chain',
  'decisions',
  'audit_entries',
  'content_hash',
  'signature',
];

/** snake_case is the contract; a camelCase twin is accepted and reported. */
const ALIASES = {
  tenant_id: ['tenantId'],
  generated_at: ['generatedAt'],
  delegation_chain: ['delegationChain'],
  audit_entries: ['auditEntries'],
  content_hash: ['contentHash'],
  policy_version: ['policyVersion'],
};

/**
 * Resolve one documented field, accepting a camelCase twin.
 *
 * Returns `{ key, value }` naming the key actually found, so the output can say
 * `tenant_id (found as tenantId)` rather than silently normalising a format
 * difference that a reviewer reconciling three repos needs to see.
 */
function field(bundle, name) {
  if (Object.prototype.hasOwnProperty.call(bundle, name)) return { key: name, value: bundle[name] };
  for (const alt of ALIASES[name] ?? []) {
    if (Object.prototype.hasOwnProperty.call(bundle, alt)) return { key: alt, value: bundle[alt] };
  }
  return null;
}

// --- kernel key sources ------------------------------------------------------
/**
 * Pull a raw 32-byte Ed25519 public key out of whatever the substrate served.
 *
 * ASSUMPTION 2 in the header. Several shapes are accepted because the endpoint's
 * response is not pinned by a contract this repo can read; an unrecognised shape
 * is reported with the keys that WERE present, which is what makes it a one-line
 * fix rather than an investigation.
 */
export function extractEd25519Key(doc) {
  if (!doc || typeof doc !== 'object') return { error: 'the response is not a JSON object' };

  // (a) A trust-anchor document: { keys: { "<thumbprint uri>": <jwk> } }.
  if (doc.keys && typeof doc.keys === 'object' && !Array.isArray(doc.keys)) {
    const entries = Object.entries(doc.keys);
    if (entries.length === 0) return { error: 'the response has an empty "keys" map' };
    if (entries.length > 1) {
      return {
        error:
          `the response carries ${entries.length} keys. This script cross-checks ONE kernel key and will not ` +
          'guess which; name the thumbprint you expect and pin that key.',
      };
    }
    const [claimed, jwk] = entries[0];
    const inner = extractEd25519Key(jwk);
    if (inner.error) return inner;
    // The anchor's own documented check: recompute, never take the filing on trust.
    const actual = ed25519Thumbprint(inner.key);
    if (claimed.startsWith(THUMBPRINT_PREFIX) && actual !== claimed) {
      return {
        error:
          `the response files a key under ${claimed} but that key hashes to ${actual}. ` +
          'Anyone following the documented procedure would reject it. Failing closed.',
      };
    }
    return { key: inner.key, keyId: jwk.key_id ?? inner.keyId ?? null, shape: 'trust-anchor keys map' };
  }

  // (b) A bare Ed25519 OKP JWK.
  if (doc.kty === 'OKP' && typeof doc.x === 'string') {
    if (doc.crv !== 'Ed25519') return { error: `JWK crv is "${doc.crv}", not Ed25519` };
    const key = unb64u(doc.x);
    if (key.length !== 32) return { error: `JWK "x" decodes to ${key.length} bytes, not 32` };
    return { key, keyId: doc.key_id ?? doc.kid ?? null, shape: 'bare Ed25519 OKP JWK' };
  }

  // (c) The key under one of several plausible names, base64 or base64url.
  for (const name of ['public_key', 'publicKey', 'kernel_public_key', 'kernelPublicKey', 'key', 'ed25519']) {
    const v = doc[name];
    if (typeof v !== 'string' || v === '') continue;
    let key;
    try {
      key = unb64u(v);
    } catch {
      continue;
    }
    if (key.length !== 32) {
      return { error: `"${name}" decodes to ${key.length} bytes, not a 32-byte Ed25519 key` };
    }
    return { key, keyId: doc.key_id ?? doc.kid ?? doc.keyId ?? null, shape: `"${name}" (base64url)` };
  }

  return {
    error:
      'no Ed25519 public key found. Top-level keys present: ' +
      `${Object.keys(doc).map((k) => JSON.stringify(k)).join(', ') || '(none)'}. ` +
      'See ASSUMPTION 2 at the top of this script — add the shape there.',
  };
}

/**
 * The pinned copy of the kernel key, from this repo — the FIRST of the two static
 * publications the cross-check is built on.
 *
 * A MISSING pinned key is NOT a skip. The whole point of the pin is that the key
 * used to verify a bundle's own signature is cross-checked against a second,
 * independently published copy; with no pin there is no cross-check, and a run
 * that quietly dropped the check would report the same clean verdict as one that
 * performed it. So this returns a reason, the caller records NOT CHECKED, and the
 * exit code is never 0.
 */
function loadPinnedKey(explicitPath) {
  let path = explicitPath;
  if (!path) {
    if (!existsSync(PINNED_DIR)) {
      return { error: `no pinned-key directory at ${PINNED_DIR}` };
    }
    // `*.json` only. The shipped example is `*.json.example` precisely so that it
    // is documentation and cannot be loaded as if it were a real pin.
    const candidates = readdirSync(PINNED_DIR)
      .filter((f) => f.endsWith('.json'))
      .sort();
    if (candidates.length === 0) {
      return {
        error:
          `no pinned kernel key in ${PINNED_DIR} (it holds only the *.json.example template). ` +
          'Until a key is pinned there by PR review, this repo is not a publisher of the key and the ' +
          'two-publication cross-check cannot be performed — see scripts/pinned-keys/README.md.',
      };
    }
    if (candidates.length > 1) {
      return {
        error:
          `${candidates.length} pinned keys in ${PINNED_DIR} (${candidates.join(', ')}). ` +
          'Pass --pinned-key to name the one this bundle should be checked against; this script ' +
          'will not guess which pin applies.',
      };
    }
    path = join(PINNED_DIR, candidates[0]);
  }

  let doc;
  try {
    doc = JSON.parse(readFileSync(path, 'utf8'));
  } catch (e) {
    return { error: `cannot read the pinned key at ${path}: ${e.message}` };
  }
  const got = extractEd25519Key(doc);
  if (got.error) return { error: `the pinned key at ${path} is unusable: ${got.error}` };
  // A pin file may state the thumbprint it is filed under. Recompute it rather
  // than take the file's word: a key whose stated thumbprint is not its own is
  // either a typo or a substitution, and both must stop the run. This is the check
  // scripts/pinned-keys/README.md tells reviewers the verifier performs.
  if (typeof doc.thumbprint === 'string' && doc.thumbprint.startsWith(THUMBPRINT_PREFIX)) {
    const actual = ed25519Thumbprint(got.key);
    if (actual !== doc.thumbprint) {
      return {
        error:
          `the pinned key at ${path} is filed under ${doc.thumbprint} but hashes to ${actual}. ` +
          'Failing closed rather than cross-checking against a pin that does not describe itself.',
      };
    }
  }
  return { key: got.key, keyId: got.keyId, path, shape: got.shape };
}

/**
 * Fetch a PUBLISHED copy of the kernel key over HTTP(S), and extract it.
 *
 * Used for both network sources — the UAB site's static asset and the substrate's
 * live endpoint — because the two are read exactly alike (ASSUMPTION 2); nothing
 * here knows or cares which publisher it is talking to.
 *
 * A fetch with no timeout hangs forever on a blackholed host, so one is set.
 */
async function fetchPublishedKey(url) {
  let res;
  try {
    res = await fetch(url, {
      redirect: 'error',
      headers: { accept: 'application/json' },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
  } catch (e) {
    return { error: `could not reach ${url}: ${e.message ?? e}` };
  }
  if (!res.ok) return { error: `${url} answered HTTP ${res.status} ${res.statusText}` };
  let doc;
  try {
    doc = await res.json();
  } catch (e) {
    return { error: `${url} did not return parseable JSON: ${e.message}` };
  }
  const got = extractEd25519Key(doc);
  if (got.error) return { error: `${url}: ${got.error}` };
  return { key: got.key, keyId: got.keyId, shape: got.shape, url };
}

/**
 * The UAB site's static publication of the key — the second independent publisher.
 *
 * The placeholder is detected BEFORE any network call. Fetching a `.invalid` host
 * would produce a DNS failure, and a DNS failure reads as "the site is down" when
 * the truth is "nobody has told this script where the site is yet". Those are
 * different states and an auditor must not have to tell them apart from a stack of
 * resolver errors.
 */
async function loadSiteKey(explicitUrl) {
  const url = explicitUrl ?? UAB_SITE_KEY_URL_PLACEHOLDER;
  if (url === UAB_SITE_KEY_URL_PLACEHOLDER) {
    return {
      url,
      placeholder: true,
      error:
        `the UAB site key URL is still the built-in PLACEHOLDER (${url}), which is a reserved ` +
        '.invalid host and was deliberately NOT fetched. The real public URL does not exist yet. ' +
        'Pass --site-key-url <url>, or update UAB_SITE_KEY_URL_PLACEHOLDER in this script once the ' +
        'UAB site publishes the asset. This is a missing cross-check, not a site outage.',
    };
  }
  return fetchPublishedKey(url);
}

// --- the checks --------------------------------------------------------------
/**
 * Run every check over an already-parsed bundle and return the findings.
 *
 * Exported and `now`-parameterised for the same reason `verifyEnvelope` is: a
 * verdict a test cannot reproduce is a verdict nobody can audit.
 */
export async function verifyBundle(bundle, opts = {}) {
  const findings = [];
  const add = (id, label, state, detail) => findings.push({ id, label, state, detail });

  // --- (a) required fields, by name ------------------------------------------
  const missing = REQUIRED.filter((n) => field(bundle, n) === null);
  if (missing.length > 0) {
    return {
      malformed: true,
      missing,
      findings: [
        {
          id: 'shape',
          label: 'Bundle shape',
          state: Finding.Fail,
          detail:
            `required field${missing.length === 1 ? '' : 's'} absent: ${missing.join(', ')}. ` +
            'No verdict was reached and none can be: the fields the checks consume are not there. ' +
            'Failing closed rather than verifying a subset and reporting it as the whole.',
        },
      ],
    };
  }
  const renamed = REQUIRED.filter((n) => field(bundle, n).key !== n).map((n) => `${n} (found as ${field(bundle, n).key})`);

  const version = field(bundle, 'version').value;
  if (version !== BUNDLE_VERSION) {
    return {
      malformed: true,
      missing: [],
      findings: [
        {
          id: 'shape',
          label: 'Bundle shape',
          state: Finding.Fail,
          detail:
            `this script implements ${BUNDLE_VERSION} and the bundle declares ${JSON.stringify(version)}. ` +
            'Refusing rather than applying v1 rules to a format whose rules it does not know.',
        },
      ],
    };
  }

  const chain = field(bundle, 'delegation_chain').value;
  const decisions = field(bundle, 'decisions').value;
  const entries = field(bundle, 'audit_entries').value;
  const claimedHash = field(bundle, 'content_hash').value;
  const signature = field(bundle, 'signature').value;

  const shapeProblems = [];
  if (!Array.isArray(chain)) shapeProblems.push('delegation_chain is not an array');
  if (!Array.isArray(decisions)) shapeProblems.push('decisions is not an array');
  if (!Array.isArray(entries)) shapeProblems.push('audit_entries is not an array');
  if (typeof claimedHash !== 'string') shapeProblems.push('content_hash is not a string');
  if (!signature || typeof signature !== 'object') shapeProblems.push('signature is not an object');
  else {
    if (typeof signature.sig_b64 !== 'string') shapeProblems.push('signature.sig_b64 is not a string');
    if (signature.alg !== undefined && signature.alg !== 'ed25519') {
      shapeProblems.push(`signature.alg is ${JSON.stringify(signature.alg)}, and only "ed25519" is implemented`);
    }
  }
  if (shapeProblems.length > 0) {
    return {
      malformed: true,
      missing: [],
      findings: [
        {
          id: 'shape',
          label: 'Bundle shape',
          state: Finding.Fail,
          detail: `${shapeProblems.join('; ')}. Failing closed.`,
        },
      ],
    };
  }

  add(
    'shape',
    'Bundle shape',
    renamed.length > 0 ? Finding.Caveat : Finding.Pass,
    renamed.length > 0
      ? `all required fields present, but under non-contract names: ${renamed.join(', ')}. ` +
          'Read, and reported, because a silent rename between producer and verifier is how two ' +
          'programs come to disagree about the same bytes.'
      : `${BUNDLE_VERSION}, scope "${field(bundle, 'scope').value}", tenant "${field(bundle, 'tenant_id').value}", ` +
          `generated ${field(bundle, 'generated_at').value}. All required fields present. ` +
          `${chain.length} delegation entr${chain.length === 1 ? 'y' : 'ies'}, ${decisions.length} decision(s), ` +
          `${entries.length} audit entr${entries.length === 1 ? 'y' : 'ies'}.`,
  );

  // --- (b) content_hash ------------------------------------------------------
  // The one check an auditor is most likely to reproduce by hand, so the recomputed
  // value is always printed — including on a pass, so the hand-run has something
  // to compare against without re-running with a flag.
  const { content_hash: _ch, contentHash: _ch2, signature: _sig, ...signedPart } = bundle;
  const canonical = canonicalJson(signedPart);
  const recomputed = sha256Hex(utf8(canonical));
  const hashMatches = recomputed === String(claimedHash).toLowerCase();
  add(
    'content_hash',
    'Content hash',
    hashMatches ? Finding.Pass : Finding.Fail,
    hashMatches
      ? `recomputed over ${canonical.length} canonical bytes and it matches: ${recomputed}. ` +
          'Every field of the bundle except content_hash and signature is exactly as hashed.'
      : `MISMATCH. The bundle has been altered since it was hashed.\n` +
          `        claimed:    ${claimedHash}\n` +
          `        recomputed: ${recomputed}\n` +
          '        Reproduce by hand:  jq -S -c \'del(.content_hash, .signature)\' <bundle> | tr -d \'\\n\' | shasum -a 256',
  );

  // --- (c) the key, cross-checked across independent publications ------------
  // See "WHERE THE TRUSTED KEY COMES FROM" in the header. Two STATIC publishers
  // gate the check; the live substrate endpoint is an optional operator-only third
  // vote whose absence is the normal case, because its Cloud Run service stays
  // behind IAM and an anonymous auditor cannot reach it.
  const pinned = loadPinnedKey(opts.pinnedKey);
  const site = await loadSiteKey(opts.siteKeyUrl);
  const live = opts.kernelUrl ? await fetchPublishedKey(opts.kernelUrl) : { error: null, absent: true };

  const sources = [
    {
      id: 'pinned',
      gating: true,
      what: 'pinned copy committed to this public repo',
      where: pinned.path ?? opts.pinnedKey ?? PINNED_DIR,
      got: pinned,
    },
    {
      id: 'site',
      gating: true,
      what: "static asset published on the UAB product's public site",
      where: site.url ?? UAB_SITE_KEY_URL_PLACEHOLDER,
      got: site,
    },
    {
      id: 'live',
      gating: false,
      what: 'live substrate endpoint — OPERATOR ONLY, behind Cloud Run IAM',
      where: opts.kernelUrl ?? '(not requested)',
      got: live,
    },
  ];

  /**
   * Byte equality of the raw 32-byte keys, and equality of their RFC 7638
   * thumbprints. The second is implied by the first — the thumbprint is a pure
   * function of those bytes — so this is a redundant check stated explicitly
   * because the model calls for comparing both. It is NOT two independent facts,
   * and nothing should be reported as if it were.
   */
  const agrees = (a, b) =>
    a.got.key.length === b.got.key.length &&
    a.got.key.every((byte, i) => byte === b.got.key[i]) &&
    ed25519Thumbprint(a.got.key) === ed25519Thumbprint(b.got.key);

  const answered = sources.filter((s) => s.got.key);
  const silent = sources.filter((s) => !s.got.key);
  const gatingAnswered = answered.filter((s) => s.gating);

  const tpOf = (s) => ed25519Thumbprint(s.got.key);
  const answeredLine = (s) =>
    `        ${s.id.padEnd(6)} ${s.where}\n` +
    `               ${tpOf(s)}${s.got.shape ? `  (${s.got.shape})` : ''}`;
  const whyNot = (s) => {
    if (s.id === 'live' && s.got.absent) {
      return (
        'not requested (no --kernel-url). EXPECTED: the substrate stays behind Cloud Run IAM by ' +
        'design, so an external auditor cannot reach it. This is not a degraded run.'
      );
    }
    return s.got.error ?? 'no key';
  };
  const silentLines = () => silent.map((s) => `        ${s.id.padEnd(6)} ${whyNot(s)}`).join('\n');

  let trustedKey = null;
  // Disagreement is tested across EVERY source that answered, before the gating
  // question, and deliberately without regard to how many agreed: a third source
  // that contradicts two others is not outvoted. Majority rule here would let the
  // script quietly pick a key, which is the one thing it must never do.
  const dissenting = answered.filter((s) => !agrees(s, answered[0]));

  if (dissenting.length > 0) {
    add(
      'key_crosscheck',
      'Kernel key cross-check',
      Finding.Fail,
      `SOURCES DISAGREE ABOUT THE SIGNING KEY. Refusing to pick one.\n` +
        `${answered.map(answeredLine).join('\n')}\n` +
        '        No signature check was performed under any of these keys. There is no majority ' +
        'vote: either a key was rotated and one publication is stale, or one of them is serving a ' +
        'key nobody reviewed. Which is which is a human decision, not this script\'s.' +
        (silent.length > 0 ? `\n        Did not answer:\n${silentLines()}` : ''),
    );
  } else if (gatingAnswered.length === 2) {
    trustedKey = gatingAnswered[0].got.key;
    const liveNote = live.key
      ? '        The live substrate endpoint was ALSO checked and agrees — a third, independent vote.'
      : `        The live substrate endpoint was NOT checked: ${whyNot(sources[2])}`;
    add(
      'key_crosscheck',
      'Kernel key cross-check',
      Finding.Pass,
      `TWO INDEPENDENT STATIC PUBLICATIONS agree on the signing key.\n` +
        `${answered.map(answeredLine).join('\n')}\n` +
        '        The key was NOT taken from inside the bundle being verified. A producer able to ' +
        're-sign a tampered bundle would also have to change a reviewed commit in this public repo ' +
        'AND the static asset deployed on the UAB site — two separate publishers.\n' +
        liveNote,
    );
  } else if (answered.length > 0) {
    // Something answered, but not both gating publications. The signature is still
    // checked under what we have — that establishes the bundle was signed by
    // whoever holds that key, which is less than, and must not be reported as, the
    // cross-check having been performed.
    trustedKey = answered[0].got.key;
    const missing = sources.filter((s) => s.gating && !s.got.key);
    add(
      'key_crosscheck',
      'Kernel key cross-check',
      Finding.NotChecked,
      `CROSS-CHECK INCOMPLETE — the two static publications were not both available, so they were ` +
        `never compared.\n` +
        `        Answered:\n${answered.map(answeredLine).join('\n')}\n` +
        `        Missing (required for the cross-check):\n` +
        `${missing.map((s) => `        ${s.id.padEnd(6)} ${whyNot(s)}`).join('\n')}\n` +
        '        The signature check below used the key above, so it still establishes that the ' +
        'bundle was signed by whoever holds that key — but NOT that that party is the Solara ' +
        'substrate, because only one publisher vouched for it. This is not a pass.' +
        (live.key && answered.length > 1
          ? '\n        The live endpoint agreed with the source above, which is reassuring and is ' +
            'still not the published cross-check: it is a source an external auditor cannot reach ' +
            'and cannot reproduce.'
          : ''),
    );
  } else {
    add(
      'key_crosscheck',
      'Kernel key cross-check',
      Finding.NotChecked,
      `NO SOURCE yielded a key, so there is nothing to verify the signature with.\n${silentLines()}`,
    );
  }

  // --- (d) the manifest signature --------------------------------------------
  // How the key was established decides how this finding may describe itself. With
  // the cross-check incomplete, "the cross-checked key" would be a claim the run
  // did not earn, so the phrase is chosen from what actually happened.
  const keyProvenance =
    gatingAnswered.length === 2
      ? 'the cross-checked kernel key'
      : 'the ONLY available copy of the kernel key (cross-check incomplete — see above)';
  if (!trustedKey) {
    add(
      'signature',
      'Manifest signature',
      Finding.NotChecked,
      'no kernel key was obtained (see above), so the signature was NOT verified. ' +
        'It is not invalid; it is unchecked, and those are different things.',
    );
  } else if (!hashMatches) {
    // Verifying a signature over a hash that does not match the content would
    // produce a true "the signature is valid" beside a tampered bundle — the exact
    // conflation that makes a plural verdict necessary. Say why it was skipped.
    add(
      'signature',
      'Manifest signature',
      Finding.NotChecked,
      'SKIPPED because content_hash does not match the content. A valid signature over a hash that ' +
        'does not describe the bundle would be a true statement about nothing. Fix the content_hash ' +
        'failure first.',
    );
  } else {
    let sig;
    try {
      sig = unb64u(signature.sig_b64);
    } catch {
      sig = null;
    }
    if (!sig || sig.length !== 64) {
      add(
        'signature',
        'Manifest signature',
        Finding.Fail,
        `signature.sig_b64 decodes to ${sig ? sig.length : 'un-decodable'} bytes; an Ed25519 signature is 64.`,
      );
    } else {
      const key = ed25519PublicKey(trustedKey);
      // ASSUMPTION 1: which message was signed. Both candidates are tried and the
      // winner is named; a forger needs the private key for either one.
      const candidates = [
        ['the 64-character lowercase hex content_hash string', utf8(recomputed)],
        ['the 32 raw bytes of the content_hash', sha256Bytes(utf8(canonical))],
      ];
      const hit = candidates.find(([, msg]) => cryptoVerify(null, msg, key, sig));
      if (hit) {
        add(
          'signature',
          'Manifest signature',
          Finding.Pass,
          `Ed25519 signature verifies under ${keyProvenance}, over ${hit[0]}.\n` +
            `        key: ${ed25519Thumbprint(trustedKey)}\n` +
            `${signature.key_id ? `        bundle names key_id ${signature.key_id}\n` : ''}` +
            '        ASSUMPTION 1 at the top of this script: the signed message was not pinned by a ' +
            'published contract, so both candidates were tried and the one that verified is named above.',
        );
      } else {
        add(
          'signature',
          'Manifest signature',
          Finding.Fail,
          `the Ed25519 signature does NOT verify under ${keyProvenance}, over either ` +
            'candidate message (the hex content_hash string, or its 32 raw bytes). The bundle was not ' +
            'signed by the holder of that key, or the signature has been altered. ' +
            `key tried: ${ed25519Thumbprint(trustedKey)}.`,
        );
      }
    }
  }

  // --- (e) the delegation chain, via the EXISTING verifier --------------------
  findings.push(await delegationFinding(bundle, chain, opts));

  // --- (f) the audit hash chain ----------------------------------------------
  findings.push(...auditChainFindings(entries));

  // --- notes that are not checks ---------------------------------------------
  const policy = field(bundle, 'policy_version');
  const pv = policy?.value ?? null;
  add(
    'policy_version',
    'Policy version',
    pv === null || pv === undefined ? Finding.Caveat : Finding.Pass,
    pv === null || pv === undefined
      ? 'the bundle carries no policy_version. Covered by content_hash either way, so this is not a ' +
          'tampering signal — it records that no policy bundle was named for this scope, which is ' +
          'itself something an auditor should see rather than have normalised away.'
      : `${pv.bundle_name ?? '(unnamed)'} ${pv.semver ?? '(no semver)'}, bundle_hash ${pv.bundle_hash ?? '(none)'}. ` +
          'Reported, NOT verified: this script has no copy of that policy bundle to hash, so it cannot ' +
          'confirm the hash describes the policy that was actually in force.',
  );

  return { malformed: false, missing: [], findings };
}

/**
 * A `delegation_chain` entry can be one of two SHAPES, and they must not be
 * verified the same way:
 *
 *   - a real, signed VAID envelope (a string, or an object carrying
 *     `kernel_key_thumbprint` and the rest of the envelope body) — check it
 *     with `verifyEnvelope`, same as `vaid verify`.
 *   - a LEDGER REFERENCE — `synthera-audit`'s own `delegation_chain_note`
 *     says the audit ledger "does NOT record VAID envelope bytes or the
 *     issuer's lineage_hash", so a chain built from `vaid_minted` ledger rows
 *     carries only `{vaid_id, parent_vaid, agent_class, tenant_id,
 *     recorded_at, seq, entry_hash}` — never `kernel_key_thumbprint`, never a
 *     signature. Feeding one of these into `verifyEnvelope` always lands on
 *     "Signing key: no kernel key named" — a wrong-entry-point FAIL that
 *     looks like a forged lineage and is not one (REPORT-s494 item 5).
 *
 * A ledger reference is reported as NOT CHECKED, naming itself as a reference
 * and pointing at `delegation_chain_note` — never run through `verifyEnvelope`
 * and never FAILED as a bad envelope.
 */
function isLedgerReferenceEntry(entry) {
  return (
    entry !== null &&
    typeof entry === 'object' &&
    !Array.isArray(entry) &&
    entry.seq !== undefined &&
    typeof entry.entry_hash === 'string' &&
    entry.kernel_key_thumbprint === undefined
  );
}

/**
 * Step (e): verify every VAID in `delegation_chain` with the SAME code
 * `vaid verify` runs.
 *
 * The library is called directly rather than spawning `skill/src/cli.mjs verify`
 * against a temp file: the types line up exactly — `verifyEnvelope` takes the
 * string form these entries already are (or JSON.stringify of the object form,
 * which `parseEnvelope` reads as a bare document) — so a subprocess would add a
 * temp file and a process boundary and buy nothing. The equivalent CLI invocation,
 * for anyone who prefers to see it run as a separate program:
 *
 *     node skill/src/cli.mjs verify '<the envelope>' --at <generated_at>
 *
 * The import is dynamic because `verify-core.mjs` pulls in `vaid-mint`, which a
 * bare clone has not installed. An absent SDK makes this NOT CHECKED, never a pass.
 */
async function delegationFinding(bundle, chain, opts) {
  const noteField = field(bundle, 'delegation_chain_note');
  const note = noteField ? String(noteField.value) : null;

  if (chain.length === 0) {
    return {
      id: 'delegation',
      label: 'Delegation chain',
      state: Finding.NotChecked,
      detail: note
        ? `NO raw VAID envelopes were exported, and the bundle says why: "${note}". ` +
          'That explanation is signed (it is covered by content_hash), so it is the exporter on the ' +
          'record rather than an unexplained gap — but the actor\'s authority is UNVERIFIED here, ' +
          'which is not the same as unconstrained and not the same as confirmed.'
        : 'delegation_chain is EMPTY and there is no delegation_chain_note saying why. Nothing was ' +
          'verified and nothing explains the absence. An exporter that could not recover the lineage ' +
          'is required to say so in delegation_chain_note; a bundle with neither is indistinguishable ' +
          'from one whose chain was dropped.',
    };
  }

  const referenceCount = chain.filter(isLedgerReferenceEntry).length;
  const envelopeEntries = chain.filter((e) => !isLedgerReferenceEntry(e));

  // Every entry is a ledger reference — nothing here is a VAID envelope, so
  // there is nothing `verifyEnvelope` (or the SDK it needs) could check.
  if (envelopeEntries.length === 0) {
    return {
      id: 'delegation',
      label: 'Delegation chain',
      state: Finding.NotChecked,
      detail:
        `${referenceCount} ledger reference(s), NOT VAID envelopes. The audit ledger does not record ` +
        'envelope bytes or the issuer\'s lineage_hash — only chain-position references — so there is ' +
        'nothing here for `verifyEnvelope` to check; running it anyway reports a wrong-entry-point FAIL ' +
        'that looks like a forged lineage and is not one. ' +
        (note
          ? `delegation_chain_note: "${note}"`
          : 'No delegation_chain_note explains this; a bundle whose chain is references with no note ' +
            'leaves an auditor unable to tell a documented limitation from a dropped explanation.') +
        '\n        Verify the real envelopes against the VAID issuer, out of band, not against this bundle.',
    };
  }

  let mod;
  let anchorDoc;
  try {
    mod = await import('../skill/src/verify-core.mjs');
    anchorDoc = JSON.parse(readFileSync(opts.trustAnchor ?? DEFAULT_ANCHOR, 'utf8'));
  } catch (e) {
    return {
      id: 'delegation',
      label: 'Delegation chain',
      state: Finding.NotChecked,
      detail:
        `${envelopeEntries.length} envelope-shaped entr${envelopeEntries.length === 1 ? 'y' : 'ies'} present, ` +
        `NOT verified: the VAID verifier could not be loaded (${e.message}). This script does not ` +
        'reimplement VAID chain verification — a fourth implementation with no conformance vector holding ' +
        'it in line would be worse than an honest gap. Install the SDK and re-run:  npm install --prefix skill' +
        (referenceCount > 0 ? ` (${referenceCount} ledger reference(s) in this chain are not envelopes either way)` : ''),
    };
  }

  let anchor;
  try {
    anchor = mod.loadAnchor(anchorDoc);
  } catch (e) {
    return {
      id: 'delegation',
      label: 'Delegation chain',
      state: Finding.NotChecked,
      detail: `the trust anchor could not be loaded, so no VAID was verified: ${e.message}`,
    };
  }

  const at = opts.at ?? new Date(String(field(bundle, 'generated_at').value));
  const when = Number.isNaN(at.getTime()) ? new Date() : at;

  const lines = [];
  let failed = 0;
  let caveated = 0;
  let verified = 0;
  for (let i = 0; i < chain.length; i += 1) {
    const entry = chain[i];

    // Ledger references never reach `verifyEnvelope` — they name themselves as
    // references and point at delegation_chain_note, and are never FAILED as a
    // bad envelope (REPORT-s494 item 5).
    if (isLedgerReferenceEntry(entry)) {
      lines.push(
        `        [${i}] ${dim('·')} NOT CHECKED — ledger reference, not a VAID envelope ` +
          `(vaid_id=${entry.vaid_id ?? '(none)'}, seq=${entry.seq}). Verify the real envelope against ` +
          'the VAID issuer, out of band.',
      );
      continue;
    }

    const input = typeof entry === 'string' ? entry : JSON.stringify(entry);
    let r;
    try {
      r = mod.verifyEnvelope(input, anchor, when);
    } catch (e) {
      failed += 1;
      lines.push(`        [${i}] ${red('✗')} threw: ${e.message}`);
      continue;
    }
    verified += 1;
    const id = r.vaid?.vaid_id ?? '(no vaid_id)';
    if (r.headline === mod.Headline.Valid) {
      lines.push(`        [${i}] ${green('✓')} ${r.headline.toUpperCase()}  ${id}`);
    } else if (r.headline === mod.Headline.ValidWithCaveats) {
      caveated += 1;
      const why = r.findings.filter((f) => f.state === mod.Finding.Caveat).map((f) => f.label).join(', ');
      lines.push(`        [${i}] ${yellow('!')} VALID WITH CAVEATS (${why})  ${id}`);
    } else {
      failed += 1;
      const why = r.findings.filter((f) => f.state === mod.Finding.Fail).map((f) => f.label).join(', ');
      lines.push(`        [${i}] ${red('✗')} ${r.headline.toUpperCase()}${why ? ` (${why})` : ''}  ${id}  — ${r.summary}`);
    }
  }

  const header =
    `${chain.length} entr${chain.length === 1 ? 'y' : 'ies'}: ${verified} envelope-shaped, each verified with the ` +
    `same code \`vaid verify\` runs (verifyEnvelope from skill/src/verify-core.mjs), at ${when.toISOString()}, ` +
    `against ${opts.trustAnchor ?? DEFAULT_ANCHOR}` +
    (referenceCount > 0 ? `; ${referenceCount} ledger reference(s), not checked (see lines below)` : '') +
    '.';
  const revocation =
    '\n        Revocation was NOT checked for any verified envelope, and cannot be: there is no published ' +
    'revocation list to consult. Read this as "genuinely issued and in date", never as "currently authorised".';

  // A ledger reference never contributes a PASS — only the envelopes actually
  // checked can. Some envelopes checked clean and the rest of the chain is
  // references: that is NOT CHECKED (part of the chain is unverified), not a
  // pass, unless every entry in the chain was a real envelope.
  const allEnvelopesVerified = referenceCount === 0;
  return {
    id: 'delegation',
    label: 'Delegation chain',
    state:
      failed > 0
        ? Finding.Fail
        : caveated > 0
          ? Finding.Caveat
          : allEnvelopesVerified
            ? Finding.Pass
            : Finding.NotChecked,
    detail: `${header}\n${lines.join('\n')}${revocation}`,
  };
}

/**
 * The REAL `entry_hash` scheme (synthera-audit's `hash::compute_entry_hash`,
 * documented in synthera's `docs/evidence-bundle-v1.md`): a raw concatenation
 * of five fields' bytes, hashed as ONE stream — NOT canonical JSON of the
 * whole row (that is `content_hash`'s scheme, a different one).
 *
 *   sha256( prev_hash_bytes || event_type_bytes || json(agent_id)_bytes ||
 *           details.to_string()_bytes || recorded_at_bytes )
 *
 * `agent_id` is JSON-serialized exactly as the row carries it (a quoted
 * string, or the four bytes `null`). `details` is hashed as its own
 * `JSON.stringify` (no inserted whitespace) — NOT the canonical form
 * `canonicalJson` produces, which is a different, deliberately incompatible
 * serialization used only for `content_hash`. This reproduces
 * `serde_json::Value::to_string()` byte-for-byte only because `details` is
 * exported verbatim, key order and all, by the same substrate that hashed it.
 *
 * A `stub: true` row carries none of `event_type`/`agent_id`/`details` — by
 * design, so another tenant's row is never exposed — so its `entry_hash`
 * cannot be recomputed this way. That is reported as NOT CHECKED for that
 * row alone; the LINKAGE check below still applies to it, scheme-independent.
 */
export function computeEntryHash(e) {
  const h = createHash('sha256');
  h.update(utf8(String(e.prev_hash)));
  h.update(utf8(String(e.event_type)));
  const agentIdJson = e.agent_id === undefined || e.agent_id === null ? 'null' : JSON.stringify(e.agent_id);
  h.update(utf8(agentIdJson));
  h.update(utf8(JSON.stringify(e.details)));
  h.update(utf8(String(e.recorded_at)));
  return h.digest('hex');
}

/**
 * Step (f): the audit hash chain.
 *
 * Two findings, kept apart on purpose. The LINKAGE check needs no knowledge of
 * the hash function and so fails hard, and applies to EVERY row including a
 * `stub: true` bridging row (see `docs/evidence-bundle-v1.md` in the
 * substrate's repo: a tenant export is a sparse subset of one global,
 * cross-tenant chain, and a stub row bridges another tenant's position with
 * only its two hashes, never its content). The entry_hash RECOMPUTATION runs
 * the real documented scheme (`computeEntryHash` above) over every non-stub
 * row and reports a genuine mismatch as FAIL; a stub row is skipped (NOT
 * CHECKED for that row specifically) because it carries none of that scheme's
 * inputs by construction, not because the scheme is in doubt.
 */
export function auditChainFindings(entries) {
  if (entries.length === 0) {
    return [
      {
        id: 'audit_linkage',
        label: 'Audit chain linkage',
        state: Finding.NotChecked,
        detail:
          'audit_entries is EMPTY. There is no chain to check, so this is not a pass — an empty list ' +
          'and an intact chain are the same green tick if you let them be. A bundle whose scope ' +
          'produced no audit entries should be read with that in mind.',
      },
    ];
  }

  const linkProblems = [];
  const hashProblems = [];
  const notRecomputable = [];
  const sorted = [...entries];

  for (let i = 0; i < sorted.length; i += 1) {
    const e = sorted[i];
    if (!e || typeof e !== 'object') {
      linkProblems.push(`[${i}] is not an object`);
      continue;
    }
    for (const n of ['entry_hash', 'prev_hash', 'seq']) {
      if (e[n] === undefined) linkProblems.push(`[${i}] has no ${n}`);
    }

    // Linkage: scheme-independent, so this is a hard check.
    if (i > 0) {
      const prev = sorted[i - 1];
      if (e.prev_hash !== prev?.entry_hash) {
        linkProblems.push(
          `[${i}] (seq ${e.seq}) prev_hash ${e.prev_hash} does not equal [${i - 1}] (seq ${prev?.seq}) ` +
            `entry_hash ${prev?.entry_hash} — the chain is BROKEN here`,
        );
      }
      if (typeof e.seq === 'number' && typeof prev?.seq === 'number' && e.seq !== prev.seq + 1) {
        linkProblems.push(
          `[${i}] seq ${e.seq} does not follow [${i - 1}] seq ${prev.seq} — ${
            e.seq > prev.seq + 1 ? `${e.seq - prev.seq - 1} entr(y|ies) MISSING from this bundle` : 'out of order'
          }`,
        );
      }
    }

    // entry_hash, under the REAL documented scheme (computeEntryHash above).
    // A stub row, or a row from a producer that predates agent_id/details
    // being exported, carries none of this scheme's inputs by construction —
    // that is NOT RECOMPUTABLE, not a hash mismatch, and is never attempted.
    if (typeof e.entry_hash === 'string') {
      if (e.stub === true || e.details === undefined || typeof e.event_type !== 'string') {
        notRecomputable.push(i);
      } else {
        const recomputed = computeEntryHash(e);
        if (recomputed !== e.entry_hash.toLowerCase()) {
          hashProblems.push(`[${i}] (seq ${e.seq}) claims ${e.entry_hash}, real scheme gives ${recomputed}`);
        }
      }
    }
  }

  const signedCount = sorted.filter((e) => e?.signed === true).length;
  const findings = [
    {
      id: 'audit_linkage',
      label: 'Audit chain linkage',
      state: linkProblems.length > 0 ? Finding.Fail : Finding.Pass,
      detail:
        linkProblems.length > 0
          ? `${linkProblems.length} problem(s). This check does NOT depend on the hash function, so these ` +
            `are real breaks, not a scheme disagreement:\n        ${linkProblems.join('\n        ')}`
          : `${sorted.length} entries link head to tail: every prev_hash equals the preceding entry_hash and ` +
            `seq increases by exactly one from ${sorted[0].seq} to ${sorted[sorted.length - 1].seq}. ` +
            `${signedCount} of ${sorted.length} are marked signed:true — a bundle whose entries are mostly ` +
            'signed:false carries entries no key vouches for, which the linkage check cannot tell you.',
    },
  ];

  const recomputedCount = sorted.length - notRecomputable.length;
  const skipNote =
    notRecomputable.length > 0
      ? ` ${notRecomputable.length} row(s) carry no agent_id/details to recompute from (stub rows, or a ` +
        'bundle from before this field was exported) and were skipped, not failed.'
      : '';

  if (hashProblems.length > 0) {
    findings.push({
      id: 'audit_entry_hash',
      label: 'Audit entry hashes',
      state: Finding.Fail,
      detail:
        `${hashProblems.length} of ${recomputedCount} recomputable entry_hash values do NOT reproduce under ` +
        'the documented scheme — sha256(prev_hash || event_type || json(agent_id) || details.to_string() || ' +
        `recorded_at), raw concatenation, one hash. This is a real mismatch, not a scheme disagreement: a ` +
        `verifier that recomputes with no data of its own and still disagrees means the row changed after ` +
        `it was hashed.${skipNote}\n        ${hashProblems.slice(0, 5).join('\n        ')}` +
        (hashProblems.length > 5 ? `\n        … and ${hashProblems.length - 5} more` : ''),
    });
  } else if (recomputedCount === 0) {
    findings.push({
      id: 'audit_entry_hash',
      label: 'Audit entry hashes',
      state: Finding.NotChecked,
      detail:
        `none of the ${sorted.length} row(s) in this bundle carry the agent_id/details the documented ` +
        'entry_hash scheme needs — every row is a stub, or this bundle predates that export. The LINKAGE ' +
        'finding above is independent of this and still ran.',
    });
  } else if (notRecomputable.length > 0) {
    findings.push({
      id: 'audit_entry_hash',
      label: 'Audit entry hashes',
      state: Finding.Caveat,
      detail:
        `all ${recomputedCount} recomputable entry_hash values reproduce under the documented scheme — ` +
        'sha256(prev_hash || event_type || json(agent_id) || details.to_string() || recorded_at), raw ' +
        `concatenation, one hash.${skipNote}`,
    });
  } else {
    findings.push({
      id: 'audit_entry_hash',
      label: 'Audit entry hashes',
      state: Finding.Pass,
      detail:
        `all ${sorted.length} entry_hash values reproduce under the documented scheme — sha256(prev_hash ` +
        '|| event_type || json(agent_id) || details.to_string() || recorded_at), raw concatenation, one ' +
        'hash, as synthera-audit\'s hash::compute_entry_hash computes it.',
    });
  }
  return findings;
}

// --- verdict -----------------------------------------------------------------
export function exitCodeFor(result) {
  if (result.malformed) return 4;
  if (result.findings.some((f) => f.state === Finding.Fail)) return 1;
  if (result.findings.some((f) => f.state === Finding.NotChecked)) return 3;
  return 0;
}

const VERDICT = {
  0: () => green(bold('VERIFIED')),
  1: () => red(bold('REJECTED')),
  3: () => yellow(bold('INCOMPLETE — NOT VERIFIED')),
  4: () => red(bold('NOT AN EVIDENCE BUNDLE')),
};

const SUMMARY = {
  0: 'Every check ran; none failed. Read any CAVEAT lines below.',
  1: 'A check ran and failed. Do not rely on this bundle.',
  3: 'Nothing failed, but a check could not run — so nothing here says "verified".',
  4: 'The input is not a well-formed evidence-bundle/v1.',
};

function printResult(result, code) {
  out();
  out(`  ${VERDICT[code]()}  ${SUMMARY[code]}`);
  out();
  for (const f of result.findings) {
    out(`  ${MARK[f.state]()}  ${bold(f.label)}`);
    for (const para of String(f.detail).split('\n')) {
      out(para.startsWith('        ') ? dim(para) : dim(wrap(para, '        ')));
    }
    out();
  }
  if (code === 3) {
    out(
      yellow(
        wrap(
          'NOT CHECKED is not a pass. Each line above marked NOT CHECKED is a question this run could ' +
            'not answer, and the exit code is 3 rather than 0 so that no script calling this one can ' +
            'mistake an unanswered question for a clean bill of health.',
          '  ',
        ),
      ),
    );
    out();
  }
}

const USAGE = `${bold('verify-evidence-bundle')} — verify an ${BUNDLE_VERSION} offline.

  node scripts/verify-evidence-bundle.mjs <bundle.json> [options]

  ${bold('The key cross-check')}   The signing key is taken from TWO independent STATIC
                       publications and trusted only if they agree:

  ${bold('--site-key-url')} <url>    The key as published on the UAB product's own public site —
                           a plain static JSON asset, no login, no IAM.
                           Default: ${UAB_SITE_KEY_URL_PLACEHOLDER}
                           which is a PLACEHOLDER (reserved .invalid host, never
                           fetched). The real URL does not exist yet; until it does,
                           pass this flag or the cross-check reports NOT CHECKED.
  ${bold('--pinned-key')} <path>     The key as committed to this public repo, changed only by
                           reviewed PR. Default: the single *.json in
                           scripts/pinned-keys/.

  ${bold('--kernel-url')} <url>      OPTIONAL THIRD VOTE, FOR SOLARA OPERATORS ONLY. The
                           substrate's live GET /kernel/public-key. Its Cloud Run
                           service stays behind IAM by design, so an external auditor
                           cannot reach it and is NOT expected to pass this. Omitting
                           it is the normal case and is reported as such, not as an
                           error. If given, it must AGREE with the two static sources
                           or the run fails loudly — there is no majority vote.
  ${bold('--trust-anchor')} <path>   Trust anchor for the VAIDs in delegation_chain.
                           Default: skill/trust-anchor.json (the published anchor).
  ${bold('--at')} <rfc3339>          Evaluate VAID expiry at this instant instead of the
                           bundle's generated_at. A verdict a test cannot reproduce is a
                           verdict nobody can audit.
  ${bold('--json')}                  Emit the findings as JSON instead of prose.

  ${bold('Exit codes')}   0 every check RAN and none failed (caveats possible — read them)
               1 a check ran and FAILED · 2 could not start
               3 a check could NOT RUN — not a pass · 4 not a well-formed bundle

  Check this script before running it — its SHA-256 is published on the
  auditor-facing page:   shasum -a 256 scripts/verify-evidence-bundle.mjs
`;

async function main() {
  const { flags, positional } = parseArgs(process.argv.slice(2));
  if (flags.help || positional[0] === 'help') {
    out(USAGE);
    process.exit(0);
  }
  const path = positional[0];
  if (!path) {
    out(USAGE);
    die('no bundle given. Pass the path to a bundle.json.');
  }

  let raw;
  try {
    raw = readFileSync(resolve(path), 'utf8');
  } catch (e) {
    die(`cannot read ${path}: ${e.message}`);
  }
  let bundle;
  try {
    bundle = JSON.parse(raw);
  } catch (e) {
    die(`${path} is not parseable JSON: ${e.message}`);
  }
  if (!bundle || typeof bundle !== 'object' || Array.isArray(bundle)) {
    die(`${path} is not a JSON object`, 4);
  }

  const at = flags.at ? new Date(String(flags.at)) : undefined;
  if (at && Number.isNaN(at.getTime())) die('--at is not a parseable timestamp');

  const result = await verifyBundle(bundle, {
    siteKeyUrl: typeof flags['site-key-url'] === 'string' ? flags['site-key-url'] : undefined,
    kernelUrl: typeof flags['kernel-url'] === 'string' ? flags['kernel-url'] : undefined,
    pinnedKey: typeof flags['pinned-key'] === 'string' ? flags['pinned-key'] : undefined,
    trustAnchor: typeof flags['trust-anchor'] === 'string' ? flags['trust-anchor'] : undefined,
    at,
  });
  const code = exitCodeFor(result);

  if (flags.json) {
    out(JSON.stringify({ verdict: code === 0 ? 'verified' : code === 1 ? 'rejected' : code === 4 ? 'malformed' : 'incomplete', exit_code: code, findings: result.findings, missing_fields: result.missing }, null, 2));
  } else {
    printResult(result, code);
  }
  process.exit(code);
}

// Only run when invoked as a program, so the test suite can import the checks.
if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  main().catch((e) => die(e?.stack ?? String(e), 2));
}

export { Finding, UAB_SITE_KEY_URL_PLACEHOLDER };
