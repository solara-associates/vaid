#!/usr/bin/env node
/**
 * `vaid` — four verbs over the published VAID SDKs.
 *
 * mint · present · verify · revoke. Nothing else, and the omissions are the
 * design. Every extra verb is another thing an agent has to be taught, another
 * thing that can be called wrongly, and another surface to keep in step with a
 * standard whose whole value is that three implementations agree byte for byte.
 *
 * This file contains no cryptography. It parses arguments, calls `vaid-mint`, and
 * prints. If a behaviour here disagrees with the Rust or Python mints, the bug is
 * here and the fix is to call the library correctly, never to reimplement it.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  InMemoryAudit,
  MintService,
  ReferenceIssuer,
  kernelKeyThumbprint,
  isSpecialUseTrustDomain,
} from 'vaid-mint';

import { packEnvelope, parseEnvelope } from './envelope.mjs';
import { mintAttenuatedChild } from './delegate.mjs';
import { Finding, Headline, loadAnchor, verifyEnvelope } from './verify-core.mjs';
import {
  b64u,
  loadIssuerSeed,
  loadRevoked,
  loadTrustedKeys,
  saveHolderSeed,
  saveRevoked,
  saveTrustedKeys,
  unb64u,
  vaidHome,
} from './store.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const PKG = JSON.parse(readFileSync(join(HERE, '..', 'package.json'), 'utf8'));
const VERIFY_URL = 'https://solara.associates/vaid/verify';

// --- output ------------------------------------------------------------------
// Colour only when stdout is a TTY. An agent capturing this output gets clean
// text; a human gets a verdict they can read at a glance.
const tty = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code) => (s) => (tty ? `[${code}m${s}[0m` : s);
const bold = c('1');
const dim = c('2');
const green = c('32');
const red = c('31');
const yellow = c('33');
const cyan = c('36');

const out = (s = '') => process.stdout.write(`${s}\n`);
const err = (s = '') => process.stderr.write(`${s}\n`);

function die(msg, code = 2) {
  err(`${red('error')}: ${msg}`);
  process.exit(code);
}

// --- args --------------------------------------------------------------------
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

const list = (v) =>
  v === undefined || v === true ? [] : String(v).split(',').map((s) => s.trim()).filter(Boolean);

function readInput(arg) {
  if (arg && arg !== '-') {
    // A path if it exists on disk; otherwise the literal envelope. Checked in
    // that order so a `vaid1:` token is never mistaken for a filename.
    if (arg.startsWith('vaid1:') || arg.startsWith('{')) return arg;
    try {
      return readFileSync(arg, 'utf8');
    } catch {
      return arg;
    }
  }
  if (process.stdin.isTTY) {
    die('no VAID given. Pass one as an argument, a file path, or pipe it in on stdin.');
  }
  try {
    return readFileSync(0, 'utf8');
  } catch {
    die('nothing on stdin and no argument given');
  }
}

// --- trust anchor ------------------------------------------------------------
/**
 * The keys this CLI accepts: the vendored published anchor, plus anything the
 * operator added out of band with `vaid verify --trust`.
 *
 * The vendored copy is byte-checked against the vaid repo's `docs/kernel-keys.json`
 * in CI, so a stale anchor in a published tarball fails the build rather than
 * quietly making every verification wrong.
 */
function anchorDoc() {
  const published = JSON.parse(readFileSync(join(HERE, '..', 'trust-anchor.json'), 'utf8'));
  const local = loadTrustedKeys();
  return { ...published, keys: { ...published.keys, ...(local.keys ?? {}) } };
}

function loadedAnchor() {
  try {
    return loadAnchor(anchorDoc());
  } catch (e) {
    die(e.message, 3);
  }
}

// --- mint --------------------------------------------------------------------
async function cmdMint(flags) {
  const { seed, trustDomain, created, path } = loadIssuerSeed();
  const ttl = Number(flags.ttl ?? 24);
  if (!Number.isFinite(ttl) || ttl <= 0) die('--ttl must be a positive number of hours');

  const issuer = ReferenceIssuer.fromSeed(seed, ttl, trustDomain);
  const mint = new MintService(issuer, new InMemoryAudit());

  const seedDoc = {
    agentClass: String(flags.class ?? 'agent'),
    version: String(flags.version ?? '1.0.0'),
    tenantId: String(flags.tenant ?? 'local'),
    scopeBoundary: list(flags.scope),
    capabilitySet: list(flags.caps),
  };

  let parentDoc = null;
  let chain = [];
  if (flags.parent) {
    const parsed = parseEnvelope(readInput(String(flags.parent)));
    parentDoc = parsed.vaid;
    // The child's presented chain is its parent plus everything the parent
    // itself presented, so a third party can walk to a root from the leaf alone.
    chain = [parentDoc, ...parsed.chain];
    seedDoc.parentVaid = parentDoc.vaid_id;
  }

  let vaid;
  let holderSeed = null;
  try {
    if (parentDoc) {
      // Delegation is always BYO-key: the child registers a holder key and proves
      // it controls it. `mintAttenuatedChild` generates that key and signs the
      // proof-of-possession; the seed comes back so it can be kept.
      const res = await mintAttenuatedChild(mint, parentDoc, seedDoc);
      vaid = res.vaid;
      holderSeed = res.holderSeed;
    } else {
      ({ vaid } = await mint.mintRoot({ seed: seedDoc }));
    }
  } catch (e) {
    // A refused mint is the attenuation rule doing its job, not a crash. Say which
    // rule, because "denied" without the reason sends people to retry the same call.
    die(`mint refused: ${e.message}`, 1);
  }

  let holderPath = null;
  if (holderSeed) holderPath = saveHolderSeed(vaid.vaid_id, holderSeed);

  const envelope = packEnvelope(vaid, chain);

  if (flags.json) {
    out(JSON.stringify({ envelope, vaid, chain, issuer: issuerLine(issuer) }, null, 2));
    return;
  }
  if (flags.quiet) {
    out(envelope);
    return;
  }

  if (created) {
    err(`${yellow('note')}: created a new local issuer key at ${path} (0600). It is a PRIVATE key — do not commit or paste it.`);
  }

  out(bold('Minted a VAID.'));
  out();
  out(`  ${dim('id')}         ${vaid.vaid_id}`);
  out(`  ${dim('class')}      ${vaid.agent_class}  ${dim('tenant')} ${vaid.tenant_id}`);
  out(`  ${dim('scope')}      ${vaid.scope_boundary.length ? vaid.scope_boundary.join(', ') : dim('(none)')}`);
  out(`  ${dim('caps')}       ${vaid.capability_set.length ? vaid.capability_set.join(', ') : dim('(none)')}`);
  out(`  ${dim('expires')}    ${vaid.expires_at}`);
  if (parentDoc) out(`  ${dim('parent')}     ${vaid.parent_vaid}  ${dim(`(+${chain.length} ancestor(s) presented)`)}`);
  if (holderPath) out(`  ${dim('holder key')} ${holderPath} ${dim('(0600, private)')}`);
  out();
  out(bold('Send this line. It is the whole credential:'));
  out();
  out(cyan(envelope));
  out();
  out(bold('The recipient also needs your issuer key, over a DIFFERENT channel:'));
  out();
  out(cyan(issuerLine(issuer)));
  out();
  out(dim(`  Sending both down one channel proves nothing: anyone who can rewrite the`));
  out(dim(`  envelope can rewrite the key beside it. The second channel is the security.`));
  out();
  out(dim(`  They can check it at ${VERIFY_URL} without installing anything,`));
  out(dim(`  or with:  npx -p vaid-skill vaid verify '<the vaid1: line>' --trust '<the key line>'`));

  if (isSpecialUseTrustDomain(vaid.trust_domain)) {
    out();
    out(`${yellow('caveat')}: trust_domain is \`${vaid.trust_domain}\`, an RFC 6761 special-use name — the`);
    out(`        deliberate default for an unconfigured issuer, so that being unconfigured is`);
    out(`        visible. A conforming verifier will not bind a trust bundle to it. Set a real`);
    out(`        domain in ${vaidHome()}/issuer.json before this is anything but a demo.`);
  }
}

/** `<thumbprint>=<base64url raw-32 public key>` — one line, pasteable both ways. */
function issuerLine(issuer) {
  const key = issuer.kernelPublicKey();
  return `${kernelKeyThumbprint(key)}=${b64u(key)}`;
}

// --- present -----------------------------------------------------------------
/**
 * Show what a recipient will actually receive, and re-emit the envelope.
 *
 * It exists because "did I copy the whole thing" is the failure mode that
 * silently wastes a round trip: a truncated envelope and a complete one look
 * alike in a chat window. `present` round-trips the token through a parse, so a
 * clipboard that lost the tail fails here rather than at the far end.
 */
function cmdPresent(positional, flags) {
  const input = readInput(positional[0]);
  let parsed;
  try {
    parsed = parseEnvelope(input);
  } catch (e) {
    die(e.message, 1);
  }
  const envelope = packEnvelope(parsed.vaid, parsed.chain);

  if (flags.json) {
    out(JSON.stringify({ envelope, vaid: parsed.vaid, chain: parsed.chain }, null, 2));
    return;
  }
  if (flags.quiet) {
    out(envelope);
    return;
  }

  out(bold('Ready to send.'));
  out();
  out(`  ${dim('id')}       ${parsed.vaid.vaid_id}`);
  out(`  ${dim('expires')}  ${parsed.vaid.expires_at}`);
  out(`  ${dim('chain')}    ${parsed.chain.length} ancestor document(s) presented`);
  if (parsed.vaid.parent_vaid && parsed.chain.length === 0) {
    out();
    out(`${yellow('warning')}: this VAID names a parent but presents no ancestors, so the recipient`);
    out(`         cannot check that its authority is contained within its parent's.`);
  }
  out();
  out(cyan(envelope));
  out();
  out(dim(`  ${envelope.length} characters. Verify at ${VERIFY_URL}`));
}

// --- verify ------------------------------------------------------------------
function cmdVerify(positional, flags) {
  // Before readInput: with no envelope argument that blocks on stdin, and listing
  // the keys you have accepted is not a verification of anything.
  if (flags.trusted) return listTrusted();

  // --trust accepts the `<thumbprint>=<key>` line `mint` prints. Saying so takes
  // the key on the operator's authority, which is what a trust decision is.
  // Handled BEFORE the envelope is read, so `vaid verify --trust '<line>'` with
  // nothing to verify is a complete command rather than a wait on empty stdin.
  if (flags.trust) {
    const line = String(flags.trust).trim();
    const eq = line.indexOf('=');
    if (eq === -1) die('--trust expects `<thumbprint>=<base64url public key>`, as printed by `vaid mint`');
    const claimed = line.slice(0, eq);
    const key = unb64u(line.slice(eq + 1));
    if (key.length !== 32) die('--trust key is not a 32-byte Ed25519 public key');
    const actual = kernelKeyThumbprint(key);
    if (actual !== claimed) {
      die(`--trust key does not hash to the thumbprint given.\n  given:      ${claimed}\n  recomputed: ${actual}`, 1);
    }
    const doc = loadTrustedKeys();
    doc.keys = doc.keys ?? {};
    doc.keys[actual] = {
      kty: 'OKP',
      crv: 'Ed25519',
      x: line.slice(eq + 1),
      $local: true,
      $note: 'Added locally with `vaid verify --trust`. Its thumbprint was recomputed before it was stored.',
    };
    const at = saveTrustedKeys(doc);
    if (!flags.json && !flags.quiet) {
      err(`${yellow('note')}: now trusting ${actual}`);
      err(dim(`      Stored in ${at}. This PERSISTS: every later 'vaid verify' on this`));
      err(dim("      machine accepts this issuer, including runs without --trust."));
      err(dim("      'vaid verify --trusted' lists what you have accepted."));
    }
    // No envelope argument means there is nothing to verify: storing the key was
    // the whole command. Not gated on isTTY — in CI stdin is inherited and stays
    // open, so an isTTY check would still hang exactly where a hang costs most.
    if (positional.length === 0) process.exit(0);
  }

  const input = readInput(positional[0]);
  const anchor = loadedAnchor();
  const now = flags.at ? new Date(String(flags.at)) : new Date();
  if (Number.isNaN(now.getTime())) die('--at is not a parseable timestamp');

  const result = verifyEnvelope(input, anchor, now);

  // The local revocation list is applied AFTER the verdict and reported beside
  // it, never folded into it. Folding it in would make this CLI's answer differ
  // from every other verifier's for a reason no third party can see.
  const localRevoked = result.vaid ? loadRevoked().revoked?.[result.vaid.vaid_id] : undefined;

  if (flags.json) {
    out(JSON.stringify({ ...result, local_revocation: localRevoked ?? null }, null, 2));
  } else {
    printResult(result, localRevoked);
  }

  // Exit code is a coarse summary of a deliberately plural verdict, so it is
  // documented rather than inferred: 0 accepted, 1 rejected/expired, 4 malformed.
  if (result.headline === Headline.Malformed) process.exit(4);
  if (result.headline === Headline.Rejected || result.headline === Headline.Expired) process.exit(1);
  process.exit(0);
}

/**
 * Show the keys this machine has accepted beyond the shipped anchor.
 *
 * The counterpart to `--trust` persisting. A stored trust decision that cannot be
 * listed is one that cannot be reviewed or withdrawn, which is how a machine ends
 * up accepting an issuer nobody remembers vouching for.
 */
function listTrusted() {
  const local = loadTrustedKeys().keys ?? {};
  const entries = Object.entries(local);
  out();
  out(`  ${bold('Shipped with this package')} ${dim('(published by solara.associates)')}`);
  const published = JSON.parse(readFileSync(join(HERE, '..', 'trust-anchor.json'), 'utf8')).keys ?? {};
  for (const [tp, k] of Object.entries(published)) {
    out(`  ${green('✓')} ${tp}`);
    out(`    ${dim(k.deployment ?? k.key_id ?? '')}`);
  }
  out();
  out(`  ${bold('Added on this machine with --trust')} ${dim(`(${vaidHome()}/trusted-keys.json)`)}`);
  if (entries.length === 0) {
    out(`  ${dim('(none)')}`);
  } else {
    for (const [tp] of entries) out(`  ${yellow('!')} ${tp}`);
    out();
    out(dim(wrap(
      'These are YOUR trust decisions, not ours, and they apply to every `vaid verify` on this machine. ' +
        'Remove any you no longer vouch for by deleting the entry from that file.',
      '  ',
    )));
  }
  out();
  process.exit(0);
}

const MARK = {
  [Finding.Pass]: () => green('✓'),
  [Finding.Fail]: () => red('✗'),
  [Finding.Caveat]: () => yellow('!'),
  [Finding.NotChecked]: () => dim('·'),
};

const BANNER = {
  [Headline.Valid]: () => green(bold('VALID')),
  [Headline.ValidWithCaveats]: () => yellow(bold('VALID — WITH CAVEATS')),
  [Headline.Expired]: () => yellow(bold('EXPIRED')),
  [Headline.Rejected]: () => red(bold('REJECTED')),
  [Headline.Malformed]: () => red(bold('NOT A VAID')),
};

function wrap(text, indent) {
  const width = Math.max(40, (process.stdout.columns || 80) - indent.length);
  const words = text.split(/\s+/);
  const lines = [];
  let line = '';
  for (const w of words) {
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

function printResult(result, localRevoked) {
  out();
  out(`  ${BANNER[result.headline]()}  ${result.summary}`);
  if (result.detail) out(wrap(result.detail, '  '));
  out();
  if (result.vaid?.vaid_id) {
    out(`  ${dim('id')}       ${result.vaid.vaid_id}`);
    out(`  ${dim('class')}    ${result.vaid.agent_class}  ${dim('tenant')} ${result.vaid.tenant_id}`);
    out(`  ${dim('caps')}     ${result.vaid.capability_set?.join(', ') || dim('(none)')}`);
    out();
  }
  for (const f of result.findings) {
    out(`  ${MARK[f.state]()} ${bold(f.label)}`);
    out(dim(wrap(f.detail, '      ')));
    out();
  }
  if (localRevoked) {
    out(`  ${red('!')} ${bold('Local revocation list')}`);
    out(dim(wrap(
      `This machine's own list marks this VAID revoked (${localRevoked.reason ?? 'no reason given'}, ` +
        `${localRevoked.at}). That is a note to YOU. It is not part of the verdict above and no other ` +
        'verifier in the world can see it.',
      '      ',
    )));
    out();
  }
  if (result.presentedBare) {
    out(dim(wrap('Input was a bare VAID document rather than a vaid1: envelope; any delegation chain was not presented.', '  ')));
    out();
  }
}

// --- revoke ------------------------------------------------------------------
/**
 * Mark a VAID revoked **on this machine**.
 *
 * The verb exists because the standard has a revocation model and pretending it
 * does not would be its own dishonesty. What it cannot do is the thing people
 * assume a `revoke` command does. There is no published revocation list; the open
 * reference mint's list is in-memory and dies with its process; durable,
 * restart-surviving revocation is the closed product. So this writes a local file,
 * and says so every single time rather than once in a man page.
 */
function cmdRevoke(positional, flags) {
  const doc = loadRevoked();
  doc.revoked = doc.revoked ?? {};

  if (flags.list) {
    const entries = Object.entries(doc.revoked);
    if (entries.length === 0) {
      out(dim('  Local revocation list is empty.'));
    } else {
      for (const [id, e] of entries) out(`  ${red('✗')} ${id}  ${dim(`${e.at}  ${e.reason ?? ''}`)}`);
    }
    out();
    out(dim(wrap('LOCAL ONLY. No third party consults this file. Revoking here does not stop the VAID being accepted anywhere else.', '  ')));
    return;
  }

  const id = positional[0];
  if (!id) die('usage: vaid revoke <vaid_id> [--reason "…"]  |  vaid revoke --list');

  doc.revoked[id] = { at: new Date().toISOString(), reason: flags.reason ? String(flags.reason) : undefined };
  const path = saveRevoked(doc);

  out(`  ${red('✗')} ${id} marked revoked in ${path}`);
  out();
  out(yellow(wrap(
    'This changed one file on this machine and nothing else. There is no published revocation list for a ' +
      'third party to consult, so the holder of this VAID can still present it and every other verifier — ' +
      'including the public verify page — will still report it genuine. If you need a revocation that ' +
      'anyone else can see, this tool is not what does that.',
    '  ',
  )));
}

// --- entry -------------------------------------------------------------------
const USAGE = `${bold('vaid')} — mint, present, verify and revoke Verifiable Agent Identities.

  ${bold('vaid mint')}     [--class C] [--tenant T] [--scope a,b] [--caps c,d] [--ttl H]
                 [--parent <envelope>] [--json|--quiet]
      Mint a VAID with this machine's local issuer key and print a single-line
      envelope you can paste into a message. With --parent, mints an attenuated
      child and presents the ancestors alongside it.

  ${bold('vaid present')}  <envelope|file|->  [--json|--quiet]
      Re-emit an envelope, round-tripped through a parse so a truncated copy
      fails here rather than at the far end.

  ${bold('vaid verify')}   <envelope|file|->  [--trust '<tp>=<key>'] [--at <rfc3339>] [--json]
      Verify offline against the published trust anchor. Reports authenticity,
      expiry, delegation and issuer identity separately, and always reports that
      revocation was NOT checked. Exit 0 accepted, 1 rejected or expired, 4 malformed.

      --trust adds an issuer key you obtained out of band, for VAIDs from a
      self-hosted mint. ${bold('It is written to')} ${vaidHome()}/trusted-keys.json
      ${bold('and stays there')} — every later 'vaid verify' on this machine accepts
      that issuer, including runs you did not pass --trust to. List what you have
      accepted with 'vaid verify --trusted', and delete entries you no longer
      vouch for. (The browser page keeps such keys for the session only.)

  ${bold('vaid revoke')}   <vaid_id> [--reason "…"]  |  --list
      Mark a VAID revoked ON THIS MACHINE ONLY. There is no published revocation
      list; nothing else in the world will see this.

  State lives in ${vaidHome()} (override with VAID_HOME).
  Verify in a browser, no install: ${VERIFY_URL}
`;

async function main() {
  const argv = process.argv.slice(2);
  const { flags, positional } = parseArgs(argv);
  const verb = positional.shift();

  if (flags.version || verb === 'version') {
    out(`vaid-skill ${PKG.version} (vaid-mint ${PKG.dependencies['vaid-mint']})`);
    return;
  }
  if (!verb || flags.help || verb === 'help') {
    out(USAGE);
    process.exit(verb ? 0 : 1);
  }

  switch (verb) {
    case 'mint':
      return cmdMint(flags);
    case 'present':
      return cmdPresent(positional, flags);
    case 'verify':
      return cmdVerify(positional, flags);
    case 'revoke':
      return cmdRevoke(positional, flags);
    default:
      die(`unknown verb \`${verb}\`. There are four: mint, present, verify, revoke.`);
  }
}

main().catch((e) => die(e?.stack ?? String(e), 3));
