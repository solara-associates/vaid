/**
 * Standalone, browser-only VAID verifier.
 *
 * Uses the published `vaid-mint` npm package directly — the same open-source
 * reference verifier anyone can `npm install vaid-mint` and run themselves.
 * Makes no network request of its own. The only network call this page can
 * ever make is fetching a `.well-known/vaid-keys.json` URL, and only when you
 * click "Fetch key from URL".
 */
import './polyfills/buffer-global.js';
import {
  assembleLineage,
  capsAttenuate,
  expiryAttenuates,
  isExpired,
  parseVaidDocument,
  PresentedBundle,
  scopeAttenuates,
  tenantAttenuates,
  verifyChain,
  verifyVaidAuthenticityGraded,
  isVerdictValid,
  type Vaid,
} from 'vaid-mint';

import { parseKeysDocument, parsePastedKey, type ParsedKey } from './vaidKey.js';
import { translateChain, translateVerdict } from './translate.js';

import validTwoHop from '../samples/valid-two-hop.json';
import scopeWidens from '../samples/scope-widens.json';
import expiredCredential from '../samples/expired-credential.json';
import tamperedByte from '../samples/tampered-byte.json';

interface SampleFile {
  label: string;
  kernelPublicKeyHex: string;
  documents: Vaid[];
}

const SAMPLES: Record<string, SampleFile> = {
  'valid-two-hop': validTwoHop as SampleFile,
  'scope-widens': scopeWidens as SampleFile,
  'expired-credential': expiredCredential as SampleFile,
  'tampered-byte': tamperedByte as SampleFile,
};

const chainInput = document.getElementById('chain-input') as HTMLTextAreaElement;
const keyInput = document.getElementById('key-input') as HTMLTextAreaElement;
const keyUrlInput = document.getElementById('key-url-input') as HTMLInputElement;
const fetchKeyButton = document.getElementById('fetch-key-button') as HTMLButtonElement;
const keyUrlStatus = document.getElementById('key-url-status') as HTMLElement;
const verifyButton = document.getElementById('verify-button') as HTMLButtonElement;
const resultsEl = document.getElementById('results') as HTMLElement;
const summaryEl = document.getElementById('summary') as HTMLElement;

function setSample(name: keyof typeof SAMPLES): void {
  const sample = SAMPLES[name];
  chainInput.value = JSON.stringify(sample.documents, null, 2);
  keyInput.value = sample.kernelPublicKeyHex;
  resultsEl.innerHTML = '';
  summaryEl.innerHTML = '';
  runVerify();
}

document.querySelectorAll<HTMLButtonElement>('[data-sample]').forEach((btn) => {
  btn.addEventListener('click', () => {
    const name = btn.dataset.sample as keyof typeof SAMPLES;
    setSample(name);
  });
});

fetchKeyButton.addEventListener('click', () => {
  void fetchKeyUrl();
});

async function fetchKeyUrl(): Promise<void> {
  const url = keyUrlInput.value.trim();
  if (url === '') {
    keyUrlStatus.textContent = 'Enter a URL first.';
    return;
  }
  keyUrlStatus.textContent = 'Fetching...';
  try {
    const res = await fetch(url);
    if (!res.ok) {
      keyUrlStatus.textContent = `Could not fetch that URL (status ${res.status}).`;
      return;
    }
    const json = await res.json();
    const keys = parseKeysDocument(json);
    if (keys.length === 0) {
      keyUrlStatus.textContent = 'That URL did not contain a recognizable VAID key.';
      return;
    }
    // If more than one key is published, prefer the one that matches a
    // document already pasted in, otherwise take the first and say so.
    let chosen: ParsedKey = keys[0]!;
    if (keys.length > 1) {
      const docs = tryParseChainInput();
      const wantedThumbprint = docs?.[docs.length - 1]?.kernel_key_thumbprint;
      const match = keys.find((k) => k.thumbprint === wantedThumbprint);
      if (match) chosen = match;
    }
    keyInput.value = toHexKey(chosen.publicKey);
    keyUrlStatus.textContent =
      keys.length > 1
        ? `Fetched ${keys.length} keys; used the one matching your pasted credential (or the first, if none matched).`
        : 'Fetched 1 key and filled it in below.';
  } catch (err) {
    keyUrlStatus.textContent = `Could not fetch or read that URL: ${(err as Error).message}`;
  }
}

function toHexKey(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function tryParseChainInput(): Vaid[] | null {
  const text = chainInput.value.trim();
  if (text === '') return null;
  try {
    const parsed = JSON.parse(text);
    if (Array.isArray(parsed)) return parsed as Vaid[];
    return [parsed as Vaid];
  } catch {
    return null;
  }
}

verifyButton.addEventListener('click', () => runVerify());

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, string> = {},
  ...children: (Node | string)[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') node.className = v;
    else node.setAttribute(k, v);
  }
  for (const child of children) {
    node.append(typeof child === 'string' ? document.createTextNode(child) : child);
  }
  return node;
}

function pill(ok: boolean, text: string): HTMLElement {
  return el('span', { class: ok ? 'pill pill-pass' : 'pill pill-fail' }, text);
}

function describeAgent(doc: Vaid): string {
  return `${doc.agent_class} (id ${shortId(doc.agent_id)})`;
}

function shortId(id: string): string {
  return id.length > 13 ? `${id.slice(0, 8)}…${id.slice(-4)}` : id;
}

function describeScope(doc: Vaid): string {
  if (doc.scope_boundary.length === 0) return 'anything (no restriction set)';
  return doc.scope_boundary.map((e) => String(e.value)).join(', ');
}

function describeCaps(doc: Vaid): string {
  if (doc.capability_set.length === 0) return 'nothing beyond identity (no capabilities granted)';
  return doc.capability_set.join(', ');
}

function formatExpiry(doc: Vaid, now: Date): string {
  const expired = isExpired(doc, now);
  return `${doc.expires_at} (${expired ? 'already passed' : 'still valid'})`;
}

function runVerify(): void {
  resultsEl.innerHTML = '';
  summaryEl.innerHTML = '';

  const docs = tryParseChainInput();
  if (!docs || docs.length === 0) {
    summaryEl.append(
      el('div', { class: 'summary summary-fail' }, 'Paste a VAID credential, or a chain of them, above.'),
    );
    return;
  }

  // Re-validate through the published parser too, so a structurally broken
  // paste is named as such rather than silently half-read.
  for (const doc of docs) {
    const reparsed = parseVaidDocument(JSON.stringify(doc));
    if (reparsed === null) {
      summaryEl.append(
        el(
          'div',
          { class: 'summary summary-fail' },
          "This isn't a VAID credential. It's missing required fields or has the wrong shape.",
        ),
      );
      return;
    }
  }

  const parsedKey = parsePastedKey(keyInput.value);
  const now = new Date();

  const leaf = docs[docs.length - 1]!;
  const ancestors = docs.slice(0, -1);
  const bundle = new PresentedBundle(ancestors);

  // Order hops root-to-leaf via the package's own lineage assembly, so display
  // order does not depend on the order the user happened to paste things in.
  const assembled = assembleLineage(leaf, bundle);
  const orderedIds = assembled ?? docs.map((d) => d.vaid_id);
  const byId = new Map(docs.map((d) => [d.vaid_id, d]));
  const ordered = orderedIds.map((id) => byId.get(id)).filter((d): d is Vaid => d !== undefined);
  const orderedDocs = ordered.length === docs.length ? ordered : docs;

  // ── Per-hop cards ──────────────────────────────────────────────────────
  let allPass = true;
  const authenticOk: boolean[] = [];
  orderedDocs.forEach((doc, i) => {
    const checks: { ok: boolean; label: string; reason: string }[] = [];

    let isAuthentic = false;
    if (parsedKey) {
      const verdict = verifyVaidAuthenticityGraded(parsedKey.publicKey, doc);
      isAuthentic = isVerdictValid(verdict);
      checks.push({
        ok: isAuthentic,
        label: 'Authenticity',
        reason: translateVerdict(verdict),
      });
    } else {
      checks.push({
        ok: false,
        label: 'Authenticity',
        reason: 'No trusted public key was provided, so this cannot be checked against anyone in particular.',
      });
    }
    authenticOk.push(isAuthentic);

    const expired = isExpired(doc, now);
    checks.push({
      ok: !expired,
      label: 'Expiry',
      reason: expired
        ? 'This credential has passed its expiry date.'
        : 'This credential has not expired.',
    });

    // Only meaningful once both this document and its delegator are known to
    // be genuine: comparing claimed authority on a forged or tampered
    // document would report on bytes nobody actually signed.
    if (i > 0 && isAuthentic && authenticOk[i - 1]) {
      const parent = orderedDocs[i - 1]!;
      const contained =
        tenantAttenuates(parent, doc.trust_domain, doc.tenant_id) &&
        scopeAttenuates(parent, doc.scope_boundary) &&
        capsAttenuate(parent, doc.capability_set) &&
        expiryAttenuates(parent, doc.expires_at);
      checks.push({
        ok: contained,
        label: 'Delegation',
        reason: contained
          ? 'Everything this credential may do is within what its delegator was allowed to hand down.'
          : 'This credential claims more than the one that created it was allowed to hand down.',
      });
    } else if (i > 0) {
      checks.push({
        ok: false,
        label: 'Delegation',
        reason: 'Not checked: this credential or the one before it is not genuine, so nothing it claims can be trusted.',
      });
    }

    const hopPass = checks.every((c) => c.ok);
    if (!hopPass) allPass = false;

    const card = el(
      'div',
      { class: `hop-card ${hopPass ? 'hop-pass' : 'hop-fail'}` },
      el('div', { class: 'hop-title' },
        el('strong', {}, describeAgent(doc)),
        i === 0 ? el('span', { class: 'hop-role' }, ', root, delegated from nobody') : el('span', { class: 'hop-role' }, `, delegated from ${describeAgent(orderedDocs[i - 1]!)}`),
      ),
      el('dl', { class: 'hop-facts' },
        el('dt', {}, 'May act on'), el('dd', {}, describeScope(doc)),
        el('dt', {}, 'May do'), el('dd', {}, describeCaps(doc)),
        el('dt', {}, 'Expires'), el('dd', {}, formatExpiry(doc, now)),
      ),
      el('div', { class: 'hop-checks' }, ...checks.flatMap((c) => [
        el('div', { class: 'hop-check' }, pill(c.ok, `${c.ok ? 'Pass' : 'Fail'}: ${c.label}`), el('span', { class: 'hop-reason' }, c.reason)),
      ])),
    );
    resultsEl.append(card);
  });

  // ── Overall summary, from the package's own chain verdict ────────────────
  let overallOk = allPass;
  let overallText: string;
  if (docs.length === 1) {
    overallText = allPass
      ? 'This credential checks out: genuine and not expired.'
      : 'This credential did not pass every check above.';
  } else if (!parsedKey) {
    overallOk = false;
    overallText = 'Provide a trusted public key to check this chain.';
  } else {
    const result = verifyChain(parsedKey.publicKey, leaf, bundle);
    const chainOk = result === 'attenuated';
    overallOk = overallOk && chainOk;
    if (!chainOk) {
      // The chain library's own verdict is the more specific complaint.
      overallText = translateChain(result);
    } else if (!allPass) {
      // The chain is genuine and properly delegated end to end — but chain
      // verification deliberately does not check the LEAF's own expiry (a
      // separate, per-document check, shown on its card above). Say both
      // things, so "Fail" is never paired with a sentence that reads as a
      // pass.
      overallText =
        'Every step in this chain is genuine, and each one only narrows what the one before it allowed. ' +
        'But at least one credential above has already expired, so this chain is not currently usable. See the card marked Fail.';
    } else {
      overallText = translateChain(result);
    }
  }

  summaryEl.append(
    el(
      'div',
      { class: `summary ${overallOk ? 'summary-pass' : 'summary-fail'}` },
      el('strong', {}, overallOk ? 'Pass. ' : 'Fail. '),
      overallText,
    ),
  );
}
