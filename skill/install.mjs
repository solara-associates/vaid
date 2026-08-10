#!/usr/bin/env node
/**
 * Register the VAID skill with whichever coding agents are on this machine.
 *
 * Five agents, three different mechanisms, and none of them is going to converge
 * on the others soon:
 *
 * - **Claude Code** and **Codex** read a `SKILL.md` with YAML frontmatter from a
 *   skills directory. The file is copied verbatim.
 * - **Cursor**, **Gemini CLI** and **Copilot** read a single always-on context
 *   file (`.cursor/rules/*.mdc`, `GEMINI.md`, `.github/copilot-instructions.md`).
 *   There is no skill slot to install into, so the same content is written as a
 *   rules file — and for the two that use one shared file, it is written as a
 *   fenced, delimited block that can be re-written in place instead of appended
 *   twice.
 *
 * Detection is by directory existence, never by running the agent's binary:
 * an installer that shells out to five CLIs to ask whether they exist is five
 * more ways to hang.
 *
 * Nothing is overwritten without saying so, and `--dry-run` prints the plan.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const NAME = 'vaid';
const SKILL_MD = join(HERE, 'skills', NAME, 'SKILL.md');

const BEGIN = '<!-- BEGIN vaid-skill -->';
const END = '<!-- END vaid-skill -->';

const args = process.argv.slice(2);
const has = (f) => args.includes(f);
const dryRun = has('--dry-run');
const global_ = has('--global');
const only = (() => {
  const i = args.indexOf('--agent');
  return i !== -1 ? args[i + 1] : null;
})();

if (has('--help') || has('-h')) {
  process.stdout.write(`vaid-skill-install — register the VAID skill with your coding agent.

  npx vaid-skill                install into every agent detected here
  npx vaid-skill --global       install into your home directory, not this project
  npx vaid-skill --agent claude install into one agent only
  npx vaid-skill --dry-run      print the plan and change nothing

  agents: claude, codex, cursor, gemini, copilot
`);
  process.exit(0);
}

// `npx vaid-skill` is the installer and `npx -p vaid-skill vaid` is the CLI, which
// are one keystroke apart. A stray verb here used to be ignored, so `npx vaid-skill
// verify <envelope>` would cheerfully install the skill and report success while
// verifying nothing. Refuse instead, and say where the verb belongs.
const VERBS = new Set(['mint', 'present', 'verify', 'revoke']);
const stray = args.find((a) => VERBS.has(a));
if (stray) {
  process.stderr.write(
    `\nvaid-skill-install: \`${stray}\` is a CLI verb, not an installer flag.\n\n` +
      `  This command installs the skill into your agents. To run the CLI:\n\n` +
      `      npx -p vaid-skill vaid ${args.join(' ')}\n\n` +
      `  (\`npx <name>\` resolves <name> as a package, so -p is what reaches the \`vaid\` bin.)\n\n`,
  );
  process.exit(2);
}

const body = readFileSync(SKILL_MD, 'utf8');
/** The frontmatter is a Claude/Codex skill convention; strip it for rules files. */
const withoutFrontmatter = body.replace(/^---\n[\s\S]*?\n---\n/, '');

const home = homedir();
const cwd = process.cwd();
const root = global_ ? home : cwd;

/**
 * @type {Array<{id:string,label:string,detect:string,target:string,mode:'file'|'block',content:string}>}
 */
const TARGETS = [
  {
    id: 'claude',
    label: 'Claude Code',
    detect: global_ ? join(home, '.claude') : join(cwd, '.claude'),
    target: join(global_ ? join(home, '.claude') : join(cwd, '.claude'), 'skills', NAME, 'SKILL.md'),
    mode: 'file',
    content: body,
  },
  {
    id: 'codex',
    label: 'Codex',
    detect: global_ ? join(home, '.codex') : join(cwd, '.codex'),
    target: join(global_ ? join(home, '.codex') : join(cwd, '.codex'), 'skills', NAME, 'SKILL.md'),
    mode: 'file',
    content: body,
  },
  {
    id: 'cursor',
    label: 'Cursor',
    detect: join(root, '.cursor'),
    // Cursor rules are per-file, so this gets its own file and needs no block markers.
    target: join(root, '.cursor', 'rules', `${NAME}.mdc`),
    mode: 'file',
    content: `---\ndescription: VAID — mint, present and verify Verifiable Agent Identities\nalwaysApply: false\n---\n\n${withoutFrontmatter}`,
  },
  {
    id: 'gemini',
    label: 'Gemini CLI',
    detect: global_ ? join(home, '.gemini') : cwd,
    target: join(root, 'GEMINI.md'),
    mode: 'block',
    content: withoutFrontmatter,
  },
  {
    id: 'copilot',
    label: 'GitHub Copilot',
    detect: join(root, '.github'),
    target: join(root, '.github', 'copilot-instructions.md'),
    mode: 'block',
    content: withoutFrontmatter,
  },
];

/**
 * Replace an existing delimited block, or append one.
 *
 * Re-running the installer must be idempotent. Appending unconditionally is the
 * common bug and it is a bad one here: two copies of a security instruction that
 * have drifted apart is strictly worse than one stale copy, because the reader
 * cannot tell which is current.
 */
function upsertBlock(existing, content) {
  const block = `${BEGIN}\n<!-- Managed by vaid-skill. Edits inside this block are overwritten on reinstall. -->\n\n${content.trim()}\n\n${END}\n`;
  if (existing.includes(BEGIN) && existing.includes(END)) {
    return existing.replace(new RegExp(`${BEGIN}[\\s\\S]*?${END}\\n?`), block);
  }
  return existing.trim() === '' ? block : `${existing.replace(/\n+$/, '')}\n\n${block}`;
}

/** The same verbs in past tense, for after the write actually happened. */
const PAST = {
  create: 'created',
  overwrite: 'overwrote',
  'update block in': 'updated block in',
  'append block to': 'appended block to',
};

let installed = 0;
let skipped = 0;
const lines = [];

for (const t of TARGETS) {
  if (only && only !== t.id) continue;
  const detected = existsSync(t.detect);
  if (!detected && !only) {
    lines.push(`  ·  ${t.label.padEnd(15)} not detected (${t.detect})`);
    skipped += 1;
    continue;
  }

  let next;
  let verb;
  if (t.mode === 'block') {
    const existing = existsSync(t.target) ? readFileSync(t.target, 'utf8') : '';
    next = upsertBlock(existing, t.content);
    verb = existing.includes(BEGIN) ? 'update block in' : existing ? 'append block to' : 'create';
  } else {
    const existed = existsSync(t.target);
    next = t.content;
    verb = existed ? 'overwrite' : 'create';
  }

  if (dryRun) {
    lines.push(`  →  ${t.label.padEnd(15)} would ${verb} ${t.target}`);
  } else {
    mkdirSync(dirname(t.target), { recursive: true });
    writeFileSync(t.target, next);
    lines.push(`  ✓  ${t.label.padEnd(15)} ${PAST[verb]} ${t.target}`);
  }
  installed += 1;
}

process.stdout.write(`\n${dryRun ? 'Plan (nothing was written):' : 'VAID skill installed.'}\n\n`);
process.stdout.write(`${lines.join('\n')}\n\n`);

if (installed === 0) {
  process.stdout.write(
    `  No agent directories found under ${root}.\n` +
      `  Run from a project that has one, use --global, or force one with --agent <name>.\n` +
      `  The CLI works regardless:  npx -p vaid-skill vaid --help\n\n`,
  );
  process.exit(1);
}

process.stdout.write(
  `  ${skipped > 0 ? `${skipped} agent(s) not present here. ` : ''}` +
    `Restart your agent so it re-reads its skills.\n` +
    `  Then try:  mint a VAID for tenant acme with read scope on data.acme\n\n`,
);
