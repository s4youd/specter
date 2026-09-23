// Regression suite for Specter frontend logic (runs against the SHIPPED app.js).
// Run:  node tests/test_appjs.mjs   (from the Specter/ directory, no deps)
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const src = fs.readFileSync(path.join(root, 'static', 'js', 'app.js'), 'utf8');

function extract(name) {
  const i = src.indexOf('function ' + name + '(');
  if (i < 0) throw new Error('missing function in app.js: ' + name);
  let j = src.indexOf('{', i), depth = 0;
  for (let k = j; k < src.length; k++) {
    if (src[k] === '{') depth++;
    if (src[k] === '}') { depth--; if (!depth) return src.slice(i, k + 1); }
  }
  throw new Error('unbalanced function in app.js: ' + name);
}

// Browser-like textContent -> innerHTML serialization (& < > escaped, quotes literal)
const stubDoc = {
  createElement: () => {
    let t = '';
    return {
      set textContent(v) { t = String(v); },
      get innerHTML() {
        return t.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
      },
    };
  },
};

const NAMES = ['esc', 'escAttr', 'secKeyOf', 'consolidateSecrets', 'secretsOfFile',
  'shortFileName', 'renderAlsoFound', 'excerptRange', 'renderExcerpt',
  'inlineValidationBadge', 'statusLabel', 'renderSecretsTable'];
const factory = new Function('document', 'window',
  'let expandedSecrets = new Set();\n' + NAMES.map(extract).join('\n') +
  '\nreturn {' + NAMES.join(',') + ', expandedSecrets};');
const F = factory(stubDoc, { _lastValidation: [] });

let pass = 0;
function ok(cond, msg) {
  if (!cond) { console.error('FAIL:', msg); process.exit(1); }
  pass++;
}

// --- escAttr: full copy values must survive attribute encoding ---
const cmd = 'curl -s -H "Authorization: Bearer abc123" -d \'{"k":"v"}\'';
const enc = F.escAttr(cmd);
ok(enc === 'curl -s -H &quot;Authorization: Bearer abc123&quot; -d &#39;{&quot;k&quot;:&quot;v&quot;}&#39;',
  'escAttr encoding, got: ' + enc);
ok(!/["']/.test(enc), 'no raw quotes remain in attribute value');
ok(!/["']/.test(F.escAttr('github_token = "abcDEF123"')), 'quoted secret encodable');

// --- consolidation: 3+ files collapse to one entry + file list ---
function files() {
  return [
    { file_id: 1, url: 'https://t/a.js', secrets: [{ type: 'GitHub Personal Access Token', match: 'ghp_X', line: 5 }] },
    { file_id: 2, url: 'https://t/b.js', secrets: [{ type: 'GitHub Personal Access Token', match: 'ghp_X', line: 9 }] },
    { file_id: 3, url: 'https://t/c.js',
      secrets: [{ type: 'GitHub Personal Access Token', match: 'ghp_X', line: 2 },
                { type: 'NPM Token', match: 'npm_Y', line: 3 }] },
  ];
}
let f = files();
F.consolidateSecrets(f);
ok(f[0].secrets.length === 1 && f[0].secrets[0].also_found_in.length === 2, 'kept earliest + file list');
ok(f[0].secrets[0].also_found_in.includes('https://t/b.js'), 'file list contents');
ok(f[1].secrets.length === 0 && f[2].secrets.length === 1, 'dropped from other files');
const snap = JSON.stringify(f);
F.consolidateSecrets(f);
ok(JSON.stringify(f) === snap, 'idempotent re-run');

// --- 2-file repeat stays untouched; grouping is type-sensitive ---
let g = [
  { file_id: 1, url: 'u1', secrets: [{ type: 'X', match: 'm', line: 1 }] },
  { file_id: 2, url: 'u2', secrets: [{ type: 'X', match: 'm', line: 1 }] },
];
F.consolidateSecrets(g);
ok(g[0].secrets.length === 1 && !g[0].secrets[0].also_found_in && g[1].secrets.length === 1,
  '2-file repeat untouched');
let h = [
  { file_id: 1, url: 'u1', secrets: [{ type: 'A', match: 'm', line: 1 }] },
  { file_id: 2, url: 'u2', secrets: [{ type: 'B', match: 'm', line: 1 }] },
  { file_id: 3, url: 'u3', secrets: [{ type: 'A', match: 'm', line: 1 }] },
];
F.consolidateSecrets(h);
ok(h[0].secrets.length === 1 && !h[0].secrets[0].also_found_in, 'type-sensitive grouping');

// --- sub-file secrets join the same grouping; survivor prefers main files ---
let s = [
  { file_id: 1, url: 'https://t/a.js', secrets: [{ type: 'T', match: 'M', line: 1 }],
    sub_files: [{ url: 'https://t/chunk.js', secrets: [] }] },
  { file_id: 2, url: 'https://t/b.js', secrets: [],
    sub_files: [{ url: 'https://t/chunk.js', secrets: [{ type: 'T', match: 'M', line: 4 }] }] },
  { file_id: 3, url: 'https://t/c.js', secrets: [],
    sub_files: [{ url: 'https://t/other.js', secrets: [{ type: 'T', match: 'M', line: 2 }] }] },
];
F.consolidateSecrets(s);
ok(s[0].secrets.length === 1 && s[0].secrets[0].also_found_in.length === 2,
  'sub-file duplicates consolidate into main-file survivor');
ok(s[1].sub_files[0].secrets.length === 0 && s[2].sub_files[0].secrets.length === 0,
  'sub-file copies removed');

// --- per-file collector ---
const ff = { url: 'https://t/a.js', secrets: [{ type: 'T', match: 'M', line: 7 }] };
ok(JSON.stringify(F.secretsOfFile(ff)) ===
  JSON.stringify([{ type: 'T', match: 'M', file: 'https://t/a.js', line: 7 }]), 'secretsOfFile');

// --- open-state survives re-renders (no collapse jumping) ---
const kA = F.secKeyOf({ type: 'T', match: 'M'.repeat(100), line: 1 });
const kB = F.secKeyOf({ type: 'T', match: 'M'.repeat(100), line: 9 });
ok(kA === kB, 'secKey stable across lines (survives consolidation moves)');
ok(F.secKeyOf({ type: 'T', match: 'M' }) !== F.secKeyOf({ type: 'U', match: 'M' }), 'secKey type-sensitive');
F.expandedSecrets.add(kA);
const openHtml = F.renderSecretsTable([{
  type: 'T', severity: 'high', match: 'M'.repeat(100), line: 1,
  excerpt: [{ n: 1, text: 'M'.repeat(100), hit: true }],
}]);
ok(openHtml.includes('sec-item open') && openHtml.includes('data-skey='), 'open accordions re-applied on render');

// --- accordion render: dup badge, file links, full (untruncated) copy values ---
const secrets = [{
  type: 'GitHub Personal Access Token', severity: 'critical',
  match: 'github_token = "ghp_ABCDEF123456"',
  line: 12, line_content: 'x', context: 'x',
  excerpt: [{ n: 11, text: '// cfg', hit: false },
            { n: 12, text: 'github_token = "ghp_ABCDEF123456";', hit: true }],
  also_found_in: ['https://t/b.js', 'https://t/c.js'],
  validation: {
    command: 'curl -s -H "Authorization: token ghp_X" https://api.github.com/user',
    indicator: '200 = live', requires_pairing: false,
  },
}];
const html = F.renderSecretsTable(secrets);
ok(html.includes('×3 files'), 'dup badge in accordion');
ok(html.includes('Also found in') && html.includes('https://t/b.js') && html.includes('target="_blank"'),
  'dup file links');
const copies = html.match(/data-copy="([^"]*)"/g) || [];
ok(copies.length >= 3, 'copy buttons present, got ' + copies.length);
ok(html.includes('&quot;Authorization: token ghp_X&quot;'), 'full validation command in data-copy');
ok(html.includes('ctx-hl'), 'excerpt match highlight');

console.log(`ALL ${pass} JS CHECKS PASS`);
