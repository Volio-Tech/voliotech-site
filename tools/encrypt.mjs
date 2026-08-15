#!/usr/bin/env node
/**
 * Volio Tech — team dossier encryptor
 *
 *   node tools/encrypt.mjs                 # encrypt with a generated key
 *   node tools/encrypt.mjs "my-access-key" # encrypt with your own key
 *
 * Reads  team.private.json   (git-ignored — the real data, never committed)
 * Writes team.enc.json       (ciphertext — safe to commit to a public repo)
 *
 * Local photo paths in the source file are read from disk and inlined as
 * data URIs *inside* the encrypted blob, so no employee photo is ever
 * served as a public file.
 *
 * No dependencies. Node 18+.
 */
import { webcrypto as crypto } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve, dirname, extname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SRC = resolve(ROOT, 'team.private.json');
const OUT = resolve(ROOT, 'team.enc.json');
const ITERATIONS = 250_000;

const MIME = {
  '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png',
  '.webp': 'image/webp', '.gif': 'image/gif', '.avif': 'image/avif'
};

const c = { dim: s => `\x1b[2m${s}\x1b[0m`, b: s => `\x1b[1m${s}\x1b[0m`,
            g: s => `\x1b[32m${s}\x1b[0m`, r: s => `\x1b[31m${s}\x1b[0m`,
            y: s => `\x1b[33m${s}\x1b[0m` };

function die(msg) { console.error(`\n${c.r('✖')} ${msg}\n`); process.exit(1); }

/** Readable, high-entropy key: 4 words + 4 digits (~52 bits). */
function makeKey() {
  const words = ['harbor','cobalt','lantern','summit','ember','quartz','meridian','cypress',
                 'falcon','tundra','vector','onyx','delta','pinnacle','arbor','zenith'];
  const pick = n => Array.from(crypto.getRandomValues(new Uint32Array(n)))
    .map(v => words[v % words.length]);
  const digits = String(crypto.getRandomValues(new Uint32Array(1))[0] % 10000).padStart(4, '0');
  return [...pick(3), digits].join('-');
}

/** Replace local image paths with data URIs so photos stay inside the ciphertext. */
function inlinePhotos(data) {
  let inlined = 0, bytes = 0;
  const missing = [], heavy = [];
  for (const m of data.members || []) {
    const p = m.photo;
    if (!p || p.startsWith('data:') || p.startsWith('http')) continue;
    const file = resolve(ROOT, p);
    if (!existsSync(file)) { missing.push(p); m.photo = ''; continue; }
    const mime = MIME[extname(file).toLowerCase()];
    if (!mime) { missing.push(`${p} (unsupported type)`); m.photo = ''; continue; }
    const buf = readFileSync(file);
    // Photos live inside the blob, so every KB is downloaded before the page
    // can render. Straight-from-phone shots are ~3 MB — flag them.
    if (buf.length > 300 * 1024) heavy.push(`${p} (${(buf.length / 1024 / 1024).toFixed(1)} MB)`);
    m.photo = `data:${mime};base64,${buf.toString('base64')}`;
    bytes += buf.length;
    inlined++;
  }
  return { inlined, missing, heavy, bytes };
}

async function main() {
  if (!existsSync(SRC)) {
    die(`No ${c.b('team.private.json')} found.\n  Copy the template to start:\n` +
        `  ${c.dim('cp team.private.example.json team.private.json')}`);
  }

  let data;
  try { data = JSON.parse(readFileSync(SRC, 'utf8')); }
  catch (e) { die(`team.private.json is not valid JSON — ${e.message}`); }

  if (!Array.isArray(data.members) || !data.members.length) {
    die('team.private.json has no "members" array, or it is empty.');
  }

  const { inlined, missing, heavy, bytes } = inlinePhotos(data);

  const pass = process.argv[2]?.trim() || makeKey();
  const plain = new TextEncoder().encode(JSON.stringify(data));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass),
    'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain);

  writeFileSync(OUT, JSON.stringify({
    v: 1,
    alg: 'AES-GCM-256',
    kdf: 'PBKDF2-SHA256',
    iter: ITERATIONS,
    salt: Buffer.from(salt).toString('base64'),
    iv: Buffer.from(iv).toString('base64'),
    ct: Buffer.from(ct).toString('base64')
  }, null, 2) + '\n');

  const kb = n => `${(n / 1024).toFixed(1)} KB`;
  console.log(`
${c.g('✔')} ${c.b('team.enc.json')} written — safe to commit.

  Members    ${data.members.length}
  Photos     ${inlined} inlined${inlined ? c.dim(` (${kb(bytes)})`) : ''}${missing.length ? c.y(`  · ${missing.length} skipped`) : ''}
  Payload    ${kb(plain.length)} → ${kb(ct.byteLength)} encrypted
${missing.length ? `\n  ${c.y('Skipped photos:')}\n${missing.map(m => `    · ${m}`).join('\n')}\n` : ''}${heavy.length ? `\n  ${c.y('Oversized photos — clients download these before the page renders:')}\n${heavy.map(m => `    · ${m}`).join('\n')}\n  ${c.dim('Shrink them:  sips -Z 500 photos/*.jpg')}\n` : ''}
  ${c.b('Access key')}   ${c.g(pass)}

  Share this link with the client:
  ${c.b(`https://voliotech.com/team.html#k=${encodeURIComponent(pass)}`)}

  ${c.dim('The key is not stored anywhere. Save it now, or re-run to make a new one.')}
  ${c.dim('To revoke access: re-run this script and send the new link.')}
`);
}

main().catch(e => die(e.stack || e.message));
