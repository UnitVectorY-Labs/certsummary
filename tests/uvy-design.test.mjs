import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const app = (p) => join(root, 'app', p);
const read = (p) => readFileSync(p, 'utf8');
const readBuf = (p) => readFileSync(p);
const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');
const sha512b64 = (buf) => createHash('sha512').update(buf).digest('base64');

// Pinned UVY Design v0.1.0 release checksums
// (source commit 396a65021c2bcab8dbcb3d1bb4cb498c807a4396)
const V010_SHA256 = {
  'assets/uvy-tokens.css': '0e97baaece886e0015c4238eaf7dbed9ea68f330c0f50729311c43b4a5a98533',
  'assets/uvy-theme.js': 'b105c0ddec8c19b6a380a33ffa5f9f558ca49baa477921a1dee9596d77bc61ed',
  'assets/uvy-elements.css': 'b2f92292dd9317bb770be1a4c745c9a00b81b6cef39cbcac54d2fe192135b092',
};

// The SRI the app previously pinned for the CDN copy of jsrsasign 11.1.0.
const JSRSASIGN_PINNED_SRI = 'sha512-Eu9j+HZBor7muHf6IDWoWZ8FKVr6nKe9eIIVR28NEte4Y4GiYRlke26XGdR/re81XE/FfLoLYYVkvNk5GY9RvQ==';

test('index.html has no external runtime references (script src / link href)', () => {
  const html = read(app('index.html'));
  const srcs = [...html.matchAll(/<script[^>]*\bsrc="([^"]+)"/g)].map((m) => m[1]);
  const hrefs = [...html.matchAll(/<link[^>]*\bhref="([^"]+)"/g)].map((m) => m[1]);
  assert.ok(srcs.length >= 3, 'expected local script tags');
  assert.ok(hrefs.length >= 3, 'expected local stylesheet links');
  for (const ref of [...srcs, ...hrefs]) {
    assert.doesNotMatch(ref, /^https?:\/\//, `external runtime reference: ${ref}`);
    assert.doesNotMatch(ref, /^\/\//, `protocol-relative runtime reference: ${ref}`);
  }
});

test('no stylesheet imports or app-source references point to a CDN', () => {
  for (const file of ['index.html', 'style.css', 'script.js', 'assets/uvy-tokens.css', 'assets/uvy-elements.css']) {
    const text = read(app(file));
    assert.doesNotMatch(text, /@import\s+url\(\s*['"]?https?:/, `${file} has a remote @import`);
    assert.doesNotMatch(text, /cdnjs|unpkg\.com|jsdelivr/, `${file} references a public CDN`);
  }
  // Anchor hrefs to crt.sh and project/license pages are ordinary links, not runtime assets.
  const script = read(app('script.js'));
  assert.match(script, /https:\/\/crt\.sh\/\?q=/, 'crt.sh output links must remain');
});

test('vendored jsrsasign exists and matches the pinned SRI', () => {
  const file = app('vendor/jsrsasign-all-min.js');
  assert.ok(existsSync(file), 'app/vendor/jsrsasign-all-min.js is missing');
  assert.equal(`sha512-${sha512b64(readBuf(file))}`, JSRSASIGN_PINNED_SRI);
});

test('copied UVY Design assets are byte-identical to v0.1.0', () => {
  for (const [rel, expected] of Object.entries(V010_SHA256)) {
    const buf = readBuf(app(rel));
    assert.equal(sha256(buf), expected, `${rel} differs from the pinned v0.1.0 checksum`);
  }
  // When the design source checkout is available, compare bytes directly.
  const designAssets = '/home/jared/github/uvy-design/assets';
  if (existsSync(designAssets)) {
    for (const rel of Object.keys(V010_SHA256)) {
      assert.deepEqual(readBuf(app(rel)), readBuf(join(designAssets, rel.split('/')[1])), `${rel} is not byte-identical to the v0.1.0 source`);
    }
  }
});

test('script.js retains fragment encode/decode and KJUR/X509 usage', () => {
  const js = read(app('script.js'));
  for (const fn of ['function encodeCertificateForURL', 'function decodeCertificateFromURL', 'function loadCertificateFromURL', 'function copyShareableLink', 'function processCertificate']) {
    assert.match(js, new RegExp(fn.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')), `missing ${fn}`);
  }
  assert.match(js, /btoa\(encodeURIComponent\(/, 'fragment encoding changed');
  assert.match(js, /decodeURIComponent\(atob\(/, 'fragment decoding changed');
  assert.match(js, /new X509\(\)/, 'X509 parsing missing');
  assert.match(js, /x509\.readCertPEM\(pem\)/, 'readCertPEM missing');
  assert.match(js, /KJUR\.crypto\.Util\.hashHex\(certHex,\s*"sha1"\)/, 'SHA-1 fingerprint via KJUR missing');
  assert.match(js, /KJUR\.crypto\.Util\.hashHex\(certHex,\s*"sha256"\)/, 'SHA-256 fingerprint via KJUR missing');
});

test('index.html retains the empty state, copy feedback and footer links', () => {
  const html = read(app('index.html'));
  assert.match(html, /<p>No certificate processed yet\.<\/p>/);
  assert.match(html, /id="copy-success"[^>]*aria-live="polite"/);
  assert.match(html, /Link copied to clipboard!/);
  assert.match(html, /href="https:\/\/github\.com\/UnitVectorY-Labs"/);
  assert.match(html, /href="https:\/\/opensource\.org\/licenses\/MIT"/);
  assert.match(html, /href="https:\/\/github\.com\/UnitVectorY-Labs\/certsummary"/);
});

test('head load order: theme script before tokens before app CSS', () => {
  const html = read(app('index.html'));
  const head = html.slice(html.indexOf('<head>'), html.indexOf('</head>'));
  const theme = head.indexOf('assets/uvy-theme.js');
  const tokens = head.indexOf('assets/uvy-tokens.css');
  const appCss = head.indexOf('href="style.css"');
  assert.ok(theme !== -1 && tokens !== -1 && appCss !== -1, 'expected theme, tokens and app CSS in head');
  assert.ok(theme < tokens, 'uvy-theme.js must load before uvy-tokens.css');
  assert.ok(tokens < appCss, 'uvy-tokens.css must load before app style.css');
  assert.doesNotMatch(head, /<script[^>]*\b(async|defer)\b/, 'theme/app scripts must load synchronously');
});

test('theme button markup has the required attributes and official inline icons', () => {
  const html = read(app('index.html'));
  const button = html.match(/<button[^>]*data-uvy-theme-toggle[^>]*>/);
  assert.ok(button, 'missing [data-uvy-theme-toggle] button');
  const attrs = button[0];
  assert.match(attrs, /\bhidden\b/, 'theme button must start hidden');
  assert.match(attrs, /aria-label="Switch to (dark|light) mode"/, 'theme button needs an initial action name');
  assert.match(html, /<span class="uvy-theme-dark-icon" aria-hidden="true" focusable="false">/, 'missing .uvy-theme-dark-icon span');
  assert.match(html, /<span class="uvy-theme-light-icon" aria-hidden="true" focusable="false">/, 'missing .uvy-theme-light-icon span');
  // Official Tabler moon path (icons/moon.svg) and sun paths (icons/sun.svg).
  assert.match(html, /M12 3c\.132 0 \.263 0 \.393 0a7\.5 7\.5 0 0 0 7\.92 12\.446a9 9 0 1 1 -8\.313 -12\.454l0 \.008/, 'official moon path missing');
  assert.match(html, /M8 12a4 4 0 1 0 8 0a4 4 0 1 0 -8 0/, 'official sun path missing');
  // The button sits in the masthead, outside dynamic content regions.
  const nav = html.slice(html.indexOf('<nav'), html.indexOf('</nav>'));
  assert.match(nav, /data-uvy-theme-toggle/, 'theme button must live in the masthead');
  // Adapter rule keeps the button hidden without JS even though uvy-elements.css sets a display value.
  assert.match(read(app('style.css')), /\.uvy-theme-toggle\[hidden\]\s*\{\s*\n?\s*display:\s*none/, 'hidden theme button must stay display:none');
});

test('no localStorage theme handler remains', () => {
  for (const file of ['index.html', 'script.js', 'style.css']) {
    assert.doesNotMatch(read(app(file)), /localStorage/, `${file} must not store a theme preference`);
  }
});
