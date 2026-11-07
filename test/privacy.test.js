// The promises in the README that can be checked by reading the code, checked on every build.
// If one of these fails, either the code is doing something it should not, or the promise needs to change
// (and the privacy policy with it).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { listFiles, manifestFor } = require('../scripts/build.js');

const SRC = path.join(__dirname, '..', 'src');
const files = listFiles(SRC);
const read = (rel) => fs.readFileSync(path.join(SRC, rel), 'utf8');

/** Source with comments removed, so a sentence like "never calls fetch(" in a comment is not flagged. */
function code(rel) {
  return read(rel)
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:'"`\\])\/\/.*$/gm, '$1');
}

test('there is no code that can send data anywhere', () => {
  const forbidden = [
    [/\bfetch\s*\(/, 'fetch()'],
    [/XMLHttpRequest/, 'XMLHttpRequest'],
    [/\bWebSocket\b/, 'WebSocket'],
    [/\bEventSource\b/, 'EventSource'],
    [/sendBeacon/, 'navigator.sendBeacon'],
    [/\bimportScripts\b/, 'importScripts'],
    [/\bchrome\.(?:runtime|tabs)\.sendMessage\b|\bbrowser\.(?:runtime|tabs)\.sendMessage\b/, 'extension messaging'],
    [/\.connect\s*\(\s*['"`{]/, 'runtime.connect'],
    [/new\s+Image\s*\(/, 'new Image() (image beacons)'],
    [/\bnavigator\.clipboard\b/, 'navigator.clipboard (the extension only reads the paste event it is handed)'],
  ];
  const problems = [];
  for (const rel of files.filter((f) => f.endsWith('.js'))) {
    const text = code(rel);
    for (const [pattern, label] of forbidden) if (pattern.test(text)) problems.push(`${rel}: ${label}`);
  }
  assert.deepEqual(problems, []);
});

test('no way to run code built from text, and no HTML built from page or clipboard text', () => {
  const forbidden = [
    [/\beval\s*\(/, 'eval()'],
    [/new\s+Function\s*\(/, 'new Function()'],
    [/setTimeout\s*\(\s*['"`]/, 'setTimeout with a string'],
    [/\.innerHTML\s*=|\.outerHTML\s*=/, 'innerHTML / outerHTML assignment'],
    [/insertAdjacentHTML/, 'insertAdjacentHTML'],
    [/document\.write/, 'document.write'],
    [/DOMParser/, 'DOMParser'],
  ];
  const problems = [];
  for (const rel of files.filter((f) => f.endsWith('.js'))) {
    const text = code(rel);
    for (const [pattern, label] of forbidden) if (pattern.test(text)) problems.push(`${rel}: ${label}`);
  }
  assert.deepEqual(problems, []);
});

test('pages and styles load nothing from the network', () => {
  const problems = [];
  for (const rel of files.filter((f) => /\.(?:html|css)$/.test(f))) {
    const text = read(rel);
    if (/(?:src|href)\s*=\s*["']https?:/i.test(text)) problems.push(`${rel}: external src/href`);
    if (/url\(\s*["']?https?:/i.test(text)) problems.push(`${rel}: external url()`);
    if (/@import\s+(?:url\()?["']?https?:/i.test(text)) problems.push(`${rel}: external @import`);
  }
  assert.deepEqual(problems, []);
});

test('the only storage it touches holds settings, hashes and counts', () => {
  const settings = code('shared/settings.js');
  const keys = [...settings.matchAll(/\b(?:get|set)\(\s*(?:'([a-z]+)'|\{\s*([a-z]+))/g)].map((m) => m[1] || m[2]);
  assert.deepEqual([...new Set(keys)].sort(), ['allowlist', 'settings', 'stats']);
  for (const rel of files.filter((f) => f.endsWith('.js') && f !== 'shared/settings.js')) {
    assert.ok(!/localStorage|sessionStorage|indexedDB|document\.cookie/.test(code(rel)), `${rel} must not use other storage`);
  }
});

test('the manifest asks for the minimum', () => {
  for (const browser of ['chrome', 'firefox']) {
    const m = manifestFor(browser);
    assert.deepEqual(m.permissions.slice().sort(), ['activeTab', 'scripting', 'storage']);
    assert.deepEqual(m.optional_host_permissions, ['https://*/*'], 'host access is optional, https only, and requested per site');
    for (const absent of ['host_permissions', 'optional_permissions', 'background', 'web_accessible_resources', 'externally_connectable', 'declarative_net_request', 'chrome_url_overrides', 'devtools_page', 'commands']) {
      assert.equal(m[absent], undefined, `${browser}: the manifest must not declare ${absent}`);
    }
    assert.equal(m.content_security_policy, undefined, 'the default extension CSP is the strictest option');
  }
});

test('the content scripts only touch the clipboard data they are handed by paste and drop events', () => {
  const text = code('content/content.js') + code('content/insert.js');
  assert.ok(/clipboardData/.test(text) && /dataTransfer/.test(text));
  // navigator.clipboard is banned outright by the first test. These cover the other ways to touch the clipboard.
  assert.ok(!/execCommand\(\s*['"](?:copy|cut)['"]/.test(text), 'never copies or cuts on its own');
  assert.ok(!/addEventListener\(\s*['"](?:copy|cut)['"]/.test(text), 'never listens for copy or cut');
});

test('what the dialog displays is masked, never the full value', () => {
  const ui = code('content/ui.js');
  // The dialog receives a mask function and shows what it returns. It must never read a finding's value itself.
  // (".value" on a button definition such as { label, value: 'redact' } is fine; that is a choice, not a secret.)
  assert.ok(!/\b(?:f|finding|findings\[\w+\])\.value\b/.test(ui), 'ui.js must not read finding.value');
  assert.ok(/mask\(f\)/.test(ui), 'findings are shown through mask()');
});
