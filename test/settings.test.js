const test = require('node:test');
const assert = require('node:assert/strict');
const S = require('../src/shared/settings.js');
const sites = require('../src/shared/sites.js');
const { categories } = require('../src/engine/rules.js');

// A stand-in for chrome.storage so the storage code runs for real.
function fakeApi() {
  const areas = { sync: {}, local: {} };
  const listeners = [];
  const area = (name) => ({
    async get(key) {
      return key in areas[name] ? { [key]: JSON.parse(JSON.stringify(areas[name][key])) } : {};
    },
    async set(obj) {
      const changes = {};
      for (const [k, v] of Object.entries(obj)) {
        changes[k] = { oldValue: areas[name][k], newValue: v };
        areas[name][k] = JSON.parse(JSON.stringify(v));
      }
      listeners.forEach((l) => l(changes, name));
    },
  });
  return { storage: { sync: area('sync'), local: area('local'), onChanged: { addListener: (l) => listeners.push(l) } }, areas };
}

test('defaults match the engine: strong categories on, noisy ones off', () => {
  const d = S.defaults();
  assert.equal(d.enabled, true);
  assert.equal(d.mode, 'balanced');
  assert.equal(d.action, 'ask');
  for (const [name, info] of Object.entries(categories)) assert.equal(d.categories[name], info.defaultOn, name);
  assert.equal(d.categories.email, false);
  assert.equal(d.categories.apiKey, true);
});

test('normalize never throws and always returns valid settings', () => {
  for (const junk of [null, undefined, 42, 'x', [], {}, { mode: 'loud' }, { categories: 'no' }, { pausedHosts: 'x' }, { customPatterns: [null, 5, {}] }]) {
    const n = S.normalize(junk);
    assert.deepEqual(Object.keys(n).sort(), Object.keys(S.defaults()).sort());
    assert.ok(S.MODES.includes(n.mode) && S.ACTIONS.includes(n.action));
  }
});

test('the typing warning is on by default and can be switched off', () => {
  assert.equal(S.defaults().liveCheck, true);
  assert.equal(S.normalize({ liveCheck: false }).liveCheck, false);
  assert.equal(S.normalize({ liveCheck: 'no' }).liveCheck, true, 'a non-boolean is ignored');
  assert.equal(S.normalize({}).liveCheck, true);
});

test('normalize keeps good values and drops bad ones', () => {
  const n = S.normalize({
    enabled: false,
    mode: 'strict',
    action: 'redact',
    scanFiles: false,
    categories: { email: true, apiKey: false, bogus: true, phone: 'yes' },
    pausedHosts: ['Claude.ai', 'claude.ai', 'bad host!', 7, 'chatgpt.com'],
    customPatterns: [
      { name: 'Codename', pattern: 'PROJECT-\\d+' },
      { name: 'Evil', pattern: '(a+)+$' },
      { name: 'Broken', pattern: 'a[' },
      { pattern: 'x'.repeat(600) },
    ],
  });
  assert.equal(n.enabled, false);
  assert.equal(n.mode, 'strict');
  assert.equal(n.action, 'redact');
  assert.equal(n.scanFiles, false);
  assert.equal(n.categories.email, true);
  assert.equal(n.categories.apiKey, false);
  assert.equal(n.categories.phone, false, 'a non-boolean is ignored');
  assert.ok(!('bogus' in n.categories));
  assert.deepEqual(n.pausedHosts, ['claude.ai', 'chatgpt.com']);
  assert.deepEqual(n.customPatterns.map((p) => p.name), ['Codename'], 'unsafe and broken patterns are dropped');
});

test('modes map to severity thresholds', () => {
  assert.equal(S.toScanOptions(S.normalize({ mode: 'quiet' })).minSeverity, 'high');
  assert.equal(S.toScanOptions(S.normalize({ mode: 'balanced' })).minSeverity, 'medium');
  assert.equal(S.toScanOptions(S.normalize({ mode: 'strict' })).minSeverity, 'low');
  const opts = S.toScanOptions(S.defaults(), ['abc']);
  assert.deepEqual(opts.allowlist, ['abc']);
  assert.ok(opts.categories && Array.isArray(opts.customPatterns));
});

test('paused hosts and the master switch', () => {
  const s = S.normalize({ pausedHosts: ['claude.ai'] });
  assert.equal(S.isPaused(s, 'claude.ai'), true);
  assert.equal(S.isPaused(s, 'CLAUDE.AI'), true);
  assert.equal(S.isPaused(s, 'chatgpt.com'), false);
  assert.equal(S.isPaused(S.normalize({ enabled: false }), 'chatgpt.com'), true);
});

test('settings round-trip through storage and survive corruption', async () => {
  const api = fakeApi();
  const store = S.createStore(api);
  assert.deepEqual(await store.getSettings(), S.defaults());
  const saved = await store.saveSettings({ mode: 'strict', categories: { email: true } });
  assert.equal(saved.mode, 'strict');
  assert.equal((await store.getSettings()).categories.email, true);
  api.areas.sync.settings = 'garbage';
  assert.deepEqual(await store.getSettings(), S.defaults());
});

test('the ignore list stores hashes only, rejects non-hashes, and can be cleared', async () => {
  const store = S.createStore(fakeApi());
  const good = 'a'.repeat(64);
  await store.addToAllowlist([good, good, 'not-a-hash', 'sk-live-secret']);
  const list = await store.getAllowlist();
  assert.deepEqual(list.map((e) => e.hash), [good]);
  assert.ok(typeof list[0].added === 'number');
  await store.clearAllowlist();
  assert.deepEqual(await store.getAllowlist(), []);
});

test('the ignore list is capped', async () => {
  const store = S.createStore(fakeApi());
  const many = Array.from({ length: 600 }, (_, i) => i.toString(16).padStart(64, '0'));
  await store.addToAllowlist(many);
  assert.equal((await store.getAllowlist()).length, 500);
});

test('counters only count, and only known ones', async () => {
  const store = S.createStore(fakeApi());
  await store.bumpStat('warned');
  await store.bumpStat('warned');
  await store.bumpStat('redacted', 3);
  await store.bumpStat('not-a-counter');
  const stats = await store.getStats();
  assert.equal(stats.warned, 2);
  assert.equal(stats.redacted, 3);
  assert.ok(!('not-a-counter' in stats));
  assert.deepEqual(Object.keys(stats).sort(), ['blockedFiles', 'cancelled', 'pastedAnyway', 'redacted', 'warned']);
  await store.resetStats();
  assert.equal((await store.getStats()).warned, 0);
});

test('changes in other tabs reach the listener', async () => {
  const api = fakeApi();
  const store = S.createStore(api);
  const seen = [];
  store.onSettingsChange((settings, allow) => seen.push({ settings, allow }));
  await store.saveSettings({ enabled: false });
  await store.addToAllowlist(['b'.repeat(64)]);
  assert.equal(seen[0].settings.enabled, false);
  assert.deepEqual(seen[1].allow, ['b'.repeat(64)]);
});

// --- sites -------------------------------------------------------------------------------------

test('match patterns are valid and cover every site', () => {
  const patterns = sites.matchPatterns();
  assert.ok(patterns.length >= sites.list.length);
  for (const p of patterns) assert.match(p, /^https:\/\/[a-z0-9.-]+\/.*\*$|^https:\/\/[a-z0-9.-]+\/\*$/i, p);
  assert.ok(patterns.includes('https://claude.ai/*'));
  assert.ok(patterns.includes('https://huggingface.co/chat*'));
  assert.equal(new Set(patterns).size, patterns.length, 'no duplicates');
});

test('siteFor recognises protected pages and nothing else', () => {
  assert.deepEqual(sites.siteFor('https://claude.ai/chat/abc'), { name: 'Claude', host: 'claude.ai' });
  assert.equal(sites.siteFor('https://chatgpt.com/c/123').name, 'ChatGPT');
  assert.equal(sites.siteFor('https://huggingface.co/chat/conversation/1').name, 'Hugging Chat');
  assert.equal(sites.siteFor('https://huggingface.co/models'), null, 'only the chat part of huggingface');
  assert.equal(sites.siteFor('http://claude.ai/'), null, 'https only');
  assert.equal(sites.siteFor('https://evil-claude.ai.example.com/'), null);
  assert.equal(sites.siteFor('https://example.com/'), null);
  assert.equal(sites.siteFor('not a url'), null);
  assert.equal(sites.siteFor('chrome://extensions'), null);
});

test('custom sites: only plain https host names are kept', () => {
  const s = require('../src/shared/settings.js');
  const out = s.normalize({ customSites: ['Chat.Example.com', 'chat.example.com', '127.0.0.1', 'localhost', 'a b.com', 'https://x.com', 'x.com/path', 42, 'ok-site.io'] });
  assert.deepEqual(out.customSites, ['chat.example.com', 'ok-site.io']);
  assert.deepEqual(s.normalize({}).customSites, []);
});
