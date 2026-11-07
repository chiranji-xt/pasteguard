const test = require('node:test');
const assert = require('node:assert/strict');
const { scan, redact, mask, hashValue, validateCustomPattern } = require('../src/engine/detect.js');
const { categories } = require('../src/engine/rules.js');
const { cleanCorpus, dirtyCorpus, fixtures, rand, pem } = require('./fixtures.js');

const DEFAULTS = { minSeverity: 'medium' }; // what the extension does out of the box: default categories, medium and above
const ALL = { minSeverity: 'low', categories: Object.fromEntries(Object.keys(categories).map((c) => [c, true])) };

// --- false positives: the thing that decides whether people keep the extension installed ---------

for (const [name, text] of Object.entries(cleanCorpus)) {
  test(`clean text stays silent: ${name}`, () => {
    const { findings } = scan(text, DEFAULTS);
    assert.deepEqual(
      findings.map((f) => `${f.ruleId}: ${f.value.slice(0, 40)}`),
      [],
      'these must not be flagged'
    );
  });
}

test('even with every category on, ordinary prose and code produce no high or medium findings', () => {
  for (const [name, text] of Object.entries(cleanCorpus)) {
    const loud = scan(text, ALL).findings.filter((f) => f.severity !== 'low');
    assert.deepEqual(loud.map((f) => f.ruleId), [], name);
  }
});

// --- true positives in realistic text -------------------------------------------------------------

for (const [name, { text, expect }] of Object.entries(dirtyCorpus())) {
  test(`real-looking text is caught: ${name}`, () => {
    const found = new Set(scan(text, DEFAULTS).findings.map((f) => f.ruleId));
    for (const id of expect) assert.ok(found.has(id), `expected ${id}; got ${[...found].join(', ') || 'nothing'}`);
  });
}

// --- invisible characters inside a secret ----------------------------------------------------------

test('a zero-width character inside a token does not hide it, and redaction removes the whole span', () => {
  const k = 'gh' + 'p_' + rand(36, 'alnum', 31);
  for (const invisible of ['​', '‌', '‍', '⁠', '﻿', '­']) {
    const dirty = k.slice(0, 18) + invisible + k.slice(18);
    const text = 'before ' + dirty + ' after';
    const { findings } = scan(text, DEFAULTS);
    assert.equal(findings.length, 1, 'U+' + invisible.charCodeAt(0).toString(16));
    assert.equal(text.slice(findings[0].start, findings[0].end), dirty, 'positions point into the original text');
    assert.equal(redact(text, findings).text, 'before [REDACTED:GITHUB_TOKEN] after');
  }
});

test('invisible characters before and between several secrets keep every position right', () => {
  const a = 'gh' + 'p_' + rand(36, 'alnum', 32);
  const b = 'AKIA' + rand(16, 'b32', 33);
  const text = '​​one ' + a.slice(0, 10) + '​' + a.slice(10) + '﻿ two ' + b + ' ‍end';
  const { findings } = scan(text, DEFAULTS);
  assert.equal(findings.length, 2);
  assert.equal(redact(text, findings).text, '​​one [REDACTED:GITHUB_TOKEN]﻿ two [REDACTED:AWS_ACCESS_KEY_ID] ‍end');
});

test('text without invisible characters is untouched by that step', () => {
  const k = 'gh' + 'p_' + rand(36, 'alnum', 34);
  const [f] = scan('x ' + k, DEFAULTS).findings;
  assert.equal(f.start, 2);
  assert.equal(f.end, 2 + k.length);
});

test('a Google service-account key written with \\n escapes is caught and fully redacted', () => {
  const head = '-----BEGIN ' + 'PRIVATE KEY-----';
  const foot = '-----END ' + 'PRIVATE KEY-----';
  const body = [rand(64, 'b64', 40), rand(64, 'b64', 41), rand(64, 'b64', 42)].join('\\n');
  const text = '{"type":"service_account","private_key":"' + head + '\\n' + body + '\\n' + foot + '\\n","client_email":"svc@p.iam.gserviceaccount.com"}';
  const out = redact(text, scan(text, DEFAULTS).findings).text;
  assert.ok(out.includes('[REDACTED:PRIVATE_KEY]') && out.includes('client_email'), out);
  assert.ok(!out.includes(body.slice(0, 40)), 'no key material is left');
});

// --- findings -------------------------------------------------------------------------------------

test('findings carry exact positions that point at the secret', () => {
  const key = fixtures['github-token'].positive[0]();
  const text = `before ${key} after`;
  const [f] = scan(text, DEFAULTS).findings;
  assert.equal(text.slice(f.start, f.end), key);
  assert.equal(f.value, key);
  assert.equal(f.tag, 'GITHUB_TOKEN');
  assert.equal(f.severity, 'high');
});

test('only the value is flagged in key=value, so the key name stays readable', () => {
  const pw = rand(12, 'alnum', 5) + '#9';
  const text = `DB_PASSWORD=${pw}`;
  const [f] = scan(text, DEFAULTS).findings;
  assert.equal(f.value, pw);
  assert.equal(redact(text, [f]).text, 'DB_PASSWORD=[REDACTED:PASSWORD_ASSIGNMENT]');
});

test('a specific rule beats a generic one on the same text', () => {
  const key = 'sk-' + 'ant-api03-' + rand(93, 'b64url', 7);
  const { findings } = scan('key: ' + key, DEFAULTS);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, 'anthropic-api-key', 'not the generic OpenAI-style rule');
});

test('the same key found by a provider rule and by a "secret =" line is reported once', () => {
  const key = 'gh' + 'p_' + rand(36, 'alnum', 8);
  const { findings } = scan(`GITHUB_TOKEN=${key}`, DEFAULTS);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, 'github-token');
});

test('several different secrets in one paste are all found, in order', () => {
  const a = 'gh' + 'p_' + rand(36, 'alnum', 1);
  const b = 'AKIA' + rand(16, 'b32', 2);
  const c = 'sk_' + 'live_' + rand(24, 'alnum', 3);
  const { findings } = scan(`one ${a}\ntwo ${b}\nthree ${c}`, DEFAULTS);
  assert.deepEqual(findings.map((f) => f.value), [a, b, c]);
});

test('a password inside a URL is flagged and the email-like part is not double counted', () => {
  const text = 'postgres://app:' + rand(16, 'alnum', 4) + '@db.mycompany.io/app';
  const { findings } = scan(text, { minSeverity: 'low', categories: { email: true } });
  assert.deepEqual(findings.map((f) => f.ruleId), ['url-credentials']);
});

// --- settings -------------------------------------------------------------------------------------

test('severity threshold: quiet mode only reports high-severity findings', () => {
  const text = 'Authorization: Bearer ' + rand(40, 'b64url', 9) + '\nkey ' + 'gh' + 'p_' + rand(36, 'alnum', 10);
  assert.deepEqual(scan(text, { minSeverity: 'medium' }).findings.map((f) => f.ruleId), ['bearer-token', 'github-token']);
  assert.deepEqual(scan(text, { minSeverity: 'high' }).findings.map((f) => f.ruleId), ['github-token']);
});

test('category switches turn rules off', () => {
  const text = 'gh' + 'p_' + rand(36, 'alnum', 11);
  assert.equal(scan(text, { categories: { apiKey: false } }).findings.length, 0);
  assert.equal(scan(text, { categories: { apiKey: true } }).findings.length, 1);
});

test('contact details are off until asked for', () => {
  const text = 'mail jane.doe@gmail.com or call +91 98765 43210';
  assert.equal(scan(text, DEFAULTS).findings.length, 0);
  assert.deepEqual(scan(text, { minSeverity: 'low', categories: { email: true, phone: true } }).findings.map((f) => f.ruleId), ['email', 'phone']);
});

test('the ignore list works by hash and never needs the value stored', () => {
  const key = 'gh' + 'p_' + rand(36, 'alnum', 12);
  assert.equal(scan(key, DEFAULTS).findings.length, 1);
  assert.equal(scan(key, { ...DEFAULTS, allowlist: [hashValue(key)] }).findings.length, 0);
  assert.equal(scan(key, { ...DEFAULTS, allowlist: new Set([hashValue(key)]) }).findings.length, 0);
  assert.equal(scan(key + 'X', { ...DEFAULTS, allowlist: [hashValue(key)] }).findings.length, 1, 'a different token is not covered by the ignore');
  assert.equal(hashValue(key).length, 64);
});

// --- custom patterns ------------------------------------------------------------------------------

test('custom patterns find what the user asked for, and always count as high severity', () => {
  const opts = { minSeverity: 'high', customPatterns: [{ name: 'Project codename', pattern: 'PROJECT-[A-Z]{4}-\\d{3}' }] };
  const { findings } = scan('the launch of PROJECT-ZEUS-042 is secret', opts);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].label, 'Project codename');
  assert.equal(findings[0].value, 'PROJECT-ZEUS-042');
});

test('a custom pattern with a capture group flags only the group', () => {
  const { findings } = scan('internal id: acct_91823', { customPatterns: [{ name: 'Account', pattern: 'acct_(\\d+)' }] });
  assert.equal(findings[0].value, '91823');
});

test('unsafe or broken custom patterns are refused', () => {
  assert.equal(validateCustomPattern('abc[').ok, false);
  assert.equal(validateCustomPattern('').ok, false);
  assert.equal(validateCustomPattern('a*').ok, false, 'matches empty text');
  assert.equal(validateCustomPattern('(a+)+$').ok, false, 'nested repetition');
  assert.equal(validateCustomPattern('(\\w+\\s*)*x').ok, false, 'nested repetition');
  assert.equal(validateCustomPattern('x'.repeat(501)).ok, false, 'too long');
  assert.equal(validateCustomPattern('PROJECT-\\d{3}').ok, true);
  const { findings } = scan('(aaaa)', { customPatterns: [{ name: 'bad', pattern: '(a+)+$' }] });
  assert.equal(findings.length, 0, 'a refused pattern is never run');
});

// --- masking and redacting --------------------------------------------------------------------------

test('masked previews never show enough to use the secret', () => {
  const key = 'gh' + 'p_' + rand(36, 'alnum', 13);
  const [f] = scan(key, DEFAULTS).findings;
  const shown = mask(f);
  assert.ok(!shown.includes(key));
  assert.ok(shown.length < 24);
  assert.match(shown, /^ghp_…/);
  const card = scan('card ' + fixtures['credit-card'].positive[0]().slice(5), DEFAULTS).findings[0];
  assert.match(mask(card), /^•••• \d{4}$/);
  const keyBlock = scan(pem('RSA ' + 'PRIVATE KEY', 14), DEFAULTS).findings[0];
  assert.ok(mask(keyBlock).startsWith('-----BEGIN') && mask(keyBlock).length < 80);
});

test('a masked preview never reveals the middle of any secret, for every kind of rule and every form', () => {
  // Regression: a private key on ONE line (Google service-account JSON) was shown in full, because the preview took "the first line".
  const ALL_ON = { minSeverity: 'low', categories: Object.fromEntries(Object.keys(categories).map((c) => [c, true])) };
  let checked = 0;
  for (const [id, fx] of Object.entries(fixtures)) {
    for (const make of fx.positive) {
      const text = make();
      for (const f of scan(text, ALL_ON).findings.filter((x) => x.ruleId === id)) {
        const shown = mask(f);
        assert.ok(shown.length <= 90, `${id}: preview is ${shown.length} characters: ${shown.slice(0, 120)}`);
        if (f.value.length >= 30) {
          const middle = f.value.slice(Math.floor(f.value.length / 2) - 6, Math.floor(f.value.length / 2) + 6);
          assert.ok(!shown.includes(middle), `${id}: the preview reveals the middle of the secret`);
        }
        checked++;
      }
    }
  }
  assert.ok(checked > 100, 'the test must actually cover many cases (covered ' + checked + ')');
});

test('redact replaces each finding with a labelled placeholder and keeps everything else', () => {
  const a = 'gh' + 'p_' + rand(36, 'alnum', 15);
  const text = `export TOKEN=${a}\nrun it`;
  const { findings } = scan(text, DEFAULTS);
  const out = redact(text, findings);
  assert.equal(out.text, 'export TOKEN=[REDACTED:GITHUB_TOKEN]\nrun it');
  assert.equal(out.count, 1);
  assert.ok(!out.text.includes(a));
});

test('redaction is consistent: one value, one placeholder; different values are numbered', () => {
  const a = 'gh' + 'p_' + rand(36, 'alnum', 16);
  const b = 'gh' + 'p_' + rand(36, 'alnum', 17);
  const text = `${a} ${b} ${a}`;
  const out = redact(text, scan(text, DEFAULTS).findings);
  assert.equal(out.text, '[REDACTED:GITHUB_TOKEN_1] [REDACTED:GITHUB_TOKEN_2] [REDACTED:GITHUB_TOKEN_1]');
});

test('redacting leaves no trace of the originals, even in a big mixed paste', () => {
  const { text, expect } = dirtyCorpus()['person with documents'];
  const findings = scan(text, DEFAULTS).findings;
  const out = redact(text, findings).text;
  for (const f of findings) assert.ok(!out.includes(f.value), `${f.ruleId} survived`);
  assert.equal(scan(out, DEFAULTS).findings.length, 0, 'the redacted text is clean when scanned again');
  assert.ok(expect.length >= 3);
});

test('redact with nothing found returns the text untouched', () => {
  assert.deepEqual(redact('hello', []), { text: 'hello', count: 0, items: [] });
});

// --- limits and robustness ---------------------------------------------------------------------------

test('empty and non-string input is safe', () => {
  for (const v of ['', null, undefined, 42, {}]) assert.deepEqual(scan(v, DEFAULTS), { findings: [], truncated: false });
});

test('very long text is cut off at the limit and says so', () => {
  const key = 'gh' + 'p_' + rand(36, 'alnum', 18);
  const filler = 'a '.repeat(500);
  const r = scan(filler + key, { ...DEFAULTS, maxChars: 800 });
  assert.equal(r.truncated, true);
  assert.equal(r.findings.length, 0, 'the key is past the limit');
});

test('scanning does not leak state between calls (global regex lastIndex)', () => {
  const key = 'gh' + 'p_' + rand(36, 'alnum', 19);
  for (let i = 0; i < 5; i++) assert.equal(scan('x ' + key, DEFAULTS).findings.length, 1);
});

test('unicode, emoji and line endings do not shift positions', () => {
  const key = 'gh' + 'p_' + rand(36, 'alnum', 20);
  const text = `héllo 🔐 日本語\r\nkey: ${key}\r\n`;
  const [f] = scan(text, DEFAULTS).findings;
  assert.equal(text.slice(f.start, f.end), key);
});

// --- speed: a paste must never freeze the page -------------------------------------------------------

function timed(label, text, budgetMs) {
  const started = process.hrtime.bigint();
  scan(text, ALL);
  const ms = Number(process.hrtime.bigint() - started) / 1e6;
  assert.ok(ms < budgetMs, `${label}: ${ms.toFixed(0)} ms (budget ${budgetMs} ms)`);
  return ms;
}

test('worst-case inputs stay fast (all rules on)', () => {
  const N = 200000;
  const cases = {
    'plain letters': 'a'.repeat(N),
    'digits only': '1'.repeat(N),
    'digit groups': '1234 '.repeat(N / 5),
    'dashes and digits': '12-'.repeat(N / 3),
    'many sk- prefixes': 'sk-'.repeat(N / 3),
    'many password= with no value': 'password='.repeat(N / 9),
    'many token: lines': 'token: \n'.repeat(N / 8),
    'long base64 line': rand(N, 'b64', 1),
    'private key header with no end, repeated': '-----BEGIN PRIVATE KEY-----\n'.repeat(N / 27),
    'many @ signs': 'a@'.repeat(N / 2),
    'many dots': '.'.repeat(N),
    'many colons and digits': '1234567890:'.repeat(N / 11),
    'whitespace': ' \n'.repeat(N / 2),
    'unterminated quotes': 'password="'.repeat(N / 10),
  };
  const slow = [];
  for (const [label, text] of Object.entries(cases)) {
    const ms = timed(label, text, 2500);
    if (ms > 400) slow.push(`${label}: ${ms.toFixed(0)} ms`);
  }
  assert.deepEqual(slow, [], 'inputs slower than 400 ms deserve a look');
});

test('a typical large paste (1 MB of code and logs) scans quickly', () => {
  const line = 'const user = await db.query("SELECT * FROM users WHERE id = $1", [id]); // fetch the user\nlogger.info("request done", { ms: 12, status: 200 });\n';
  const ms = timed('1 MB of code', line.repeat(Math.ceil(1000000 / line.length)), 1500);
  assert.ok(ms >= 0);
});

// --- keys wrapped onto several lines (chat boxes, PDFs, emails break long tokens) ----------------

test('a provider key wrapped across lines is found and redacted whole', () => {
  const k = 'sk-' + 'ant-api03-' + rand(93, 'b64url', 5);
  const texts = [
    `my key is ${k.slice(0, 40)}\n${k.slice(40)}\nthanks`,
    `key:\n${k.slice(0, 40)}\r\n   ${k.slice(40, 70)}\n${k.slice(70)}`,
  ];
  for (const text of texts) {
    const result = scan(text, DEFAULTS);
    assert.equal(result.findings.length, 1, JSON.stringify(text.slice(0, 80)));
    const out = redact(text, result.findings);
    const redacted = typeof out === 'string' ? out : out.text;
    assert.ok(!redacted.includes(k.slice(0, 40)) && !redacted.includes(k.slice(70)), 'no part of the key may remain');
  }
});

test('line breaks next to ordinary prose are not joined', () => {
  assert.equal(scan('line one is here\nline two goes there\nsk-learn is nice', DEFAULTS).findings.length, 0);
  const k = 'sk-' + 'ant-api03-' + rand(93, 'b64url', 5);
  const result = scan(`${k}\nthanks a lot`, DEFAULTS);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].end, k.length, 'the word after the key must stay outside it');
});
