const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const V = require('../src/engine/validators.js');
const { sha256Hex } = require('../src/engine/hash.js');

test('luhn accepts the standard test cards and rejects altered ones', () => {
  for (const ok of ['4111111111111111', '5555555555554444', '378282246310005', '6011111111111117']) {
    assert.equal(V.luhn(ok), true, ok);
  }
  for (const bad of ['4111111111111112', '5555555555554445', '1234567812345678', '']) {
    assert.equal(V.luhn(bad), false, bad);
  }
});

test('verhoeff: a generated check digit validates, and any single-digit change is caught', () => {
  for (const base of ['23634567891', '98765432109', '42424242424']) {
    const full = base + V.verhoeffCheckDigit(base);
    assert.equal(V.verhoeff(full), true, full);
    for (let i = 0; i < full.length; i++) {
      const altered = full.slice(0, i) + String((Number(full[i]) + 1) % 10) + full.slice(i + 1);
      assert.equal(V.verhoeff(altered), false, `${full} -> ${altered}`);
    }
  }
  assert.equal(V.verhoeff('2363'), true, 'the textbook example');
});

test('iban mod-97', () => {
  assert.equal(V.ibanValid('GB82 WEST 1234 5698 7654 32'), true);
  assert.equal(V.ibanValid('DE89370400440532013000'), true);
  assert.equal(V.ibanValid('GB82 WEST 1234 5698 7654 33'), false);
  assert.equal(V.ibanValid('not an iban'), false);
});

test('entropy separates words from random strings', () => {
  assert.equal(V.shannonEntropy('aaaaaaaa'), 0);
  assert.ok(V.shannonEntropy('password') < 3);
  assert.ok(V.shannonEntropy(crypto.randomBytes(30).toString('base64')) > 4);
});

test('repetitive strings are recognised', () => {
  for (const s of ['xxxxxxxxxxxxxxxxxxxx', '00000000000000000000', 'abababababababababab', 'aaaaaaaaBBBB1111']) {
    assert.equal(V.isRepetitive(s), true, s);
  }
  for (const s of ['k3Jd9sL0qPz7Wm2XvB8n', 'short']) assert.equal(V.isRepetitive(s), false, s);
});

test('placeholders', () => {
  const yes = [
    '<your-token>', '${API_KEY}', '{{ secrets.TOKEN }}', '$(cat key)', '$DB_PASS', '%DB_PASS%', '********', 'xxxxxxxx',
    'your_api_key', 'your-secret-here', 'YOUR_API_KEY_HERE', 'changeme', 'password', 'example', 'null', 'undefined',
    'hunter2', 'my-secret-token', '[REDACTED:API_KEY]', 'replace_me', '', 'true', 'string',
  ];
  for (const v of yes) assert.equal(V.isPlaceholder(v), true, JSON.stringify(v));
  const no = ['k3Jd9sL0qPz7Wm2X', 'Tr0ub4dor&3', 's3cr3t-Value-9921', 'correct-horse-battery-staple-7'];
  for (const v of no) assert.equal(V.isPlaceholder(v), false, v);
});

test('code references are not secrets', () => {
  const yes = [
    'process.env.API_KEY', 'os.environ["KEY"]', 'config.get("token")', 'getPassword()', 'self.token', 'user_password',
    'userPassword', 'request.headers.Authorization', 'Optional[str]', 'args.password', '$secret', 'await vault.read()',
  ];
  for (const v of yes) assert.equal(V.looksLikeCodeReference(v), true, v);
  const no = ['k3Jd9sL0qPz7Wm2X', 'Tr0ub4dor&3', 'a1b2c3d4e5f6a7b8', 's3cr3t-Value-9921'];
  for (const v of no) assert.equal(V.looksLikeCodeReference(v), false, v);
});

test('jwt header check', () => {
  const b64url = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  assert.equal(V.jwtLooksValid(`${b64url({ alg: 'HS256', typ: 'JWT' })}.${b64url({ sub: '1' })}.abcdefghij`), true);
  assert.equal(V.jwtLooksValid('eyJub3Rqc29u.eyJ4.yyy'), false);
  assert.equal(V.jwtLooksValid('plain.text.here'), false);
});

test('card numbers need the right issuer, length and checksum', () => {
  // Real-looking numbers are generated (prefix + body + Luhn digit) rather than written out.
  const make = (prefix, length) => {
    let body = prefix;
    while (body.length < length - 1) body += String((body.length * 7 + 3) % 10);
    return body + V.luhnCheckDigit(body);
  };
  for (const [prefix, length] of [['4539', 16], ['4916', 13], ['5425', 16], ['2221', 16], ['3714', 15], ['6011', 16], ['3528', 16], ['6521', 16]]) {
    const number = make(prefix, length);
    assert.equal(number.length, length);
    assert.equal(V.cardNumberValid(number), true, number);
  }
  const good = make('4539', 16);
  assert.equal(V.cardNumberValid(good.slice(0, 15) + String((Number(good[15]) + 1) % 10)), false, 'fails Luhn');
  assert.equal(V.cardNumberValid(make('9999', 16)), false, 'no such issuer');
  assert.equal(V.cardNumberValid('0000000000000000'), false);
  assert.equal(V.cardNumberValid('411111111111'), false, 'too short');
});

test('well-known documentation test cards are not flagged', () => {
  for (const n of ['4111111111111111', '4242424242424242', '5555555555554444', '378282246310005', '6011111111111117']) {
    assert.equal(V.luhn(n), true, 'they are valid numbers...');
    assert.equal(V.cardNumberValid(n), false, '...but pasting them is harmless: ' + n);
  }
});

test('reserved documentation domains', () => {
  for (const d of ['example.com', 'sub.example.org', 'foo.test', 'localhost']) assert.equal(V.isExampleDomain(d), true, d);
  for (const d of ['gmail.com', 'company.io']) assert.equal(V.isExampleDomain(d), false, d);
});

test('sha256 matches node:crypto, including awkward lengths and non-ASCII text', () => {
  const samples = ['', 'abc', 'The quick brown fox jumps over the lazy dog', 'héllo wörld ✓ 日本語 🔐'];
  for (const n of [1, 54, 55, 56, 57, 63, 64, 65, 119, 120, 128, 1000, 100000]) samples.push('a'.repeat(n));
  for (const s of samples) {
    const expected = crypto.createHash('sha256').update(s, 'utf8').digest('hex');
    assert.equal(sha256Hex(s), expected, `length ${s.length}`);
  }
  assert.equal(sha256Hex(''), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
});
