const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const zlib = require('node:zlib');
const { createZip, readZip } = require('../scripts/lib/zip.js');
const { crc32 } = require('../scripts/lib/crc32.js');
const { makeIcons, SIZES } = require('../scripts/make-icons.js');
const { manifestFor, checkBuild, CONTENT_SCRIPTS } = require('../scripts/build.js');
const sites = require('../src/shared/sites.js');
const pkg = require('../package.json');

test('crc32 matches the standard check value', () => {
  assert.equal(crc32(Buffer.from('123456789')), 0xcbf43926);
  assert.equal(crc32(Buffer.alloc(0)), 0);
});

test('zip round-trips, stays deterministic, and is a valid archive', () => {
  const entries = [
    { name: 'b/file.txt', data: Buffer.from('hello '.repeat(100)) },
    { name: 'a.json', data: Buffer.from('{"x":1}') },
    { name: 'binary.bin', data: Buffer.from([0, 1, 2, 3, 255, 254]) },
    { name: 'unicode-ü-日本.txt', data: Buffer.from('ü') },
  ];
  const zip = createZip(entries);
  assert.deepEqual(zip, createZip(entries.slice().reverse()), 'entry order must not change the output');
  const back = readZip(zip);
  assert.deepEqual(back.map((e) => e.name), ['a.json', 'b/file.txt', 'binary.bin', 'unicode-ü-日本.txt']);
  for (const e of entries) assert.deepEqual(back.find((b) => b.name === e.name).data, e.data);
  assert.equal(zip.readUInt32LE(0), 0x04034b50, 'starts with a zip local header');
});

test('icons are valid PNGs at every size', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pg-icons-'));
  try {
    const files = makeIcons(dir);
    assert.equal(files.length, SIZES.length);
    for (const file of files) {
      const data = fs.readFileSync(file);
      assert.deepEqual([...data.subarray(0, 8)], [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
      const size = Number(path.basename(file).match(/\d+/)[0]);
      assert.equal(data.readUInt32BE(16), size);
      assert.equal(data.readUInt32BE(20), size);
      // every chunk's checksum must be right, or browsers refuse the image
      let p = 8;
      while (p < data.length) {
        const length = data.readUInt32BE(p);
        const type = data.toString('ascii', p + 4, p + 8);
        const body = data.subarray(p + 4, p + 8 + length);
        assert.equal(data.readUInt32BE(p + 8 + length), crc32(body), `${path.basename(file)} ${type} checksum`);
        if (type === 'IDAT') assert.ok(zlib.inflateSync(data.subarray(p + 8, p + 8 + length)).length === (size * 4 + 1) * size);
        p += 12 + length;
      }
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('the committed icons exist at every size', () => {
  for (const size of SIZES) assert.ok(fs.existsSync(path.join(__dirname, '..', 'src', 'icons', `icon-${size}.png`)), `icon-${size}.png`);
});

for (const browser of ['chrome', 'firefox']) {
  test(`${browser} manifest is minimal and correct`, () => {
    const m = manifestFor(browser);
    assert.equal(m.manifest_version, 3);
    assert.equal(m.version, pkg.version);
    assert.deepEqual(m.permissions, ['storage', 'activeTab'], 'ask for as little as possible');
    assert.equal(m.host_permissions, undefined);
    assert.equal(m.background, undefined, 'there is no background script: nothing runs when no protected page is open');
    assert.deepEqual(m.content_scripts[0].matches, sites.matchPatterns());
    assert.equal(m.content_scripts[0].run_at, 'document_start');
    assert.ok(m.description.length <= 132, 'store limit for the description');
    assert.ok(m.name.length <= 45);
    for (const size of [16, 32, 48, 128]) assert.ok(m.icons[size]);
    if (browser === 'firefox') {
      assert.match(m.browser_specific_settings.gecko.id, /^[a-z0-9._-]+@[a-z0-9._-]+$/i);
      assert.deepEqual(m.browser_specific_settings.gecko.data_collection_permissions, { required: ['none'] });
    } else {
      assert.equal(m.browser_specific_settings, undefined);
      assert.ok(Number(m.minimum_chrome_version) >= 90, 'the d regex flag needs Chrome 90');
    }
  });
}

test('every match pattern is https-only and none is a wildcard host', () => {
  for (const p of sites.matchPatterns()) {
    assert.ok(p.startsWith('https://'), p);
    assert.ok(!p.startsWith('https://*'), 'never match every site: ' + p);
    assert.ok(!p.startsWith('https://*.'), 'no wildcard subdomains: ' + p);
  }
});

test('the content script list has no duplicates and starts with the engine', () => {
  assert.equal(new Set(CONTENT_SCRIPTS).size, CONTENT_SCRIPTS.length);
  assert.equal(CONTENT_SCRIPTS[0], 'engine/validators.js');
  assert.ok(CONTENT_SCRIPTS.indexOf('engine/detect.js') > CONTENT_SCRIPTS.indexOf('engine/rules.js'));
  assert.ok(CONTENT_SCRIPTS.indexOf('shared/settings.js') > CONTENT_SCRIPTS.indexOf('engine/detect.js'));
});

test('checkBuild catches a broken extension', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pg-check-'));
  try {
    fs.mkdirSync(path.join(dir, 'popup'));
    const manifest = manifestFor('chrome');
    manifest.permissions.push('tabs');
    fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(manifest));
    fs.writeFileSync(path.join(dir, 'popup', 'popup.html'), '<script src="nope.js"></script><script>alert(1)</script><button onclick="x()">');
    const problems = checkBuild(dir).join('\n');
    assert.match(problems, /missing content script/);
    assert.match(problems, /missing icon/);
    assert.match(problems, /loads a missing script: nope\.js/);
    assert.match(problems, /inline script/);
    assert.match(problems, /inline event handler/);
    assert.match(problems, /unexpected permission/);
    assert.match(problems, /missing page: options/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
