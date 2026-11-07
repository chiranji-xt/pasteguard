const test = require('node:test');
const assert = require('node:assert/strict');
const { createZip } = require('../scripts/lib/zip.js');
const detect = require('../src/engine/detect.js');
globalThis.PasteGuard = globalThis.PasteGuard || {};
globalThis.PasteGuard.detect = detect;
const files = require('../src/content/files.js');
const { rand } = require('./fixtures.js');

const zipFile = (name, entries) => new File([createZip(entries.map(([n, t]) => ({ name: n, data: Buffer.from(t) })))], name);
const key = () => 'sk-' + 'ant-api03-' + rand(93, 'b64url', 5);
const OPTIONS = { minSeverity: 'medium' };

test('office and zip files are candidates; huge ones are not', () => {
  assert.equal(files.isCandidate(new File(['x'], 'notes.docx')), true);
  assert.equal(files.isCandidate(new File(['x'], 'sheet.xlsx', { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' })), true);
  assert.equal(files.isCandidate(new File(['x'], 'bundle.zip')), true);
  assert.equal(files.isCandidate({ name: 'big.zip', size: 50 * 1024 * 1024, type: '' }), false);
  assert.equal(files.isCandidate(new File(['x'], 'photo.png', { type: 'image/png' })), false);
});

test('a key inside a Word document is found, even when Word splits it into several runs', async () => {
  const k = key();
  const xml = `<?xml version="1.0"?><w:document><w:body><w:p><w:r><w:t>My key:</w:t></w:r></w:p><w:p><w:r><w:t>${k.slice(0, 20)}</w:t></w:r><w:r><w:t>${k.slice(20)}</w:t></w:r></w:p></w:body></w:document>`;
  const hits = await files.scanFiles([zipFile('plan.docx', [['word/document.xml', xml], ['[Content_Types].xml', '<Types/>']])], OPTIONS);
  assert.equal(hits.length, 1);
  assert.ok(hits[0].findings.some((f) => f.ruleId === 'anthropic-api-key'));
});

test('text in an Excel sheet is extracted (shared strings, XML entities decoded)', async () => {
  const xml = '<?xml version="1.0"?><sst><si><t>DB_PASS</t></si><si><t>hunter2&amp;&lt;Xy9!kQ</t></si></sst>';
  const sheet = '<?xml version="1.0"?><worksheet><sheetData><row><c><v>0</v></c><c><v>1</v></c></row></sheetData></worksheet>';
  const text = await files.readArchive(zipFile('creds.xlsx', [['xl/sharedStrings.xml', xml]]));
  assert.match(text, /hunter2&<Xy9!kQ/);
});

test('text files inside a plain zip are scanned, binary parts are skipped', async () => {
  const hits = await files.scanFiles([zipFile('backup.zip', [['app/.env', 'ANTHROPIC_API_KEY=' + key() + '\n'], ['img/logo.png', '\u0089PNG\r\n']])], OPTIONS);
  assert.equal(hits.length, 1);
});

test('a clean document and a clean zip raise nothing', async () => {
  const hits = await files.scanFiles(
    [zipFile('memo.docx', [['word/document.xml', '<w:document><w:p><w:t>Quarterly plan, see the process.env.API_KEY note and https://example.com</w:t></w:p></w:document>']]), zipFile('c.zip', [['readme.md', '# Hello\nNothing here.']])],
    OPTIONS
  );
  assert.equal(hits.length, 0);
});

test('a decompression bomb is cut off, not expanded', async () => {
  const bomb = zipFile('bomb.zip', [['zeros.txt', 'a'.repeat(40 * 1024 * 1024)]]);
  const started = Date.now();
  const text = await files.readArchive(bomb);
  assert.ok(text.length <= 2 * 1024 * 1024 + 16, 'read at most the per-file limit');
  assert.ok(Date.now() - started < 5000);
});

test('damaged and non-zip files are skipped quietly', async () => {
  assert.equal(await files.readArchive(new File(['this is not a zip at all, just words'], 'fake.docx')), null);
  const hits = await files.scanFiles([new File(['PK\u0003\u0004broken'], 'broken.zip')], OPTIONS);
  assert.equal(hits.length, 0);
});
