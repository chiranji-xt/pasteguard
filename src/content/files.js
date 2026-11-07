/* Paste Guard: check files before they are attached.
 *
 * People attach .env files, key files and config dumps to chats. Only files that could hold text are
 * read, and only the first couple of megabytes. Images, video, PDFs and archives are never touched,
 * so ordinary uploads are not delayed. Nothing is uploaded; the file is read locally.
 */
(function (global) {
  'use strict';

  const PG = (global.PasteGuard = global.PasteGuard || {});

  const MAX_BYTES = 2 * 1024 * 1024;
  const MAX_ARCHIVE_BYTES = 12 * 1024 * 1024; // a zip is read whole, because its index is at the end
  const MAX_ENTRY_BYTES = 2 * 1024 * 1024; // per file inside, after unpacking: a guard against zip bombs
  const MAX_TOTAL_BYTES = 8 * 1024 * 1024;
  const MAX_ENTRIES = 300;
  const ARCHIVE_EXTENSIONS = new Set(['zip', 'docx', 'xlsx', 'pptx', 'docm', 'xlsm', 'pptm', 'odt', 'ods', 'odp']);

  const TEXT_EXTENSIONS = new Set([
    'env', 'pem', 'key', 'crt', 'cer', 'json', 'yaml', 'yml', 'toml', 'ini', 'cfg', 'conf', 'config', 'txt', 'log', 'csv', 'tsv', 'md',
    'sh', 'bash', 'zsh', 'ps1', 'bat', 'cmd', 'py', 'js', 'mjs', 'cjs', 'ts', 'jsx', 'tsx', 'java', 'kt', 'go', 'rb', 'php', 'rs', 'c', 'cc',
    'cpp', 'h', 'hpp', 'cs', 'swift', 'sql', 'xml', 'html', 'htm', 'properties', 'tf', 'tfvars', 'gradle', 'npmrc', 'netrc', 'pgpass', 'ipynb',
    'rtf', 'tex', 'rst', 'vue', 'svelte', 'dockerfile', 'lock', 'har',
  ]);
  const TEXT_NAMES = /^(?:\.env(?:\..+)?|dockerfile|id_(?:rsa|dsa|ecdsa|ed25519)|credentials|config|\.npmrc|\.netrc|\.pgpass|\.git-credentials|authorized_keys|known_hosts)$/i;
  const NEVER = /^(?:image|video|audio|font)\//i;
  const XML_PARTS = /\.(?:xml|rels)$/i;
  const BINARY_TYPES = /(?:pdf|zip|gzip|x-tar|x-7z|rar|octet-stream|msword|officedocument|vnd\.ms-)/i;

  /** Could this file contain text worth scanning? Cheap check on name, type and size: the file is not read. */
  function isCandidate(file) {
    if (!file || typeof file.size !== 'number' || file.size === 0) return false;
    const type = file.type || '';
    if (NEVER.test(type)) return false;
    const name = file.name || '';
    const extension = name.includes('.') ? name.split('.').pop().toLowerCase() : '';
    if (ARCHIVE_EXTENSIONS.has(extension)) return file.size <= MAX_ARCHIVE_BYTES;
    if (TEXT_NAMES.test(name) || TEXT_EXTENSIONS.has(extension)) return true;
    if (BINARY_TYPES.test(type)) return false;
    return /^text\//i.test(type) || /json|xml|yaml|javascript|x-sh/i.test(type);
  }

  /** The start of the file as text, or null if it is too large to be worth reading whole or looks binary. */
  async function readText(file) {
    const bytes = new Uint8Array(await file.slice(0, MAX_BYTES).arrayBuffer());
    for (let i = 0; i < Math.min(bytes.length, 4096); i++) if (bytes[i] === 0) return null; // a NUL byte means binary
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  }

  // --- Word, Excel, PowerPoint, OpenDocument and plain zip files: a zip of parts, read with the browser's own inflate ---

  const u16 = (b, p) => b[p] | (b[p + 1] << 8);
  const u32 = (b, p) => (b[p] | (b[p + 1] << 8) | (b[p + 2] << 16) | (b[p + 3] << 24)) >>> 0;

  /** The central directory of a zip: [{ name, method, size, offset }], or null if this is not a readable zip. */
  function listZip(bytes) {
    let end = bytes.length - 22;
    const stop = Math.max(0, end - 65557);
    while (end >= stop && u32(bytes, end) !== 0x06054b50) end--;
    if (end < stop) return null;
    const count = u16(bytes, end + 10);
    let p = u32(bytes, end + 16);
    const entries = [];
    for (let i = 0; i < count && i < MAX_ENTRIES * 4; i++) {
      if (p + 46 > bytes.length || u32(bytes, p) !== 0x02014b50) break;
      const flags = u16(bytes, p + 8);
      const nameLength = u16(bytes, p + 28);
      const extraLength = u16(bytes, p + 30);
      const commentLength = u16(bytes, p + 32);
      entries.push({
        name: new TextDecoder('utf-8').decode(bytes.subarray(p + 46, p + 46 + nameLength)),
        method: u16(bytes, p + 10),
        compressedSize: u32(bytes, p + 20),
        offset: u32(bytes, p + 42),
        encrypted: (flags & 1) !== 0,
      });
      p += 46 + nameLength + extraLength + commentLength;
    }
    return entries;
  }

  /** The unpacked bytes of one entry (at most `limit`), or null when it cannot be read. */
  async function unpack(bytes, entry, limit) {
    if (entry.encrypted || bytes.length < entry.offset + 30 || u32(bytes, entry.offset) !== 0x04034b50) return null;
    const start = entry.offset + 30 + u16(bytes, entry.offset + 26) + u16(bytes, entry.offset + 28);
    const body = bytes.subarray(start, start + entry.compressedSize);
    if (entry.method === 0) return body.subarray(0, limit);
    if (entry.method !== 8 || typeof DecompressionStream === 'undefined') return null;
    const reader = new Blob([body]).stream().pipeThrough(new DecompressionStream('deflate-raw')).getReader();
    const chunks = [];
    let total = 0;
    try {
      while (total < limit) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value);
        total += value.length;
      }
    } catch (e) {
      if (!total) return null; // damaged data: use whatever was read before the damage
    }
    try { await reader.cancel(); } catch (e) { /* already closed */ }
    const out = new Uint8Array(Math.min(total, limit));
    let at = 0;
    for (const chunk of chunks) {
      const room = out.length - at;
      if (room <= 0) break;
      out.set(chunk.subarray(0, room), at);
      at += Math.min(chunk.length, room);
    }
    return out;
  }

  const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };
  /** Text of an XML part. Paragraph, row and cell ends become line breaks; runs inside a paragraph are joined. */
  function xmlToText(xml) {
    return xml
      .replace(/<\/(?:w:p|a:p|text:p|text:h|si|row|c|definedName|comment|t:p)>|<(?:w:br|w:tab|a:br|text:line-break)\b[^>]*\/?>/g, '\n')
      .replace(/<[^>]*>/g, '')
      .replace(/&(?:#(\d+)|#x([0-9a-f]+)|(amp|lt|gt|quot|apos));/gi, (m, dec, hex, name) =>
        name ? ENTITIES[name.toLowerCase()] : String.fromCodePoint(Math.min(parseInt(dec || hex, dec ? 10 : 16), 0x10ffff)));
  }

  function isTextEntry(name) {
    if (/\/$/.test(name) || /(?:^|\/)__MACOSX\//.test(name)) return false;
    const base = name.split('/').pop();
    const extension = base.includes('.') ? base.split('.').pop().toLowerCase() : '';
    return XML_PARTS.test(base) || TEXT_EXTENSIONS.has(extension) || TEXT_NAMES.test(base);
  }

  /** All readable text in a zip-based file, with a heading line per part. Null if it is not a zip. */
  async function readArchive(file) {
    const bytes = new Uint8Array(await file.arrayBuffer());
    const entries = listZip(bytes);
    if (!entries) return null;
    let total = 0;
    let used = 0;
    const parts = [];
    for (const entry of entries) {
      if (used >= MAX_ENTRIES || total >= MAX_TOTAL_BYTES) break;
      if (!isTextEntry(entry.name)) continue;
      used++;
      const data = await unpack(bytes, entry, Math.min(MAX_ENTRY_BYTES, MAX_TOTAL_BYTES - total));
      if (!data || !data.length) continue;
      total += data.length;
      let text = new TextDecoder('utf-8', { fatal: false }).decode(data);
      if (text.indexOf('\u0000') !== -1) continue;
      if (XML_PARTS.test(entry.name) || /^\s*<\?xml/.test(text)) text = xmlToText(text);
      if (text.trim()) parts.push(text);
    }
    return parts.join('\n');
  }

  const isArchive = (file) => ARCHIVE_EXTENSIONS.has((file.name || '').split('.').pop().toLowerCase());

  /** Scan candidate files. Resolves a list of { file, findings, truncated } for files that have findings. */
  async function scanFiles(files, scanOptions) {
    const hits = [];
    for (const file of files) {
      if (!isCandidate(file)) continue;
      let text = null;
      try {
        text = ARCHIVE_EXTENSIONS.has((file.name || '').split('.').pop().toLowerCase()) ? await readArchive(file) : await readText(file);
      } catch (e) {
        continue; // unreadable: let it through rather than block an upload we cannot judge
      }
      if (text === null) continue;
      const result = PG.detect.scan(text, scanOptions);
      if (result.findings.length) hits.push({ file, findings: result.findings, truncated: result.truncated || (file.size > MAX_BYTES && !isArchive(file)) });
    }
    return hits;
  }

  PG.files = { isCandidate, readText, readArchive, xmlToText, scanFiles, MAX_BYTES };

  if (typeof module !== 'undefined' && module.exports) module.exports = PG.files;
})(typeof globalThis !== 'undefined' ? globalThis : this);
