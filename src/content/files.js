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

  const TEXT_EXTENSIONS = new Set([
    'env', 'pem', 'key', 'crt', 'cer', 'json', 'yaml', 'yml', 'toml', 'ini', 'cfg', 'conf', 'config', 'txt', 'log', 'csv', 'tsv', 'md',
    'sh', 'bash', 'zsh', 'ps1', 'bat', 'cmd', 'py', 'js', 'mjs', 'cjs', 'ts', 'jsx', 'tsx', 'java', 'kt', 'go', 'rb', 'php', 'rs', 'c', 'cc',
    'cpp', 'h', 'hpp', 'cs', 'swift', 'sql', 'xml', 'html', 'htm', 'properties', 'tf', 'tfvars', 'gradle', 'npmrc', 'netrc', 'pgpass', 'ipynb',
    'rtf', 'tex', 'rst', 'vue', 'svelte', 'dockerfile', 'lock', 'har',
  ]);
  const TEXT_NAMES = /^(?:\.env(?:\..+)?|dockerfile|id_(?:rsa|dsa|ecdsa|ed25519)|credentials|config|\.npmrc|\.netrc|\.pgpass|\.git-credentials|authorized_keys|known_hosts)$/i;
  const NEVER = /^(?:image|video|audio|font)\//i;
  const BINARY_TYPES = /(?:pdf|zip|gzip|x-tar|x-7z|rar|octet-stream|msword|officedocument|vnd\.ms-)/i;

  /** Could this file contain text worth scanning? Cheap check on name, type and size: the file is not read. */
  function isCandidate(file) {
    if (!file || typeof file.size !== 'number' || file.size === 0) return false;
    const type = file.type || '';
    if (NEVER.test(type)) return false;
    const name = file.name || '';
    const extension = name.includes('.') ? name.split('.').pop().toLowerCase() : '';
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

  /** Scan candidate files. Resolves a list of { file, findings, truncated } for files that have findings. */
  async function scanFiles(files, scanOptions) {
    const hits = [];
    for (const file of files) {
      if (!isCandidate(file)) continue;
      let text = null;
      try {
        text = await readText(file);
      } catch (e) {
        continue; // unreadable: let it through rather than block an upload we cannot judge
      }
      if (text === null) continue;
      const result = PG.detect.scan(text, scanOptions);
      if (result.findings.length) hits.push({ file, findings: result.findings, truncated: result.truncated || file.size > MAX_BYTES });
    }
    return hits;
  }

  PG.files = { isCandidate, readText, scanFiles, MAX_BYTES };

  if (typeof module !== 'undefined' && module.exports) module.exports = PG.files;
})(typeof globalThis !== 'undefined' ? globalThis : this);
