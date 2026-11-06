// Builds the extension for Chrome (and Edge, Brave) and for Firefox.
//   node scripts/build.js          -> dist/chrome and dist/firefox (load these as unpacked / temporary add-ons)
//   node scripts/build.js --zip    -> also dist/pasteguard-<browser>-<version>.zip (what the stores want)
// There is no bundler: the files in src/ are what ships, so anyone can read exactly what runs.
const fs = require('node:fs');
const path = require('node:path');
const { createZip } = require('./lib/zip.js');

const ROOT = path.resolve(__dirname, '..');
const SRC = path.join(ROOT, 'src');
const pkg = require(path.join(ROOT, 'package.json'));
const sites = require(path.join(SRC, 'shared', 'sites.js'));

// The order matters: each file may use the ones before it.
const CONTENT_SCRIPTS = [
  'engine/validators.js',
  'engine/hash.js',
  'engine/rules.js',
  'engine/detect.js',
  'shared/settings.js',
  'content/ui.js',
  'content/insert.js',
  'content/files.js',
  'content/content.js',
];

const ICONS = { 16: 'icons/icon-16.png', 32: 'icons/icon-32.png', 48: 'icons/icon-48.png', 128: 'icons/icon-128.png' };

/** The manifest for one browser. */
function manifestFor(browser) {
  const manifest = {
    manifest_version: 3,
    name: 'Paste Guard',
    version: pkg.version,
    description: 'Stops API keys, passwords and personal data from being pasted into AI chat boxes. Everything is checked on your device.',
    icons: ICONS,
    action: { default_title: 'Paste Guard', default_popup: 'popup/popup.html', default_icon: ICONS },
    options_ui: { page: 'options/options.html', open_in_tab: true },
    permissions: ['storage', 'activeTab'],
    content_scripts: [
      {
        matches: sites.matchPatterns(),
        js: CONTENT_SCRIPTS,
        run_at: 'document_start',
        all_frames: false,
      },
    ],
  };
  if (browser === 'chrome') {
    manifest.minimum_chrome_version = '102';
  } else if (browser === 'firefox') {
    manifest.browser_specific_settings = {
      gecko: {
        id: 'pasteguard@chiranji-xt',
        strict_min_version: '128.0',
        data_collection_permissions: { required: ['none'] },
      },
    };
  } else {
    throw new Error('unknown browser: ' + browser);
  }
  return manifest;
}

function listFiles(dir, base = dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...listFiles(full, base));
    else out.push(path.relative(base, full).replace(/\\/g, '/'));
  }
  return out.sort();
}

/**
 * Check a built extension folder. Returns a list of problems (empty means fine):
 * files the manifest names that are missing, pages that load missing files, and inline script,
 * which extension pages are not allowed to run.
 */
function checkBuild(dir) {
  const problems = [];
  const exists = (rel) => fs.existsSync(path.join(dir, rel));
  const manifest = JSON.parse(fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8'));

  for (const script of manifest.content_scripts.flatMap((c) => c.js || [])) if (!exists(script)) problems.push('missing content script: ' + script);
  for (const icon of Object.values(manifest.icons || {})) if (!exists(icon)) problems.push('missing icon: ' + icon);
  const pages = [manifest.action && manifest.action.default_popup, manifest.options_ui && manifest.options_ui.page].filter(Boolean);
  for (const page of pages) {
    if (!exists(page)) {
      problems.push('missing page: ' + page);
      continue;
    }
    const html = fs.readFileSync(path.join(dir, page), 'utf8');
    for (const [, src] of html.matchAll(/<script[^>]*\ssrc="([^"]+)"/g)) {
      if (!fs.existsSync(path.join(dir, path.dirname(page), src))) problems.push(`${page} loads a missing script: ${src}`);
    }
    for (const [, href] of html.matchAll(/<link[^>]*\shref="([^"]+)"/g)) {
      if (!/^https?:/.test(href) && !fs.existsSync(path.join(dir, path.dirname(page), href))) problems.push(`${page} loads a missing file: ${href}`);
    }
    if (/<script(?![^>]*\ssrc=)[^>]*>/i.test(html)) problems.push(`${page} has inline script, which extension pages cannot run`);
    if (/\son[a-z]+\s*=\s*["']/i.test(html)) problems.push(`${page} has an inline event handler (onclick=...), which extension pages cannot run`);
    if (/https?:\/\/[^"'\s]+\.(?:js|css)/i.test(html)) problems.push(`${page} loads code from the network, which the extension must never do`);
  }
  if (!manifest.permissions.every((p) => ['storage', 'activeTab'].includes(p))) problems.push('unexpected permission: keep the permission list minimal');
  if (manifest.host_permissions) problems.push('host_permissions found: the extension should only need content-script matches');
  return problems;
}

function build(options = {}) {
  const outRoot = options.outDir || path.join(ROOT, 'dist');
  const browsers = options.browsers || ['chrome', 'firefox'];
  const results = [];
  fs.rmSync(outRoot, { recursive: true, force: true });
  for (const browser of browsers) {
    const dir = path.join(outRoot, browser);
    fs.mkdirSync(dir, { recursive: true });
    for (const rel of listFiles(SRC)) {
      fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      fs.copyFileSync(path.join(SRC, rel), path.join(dir, rel));
    }
    fs.copyFileSync(path.join(ROOT, 'LICENSE'), path.join(dir, 'LICENSE'));
    fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(manifestFor(browser), null, 2) + '\n');

    const problems = checkBuild(dir);
    if (problems.length) throw new Error(`${browser} build has problems:\n  - ` + problems.join('\n  - '));

    const result = { browser, dir, zip: null };
    if (options.zip) {
      const entries = listFiles(dir).map((rel) => ({ name: rel, data: fs.readFileSync(path.join(dir, rel)) }));
      result.zip = path.join(outRoot, `pasteguard-${browser}-${pkg.version}.zip`);
      fs.writeFileSync(result.zip, createZip(entries));
    }
    results.push(result);
  }
  return results;
}

if (require.main === module) {
  try {
    const results = build({ zip: process.argv.includes('--zip') });
    for (const r of results) console.log(`built ${r.browser}: ${path.relative(ROOT, r.dir)}` + (r.zip ? `  and ${path.relative(ROOT, r.zip)}` : ''));
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}

module.exports = { build, manifestFor, checkBuild, listFiles, CONTENT_SCRIPTS };
