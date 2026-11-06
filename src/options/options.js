/* Paste Guard: the settings page. Every change is saved at once. */
(async function () {
  'use strict';
  const PG = window.PasteGuard;
  const S = PG.settings;
  const store = S.store;
  const detect = PG.detect;
  const $ = (id) => document.getElementById(id);
  const api = typeof browser !== 'undefined' && browser.runtime ? browser : chrome;

  let settings = await store.getSettings();
  let allowlist = (await store.getAllowlist()).map((e) => e.hash);

  function h(tag, props, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(props || {})) {
      if (value === undefined || value === false) continue;
      if (key === 'class') node.className = value;
      else if (key === 'text') node.textContent = value;
      else node.setAttribute(key, value === true ? '' : value);
    }
    for (const child of children) if (child) node.append(child);
    return node;
  }

  let savedTimer = null;
  function flashSaved(message) {
    $('saved').textContent = message || 'Saved';
    clearTimeout(savedTimer);
    savedTimer = setTimeout(() => ($('saved').textContent = ''), 1800);
  }

  async function save(patch, message) {
    settings = await store.saveSettings(Object.assign({}, settings, patch));
    flashSaved(message);
    renderTry();
  }

  // --- basic controls -----------------------------------------------------------------------------

  function renderBasics() {
    $('enabled').checked = settings.enabled;
    $('scanFiles').checked = settings.scanFiles;
    for (const radio of document.querySelectorAll('input[name="mode"]')) radio.checked = radio.value === settings.mode;
    for (const radio of document.querySelectorAll('input[name="action"]')) radio.checked = radio.value === settings.action;
    for (const box of document.querySelectorAll('#categories input')) box.checked = !!settings.categories[box.dataset.category];
  }

  $('enabled').addEventListener('change', (e) => save({ enabled: e.target.checked }));
  $('scanFiles').addEventListener('change', (e) => save({ scanFiles: e.target.checked }));
  for (const radio of document.querySelectorAll('input[name="mode"]')) radio.addEventListener('change', () => radio.checked && save({ mode: radio.value }));
  for (const radio of document.querySelectorAll('input[name="action"]')) radio.addEventListener('change', () => radio.checked && save({ action: radio.value }));

  const categoryHelp = {
    apiKey: 'OpenAI, Anthropic, Google, AWS, GitHub, Stripe, Slack and many more',
    privateKey: 'SSH, TLS and PGP private keys',
    token: 'JWTs, Bearer and Basic auth headers',
    credential: 'password = "...", database URLs with passwords, secrets on command lines',
    financial: 'Card numbers (checked with the card checksum) and IBANs',
    government: 'US Social Security, Indian Aadhaar and PAN numbers',
    email: 'Off by default: you paste email addresses on purpose all the time',
    phone: 'Off by default: lots of false alarms',
    highEntropy: 'Off by default: any long random-looking string. Noisy.',
  };
  for (const [name, info] of Object.entries(PG.categories)) {
    const box = h('input', { type: 'checkbox', 'data-category': name });
    box.addEventListener('change', () => save({ categories: Object.assign({}, settings.categories, { [name]: box.checked }) }));
    $('categories').append(h('label', { class: 'choice' }, box, h('span', null, h('strong', { text: info.label }), h('span', { class: 'muted block', text: categoryHelp[name] || '' }))));
  }

  // --- custom patterns ------------------------------------------------------------------------------

  function renderCustom() {
    const list = $('custom-list');
    list.replaceChildren();
    settings.customPatterns.forEach((p, index) => {
      const remove = h('button', { type: 'button', text: 'Remove', 'aria-label': 'Remove ' + p.name });
      remove.addEventListener('click', () => save({ customPatterns: settings.customPatterns.filter((_, i) => i !== index) }).then(renderCustom));
      list.append(h('li', null, h('span', null, h('strong', { text: p.name + ' ' }), h('code', { text: '/' + p.pattern + '/' + p.flags })), remove));
    });
  }
  $('custom-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const pattern = $('custom-pattern').value.trim();
    const flags = $('custom-i').checked ? 'i' : '';
    const check = detect.validateCustomPattern(pattern, flags);
    $('custom-error').textContent = check.ok ? '' : check.error;
    if (!check.ok) return;
    if (settings.customPatterns.length >= 20) {
      $('custom-error').textContent = 'You can have up to 20 custom patterns.';
      return;
    }
    await save({ customPatterns: settings.customPatterns.concat({ name: $('custom-name').value.trim() || 'Custom pattern', pattern, flags }) }, 'Pattern added');
    $('custom-name').value = '';
    $('custom-pattern').value = '';
    renderCustom();
  });

  // --- try it ----------------------------------------------------------------------------------------

  const ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const rand = (n) => Array.from({ length: n }, () => ALPHA[Math.floor(Math.random() * ALPHA.length)]).join('');
  function sampleText() {
    // Built from parts on purpose: these are made up and match the real formats, nothing more.
    let card = '4539';
    while (card.length < 15) card += Math.floor(Math.random() * 10);
    card += PG.validators.luhnCheckDigit(card);
    return [
      'Here is my config, can you see why it fails?',
      '',
      'OPENAI_API_KEY=' + 'sk-' + 'proj-' + rand(90),
      'DATABASE_URL=postgres://app:' + rand(16) + '@db.internal:5432/app',
      'GITHUB_TOKEN=' + 'gh' + 'p_' + rand(36),
      'PORT=8080',
      'card: ' + card.replace(/(\d{4})(?=\d)/g, '$1 '),
    ].join('\n');
  }

  function previewNodes(text) {
    const pre = h('pre');
    for (const part of text.split(/(\[REDACTED:[A-Z0-9_]+\])/)) {
      if (part) pre.append(/^\[REDACTED:/.test(part) ? h('mark', { text: part }) : document.createTextNode(part));
    }
    return pre;
  }

  function renderTry() {
    const out = $('try-out');
    out.replaceChildren();
    const text = $('try-input').value;
    if (!text) return;
    const { findings } = detect.scan(text, S.toScanOptions(settings, allowlist));
    if (!findings.length) {
      out.append(h('p', { class: 'clean', text: 'Nothing found. This would be pasted as it is.' }));
      return;
    }
    for (const f of findings) {
      out.append(h('div', { class: 'hit' }, h('span', { class: 'dot ' + f.severity, 'aria-hidden': 'true' }), h('strong', { text: f.label }), h('code', { text: detect.mask(f) }), h('span', { class: 'muted', text: f.severity + ' severity' })));
    }
    out.append(h('p', { class: 'muted', text: 'What "Redact and paste" would paste:' }), previewNodes(detect.redact(text, findings).text));
  }
  $('try-input').addEventListener('input', renderTry);
  $('try-sample').addEventListener('click', () => {
    $('try-input').value = sampleText();
    renderTry();
  });
  $('try-clear').addEventListener('click', () => {
    $('try-input').value = '';
    renderTry();
  });

  // --- paused sites, ignore list, sites, counters ----------------------------------------------------------

  function renderPaused() {
    const list = $('paused-list');
    list.replaceChildren();
    $('paused-empty').hidden = settings.pausedHosts.length > 0;
    for (const host of settings.pausedHosts) {
      const resume = h('button', { type: 'button', text: 'Resume', 'aria-label': 'Resume on ' + host });
      resume.addEventListener('click', () => save({ pausedHosts: settings.pausedHosts.filter((x) => x !== host) }).then(renderPaused));
      list.append(h('li', null, h('span', { text: host }), resume));
    }
  }

  function renderAllow() {
    $('allow-count').textContent = String(allowlist.length);
    $('allow-clear').disabled = allowlist.length === 0;
  }
  $('allow-clear').addEventListener('click', async () => {
    await store.clearAllowlist();
    allowlist = [];
    renderAllow();
    renderTry();
    flashSaved('Cleared');
  });

  for (const site of PG.sites.list) $('sites').append(h('li', { text: site.name }));

  async function renderStats() {
    const s = await store.getStats();
    $('stats').textContent =
      `Warned ${s.warned} time${s.warned === 1 ? '' : 's'}. Redacted ${s.redacted}, pasted anyway ${s.pastedAnyway}, cancelled ${s.cancelled}, files stopped ${s.blockedFiles}.`;
  }
  $('stats-reset').addEventListener('click', async () => {
    await store.resetStats();
    renderStats();
    flashSaved('Counters reset');
  });

  // --- export, import, reset ---------------------------------------------------------------------------

  $('export').addEventListener('click', () => {
    const blob = new Blob([JSON.stringify({ pasteguard: 1, settings }, null, 2)], { type: 'application/json' });
    const link = h('a', { href: URL.createObjectURL(blob), download: 'pasteguard-settings.json' });
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(link.href), 1000);
    $('backup-message').textContent = 'Exported. The file holds settings only: no values you ignored and no counters.';
  });
  $('import').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    e.target.value = '';
    if (!file) return;
    try {
      const parsed = JSON.parse(await file.text());
      if (!parsed || !parsed.settings || typeof parsed.settings !== 'object') throw new Error('not a Paste Guard settings file');
      settings = await store.saveSettings(parsed.settings);
      renderAll();
      $('backup-message').textContent = 'Imported. Anything invalid in the file was replaced with the default.';
    } catch (error) {
      $('backup-message').textContent = 'Could not import that file: ' + error.message + '.';
    }
  });
  $('reset').addEventListener('click', async () => {
    if (!window.confirm('Reset every setting to its default? Your ignored values stay.')) return;
    settings = await store.saveSettings(S.defaults());
    renderAll();
    flashSaved('Reset');
  });

  function renderAll() {
    renderBasics();
    renderCustom();
    renderPaused();
    renderAllow();
    renderTry();
  }

  store.onSettingsChange((s, hashes) => {
    if (s) {
      settings = s;
      renderBasics();
      renderCustom();
      renderPaused();
    }
    if (hashes) {
      allowlist = hashes;
      renderAllow();
    }
    renderTry();
  });

  try {
    $('version').textContent = 'Version ' + api.runtime.getManifest().version + '.';
  } catch (e) {
    /* not available in a plain web page */
  }
  renderAll();
  renderStats();
})();
