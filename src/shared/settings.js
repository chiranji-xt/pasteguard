/* Paste Guard: settings, the ignore list, and local counters.
 *
 *   settings   chrome.storage.sync   small, follows you between browsers
 *   allowlist  chrome.storage.local  SHA-256 hashes of values you chose to ignore. Never the values.
 *   stats      chrome.storage.local  counts only. Nothing you pasted is ever stored.
 */
(function (global) {
  'use strict';

  const PG = (global.PasteGuard = global.PasteGuard || {});
  const rulesModule = PG.rules ? { categories: PG.categories } : require('../engine/rules.js');
  const detect = PG.detect || require('../engine/detect.js');

  const MODES = ['quiet', 'balanced', 'strict'];
  const ACTIONS = ['ask', 'redact', 'block'];
  const MODE_SEVERITY = { quiet: 'high', balanced: 'medium', strict: 'low' };
  const MAX_CUSTOM = 20;
  const MAX_PAUSED = 200;
  const MAX_ALLOWLIST = 500;

  function defaultCategories() {
    const out = {};
    for (const [name, info] of Object.entries(rulesModule.categories)) out[name] = info.defaultOn;
    return out;
  }

  function defaults() {
    return {
      version: 1,
      enabled: true,
      mode: 'balanced', // quiet = only the clearest secrets, balanced = default, strict = also lower-confidence finds
      action: 'ask', // ask = show the dialog, redact = clean the paste without asking, block = refuse it
      scanFiles: true,
      categories: defaultCategories(),
      pausedHosts: [],
      customPatterns: [],
    };
  }

  /** Make any stored value into valid settings. Corrupt or old data falls back to the defaults, never throws. */
  function normalize(raw) {
    const out = defaults();
    if (!raw || typeof raw !== 'object') return out;
    if (typeof raw.enabled === 'boolean') out.enabled = raw.enabled;
    if (MODES.includes(raw.mode)) out.mode = raw.mode;
    if (ACTIONS.includes(raw.action)) out.action = raw.action;
    if (typeof raw.scanFiles === 'boolean') out.scanFiles = raw.scanFiles;
    if (raw.categories && typeof raw.categories === 'object') {
      for (const name of Object.keys(out.categories)) {
        if (typeof raw.categories[name] === 'boolean') out.categories[name] = raw.categories[name];
      }
    }
    if (Array.isArray(raw.pausedHosts)) {
      out.pausedHosts = Array.from(
        new Set(raw.pausedHosts.filter((h) => typeof h === 'string' && /^[a-z0-9.-]{1,253}$/i.test(h)).map((h) => h.toLowerCase()))
      ).slice(0, MAX_PAUSED);
    }
    if (Array.isArray(raw.customPatterns)) {
      out.customPatterns = raw.customPatterns
        .filter((p) => p && typeof p.pattern === 'string' && detect.validateCustomPattern(p.pattern, p.flags).ok)
        .slice(0, MAX_CUSTOM)
        .map((p) => ({
          name: String(p.name || 'Custom pattern').slice(0, 60),
          pattern: p.pattern.slice(0, 500),
          flags: String(p.flags || '').replace(/[^imsu]/g, ''),
        }));
    }
    return out;
  }

  /** The options the detection engine wants, built from settings plus the ignore list. */
  function toScanOptions(settings, allowlistHashes) {
    return {
      minSeverity: MODE_SEVERITY[settings.mode] || 'medium',
      categories: settings.categories,
      customPatterns: settings.customPatterns,
      allowlist: allowlistHashes || [],
    };
  }

  function isPaused(settings, hostname) {
    return !settings.enabled || settings.pausedHosts.includes(String(hostname || '').toLowerCase());
  }

  // --- storage ---------------------------------------------------------------------------------

  function browserApi() {
    if (typeof browser !== 'undefined' && browser.storage) return browser;
    if (typeof chrome !== 'undefined' && chrome.storage) return chrome;
    return null;
  }

  /** Storage helpers bound to an extension API object. Tests pass a fake one. */
  function createStore(api) {
    const sync = () => api.storage.sync;
    const local = () => api.storage.local;

    async function getSettings() {
      try {
        const got = await sync().get('settings');
        return normalize(got && got.settings);
      } catch (e) {
        return defaults();
      }
    }
    async function saveSettings(settings) {
      const clean = normalize(settings);
      await sync().set({ settings: clean });
      return clean;
    }

    async function getAllowlist() {
      try {
        const got = await local().get('allowlist');
        return Array.isArray(got && got.allowlist) ? got.allowlist.filter((e) => e && typeof e.hash === 'string') : [];
      } catch (e) {
        return [];
      }
    }
    async function addToAllowlist(hashes) {
      const list = await getAllowlist();
      const known = new Set(list.map((e) => e.hash));
      for (const hash of hashes) {
        if (/^[a-f0-9]{64}$/.test(hash) && !known.has(hash)) {
          known.add(hash);
          list.push({ hash, added: Date.now() });
        }
      }
      await local().set({ allowlist: list.slice(-MAX_ALLOWLIST) });
    }
    async function clearAllowlist() {
      await local().set({ allowlist: [] });
    }

    const EMPTY_STATS = { warned: 0, redacted: 0, pastedAnyway: 0, cancelled: 0, blockedFiles: 0 };
    async function getStats() {
      try {
        const got = await local().get('stats');
        return Object.assign({}, EMPTY_STATS, got && got.stats);
      } catch (e) {
        return Object.assign({}, EMPTY_STATS);
      }
    }
    async function bumpStat(name, by) {
      if (!(name in EMPTY_STATS)) return;
      const stats = await getStats();
      stats[name] += by || 1;
      await local().set({ stats });
    }
    async function resetStats() {
      await local().set({ stats: Object.assign({}, EMPTY_STATS) });
    }

    function onSettingsChange(callback) {
      api.storage.onChanged.addListener((changes, area) => {
        if (area === 'sync' && changes.settings) callback(normalize(changes.settings.newValue));
        if (area === 'local' && changes.allowlist) callback(null, (changes.allowlist.newValue || []).map((e) => e.hash));
      });
    }

    return { getSettings, saveSettings, getAllowlist, addToAllowlist, clearAllowlist, getStats, bumpStat, resetStats, onSettingsChange };
  }

  const api = browserApi();
  PG.settings = { defaults, normalize, toScanOptions, isPaused, createStore, store: api ? createStore(api) : null, MODES, ACTIONS, MODE_SEVERITY };

  if (typeof module !== 'undefined' && module.exports) module.exports = PG.settings;
})(typeof globalThis !== 'undefined' ? globalThis : this);
