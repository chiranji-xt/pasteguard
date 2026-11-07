/* Paste Guard: scan text for secrets and personal data, and redact what was found.
 *
 * Everything here is synchronous, pure and offline: text goes in, findings come out.
 */
(function (global) {
  'use strict';

  const PG = (global.PasteGuard = global.PasteGuard || {});
  const V = PG.validators || require('./validators.js');
  const H = PG.hash || require('./hash.js');
  const R = PG.rules ? { rules: PG.rules, categories: PG.categories } : require('./rules.js');

  const SEVERITY_RANK = { low: 1, medium: 2, high: 3 };
  const MAX_SCAN_CHARS = 2000000;

  const compiled = new WeakMap();
  /** A private copy of the rule's pattern with the global and indices flags, so matches report capture positions. */
  function compile(rule) {
    let re = compiled.get(rule);
    if (!re) {
      const flags = Array.from(new Set((rule.pattern.flags + 'gd').split(''))).join('');
      re = new RegExp(rule.pattern.source, flags);
      compiled.set(rule, re);
    }
    re.lastIndex = 0;
    return re;
  }

  function spanOf(match, group) {
    const groups = Array.isArray(group) ? group : [group];
    for (const g of groups) {
      const span = match.indices[g];
      if (span) return span;
    }
    return null;
  }

  function tagFor(rule) {
    return (rule.tag || rule.id).toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_|_$/g, '');
  }

  function isEnabled(rule, options) {
    const choice = options.categories && options.categories[rule.category];
    const on = choice === undefined ? (R.categories[rule.category] || {}).defaultOn : choice;
    return !!on && SEVERITY_RANK[rule.severity] >= (SEVERITY_RANK[options.minSeverity] || 1);
  }

  // --- user-written patterns -------------------------------------------------------------------

  /**
   * Check a pattern someone typed into the settings. Returns { ok, error }.
   * JavaScript has no way to time-limit a regular expression, so patterns that can run away are refused.
   */
  function validateCustomPattern(source, flags) {
    if (typeof source !== 'string' || !source.trim()) return { ok: false, error: 'The pattern is empty.' };
    if (source.length > 500) return { ok: false, error: 'The pattern is too long (500 characters at most).' };
    let re;
    try {
      re = new RegExp(source, (flags || '').replace(/[^imsu]/g, ''));
    } catch (e) {
      return { ok: false, error: 'Not a valid regular expression: ' + e.message };
    }
    if (re.test('')) return { ok: false, error: 'The pattern matches empty text, so it would match everywhere.' };
    if (/\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)[+*{]/.test(source)) {
      return { ok: false, error: 'A repeated group that itself repeats (like (a+)+) can freeze the page. Rewrite it without nesting.' };
    }
    const started = Date.now();
    new RegExp(source, (flags || '').replace(/[^imsu]/g, '')).test('a'.repeat(4000) + '!' + ' '.repeat(2000));
    if (Date.now() - started > 100) return { ok: false, error: 'The pattern is too slow on long text.' };
    return { ok: true };
  }

  function customRules(patterns) {
    const out = [];
    (patterns || []).forEach((item, index) => {
      if (!item || !item.pattern || !validateCustomPattern(item.pattern, item.flags).ok) return;
      const flags = (item.flags || '').replace(/[^imsu]/g, '');
      const hasGroup = new RegExp(item.pattern + '|', flags).exec('').length > 1;
      out.push({
        id: 'custom-' + (index + 1),
        tag: 'CUSTOM_' + (index + 1),
        label: item.name || 'Custom pattern ' + (index + 1),
        category: 'custom',
        severity: 'high',
        priority: 95,
        pattern: new RegExp(item.pattern, flags),
        group: hasGroup ? 1 : 0,
      });
    });
    return out;
  }

  // Characters that are invisible but can sit inside a token when it is copied from a web page: zero-width space,
  // joiners, word joiner, byte-order mark, soft hyphen. They must not hide a secret.
  const INVISIBLE = /[​-‍⁠﻿­]/;

  /** The text without invisible characters, and for each kept character its position in the original (or null if none). */
  function withoutInvisible(text) {
    if (!INVISIBLE.test(text)) return { text, map: null };
    const kept = [];
    const map = [];
    for (let i = 0; i < text.length; i++) {
      if (!INVISIBLE.test(text[i])) {
        kept.push(text[i]);
        map.push(i);
      }
    }
    return { text: kept.join(''), map };
  }

  // --- scanning --------------------------------------------------------------------------------

  /**
   * Find secrets and personal data in `text`.
   *
   * options.minSeverity   'low' | 'medium' | 'high'   (default 'medium')
   * options.categories    { apiKey: true, email: false, ... }   (anything missing uses the rule's default)
   * options.customPatterns [{ name, pattern, flags }]
   * options.allowlist     Set or array of sha256 hashes of values to ignore
   * options.maxChars      stop reading after this many characters
   *
   * Returns { findings, truncated }. Each finding: { ruleId, label, category, severity, start, end, value, tag }.
   */
  function scan(text, options) {
    options = options || {};
    if (typeof text !== 'string' || !text) return { findings: [], truncated: false };
    const limit = options.maxChars || MAX_SCAN_CHARS;
    const truncated = text.length > limit;
    if (truncated) text = text.slice(0, limit);
    const stripped = withoutInvisible(text);
    text = stripped.text;

    const allow = options.allowlist instanceof Set ? options.allowlist : new Set(options.allowlist || []);
    const lower = text.toLowerCase();
    const candidates = [];
    const active = R.rules.filter((rule) => isEnabled(rule, options)).concat(customRules(options.customPatterns));

    for (const rule of active) {
      if (rule.keywords && !rule.keywords.some((k) => lower.includes(k))) continue;
      const re = compile(rule);
      let match;
      while ((match = re.exec(text)) !== null) {
        if (match[0].length === 0) {
          re.lastIndex++;
          continue;
        }
        const span = spanOf(match, rule.group === undefined ? 1 : rule.group);
        if (!span) continue;
        const [start, end] = span;
        const value = text.slice(start, end);
        const ctx = { text, start, end, match, before: text.slice(Math.max(0, start - 120), start), after: text.slice(end, end + 40) };
        if (rule.validate && !rule.validate(value, ctx)) continue;
        if (allow.size && allow.has(H.sha256Hex(value))) continue;
        candidates.push({
          ruleId: rule.id,
          label: rule.label,
          category: rule.category,
          severity: rule.severity,
          priority: rule.priority || 0,
          tag: tagFor(rule),
          start,
          end,
          value,
        });
      }
    }

    // When two findings overlap, keep the more specific rule (higher priority), then the longer one.
    candidates.sort((a, b) => b.priority - a.priority || b.end - b.start - (a.end - a.start) || a.start - b.start);
    const kept = [];
    for (const c of candidates) {
      if (!kept.some((k) => c.start < k.end && k.start < c.end)) kept.push(c);
    }
    kept.sort((a, b) => a.start - b.start);
    for (const f of kept) {
      delete f.priority;
      if (stripped.map) {
        // Report positions in the text as given, so redaction cuts the right span (invisible characters included).
        f.start = stripped.map[f.start];
        f.end = stripped.map[f.end - 1] + 1;
      }
    }
    return { findings: kept, truncated };
  }

  // --- showing and redacting ---------------------------------------------------------------------

  /** A short, safe-to-display version of a value: enough to recognise it, never enough to use it. */
  function mask(finding) {
    const v = finding.value;
    if (finding.ruleId === 'private-key') return v.split('\n')[0].trim() + ' ... (' + v.length + ' characters)';
    if (finding.category === 'financial' || finding.category === 'government') {
      const digits = v.replace(/[^A-Za-z0-9]/g, '');
      return '•••• ' + digits.slice(-4);
    }
    if (v.length <= 8) return '••••••••';
    const head = Math.min(4, Math.floor(v.length / 6));
    return v.slice(0, head) + '…' + v.slice(-2) + ' (' + v.length + ' chars)';
  }

  /**
   * Replace each finding with a placeholder like [REDACTED:OPENAI_API_KEY].
   * The same value always gets the same placeholder, and distinct values of one type are numbered,
   * so the model can still tell "the first key" from "the second key".
   */
  function redact(text, findings) {
    if (!findings || !findings.length) return { text, count: 0, items: [] };
    const sorted = findings.slice().sort((a, b) => a.start - b.start);
    const byTag = new Map();
    for (const f of sorted) {
      if (!byTag.has(f.tag)) byTag.set(f.tag, new Map());
      const values = byTag.get(f.tag);
      if (!values.has(f.value)) values.set(f.value, values.size + 1);
    }
    let out = '';
    let cursor = 0;
    const items = [];
    for (const f of sorted) {
      const values = byTag.get(f.tag);
      const placeholder = '[REDACTED:' + f.tag + (values.size > 1 ? '_' + values.get(f.value) : '') + ']';
      out += text.slice(cursor, f.start) + placeholder;
      cursor = f.end;
      items.push({ tag: f.tag, label: f.label, placeholder });
    }
    out += text.slice(cursor);
    return { text: out, count: sorted.length, items };
  }

  /** Hash of a value for the ignore list. The value itself is never stored. */
  function hashValue(value) {
    return H.sha256Hex(value);
  }

  /** Is `text` a plain secret-free string? Convenience for callers that only need yes or no. */
  function hasFindings(text, options) {
    return scan(text, options).findings.length > 0;
  }

  PG.detect = { scan, redact, mask, hashValue, hasFindings, validateCustomPattern, SEVERITY_RANK };

  if (typeof module !== 'undefined' && module.exports) module.exports = PG.detect;
})(typeof globalThis !== 'undefined' ? globalThis : this);
