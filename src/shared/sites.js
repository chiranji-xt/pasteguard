/* Paste Guard: the sites it protects.
 *
 * This list is the single source of truth. The build turns it into the extension's `matches`
 * patterns, and the popup uses it to say whether the current tab is protected.
 * To add a site, add a line here. An entry is a host, optionally followed by a path prefix.
 */
(function (global) {
  'use strict';

  const PG = (global.PasteGuard = global.PasteGuard || {});

  const SITES = [
    { name: 'ChatGPT', matches: ['chatgpt.com', 'chat.openai.com'] },
    { name: 'Claude', matches: ['claude.ai'] },
    { name: 'Gemini', matches: ['gemini.google.com'] },
    { name: 'Google AI Studio', matches: ['aistudio.google.com'] },
    { name: 'Microsoft Copilot', matches: ['copilot.microsoft.com'] },
    { name: 'Perplexity', matches: ['www.perplexity.ai', 'perplexity.ai'] },
    { name: 'Grok', matches: ['grok.com'] },
    { name: 'DeepSeek', matches: ['chat.deepseek.com'] },
    { name: 'Mistral Le Chat', matches: ['chat.mistral.ai'] },
    { name: 'Poe', matches: ['poe.com'] },
    { name: 'Hugging Chat', matches: ['huggingface.co/chat'] },
    { name: 'Meta AI', matches: ['www.meta.ai', 'meta.ai'] },
    { name: 'Qwen Chat', matches: ['chat.qwen.ai'] },
    { name: 'T3 Chat', matches: ['t3.chat'] },
    { name: 'OpenRouter', matches: ['openrouter.ai'] },
    { name: 'OpenAI Platform', matches: ['platform.openai.com'] },
    { name: 'Anthropic Console', matches: ['console.anthropic.com'] },
  ];

  function split(entry) {
    const slash = entry.indexOf('/');
    return slash === -1 ? { host: entry, path: '' } : { host: entry.slice(0, slash), path: entry.slice(slash) };
  }

  /** Chrome/Firefox match patterns for the manifest: "https://claude.ai/*". */
  function matchPatterns() {
    const patterns = [];
    for (const site of SITES) {
      for (const entry of site.matches) {
        const { host, path } = split(entry);
        patterns.push(`https://${host}${path ? path + '*' : '/*'}`);
      }
    }
    return patterns;
  }

  /** The site a URL belongs to ({ name, host }), or null if Paste Guard does not run there. */
  function siteFor(url) {
    let parsed;
    try {
      parsed = new URL(url);
    } catch (e) {
      return null;
    }
    if (parsed.protocol !== 'https:') return null;
    for (const site of SITES) {
      for (const entry of site.matches) {
        const { host, path } = split(entry);
        if (parsed.hostname === host && (!path || parsed.pathname === path || parsed.pathname.startsWith(path + '/') || parsed.pathname.startsWith(path))) {
          return { name: site.name, host: parsed.hostname };
        }
      }
    }
    return null;
  }

  PG.sites = { list: SITES, matchPatterns, siteFor };

  if (typeof module !== 'undefined' && module.exports) module.exports = PG.sites;
})(typeof globalThis !== 'undefined' ? globalThis : this);
