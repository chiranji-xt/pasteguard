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
    { name: 'Claude (claude.com)', matches: ['claude.com'] },
    { name: 'Microsoft 365 Copilot', matches: ['m365.cloud.microsoft', 'copilot.cloud.microsoft'] },
    { name: 'GitHub Copilot Chat', matches: ['github.com/copilot'] },
    { name: 'Grok on X', matches: ['x.com/i/grok'] },
    { name: 'Kimi', matches: ['www.kimi.com', 'kimi.com', 'kimi.moonshot.cn'] },
    { name: 'Z.ai (GLM)', matches: ['chat.z.ai'] },
    { name: 'LMArena', matches: ['lmarena.ai'] },
    { name: 'Groq Console', matches: ['console.groq.com'] },
    { name: 'DuckDuckGo AI Chat', matches: ['duck.ai', 'duckduckgo.com/aichat'] },
    { name: 'You.com', matches: ['you.com'] },
    { name: 'Phind', matches: ['www.phind.com', 'phind.com'] },
    { name: 'Kagi Assistant', matches: ['kagi.com/assistant'] },
    { name: 'Pi', matches: ['pi.ai'] },
    { name: 'Character.AI', matches: ['character.ai', 'www.character.ai'] },
    { name: 'Venice', matches: ['venice.ai'] },
    { name: 'Monica', matches: ['monica.im'] },
    { name: 'Manus', matches: ['manus.im'] },
    { name: 'Genspark', matches: ['www.genspark.ai', 'genspark.ai'] },
    { name: 'Coze', matches: ['www.coze.com', 'www.coze.cn'] },
    { name: 'NotebookLM', matches: ['notebooklm.google.com'] },
    { name: 'Jules', matches: ['jules.google.com'] },
    { name: 'v0', matches: ['v0.dev', 'v0.app'] },
    { name: 'Bolt', matches: ['bolt.new'] },
    { name: 'Lovable', matches: ['lovable.dev'] },
    { name: 'Replit', matches: ['replit.com'] },
    { name: 'Base44', matches: ['base44.com', 'app.base44.com'] },
    { name: 'Devin', matches: ['app.devin.ai'] },
    { name: 'Cursor Agents', matches: ['cursor.com/agents'] },
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

  const HOST = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
  /** A host the person may add themselves: a plain https website name (no IP addresses, ports or paths). */
  const isValidHost = (host) => typeof host === 'string' && HOST.test(host);

  /** The site a URL belongs to ({ name, host }), or null if Paste Guard does not run there. `custom` is the list of hosts the person added. */
  function siteFor(url, custom) {
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
    if (Array.isArray(custom) && custom.includes(parsed.hostname.toLowerCase())) return { name: parsed.hostname, host: parsed.hostname, custom: true };
    return null;
  }

  PG.sites = { list: SITES, matchPatterns, siteFor, isValidHost };

  if (typeof module !== 'undefined' && module.exports) module.exports = PG.sites;
})(typeof globalThis !== 'undefined' ? globalThis : this);
