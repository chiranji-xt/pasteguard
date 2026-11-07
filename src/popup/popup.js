/* Paste Guard: the toolbar popup. Says whether the current tab is protected and lets you pause it. */
(async function () {
  'use strict';
  const PG = window.PasteGuard;
  const api = typeof browser !== 'undefined' && browser.tabs ? browser : chrome;
  const store = PG.settings.store;
  const $ = (id) => document.getElementById(id);

  let settings = await store.getSettings();
  let tab = null;
  try {
    [tab] = await api.tabs.query({ active: true, currentWindow: true });
  } catch (e) {
    tab = null;
  }
  let site = tab && tab.url ? PG.sites.siteFor(tab.url, settings.customSites) : null;
  if (site && site.custom) {
    // Settings follow you between browsers, but the permission does not: only claim protection that is really granted here.
    try {
      if (!(await api.permissions.contains({ origins: ['https://' + site.host + '/*'] }))) site = null;
    } catch (e) {
      site = null;
    }
  }
  const pageHost = () => {
    try {
      const u = new URL(tab.url);
      return u.protocol === 'https:' && PG.sites.isValidHost(u.hostname) ? u.hostname.toLowerCase() : null;
    } catch (e) {
      return null;
    }
  };
  const scriptId = (host) => 'pg-' + host;

  function describeStatus() {
    const line = $('status-line');
    const detail = $('status-detail');
    const toggle = $('site-toggle');
    toggle.hidden = true;
    $('site-protect').hidden = true;
    line.className = 'status-line';

    if (!settings.enabled) {
      line.textContent = 'Paste Guard is off';
      detail.textContent = 'Nothing is being checked. Switch it on below.';
      return;
    }
    if (!site) {
      line.textContent = 'Not active on this page';
      detail.textContent = 'Paste Guard runs on AI chat sites like ChatGPT, Claude and Gemini. See the full list in Settings.';
      const host = tab && tab.url ? pageHost() : null;
      if (host && api.scripting && api.permissions) {
        const button = $('site-protect');
        button.hidden = false;
        button.textContent = 'Protect ' + host;
        detail.textContent = 'This site is not on the built-in list. You can add it: your browser will ask for permission for this one site only.';
      }
      return;
    }
    const paused = settings.pausedHosts.includes(site.host);
    line.textContent = paused ? 'Paused on ' + site.name : 'Protecting ' + site.name;
    line.classList.add(paused ? 'paused' : 'on');
    detail.textContent = paused ? 'Pastes on this site are not checked.' : 'Pastes, drops and attached files are checked before they are sent to the page.';
    toggle.hidden = false;
    toggle.textContent = paused ? 'Resume on ' + site.host : 'Pause on ' + site.host;
    if (site.custom) {
      const button = $('site-protect');
      button.hidden = false;
      button.textContent = 'Stop protecting ' + site.host;
    }
  }

  /** Add the current site: the browser asks for access to this one host, then the same content scripts are registered for it. */
  async function protectSite(host) {
    const origins = ['https://' + host + '/*'];
    const granted = await api.permissions.request({ origins });
    if (!granted) return false;
    const js = api.runtime.getManifest().content_scripts[0].js;
    try {
      await api.scripting.unregisterContentScripts({ ids: [scriptId(host)] });
    } catch (e) {
      /* not registered yet */
    }
    await api.scripting.registerContentScripts([{ id: scriptId(host), matches: origins, js, runAt: 'document_start', allFrames: false, persistAcrossSessions: true }]);
    try {
      await api.scripting.executeScript({ target: { tabId: tab.id }, files: js }); // protect the page that is already open, without a reload
    } catch (e) {
      /* the next load is protected anyway */
    }
    settings = await store.saveSettings(Object.assign({}, settings, { customSites: Array.from(new Set(settings.customSites.concat(host))) }));
    return true;
  }

  async function unprotectSite(host) {
    try {
      await api.scripting.unregisterContentScripts({ ids: [scriptId(host)] });
    } catch (e) {
      /* already gone */
    }
    try {
      await api.permissions.remove({ origins: ['https://' + host + '/*'] });
    } catch (e) {
      /* already gone */
    }
    settings = await store.saveSettings(Object.assign({}, settings, { customSites: settings.customSites.filter((h) => h !== host) }));
  }

  async function renderStats() {
    const s = await store.getStats();
    const caught = s.redacted + s.pastedAnyway + s.cancelled + s.blockedFiles;
    $('stats').textContent = s.warned
      ? 'Warned you ' + s.warned + (s.warned === 1 ? ' time' : ' times') + ' so far. ' + s.redacted + ' redacted, ' + s.cancelled + ' cancelled.'
      : caught
      ? ''
      : 'No warnings yet. Counts are kept on this device only.';
  }

  $('enabled').checked = settings.enabled;
  $('enabled').addEventListener('change', async (e) => {
    settings = await store.saveSettings(Object.assign({}, settings, { enabled: e.target.checked }));
    describeStatus();
  });
  $('site-toggle').addEventListener('click', async () => {
    const paused = new Set(settings.pausedHosts);
    if (paused.has(site.host)) paused.delete(site.host);
    else paused.add(site.host);
    settings = await store.saveSettings(Object.assign({}, settings, { pausedHosts: Array.from(paused) }));
    describeStatus();
  });
  $('site-protect').addEventListener('click', async () => {
    const button = $('site-protect');
    button.disabled = true;
    try {
      if (site && site.custom) {
        await unprotectSite(site.host);
        site = null;
      } else {
        const host = pageHost();
        if (host && (await protectSite(host))) site = PG.sites.siteFor(tab.url, settings.customSites);
      }
    } catch (e) {
      $('status-detail').textContent = 'Could not change protection for this site: ' + (e && e.message ? e.message : e);
      button.disabled = false;
      return;
    }
    button.disabled = false;
    describeStatus();
  });
  $('open-options').addEventListener('click', () => {
    api.runtime.openOptionsPage();
    window.close();
  });
  $('sites-link').addEventListener('click', (e) => {
    e.preventDefault();
    api.runtime.openOptionsPage();
    window.close();
  });

  describeStatus();
  await renderStats();
})();
