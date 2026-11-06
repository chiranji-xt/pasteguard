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
  const site = tab && tab.url ? PG.sites.siteFor(tab.url) : null;

  function describeStatus() {
    const line = $('status-line');
    const detail = $('status-detail');
    const toggle = $('site-toggle');
    toggle.hidden = true;
    line.className = 'status-line';

    if (!settings.enabled) {
      line.textContent = 'Paste Guard is off';
      detail.textContent = 'Nothing is being checked. Switch it on below.';
      return;
    }
    if (!site) {
      line.textContent = 'Not active on this page';
      detail.textContent = 'Paste Guard runs on AI chat sites like ChatGPT, Claude and Gemini. See the full list in Settings.';
      return;
    }
    const paused = settings.pausedHosts.includes(site.host);
    line.textContent = paused ? 'Paused on ' + site.name : 'Protecting ' + site.name;
    line.classList.add(paused ? 'paused' : 'on');
    detail.textContent = paused ? 'Pastes on this site are not checked.' : 'Pastes, drops and attached files are checked before they are sent to the page.';
    toggle.hidden = false;
    toggle.textContent = paused ? 'Resume on ' + site.host : 'Pause on ' + site.host;
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
