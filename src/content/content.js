/* Paste Guard: the content script. It runs on the supported chat sites and watches for secrets going in.
 *
 * What it listens for: paste, drop, and files chosen with an <input type="file">.
 * What it does when the text is clean: nothing at all. The browser's own paste goes ahead untouched.
 * What it does when it finds something: holds the paste back, asks, then inserts what the person chose.
 */
(function (global) {
  'use strict';

  const PG = global.PasteGuard;
  if (!PG || !PG.detect || !PG.settings || !PG.ui || !PG.insert || !PG.files) return;
  if (global.__pasteGuardLoaded) return; // never attach twice
  global.__pasteGuardLoaded = true;

  const { detect, settings: S, ui, insert, files } = PG;
  const store = S.store;

  let settings = S.defaults();
  let allowlist = new Set();
  let busy = false; // one dialog at a time

  if (store) {
    store.getSettings().then((s) => (settings = s));
    store.getAllowlist().then((list) => (allowlist = new Set(list.map((e) => e.hash))));
    store.onSettingsChange((s, hashes) => {
      if (s) settings = s;
      if (hashes) allowlist = new Set(hashes);
    });
  }

  const stat = (name, by) => store && store.bumpStat(name, by).catch(() => {});
  const active = () => !S.isPaused(settings, location.hostname);
  const scanOptions = () => S.toScanOptions(settings, allowlist);
  const mask = (finding) => detect.mask(finding);
  const noun = (n) => (n === 1 ? 'sensitive item' : 'sensitive items');

  /** Hold an event back from the page. */
  function hold(event) {
    event.preventDefault();
    event.stopImmediatePropagation();
  }

  async function rememberIgnored(findings) {
    if (!findings.length || !store) return;
    await store.addToAllowlist(findings.map((f) => detect.hashValue(f.value)));
  }

  // --- text: paste and drop ----------------------------------------------------------------------

  async function handleText(event, text, source) {
    const { findings, truncated } = detect.scan(text, scanOptions());
    if (!findings.length) return; // clean: let the browser carry on

    hold(event);
    if (busy) return; // a dialog is already open; this paste is dropped rather than queued
    const target = insert.findTarget(event);
    const saved = insert.snapshot(target);
    const redacted = detect.redact(text, findings);
    const put = (value) => {
      if (!insert.insertText(target, saved, value)) ui.toast('Paste Guard could not put the text back. Try pasting again with Paste Guard paused for this site.', 'warn');
    };

    if (settings.action === 'block') {
      ui.toast('Paste blocked: it contained ' + findings.length + ' ' + noun(findings.length) + '.', 'warn');
      stat('cancelled');
      return;
    }
    if (settings.action === 'redact') {
      put(redacted.text);
      ui.toast('Paste Guard redacted ' + findings.length + ' ' + noun(findings.length) + '.');
      stat('redacted');
      return;
    }

    busy = true;
    stat('warned');
    let answer;
    try {
      answer = await ui.confirmPaste({ findings, redactedText: redacted.text, mask, truncated, source });
    } finally {
      busy = false;
    }
    await rememberIgnored(answer.ignore).catch(() => {});
    if (answer.choice === 'redact') {
      put(redacted.text);
      stat('redacted');
    } else if (answer.choice === 'original') {
      put(text);
      stat('pastedAnyway');
    } else {
      insert.restore(target, saved);
      stat('cancelled');
    }
  }

  // --- files -------------------------------------------------------------------------------------

  /** Scan files that a paste, drop or file chooser is about to hand to the page. Calls `release()` to let them through. */
  async function handleFiles(event, fileList, release, discard) {
    const candidates = fileList.filter(files.isCandidate);
    if (!candidates.length) return false; // images and the like: do not touch the event at all
    hold(event);
    let hits;
    try {
      hits = await files.scanFiles(candidates, scanOptions());
    } catch (e) {
      hits = [];
    }
    if (!hits.length) {
      release();
      return true;
    }
    if (busy) {
      discard();
      return true;
    }
    busy = true;
    stat('warned');
    let answer;
    try {
      const first = hits[0];
      answer = await ui.confirmFile({ fileName: first.file.name || 'This file', findings: first.findings, mask });
    } finally {
      busy = false;
    }
    if (answer.choice === 'attach') {
      release();
    } else {
      discard();
      stat('blockedFiles');
      ui.toast('File not attached.');
    }
    return true;
  }

  function redispatchWithFiles(type, init, target, fileList) {
    const data = new DataTransfer();
    for (const file of fileList) data.items.add(file);
    let event;
    if (type === 'paste') event = new ClipboardEvent('paste', Object.assign({ clipboardData: data, bubbles: true, cancelable: true, composed: true }, init));
    else event = new DragEvent('drop', Object.assign({ dataTransfer: data, bubbles: true, cancelable: true, composed: true }, init));
    insert.own.add(event);
    target.dispatchEvent(event);
  }

  // --- listeners ---------------------------------------------------------------------------------

  function onPaste(event) {
    if (insert.own.has(event) || !active()) return;
    const data = event.clipboardData;
    if (!data) return;
    const text = data.getData('text/plain');
    if (text) {
      handleText(event, text, 'paste');
      return;
    }
    if (settings.scanFiles && data.files && data.files.length) {
      const list = Array.from(data.files);
      const target = event.target;
      handleFiles(event, list, () => {
        try {
          redispatchWithFiles('paste', {}, target, list);
        } catch (e) {
          ui.toast('Paste Guard could not hand the file back. Try again with Paste Guard paused for this site.', 'warn');
        }
      }, () => {});
    }
  }

  function onDrop(event) {
    if (insert.own.has(event) || !active()) return;
    const data = event.dataTransfer;
    if (!data) return;
    if (settings.scanFiles && data.files && data.files.length) {
      const list = Array.from(data.files);
      const target = event.target;
      const init = { clientX: event.clientX, clientY: event.clientY };
      const handled = handleFiles(event, list, () => {
        try {
          redispatchWithFiles('drop', init, target, list);
        } catch (e) {
          ui.toast('Paste Guard could not hand the file back. Try again with Paste Guard paused for this site.', 'warn');
        }
      }, () => {});
      if (list.some(files.isCandidate)) return handled;
    }
    const text = data.getData && data.getData('text/plain');
    if (text) handleText(event, text, 'drop');
  }

  function onChange(event) {
    const input = event.target;
    if (insert.own.has(event) || !active() || !settings.scanFiles) return;
    if (!input || input.tagName !== 'INPUT' || input.type !== 'file' || !input.files || !input.files.length) return;
    const list = Array.from(input.files);
    handleFiles(
      event,
      list,
      () => {
        const again = new Event('change', { bubbles: true });
        insert.own.add(again);
        input.dispatchEvent(again);
      },
      () => {
        try {
          input.value = '';
        } catch (e) {
          /* some inputs refuse; the file was not handed to the page, which is what matters */
        }
      }
    );
  }

  // Window capture phase, registered at document_start: this runs before any listener the page adds later.
  global.addEventListener('paste', onPaste, true);
  global.addEventListener('drop', onDrop, true);
  global.addEventListener('change', onChange, true);

  PG.content = { handleText, onPaste, onDrop, onChange, state: () => ({ settings, allowlist }) };
})(typeof globalThis !== 'undefined' ? globalThis : this);
