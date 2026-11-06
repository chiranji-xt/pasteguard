/* Paste Guard: the warning dialog and toast.
 *
 * Both live in a closed Shadow DOM, so the page's own CSS cannot change how they look and the page's
 * scripts cannot read them. Styles use a constructable stylesheet (exempt from inline-style CSP), falling
 * back to a <style> element. All text is set with textContent: nothing from the clipboard becomes HTML.
 */
(function (global) {
  'use strict';

  const PG = (global.PasteGuard = global.PasteGuard || {});

  const CSS = `
    :host { all: initial; }
    * { box-sizing: border-box; }
    .backdrop {
      position: fixed; inset: 0; z-index: 2147483647; display: flex; align-items: center; justify-content: center;
      background: rgba(15, 23, 42, 0.55); padding: 16px;
      font: 14px/1.45 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; color: #0f172a;
    }
    .dialog {
      width: min(520px, 100%); max-height: min(640px, 100%); overflow: auto; background: #ffffff; border-radius: 14px;
      box-shadow: 0 24px 60px rgba(0, 0, 0, 0.35); padding: 20px 22px 18px; border: 1px solid #e2e8f0;
    }
    header { display: flex; align-items: center; gap: 10px; margin-bottom: 4px; }
    .badge {
      flex: none; width: 28px; height: 28px; border-radius: 8px; display: grid; place-items: center;
      background: linear-gradient(160deg, #0ea5e9, #4f46e5); color: #fff; font-weight: 700; font-size: 16px;
    }
    h2 { margin: 0; font-size: 17px; font-weight: 650; }
    .sub { margin: 2px 0 14px 38px; color: #475569; font-size: 13px; }
    ul { list-style: none; margin: 0 0 12px; padding: 0; display: grid; gap: 8px; }
    li { border: 1px solid #e2e8f0; border-radius: 10px; padding: 9px 11px; background: #f8fafc; }
    .row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
    .dot { flex: none; width: 9px; height: 9px; border-radius: 50%; background: #94a3b8; }
    .dot.high { background: #dc2626; } .dot.medium { background: #d97706; } .dot.low { background: #2563eb; }
    .label { font-weight: 600; }
    code { font: 12.5px ui-monospace, "Cascadia Mono", Consolas, monospace; color: #334155; background: #e2e8f0; border-radius: 5px; padding: 1px 6px; overflow-wrap: anywhere; }
    .ignore { display: flex; align-items: center; gap: 6px; margin-top: 6px; color: #475569; font-size: 12.5px; cursor: pointer; }
    details { margin: 0 0 14px; }
    summary { cursor: pointer; color: #334155; font-size: 13px; }
    pre { margin: 8px 0 0; max-height: 150px; overflow: auto; padding: 10px; border-radius: 8px; background: #f1f5f9; white-space: pre-wrap; overflow-wrap: anywhere; font: 12.5px/1.45 ui-monospace, "Cascadia Mono", Consolas, monospace; }
    mark { background: #fde68a; color: #422006; border-radius: 3px; padding: 0 2px; }
    footer { display: flex; gap: 8px; justify-content: flex-end; flex-wrap: wrap; }
    button {
      font: inherit; font-weight: 600; border-radius: 9px; padding: 8px 14px; cursor: pointer; border: 1px solid #cbd5e1;
      background: #ffffff; color: #0f172a;
    }
    button:hover { background: #f1f5f9; }
    button.primary { background: #4f46e5; border-color: #4f46e5; color: #fff; }
    button.primary:hover { background: #4338ca; }
    button.danger { color: #b91c1c; border-color: #fecaca; }
    button.danger:hover { background: #fef2f2; }
    button:focus-visible, summary:focus-visible, input:focus-visible { outline: 3px solid #93c5fd; outline-offset: 2px; }
    .note { margin: 0 0 12px; color: #92400e; background: #fffbeb; border: 1px solid #fde68a; border-radius: 8px; padding: 7px 10px; font-size: 12.5px; }
    .toast {
      position: fixed; right: 18px; bottom: 18px; z-index: 2147483647; max-width: 340px; padding: 10px 14px; border-radius: 10px;
      background: #0f172a; color: #fff; font: 13.5px/1.4 system-ui, -apple-system, "Segoe UI", sans-serif; box-shadow: 0 10px 30px rgba(0,0,0,.35);
    }
    .toast.warn { background: #92400e; }
    @media (prefers-color-scheme: dark) {
      .backdrop { color: #e2e8f0; }
      .dialog { background: #111827; border-color: #1f2937; }
      .sub, .ignore, summary { color: #94a3b8; }
      li { background: #0b1220; border-color: #1f2937; }
      code { background: #1f2937; color: #cbd5e1; }
      pre { background: #0b1220; }
      mark { background: #854d0e; color: #fef3c7; }
      button { background: #111827; border-color: #374151; color: #e2e8f0; }
      button:hover { background: #1f2937; }
      button.primary { background: #6366f1; border-color: #6366f1; color: #fff; }
      button.primary:hover { background: #4f46e5; }
      button.danger { color: #fca5a5; border-color: #7f1d1d; }
      button.danger:hover { background: #2a1212; }
      .note { background: #2a1d05; border-color: #713f12; color: #fde68a; }
    }
    @media (prefers-reduced-motion: no-preference) {
      .dialog { animation: pop 120ms ease-out; }
      @keyframes pop { from { transform: translateY(6px) scale(0.98); opacity: 0; } to { transform: none; opacity: 1; } }
    }
  `;

  let host = null;
  let shadow = null;
  let open = false;

  function h(tag, props, ...children) {
    const node = document.createElement(tag);
    if (props) {
      for (const [key, value] of Object.entries(props)) {
        if (value === undefined || value === null || value === false) continue;
        if (key === 'class') node.className = value;
        else if (key === 'text') node.textContent = value;
        else node.setAttribute(key, value === true ? '' : value);
      }
    }
    for (const child of children) if (child) node.append(child);
    return node;
  }

  function ensureHost() {
    if (shadow && host.isConnected) return shadow;
    host = document.createElement('div');
    host.setAttribute('data-pasteguard', '');
    shadow = host.attachShadow({ mode: 'closed' });
    let styled = false;
    try {
      const sheet = new CSSStyleSheet();
      sheet.replaceSync(CSS);
      shadow.adoptedStyleSheets = [sheet];
      styled = true;
    } catch (e) {
      /* fall through to a <style> element */
    }
    if (!styled) shadow.append(h('style', { text: CSS }));
    (document.documentElement || document).append(host);
    return shadow;
  }

  /** Text with [REDACTED:...] placeholders wrapped in <mark>, built without innerHTML. */
  function previewNodes(text) {
    const limit = 1500;
    const shown = text.length > limit ? text.slice(0, limit) : text;
    const pre = h('pre');
    const parts = shown.split(/(\[REDACTED:[A-Z0-9_]+\])/);
    for (const part of parts) {
      if (!part) continue;
      pre.append(/^\[REDACTED:/.test(part) ? h('mark', { text: part }) : document.createTextNode(part));
    }
    if (text.length > limit) pre.append(document.createTextNode('\n… (' + (text.length - limit).toLocaleString() + ' more characters)'));
    return pre;
  }

  function plural(n, one, many) {
    return n === 1 ? one : many;
  }

  /**
   * Show a modal and resolve with the button that was chosen.
   * `build(close)` returns { title, sub, body: [nodes], buttons: [{ label, value, kind }] }.
   * Escape resolves with `cancelValue`.
   */
  function showModal(build, cancelValue) {
    return new Promise((resolve) => {
      const root = ensureHost();
      open = true;
      const returnFocus = document.activeElement;
      let finished = false;
      const spec = build();

      const finish = (value) => {
        if (finished) return;
        finished = true;
        open = false;
        backdrop.remove();
        resolve(value);
        try {
          if (returnFocus && returnFocus.focus) returnFocus.focus({ preventScroll: true });
        } catch (e) {
          /* the element may be gone */
        }
      };

      const buttons = spec.buttons.map((b) => h('button', { class: b.kind || '', type: 'button', text: b.label }));
      buttons.forEach((el, i) => el.addEventListener('click', () => finish(spec.buttons[i].value)));

      const dialog = h(
        'div',
        { class: 'dialog', role: 'alertdialog', 'aria-modal': 'true', 'aria-labelledby': 'pg-title', 'aria-describedby': 'pg-sub' },
        h('header', null, h('span', { class: 'badge', 'aria-hidden': 'true', text: '!' }), h('h2', { id: 'pg-title', text: spec.title })),
        h('p', { class: 'sub', id: 'pg-sub', text: spec.sub }),
        ...spec.body,
        h('footer', null, ...buttons)
      );
      const backdrop = h('div', { class: 'backdrop', role: 'presentation' }, dialog);
      root.append(backdrop);

      // Keep keystrokes away from the page (chat sites have keyboard shortcuts) and trap focus in the dialog.
      const stop = (e) => e.stopPropagation();
      backdrop.addEventListener('keyup', stop);
      backdrop.addEventListener('keypress', stop);
      backdrop.addEventListener('keydown', (e) => {
        e.stopPropagation();
        if (e.key === 'Escape') {
          e.preventDefault();
          finish(cancelValue);
        } else if (e.key === 'Tab') {
          const focusable = Array.from(dialog.querySelectorAll('button, input, summary'));
          const first = focusable[0];
          const last = focusable[focusable.length - 1];
          const active = root.activeElement;
          if (e.shiftKey && active === first) {
            e.preventDefault();
            last.focus();
          } else if (!e.shiftKey && active === last) {
            e.preventDefault();
            first.focus();
          }
        }
      });
      backdrop.addEventListener('mousedown', (e) => {
        if (e.target === backdrop) e.preventDefault(); // clicking outside does nothing: a stray click must not decide
      });

      (buttons[spec.focus === undefined ? 0 : spec.focus] || buttons[0]).focus();
    });
  }

  /**
   * Ask what to do with a paste that contains secrets.
   * Resolves { choice: 'redact' | 'original' | 'cancel', ignore: [finding, ...] }.
   */
  function confirmPaste(options) {
    const { findings, redactedText, mask, truncated } = options;
    const checks = [];
    const items = findings.map((f) => {
      const box = h('input', { type: 'checkbox' });
      checks.push({ box, finding: f });
      return h(
        'li',
        null,
        h('div', { class: 'row' }, h('span', { class: 'dot ' + f.severity, 'aria-hidden': 'true' }), h('span', { class: 'label', text: f.label }), h('code', { text: mask(f) })),
        h('label', { class: 'ignore' }, box, document.createTextNode('This is fine: stop warning me about this exact value'))
      );
    });
    const body = [h('ul', null, ...items)];
    if (truncated) body.push(h('p', { class: 'note', text: 'This paste is very large, so only the first part was checked.' }));
    body.push(h('details', null, h('summary', { text: 'Show what will be pasted if you redact' }), previewNodes(redactedText)));

    return showModal(
      () => ({
        title: 'Paste Guard found ' + (findings.length === 1 ? 'something sensitive' : findings.length + ' sensitive items'),
        sub: 'Nothing has been pasted yet. This check ran on your device and nothing was sent anywhere.',
        body,
        buttons: [
          { label: 'Redact and paste', value: 'redact', kind: 'primary' },
          { label: 'Paste anyway', value: 'original', kind: 'danger' },
          { label: 'Cancel', value: 'cancel' },
        ],
      }),
      'cancel'
    ).then((choice) => ({ choice, ignore: checks.filter((c) => c.box.checked).map((c) => c.finding) }));
  }

  /** Ask what to do with a file that contains secrets. Resolves { choice: 'remove' | 'attach' }. */
  function confirmFile(options) {
    const { fileName, findings, mask } = options;
    const items = findings.slice(0, 6).map((f) =>
      h('li', null, h('div', { class: 'row' }, h('span', { class: 'dot ' + f.severity, 'aria-hidden': 'true' }), h('span', { class: 'label', text: f.label }), h('code', { text: mask(f) })))
    );
    const more = findings.length > 6 ? h('p', { class: 'note', text: '…and ' + (findings.length - 6) + ' more.' }) : null;
    return showModal(
      () => ({
        title: 'This file contains ' + (findings.length === 1 ? 'a secret' : findings.length + ' sensitive items'),
        sub: fileName + ' has not been attached. It was checked on your device and nothing was sent anywhere.',
        body: [h('ul', null, ...items), more],
        buttons: [
          { label: "Don't attach", value: 'remove', kind: 'primary' },
          { label: 'Attach anyway', value: 'attach', kind: 'danger' },
        ],
      }),
      'remove'
    ).then((choice) => ({ choice }));
  }

  let toastTimer = null;
  /** A short message in the corner. */
  function toast(message, kind) {
    const root = ensureHost();
    root.querySelectorAll('.toast').forEach((n) => n.remove());
    const node = h('div', { class: 'toast' + (kind === 'warn' ? ' warn' : ''), role: 'status', 'aria-live': 'polite', text: message });
    root.append(node);
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => node.remove(), 4500);
  }

  PG.ui = { confirmPaste, confirmFile, toast, isOpen: () => open, plural };
  // Test hook. Only the local test harness (where nothing is isolated) can set this flag: a content script
  // runs in its own JavaScript world, so a web page can never reach it and the shadow root stays closed.
  if (global.__PG_TEST__) PG.ui.__shadow = () => shadow;

  if (typeof module !== 'undefined' && module.exports) module.exports = PG.ui;
})(typeof globalThis !== 'undefined' ? globalThis : this);
