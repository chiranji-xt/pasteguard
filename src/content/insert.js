/* Paste Guard: put text back where the person was typing.
 *
 * Once a paste has been held back, the (possibly redacted) text has to be inserted again, into whatever
 * the page uses as a text box: a <textarea>, an <input>, or a rich editor built on contenteditable
 * (ChatGPT, Claude and others use ProseMirror-style editors).
 *
 * The approach is to let the page do its own insertion whenever it can, and to check that something
 * actually changed before trying the next method, so text is never inserted twice.
 */
(function (global) {
  'use strict';

  const PG = (global.PasteGuard = global.PasteGuard || {});

  /** Events this extension dispatched itself. The paste listener skips them so they are not scanned again. */
  const own = new WeakSet();

  const TEXT_INPUT_TYPES = new Set(['text', 'search', 'url', 'tel', 'email', 'password', '']);

  function isTextField(el) {
    if (!el || el.nodeType !== 1) return false;
    if (el.tagName === 'TEXTAREA') return true;
    return el.tagName === 'INPUT' && TEXT_INPUT_TYPES.has((el.getAttribute('type') || '').toLowerCase());
  }

  /** The root of a rich editor: the outermost editable ancestor. */
  function editableRoot(el) {
    if (!el || !el.isContentEditable) return null;
    let root = el;
    while (root.parentElement && root.parentElement.isContentEditable) root = root.parentElement;
    return root;
  }

  /** Where a paste or drop was aimed: { el, kind: 'field' | 'rich' } or null (not a text box). */
  function findTarget(event) {
    const path = typeof event.composedPath === 'function' ? event.composedPath() : [event.target];
    for (const node of path) {
      if (isTextField(node)) return { el: node, kind: 'field' };
      if (node && node.nodeType === 1 && node.isContentEditable) return { el: editableRoot(node), kind: 'rich' };
    }
    return null;
  }

  /** Remember the cursor or selection so it can be restored after the dialog steals focus. */
  function snapshot(target) {
    if (!target) return null;
    if (target.kind === 'field') {
      const el = target.el;
      return { start: el.selectionStart, end: el.selectionEnd, direction: el.selectionDirection };
    }
    const selection = global.getSelection && global.getSelection();
    return { range: selection && selection.rangeCount ? selection.getRangeAt(0).cloneRange() : null };
  }

  function restore(target, saved) {
    if (!target) return;
    try {
      target.el.focus({ preventScroll: true });
      if (!saved) return;
      if (target.kind === 'field') {
        if (saved.start !== null && saved.start !== undefined) target.el.setSelectionRange(saved.start, saved.end, saved.direction || 'none');
      } else if (saved.range) {
        const selection = global.getSelection();
        selection.removeAllRanges();
        selection.addRange(saved.range);
      }
    } catch (e) {
      /* the element may have been removed or re-rendered; inserting will simply fail safely */
    }
  }

  const contentOf = (target) => (target.kind === 'field' ? target.el.value : target.el.textContent);

  function fireInput(el, text) {
    try {
      el.dispatchEvent(new InputEvent('input', { bubbles: true, composed: true, inputType: 'insertFromPaste', data: text }));
    } catch (e) {
      el.dispatchEvent(new Event('input', { bubbles: true }));
    }
  }

  /** Last resort for a text field: write the value directly, using the native setter so React-style frameworks notice. */
  function setValueDirectly(el, text) {
    const start = el.selectionStart === null ? el.value.length : el.selectionStart;
    const end = el.selectionEnd === null ? el.value.length : el.selectionEnd;
    const next = el.value.slice(0, start) + text + el.value.slice(end);
    const proto = el.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(proto, 'value');
    if (setter && setter.set) setter.set.call(el, next);
    else el.value = next;
    el.setSelectionRange(start + text.length, start + text.length);
    fireInput(el, text);
  }

  /** Last resort for a rich editor: put a text node at the cursor. */
  function insertNodeDirectly(el, text) {
    const selection = global.getSelection();
    if (!selection || !selection.rangeCount) return false;
    const range = selection.getRangeAt(0);
    if (!el.contains(range.commonAncestorContainer)) return false;
    range.deleteContents();
    const node = document.createTextNode(text);
    range.insertNode(node);
    range.setStartAfter(node);
    range.collapse(true);
    selection.removeAllRanges();
    selection.addRange(range);
    fireInput(el, text);
    return true;
  }

  /**
   * Insert `text` at the saved cursor. Returns true if the text box changed.
   * Order of attempts: the page's own paste handling (rich editors), then the browser's insertText
   * command (keeps undo working), then writing the value directly. Each attempt is skipped if an
   * earlier one already changed the content, so nothing is inserted twice.
   */
  function insertText(target, saved, text) {
    if (!target || !target.el || !target.el.isConnected) return false;
    restore(target, saved);
    const before = contentOf(target);
    const changed = () => contentOf(target) !== before;

    if (target.kind === 'rich') {
      try {
        const data = new DataTransfer();
        data.setData('text/plain', text);
        const event = new ClipboardEvent('paste', { clipboardData: data, bubbles: true, cancelable: true, composed: true });
        own.add(event);
        target.el.dispatchEvent(event);
      } catch (e) {
        /* ClipboardEvent with data is not available: use the next method */
      }
      if (changed()) return true;
    }
    try {
      document.execCommand('insertText', false, text);
    } catch (e) {
      /* some pages disable it */
    }
    if (changed()) return true;

    if (target.kind === 'field') setValueDirectly(target.el, text);
    else insertNodeDirectly(target.el, text);
    return changed();
  }

  /** The text currently in a box. */
  function readText(target) {
    if (!target || !target.el) return '';
    return target.kind === 'field' ? target.el.value : target.el.innerText || target.el.textContent || '';
  }

  /** Select everything in the box and put `text` in its place (used by the one-click "Redact" on the typing warning). */
  function replaceAll(target, text) {
    if (!target || !target.el || !target.el.isConnected) return false;
    try {
      target.el.focus({ preventScroll: true });
      if (target.kind === 'field') {
        target.el.setSelectionRange(0, target.el.value.length);
      } else {
        const selection = global.getSelection();
        const range = document.createRange();
        range.selectNodeContents(target.el);
        selection.removeAllRanges();
        selection.addRange(range);
      }
    } catch (e) {
      return false;
    }
    return insertText(target, snapshot(target), text);
  }

  PG.insert = { own, findTarget, snapshot, restore, insertText, replaceAll, readText, isTextField, editableRoot };

  if (typeof module !== 'undefined' && module.exports) module.exports = PG.insert;
})(typeof globalThis !== 'undefined' ? globalThis : this);
