// Loads the extension's content scripts in manifest order, then installs the "page" behaviour that the
// extension has to coexist with. The page's listeners are added AFTER the extension's, like on a real site.
(async function () {
  const scripts = await (await fetch('/__scripts')).json();
  for (const src of scripts) {
    await new Promise((resolve, reject) => {
      const el = document.createElement('script');
      el.src = src;
      el.onload = resolve;
      el.onerror = () => reject(new Error('failed to load ' + src));
      document.head.append(el);
    });
  }

  // --- the "page" ---------------------------------------------------------------------------------
  const log = [];
  window.__log = log;
  const out = document.getElementById('log');
  const note = (entry) => {
    log.push(entry);
    out.textContent = log.map((e) => JSON.stringify(e)).join('\n');
  };

  // A page that watches every paste, to prove what the extension did and did not let through.
  window.addEventListener('paste', (e) => note({ page: 'paste', id: e.target.id || e.target.tagName, text: e.clipboardData && e.clipboardData.getData('text/plain'), synthetic: !e.isTrusted }), true);
  window.addEventListener('drop', (e) => note({ page: 'drop', id: e.target.id, files: e.dataTransfer ? Array.from(e.dataTransfer.files).map((f) => f.name) : [] }), true);
  document.getElementById('file').addEventListener('change', (e) => note({ page: 'file-change', files: Array.from(e.target.files).map((f) => f.name) }));

  // A rich editor that takes over paste, as ProseMirror does.
  //
  // The important detail: like ProseMirror, it keeps its OWN record of the selection, which it only updates when the
  // browser fires "selectionchange" (a moment after the selection actually changes). A paste is applied to that
  // record, not to the browser's live selection. So code that selects everything and pastes in the same instant
  // pastes at the OLD position. A real ChatGPT box did exactly this, which is how this was found.
  const rich = document.getElementById('rich');
  window.__richPastes = 0;
  let editorSelection = null;
  const syncSelection = () => {
    const selection = getSelection();
    if (selection.rangeCount && rich.contains(selection.anchorNode)) editorSelection = selection.getRangeAt(0).cloneRange();
  };
  // window.__pmDelay (milliseconds) makes the editor even slower to notice a new selection, for stress tests.
  document.addEventListener('selectionchange', () => (window.__pmDelay ? setTimeout(syncSelection, window.__pmDelay) : syncSelection()));
  rich.addEventListener('input', syncSelection);
  rich.addEventListener('focus', () => setTimeout(syncSelection, 0));
  rich.addEventListener('paste', (e) => {
    e.preventDefault();
    window.__richPastes++;
    const text = e.clipboardData.getData('text/plain');
    const range = editorSelection && rich.contains(editorSelection.commonAncestorContainer) ? editorSelection : document.createRange();
    if (!rich.contains(range.commonAncestorContainer)) { range.selectNodeContents(rich); range.collapse(false); }
    range.deleteContents();
    const node = document.createTextNode(text);
    range.insertNode(node);
    range.setStartAfter(node);
    range.collapse(true);
    editorSelection = range.cloneRange();
    const selection = getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
  });

  window.__ready = true;
  note({ page: 'ready', scripts: scripts.length });
})();
