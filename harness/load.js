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
  const rich = document.getElementById('rich');
  window.__richPastes = 0;
  rich.addEventListener('paste', (e) => {
    e.preventDefault();
    window.__richPastes++;
    const text = e.clipboardData.getData('text/plain');
    const selection = getSelection();
    const range = selection.rangeCount ? selection.getRangeAt(0) : document.createRange();
    if (!rich.contains(range.commonAncestorContainer)) { range.selectNodeContents(rich); range.collapse(false); }
    range.deleteContents();
    const node = document.createTextNode(text);
    range.insertNode(node);
    range.setStartAfter(node);
    range.collapse(true);
    selection.removeAllRanges();
    selection.addRange(range);
  });

  window.__ready = true;
  note({ page: 'ready', scripts: scripts.length });
})();
