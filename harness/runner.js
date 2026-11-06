// Wires the "Run all checks" button once the extension scripts have loaded.
(async function () {
  while (!window.__ready) await new Promise((r) => setTimeout(r, 25));
  await new Promise((resolve, reject) => {
    const el = document.createElement('script');
    el.src = '/harness/tests.js';
    el.onload = resolve;
    el.onerror = reject;
    document.head.append(el);
  });
  const button = document.getElementById('run');
  const results = document.getElementById('results');
  const summary = document.getElementById('summary');
  button.addEventListener('click', async () => {
    button.disabled = true;
    summary.textContent = 'running...';
    const list = await window.runHarnessChecks();
    const failed = list.filter((r) => !r.pass);
    results.hidden = false;
    results.replaceChildren(
      ...list.map((r) => {
        const line = document.createElement('div');
        line.className = r.pass ? 'pass' : 'fail';
        line.textContent = (r.pass ? 'PASS  ' : 'FAIL  ') + r.name + (r.detail ? '  ->  ' + r.detail : '');
        return line;
      })
    );
    window.__checkResults = list;
    summary.textContent = failed.length ? failed.length + ' of ' + list.length + ' checks failed' : 'all ' + list.length + ' checks passed';
    button.disabled = false;
  });
  window.__runnerReady = true;
})();
