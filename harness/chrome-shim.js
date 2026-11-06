// Stands in for chrome.storage in the harness page, backed by localStorage, with the same promise API.
(function () {
  const listeners = [];
  function area(name) {
    const prefix = 'pgharness:' + name + ':';
    return {
      async get(key) {
        const raw = localStorage.getItem(prefix + key);
        return raw === null ? {} : { [key]: JSON.parse(raw) };
      },
      async set(values) {
        const changes = {};
        for (const [key, value] of Object.entries(values)) {
          const old = localStorage.getItem(prefix + key);
          localStorage.setItem(prefix + key, JSON.stringify(value));
          changes[key] = { oldValue: old === null ? undefined : JSON.parse(old), newValue: value };
        }
        listeners.forEach((listener) => listener(changes, name));
      },
    };
  }
  window.chrome = { storage: { sync: area('sync'), local: area('local'), onChanged: { addListener: (l) => listeners.push(l) } } };
  window.__PG_TEST__ = true; // exposes the dialog's shadow root to tests (see ui.js)
})();
