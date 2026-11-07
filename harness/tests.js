// Browser checks for the content script. Open the harness (npm run harness) and press "Run all checks".
// They drive the real scripts with real DOM events and report what the page saw.
(function () {
  const PG = window.PasteGuard;
  const store = PG.settings.store;
  const ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const rnd = (n) => Array.from({ length: n }, () => ALPHA[Math.floor(Math.random() * ALPHA.length)]).join('');
  // Fake secrets are built here, at run time, from parts: nothing in this repository is shaped like a real key.
  const KEY = () => 'gh' + 'p_' + rnd(36);
  const KEY2 = () => 'AKIA' + Array.from({ length: 16 }, () => 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'[Math.floor(Math.random() * 32)]).join('');
  const settle = (ms = 40) => new Promise((r) => setTimeout(r, ms));
  // Wait until the content script has finished whatever it was doing (a redaction takes a few steps).
  const idle = async () => {
    await settle(30);
    for (let i = 0; i < 40 && PG.content.state().busy; i++) await settle(50);
    await settle(30);
  };
  const $ = (id) => document.getElementById(id);
  const shadow = () => PG.ui.__shadow && PG.ui.__shadow();
  const dialog = () => shadow() && shadow().querySelector('.dialog');
  const button = (label) => shadow() && [...shadow().querySelectorAll('button')].find((b) => b.textContent === label);
  const toastText = () => { const t = shadow() && shadow().querySelector('.toast'); return t ? t.textContent : null; };
  const pageSaw = (text) => window.__log.some((e) => e.page === 'paste' && e.text && e.text.includes(text));
  const fileChanges = () => window.__log.filter((e) => e.page === 'file-change');
  const withSettings = async (patch) => { await store.saveSettings(Object.assign(PG.settings.defaults(), patch)); await settle(30); };
  const fileOf = (name, content, type = '') => new File([content], name, { type });
  const envWithSecret = () => 'APP=demo\nGITHUB_TOKEN=' + KEY() + '\nDEBUG=false\n';

  function paste(el, text) {
    const data = new DataTransfer();
    data.setData('text/plain', text);
    const event = new ClipboardEvent('paste', { clipboardData: data, bubbles: true, cancelable: true, composed: true });
    el.focus();
    el.dispatchEvent(event);
    return event;
  }
  function chooseFile(file) {
    const data = new DataTransfer();
    data.items.add(file);
    $('file').files = data.files;
    $('file').dispatchEvent(new Event('change', { bubbles: true }));
  }
  async function reset() {
    await idle(); // never start a check while the previous one's redaction is still running
    while (dialog()) { (button('Cancel') || button("Don't attach")).click(); await settle(); }
    for (const id of ['ta', 'inp', 'chat']) $(id).value = '';
    for (const id of ['ce', 'rich']) $(id).textContent = '';
    $('file').value = '';
    window.__log.length = 0;
    window.__richPastes = 0;
    await store.saveSettings(PG.settings.defaults());
    await store.clearAllowlist();
    await store.resetStats();
    await settle(20);
  }

  const checks = [];
  const check = (name, fn) => checks.push({ name, fn });

  // --- paste: the basics ---------------------------------------------------------------------------
  check('clean text pastes normally (nothing held, the page sees it)', async () => {
    const ev = paste($('ta'), 'hello, here is some ordinary text 12345');
    await settle();
    if (ev.defaultPrevented) return 'a clean paste was held back';
    if (dialog()) return 'a dialog appeared for clean text';
    if (!pageSaw('ordinary text')) return 'the page never saw the clean paste';
  });
  check('secret into a textarea: held, dialog shown, redact inserts a placeholder', async () => {
    const k = KEY();
    const ev = paste($('ta'), k);
    if (!ev.defaultPrevented) return 'paste was not held';
    if (pageSaw(k)) return 'the page saw the secret';
    if (!dialog()) return 'no dialog';
    const shown = dialog().textContent;
    if (shown.includes(k)) return 'the dialog shows the full secret';
    if (!/GitHub token/.test(shown) || !/ghp_…/.test(shown)) return 'dialog missing label or masked preview: ' + shown.slice(0, 200);
    button('Redact and paste').click();
    await settle();
    if ($('ta').value !== '[REDACTED:GITHUB_TOKEN]') return 'textarea has: ' + $('ta').value;
    if (dialog()) return 'dialog still open';
    if (JSON.stringify(window.__log).includes(k)) return 'the secret leaked to the page after redaction';
  });
  check('paste anyway inserts the original', async () => {
    const k = KEY();
    paste($('ta'), k);
    button('Paste anyway').click();
    await settle();
    return $('ta').value === k || 'got: ' + $('ta').value;
  });
  check('cancel inserts nothing and returns focus to the box', async () => {
    $('ta').value = 'keep me';
    paste($('ta'), KEY());
    button('Cancel').click();
    await settle();
    if ($('ta').value !== 'keep me') return 'value changed: ' + $('ta').value;
    if (document.activeElement !== $('ta')) return 'focus not returned';
  });
  check('escape key cancels', async () => {
    paste($('ta'), KEY());
    dialog().dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, composed: true }));
    await settle();
    return (!dialog() && $('ta').value === '') || 'dialog open: ' + !!dialog();
  });
  check('pasting over a selection replaces just the selection', async () => {
    const ta = $('ta');
    ta.value = 'hello WORLD end';
    ta.focus();
    ta.setSelectionRange(6, 11);
    paste(ta, KEY());
    button('Redact and paste').click();
    await settle();
    return ta.value === 'hello [REDACTED:GITHUB_TOKEN] end' || 'got: ' + ta.value;
  });
  check('surrounding text is preserved, only the secret is replaced', async () => {
    paste($('ta'), 'export TOKEN=' + KEY() + '\nnpm run build');
    button('Redact and paste').click();
    await settle();
    return $('ta').value === 'export TOKEN=[REDACTED:GITHUB_TOKEN]\nnpm run build' || 'got: ' + JSON.stringify($('ta').value);
  });
  check('two different secrets get their own placeholders', async () => {
    paste($('ta'), KEY() + ' and ' + KEY2());
    button('Redact and paste').click();
    await settle();
    return $('ta').value === '[REDACTED:GITHUB_TOKEN] and [REDACTED:AWS_ACCESS_KEY_ID]' || 'got: ' + $('ta').value;
  });

  // --- every kind of text box ----------------------------------------------------------------------
  check('single-line input works', async () => {
    paste($('inp'), KEY());
    button('Redact and paste').click();
    await settle();
    return $('inp').value === '[REDACTED:GITHUB_TOKEN]' || 'got: ' + $('inp').value;
  });
  check('plain contenteditable works (the browser inserts)', async () => {
    paste($('ce'), 'key ' + KEY());
    button('Redact and paste').click();
    await settle();
    return $('ce').textContent === 'key [REDACTED:GITHUB_TOKEN]' || 'got: ' + JSON.stringify($('ce').textContent);
  });
  check('rich editor that handles paste itself: handled exactly once, no duplicate', async () => {
    paste($('rich'), 'key ' + KEY());
    button('Redact and paste').click();
    await settle();
    if (window.__richPastes !== 1) return 'the editor handled ' + window.__richPastes + ' pastes';
    return $('rich').textContent === 'key [REDACTED:GITHUB_TOKEN]' || 'got: ' + JSON.stringify($('rich').textContent);
  });

  function selectIn(el, from, to) {
    const node = el.firstChild;
    const range = document.createRange();
    range.setStart(node, from);
    range.setEnd(node, to);
    const selection = getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
  }
  check('rich editor: pasting over a selected phrase replaces only that phrase', async () => {
    $('rich').textContent = 'hello WORLD end';
    $('rich').focus();
    selectIn($('rich'), 6, 11);
    await settle(80); // the editor notices a selection a moment after it is made, as real ones do
    paste($('rich'), KEY());
    button('Redact and paste').click();
    await settle(120);
    return $('rich').textContent === 'hello [REDACTED:GITHUB_TOKEN] end' || 'got: ' + $('rich').textContent;
  });
  check('rich editor: pasting at a caret in the middle of existing text', async () => {
    $('rich').textContent = 'before after';
    $('rich').focus();
    selectIn($('rich'), 7, 7);
    await settle(80);
    paste($('rich'), 'X ' + KEY() + ' Y');
    button('Redact and paste').click();
    await settle(120);
    return $('rich').textContent === 'before X [REDACTED:GITHUB_TOKEN] Yafter' || 'got: ' + $('rich').textContent;
  });

  // --- the ignore list and the dialog ----------------------------------------------------------------
  check('ignore checkbox: that exact value is let through next time, and only a hash is stored', async () => {
    const k = KEY();
    paste($('ta'), k);
    shadow().querySelector('input[type=checkbox]').click();
    button('Redact and paste').click();
    await settle(80);
    const ev = paste($('ta'), k);
    await settle();
    const list = await store.getAllowlist();
    if (ev.defaultPrevented) return 'the ignored value was held again';
    if (list.length !== 1 || !/^[a-f0-9]{64}$/.test(list[0].hash)) return 'allowlist: ' + JSON.stringify(list);
    if (JSON.stringify(list).includes(k)) return 'the allowlist contains the raw secret';
    const other = paste($('ta'), KEY());
    if (!other.defaultPrevented) return 'a different key was let through';
    button('Cancel').click();
    await settle();
  });
  check('a second paste while the dialog is open is dropped, not stacked', async () => {
    paste($('ta'), KEY());
    const ev = paste($('ta'), KEY2());
    const n = shadow().querySelectorAll('.dialog').length;
    button('Cancel').click();
    await settle();
    return (ev.defaultPrevented && n === 1) || 'dialogs: ' + n;
  });
  check('tab key stays inside the dialog (focus trap)', async () => {
    paste($('ta'), KEY());
    const buttons = [...shadow().querySelectorAll('button')];
    buttons[buttons.length - 1].focus();
    dialog().dispatchEvent(new KeyboardEvent('keydown', { key: 'Tab', bubbles: true, composed: true, cancelable: true }));
    const inside = shadow().activeElement;
    button('Cancel').click();
    await settle();
    return (inside && inside.closest && inside.closest('.dialog') !== null) || 'focus escaped the dialog';
  });
  check('a large clean paste (1 MB) is fast and untouched', async () => {
    const big = 'const x = await fetch(url); // some code line\n'.repeat(22000);
    const started = performance.now();
    const ev = paste($('ta'), big);
    const ms = performance.now() - started;
    if (ev.defaultPrevented) return 'held';
    return ms < 400 || ms.toFixed(0) + ' ms for ' + big.length + ' characters';
  });

  // --- settings --------------------------------------------------------------------------------------
  check('action=redact: cleans the paste with no dialog and shows a notice', async () => {
    await withSettings({ action: 'redact' });
    const ev = paste($('ta'), KEY());
    await settle();
    if (!ev.defaultPrevented) return 'not held';
    if (dialog()) return 'a dialog appeared';
    if ($('ta').value !== '[REDACTED:GITHUB_TOKEN]') return 'value: ' + $('ta').value;
    return /redacted 1 sensitive item/i.test(toastText() || '') || 'toast: ' + toastText();
  });
  check('action=block: refuses the paste', async () => {
    await withSettings({ action: 'block' });
    const ev = paste($('ta'), KEY());
    await settle();
    if (!ev.defaultPrevented) return 'not held';
    if ($('ta').value !== '') return 'text was inserted';
    return /blocked/i.test(toastText() || '') || 'toast: ' + toastText();
  });
  check('paused on this site: everything passes through', async () => {
    await withSettings({ pausedHosts: [location.hostname] });
    const ev = paste($('ta'), KEY());
    await settle();
    return (!ev.defaultPrevented && !dialog()) || 'held while paused';
  });
  check('master switch off: everything passes through', async () => {
    await withSettings({ enabled: false });
    const ev = paste($('ta'), KEY());
    await settle();
    return (!ev.defaultPrevented && !dialog()) || 'held while disabled';
  });
  check('turning a category off stops that rule', async () => {
    await withSettings({ categories: Object.assign(PG.settings.defaults().categories, { apiKey: false }) });
    const ev = paste($('ta'), KEY());
    await settle();
    return !ev.defaultPrevented || 'api keys still flagged';
  });
  check('quiet mode ignores medium-severity finds but still catches high ones', async () => {
    await withSettings({ mode: 'quiet' });
    const medium = paste($('ta'), 'Authorization: Bearer ' + rnd(40));
    await settle();
    if (medium.defaultPrevented) return 'quiet mode flagged a medium finding';
    const high = paste($('ta'), KEY());
    if (!high.defaultPrevented) return 'quiet mode missed a high finding';
    button('Cancel').click();
    await settle();
  });
  check('a custom pattern from settings is enforced', async () => {
    await withSettings({ customPatterns: [{ name: 'Project codename', pattern: 'PROJECT-[A-Z]{4}-\\d{3}' }] });
    const ev = paste($('ta'), 'ship PROJECT-ZEUS-042 soon');
    if (!ev.defaultPrevented) return 'not held';
    const shown = dialog().textContent;
    button('Redact and paste').click();
    await settle();
    return (/Project codename/.test(shown) && $('ta').value === 'ship [REDACTED:CUSTOM_1] soon') || 'value: ' + $('ta').value;
  });

  // --- files ---------------------------------------------------------------------------------------
  check('file with a secret: the page never sees it, "Don\'t attach" clears the input', async () => {
    chooseFile(fileOf('.env', envWithSecret()));
    await settle(120);
    if (fileChanges().length) return 'the page saw the file before the answer';
    if (!dialog() || !/GitHub token/.test(dialog().textContent)) return 'no dialog with the finding';
    button("Don't attach").click();
    await settle();
    return ($('file').files.length === 0 && fileChanges().length === 0) || 'files left: ' + $('file').files.length;
  });
  check('file with a secret: "Attach anyway" hands it to the page', async () => {
    chooseFile(fileOf('.env', envWithSecret()));
    await settle(120);
    button('Attach anyway').click();
    await settle(60);
    const c = fileChanges();
    return (c.length === 1 && c[0].files[0] === '.env') || 'page changes: ' + JSON.stringify(c);
  });
  check('a clean text file is released to the page after the scan', async () => {
    chooseFile(fileOf('notes.txt', 'just some notes\nnothing secret here\n', 'text/plain'));
    await settle(150);
    const c = fileChanges();
    return (!dialog() && c.length === 1 && c[0].files[0] === 'notes.txt') || 'dialog: ' + !!dialog();
  });
  check('an image is never touched or delayed', async () => {
    chooseFile(new File([new Uint8Array([137, 80, 78, 71, 0, 1, 2, 3])], 'photo.png', { type: 'image/png' }));
    return (fileChanges().length === 1 && !dialog()) || 'the page did not see it straight away';
  });
  check('a binary file named .txt is not misread as text', async () => {
    chooseFile(new File([new Uint8Array([0, 1, 2, 3, 0, 5])], 'blob.txt', { type: 'text/plain' }));
    await settle(150);
    return (fileChanges().length === 1 && !dialog()) || 'dialog: ' + !!dialog();
  });
  check('file scanning off: the file goes straight through', async () => {
    await withSettings({ scanFiles: false });
    chooseFile(fileOf('.env', envWithSecret()));
    await settle(60);
    return (fileChanges().length === 1 && !dialog()) || 'changes: ' + fileChanges().length;
  });
  check('dropping a file with a secret: held, then handed over on "Attach anyway"', async () => {
    const data = new DataTransfer();
    data.items.add(fileOf('prod.env', envWithSecret()));
    const ev = new DragEvent('drop', { dataTransfer: data, bubbles: true, cancelable: true, composed: true });
    $('drop').dispatchEvent(ev);
    await settle(120);
    if (!ev.defaultPrevented || !dialog()) return 'drop was not held';
    if (window.__log.some((e) => e.page === 'drop')) return 'the page saw the drop early';
    button('Attach anyway').click();
    await settle(60);
    const d = window.__log.filter((e) => e.page === 'drop');
    return (d.length === 1 && d[0].files[0] === 'prod.env') || 'drops: ' + JSON.stringify(d);
  });
  check('dropping text with a secret is held and can be redacted', async () => {
    const data = new DataTransfer();
    data.setData('text/plain', 'token ' + KEY());
    const ev = new DragEvent('drop', { dataTransfer: data, bubbles: true, cancelable: true, composed: true });
    $('ta').focus();
    $('ta').dispatchEvent(ev);
    if (!ev.defaultPrevented || !dialog()) return 'not held';
    button('Redact and paste').click();
    await settle();
    return $('ta').value === 'token [REDACTED:GITHUB_TOKEN]' || 'value: ' + $('ta').value;
  });

  // --- the typing warning (non-blocking) -----------------------------------------------------------------
  const live = () => shadow() && shadow().querySelector('.live');
  const liveButton = (label) => live() && [...live().querySelectorAll('button')].find((b) => b.textContent === label);
  function typeInto(el, text, extra) {
    if (el.tagName === 'TEXTAREA' || el.tagName === 'INPUT') el.value = text;
    else el.textContent = text;
    el.focus();
    el.dispatchEvent(new InputEvent('input', Object.assign({ bubbles: true, composed: true, inputType: 'insertText', data: text.slice(-1) }, extra)));
  }
  const LIVE_WAIT = 750;

  check('typing a secret shows a warning, without taking focus or blocking', async () => {
    const k = KEY();
    typeInto($('ta'), 'my key is ' + k + ' thanks');
    await settle(LIVE_WAIT);
    if (!live()) return 'no warning appeared';
    if (dialog()) return 'a blocking dialog appeared for typing';
    const text = live().textContent;
    if (text.includes(k)) return 'the warning shows the full secret';
    if (!/GitHub token in your message/.test(text) || !/ghp_…/.test(text)) return 'warning text: ' + text;
    if (document.activeElement !== $('ta')) return 'focus moved away from the box';
    const down = new MouseEvent('mousedown', { bubbles: true, cancelable: true });
    live().dispatchEvent(down);
    if (!down.defaultPrevented) return 'clicking the warning would take focus from the box';
    const r = live().getBoundingClientRect();
    if (r.left < 0 || r.top < 0 || r.right > window.innerWidth || r.bottom > window.innerHeight) return 'the warning is off screen';
  });
  check('Redact on the warning replaces the secret and keeps the rest', async () => {
    typeInto($('ta'), 'my key is ' + KEY() + ' thanks');
    await settle(LIVE_WAIT);
    liveButton('Redact').click();
    await settle();
    if ($('ta').value !== 'my key is [REDACTED:GITHUB_TOKEN] thanks') return 'got: ' + $('ta').value;
    return !live() || 'the warning stayed after redacting';
  });
  check('Dismiss hides it, and the same value does not come back, but a new secret does', async () => {
    const k = KEY();
    typeInto($('ta'), 'token ' + k);
    await settle(LIVE_WAIT);
    liveButton('Dismiss').click();
    await settle();
    if (live()) return 'still showing after Dismiss';
    typeInto($('ta'), 'token ' + k + ' and some more words');
    await settle(LIVE_WAIT);
    if (live()) return 'the same value was flagged again';
    typeInto($('ta'), 'token ' + k + ' ' + KEY2());
    await settle(LIVE_WAIT);
    return !!live() || 'a different secret was not flagged';
  });
  check('ordinary typing, including the word "token", never shows a warning', async () => {
    typeInto($('ta'), 'Can you explain how a token bucket rate limiter works? password: string, api_key = os.getenv("KEY")');
    await settle(LIVE_WAIT);
    return !live() || 'a warning appeared for ordinary text';
  });
  check('two secrets: the warning counts them', async () => {
    typeInto($('ta'), KEY() + ' ' + KEY2());
    await settle(LIVE_WAIT);
    return (live() && /2 sensitive items in your message/.test(live().textContent)) || 'text: ' + (live() && live().textContent);
  });
  check('works in a contenteditable box and in a rich editor that handles paste itself', async () => {
    typeInto($('ce'), 'a ' + KEY());
    await settle(LIVE_WAIT);
    if (!live()) return 'no warning in the contenteditable';
    liveButton('Redact').click();
    await idle();
    if ($('ce').textContent !== 'a [REDACTED:GITHUB_TOKEN]') return 'contenteditable has: ' + $('ce').textContent;
    typeInto($('rich'), 'b ' + KEY());
    await settle(LIVE_WAIT);
    if (!live()) return 'no warning in the rich editor';
    liveButton('Redact').click();
    await idle();
    if (window.__richPastes !== 1) return 'the rich editor handled ' + window.__richPastes + ' pastes';
    return $('rich').textContent === 'b [REDACTED:GITHUB_TOKEN]' || 'rich editor has: ' + $('rich').textContent;
  });
  check('Redact on the typing warning REPLACES the text in a rich editor (it must not append a second copy)', async () => {
    // The bug seen on a real ChatGPT box: the redacted copy was added after the original instead of replacing it.
    const secret = KEY();
    typeInto($('rich'), 'first line\nmy token is ' + secret + ' and some words after');
    await settle(LIVE_WAIT);
    if (!live()) return 'no warning in the rich editor';
    liveButton('Redact').click();
    await idle();
    const text = $('rich').textContent;
    if (text.includes(secret)) return 'the original secret is still in the box: ' + text;
    if ((text.match(/\[REDACTED:GITHUB_TOKEN\]/g) || []).length !== 1) return 'expected exactly one placeholder, got: ' + text;
    if (!/first line/.test(text) || !/and some words after/.test(text)) return 'the surrounding text was lost: ' + text;
    return !live() || 'the warning stayed';
  });
  check('Redact works on a multi-line message with several secrets in a rich editor', async () => {
    const a = KEY();
    const b = KEY2();
    typeInto($('rich'), 'line one ' + a + '\nline two\n' + b + ' end');
    await settle(LIVE_WAIT);
    liveButton('Redact').click();
    await idle();
    const text = $('rich').textContent;
    if (text.includes(a) || text.includes(b)) return 'a secret is still in the box: ' + text;
    return (/\[REDACTED:GITHUB_TOKEN\]/.test(text) && /\[REDACTED:AWS_ACCESS_KEY_ID\]/.test(text)) || 'got: ' + text;
  });
  check('"Paste anyway" is respected: no typing warning for what they chose to keep', async () => {
    paste($('ta'), KEY());
    button('Paste anyway').click();
    await settle(LIVE_WAIT);
    return !live() || 'the typing warning flagged a paste the person approved';
  });
  check('the warning goes away when the box is cleared (a sent message clears it silently)', async () => {
    typeInto($('ta'), KEY());
    await settle(LIVE_WAIT);
    if (!live()) return 'no warning';
    $('ta').value = ''; // no input event, like a chat site clearing the box after sending
    await settle(1400);
    return !live() || 'the warning stayed after the box was cleared';
  });
  check('the recheck timer does not re-show the warning or inflate the counter', async () => {
    typeInto($('ta'), KEY());
    await settle(LIVE_WAIT + 2300); // two or three recheck cycles
    const s = await store.getStats();
    return (s.warned === 1 && shadow().querySelectorAll('.live').length === 1) || 'warned: ' + s.warned + ', banners: ' + shadow().querySelectorAll('.live').length;
  });
  check('password fields and IME composition are never checked', async () => {
    const pw = document.createElement('input');
    pw.type = 'password';
    document.body.append(pw);
    typeInto(pw, KEY());
    await settle(LIVE_WAIT);
    pw.remove();
    if (live()) return 'a password field was checked';
    typeInto($('ta'), KEY(), { isComposing: true });
    await settle(LIVE_WAIT);
    return !live() || 'a composition event was checked';
  });
  check('switching the typing warning off, or pausing the site, silences it', async () => {
    await withSettings({ liveCheck: false });
    typeInto($('ta'), KEY());
    await settle(LIVE_WAIT);
    if (live()) return 'warned while switched off';
    await withSettings({ pausedHosts: [location.hostname] });
    typeInto($('ta'), KEY());
    await settle(LIVE_WAIT);
    return !live() || 'warned while paused';
  });
  check('turning it off while a warning is showing removes the warning', async () => {
    typeInto($('ta'), KEY());
    await settle(LIVE_WAIT);
    if (!live()) return 'no warning to begin with';
    await withSettings({ liveCheck: false });
    await settle(100);
    return !live() || 'the warning stayed after switching off';
  });
  check('the typing warning follows the sensitivity setting (quiet ignores medium finds)', async () => {
    await withSettings({ mode: 'quiet' });
    typeInto($('ta'), 'Authorization: Bearer ' + rnd(40));
    await settle(LIVE_WAIT);
    return !live() || 'quiet mode warned about a medium-severity find';
  });

  // --- privacy ---------------------------------------------------------------------------------------
  check('counters count events, and nothing secret is ever stored', async () => {
    paste($('ta'), KEY());
    button('Redact and paste').click();
    await settle(60);
    paste($('ta'), KEY());
    button('Paste anyway').click();
    await settle(60);
    paste($('ta'), KEY());
    button('Cancel').click();
    await settle(60);
    const s = await store.getStats();
    if (s.warned !== 3 || s.redacted !== 1 || s.pastedAnyway !== 1 || s.cancelled !== 1) return 'stats: ' + JSON.stringify(s);
    const stored = JSON.stringify(Object.entries(localStorage).filter(([key]) => key.startsWith('pgharness')));
    return !/ghp_[A-Za-z0-9]{36}/.test(stored) || 'a secret ended up in storage';
  });


  // --- sending: Enter and the Send button -------------------------------------------------------------------
  const sends = () => window.__log.filter((e) => e.page === 'send');
  const pressEnter = (el) => { el.focus(); const e = new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true, composed: true }); el.dispatchEvent(e); return e; };

  check('Enter with a secret in the box is held back: nothing is sent, a dialog asks', async () => {
    const k = KEY();
    $('chat').value = 'use ' + k;
    pressEnter($('chat'));
    await settle(80);
    if (sends().length) return 'the message was sent with the secret in it';
    if (!dialog()) return 'no dialog appeared';
    return /not been sent/i.test(dialog().textContent) || 'dialog text: ' + dialog().textContent.slice(0, 120);
  });

  check('Enter with a clean message sends normally and shows nothing', async () => {
    $('chat').value = 'what is the token limit for this model?';
    pressEnter($('chat'));
    await settle(80);
    return (sends().length === 1 && !dialog()) || 'sends: ' + sends().length + ', dialog: ' + !!dialog();
  });

  check('the Send button is held back too', async () => {
    $('chat').value = 'key ' + KEY();
    $('chat').focus();
    $('chat').dispatchEvent(new InputEvent('input', { bubbles: true, composed: true, inputType: 'insertText', data: 'x' }));
    $('sendbtn').click();
    await settle(80);
    return (!sends().length && !!dialog()) || 'sends: ' + sends().length + ', dialog: ' + !!dialog();
  });

  check('"Redact the message" edits the box, does not send, and a second Enter then sends the redacted text', async () => {
    const k = KEY();
    $('chat').value = 'use ' + k + ' now';
    pressEnter($('chat'));
    await settle(80);
    button('Redact the message').click();
    await idle();
    if (sends().length) return 'it sent on its own';
    if ($('chat').value.includes(k)) return 'the secret is still in the box';
    pressEnter($('chat'));
    await settle(80);
    if (sends().length !== 1) return 'second Enter did not send';
    return !JSON.stringify(window.__log).includes(k) || 'the secret reached the page';
  });

  check('"Keep it, let me send" lets the next Enter through, once chosen', async () => {
    const k = KEY();
    $('chat').value = 'use ' + k;
    pressEnter($('chat'));
    await settle(80);
    button('Keep it, let me send').click();
    await idle();
    if (sends().length) return 'it sent on its own';
    pressEnter($('chat'));
    await settle(80);
    return (sends().length === 1 && sends()[0].text.includes(k)) || 'sends: ' + sends().length;
  });

  check('Cancel on the send dialog leaves the box alone and sends nothing', async () => {
    const k = KEY();
    $('chat').value = 'use ' + k;
    pressEnter($('chat'));
    await settle(80);
    button('Cancel').click();
    await idle();
    return (!sends().length && $('chat').value.includes(k)) || 'box: ' + $('chat').value;
  });

  check('Shift+Enter, Enter during IME composition, and the setting switched off never hold anything', async () => {
    $('chat').value = 'use ' + KEY();
    $('chat').focus();
    $('chat').dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', shiftKey: true, bubbles: true, cancelable: true, composed: true }));
    $('chat').dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', isComposing: true, bubbles: true, cancelable: true, composed: true }));
    await settle(60);
    if (dialog()) return 'a dialog opened for Shift+Enter or composition';
    await withSettings({ sendGuard: false });
    pressEnter($('chat'));
    await settle(60);
    return (sends().length === 1 && !dialog()) || 'with the setting off, sends: ' + sends().length;
  });

  check('an unrelated button is not treated as Send', async () => {
    $('chat').value = 'use ' + KEY();
    $('chat').focus();
    $('run').click();
    await settle(60);
    return !dialog() || 'a dialog opened for the Run button';
  });

  check('in "block" mode a send with a secret is refused with a message, nothing is sent', async () => {
    await withSettings({ action: 'block' });
    $('chat').value = 'use ' + KEY();
    pressEnter($('chat'));
    await settle(80);
    return (!sends().length && /not sent/i.test(toastText() || '')) || 'sends: ' + sends().length + ', toast: ' + toastText();
  });

  window.runHarnessChecks = async function () {
    const results = [];
    for (const { name, fn } of checks) {
      await reset();
      try {
        const detail = await fn();
        results.push({ name, pass: detail === undefined || detail === true, detail: detail === true ? undefined : detail });
      } catch (error) {
        results.push({ name, pass: false, detail: 'threw: ' + error.message });
      }
    }
    await reset();
    return results;
  };
})();
