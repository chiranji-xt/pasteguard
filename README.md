# Paste Guard

**Stop pasting secrets into AI chats.**

A browser extension that checks what you paste, drop or attach on ChatGPT, Claude, Gemini and other AI chat sites. If it finds an API key, password, private key or personal ID, it holds the paste back and shows you what it found. You choose: **redact it**, paste anyway, or cancel.

Everything is checked on your device. The extension has no code that can send data anywhere, and the tests enforce that.

```
 ┌───────────────────────────────────────────────────────────┐
 │ !  Paste Guard found 3 sensitive items                    │
 │    Nothing has been pasted yet. This check ran on your    │
 │    device and nothing was sent anywhere.                  │
 │                                                           │
 │ ● OpenAI-style API key   sk-p…w6 (98 chars)               │
 │ ● Password in a URL      0r…bu (16 chars)                 │
 │ ● GitHub token           ghp_…V6 (40 chars)               │
 │                                                           │
 │ ▸ Show what will be pasted if you redact                  │
 │                                                           │
 │         [ Redact and paste ]  [ Paste anyway ]  [ Cancel ]│
 └───────────────────────────────────────────────────────────┘
```

"Redact and paste" replaces each secret with a label, so you can still ask your question and the AI still knows what was there:

```
OPENAI_API_KEY=[REDACTED:OPENAI_API_KEY]
DATABASE_URL=postgres://app:[REDACTED:URL_CREDENTIALS]@db.internal:5432/app
GITHUB_TOKEN=[REDACTED:GITHUB_TOKEN]
```

It also watches the message box as you type. If a secret shows up there (typed, dictated or autofilled), a small banner appears next to the box with a one-click **Redact**. It never blocks or interrupts typing:

```
 ┌──────────────────────────────────────────────────────────┐
 │ ! GitHub token in your message  ghp_…Ez (40 chars)       │
 │                                  [ Redact ]  [ Dismiss ] │
 └──────────────────────────────────────────────────────────┘
```

## Status

**Version 0.1.0.** The detection engine and the extension are complete and tested, but it is not in the Chrome Web Store or Firefox Add-ons yet, and it has not been tried on every real site. What has been verified, and what has not:

| | |
| --- | --- |
| Detection engine | 210 automated tests, including a corpus of innocent text that must stay silent, worst-case timing, and an audit against real code (the Python standard library, npm, installed packages). |
| Content script | 48 checks in a real browser against a simulated page, including a rich editor that handles paste itself and (like ProseMirror) is slow to notice a new selection, plus a randomized stress run of the Redact button (30 of 30 across 0, 100 and 250 ms of editor lag). |
| Options page and popup | Exercised in a real browser: every control, every state. |
| **Real chat sites** | **ChatGPT, verified by hand:** paste and redact on a 16-case block of tricky made-up secrets (every one redacted, inserted once); 15 lookalikes stayed silent; the typing banner appears without taking focus. Testing found one real bug there (the banner's Redact appended a second copy instead of replacing the text, because the editor learns about a new selection late), now fixed and covered by tests, **awaiting a retest on the real site**. Other sites and Firefox are not yet verified. Each site's editor can change without notice. [docs/MANUAL_TEST.md](docs/MANUAL_TEST.md) is the checklist. Please report anything that misbehaves. |
| Firefox | Built and linted in CI, but needs real-world testing. |

## Install

Not in the stores yet, so for now install it from source (it takes a minute, needs [Node.js](https://nodejs.org) 20 or newer, and has no dependencies to download).

```sh
git clone https://github.com/chiranji-xt/pasteguard.git
cd pasteguard
npm run build
```

**Chrome, Edge, Brave:** open `chrome://extensions`, turn on **Developer mode**, choose **Load unpacked**, and select the `dist/chrome` folder.

**Firefox:** open `about:debugging#/runtime/this-firefox`, choose **Load Temporary Add-on**, and select `dist/firefox/manifest.json`. (Firefox removes temporary add-ons when it closes.)

Then open the extension's **Settings** and try the **Try it** box.

## What it catches

| Category | Examples | On by default |
| --- | --- | --- |
| API keys | 36 provider formats, including OpenAI, Anthropic, Google, AWS, GitHub, GitLab, Stripe, Slack, Hugging Face, Groq, npm, PyPI, SendGrid and Twilio | yes |
| Private keys | SSH, TLS, PGP | yes |
| Tokens | JWTs, `Authorization: Bearer ...`, Basic auth | yes |
| Passwords and secrets | `password = "..."`, `DB_PASS=`, `SESSION_KEY=`, database URLs with a password, `?api_key=...` in a URL, `curl -u user:pass`, `docker login -p`, `mysql -ppass`, `.netrc` entries | yes |
| Card and bank numbers | Cards (issuer + length + Luhn checksum), IBANs (mod-97) | yes |
| Government IDs | US Social Security, Indian Aadhaar (Verhoeff checksum), PAN | yes |
| Email addresses, phone numbers | | no (you paste these on purpose) |
| Random-looking strings | any long high-entropy string | no (noisy) |
| **Your own patterns** | a project codename, an internal hostname | when you add them |

It is built to stay quiet: placeholders (`<your-token>`, `${API_KEY}`, `changeme`), documentation examples (`AKIAIOSFODNN7EXAMPLE`), test card numbers from payment docs, code that merely *refers* to a secret (`process.env.API_KEY`, `os.getenv(...)`), and metadata like `token_type = 'bearer'` are all ignored. There are three sensitivity levels, per-category switches, and a per-value "this is fine" button.

## Privacy, and how to check it

- **No network code.** No `fetch`, `XMLHttpRequest`, WebSocket or beacon anywhere. No analytics, no telemetry.
- **Minimal permissions.** It runs only on the listed chat sites (no "all sites" access), plus `storage` and `activeTab`. No background process, no access to your tabs, history or cookies.
- **Nothing you paste is stored**, including when it contains a secret. It keeps your settings, one-way fingerprints of values you chose to ignore, and five counters.
- **No `eval`, no `innerHTML`.** Nothing from the clipboard is ever turned into HTML or code.
- **The dialog never shows a full secret**, only a short masked preview.

These are not promises to take on trust: `npm test` runs [`test/privacy.test.js`](test/privacy.test.js), which fails if any of them stops being true. There is no build step or bundler, so the files in `src/` are exactly what ships. The full policy is in [docs/PRIVACY.md](docs/PRIVACY.md).

## What it does not do

It is a safety net, not a guarantee. These are the cases it leaves, found by probing it with realistic leaks and written down so nobody is surprised.

**Secrets it cannot recognise** (detection is pattern-based):

- **A secret with no shape**: a password in a plain sentence ("my password is Tr0ub4dor&3"), one in a table cell, or a `login / password` line.
- **A bare random string with no label**: a 32-character hex key, a UUID used as an API key, or any unlabelled random token. The *Random-looking strings* setting finds some of these, but it is off by default because it is noisy.
- **Deliberately disguised secrets**: reversed, base64- or percent-encoded, spaces between the characters, or a token split across lines (for example hard-wrapped by a terminal). Zero-width characters inside a token *are* handled.
- **Personal data beyond IDs**: names, addresses, health or legal text. Email addresses and phone numbers are found, but are off by default because people paste them on purpose.
- **A 12-digit Aadhaar number written without spaces and without the word "Aadhaar"**, because that is indistinguishable from any other 12-digit number.

**Places it cannot look:**

- **Only the [listed sites](src/shared/sites.js).** Not desktop or phone apps, editor chat panels, command-line tools, or a chat widget embedded in another site (it does not run inside iframes). Adding a site is a one-line change.
- **Files it cannot read as text**: images, PDFs, Word and Excel files, zip archives. It reads plain-text-like files only, and at most the first 2 MB of a file or paste.
- **A secret pasted in two halves**: each half alone looks harmless.
- **A site that reads the clipboard itself** from its own "Paste" button, or opens files through the browser's newer file-picker API, never fires the events Paste Guard listens for.

**By design:**

- It **blocks** what you paste, drop or attach. What you type, dictate or have autofilled can only get a **warning** (the banner with a one-click Redact), because holding back every keystroke would make the box unusable. If you send a message in the half second before the banner appears, or dismiss it, it is not stopped.
- **Paste anyway**, the per-value ignore, pausing a site and turning a category off are all your choice, and all mean the secret goes through.

Rare lookalikes can also be flagged by mistake. The ignore button and the sensitivity setting are there for that.

## How it works

```
 paste / drop / file chosen
          │
          ▼
 content script (window capture, runs before the page's own handlers)
          │
          ├── nothing found ──────────► the browser's own paste goes ahead, untouched
          │
          └── something found ─► hold the event ─► dialog (Shadow DOM, closed)
                                                        │
                       redact ◄─────────────────────────┤──► paste anyway ──► insert original
                         │                              └──► cancel
                         ▼
        insert the redacted text the way the page expects:
        its own paste handler first (rich editors), then the browser's
        insertText command, then writing the value directly
        (each step is skipped if an earlier one worked, so nothing is inserted twice)
```

While you type, a short delay after each change the message box is scanned the same way. If something is found, the banner above appears; it takes no focus, goes away when the box is cleared (for example after sending), and does not nag about a value you dismissed or chose to paste anyway.

The engine ([`src/engine`](src/engine)) is plain data and pure functions: rules in `rules.js`, checksums in `validators.js`, scanning and redaction in `detect.js`.

## Develop

```sh
npm test            # 210 unit tests, no dependencies
npm run build       # dist/chrome and dist/firefox
npm run package     # also writes the store zips
npm run harness     # a local page to try it, with "Run all checks" (48 browser checks)
npm run audit -- <folder>   # scan real code for false positives
```

### Add a detection rule

A rule is a few lines of data in [`src/engine/rules.js`](src/engine/rules.js) plus examples in [`test/fixtures.js`](test/fixtures.js). The tests refuse a rule without both a positive and a negative example. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
