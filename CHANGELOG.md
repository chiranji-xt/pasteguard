# Changelog

## 0.1.0 (unreleased)

First version.

- Checks text you **paste or drop**, and files you **attach**, on 17 AI chat sites (ChatGPT, Claude, Gemini, Copilot, Perplexity, Grok, DeepSeek and more). Ordinary text is never touched.
- 53 detection rules (36 provider key formats), including credentials in URL query strings (`?api_key=...`): provider API keys, private keys, JWT / Bearer / Basic tokens, passwords and secrets in code and URLs, card numbers (Luhn), IBANs, US SSN, Indian Aadhaar (Verhoeff) and PAN. Emails, phone numbers and random-looking strings are available but off by default.
- Built to stay quiet: placeholders, documentation examples, public test card numbers, code references like `process.env.KEY`, and metadata like `token_type` are ignored.
- A warning dialog (closed Shadow DOM, light and dark, keyboard and screen-reader friendly) with **Redact and paste**, **Paste anyway** and **Cancel**, a masked preview of every finding, a preview of the redacted text, and a per-value "this is fine".
- **Warns while you type**: if a secret appears in the message box without a paste (typed, dictated, autofilled), a non-blocking banner with a one-click Redact appears. It takes no focus, ignores password fields and IME composition, goes away when the box is cleared, and does not re-flag values you dismissed or chose to paste anyway. Switch it off in Settings.
- The typing warning's **Redact** replaces the box's contents reliably in rich editors such as ChatGPT's. Rich editors learn about a new selection a moment late, so selecting everything and inserting at once appended a second copy and left the secret in place. Redact now waits for the editor, empties the box with the browser's own delete, inserts, and then checks that the secret is really gone, trying other methods and finally telling you if it cannot.
- Works in plain inputs, `contenteditable` boxes and rich editors that handle paste themselves, without inserting text twice.
- Settings: three sensitivity levels, ask / redact automatically / block, per-category switches, file scanning, custom patterns (with a guard against patterns that could freeze the page), per-site pause, a live "Try it" playground, counters, and settings export and import.
- Chrome, Edge, Brave and Firefox builds from one source. No dependencies and no build step.
- Privacy by construction: no network code, no `eval`, no `innerHTML`, minimal permissions, all enforced by tests.
