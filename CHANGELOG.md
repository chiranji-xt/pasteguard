# Changelog

## 0.1.0 (unreleased)

First version.

- Checks text you **paste or drop**, and files you **attach**, on 17 AI chat sites (ChatGPT, Claude, Gemini, Copilot, Perplexity, Grok, DeepSeek and more). Ordinary text is never touched.
- About 45 detection rules: provider API keys, private keys, JWT / Bearer / Basic tokens, passwords and secrets in code and URLs, card numbers (Luhn), IBANs, US SSN, Indian Aadhaar (Verhoeff) and PAN. Emails, phone numbers and random-looking strings are available but off by default.
- Built to stay quiet: placeholders, documentation examples, public test card numbers, code references like `process.env.KEY`, and metadata like `token_type` are ignored.
- A warning dialog (closed Shadow DOM, light and dark, keyboard and screen-reader friendly) with **Redact and paste**, **Paste anyway** and **Cancel**, a masked preview of every finding, a preview of the redacted text, and a per-value "this is fine".
- Works in plain inputs, `contenteditable` boxes and rich editors that handle paste themselves, without inserting text twice.
- Settings: three sensitivity levels, ask / redact automatically / block, per-category switches, file scanning, custom patterns (with a guard against patterns that could freeze the page), per-site pause, a live "Try it" playground, counters, and settings export and import.
- Chrome, Edge, Brave and Firefox builds from one source. No dependencies and no build step.
- Privacy by construction: no network code, no `eval`, no `innerHTML`, minimal permissions, all enforced by tests.
