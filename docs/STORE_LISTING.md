# Store listing

Text to paste into the Chrome Web Store and Firefox Add-ons submission forms. Edit freely.

## Name

Paste Guard

## Summary (132 characters at most)

Stops API keys, passwords and personal data from being pasted into AI chats. Checked on your device; nothing is sent anywhere.

## Category

Chrome Web Store: Developer Tools. Firefox Add-ons: Privacy & Security.

## Description

Ever pasted a config file into ChatGPT and then realised it had your API key in it? Paste Guard catches that before it happens.

When you paste text, drop text, or attach a file on a supported AI chat site, Paste Guard checks it first. If it finds a secret or personal data, it holds the paste back and shows you what it found. You choose: redact it, paste anyway, or cancel.

WHAT IT CATCHES
- API keys: OpenAI, Anthropic, Google, AWS, GitHub, GitLab, Stripe, Slack, Hugging Face and many more
- Private keys (SSH, TLS, PGP)
- Passwords in code, config files and database URLs
- JWTs and Bearer / Basic auth headers
- Card numbers (checked with the card checksum, so random numbers do not trigger it) and IBANs
- US Social Security, Indian Aadhaar and PAN numbers
- Your own patterns, for things only you know about (a project codename, an internal hostname)

REDACT, DON'T JUST BLOCK
"Redact and paste" replaces each secret with a label such as [REDACTED:OPENAI_API_KEY], so you can still ask your question and the AI still understands what was there.

WARNS WHILE YOU TYPE, TOO
If a secret ends up in the message box without a paste (typed, dictated or autofilled), a small banner appears with a one-click Redact. It never blocks or interrupts your typing.

QUIET WHEN IT SHOULD BE
Ordinary text is never touched. Example values, placeholders like <your-token> or ${API_KEY}, and test card numbers from payment docs are ignored. You can tell it to ignore any value it flags by mistake.

PRIVATE BY DESIGN
- Everything is checked on your device. The extension has no code that sends data anywhere.
- It asks for no access to all sites, your tabs, history or cookies. Only the AI chat sites it protects.
- What you paste is never stored or logged.
- Open source (MIT). Read exactly what it does.

WORKS WITH
ChatGPT, Claude, Gemini, Google AI Studio, Microsoft Copilot, Perplexity, Grok, DeepSeek, Mistral Le Chat, Poe, Hugging Chat, Meta AI, Qwen Chat, T3 Chat, OpenRouter, OpenAI Platform and Anthropic Console.

LIMITS
Paste Guard blocks what you paste, drop or attach. Text you type by hand can only get a warning (a small banner with a one-click Redact), and it cannot read text inside images or PDFs. It is a safety net, not a guarantee.

## Single purpose (Chrome Web Store asks for this)

Detect and redact secrets and personal data in text before it is pasted into AI chat websites.

## Permission justifications (Chrome Web Store asks for each)

- **Content script on the listed sites:** Reads the text of paste, drop and file-attach events, and (unless switched off) the text in the message box as the user types, on the listed AI chat sites so it can be checked for secrets. All processing is local; nothing is transmitted.
- **storage:** Saves the user's settings, the list of values they chose to ignore (as one-way hashes), and five usage counters. No pasted content is stored.
- **activeTab:** Lets the toolbar popup show whether the current tab is a protected site, only when the user opens the popup.

## Data disclosures (Chrome Web Store "Privacy practices" tab)

Collects: none. Certify: not sold, not used for unrelated purposes, not used for creditworthiness. Privacy policy URL: https://github.com/chiranji-xt/pasteguard/blob/main/docs/PRIVACY.md

Firefox: `data_collection_permissions` is declared as `none` in the manifest.

## Assets to prepare

| Asset | Size | Notes |
| --- | --- | --- |
| Store icon | 128×128 | `src/icons/icon-128.png` (done) |
| Screenshots (1 to 5) | 1280×800 | Take these from the harness (`npm run harness`): 1) the dialog with 3 findings, light mode; 2) the same in dark mode; 3) the "show what will be pasted" preview open; 4) the Settings "Try it" playground; 5) the toolbar popup on a protected site. |
| Small promo tile (optional) | 440×280 | Icon plus "Stop pasting secrets into AI chats". |
| Short demo GIF for the repo | ~900px wide | See `docs/demo-plan.md`. |
