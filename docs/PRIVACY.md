# Privacy policy

**Paste Guard does not collect, store, transmit or share any personal data.** This page explains what that means in practice, so you can check it rather than take it on trust.

_Last updated: 2026-11-06_

## What Paste Guard reads

When you paste, drop or attach something on one of the supported chat sites, Paste Guard reads that text (or the start of that file) in your browser, to check it for secrets and personal data. With **Also warn while I type** on (it is on by default; you can switch it off in Settings), it also reads the text currently in the message box a moment after you change it, to show a warning if a secret appears there. It does not read other text on the page, and it ignores password fields. The check runs entirely on your device, inside the page, in the extension's own code.

## What leaves your device

**Nothing.** The extension contains no code that makes network requests: no `fetch`, no `XMLHttpRequest`, no WebSocket, no beacons, no analytics, no crash reporting, no remote configuration, no remote code. The automated tests fail if any of that is ever added (`test/privacy.test.js`). The extension also does not read the clipboard on its own: it only sees the text a paste or drop event hands it.

## What is stored

Paste Guard stores three things in your browser's extension storage, and nothing else:

| Stored | Where | What it contains |
| --- | --- | --- |
| Settings | `storage.sync` (follows your browser account if you use sync) | Your choices: sensitivity, what to do when something is found, which categories are on, paused sites, and any custom patterns you wrote. |
| Ignore list | `storage.local` (this device only) | A one-way SHA-256 fingerprint of each value you told it to ignore. The value itself is never stored. A fingerprint cannot be reversed, but for a short or guessable value (a card or ID number has relatively few possibilities) someone with access to your browser profile could test guesses against it. So only ignore values you are comfortable with that. |
| Counters | `storage.local` (this device only) | Five whole numbers: how many times it warned you, and what you chose. |

What you paste is never stored, logged or written anywhere, including when it contains a secret.

If you use a browser account with sync, your browser vendor syncs the **settings** (never the ignore list or counters) the way it syncs any extension's settings. That is done by the browser, not by Paste Guard.

## Permissions, and why

| Permission | Why it is needed |
| --- | --- |
| Run on the listed AI chat sites (`content_scripts` matches) | To see text before the page receives it. Only those sites are listed; there is no "all sites" access. |
| `storage` | To save your settings, ignore list and counters. |
| `activeTab` | So the toolbar popup can tell you whether the tab you are looking at is protected, only when you open it. |
| `scripting`, and optional access to a single site | Only used when you press **Protect this site** in the popup for a site that is not on the built-in list. Your browser then asks you for access to that one site, nothing is granted in advance, and **Stop protecting** removes it again. The site name is stored in your settings. |

There is no background process, no access you did not grant to a site, and no access to your browsing history, tabs list, cookies or downloads. Files you attach (including Word, Excel, PowerPoint and zip files) are opened and read inside your browser to check them; nothing is uploaded.

## The dialog

The warning dialog shows each finding as a short masked preview (for example the first four characters and the last two) and never the full secret. You can open "Show what will be pasted" to see the redacted text.

## Children, sale of data, third parties

Paste Guard is not directed at children. No data is sold, shared or disclosed to anyone, because none is collected. There are no third-party services.

## Changes

If this ever changes, this page and the changelog will say so, and a version that collected anything would need new permissions that the browser would ask you to approve.

## Contact

Questions or concerns: open an issue at https://github.com/chiranji-xt/pasteguard/issues
