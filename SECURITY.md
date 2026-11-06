# Security policy

## Reporting a vulnerability

Please report security problems privately, using GitHub's **Report a vulnerability** button on the repository's Security tab, rather than a public issue. You should get a reply within a few days.

## What counts

Worth reporting privately:

- A way for a web page to read, change or dismiss Paste Guard's dialog, or to read what it is checking.
- A way for the extension to send data off the device, or to store a pasted value.
- A way for crafted clipboard text, a file name or a file's contents to run code, inject HTML, or freeze the page (a regular expression that takes unreasonable time on some input is a real bug here: please send the input's shape).
- A permission or manifest change that widens what the extension can access.

Not a vulnerability, but very welcome as an ordinary issue: a secret format that is not detected, a false positive, or a site where it does not work. Paste Guard is a safety net, not a guarantee, and it says so.

## Design choices that matter for security

- No network code, no `eval`, no `innerHTML`, no background process, and a minimal permission set, enforced by `test/privacy.test.js` on every change.
- The dialog lives in a closed Shadow DOM. Pasted text is only ever set with `textContent`.
- Only a one-way hash of an ignored value is stored, never the value (see [docs/PRIVACY.md](docs/PRIVACY.md) for the caveat on guessable values).
