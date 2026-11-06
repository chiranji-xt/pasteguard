# Contributing

Thank you. The most useful contributions are **new detection rules**, **false-positive reports**, and **real-site bug reports**.

## Setup

You need Node.js 20 or newer. There are no dependencies to install.

```sh
git clone https://github.com/chiranji-xt/pasteguard.git
cd pasteguard
npm test
```

## Never put a real secret anywhere

Not in an issue, a pull request, a test or a comment. If you hit a bug with a real secret, describe its *shape* ("`sk-` followed by 48 letters and digits") and use a made-up one.

This also matters mechanically: **GitHub's push protection blocks commits that contain strings shaped like real keys**, and a project full of sample secrets would trip it constantly. So test samples are never written out as literals. They are built at run time from a fixed prefix plus a seeded random body (see `test/fixtures.js`). Follow that pattern: `'gh' + 'p_' + rand(36, 'alnum', 27)`, not a pasted token.

## Add a detection rule

1. Add an entry to `rules` in [`src/engine/rules.js`](src/engine/rules.js). The comment at the top of that file explains every field. For a provider key with a fixed prefix it is one line using the `apiKey(...)` helper.
2. Add examples for it in [`test/fixtures.js`](test/fixtures.js): at least one **positive** (must be found) and one **negative** (must not be found by that rule). The tests fail if either is missing.
3. Think about false positives. Prefer a distinctive prefix and a fixed length. Use `validate` to cut lookalikes: checksums, "is this a placeholder", "is this a reference to a secret rather than the secret". A rule that fires on ordinary code or prose will get the extension uninstalled, so be strict.
4. Run `npm test`.
5. Run the audit on some real code you have and look at what it flags:

   ```sh
   npm run audit -- path/to/a/big/repo medium
   ```

   Anything that is not a genuine secret is a false positive: fix the rule, and add the case to the negatives so it stays fixed.

## Report a false positive

Open an issue using the **False positive** template. Say which rule fired (the label in the dialog, or the Settings → Try it box) and describe the *shape* of the text, not the text. If the text is public (documentation, an open-source repo), a link is ideal.

## Report a site that misbehaves

Open an issue using the **Bug** template. Include the site, browser and version, and which step of [docs/MANUAL_TEST.md](docs/MANUAL_TEST.md) failed.

## Code style

- Plain JavaScript, no build step, no dependencies. The files in `src/` are what ships.
- The extension must not gain network code, `eval`, `innerHTML` or extra permissions. `test/privacy.test.js` enforces it. If you believe a change needs one of them, open an issue first.
- Keep comments to the *why*. Keep dialog and settings text short and in plain English.

## Before you open a pull request

- `npm test` passes.
- If you changed anything in `src/content/`, run `npm run harness`, open the printed address and press **Run all checks**.
- If you changed rules, you ran the audit and added the false positives you found.
