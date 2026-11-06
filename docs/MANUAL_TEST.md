# Testing on the real sites

The automated tests cover the engine (200 tests) and the content script against a simulated page, including a rich editor that handles paste itself. What they cannot cover is each real site's own editor, which changes without notice. Before a release, and whenever a site seems to misbehave, run this checklist on the real sites.

## Set up

1. `npm run build`
2. **Chrome / Edge / Brave:** open `chrome://extensions`, switch on Developer mode, choose **Load unpacked**, select the `dist/chrome` folder. After a rebuild, press the reload icon on the extension.
3. **Firefox:** open `about:debugging#/runtime/this-firefox`, choose **Load Temporary Add-on**, select `dist/firefox/manifest.json`. (It is removed when Firefox closes.)
4. Open the extension's **Settings** and use **Try it → Fill with an example** to get a block of made-up secrets. Copy that text.

> Only ever test with made-up secrets. The example generator makes strings that match real key formats but belong to nothing.

## For each site (ChatGPT, Claude, Gemini, Copilot, Perplexity, Grok, DeepSeek, ...)

Do these in the site's normal message box. Tick them off in the release notes.

| # | Do this | Expect |
| --- | --- | --- |
| 1 | Paste ordinary text ("hello, can you help me with a recipe?") | Pastes normally. No dialog. |
| 2 | Paste the example block | The dialog appears, listing 4 items, **before** anything shows in the box. |
| 3 | Press **Redact and paste** | The box contains the text with `[REDACTED:...]` placeholders, once (not twice). The cursor is at the end. |
| 4 | Press Enter to send that message | The site accepts it as normal (the box is not "empty" or stuck). |
| 5 | Paste the example block again, press **Cancel** | Nothing is inserted. Focus is back in the box. |
| 6 | Paste it, tick **This is fine** on one item, **Redact and paste**; paste the same block again | That one item is no longer flagged. |
| 7 | Type some words, select two of them, paste the example, **Redact and paste** | Only the selected words are replaced. |
| 8 | Paste the example while the message box is empty, then press **Ctrl+Z** (or Cmd+Z) | The site's undo behaves normally. |
| 9 | Click the paperclip, choose a `.env` file containing a made-up key | The dialog appears. **Don't attach** leaves the site with no file. |
| 10 | Same, choose **Attach anyway** | The file attaches normally. |
| 11 | Attach a normal image | Attaches immediately, with no delay and no dialog. |
| 12 | Drag the example text into the box | The dialog appears. |
| 13 | Open the toolbar popup | Says "Protecting <site>". **Pause** then paste the example: it pastes straight through. |
| 14 | Resume, then **type** a made-up key by hand in the box (copy one from the example block and type it, or pause, paste it, resume, and add a letter) | After a moment a small banner appears next to the box naming it. Your typing is not interrupted and focus stays in the box. |
| 15 | Press **Redact** on that banner | The secret is replaced by a `[REDACTED:...]` label, **the original is gone** (not left in the box with the redacted copy added after it), the rest of your text is intact, and the banner goes away. Allow about a quarter of a second. |
| 16 | Type a secret again, then send the message (Enter) | The banner disappears once the box clears. |
| 17 | Paste the example, choose **Paste anyway**, then keep typing | No banner for the value you chose to keep. |

If a step fails, note the site, browser and version, and which step. Do **not** paste a real secret into a bug report; the example block reproduces it.

## Firefox-specific

Steps 3, 4, 9 and 10 are the likeliest to differ: Firefox handles events created by extensions differently. If the text appears twice or not at all, or a file does not attach after **Attach anyway**, that is a bug worth reporting.

## The simulated page

`npm run harness` serves a page that loads the real scripts. Press **Run all checks** to run 48 checks in about half a minute (the typing checks wait for the short delay). Run this first; if it fails, nothing on a real site will work.
