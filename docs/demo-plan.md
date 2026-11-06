# Demo GIF plan

One GIF at the top of the README. It must show the whole point in about ten seconds, with no sound and no reading beyond the dialog.

**The story:** you paste a config file into a chat box, Paste Guard stops it and shows what it found, you press "Redact and paste", and the chat box now holds the same text with the secrets labelled.

## Storyboard (about 10 s)

| Time | What happens | What the viewer sees |
| --- | --- | --- |
| 0:00 to 0:02 | An editor or terminal window with a short `.env` file; select all, copy. (Use the example from Settings → Try it → "Fill with an example"; those secrets are made up.) | The file, with an obvious `OPENAI_API_KEY=sk-proj-...` line. |
| 0:02 to 0:03 | Click into the chat box of a real chat site (Claude or ChatGPT) and press Ctrl+V. | The box stays empty. |
| 0:03 to 0:06 | The dialog appears. Hold for two seconds. | "Paste Guard found 3 sensitive items", each with a masked preview. |
| 0:06 to 0:07 | Click **Show what will be pasted if you redact**. | Highlighted `[REDACTED:...]` labels. |
| 0:07 to 0:09 | Click **Redact and paste**. | The chat box now holds the redacted text. |
| 0:09 to 0:10 | Hold. | The finished box. |

## Capture

- Windows: ScreenToGif (free). Record a 1280×720 region at 12 fps. Cut hesitation frames.
- Use the browser's dark or light mode consistently; both are supported.
- Crop out bookmarks, extensions, profile pictures and anything personal. Use a throwaway chat, and never a real key: the example generator makes safe ones.
- Optimise: `gifsicle -O3 --lossy=80 --colors 128 in.gif -o docs/demo.gif`. Aim for under 4 MB.
- Add to the README under the tagline: `![Paste Guard stopping a paste that contains API keys](docs/demo.gif)`

## A second asset worth making

A 1280×800 still of the dialog for the store listing (see [STORE_LISTING.md](STORE_LISTING.md)). The harness page (`npm run harness`) is the easiest place to take it: it has no personal data on screen.
