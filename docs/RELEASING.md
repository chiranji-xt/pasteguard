# Releasing

## Each release

1. Make sure `main` is green in CI and `npm test` passes locally.
2. Run `npm run harness` and press **Run all checks**. Then go through [MANUAL_TEST.md](MANUAL_TEST.md) on at least ChatGPT and Claude in Chrome and one site in Firefox.
3. Update the version in `package.json` (the manifests take it from there) and add a section to `CHANGELOG.md`.
4. Commit, then tag and push the tag. The tag must match the version:

   ```sh
   git tag v0.1.0
   git push origin v0.1.0
   ```

   The **Release** workflow runs the tests, builds both packages and creates a GitHub release with the two zips attached.
5. Upload the same zips to the stores (below). They are built reproducibly: the same source always produces the same zip.

## Chrome Web Store (also covers Edge and Brave users)

1. Create a developer account at the [Chrome Web Store developer dashboard](https://chrome.google.com/webstore/devconsole) (one-time registration fee).
2. **New item**, upload `pasteguard-chrome-<version>.zip`.
3. Fill in the listing from [STORE_LISTING.md](STORE_LISTING.md): description, category, screenshots, privacy policy URL, single purpose, and a justification for each permission.
4. Submit for review. Reviews of extensions that run on specific sites with no network access are usually quick, but can take days.

## Firefox Add-ons (AMO)

1. Sign in at [addons.mozilla.org/developers](https://addons.mozilla.org/developers/).
2. **Submit a new add-on**, upload `pasteguard-firefox-<version>.zip`, choose **On this site** (listed).
3. The add-on id is `pasteguard@chiranji-xt` (in `scripts/build.js`). It must never change once published.
4. Because there is no bundler or minification, you do not need to submit source separately: the zip *is* the source. Say so in the notes to the reviewer.
5. The manifest declares `data_collection_permissions: none`, matching [PRIVACY.md](PRIVACY.md).

## Microsoft Edge Add-ons (optional)

Upload the Chrome zip at [Partner Center](https://partner.microsoft.com/dashboard/microsoftedge/overview). Same listing text.

## After publishing

Put the store links in the README's Install section and remove the "not in the stores yet" wording.
