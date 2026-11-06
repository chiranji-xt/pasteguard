## What this changes

## Checklist

- [ ] `npm test` passes
- [ ] No real secret anywhere: test samples are built at run time (see CONTRIBUTING.md)
- [ ] New or changed rule: has positive **and** negative examples, and I ran `npm run audit -- <a big repo>` and handled what it flagged
- [ ] Changed `src/content/`: ran `npm run harness` and **Run all checks**
- [ ] No network code, `eval`, `innerHTML` or new permissions (`test/privacy.test.js` checks this)
