## What and why

<!-- What does this change do, and what problem does it solve? Link the issue: "Fixes #123". -->

## How it was tested

<!-- Commands you ran, on which system and browser, and what they showed. A behavior change comes with a test that fails without it. -->

## Checklist

- [ ] `cargo test` passes; platform code was checked on both Windows and Linux (CI runs both).
- [ ] `cd extension && npm test` passes, and `node scripts/verify-community-package.mjs` after `node extension/build-editions.js`.
- [ ] Input from the browser, the network or another process is bounded and validated.
- [ ] No real names, customer names, credentials or personal data anywhere (code, tests, fixtures, comments).
- [ ] New dependencies, if any, are pinned to an exact version.
- [ ] Commits are signed off (`git commit -s`), see CONTRIBUTING.md.
