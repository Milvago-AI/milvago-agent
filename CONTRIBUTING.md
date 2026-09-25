# Contributing

Thanks for helping. Before a large change, say hello on the
[Milvago AI Discord](https://discord.gg/69JPyVjqv) or open an issue: agreeing on the approach
first saves everyone a rewrite. Everyone taking part follows the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Licensing of contributions

A contribution is accepted under the Apache License 2.0, the license of this repository.
Copyright holder: Milvago AI, LLC. Sign your commits off (`git commit -s`), which states that
you have the right to submit the work under that license — the
[Developer Certificate of Origin](https://developercertificate.org/).

## Before opening a pull request

Run what your change touches, on the platform it affects:

```
cargo test
cargo test --manifest-path browser-engine/Cargo.toml
cd extension && npm ci && npm test
node extension/build-editions.js && node scripts/verify-community-package.mjs
```

Windows and Linux do not compile the same code (`#[cfg(windows)]` / `#[cfg(unix)]`): CI runs
both, and a change to platform code is only done when both are green.

A pull request that changes behavior comes with a test that fails without it. A test whose
only proof is a zero exit code proves nothing: assert on what the code actually produced.

## Editing conventions

- Comments explain *why*, in English; the code says *what*.
- The agent runs with high privileges on managed machines: any input from the browser, the
  network or a local process is untrusted. Bound sizes, validate before use, never panic on
  hostile input.
- The extension is the same source for Chromium and Firefox; `extension/build-editions.js`
  assembles both. Never edit the generated `extension-*` directories.
- Dependencies are pinned to exact versions (`=x.y.z` in Cargo, exact versions in npm).
- No real names, customer names, credentials or personal data anywhere: code, tests, fixtures,
  comments.

## Reporting bugs

Open an issue with the version or commit, the system and browser, what you did, what happened
and what you expected. For anything with a security dimension, follow `SECURITY.md` instead.
