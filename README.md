<p align="center">
  <img src=".github/assets/milvago-github-banner-v1.png" alt="Milvago">
</p>

<h3 align="center">The endpoint side of Milvago: a local agent and its browser extension.</h3>

<p align="center">
  Where AI usage actually happens — in the browser — Milvago sees it, applies your policy,
  and masks sensitive data <em>before</em> it leaves the machine.
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-18181B"></a>
  <img alt="Rust 1.94" src="https://img.shields.io/badge/Rust-1.94-B7410E">
  <img alt="Windows and Linux" src="https://img.shields.io/badge/platforms-Windows%20%C2%B7%20Linux-18181B">
  <img alt="Browsers" src="https://img.shields.io/badge/browsers-Chrome%20%C2%B7%20Edge%20%C2%B7%20Brave%20%C2%B7%20Vivaldi%20%C2%B7%20Arc%20%C2%B7%20Firefox-18181B">
  <a href="https://discord.gg/69JPyVjqv"><img alt="Discord" src="https://img.shields.io/badge/Discord-join%20the%20community-5865F2?logo=discord&logoColor=white"></a>
</p>

---

This repository holds the **Community edition** of the Milvago endpoint: the browser
extension that observes AI usage, and the Rust agent that runs on the machine next to it.
They report to a [Milvago server](https://github.com/Milvago-AI/milvago-server), which holds
the policy and the console.

## What it does

**In the browser (the extension)**

- **Presence** — recognizes the AI platforms listed in the signed detection catalogue and
  reports that one was reached, without reading the page.
- **Capture** on ChatGPT and Claude — prompts, responses, the model that answered, attached
  file names.
- **Masking before sending** — the organization's masking rules replace sensitive values in
  the prompt itself, in the browser, before the request reaches the provider.
- **Upload blocking** on the upload routes measured for each covered site.

**On the machine (the agent)**

- **Holds the signed policy and catalogue** and refuses any that does not verify (Ed25519).
- **Queues events durably and encrypted** while the server is unreachable, and delivers them
  when it is back.
- **Brokers the extension** over a local channel: the extension never talks to the server
  with its own credentials.
- **Updates itself** from signed release manifests only, with a key-rotation anchor.

Supported browsers: Google Chrome, Microsoft Edge, Brave, Vivaldi, Arc and Mozilla Firefox.
Supported systems: Windows and Linux.

## Building

Requirements: Rust 1.94 and Node.js 26.

```bash
# Agent and helpers (milvago-browser-agent, milvago-relay, milvago-updater)
cargo build --release
cargo test

# Browser extension: tests, then the unpacked Community packages
cd extension && npm ci && npm test && cd ..
node extension/build-editions.js        # -> extension-community/, extension-firefox-community/
node scripts/verify-community-package.mjs
```

On Windows, a release build embeds the signed extension packages it distributes, and fails if
they are absent. Without them, opt out explicitly: `MILVAGO_EMBED_EXTENSION=0 cargo build --release`.
The agent then carries no extension of its own.

Signed packages (CRX, Mozilla-signed XPI) and installers (MSI, Linux archives) are produced by
the release pipeline and are not built from this repository. The prepared release uses common
agent and extension version `0.6.3` across both editions and all supported browsers; it has not
been published yet.

## Repository layout

| Path | What it is |
|---|---|
| `src/` | The agent: enrollment, policy, queue, local broker, updates |
| `browser-engine/` | Detection and masking engine shared by the agent, platform-independent |
| `extension/` | The browser extension (Chromium and Firefox from one source tree) |
| `tests/` | Integration tests |
| `fuzz/` | Fuzz targets (nightly toolchain, see `fuzz/README.md`) |

## Community and Enterprise

This repository is the Community edition. The Enterprise edition adds per-model control, the
native desktop AI tools (Claude Code, Codex, Claude Desktop) and coverage of nine AI providers;
its modules are proprietary and are not part of this repository. See
[www.milvago.ai](https://www.milvago.ai).

## Community

Questions and setups: the **[Milvago AI Discord](https://discord.gg/69JPyVjqv)**. Bugs and
feature requests: [GitHub issues](https://github.com/Milvago-AI/milvago-agent/issues);
[SUPPORT.md](SUPPORT.md) says which channel fits what. Everyone taking part follows the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Found a vulnerability? Please do not open a public issue — see [SECURITY.md](SECURITY.md).

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) first; [CHANGELOG.md](CHANGELOG.md) records what changed
between releases.

## License

Copyright © 2026 Milvago AI, LLC. Licensed under the [Apache License 2.0](LICENSE); see
[LICENSING.md](LICENSING.md) and [NOTICE](NOTICE). "Milvago" and the Milvago logo are
trademarks of Milvago AI, LLC.
