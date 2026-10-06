# Changelog

All notable changes to this repository are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- Upgrade rand to 0.10.2 and sha2 to 0.11.0 while preserving system randomness and lowercase SHA-256 formats.
- Keep the agent and browser extension on common version 0.6.5.
- Pin source-map-js to the patched version 1.2.2 for development tools.
- Stage dependency update pull requests on dev.

Changes staged for the next Community endpoint release.
The release pipeline is prepared for shared agent and extension version `0.6.5`; `v0.6.5` has
not been published.

### Added

- Browser extension for Chrome, Edge, Brave, Vivaldi, Arc and Firefox, from one source tree:
  presence detection from the signed catalogue, capture on ChatGPT and Claude, masking before
  sending, upload blocking on measured routes.
- Rust agent for Windows and Linux: signed policy and catalogue, encrypted durable queue with
  offline recovery, local broker for the extension, signed self-update with key rotation.
- `MILVAGO_EMBED_EXTENSION=0` builds a Windows release without the signed extension packages.
