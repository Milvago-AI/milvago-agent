# Changelog

All notable changes to this repository are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

First public release of the Milvago Community endpoint agent and browser extension.
The release pipeline is prepared for shared agent and extension version `0.6.4`; `v0.6.4` has
not been published.

### Added

- Browser extension for Chrome, Edge, Brave, Vivaldi, Arc and Firefox, from one source tree:
  presence detection from the signed catalogue, capture on ChatGPT and Claude, masking before
  sending, upload blocking on measured routes.
- Rust agent for Windows and Linux: signed policy and catalogue, encrypted durable queue with
  offline recovery, local broker for the extension, signed self-update with key rotation.
- `MILVAGO_EMBED_EXTENSION=0` builds a Windows release without the signed extension packages.
