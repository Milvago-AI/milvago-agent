# Changelog

All notable changes to this repository are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.7.0] - not yet released

The release pipeline is prepared for shared agent and extension version `0.7.0`; `v0.7.0` has
not been published. It supersedes the unpublished `0.6.5`.

### Added

- `installer/`: the native custom actions of the Windows MSI (`milvago-installer`), published
  under Apache-2.0. The MSI no longer runs any PowerShell custom action: the former hidden
  PowerShell actions were reported by Microsoft Defender as a false positive
  (`Trojan:Win32/ClickFix`). Machines on 0.6.4 or earlier should upgrade to a native MSI before
  uninstalling.
- Staged provisioning: the installer reads the organization's provisioning from
  `<package>.provision.json` next to the MSI, so a single shared MSI serves every organization.
- Browser extension for Chrome, Edge, Brave, Vivaldi, Arc and Firefox, from one source tree:
  presence detection from the signed catalogue, capture on ChatGPT and Claude, masking before
  sending, upload blocking on measured routes.
- Rust agent for Windows and Linux: signed policy and catalogue, encrypted durable queue with
  offline recovery, local broker for the extension, signed self-update with key rotation.
- `MILVAGO_EMBED_EXTENSION=0` builds a Windows release without the signed extension packages.

### Changed

- Keep the agent and browser extension on common version 0.7.0.
- Reduce the cognitive complexity of the extension's `capture.js`, without behaviour change.
- Upgrade rand to 0.10.2 and sha2 to 0.11.0 while preserving system randomness and lowercase SHA-256 formats.
- Pin source-map-js to the patched version 1.2.2 for development tools.
- Stage dependency update pull requests on dev.

### Security

- Update rustls to 0.23.46 and quinn-proto to 0.11.18 for the RustSec advisories published
  against 0.23.45 and 0.11.17 (RUSTSEC-2026-0338, -0340, -0343, -0346, -0347).
