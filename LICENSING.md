# Licensing

**Copyright (c) 2026 Milvago AI, LLC.** Milvago AI, LLC is the copyright holder and the
licensor of every component in this repository.

| Component | Path | License |
| --- | --- | --- |
| Endpoint agent (Rust) | `src/`, `tests/`, `fuzz/` | Apache-2.0 |
| Detection and masking engine | `browser-engine/` | Apache-2.0 |
| Browser extension | `extension/` | Apache-2.0 |

Full text: `LICENSE`.

## Why Apache-2.0 here, AGPL-3.0 for the server

The agent and the extension are installed on end-user machines by IT teams: a permissive
license with an explicit patent grant. The [server and the console](https://github.com/Milvago-AI/milvago-server)
run as a network service and are under AGPL-3.0-only. The two sides talk only over the network
API; no code is linked across them.

## Trademark

"Milvago" and the Milvago logo are trademarks of Milvago AI, LLC. The license grants rights on
the code, not on the name or the logo: a modified distribution must not present itself as
Milvago or use the logo in a way that suggests endorsement.

## Enterprise modules

The Enterprise edition (per-model control, native desktop tools, the bridge, collector and
filter components) is proprietary and is **not** part of this repository.

## Third-party dependencies

They keep their own licenses; they are pinned in `Cargo.lock`, `browser-engine/Cargo.lock`
and `extension/package-lock.json`.
