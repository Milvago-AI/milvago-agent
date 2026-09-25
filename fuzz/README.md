# Fuzzing (cargo-fuzz / libFuzzer)

This crate is a fuzzing harness for `milvago-browser-agent` and
`milvago-browser-engine`. It is **never** included in the shipped binary:
it is a separate crate (`[workspace] members = ["."]`), outside the Cargo.lock
of `endpoint/` and of `endpoint/browser-engine/`, and it is not referenced by
any `Dockerfile` or build script (`package-msi.ps1`,
`package-linux.ps1`, `build-editions.js`). Removing it changes nothing in the
shipped binary.

## Targets

| Target | Fuzzed function | Plausible hostile input |
|---|---|---|
| `fuzz_browser_broker_parse` | `browser_broker::parse(&Value)` | Native request sent by the extension to the SYSTEM agent's broker |
| `fuzz_model_access` | `model_access::{rules, valid_model, browser_platform, valid_platform}` | `model_access` section of a server policy; identifiers coming from the browser |
| `fuzz_engine_inspect` | `milvago_browser_engine::inspect(&InspectionInput)` | Text typed/pasted on an arbitrary AI page + server policy |
| `fuzz_update_verify` | `update::verify(&Envelope, ...)` | Server (or MITM) response to an update check, once the Ed25519 signature has been verified with a test key generated locally in the harness |

The four targets are pure functions: none touches disk or
network, so there is no state to set up or clean up between runs.

## Running

libFuzzer requires a **nightly** toolchain and works best on Linux.
From `endpoint/` (this crate reads `..` and `../browser-engine` by relative
path, so the full `endpoint/` folder must be mounted):

```bash
docker run --rm -it \
  -v "$(pwd)/endpoint:/work" \
  -v milvago-fuzz-cargo-cache:/root/.cargo/registry \
  -w /work/fuzz \
  -e CARGO_TARGET_DIR=/tmp/fuzz-target \
  rust:1.94.1-bookworm@sha256:<resolved digest> \
  bash -lc '
    rustup toolchain install nightly-2026-09-20 --profile minimal &&
    cargo +nightly-2026-09-20 install cargo-fuzz --version =0.13.2 --locked &&
    cargo +nightly-2026-09-20 fuzz run fuzz_browser_broker_parse -- -max_total_time=180
  '
```

Repeat the last command for `fuzz_model_access`, `fuzz_engine_inspect`
and `fuzz_update_verify`. `CARGO_TARGET_DIR` points under `/tmp` so it never
writes a `target/` directory into the mounted repository.

## Replaying a crash

```bash
cargo +nightly-2026-09-20 fuzz run <target> fuzz/artifacts/<target>/<artifact>
cargo +nightly-2026-09-20 fuzz tmin <target> fuzz/artifacts/<target>/<artifact>
```

A crash is not fixed from this crate: it is reported (target, input in
hexadecimal, trace, actual reach path) for a fix in
`endpoint/src/` or `endpoint/browser-engine/src/`, outside the scope of this
harness.
