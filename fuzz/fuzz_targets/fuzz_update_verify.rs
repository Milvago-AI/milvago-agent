#![no_main]
//! Target: `milvago_browser_agent::update::verify(&Envelope, &str, &str, &str, &str)`.
//! Real path: server (or MITM) response to an update check, before the privileged
//! application of the binary/MSI. A random Ed25519 signature is rejected before even
//! reaching the JSON decoding of the `Release`; to fuzz that decoding (and not just
//! signature verification), the harness itself signs the fuzzed bytes with a locally
//! generated test key (fixed seed, never disk or network) and supplies the matching
//! public key to `verify`. This deterministically reaches
//! `decode_release`/`release_newer`/`version` on an arbitrary payload, without ever
//! validating content produced by a third party.
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer, SigningKey};
use libfuzzer_sys::fuzz_target;
use milvago_browser_agent::{Envelope, update::verify};

fuzz_target!(|data: &[u8]| {
    let key = SigningKey::from_bytes(&[13; 32]);
    let signature = key.sign(data);
    let envelope = Envelope {
        payload: STANDARD.encode(data),
        signature: STANDARD.encode(signature.to_bytes()),
    };
    let public = STANDARD.encode(key.verifying_key().as_bytes());
    let _ = verify(&envelope, &public, "community", "windows", "0.0.0");
});
