#![no_main]
//! Target: `milvago_browser_agent::model_access::{rules, valid_model, browser_platform,
//! valid_platform}`. Real path: `rules` reads the `model_access` section of a policy
//! received from the server (signed config, but its business content is not fuzzed by
//! the signature); the other three validate identifiers coming from the browser or the
//! server. Pure functions, no disk or network: a single harness is enough for all
//! four, on the same input split two different ways.
use libfuzzer_sys::fuzz_target;
use milvago_browser_agent::model_access;

fuzz_target!(|data: &[u8]| {
    // `rules` reads an arbitrary JSON policy.
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) {
        let _ = model_access::rules(&value);
    }
    // The string validators read the same text, raw or split in two.
    let text = String::from_utf8_lossy(data);
    let _ = model_access::valid_model(&text);
    let _ = model_access::browser_platform(&text);
    let mut parts = text.splitn(2, '\n');
    let platform = parts.next().unwrap_or("");
    let channel = parts.next().unwrap_or("");
    let _ = model_access::valid_platform(platform, channel);
});
