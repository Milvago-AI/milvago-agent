#![no_main]
//! Target: `milvago_browser_engine::inspect(&InspectionInput)`, the public API of the
//! detection/masking engine. Real path: `input.text` is the text typed (or pasted) by a
//! user on an arbitrary AI page; `input.config`/`input.service` come from the policy
//! received from the server. This is the surface most directly exposed to hostile page
//! content: Unicode normalization, fixed and custom regex rules,
//! masking/redaction of spans.
use libfuzzer_sys::fuzz_target;
use milvago_browser_engine::InspectionInput;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = serde_json::from_slice::<InspectionInput>(data) else {
        return;
    };
    let _ = milvago_browser_engine::inspect(&input);
});
