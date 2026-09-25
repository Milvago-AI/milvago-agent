#![no_main]
//! Target: `milvago_browser_agent::browser_broker::parse(&serde_json::Value)`.
//! Real path: request sent by the browser (extension) to the SYSTEM agent's native
//! broker, before any application-level identity check. Plausible hostile input from
//! a compromised extension or a local peer spoofing the channel.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Bytes that are not valid JSON never reach `parse`, which is only called on the
    // agent side once the native message has been deserialized into a `Value`.
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };
    let _ = milvago_browser_agent::browser_broker::parse(&value);
});
