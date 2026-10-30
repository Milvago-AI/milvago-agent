//! Closed wire contract shared by the platform-specific system collectors.
use crate::Envelope;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u32,
    pub collect: bool,
    pub sequence: u64,
    pub authorization: Envelope,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub version: u32,
    pub revision: u64,
    pub catalog_revision: u64,
    pub status: String,
    pub retry_after: u64,
    pub snapshot: Option<milvago_discovery_engine::Snapshot>,
}
impl Drop for Response {
    fn drop(&mut self) {
        if let Some(snapshot) = self.snapshot.as_mut() {
            for fact in &mut snapshot.facts {
                for values in fact.fields.values_mut() {
                    for value in values {
                        zeroize::Zeroize::zeroize(value);
                    }
                }
            }
        }
    }
}
