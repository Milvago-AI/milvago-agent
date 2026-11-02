//! Read-only, bounded collectors. Activation and signed authorization belong to the endpoint.
pub mod containerd;
#[cfg(target_os = "linux")]
mod containerd_process;
pub mod containers;
pub mod docker;
#[cfg(target_os = "linux")]
mod docker_socket;
pub mod guest;
pub mod host;
pub mod http;
pub mod installation;
pub mod network;
pub mod pipe;
pub mod system;
pub mod tls;
pub mod vm;
pub mod vm_http;
#[cfg(target_os = "linux")]
mod vm_http_ndp;
pub mod vm_network;

use milvago_discovery_engine::*;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

pub const MAX_RESPONSE: usize = 2 * 1024 * 1024;

pub struct Budget<'a> {
    deadline: Instant,
    stop: &'a AtomicBool,
}
impl<'a> Budget<'a> {
    pub fn new(duration: Duration, stop: &'a AtomicBool) -> Self {
        Self {
            deadline: Instant::now() + duration.min(Duration::from_secs(30)),
            stop,
        }
    }
    pub fn check(&self) -> Result<(), &'static str> {
        if self.stop.load(Ordering::Acquire) {
            Err("cancelled")
        } else if Instant::now() >= self.deadline {
            Err("timeout")
        } else {
            Ok(())
        }
    }
    pub fn child(&self, duration: Duration) -> Self {
        Self {
            deadline: self.deadline.min(Instant::now() + duration),
            stop: self.stop,
        }
    }
    pub fn remaining(&self) -> Result<Duration, &'static str> {
        self.check()?;
        Ok(self
            .deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(2)))
    }
}

pub fn identity(namespace: &str, parts: &[&str]) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update((part.len() as u64).to_le_bytes());
        digest.update(part.as_bytes());
    }
    let hash = digest.finalize();
    let hex: String = hash.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("{namespace}/{hex}")
}

pub fn empty(scope: &str, sequence: u64, now: i64) -> Snapshot {
    Snapshot {
        version: VERSION,
        scope: scope.into(),
        sequence,
        observed_at: now,
        complete: false,
        entities: vec![],
        facts: vec![],
        relations: vec![],
        coverage: vec![],
    }
}

pub fn coverage(snapshot: &mut Snapshot, adapter: &str, status: CoverageStatus, complete: bool) {
    if snapshot.coverage.len() < 256 {
        snapshot.coverage.push(Coverage {
            scope: snapshot.scope.clone(),
            adapter: adapter.into(),
            status,
            checked_at: snapshot.observed_at,
            complete,
        });
    }
}

// Leave room below the system collector's 8 MiB frame for a rejected adapter's
// final metadata, source coverage and the protocol envelope.
const MAX_PROJECTED_JSON: usize = 6 * 1024 * 1024;

fn json_size(value: &impl serde::Serialize) -> usize {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len());
            if self.0 > MAX_PROJECTED_JSON {
                return Err(std::io::Error::other("projection_limit"));
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    if serde_json::to_writer(&mut counter, value).is_err() {
        usize::MAX
    } else {
        counter.0.saturating_add(1)
    }
}
fn charge<T: serde::Serialize>(bytes: usize, rows: &[T]) -> usize {
    rows.iter()
        .fold(bytes, |total, row| total.saturating_add(json_size(row)))
}

/// One adapter's append-only pass. Rebuilt from facts between adapters, never
/// deserialized from an untrusted projection or persisted as an admission claim.
pub struct FieldBudget {
    bytes: usize,
    encoded: usize,
    facts: usize,
    entities: usize,
    relations: usize,
    coverage: usize,
}
impl FieldBudget {
    pub fn new(snapshot: &Snapshot) -> Self {
        let bytes = snapshot
            .facts
            .iter()
            .flat_map(|fact| fact.fields.values())
            .flatten()
            .fold(0usize, |total, value| total.saturating_add(value.len()));
        // This reserve covers the outer snapshot keys, scope, timestamps and
        // small in-place coverage changes. Rows are charged without allocating
        // a second serialization of the snapshot or its HTTP bodies.
        let encoded = charge(
            charge(
                charge(charge(2048, &snapshot.facts), &snapshot.entities),
                &snapshot.relations,
            ),
            &snapshot.coverage,
        );
        Self {
            bytes,
            encoded,
            facts: snapshot.facts.len(),
            entities: snapshot.entities.len(),
            relations: snapshot.relations.len(),
            coverage: snapshot.coverage.len(),
        }
    }
    pub fn insert(
        &mut self,
        snapshot: &mut Snapshot,
        entity: &str,
        source: Source,
        fields: BTreeMap<Field, Vec<String>>,
    ) -> bool {
        if snapshot.facts.len() != self.facts
            || snapshot.entities.len() < self.entities
            || snapshot.relations.len() < self.relations
            || snapshot.coverage.len() < self.coverage
        {
            *self = Self::new(snapshot);
        }
        self.encoded = charge(
            charge(
                charge(self.encoded, &snapshot.entities[self.entities..]),
                &snapshot.relations[self.relations..],
            ),
            &snapshot.coverage[self.coverage..],
        );
        self.entities = snapshot.entities.len();
        self.relations = snapshot.relations.len();
        self.coverage = snapshot.coverage.len();
        if snapshot.facts.len() >= MAX_FACTS || self.bytes > MAX_INPUT {
            return false;
        }
        let Some(bytes) = fields
            .values()
            .flatten()
            .try_fold(self.bytes, |total, value| {
                total
                    .checked_add(value.len())
                    .filter(|size| *size <= MAX_INPUT)
            })
        else {
            return false;
        };
        let id = identity(
            "fact",
            &[
                entity,
                &format!("{source:?}"),
                &snapshot.facts.len().to_string(),
            ],
        );
        let candidate = Fact {
            id,
            entity_id: entity.into(),
            source,
            observed_at: snapshot.observed_at,
            fields,
        };
        let encoded = self.encoded.saturating_add(json_size(&candidate));
        if encoded > MAX_PROJECTED_JSON {
            return false;
        }
        snapshot.facts.push(candidate);
        self.bytes = bytes;
        self.encoded = encoded;
        self.facts = snapshot.facts.len();
        true
    }
}

pub fn fact(
    snapshot: &mut Snapshot,
    entity: &str,
    source: Source,
    fields: BTreeMap<Field, Vec<String>>,
) -> bool {
    FieldBudget::new(snapshot).insert(snapshot, entity, source, fields)
}

pub fn bounded_json(bytes: &[u8]) -> Result<serde_json::Value, &'static str> {
    if bytes.len() > MAX_RESPONSE {
        return Err("response_limit");
    }
    serde_json::from_slice(bytes).map_err(|_| "invalid_response")
}

#[cfg(target_os = "linux")]
mod vm_http_connection;

#[cfg(test)]
mod test_support;
