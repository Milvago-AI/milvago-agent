//! Shared durable reservation; callers authenticate their OS peer before entering.
use crate::{Result, discovery::Policy};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
const MAX_RUNS: usize = 256;
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Ledger {
    pub(crate) binding: String,
    pub(crate) settings_revision: u64,
    pub(crate) catalog_revision: u64,
    pub(crate) used_runs: BTreeMap<String, DateTime<Utc>>,
    pub(crate) not_before: Option<DateTime<Utc>>,
}

pub(crate) struct Reservation {
    pub next: Ledger,
    pub collect: bool,
    pub remaining: Duration,
    pub active: bool,
}
pub(crate) fn reserve(
    ledger: &Ledger,
    last_scan: Option<Instant>,
    policy: &Policy,
    now: DateTime<Utc>,
    clock: Instant,
    acquire: bool,
) -> Result<Reservation> {
    let mut next = ledger.clone();
    next.settings_revision = policy.revision;
    next.catalog_revision = policy.catalog.revision;
    next.used_runs.retain(|_, expiry| *expiry > now);
    let requested = policy.runs.first().cloned();
    let new_run = requested
        .as_ref()
        .is_some_and(|id| !next.used_runs.contains_key(id));
    let active = policy.configuration.host
        || policy.configuration.containers
        || policy.configuration.virtual_machines
        || policy.configuration.network;
    let interval = Duration::from_secs(policy.configuration.interval_seconds);
    let monotonic = last_scan
        .map(|last| interval.saturating_sub(clock.saturating_duration_since(last)))
        .unwrap_or_default();
    let persisted = ledger
        .not_before
        .and_then(|until| (until - now).to_std().ok())
        .unwrap_or_default();
    let remaining = monotonic.max(persisted);
    let collect = acquire && active && (remaining.is_zero() || new_run);
    if let Some(run) = requested {
        if let Some(expiry) = next.used_runs.get_mut(&run) {
            *expiry = (*expiry).max(policy.expires_at)
        } else if collect {
            if next.used_runs.len() >= MAX_RUNS {
                return Err("privileged discovery run budget reached".into());
            }
            // The server keeps an active run for up to thirty minutes.
            // Remember its identity beyond this policy's ten-minute window,
            // so a later policy refresh cannot replay the same request.
            next.used_runs
                .insert(run, policy.expires_at + chrono::Duration::minutes(30));
        }
    }

    if collect {
        next.not_before =
            Some(now + chrono::Duration::seconds(policy.configuration.interval_seconds as i64));
    }
    Ok(Reservation {
        next,
        collect,
        remaining,
        active,
    })
}
