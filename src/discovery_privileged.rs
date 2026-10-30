//! Authorization boundary for a separate system collector. The browser bridge
//! remains unprivileged; an installer-owned anchor chooses the peer and device.
pub mod enrollment;
pub mod files;
pub mod service;
use crate::{
    Envelope, Result, State,
    discovery::{Cache, Policy},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    os::{fd::AsRawFd, unix::net::UnixStream},
    time::{Duration, Instant},
};

const MAX_RUNS: usize = 256;

fn peer_uid(peer: &UnixStream) -> Result<u32> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&credentials) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            peer.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    } != 0
        || length as usize != std::mem::size_of_val(&credentials)
        || credentials.pid <= 0
    {
        return Err("privileged discovery peer unavailable".into());
    }
    Ok(credentials.uid)
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Anchor {
    pub version: u32,
    pub agent_uid: u32,
    pub server_url: String,
    pub public_key: String,
    pub device_id: String,
}

pub use crate::discovery_reservation::Ledger;

pub enum Decision {
    Collect {
        policy: Policy,
        deadline: Instant,
    },
    Wait {
        policy: Policy,
        retry_after: Duration,
    },
    Disabled {
        policy: Policy,
    },
}

pub struct Authority {
    anchor: Anchor,
    ledger: Ledger,
    last_scan: Option<Instant>,
}

impl Authority {
    // The caller must obtain both values from protected root-owned files, never
    // from a request, the browser channel or the agent's writable cache.
    pub fn new(anchor: Anchor, mut ledger: Ledger) -> Result<Self> {
        let url = reqwest::Url::parse(&anchor.server_url)?;
        if anchor.version != 1
            || anchor.agent_uid == 0
            || anchor.agent_uid == u32::MAX
            || uuid::Uuid::parse_str(&anchor.device_id).is_err()
            || anchor.server_url.len() > 2048
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || (url.scheme() != "https"
                && !(url.scheme() == "http"
                    && matches!(
                        url.host_str(),
                        Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
                    )))
            || STANDARD
                .decode(&anchor.public_key)
                .map_or(true, |key| key.len() != 32)
            || ledger.used_runs.len() > MAX_RUNS
            || ledger
                .used_runs
                .keys()
                .any(|id| uuid::Uuid::parse_str(id).is_err())
        {
            return Err("invalid privileged discovery anchor or ledger".into());
        }
        let binding = milvago_discovery_collector::identity(
            "system-discovery-anchor",
            &[
                &anchor.agent_uid.to_string(),
                &anchor.server_url,
                &anchor.public_key,
                &anchor.device_id,
            ],
        );
        if !ledger.binding.is_empty() && ledger.binding != binding {
            return Err("privileged discovery anchor changed".into());
        }
        ledger.binding = binding;
        Ok(Self {
            anchor,
            ledger,
            last_scan: None,
        })
    }

    pub fn authorize(
        &mut self,
        peer: &UnixStream,
        envelope: &Envelope,
        persist: impl FnOnce(&Ledger) -> Result<()>,
    ) -> Result<Decision> {
        self.authorize_request(
            peer_uid(peer)?,
            envelope,
            Utc::now(),
            Instant::now(),
            true,
            persist,
        )
    }

    pub fn refresh(
        &mut self,
        peer: &UnixStream,
        envelope: &Envelope,
        persist: impl FnOnce(&Ledger) -> Result<()>,
    ) -> Result<Decision> {
        self.authorize_request(
            peer_uid(peer)?,
            envelope,
            Utc::now(),
            Instant::now(),
            false,
            persist,
        )
    }

    #[cfg(test)]
    fn authorize_peer(
        &mut self,
        uid: u32,
        envelope: &Envelope,
        now: DateTime<Utc>,
        clock: Instant,
        persist: impl FnOnce(&Ledger) -> Result<()>,
    ) -> Result<Decision> {
        self.authorize_request(uid, envelope, now, clock, true, persist)
    }

    fn authorize_request(
        &mut self,
        uid: u32,
        envelope: &Envelope,
        now: DateTime<Utc>,
        clock: Instant,
        acquire: bool,
        persist: impl FnOnce(&Ledger) -> Result<()>,
    ) -> Result<Decision> {
        if uid != self.anchor.agent_uid {
            return Err("privileged discovery peer rejected".into());
        }
        let state = State {
            device_id: self.anchor.device_id.clone(),
            public_key: self.anchor.public_key.clone(),
            server_url: self.anchor.server_url.clone(),
            discovery: Cache {
                settings_revision: self.ledger.settings_revision,
                catalog_revision: self.ledger.catalog_revision,
                ..Default::default()
            },
            ..Default::default()
        };
        let policy = crate::discovery::verify(envelope, &state, now)?;
        let reservation = crate::discovery_reservation::reserve(
            &self.ledger,
            self.last_scan,
            &policy,
            now,
            clock,
            acquire,
        )?;
        let (next, collect, remaining, active) = (
            reservation.next,
            reservation.collect,
            reservation.remaining,
            reservation.active,
        );
        // Reserve before issuing a permit: failed persistence or a restart must
        // not turn one signed on-demand request into repeated privileged work.
        persist(&next)?;
        self.ledger = next;
        if !active {
            return Ok(Decision::Disabled { policy });
        }
        if !collect {
            return Ok(Decision::Wait {
                policy,
                retry_after: remaining,
            });
        }
        self.last_scan = Some(clock);
        let validity = (policy.expires_at - now)
            .to_std()
            .map_err(|_| "expired privileged discovery policy")?;
        Ok(Decision::Collect {
            policy,
            deadline: clock + validity.min(Duration::from_secs(600)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    fn fixture() -> (
        Anchor,
        serde_json::Value,
        SigningKey,
        DateTime<Utc>,
        Instant,
    ) {
        let key = SigningKey::from_bytes(&[43; 32]);
        let now = Utc::now();
        let anchor = Anchor {
            version: 1,
            agent_uid: 1000,
            server_url: "https://server.example.test".into(),
            public_key: STANDARD.encode(key.verifying_key().to_bytes()),
            device_id: "11111111-1111-4111-8111-111111111111".into(),
        };
        let catalog: serde_json::Value =
            serde_json::from_slice(include_bytes!("../discovery-engine/catalog/factory.json"))
                .unwrap();
        let policy = serde_json::json!({"kind":"discovery_policy","version":1,"device_id":anchor.device_id,"revision":7,"issued_at":now,"expires_at":now+chrono::Duration::minutes(10),"configuration":{"host":true,"containers":false,"virtual_machines":false,"guest_read":false,"guest_execute":false,"http":false,"network":false,"interval_seconds":300},"catalog":catalog,"runs":[]});
        (anchor, policy, key, now, Instant::now())
    }
    fn sign(value: &serde_json::Value, key: &SigningKey) -> Envelope {
        let bytes = serde_json::to_vec(value).unwrap();
        Envelope {
            payload: STANDARD.encode(&bytes),
            signature: STANDARD.encode(key.sign(&bytes).to_bytes()),
        }
    }
    #[test]
    fn authority_requires_kernel_peer_signature_device_and_a_protected_persistence_step() {
        let (anchor, policy, key, now, clock) = fixture();
        let mut authority = Authority::new(anchor, Ledger::default()).unwrap();
        assert!(
            authority
                .authorize_peer(1001, &sign(&policy, &key), now, clock, |_| panic!(
                    "unauthorized peer reached persistence"
                ))
                .is_err()
        );
        let (pair, _) = UnixStream::pair().unwrap();
        let mut peer_anchor = authority.anchor.clone();
        peer_anchor.agent_uid = if unsafe { libc::geteuid() } == 1000 {
            1001
        } else {
            1000
        };
        let mut peer_authority = Authority::new(peer_anchor, Ledger::default()).unwrap();
        assert!(
            peer_authority
                .authorize(&pair, &sign(&policy, &key), |_| panic!(
                    "root test peer was accepted as service UID1000"
                ))
                .is_err()
        );
        assert!(
            authority
                .authorize_peer(
                    1000,
                    &sign(&policy, &SigningKey::from_bytes(&[44; 32])),
                    now,
                    clock,
                    |_| Ok(())
                )
                .is_err()
        );
        let mut wrong = policy.clone();
        wrong["device_id"] = "22222222-2222-4222-8222-222222222222".into();
        assert!(
            authority
                .authorize_peer(1000, &sign(&wrong, &key), now, clock, |_| Ok(()))
                .is_err()
        );
        assert!(
            authority
                .authorize_peer(1000, &sign(&policy, &key), now, clock, |_| Err(
                    "synthetic disk failure".into()
                ))
                .is_err()
        );
        assert!(matches!(
            authority
                .authorize_peer(1000, &sign(&policy, &key), now, clock, |_| Ok(()))
                .unwrap(),
            Decision::Collect { .. }
        ));
        assert!(matches!(
            authority
                .authorize_peer(
                    1000,
                    &sign(&policy, &key),
                    now,
                    clock + Duration::from_secs(1),
                    |_| Ok(())
                )
                .unwrap(),
            Decision::Wait { .. }
        ));
    }
    #[test]
    fn consumed_runs_survive_restart_and_anchor_change_and_rollback_are_rejected() {
        let (anchor, mut policy, key, now, clock) = fixture();
        policy["runs"] = serde_json::json!(["33333333-3333-4333-8333-333333333333"]);
        let mut authority = Authority::new(anchor.clone(), Ledger::default()).unwrap();
        let mut saved = Ledger::default();
        assert!(matches!(
            authority
                .authorize_peer(1000, &sign(&policy, &key), now, clock, |ledger| {
                    saved = ledger.clone();
                    Ok(())
                })
                .unwrap(),
            Decision::Collect { .. }
        ));
        let mut restarted = Authority::new(anchor.clone(), saved.clone()).unwrap();
        // Both the run and scheduled interval survive a daemon restart.
        assert!(matches!(
            restarted
                .authorize_peer(
                    1000,
                    &sign(&policy, &key),
                    now,
                    clock + Duration::from_secs(1),
                    |_| Ok(())
                )
                .unwrap(),
            Decision::Wait { .. }
        ));
        let mut older = policy.clone();
        older["revision"] = 6.into();
        assert!(
            restarted
                .authorize_peer(1000, &sign(&older, &key), now, clock, |_| Ok(()))
                .is_err()
        );
        let mut changed = anchor;
        changed.agent_uid = 1001;
        assert!(Authority::new(changed, saved).is_err());
        assert!(
            restarted
                .authorize_peer(
                    1000,
                    &sign(&policy, &key),
                    now + chrono::Duration::minutes(11),
                    clock,
                    |_| Ok(())
                )
                .is_err()
        );
    }
    #[test]
    fn disabled_sources_and_bounded_run_ledgers_do_not_create_collection_permits() {
        let (anchor, mut policy, key, now, clock) = fixture();
        let mut authority = Authority::new(anchor.clone(), Ledger::default()).unwrap();
        policy["configuration"]["host"] = false.into();
        assert!(matches!(
            authority
                .authorize_peer(1000, &sign(&policy, &key), now, clock, |_| Ok(()))
                .unwrap(),
            Decision::Disabled { .. }
        ));
        let mut ledger = Ledger::default();
        for n in 0..257 {
            ledger.used_runs.insert(
                format!("00000000-0000-4000-8000-{n:012}"),
                now + chrono::Duration::minutes(10),
            );
        }
        assert!(Authority::new(anchor, ledger).is_err());
        assert!(serde_json::from_value::<Anchor>(serde_json::json!({"version":1,"agent_uid":1000,"server_url":"https://server.example.test","public_key":"data:image/png","device_id":"image","exec":"arbitrary"})).is_err());
    }
    #[test]
    fn policy_refresh_never_consumes_a_run_or_starts_a_process_inventory() {
        let (anchor, mut policy, key, now, clock) = fixture();
        policy["runs"] = serde_json::json!(["33333333-3333-4333-8333-333333333333"]);
        let mut authority = Authority::new(anchor, Ledger::default()).unwrap();
        assert!(matches!(
            authority
                .authorize_request(1000, &sign(&policy, &key), now, clock, false, |ledger| {
                    assert!(ledger.used_runs.is_empty());
                    Ok(())
                })
                .unwrap(),
            Decision::Wait { .. }
        ));
        assert!(matches!(
            authority
                .authorize_peer(1000, &sign(&policy, &key), now, clock, |_| Ok(()))
                .unwrap(),
            Decision::Collect { .. }
        ));
    }

    #[test]
    fn refreshing_a_still_active_run_after_policy_expiry_does_not_force_an_extra_scan() {
        let (anchor, mut policy, key, now, clock) = fixture();
        policy["runs"] = serde_json::json!(["33333333-3333-4333-8333-333333333333"]);
        let mut authority = Authority::new(anchor, Ledger::default()).unwrap();
        assert!(matches!(
            authority
                .authorize_peer(1000, &sign(&policy, &key), now, clock, |_| Ok(()))
                .unwrap(),
            Decision::Collect { .. }
        ));
        assert!(matches!(
            authority
                .authorize_peer(
                    1000,
                    &sign(&policy, &key),
                    now + chrono::Duration::minutes(9),
                    clock + Duration::from_secs(540),
                    |_| Ok(())
                )
                .unwrap(),
            Decision::Collect { .. }
        ));
        policy["issued_at"] = serde_json::to_value(now + chrono::Duration::minutes(11)).unwrap();
        policy["expires_at"] = serde_json::to_value(now + chrono::Duration::minutes(21)).unwrap();
        assert!(matches!(
            authority
                .authorize_peer(
                    1000,
                    &sign(&policy, &key),
                    now + chrono::Duration::minutes(11),
                    clock + Duration::from_secs(660),
                    |_| Ok(())
                )
                .unwrap(),
            Decision::Wait { .. }
        ));
    }
}
