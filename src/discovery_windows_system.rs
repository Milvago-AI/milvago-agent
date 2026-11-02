//! Windows system boundary: machine-owned trust, authenticated service peer and durable quotas.
use crate::{
    Envelope, Result, State,
    discovery::{Cache, Policy},
    discovery_reservation::{Ledger, reserve},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

#[cfg(windows)]
mod native;

#[cfg(windows)]
pub(crate) use native::request;

pub fn edition() -> &'static str {
    if cfg!(feature = "enterprise-extension") {
        "commercial"
    } else {
        "community"
    }
}

pub fn service_name(edition: &str) -> Result<&'static str> {
    match edition {
        "community" => Ok("Milvago Discovery Community"),
        "commercial" => Ok("Milvago Discovery"),
        _ => Err("invalid discovery edition".into()),
    }
}

#[cfg(windows)]
pub fn run(stop: std::sync::Arc<std::sync::atomic::AtomicBool>) -> Result<()> {
    native::run(edition(), stop)
}

#[cfg(windows)]
pub fn initialize(bytes: &[u8]) -> Result<()> {
    native::initialize(edition(), bytes)
}

#[cfg(windows)]
pub fn initialize_staged() -> Result<()> {
    native::initialize_staged(edition())
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Anchor {
    pub version: u32,
    pub edition: String,
    pub agent_service_sid: String,
    pub server_url: String,
    pub public_key: String,
    pub device_id: String,
}

// Same public document exported by the console for a local administrator.
// The installed Windows service identity is selected locally, never by this file.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdministrativeBinding {
    version: u32,
    device_id: String,
    server_url: String,
    public_key: String,
}

fn administrator_anchor(bytes: &[u8], edition: &str, service_sid: &str) -> Result<Anchor> {
    if bytes.len() > 16384 {
        return Err("Windows discovery binding exceeds limit".into());
    }
    let binding: AdministrativeBinding = serde_json::from_slice(bytes)?;
    let anchor = Anchor {
        version: binding.version,
        edition: edition.into(),
        agent_service_sid: service_sid.into(),
        server_url: binding.server_url,
        public_key: binding.public_key,
        device_id: uuid::Uuid::parse_str(&binding.device_id)?.to_string(),
    };
    anchor.binding()?;
    Ok(anchor)
}
fn service_sid(value: &str) -> bool {
    let Some(tail) = value.strip_prefix("S-1-5-80-") else {
        return false;
    };
    let parts: Vec<_> = tail.split('-').collect();
    parts.len() == 5
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 10
                && (*p == "0" || !p.starts_with('0'))
                && p.bytes().all(|c| c.is_ascii_digit())
                && p.parse::<u32>().is_ok()
        })
}
impl Anchor {
    fn binding(&self) -> Result<String> {
        let url = reqwest::Url::parse(&self.server_url)?;
        if self.version != 1
            || !["community", "commercial"].contains(&self.edition.as_str())
            || !service_sid(&self.agent_service_sid)
            || self.server_url.len() > 2048
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.scheme() != "https"
                && !(url.scheme() == "http"
                    && matches!(
                        url.host_str(),
                        Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
                    ))
            || STANDARD
                .decode(&self.public_key)
                .map_or(true, |v| v.len() != 32)
            || uuid::Uuid::parse_str(&self.device_id).map_or(true, |v| v.is_nil())
        {
            return Err("invalid Windows discovery anchor".into());
        }
        Ok(milvago_discovery_collector::identity(
            "system-discovery-anchor",
            &[
                &self.agent_service_sid,
                &self.edition,
                &self.server_url,
                &self.public_key,
                &self.device_id,
            ],
        ))
    }
}

// Constructed only after the pipe layer verified the enabled service-token group.
struct Peer {
    service_sid: String,
}
struct Authority {
    anchor: Anchor,
    ledger: Ledger,
    last_scan: Option<Instant>,
}
enum Decision {
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
impl Authority {
    fn new(anchor: Anchor, mut ledger: Ledger) -> Result<Self> {
        let binding = anchor.binding()?;
        if !ledger.binding.is_empty() && ledger.binding != binding
            || ledger.used_runs.len() > 256
            || ledger
                .used_runs
                .keys()
                .any(|k| uuid::Uuid::parse_str(k).is_err())
        {
            return Err("Windows discovery anchor or ledger rejected".into());
        }
        ledger.binding = binding;
        Ok(Self {
            anchor,
            ledger,
            last_scan: None,
        })
    }
    fn authorize(
        &mut self,
        peer: &Peer,
        envelope: &Envelope,
        acquire: bool,
        now: DateTime<Utc>,
        clock: Instant,
        persist: impl FnOnce(&Ledger) -> Result<()>,
    ) -> Result<Decision> {
        if peer.service_sid != self.anchor.agent_service_sid {
            return Err("Windows discovery peer rejected".into());
        }
        let state = State {
            device_id: self.anchor.device_id.clone(),
            server_url: self.anchor.server_url.clone(),
            public_key: self.anchor.public_key.clone(),
            discovery: Cache {
                settings_revision: self.ledger.settings_revision,
                catalog_revision: self.ledger.catalog_revision,
                ..Default::default()
            },
            ..Default::default()
        };
        let policy = crate::discovery::verify(envelope, &state, now)?;
        let reservation = reserve(&self.ledger, self.last_scan, &policy, now, clock, acquire)?;
        // A failed write must never issue a new collection permit.
        persist(&reservation.next)?;
        self.ledger = reservation.next;
        if !reservation.active {
            return Ok(Decision::Disabled { policy });
        }
        if !reservation.collect {
            return Ok(Decision::Wait {
                policy,
                retry_after: reservation.remaining,
            });
        }
        self.last_scan = Some(clock);
        let lifetime = (policy.expires_at - now)
            .to_std()?
            .min(Duration::from_secs(600));
        Ok(Decision::Collect {
            policy,
            deadline: clock + lifetime,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    const SID: &str = "S-1-5-80-11-22-33-44-55";
    #[test]
    fn public_administrator_binding_uses_only_the_local_service_identity() {
        let (anchor, _, _, _) = fixture();
        let document = serde_json::json!({"version":1,"device_id":"ABCDEFAB-CDEF-4ABC-8ABC-ABCDEFABCDEF","server_url":anchor.server_url,"public_key":anchor.public_key});
        let bytes = serde_json::to_vec(&document).unwrap();
        let parsed = administrator_anchor(&bytes, "community", SID).unwrap();
        assert_eq!(parsed.device_id, "abcdefab-cdef-4abc-8abc-abcdefabcdef");
        assert_eq!(parsed.edition, "community");
        assert_eq!(parsed.agent_service_sid, SID);
        assert!(administrator_anchor(&bytes, "other", SID).is_err());
        assert!(administrator_anchor(&bytes, "community", "S-1-5-18").is_err());
        for name in ["agent_service_sid", "edition", "credential", "command"] {
            let mut bad = document.clone();
            bad[name] = serde_json::json!("caller supplied authority");
            assert!(
                administrator_anchor(&serde_json::to_vec(&bad).unwrap(), "community", SID).is_err()
            );
        }
        for bytes in [
            b"[]".as_slice(),
            b"null",
            br#"{"version":1,"device_id":{"image":"png"}}"#,
            &vec![b'x'; 16385],
        ] {
            assert!(administrator_anchor(bytes, "community", SID).is_err());
        }
        let mut nil = document;
        nil["device_id"] = serde_json::json!("00000000-0000-0000-0000-000000000000");
        assert!(
            administrator_anchor(&serde_json::to_vec(&nil).unwrap(), "community", SID).is_err()
        );
    }
    #[test]
    fn anchor_rejects_ambiguous_identity_and_untrusted_origins() {
        let (anchor, _, _, _) = fixture();
        assert!(anchor.binding().is_ok());
        assert!(service_sid("S-1-5-80-0-1-2-3-4294967295"));
        for sid in [
            "S-1-5-80-01-2-3-4-5",
            "S-1-5-80-1-2-3-4-4294967296",
            "S-1-5-18",
            "S-1-5-80-1-2-3-4",
            "S-1-5-80-1-2-3-4-5-6",
        ] {
            assert!(!service_sid(sid), "{sid}");
        }
        for origin in [
            "http://remote.example.test",
            "https://user:secret@example.test",
            "https://example.test/?key=value",
            "file:///etc/passwd",
            "https://example.test/#fragment",
        ] {
            let mut invalid = anchor.clone();
            invalid.server_url = origin.into();
            assert!(invalid.binding().is_err(), "{origin}");
        }
        let mut invalid = anchor.clone();
        invalid.device_id = uuid::Uuid::nil().to_string();
        assert!(invalid.binding().is_err());
        invalid = anchor.clone();
        invalid.public_key = STANDARD.encode([71; 31]);
        assert!(invalid.binding().is_err());
        let mut wire = serde_json::to_value(&anchor).unwrap();
        wire["executable"] = "untrusted".into();
        assert!(serde_json::from_value::<Anchor>(wire).is_err());
    }
    fn fixture() -> (Anchor, serde_json::Value, SigningKey, DateTime<Utc>) {
        let key = SigningKey::from_bytes(&[71; 32]);
        let now = Utc::now();
        let anchor = Anchor {
            version: 1,
            edition: "community".into(),
            agent_service_sid: SID.into(),
            server_url: "https://server.example.test".into(),
            public_key: STANDARD.encode(key.verifying_key().to_bytes()),
            device_id: "11111111-1111-4111-8111-111111111111".into(),
        };
        let catalog: serde_json::Value =
            serde_json::from_slice(include_bytes!("../discovery-engine/catalog/factory.json"))
                .unwrap();
        let policy = serde_json::json!({"kind":"discovery_policy","version":1,"device_id":anchor.device_id,"revision":7,"issued_at":now,"expires_at":now+chrono::Duration::minutes(10),"configuration":{"host":true,"containers":false,"virtual_machines":true,"guest_read":true,"guest_execute":true,"http":false,"network":false,"interval_seconds":300},"catalog":catalog,"runs":[]});
        (anchor, policy, key, now)
    }
    fn sign(policy: &serde_json::Value, key: &SigningKey) -> Envelope {
        let bytes = serde_json::to_vec(policy).unwrap();
        Envelope {
            payload: STANDARD.encode(&bytes),
            signature: STANDARD.encode(key.sign(&bytes).to_bytes()),
        }
    }
    #[test]
    fn windows_authority_binds_kernel_service_identity_device_and_root_persistence() {
        let (anchor, policy, key, now) = fixture();
        let clock = Instant::now();
        let mut authority = Authority::new(anchor, Ledger::default()).unwrap();
        for sid in ["S-1-5-20", "S-1-5-18", "S-1-5-80-11-22-33-44-56", ""] {
            assert!(
                authority
                    .authorize(
                        &Peer {
                            service_sid: sid.into()
                        },
                        &sign(&policy, &key),
                        true,
                        now,
                        clock,
                        |_| panic!("untrusted peer reached persistence")
                    )
                    .is_err()
            );
        }
        let peer = Peer {
            service_sid: SID.into(),
        };
        let mut wrong = policy.clone();
        wrong["device_id"] = "22222222-2222-4222-8222-222222222222".into();
        assert!(
            authority
                .authorize(&peer, &sign(&wrong, &key), true, now, clock, |_| panic!(
                    "foreign device reached persistence"
                ))
                .is_err()
        );
        assert!(
            authority
                .authorize(
                    &peer,
                    &sign(&policy, &SigningKey::from_bytes(&[72; 32])),
                    true,
                    now,
                    clock,
                    |_| panic!("wrong signature reached persistence")
                )
                .is_err()
        );
        assert!(
            authority
                .authorize(&peer, &sign(&policy, &key), true, now, clock, |_| Err(
                    "synthetic write failure".into()
                ))
                .is_err()
        );
        assert!(matches!(
            authority
                .authorize(&peer, &sign(&policy, &key), true, now, clock, |_| Ok(()))
                .unwrap(),
            Decision::Collect { .. }
        ));
        assert!(matches!(
            authority
                .authorize(&peer, &sign(&policy, &key), true, now, clock, |_| Ok(()))
                .unwrap(),
            Decision::Wait { .. }
        ));
    }
    #[test]
    fn windows_restart_rollback_withdrawal_and_run_quotas_keep_the_same_authority() {
        let (anchor, mut policy, key, now) = fixture();
        let clock = Instant::now();
        let peer = Peer {
            service_sid: SID.into(),
        };
        policy["runs"] = serde_json::json!(["33333333-3333-4333-8333-333333333333"]);
        let mut authority = Authority::new(anchor.clone(), Ledger::default()).unwrap();
        let mut saved = Ledger::default();
        assert!(matches!(
            authority
                .authorize(&peer, &sign(&policy, &key), false, now, clock, |l| {
                    assert!(l.used_runs.is_empty());
                    Ok(())
                })
                .unwrap(),
            Decision::Wait { .. }
        ));
        assert!(matches!(
            authority
                .authorize(&peer, &sign(&policy, &key), true, now, clock, |l| {
                    saved = l.clone();
                    Ok(())
                })
                .unwrap(),
            Decision::Collect { .. }
        ));
        let mut restarted = Authority::new(anchor.clone(), saved.clone()).unwrap();
        assert!(matches!(
            restarted
                .authorize(&peer, &sign(&policy, &key), true, now, clock, |_| Ok(()))
                .unwrap(),
            Decision::Wait { .. }
        ));
        let mut old = policy.clone();
        old["revision"] = 6.into();
        assert!(
            restarted
                .authorize(&peer, &sign(&old, &key), true, now, clock, |_| Ok(()))
                .is_err()
        );
        assert!(
            restarted
                .authorize(
                    &peer,
                    &sign(&policy, &key),
                    true,
                    now + chrono::Duration::minutes(11),
                    clock,
                    |_| Ok(())
                )
                .is_err()
        );
        let mut disabled = policy.clone();
        for key in ["host", "virtual_machines", "guest_read", "guest_execute"] {
            disabled["configuration"][key] = false.into();
        }
        assert!(matches!(
            restarted
                .authorize(&peer, &sign(&disabled, &key), true, now, clock, |_| Ok(()))
                .unwrap(),
            Decision::Disabled { .. }
        ));
        let mut foreign = anchor;
        foreign.edition = "commercial".into();
        assert!(Authority::new(foreign, saved).is_err());
    }
}
