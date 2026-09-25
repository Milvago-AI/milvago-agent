//! Local operational health is independent from network reachability and approval.
use crate::{Result, Store, ipc};
use serde_json::{Value, json};
use std::{path::Path, time::{Duration, Instant}};
use base64::{Engine, engine::general_purpose::STANDARD};

pub fn local(home: &Path, edition: &str, version: &str) -> Result<Value> {
    let state = Store::read_existing(home)?.load()?;
    let enrollment = if !state.credential.is_empty() {
        crate::trusted_url(&state.server_url)?;
        uuid::Uuid::parse_str(&state.device_id)?;
        let key: [u8;32] = STANDARD.decode(&state.public_key)?.try_into().map_err(|_| "invalid state anchor")?;
        ed25519_dalek::VerifyingKey::from_bytes(&key)?;
        "enrolled"
    } else if let Some(pending) = state.pending_installation {
        pending.validate_local(edition)?;
        "pending"
    } else { return Err("installation has no local provisioning".into()); };
    Ok(json!({"ok":true,"ready":true,"version":version,"edition":edition,"enrollment":enrollment}))
}

pub fn matches(value: &Value, edition: &str, version: &str) -> bool {
    value["ok"] == true && value["ready"] == true && value["edition"] == edition && value["version"] == version
}

pub fn probe(channel: &str, access: ipc::Access, edition: &str, version: &str) -> Result<Value> {
    let value = ipc::exchange_timeout(channel, access, &json!({"op":"health"}), Duration::from_secs(3))?;
    if !matches(&value, edition, version) { return Err("local service health does not match installation".into()); }
    Ok(value)
}

/// The final three-second probe ends before the sixty-second installation budget.
pub fn wait(channel: &str, access: ipc::Access, edition: &str, version: &str) -> Result<Value> {
    let deadline = Instant::now() + Duration::from_secs(55);
    loop {
        match probe(channel, access, edition, version) {
            Ok(value) => return Ok(value),
            Err(error) if Instant::now() >= deadline => return Err(error),
            Err(_) => std::thread::sleep(Duration::from_millis(200)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_or_empty_state_never_claims_ready_or_creates_files() {
        let dir = tempfile::tempdir().unwrap();
        assert!(local(dir.path(), "community", "1.0.0").is_err());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        { let store = Store::open(dir.path()).unwrap(); store.save(&crate::State::default()).unwrap(); }
        assert!(local(dir.path(), "community", "1.0.0").is_err());
    }
    #[test]
    fn enrolled_offline_state_is_read_without_mutation_or_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::State {
            credential: "synthetic-health-credential".into(),
            device_id: uuid::Uuid::new_v4().to_string(),
            server_url: "https://offline.example.test".into(),
            public_key: STANDARD.encode(ed25519_dalek::SigningKey::from_bytes(&[41;32]).verifying_key().as_bytes()),
            ..crate::State::default()
        };
        { Store::open(dir.path()).unwrap().save(&state).unwrap(); }
        let before = std::fs::read(dir.path().join("state.bin")).unwrap();
        let result = local(dir.path(), "community", "1.2.3").unwrap();
        assert_eq!(result["enrollment"], "enrolled");
        assert!(matches(&result, "community", "1.2.3"));
        assert!(!result.to_string().contains(&state.credential));
        assert!(!result.to_string().contains(&state.device_id));
        assert_eq!(std::fs::read(dir.path().join("state.bin")).unwrap(), before);
        let store = Store::open(dir.path()).unwrap();
        assert!(local(dir.path(), "community", "1.2.3").is_err(), "health must not wait for a writer");
        drop(store);
    }
    #[test]
    fn readiness_requires_exact_version_edition_and_success() {
        let healthy = json!({"ok":true,"ready":true,"edition":"community","version":"1.0.0"});
        assert!(matches(&healthy,"community","1.0.0"));
        assert!(!matches(&healthy,"commercial","1.0.0"));
        assert!(!matches(&healthy,"community","1.0.1"));
        assert!(!matches(&json!({"ok":true,"edition":"community","version":"1.0.0"}),"community","1.0.0"));
    }
}
