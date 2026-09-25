//! Browser-only cache authority. Its journal is independent from MSI snapshots.
//! Browser callers can request an existing sealed document; they cannot supply
//! policy documents, plaintext to sign, installation inputs or a new deadline.
use crate::{Envelope, Result};
use aes_gcm::{Aes256Gcm, Nonce, aead::{Aead, KeyInit, Payload}};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer, SigningKey};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub const PROTOCOL: u32 = 1;
pub const GRACE_MS: u64 = 300_000;
pub const ENGINE: &str = "1";

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    pub installation: String,
    pub edition: String,
    pub origin: String,
    pub organization_anchor: String,
    pub signing_key: String,
}
impl Pin {
    pub fn validate(&self) -> Result<()> {
        uuid::Uuid::parse_str(&self.installation)?;
        if !matches!(self.edition.as_str(), "community" | "commercial") { return Err("invalid cache edition".into()); }
        if crate::trusted_url(&self.origin)?.as_str().trim_end_matches('/') != self.origin { return Err("invalid cache origin".into()); }
        for key in [&self.organization_anchor, &self.signing_key] {
            let bytes: [u8;32] = STANDARD.decode(key)?.try_into().map_err(|_| "invalid cache anchor")?;
            ed25519_dalek::VerifyingKey::from_bytes(&bytes)?;
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedCache { pub aad: String, pub nonce: String, pub ciphertext: String }

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Journal {
    pub pin: Pin,
    pub generation: u64,
    pub policy_revision: u64,
    pub policy_hash: String,
    pub policy_content_hash: String,
    pub policy_issued_at: Option<chrono::DateTime<chrono::Utc>>,
    pub catalog_revision: u64,
    pub catalog_hash: String,
    pub catalog_content_hash: String,
    pub cache_hash: String,
    pub cache: Option<SealedCache>,
    pub boot: String,
    pub deadline: Option<u64>,
    pub armed: bool,
    pub last_tick: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Presence { Valid, Unreachable, Refused }

impl Journal {
    pub fn new(pin: Pin) -> Result<Self> {
        pin.validate()?;
        Ok(Self { pin, generation: 0, policy_revision: 0, policy_hash: String::new(), policy_content_hash: String::new(), policy_issued_at: None,
            catalog_revision: 0, catalog_hash: String::new(), catalog_content_hash: String::new(), cache_hash: String::new(), cache: None,
            boot: String::new(), deadline: None, armed: false, last_tick: 0 })
    }
    pub fn invalidate(&mut self) -> Result<()> {
        self.armed = false;
        self.cache = None;
        self.cache_hash.clear();
        self.generation = self.generation.saturating_add(1);
        Ok(())
    }
    /// Called only after the service itself obtained a valid agent response and
    /// admitted its current configuration. A browser assertion never reaches here.
    pub fn recovered(&mut self, boot: &str, tick: u64) -> Result<()> {
        uuid::Uuid::parse_str(boot)?;
        if self.cache.is_none() { return Err("cache unavailable".into()); }
        self.boot = boot.into(); self.deadline = None; self.armed = true; self.last_tick = tick;
        Ok(())
    }
    /// The caller MUST durably persist this mutation before sending any grant.
    /// A fresh process loads this same journal, rather than creating a new epoch.
    pub fn remaining(&mut self, boot: &str, tick: u64, presence: Presence) -> Result<u64> {
        if presence == Presence::Refused { self.invalidate()?; return Err("agent_refused".into()); }
        if presence == Presence::Valid { return Err("agent_available".into()); }
        if !self.armed || self.cache.is_none() || boot != self.boot || tick < self.last_tick {
            self.armed = false; return Err("cache_not_authorized".into());
        }
        self.last_tick = tick;
        let deadline = match self.deadline {
            Some(deadline) => deadline,
            None => { let deadline = tick.checked_add(GRACE_MS).ok_or("cache clock exhausted")?;
                self.deadline = Some(deadline); deadline }
        };
        if tick >= deadline { self.armed = false; return Err("cache_expired".into()); }
        Ok(deadline - tick)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Keys { signing: [u8;32], encryption: [u8;32] }
impl Drop for Keys { fn drop(&mut self) { self.signing.zeroize(); self.encryption.zeroize(); } }
impl Keys {
    pub fn generate() -> Self { let mut value=Self { signing:[0;32], encryption:[0;32] };
        OsRng.fill_bytes(&mut value.signing); OsRng.fill_bytes(&mut value.encryption); value }
    pub fn public(&self) -> String { STANDARD.encode(SigningKey::from_bytes(&self.signing).verifying_key().as_bytes()) }
    pub(crate) fn sign(&self, value: &Value) -> Result<Envelope> {
        let payload=serde_json::to_vec(value)?;
        Ok(Envelope { payload:STANDARD.encode(&payload), signature:STANDARD.encode(SigningKey::from_bytes(&self.signing).sign(&payload).to_bytes()) })
    }
}

pub fn hash(bytes: &[u8]) -> String { format!("{:x}",Sha256::digest(bytes)) }
pub fn policy_content_hash(policy: &crate::shadow::ShadowPolicy) -> Result<String> {
    Ok(hash(&serde_json::to_vec(&json!({"version":policy.version,"config":policy.config,"capabilities":policy.capabilities}))?))
}
pub fn envelope_hash(envelope: &Envelope) -> Result<String> { Ok(hash(&STANDARD.decode(&envelope.payload)?)) }

/// Whitelist browser settings. Native inventory, credentials, installation
/// tokens and server secrets never enter the signed browser document.
fn browser_config(config: &Value, edition: &str) -> Result<Value> {
    let mut out = json!({});
    for key in ["services", "protection", "privacy", "collection", "discovery"] {
        if let Some(value)=config.get(key) { out[key]=value.clone(); }
    }
    if let Some(classification)=config.get("classification") {
        out["classification"]=json!({"browser":classification["browser"],"medical_terms":classification["medical_terms"]});
    }
    if edition=="commercial" {
        out["model_access"]=Value::Array(config["model_access"].as_array().into_iter().flatten()
            .filter(|rule|rule["channel"]=="browser").cloned().collect());
    } else if config["model_access"].as_array().is_some_and(|rules|!rules.is_empty()) {
        return Err("foreign edition policy".into());
    }
    Ok(out)
}

/// Admission on the service-only channel. Same-revision equivocation is refused.
/// An expired envelope may only be reused when its exact bytes were already
/// admitted by this independent authority.
pub fn prepare(journal: &mut Journal, keys: &Keys, policy: &Envelope, catalog: &Envelope) -> Result<()> {
    journal.pin.validate()?;
    if keys.public()!=journal.pin.signing_key { return Err("cache key mismatch".into()); }
    let policy_hash=envelope_hash(policy)?;
    let catalog_envelope_hash=envelope_hash(catalog)?;
    let now=chrono::Utc::now();
    let raw_policy:crate::shadow::ShadowPolicy=serde_json::from_slice(&STANDARD.decode(&policy.payload)?)?;
    let content_hash=policy_content_hash(&raw_policy)?;
    let policy_time=if content_hash==journal.policy_content_hash && journal.cache.is_some() {
        let p:crate::shadow::ShadowPolicy=serde_json::from_slice(&STANDARD.decode(&policy.payload)?)?;
        p.issued_at
    } else { now };
    let p=crate::shadow::verify(policy,&journal.pin.organization_anchor,journal.policy_revision,policy_time)?;
    if journal.policy_issued_at.is_some_and(|issued| p.issued_at < issued ||
        (p.issued_at == issued && content_hash != journal.policy_content_hash)) {
        return Err("policy issue time replay or equivocation".into());
    }
    let catalog_time=if catalog_envelope_hash==journal.catalog_hash && journal.cache.is_some() {
        let c:crate::detection::Header=serde_json::from_slice(&STANDARD.decode(&catalog.payload)?)?;
        c.issued_at
    } else { now };
    let c=crate::detection::verify(catalog,&journal.pin.organization_anchor,journal.catalog_revision,&journal.catalog_content_hash,catalog_time)?;
    if c.header.revision==journal.catalog_revision && !journal.catalog_content_hash.is_empty() && c.header.content_hash!=journal.catalog_content_hash {
        return Err("catalog revision equivocation".into());
    }
    if content_hash==journal.policy_content_hash && c.header.content_hash==journal.catalog_content_hash
        && p.revision==journal.policy_revision && c.header.revision==journal.catalog_revision && journal.cache.is_some() {
        journal.policy_hash=policy_hash;journal.catalog_hash=catalog_envelope_hash;journal.policy_issued_at=Some(p.issued_at);
        return Ok(());
    }
    let generation=journal.generation.checked_add(1).ok_or("cache generation exhausted")?;
    let metadata=json!({"protocol":PROTOCOL,"pin":journal.pin,"generation":generation,"engine":ENGINE,
        "policy_revision":p.revision,"catalog_revision":c.header.revision});
    let document=json!({"metadata":metadata,"policy":{"version":p.version,"revision":p.revision,
        "issued_at":p.issued_at,"expires_at":p.expires_at,"config":browser_config(&p.config,&journal.pin.edition)?},
        "catalog":{"providers":c.content.providers,"heuristics":c.content.heuristics},
        "excluded_domains":[crate::trusted_url(&journal.pin.origin)?.host_str()]});
    let signed=keys.sign(&document)?;
    let mut plaintext=serde_json::to_vec(&signed)?;
    let aad=serde_json::to_vec(&metadata)?;
    let mut nonce=[0u8;12];OsRng.fill_bytes(&mut nonce);
    let encrypted=Aes256Gcm::new_from_slice(&keys.encryption).map_err(|_|"cache key invalid")?
        .encrypt(Nonce::from_slice(&nonce),Payload{msg:&plaintext,aad:&aad});
    plaintext.zeroize();
    let cache=SealedCache{aad:STANDARD.encode(aad),nonce:STANDARD.encode(nonce),
        ciphertext:STANDARD.encode(encrypted.map_err(|_|"cache encryption failed")?)};
    journal.cache_hash=hash(&serde_json::to_vec(&cache)?);
    journal.cache=Some(cache);journal.generation=generation;
    journal.policy_revision=p.revision;journal.policy_hash=policy_hash;
    journal.policy_content_hash=content_hash;journal.policy_issued_at=Some(p.issued_at);
    journal.catalog_revision=c.header.revision;journal.catalog_hash=catalog_envelope_hash;journal.catalog_content_hash=c.header.content_hash;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn state()->Journal {
        let keys=Keys::generate();let mut state=Journal::new(Pin{installation:uuid::Uuid::new_v4().to_string(),
            edition:"community".into(),origin:"https://example.test".into(),organization_anchor:keys.public(),signing_key:keys.public()}).unwrap();
        state.cache=Some(SealedCache{aad:String::new(),nonce:String::new(),ciphertext:String::new()});
        state.recovered(&uuid::Uuid::new_v4().to_string(),100).unwrap();state
    }
    #[test]
    fn idle_time_does_not_consume_grace_and_repeated_failures_never_extend_it() {
        let mut s=state();let boot=s.boot.clone();let first=50*60*1000;
        assert_eq!(s.remaining(&boot,first,Presence::Unreachable).unwrap(),GRACE_MS);
        let deadline=s.deadline;
        assert_eq!(s.remaining(&boot,first+299_999,Presence::Unreachable).unwrap(),1);
        assert_eq!(s.deadline,deadline);
        assert!(s.remaining(&boot,first+300_000,Presence::Unreachable).is_err());
        assert!(s.remaining(&boot,first+300_001,Presence::Unreachable).is_err());
        assert_eq!(s.deadline,deadline);
    }
    #[test]
    fn persisted_restart_and_boot_change_cannot_reset_deadline() {
        let mut s=state();let boot=s.boot.clone();s.remaining(&boot,1000,Presence::Unreachable).unwrap();
        let bytes=serde_json::to_vec(&s).unwrap();let mut restored:Journal=serde_json::from_slice(&bytes).unwrap();
        assert_eq!(restored.remaining(&boot,2000,Presence::Unreachable).unwrap(),299_000);
        assert!(restored.remaining(&uuid::Uuid::new_v4().to_string(),3000,Presence::Unreachable).is_err());
        assert!(!restored.armed);
    }
    #[test]
    fn refusal_missing_cache_and_monotone_rewind_fail_closed() {
        let mut s=state();let boot=s.boot.clone();assert!(s.remaining(&boot,99,Presence::Unreachable).is_err());
        let mut s=state();let boot=s.boot.clone();assert!(s.remaining(&boot,100,Presence::Refused).is_err());assert!(s.cache.is_none());
        assert!(s.remaining(&boot,101,Presence::Unreachable).is_err());
    }
}

/// Read the admitted document only inside the privileged authority. Neither its
/// key nor its full rules are part of the browser protocol.
pub(crate) fn open(journal:&Journal,keys:&Keys)->Result<Value>{
    let blob=journal.cache.as_ref().ok_or("cache absent")?;
    if keys.public()!=journal.pin.signing_key||hash(&serde_json::to_vec(blob)?)!=journal.cache_hash{return Err("cache identity invalid".into())}
    let aad=STANDARD.decode(&blob.aad)?;
    let expected=json!({"protocol":PROTOCOL,"pin":journal.pin,"generation":journal.generation,"engine":ENGINE,
        "policy_revision":journal.policy_revision,"catalog_revision":journal.catalog_revision});
    if serde_json::from_slice::<Value>(&aad)?!=expected{return Err("cache metadata invalid".into())}
    let nonce=STANDARD.decode(&blob.nonce)?;if nonce.len()!=12{return Err("cache nonce invalid".into())}
    let mut plaintext=Aes256Gcm::new_from_slice(&keys.encryption).map_err(|_|"cache key invalid")?
        .decrypt(Nonce::from_slice(&nonce),Payload{msg:&STANDARD.decode(&blob.ciphertext)?,aad:&aad}).map_err(|_|"cache authentication failed")?;
    let parsed=serde_json::from_slice::<Envelope>(&plaintext);plaintext.zeroize();let envelope=parsed?;
    let mut document_bytes=STANDARD.decode(&envelope.payload)?;
    let public:[u8;32]=STANDARD.decode(&journal.pin.signing_key)?.try_into().map_err(|_|"cache anchor invalid")?;
    let verified=ed25519_dalek::VerifyingKey::from_bytes(&public)?.verify_strict(&document_bytes,
        &ed25519_dalek::Signature::from_slice(&STANDARD.decode(&envelope.signature)?)?);
    if verified.is_err(){document_bytes.zeroize();return Err("cache signature invalid".into())}
    let parsed=serde_json::from_slice::<Value>(&document_bytes);document_bytes.zeroize();let document=parsed?;
    if document["metadata"]!=expected{return Err("cache signed identity invalid".into())}
    let policy:crate::shadow::ShadowPolicy=serde_json::from_value(document["policy"].clone())?;
    if policy.revision!=journal.policy_revision{return Err("cache revision invalid".into())}
    Ok(document)
}
