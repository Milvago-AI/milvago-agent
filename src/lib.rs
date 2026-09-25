use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use fs2::FileExt;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};
use uuid::Uuid;
use zeroize::Zeroize;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub mod bootstrap;
pub mod config;
 pub mod detection;
pub mod eventlog;
pub mod ipc;
pub mod health;
pub mod extension_update;
pub mod extension_tls;
pub mod log;
pub mod native;
pub mod model_access;
pub mod session_user;
pub mod shadow;
#[cfg(test)]
mod shadow_tests;
pub mod update;
pub mod update_host;
pub mod browser_cache;
pub mod browser_broker;
#[cfg(windows)]
pub mod cache_windows;
#[cfg(windows)]
pub mod cache_peer;
#[cfg(windows)]
pub mod cache_service;
pub mod watch;
// Keep queued data readable after a configured capacity decrease.
const STATE_LIMIT: usize = (config::MAX_QUEUE_SIZE_MB + 16) * 1024 * 1024;
pub const QUEUE_LIMIT: usize = 10000;
const AAD: &[u8] = b"milvago.browser-state.v1";

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub domain: String,
    pub action: String,
    pub enabled: bool,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Collection {
    pub prompt_content: bool,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    pub revision: u64,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub rules: Vec<Rule>,
    pub collection: Collection,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub payload: String,
    pub signature: String,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub id: Uuid,
    pub occurred_at: DateTime<Utc>,
    pub provider: String,
    pub action: String,
    pub source: String,
    pub characters: u32,
    pub labels: Vec<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provision {
    pub server_url: String,
    pub policy_public_key: String,
    pub token: String,
    #[serde(default)]
    pub update_public_key: Option<String>,
}
#[derive(Serialize, Deserialize, Default)]
pub struct State {
    #[serde(default)]
    pub browser_broker_receipt: Option<browser_broker::AgentReceipt>,
    #[serde(default)]
    pub detection: detection::Cache,
    #[serde(default)]
    pub update_reports: Vec<update::UpdateReport>,
    #[serde(default)]
    pub unsettled_update: Option<update::UnsettledUpdate>,
    #[serde(default)]
    pub pending_installation: Option<bootstrap::PendingInstallation>,
    #[serde(default)]
    pub pending_reinstallation: Option<bootstrap::PendingInstallation>,
    pub server_url: String,
    pub public_key: String,
    pub device_id: String,
    pub credential: String,
    pub max_revision: u64,
    pub policy: Option<Envelope>,
    pub queue: Vec<Event>,
    #[serde(default)]
    pub shadow_policy: Option<Envelope>,
    #[serde(default)]
    pub shadow_revision: u64,
    /// Changes on an authenticated refusal so outstanding earlier responses
    /// cannot reinstall authorization after revocation.
    #[serde(default)]
    pub authorization_generation: u64,
    /// Outcome and time of the last policy synchronization attempt. They exist so
    /// the IPC policy answer can report reachability without performing a network
    /// round trip of its own while holding the exclusive store lock.
    #[serde(default)]
    pub shadow_online: bool,
    #[serde(default)]
    pub shadow_synced_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Time of the last delivery attempt, reserved before releasing the lock.
    /// Both protocol versions share this cooldown against repeated IPC triggers.
    #[serde(default)]
    pub shadow_flushed_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub association_attempted_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Keys are restricted to the compiled browser-platform vocabulary.
    #[serde(default)]
    pub enforcement_attempts: std::collections::BTreeMap<String, chrono::DateTime<chrono::Utc>>,
    /// Last time each browser's extension talked to this agent. Reported to the
    /// server so an extension a user disabled stops looking like an absence of AI
    /// use. Bounded by the browser vocabulary, so it cannot grow.
    #[serde(default)]
    pub browsers: std::collections::BTreeMap<String, chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub shadow_queue: Vec<shadow::ShadowEvent>,
    /// Completions waiting for the server: what an outgoing request said about an
    /// exchange the server has already accepted. An event still in `shadow_queue` is
    /// completed there instead, so nothing here can outrun the event it names.
    #[serde(default)]
    pub shadow_completions: Vec<shadow::ShadowCompletion>,
    /// Bounded diagnostics for permanently invalid events, never their contents.
    #[serde(default)]
    pub rejected_events: Vec<shadow::RejectedEvent>,
    #[serde(default)]
    pub extension_data: serde_json::Value,
    #[serde(default)]
    pub update_public_key: Option<String>,
    /// Highest AI-application catalog revision this installation has accepted. Held
    /// by the privileged collector so an earlier catalog cannot be replayed at it.
    #[serde(default)]
    pub catalog_revision: u64,
    /// The catalog document itself, kept so a pass that could not fetch a fresh one
    /// still detects. Verified on every read, never trusted because it was stored.
    #[serde(default)]
    pub extension_catalog: Option<Envelope>,
    /// Successor release trust anchor, learned from a document signed by the current
    /// anchor. It exists so a signing key can be rotated without re-enrolling every
    /// device; it is promoted the first time a release verifies against it.
    #[serde(default)]
    pub update_public_key_next: Option<String>,
    /// The machine this identity belongs to. A copy of the disk on another machine (a
    /// VDI golden image, a sysprep'd clone) re-registers as a new device instead of
    /// sharing this one's credential.
    #[serde(default)]
    pub machine: Option<bootstrap::MachineBinding>,
}

pub fn trusted_url(value: &str) -> Result<reqwest::Url> {
    let u = reqwest::Url::parse(value)?;
    if !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
        || u.path() != "/"
    {
        return Err("server URL must be an origin without credentials".into());
    }
    if u.scheme() != "https"
        && !(u.scheme() == "http"
            && matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")))
    {
        return Err("HTTPS is required outside loopback".into());
    }
    Ok(u)
}
pub fn domain_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.contains('.')
        && s.split('.').all(|v| {
            !v.is_empty()
                && v.len() <= 63
                && !v.starts_with('-')
                && !v.ends_with('-')
                && v.bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        })
}
pub fn verify_policy(
    env: &Envelope,
    key: &str,
    min_revision: u64,
    now: DateTime<Utc>,
) -> Result<Policy> {
    if env.payload.len() > 128 * 1024 {
        return Err("policy too large".into());
    }
    let key: [u8; 32] = STANDARD
        .decode(key)?
        .try_into()
        .map_err(|_| "invalid public key")?;
    let raw = STANDARD.decode(&env.payload)?;
    let sig = Signature::from_slice(&STANDARD.decode(&env.signature)?)?;
    VerifyingKey::from_bytes(&key)?.verify_strict(&raw, &sig)?;
    let p: Policy = serde_json::from_slice(&raw)?;
    if p.version != 1
        || p.revision < min_revision
        || p.expires_at <= now
        || p.issued_at > now + chrono::Duration::seconds(60)
        || p.expires_at <= p.issued_at
        || p.expires_at - p.issued_at > chrono::Duration::hours(24)
        || p.collection.prompt_content
        || p.rules.len() > 500
    {
        return Err("policy validity rejected".into());
    }
    if p.rules.iter().any(|r| {
        !domain_ok(&r.domain)
            || !matches!(r.action.as_str(), "observe" | "block")
            || r.id.len() > 128
    }) {
        return Err("policy rule rejected".into());
    }
    Ok(p)
}

fn private_file(path: &Path, create_new: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true);
    if create_new {
        options.create_new(true);
    } else {
        options.create(true).truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}
fn atomic_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension(format!("{}.tmp", Uuid::new_v4()));
    let result = replace_with(&tmp, path, bytes);
    // A failed write (full disk, a sharing violation) must not leave its partial copy:
    // repeated, the leftovers would fill the protected directory.
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}
fn replace_with(tmp: &Path, path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = private_file(tmp, true)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        unsafe extern "system" {
            fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
        }
        let from: Vec<u16> = tmp.as_os_str().encode_wide().chain(Some(0)).collect();
        let to: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 0x1 | 0x8) } == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    #[cfg(not(windows))]
    {
        fs::rename(tmp, path)?;
        File::open(path.parent().ok_or("missing parent")?)?.sync_all()?;
    }
    Ok(())
}
#[cfg(windows)]
fn os_wrap(bytes: &[u8], encrypt: bool) -> Result<Vec<u8>> {
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{
            CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN,
            CryptProtectData, CryptUnprotectData,
        },
    };
    // Machine-scope DPAPI on write so the machine service account (NetworkService)
    // can read the state it protects; the scope flag is ignored on unprotect.
    let flags = CRYPTPROTECT_UI_FORBIDDEN
        | if encrypt {
            CRYPTPROTECT_LOCAL_MACHINE
        } else {
            0
        };
    let input = CRYPT_INTEGER_BLOB {
        cbData: bytes.len().try_into()?,
        pbData: bytes.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let ok = unsafe {
        if encrypt {
            CryptProtectData(
                &input,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                flags,
                &mut output,
            )
        } else {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                flags,
                &mut output,
            )
        }
    };
    if ok == 0 {
        return Err("OS key protection failed".into());
    }
    let result =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        LocalFree(output.pbData as *mut _);
    }
    Ok(result)
}
#[cfg(not(windows))]
fn os_wrap(bytes: &[u8], _encrypt: bool) -> Result<Vec<u8>> {
    Ok(bytes.to_vec())
}

/// Opens a regular file without following a final link or reparse point and without
/// blocking on a FIFO or device: the privileged applier reads the agent's state this
/// way. A pipe reached through a redirect only ever learns an identification token.
fn open_regular(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000).security_qos_flags(0x0001_0000);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err("state file is not a regular file".into());
    }
    Ok(file)
}
pub(crate) fn read_regular(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    open_regular(path)?.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("state exceeds limit".into());
    }
    Ok(bytes)
}

pub struct Store {
    dir: PathBuf,
    key: [u8; 32],
    _lock: File,
}
impl Drop for Store {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}
mod reinstallation;

impl Store {
    /// Archive deleted identity data under the existing machine-protected key.
    /// Never replay these events as a newly enrolled device.
    pub(crate) fn archive_identity(&self) -> Result<()> {
        let raw = fs::read(self.dir.join("state.bin"))?;
        if raw.len() > STATE_LIMIT { return Err("state exceeds limit".into()); }
        atomic_private(&self.dir.join(format!("retired-identity-{}.bin", uuid::Uuid::new_v4())), &raw)
    }

    /// Observational access: no creation, permission changes or waiting for a writer.
    pub fn read_existing(dir: &Path) -> Result<Self> {
        for name in ["state.lock", "state.key", "state.bin"] {
            for part in dir.join(name).ancestors() {
                let metadata = fs::symlink_metadata(part)?;
                if metadata.file_type().is_symlink() { return Err("redirected state refused".into()); }
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    if metadata.file_attributes() & 0x400 != 0 { return Err("redirected state refused".into()); }
                }
            }
        }
        let lock = open_regular(&dir.join("state.lock"))?;
        fs2::FileExt::try_lock_shared(&lock)?;
        let mut decoded = os_wrap(&read_regular(&dir.join("state.key"), 4096)?, false)?;
        let key = decoded.as_slice().try_into().map_err(|_| "invalid state key")?;
        decoded.zeroize();
        Ok(Self { dir: dir.to_owned(), key, _lock: lock })
    }

    pub fn open(dir: &Path) -> Result<Self> {
        // The SYSTEM applier opens stores under the agent's state (update-journal):
        // a junction anywhere above would redirect its writes. Checked before anything
        // is created, and again once the whole path exists.
        let refuse_redirection = || -> Result<()> {
            for part in dir.ancestors().filter(|part| !part.as_os_str().is_empty()) {
                let metadata = match fs::symlink_metadata(part) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    other => other?,
                };
                if metadata.file_type().is_symlink() {
                    return Err("state directory cannot be a symlink".into());
                }
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    if metadata.file_attributes() & 0x400 != 0 { return Err("redirected state refused".into()); }
                }
            }
            Ok(())
        };
        refuse_redirection()?;
        fs::create_dir_all(dir)?;
        refuse_redirection()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
        let lockpath = dir.join("state.lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lockpath)?;
        lock.lock_exclusive()?;
        let keypath = dir.join("state.key");
        let key = if keypath.exists() {
            if fs::symlink_metadata(&keypath)?.file_type().is_symlink() {
                return Err("key cannot be a symlink".into());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if fs::metadata(&keypath)?.permissions().mode() & 0o077 != 0 {
                    return Err("key permissions must be 0600".into());
                }
            }
            let mut decoded = os_wrap(&fs::read(&keypath)?, false)?;
            let key: [u8; 32] = decoded
                .as_slice()
                .try_into()
                .map_err(|_| "invalid state key")?;
            decoded.zeroize();
            key
        } else {
            if dir.join("state.bin").exists() {
                return Err("state key missing; refusing data loss".into());
            }
            let mut key = [0u8; 32];
            OsRng.fill_bytes(&mut key);
            let encrypted = os_wrap(&key, true)?;
            let mut file = private_file(&keypath, true)?;
            file.write_all(&encrypted)?;
            file.sync_all()?;
            key
        };
        Ok(Self {
            dir: dir.to_owned(),
            key,
            _lock: lock,
        })
    }
    pub fn load(&self) -> Result<State> {
        let p = self.dir.join("state.bin");
        if !p.exists() {
            return Ok(State::default());
        }
        let raw = read_regular(&p, STATE_LIMIT)?;
        if raw.len() < 13 || raw[0] != 1 {
            return Err("state format rejected".into());
        }
        let cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|_| "invalid encryption key")?;
        let mut plain = cipher
            .decrypt(
                Nonce::from_slice(&raw[1..13]),
                Payload {
                    msg: &raw[13..],
                    aad: AAD,
                },
            )
            .map_err(|_| "state integrity check failed")?;
        let parsed = serde_json::from_slice(&plain);
        plain.zeroize();
        Ok(parsed?)
    }
    pub fn save(&self, state: &State) -> Result<()> {
        let mut plain = serde_json::to_vec(state)?;
        if plain.len() > STATE_LIMIT - 64 {
            return Err("state is full".into());
        }
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|_| "invalid encryption key")?;
        let encrypted = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plain,
                    aad: AAD,
                },
            )
            .map_err(|_| "encryption failed")?;
        plain.zeroize();
        let mut output = vec![1];
        output.extend_from_slice(&nonce);
        output.extend(encrypted);
        atomic_private(&self.dir.join("state.bin"), &output)
    }
}

/// The one HTTP client every network call goes through: bounded timeout, no
/// redirect following, no cookie store, and the HTTPS trust the administrator
/// configured — which can only ever add a certificate authority, never disable
/// verification. See [`config::apply_tls`].
pub fn client() -> Result<reqwest::blocking::Client> {
    Ok(config::apply_tls(
        reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(8))
            .redirect(reqwest::redirect::Policy::none()),
    )?
    .build()?)
}
/// A server reply parsed from at most `limit` bytes. `.json()` reads whatever the
/// server sends: a hostile or intercepted one could exhaust the service's memory.
pub(crate) fn bounded_json<T: serde::de::DeserializeOwned>(response: reqwest::blocking::Response, limit: u64) -> Result<T> {
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut std::io::Read::take(response, limit + 1), &mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err("server reply exceeds limit".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}
pub fn api_url(state: &State, path: &str) -> Result<reqwest::Url> {
    Ok(trusted_url(&state.server_url)?.join(path)?)
}
pub fn enroll(store: &Store, provision: &Provision, hostname: &str) -> Result<()> {
    let mut state = store.load()?;
    if !state.credential.is_empty() {
        return Err("already enrolled; revoke before reprovisioning".into());
    }
    if hostname.is_empty() || hostname.len() > 128 {
        return Err("invalid hostname".into());
    }
    let url = trusted_url(&provision.server_url)?;
    let _: [u8; 32] = STANDARD
        .decode(&provision.policy_public_key)?
        .try_into()
        .map_err(|_| "invalid trust anchor")?;
    #[derive(Deserialize)]
    struct Reply {
        device_id: String,
        credential: String,
    }
    let reply=client()?.post(url.join("/v1/enroll")?).json(&serde_json::json!({"token":provision.token,"hostname":hostname,"platform":std::env::consts::OS,"version":env!("CARGO_PKG_VERSION"),"machine_domains":bootstrap::machine_domains()})).send()?.error_for_status()?;
    let reply: Reply = bounded_json(reply, 64 * 1024)?;
    if reply.credential.is_empty() {
        return Err("empty device credential".into());
    }
    state.server_url = provision.server_url.clone();
    state.public_key = provision.policy_public_key.clone();
    state.device_id = reply.device_id;
    state.credential = reply.credential;
    store.save(&state)
}
pub fn refresh(state: &mut State) -> Result<Policy> {
    if state.credential.is_empty() {
        return Err("not enrolled".into());
    }
    let response = client()?
        .get(api_url(state, "/v1/policy")?)
        .bearer_auth(&state.credential)
        .send()?;
    if matches!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
    ) {
        shadow::revoke_authorization(state);
        return Err("endpoint authorization revoked or refused".into());
    }
    let response = response.error_for_status()?;
    if response.content_length().unwrap_or(0) > 160 * 1024 {
        return Err("policy response too large".into());
    }
    let mut raw = Vec::new();
    response.take(160 * 1024 + 1).read_to_end(&mut raw)?;
    if raw.len() > 160 * 1024 {
        return Err("policy response too large".into());
    }
    let envelope: Envelope = serde_json::from_slice(&raw)?;
    let policy = verify_policy(&envelope, &state.public_key, state.max_revision, Utc::now())?;
    state.max_revision = policy.revision;
    state.policy = Some(envelope);
    Ok(policy)
}
pub fn cached_policy(state: &State) -> Result<Policy> {
    verify_policy(
        state.policy.as_ref().ok_or("policy unavailable")?,
        &state.public_key,
        state.max_revision,
        Utc::now(),
    )
}
pub fn enqueue(state: &mut State, provider: &str, characters: u32) -> Result<Uuid> {
    if !domain_ok(provider) || characters > 1_000_000 {
        return Err("invalid browser event".into());
    }
    let policy = cached_policy(state)?;
    let rule = policy.rules.iter().find(|r| {
        r.enabled && (provider == r.domain || provider.ends_with(&format!(".{}", r.domain)))
    });
    let action = if rule.is_some_and(|r| r.action == "block") {
        "blocked"
    } else {
        "observed"
    };
    let id = Uuid::new_v4();
    let event = Event {
        id,
        occurred_at: Utc::now(),
        provider: provider.to_string(),
        action: action.to_string(),
        source: "browser".to_string(),
        characters,
        labels: Vec::new(),
    };
    config::current().queue.check(state, 1, shadow::serialized_size(&event)? + 1)?;
    state.queue.push(event);
    Ok(id)
}
pub fn flush(state: &mut State) -> Result<usize> {
    if state.queue.is_empty() {
        return Ok(0);
    }
    #[derive(Deserialize)]
    struct Ack {
        accepted_ids: Vec<Uuid>,
    }
    let batch: Vec<Event> = state.queue.iter().take(100).cloned().collect();
    let response = client()?
        .post(api_url(state, "/v1/events")?)
        .bearer_auth(&state.credential)
        .json(&serde_json::json!({"events":batch}))
        .send()?;
    if matches!(response.status().as_u16(), 401 | 403) {
        shadow::revoke_authorization(state);
        return Err("installation authorization refused".into());
    }
    let ack: Ack = bounded_json(response.error_for_status()?, 256 * 1024)?;
    if ack
        .accepted_ids
        .iter()
        .any(|id| !batch.iter().any(|e| e.id == *id))
    {
        return Err("invalid acknowledgement".into());
    }
    let before = state.queue.len();
    state.queue.retain(|e| !ack.accepted_ids.contains(&e.id));
    Ok(before - state.queue.len())
}
pub fn frame<R: Read>(input: &mut R) -> Result<Option<serde_json::Value>> {
    frame_limit(input,128*1024)
}
pub(crate) fn frame_limit<R:Read>(input:&mut R,limit:usize)->Result<Option<serde_json::Value>>{
    let mut header = [0u8; 4];
    match input.read(&mut header[..1])? {
        0 => return Ok(None),
        1 => {}
        _ => unreachable!(),
    };
    input.read_exact(&mut header[1..])?;
    let size = u32::from_le_bytes(header) as usize;
    if size == 0 || size > limit {
        return Err("native message length rejected".into());
    }
    let mut bytes = vec![0u8; size];
    input.read_exact(&mut bytes)?;
    Ok(Some(serde_json::from_slice(&bytes)?))
}
pub fn write_frame<W: Write>(out: &mut W, value: &serde_json::Value) -> Result<()> {
    let raw = serde_json::to_vec(value)?;
    out.write_all(&(raw.len() as u32).to_le_bytes())?;
    out.write_all(&raw)?;
    out.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    // The root applier reads the agent's state: a FIFO or a link to /dev/zero planted
    // there must be refused at once, never block it nor exhaust its memory.
    #[cfg(unix)]
    #[test]
    fn a_planted_fifo_or_device_link_is_refused_without_blocking() {
        let home = tempfile::tempdir().unwrap();
        Store::open(home.path()).unwrap().save(&State::default()).unwrap();
        let state = home.path().join("state.bin");
        std::fs::remove_file(&state).unwrap();
        let path = std::ffi::CString::new(state.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        let started = std::time::Instant::now();
        assert!(Store::read_existing(home.path()).and_then(|store| store.load()).is_err());
        assert!(started.elapsed() < std::time::Duration::from_secs(2), "the FIFO blocked the reader");
        std::fs::remove_file(&state).unwrap();
        std::os::unix::fs::symlink("/dev/zero", &state).unwrap();
        assert!(Store::read_existing(home.path()).and_then(|store| store.load()).is_err());
    }
    // The SYSTEM applier opens stores under the agent's state: a junction the agent
    // plants there must not redirect it (a real junction, as a standard user can make).
    #[cfg(windows)]
    #[test]
    fn a_store_under_a_junction_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let elsewhere = root.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        let junction = root.path().join("update-journal");
        let made = std::process::Command::new("cmd").args(["/C", "mklink", "/J"]).arg(&junction).arg(&elsewhere)
            .stdout(std::process::Stdio::null()).status().unwrap();
        assert!(made.success(), "junction creation failed");
        assert!(Store::open(&junction.join("installation")).is_err());
        assert!(!elsewhere.join("installation").exists(), "the store followed the junction");
        assert!(Store::open(&root.path().join("plain").join("installation")).is_ok());
    }
    fn signed(revision: u64) -> (Envelope, String) {
        let key = SigningKey::from_bytes(&[37u8; 32]);
        let now = Utc::now();
        let p = Policy {
            version: 1,
            revision,
            issued_at: now,
            expires_at: now + chrono::Duration::minutes(10),
            rules: vec![],
            collection: Collection {
                prompt_content: false,
            },
        };
        let payload = serde_json::to_vec(&p).unwrap();
        let sig = key.sign(&payload);
        (
            Envelope {
                payload: STANDARD.encode(&payload),
                signature: STANDARD.encode(sig.to_bytes()),
            },
            STANDARD.encode(key.verifying_key().as_bytes()),
        )
    }
    #[test]
    fn signature_tamper_replay_expiry() {
        let (e, k) = signed(4);
        assert!(verify_policy(&e, &k, 4, Utc::now()).is_ok());
        assert!(verify_policy(&e, &k, 5, Utc::now()).is_err());
        assert!(verify_policy(&e, &k, 0, Utc::now() + chrono::Duration::hours(1)).is_err());
        let mut tampered = e.clone();
        tampered.payload = STANDARD.encode(b"{}");
        assert!(verify_policy(&tampered, &k, 0, Utc::now()).is_err());
        assert!(verify_policy(&e, &STANDARD.encode([1u8; 32]), 0, Utc::now()).is_err());
    }
    #[test]
    fn urls_are_origins() {
        for url in [
            "http://localhost:4020",
            "https://console.example.test",
            "http://[::1]:4020",
        ] {
            assert!(trusted_url(url).is_ok(), "{url}");
        }
        for url in [
            "http://localhost.attacker.test",
            "http://localhost@attacker.test",
            "https://user:pass@example.test",
            "https://example.test/path",
            "http://example.test",
            "https://example.test/?secret=x",
        ] {
            assert!(trusted_url(url).is_err(), "{url}");
        }
    }
    #[test]
    fn queue_persists_encrypted_and_tampering_fails() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let mut state = State::default();
        state.credential = "synthetic-sensitive-device-secret".into();
        store.save(&state).unwrap();
        assert_eq!(store.load().unwrap().credential, state.credential);
        let path = dir.path().join("state.bin");
        let mut bytes = fs::read(&path).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains(&state.credential));
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(path, bytes).unwrap();
        assert!(store.load().is_err());
    }
    #[test]
    fn no_unsigned_offline_capture() {
        let mut state = State::default();
        assert!(enqueue(&mut state, "chatgpt.com", 4).is_err());
        assert!(state.queue.is_empty());
    }
    #[test]
    fn native_input_is_bounded() {
        let mut raw = (129 * 1024u32).to_le_bytes().to_vec();
        assert!(frame(&mut raw.as_slice()).is_err());
        raw = vec![5, 0, 0, 0, b'{'];
        assert!(frame(&mut raw.as_slice()).is_err());
        assert!(frame(&mut [].as_slice()).unwrap().is_none());
    }
    #[test]
    fn round_trip_native_frame() {
        let v = serde_json::json!({"op":"policy"});
        let mut out = Vec::new();
        write_frame(&mut out, &v).unwrap();
        assert_eq!(frame(&mut out.as_slice()).unwrap().unwrap(), v);
    }
    #[test]
    fn browser_event_never_has_prompt_content() {
        let (e, k) = signed(1);
        let mut s = State {
            public_key: k,
            policy: Some(e),
            ..State::default()
        };
        enqueue(&mut s, "chatgpt.com", 42).unwrap();
        let v = serde_json::to_value(&s.queue[0]).unwrap();
        assert_eq!(v["characters"], 42);
        assert!(v.get("prompt").is_none());
        assert_eq!(v["source"], "browser");
    }
}

#[cfg(test)]
mod browser_broker_tests;
