//! Independent release trust: the policy signing key cannot authorize executable code.
use crate::{Envelope, Result, State, Store};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Release {
    #[serde(default = "binary_format")]
    pub format: String,
    pub version: String,
    pub edition: String,
    pub platform: String,
    pub protocol: u32,
    pub sha256: String,
    pub size: u64,
    pub expires_at: DateTime<Utc>,
    pub artifact: String,
    #[serde(default)]
    pub rollback_from: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct UpdateReport {
    id: uuid::Uuid,
    version: String,
    status: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct UnsettledUpdate {
    edition: String,
    version: String,
    boot_marker: String,
    reason: String,
    product_code: String,
    previous_version: String,
    began: DateTime<Utc>,
    previous_receipt: Option<String>,
}
fn same_identity(a: &State, b: &State) -> bool {
    a.device_id == b.device_id && a.credential == b.credential && a.server_url == b.server_url && a.public_key == b.public_key
}
/// The applier's outcome journal and lease sit beside the agent's state, not in it:
/// a directory the agent account can write is no place for SYSTEM to write, since a
/// junction planted there redirects the write. The installer lets the agent read it.
fn journal_root(home: &Path) -> PathBuf {
    crate::config::beside(home, "update-journal")
}
fn not_found(error: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
    error.downcast_ref::<std::io::Error>().is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
}
/// A store read without creating or taking a write lock on anything: how the
/// privileged applier reads the agent's state, and the agent reads the journal. An
/// absent store reads as empty. A writer holding its lock is waited out briefly.
fn read_store(dir: &Path) -> Result<State> {
    let start = Instant::now();
    loop {
        match Store::read_existing(dir).and_then(|store| store.load()) {
            Ok(state) => return Ok(state),
            Err(error) if not_found(&*error) => return Ok(State::default()),
            Err(_) if start.elapsed() < Duration::from_secs(10) => std::thread::sleep(Duration::from_millis(200)),
            Err(error) => return Err(error),
        }
    }
}
fn identity(home: &Path) -> Result<State> {
    read_store(home)
}
fn journal_read(home: &Path, identity: &State) -> Result<State> {
    let installation = uuid::Uuid::parse_str(&identity.device_id)?;
    let state = read_store(&journal_root(home).join(installation.to_string()))?;
    if !state.credential.is_empty() && !same_identity(identity, &state) { return Err("update journal belongs to another installation".into()); }
    Ok(state)
}
fn journal(home: &Path, identity: &State) -> Result<(Store, State)> {
    // Distinct installations keep distinct outcome journals, including after
    // an explicitly provisioned change of organization on the same machine.
    let installation = uuid::Uuid::parse_str(&identity.device_id)?;
    let store = Store::open(&journal_root(home).join(installation.to_string()))?;
    let mut state = store.load()?;
    if state.credential.is_empty() {
        state.device_id = identity.device_id.clone();
        state.credential = identity.credential.clone();
        state.server_url = identity.server_url.clone();
        state.public_key = identity.public_key.clone();
    }
    if !same_identity(identity, &state) { return Err("update journal belongs to another installation".into()); }
    Ok((store, state))
}
fn unresolved(home: &Path) -> Result<bool> {
    let identity = identity(home)?;
    Ok(journal_read(home, &identity)?.unsettled_update.is_some())
}
fn save_unsettled(home: &Path, identity: &State, pending: Option<UnsettledUpdate>) -> Result<()> {
    let latest = self::identity(home)?;
    if !same_identity(identity, &latest) { return Err("installation changed during update".into()); }
    let (store, mut state) = journal(home, identity)?;
    state.unsettled_update = pending;
    store.save(&state)
}
fn queue_report(home: &Path, identity: &State, version: &str, status: &str) -> Result<()> {
    let latest = self::identity(home)?;
    if !same_identity(identity, &latest) { return Err("installation changed during update".into()); }
    let (store, mut state) = journal(home, identity)?;
    if state.update_reports.len() >= 32 { return Err("update report queue full".into()); }
    state.update_reports.push(UpdateReport { id: uuid::Uuid::new_v4(), version: version.into(), status: status.into() });
    store.save(&state)
}
pub fn flush_reports(home: &Path) -> Result<()> {
    loop {
        let identity = self::identity(home)?;
        let state = { journal(home, &identity)?.1 };
        let Some(report) = state.update_reports.first() else { return Ok(()); };
        crate::client()?.post(crate::api_url(&identity, "/v2/update/status")?)
            .bearer_auth(&identity.credential)
            .json(&serde_json::json!({"version":report.version,"status":report.status}))
            .send()?.error_for_status()?;
        let latest_identity = self::identity(home)?;
        if !same_identity(&identity, &latest_identity) { return Err("installation changed while reporting update".into()); }
        let (store, mut latest) = journal(home, &identity)?;
        latest.update_reports.retain(|row| row.id != report.id);
        store.save(&latest)?;
    }
}
#[cfg(windows)]
fn boot_registry(marker: &str, create: bool) -> Result<bool> {
    uuid::Uuid::parse_str(marker)?;
    #[link(name="advapi32")]
    unsafe extern "system" {
        fn RegCreateKeyExW(key: isize, sub: *const u16, reserved: u32, class: *const u16, options: u32, access: u32, security: *const std::ffi::c_void, result: *mut isize, disposition: *mut u32) -> i32;
        fn RegOpenKeyExW(key: isize, sub: *const u16, options: u32, access: u32, result: *mut isize) -> i32;
        fn RegCloseKey(key: isize) -> i32;
    }
    let path: Vec<u16> = format!(r"SOFTWARE\Milvago\UpdateBoot\{marker}").encode_utf16().chain(Some(0)).collect();
    let mut handle = 0isize;
    let hklm = 0x80000002u32 as i32 as isize;
    // REG_OPTION_VOLATILE, KEY_READ and explicit 64-bit registry view.
    let status = if create {
        let mut disposition = 0u32;
        unsafe { RegCreateKeyExW(hklm, path.as_ptr(), 0, std::ptr::null(), 1, 0x20119,
            std::ptr::null(), &mut handle, &mut disposition) }
    } else {
        unsafe { RegOpenKeyExW(hklm, path.as_ptr(), 0, 0x20119, &mut handle) }
    };
    if status == 2 && !create { return Ok(false); }
    if status != 0 { return Err(std::io::Error::from_raw_os_error(status).into()); }
    unsafe { RegCloseKey(handle); }
    Ok(true)
}
fn boot_marker() -> Result<String> {
    #[cfg(windows)]
    {
        let marker = uuid::Uuid::new_v4().to_string();
        boot_registry(&marker, true)?;
        Ok(marker)
    }
    #[cfg(not(windows))]
    { Err("Windows update recovery requires Windows".into()) }
}
fn reboot_observed(marker: &str) -> Result<bool> {
    #[cfg(windows)]
    { Ok(!boot_registry(marker, false)?) }
    #[cfg(not(windows))]
    { let _ = marker; Ok(false) }
}
/// A timeout remains unresolved until a reboot ends the previous installer
/// processes. Expiration of an arbitrary lease never authorizes a new attempt.
fn reconcile(home: &Path, target: &Path, edition: &str) -> Result<()> {
    let state = identity(home)?;
    let journal = { journal(home, &state)?.1 };
    let Some(pending) = journal.unsettled_update.as_ref() else { return Ok(()); };
    if pending.edition != edition { return Err("pending update edition mismatch".into()); }
    if !reboot_observed(&pending.boot_marker)? { return Ok(()); }
    if !installer_idle()? { return Ok(()); }
    if msi_product_installed(&pending.product_code)? {
        if !service_healthy(target, edition, &pending.version) { return Ok(()); }
        queue_report(home, &state, &pending.version, "installed")?;
    } else {
        if !rollback_verified(&pending.product_code, edition, pending.began, pending.previous_receipt.as_deref())?
            || !service_healthy(target, edition, &pending.previous_version) { return Ok(()); }
        queue_report(home, &state, &pending.previous_version, "rolled_back")?;
    }
    save_unsettled(home, &state, None)
}
#[cfg(windows)]
fn installer_idle() -> Result<bool> {
    use windows_service::{service::{ServiceAccess, ServiceControlAccept, ServiceState}, service_manager::{ServiceManager, ServiceManagerAccess}};
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let status = manager.open_service("msiserver", ServiceAccess::QUERY_STATUS)?.query_status()?;
    Ok(status.current_state == ServiceState::Stopped || status.controls_accepted.contains(ServiceControlAccept::STOP))
}
#[cfg(not(windows))]
fn installer_idle() -> Result<bool> { Ok(false) }
#[cfg(windows)]
fn msi_product_installed(product: &str) -> Result<bool> {
    uuid::Uuid::parse_str(product.trim_matches(['{', '}']))?;
    #[link(name="msi")]
    unsafe extern "system" { fn MsiQueryProductStateW(product: *const u16) -> i32; }
    let product: Vec<u16> = product.encode_utf16().chain(Some(0)).collect();
    Ok(unsafe { MsiQueryProductStateW(product.as_ptr()) } == 5)
}
#[cfg(not(windows))]
fn msi_product_installed(_: &str) -> Result<bool> { Ok(false) }


#[cfg(any(windows, test))]
fn health_target_in(root: &Path, name: &str, edition: &str, expected: &str) -> Result<PathBuf> {
    version(expected)?;
    let legacy = root.join(name);
    let marker = installation(&legacy)?.ok_or("installed release marker missing")?;
    if marker.format != "msi" || marker.scope != "machine" || marker.edition != edition
        || marker.version.as_deref() != Some(expected) {
        return Err("installed release marker differs from health request".into());
    }
    let candidate = root.join("runtime").join(expected).join(name);
    match fs::symlink_metadata(&candidate) {
        Ok(_) => { regular_path(&candidate)?; Ok(candidate) }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            regular_path(&legacy)?;
            Ok(legacy)
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(windows)]
fn managed_health_target(target: &Path, edition: &str, expected: &str) -> Result<PathBuf> {
    let (folder, name) = match edition {
        "community" => ("Browser", "milvago-browser-agent.exe"),
        "commercial" => ("Commercial", "milvago-commercial-bridge.exe"),
        _ => return Err("invalid health edition".into()),
    };
    // Keep portable installs on their original path. MSI outcomes instead follow
    // the protected current marker, since the old runtime survives the upgrade.
    let Some(marker) = installation(target)? else { return Ok(target.to_path_buf()); };
    if marker.format != "msi" || marker.scope != "machine" { return Ok(target.to_path_buf()); }
    let programs = std::env::var_os("ProgramW6432")
        .or_else(|| std::env::var_os("ProgramFiles")).ok_or("Program Files missing")?;
    let root = PathBuf::from(programs).join("Milvago").join(folder);
    let same = |a: &Path, b: &Path| a.as_os_str().to_string_lossy()
        .eq_ignore_ascii_case(&b.as_os_str().to_string_lossy());
    let legacy = root.join(name);
    let runtime = target.parent().and_then(|p| p.file_name()).and_then(|p| p.to_str())
        .filter(|v| version(v).is_ok())
        .map(|v| root.join("runtime").join(v).join(name));
    if !same(target, &legacy) && !runtime.as_ref().is_some_and(|p| same(target, p)) {
        return Err("MSI health target is outside installed runtime".into());
    }
    let _root = crate::cache_windows::Directory::installed(&root)?;
    health_target_in(&root, name, edition, expected)
}

fn service_healthy(target: &Path, edition: &str, expected: &str) -> bool {
    #[cfg(windows)]
    let resolved = match managed_health_target(target, edition, expected) {
        Ok(path) => path,
        Err(_) => return false,
    };
    #[cfg(windows)]
    let target = resolved.as_path();
    #[cfg(windows)]
    let _installed_file = if installation(target).ok().flatten().is_some_and(|m| m.format == "msi" && m.scope == "machine") {
        let Some(parent) = target.parent() else { return false; };
        let Ok(directory) = crate::cache_windows::Directory::installed(parent) else { return false; };
        let Some(name) = target.file_name() else { return false; };
        let Ok(file) = directory.hold_file(name) else { return false; };
        Some((directory, file))
    } else { None };
    if !binary_matches(target, expected) { return false; }
    let mut command = Command::new(target);
    command.arg("health").stdin(Stdio::null()).stderr(Stdio::null()).stdout(Stdio::piped());
    hidden(&mut command);
    let Ok(mut child) = command.spawn() else { return false; };
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut output = String::new();
                if let Some(stream) = child.stdout.take() {
                    if stream.take(4096).read_to_string(&mut output).is_err() { return false; }
                }
                return status.success() && serde_json::from_str(&output).is_ok_and(|value| crate::health::matches(&value, edition, expected));
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
            _ => { let _ = child.kill(); let _ = child.wait(); return false; }
        }
    }
}
fn binary_format() -> String {
    "binary".into()
}
fn version(s: &str) -> Result<[u32; 3]> {
    let parts: Vec<_> = s.split('.').collect();
    if parts.len() != 3
        || s.len() > 32
        || parts.iter().any(|p| {
            p.is_empty()
                || p.len() > 6
                || (p.len() > 1 && p.starts_with('0'))
                || !p.bytes().all(|b| b.is_ascii_digit())
        })
    {
        return Err("invalid release version".into());
    }
    Ok([parts[0].parse()?, parts[1].parse()?, parts[2].parse()?])
}
fn verify_signature(envelope: &Envelope, key: &str) -> Result<Vec<u8>> {
    if envelope.payload.len() > 16384 {
        return Err("release manifest too large".into());
    }
    let key: [u8; 32] = STANDARD
        .decode(key)?
        .try_into()
        .map_err(|_| "invalid update key")?;
    let raw = STANDARD.decode(&envelope.payload)?;
    VerifyingKey::from_bytes(&key)?.verify_strict(
        &raw,
        &Signature::from_slice(&STANDARD.decode(&envelope.signature)?)?,
    )?;
    Ok(raw)
}

fn decode_release(raw: &[u8], edition: &str, platform: &str) -> Result<Release> {
    let r: Release = serde_json::from_slice(&raw)?;
    if !matches!(edition, "community" | "commercial")
        || r.edition != edition
        || r.platform != platform
        || !matches!(platform, "windows" | "linux")
        || r.protocol != 2
        || r.expires_at <= Utc::now()
        || r.size == 0
        || r.size > 128 * 1024 * 1024
        || !matches!(r.format.as_str(), "binary" | "msi")
        || (r.format == "msi" && r.platform != "windows")
        || r.sha256.len() != 64
        || !r
            .sha256
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        || r.artifact != format!("/v2/update/artifact/{}", r.sha256)
        || r.rollback_from.len() > 50
    {
        return Err("release constraints rejected".into());
    }
    version(&r.version)?;
    for allowed in &r.rollback_from {
        version(allowed)?;
    }
    Ok(r)
}

fn release_newer(release: &Release, current: &str) -> Result<bool> {
    let target = version(&release.version)?;
    let installed = version(current)?;
    if target < installed {
        return Err("release downgrade or replay rejected".into());
    }
    Ok(target > installed)
}

fn select_release(
    envelope: &Envelope,
    key: &str,
    next: Option<&str>,
    edition: &str,
    platform: &str,
    current: &str,
) -> Result<(Option<Release>, bool)> {
    let (raw, rotated) = match verify_signature(envelope, key) {
        Ok(raw) => (raw, false),
        Err(primary) => match next {
            Some(next) => (verify_signature(envelope, next)?, true),
            None => return Err(primary),
        },
    };
    let release = decode_release(&raw, edition, platform)?;
    if !release_newer(&release, current)? {
        return Ok((None, rotated));
    }
    Ok((Some(release), rotated))
}

pub fn verify(
    envelope: &Envelope,
    key: &str,
    edition: &str,
    platform: &str,
    current: &str,
) -> Result<Release> {
    let raw = verify_signature(envelope, key)?;
    let release = decode_release(&raw, edition, platform)?;
    if !release_newer(&release, current)? {
        return Err("release downgrade or replay rejected".into());
    }
    Ok(release)
}
fn check_hash(r: &Release, bytes: &[u8]) -> Result<()> {
    if bytes.len() as u64 != r.size || crate::sha256_hex(bytes) != r.sha256 {
        return Err("release checksum rejected".into());
    }
    Ok(())
}
/// Successor trust anchor, published in a document signed by the **current** anchor.
/// Signing it with the policy key would let a compromised server authorize code, so
/// the chain deliberately stays inside the release key.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Anchor {
    next_public_key: String,
    expires_at: DateTime<Utc>,
}
fn anchor_key(raw: &str) -> Result<()> {
    let bytes: [u8; 32] = STANDARD
        .decode(raw)?
        .try_into()
        .map_err(|_| "invalid successor anchor")?;
    VerifyingKey::from_bytes(&bytes)?;
    Ok(())
}
/// What a release fetch trusts. The privileged applier builds it from the anchor only
/// SYSTEM can write ([`read_anchor`]), never from the agent-writable state: an account
/// that can rewrite `state.bin` would otherwise choose the key that authorizes the MSI
/// LocalSystem installs. The credential is the one value still taken from the state;
/// it lets a caller download a manifest, never sign one.
pub(crate) struct Trust {
    key: String,
    next: Option<String>,
    origin: String,
    credential: String,
}
impl Trust {
    fn from_state(state: &State) -> Result<Self> {
        Ok(Self {
            key: state.update_public_key.clone().ok_or("update trust anchor not provisioned")?,
            next: state.update_public_key_next.clone(),
            origin: state.server_url.clone(),
            credential: state.credential.clone(),
        })
    }
    fn url(&self, path: &str) -> Result<reqwest::Url> {
        Ok(crate::trusted_url(&self.origin)?.join(path)?)
    }
}
/// Release trust pinned for the privileged applier, outside the agent's state.
/// Written by the installer (SYSTEM) from the organization MSI, or once from the
/// state at the first privileged update of an installation that predates it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseAnchor {
    pub update_public_key: String,
    pub server_url: String,
}
impl ReleaseAnchor {
    fn validate(&self) -> Result<()> {
        anchor_key(&self.update_public_key)?;
        crate::trusted_url(&self.server_url)?;
        Ok(())
    }
}
#[cfg(windows)]
fn anchor_directory(edition: &str) -> Result<crate::cache_windows::Directory> {
    crate::cache_windows::Directory::open(&crate::cache_windows::root(edition)?.join("private"), true)
}
#[cfg(windows)]
pub fn read_anchor(edition: &str) -> Result<Option<ReleaseAnchor>> {
    let directory = anchor_directory(edition)?;
    if !directory.contains("release.json")? {
        return Ok(None);
    }
    let anchor: ReleaseAnchor = serde_json::from_slice(&directory.read("release.json", 4096)?)?;
    anchor.validate()?;
    Ok(Some(anchor))
}
#[cfg(windows)]
pub fn write_anchor(edition: &str, anchor: &ReleaseAnchor) -> Result<()> {
    anchor.validate()?;
    anchor_directory(edition)?.write("release.json", &serde_json::to_vec(anchor)?)
}
/// Linux: `release.json` in the edition's `/etc` directory (see
/// `config::directory`), root-owned and never group or world writable. The agent
/// account cannot write `/etc`.
#[cfg(unix)]
fn anchor_path(edition: &str) -> Result<PathBuf> {
    Ok(PathBuf::from(match edition {
        "community" => "/etc/milvago-browser/release.json",
        "commercial" => "/etc/milvago-commercial/release.json",
        _ => return Err("invalid anchor edition".into()),
    }))
}
/// The root applier (systemd `milvago-<edition>-updater.service`, started by a path
/// unit when the agent drops `update-request` in its state). It only reads that
/// state: any file root created there would be root's, and a directory the agent
/// controls is no place for root to write. Trust comes from the `/etc` anchor.
/// `service` is the agent unit to restart, from the root-written unit command line.
#[cfg(unix)]
pub fn apply_root(home: &Path, target: &Path, edition: &str, service: &str) -> Result<Applied> {
    // The agent's request file stays (root cannot write the agent's state), and the
    // agent controls how often it changes: the applier bounds itself, from root's /etc.
    let last_run = anchor_path(edition)?.with_file_name(".applier-run");
    if fs::symlink_metadata(&last_run).and_then(|m| m.modified()).is_ok_and(|at| at.elapsed().is_ok_and(|age| age < Duration::from_secs(3600))) {
        return Ok(Applied::NoUpdate);
    }
    crate::atomic_private(&last_run, b"")?;
    crate::config::open(home);
    if !service.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') || service.is_empty() {
        return Err("invalid agent unit".into());
    }
    let state = {
        let start = Instant::now();
        loop {
            match Store::read_existing(home).and_then(|store| store.load()) {
                Ok(state) => break state,
                Err(_) if start.elapsed() < Duration::from_secs(10) => std::thread::sleep(Duration::from_millis(200)),
                Err(error) => return Err(error),
            }
        }
    };
    let current = installed_version(target)?;
    let trust = pinned_trust(edition, &state)?;
    let Some((release, bytes, rotated)) = fetch_trusted(&trust, edition, &current, true)? else {
        return Ok(Applied::NoUpdate);
    };
    if rotated {
        let next = trust.next.clone().ok_or("rotated release without successor")?;
        write_anchor(edition, &ReleaseAnchor { update_public_key: next, server_url: trust.origin.clone() })?;
    }
    if !install(target, &release, &bytes)? {
        return Ok(Applied::RolledBack);
    }
    let status = Command::new("/usr/bin/systemctl").args(["try-restart", &format!("{service}.service")])
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status()?;
    Ok(if status.success() { Applied::Installed } else { Applied::Failed })
}
/// Asks the root applier for an update, at most once an hour: every request makes it
/// download the artifact again, and one that keeps failing must not do so every minute.
#[cfg(unix)]
fn request_root_update(home: &Path) -> Result<bool> {
    static LAST: std::sync::Mutex<Option<Instant>> = std::sync::Mutex::new(None);
    let mut last = LAST.lock().unwrap_or_else(|e| e.into_inner());
    if last.is_some_and(|at| at.elapsed() < Duration::from_secs(3600)) {
        return Ok(false);
    }
    crate::atomic_private(&home.join("update-request"), b"{}")?;
    *last = Some(Instant::now());
    Ok(false)
}
#[cfg(unix)]
pub fn read_anchor(edition: &str) -> Result<Option<ReleaseAnchor>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let path = anchor_path(edition)?;
    let file = match OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        other => other?,
    };
    regular_path(&path)?;
    for metadata in [file.metadata()?, fs::metadata(path.parent().ok_or("anchor parent missing")?)?] {
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err("release anchor must be root-owned and not group or world writable".into());
        }
    }
    let mut bytes = Vec::new();
    file.take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err("release anchor exceeds limit".into());
    }
    let anchor: ReleaseAnchor = serde_json::from_slice(&bytes)?;
    anchor.validate()?;
    Ok(Some(anchor))
}
#[cfg(unix)]
pub fn write_anchor(edition: &str, anchor: &ReleaseAnchor) -> Result<()> {
    anchor.validate()?;
    let path = anchor_path(edition)?;
    let parent = path.parent().ok_or("anchor parent missing")?;
    fs::create_dir_all(parent)?;
    regular_path(parent)?;
    crate::atomic_private(&path, &serde_json::to_vec(anchor)?)
}
/// The privileged applier's trust: the pinned anchor, plus a successor the pinned
/// key itself signed. Without an anchor it refuses: taking one from the state would
/// let the account that writes the state choose the key (the installer pins it, from
/// the organization package or the one Windows Installer keeps).
fn pinned_trust(edition: &str, state: &State) -> Result<Trust> {
    let anchor = read_anchor(edition)?
        .ok_or("release anchor not provisioned; reinstall the organization package")?;
    let mut trust = anchored(anchor, state);
    // Never the successor recorded in the state: re-verify it against the pinned key.
    trust.next = successor(&trust).unwrap_or(None);
    Ok(trust)
}
fn anchored(anchor: ReleaseAnchor, state: &State) -> Trust {
    Trust { key: anchor.update_public_key, next: None, origin: anchor.server_url, credential: state.credential.clone() }
}
/// Learns the successor anchor, if the server publishes one. Best effort: a missing
/// or unverifiable document leaves the pinned anchor untouched.
pub fn refresh_anchor(state: &mut State) -> Result<bool> {
    let Some(next) = successor(&Trust::from_state(state)?)? else {
        return Ok(false);
    };
    let changed = state.update_public_key_next.as_deref() != Some(next.as_str());
    state.update_public_key_next = Some(next);
    Ok(changed)
}
/// The successor key published in a document the trusted key signed, if any.
fn successor(trust: &Trust) -> Result<Option<String>> {
    let key = trust.key.clone();
    let response = crate::client()?
        .get(trust.url("/v2/update/anchor")?)
        .bearer_auth(&trust.credential)
        .send()?;
    if response.status().as_u16() == 204 {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    response.error_for_status()?.take(8193).read_to_end(&mut bytes)?;
    if bytes.len() > 8192 {
        return Err("anchor response too large".into());
    }
    let envelope: Envelope = serde_json::from_slice(&bytes)?;
    let public: [u8; 32] = STANDARD
        .decode(&key)?
        .try_into()
        .map_err(|_| "invalid update key")?;
    let raw = STANDARD.decode(&envelope.payload)?;
    VerifyingKey::from_bytes(&public)?.verify_strict(
        &raw,
        &Signature::from_slice(&STANDARD.decode(&envelope.signature)?)?,
    )?;
    let anchor: Anchor = serde_json::from_slice(&raw)?;
    if anchor.expires_at <= Utc::now() || anchor.next_public_key == key {
        return Err("successor anchor expired or unchanged".into());
    }
    anchor_key(&anchor.next_public_key)?;
    Ok(Some(anchor.next_public_key))
}
/// Returns the release, its bytes, and whether it verified against the successor
/// anchor rather than the pinned one (which completes a key rotation).
/// A fleet managed by Intune, SCCM or GPO owns the agent's version: its tool detects the
/// product and would reinstall the old package after every self-update. Either machine
/// value turns the agent's own updates off: the policy (GPO/Intune)
/// `HKLM\SOFTWARE\Policies\Milvago` `DisableSelfUpdate`=1, or the installer's
/// `HKLM\SOFTWARE\Milvago\<edition>` `SelfUpdate`=0 (MSI property `MILVAGO_SELF_UPDATE=0`).
/// Both keys are writable by administrators only.
#[cfg(windows)]
fn self_update_disabled(edition: &str) -> bool {
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn RegGetValueW(key: isize, sub: *const u16, value: *const u16, flags: u32, kind: *mut u32, data: *mut std::ffi::c_void, size: *mut u32) -> i32;
    }
    let read = |sub: &str, value: &str| -> Option<u32> {
        let sub: Vec<u16> = sub.encode_utf16().chain(Some(0)).collect();
        let value: Vec<u16> = value.encode_utf16().chain(Some(0)).collect();
        let (mut data, mut size) = (0u32, 4u32);
        // RRF_RT_REG_DWORD | RRF_SUBKEY_WOW6464KEY: a DWORD, from the 64-bit view.
        let status = unsafe { RegGetValueW(0x80000002u32 as i32 as isize, sub.as_ptr(), value.as_ptr(), 0x0001_0010,
            std::ptr::null_mut(), std::ptr::from_mut(&mut data).cast(), &mut size) };
        (status == 0).then_some(data)
    };
    read(r"SOFTWARE\Policies\Milvago", "DisableSelfUpdate") == Some(1)
        || read(&format!(r"SOFTWARE\Milvago\{edition}"), "SelfUpdate") == Some(0)
}
#[cfg(not(windows))]
fn self_update_disabled(_: &str) -> bool { false }

/// `download` is false for the agent's preflight: whoever applies the release fetches
/// and verifies it again, so the preflight never needs the artifact itself.
pub fn fetch(state: &State, edition: &str, current: &str, download: bool) -> Result<Option<(Release, Vec<u8>, bool)>> {
    fetch_trusted(&Trust::from_state(state)?, edition, current, download)
}
fn fetch_trusted(trust: &Trust, edition: &str, current: &str, download: bool) -> Result<Option<(Release, Vec<u8>, bool)>> {
    // The one path both the agent and the privileged applier take to a release.
    static REPORTED: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(2);
    let disabled = self_update_disabled(edition);
    if REPORTED.swap(u8::from(disabled), std::sync::atomic::Ordering::AcqRel) != u8::from(disabled) && disabled {
        crate::log::info("self-update disabled by machine policy (DisableSelfUpdate or SelfUpdate=0); the deployment tool owns versions");
    }
    if disabled {
        return Ok(None);
    }
    let response = crate::client()?
        .get(trust.url("/v2/update")?)
        .bearer_auth(&trust.credential)
        .send()?;
    if response.status().as_u16() == 204 {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    response
        .error_for_status()?
        .take(32769)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 32768 {
        return Err("manifest response too large".into());
    }
    let envelope: Envelope = serde_json::from_slice(&bytes)?;
    let (release, rotated) = select_release(
        &envelope,
        &trust.key,
        trust.next.as_deref(),
        edition,
        std::env::consts::OS,
        current,
    )?;
    let Some(release) = release else { return Ok(None); };
    let mut bytes = Vec::new();
    if !download {
        return Ok(Some((release, bytes, rotated)));
    }
    crate::client()?
        .get(trust.url(&release.artifact)?)
        .bearer_auth(&trust.credential)
        // The client's 8 s bound covers the whole body: a 10 MB installer then needs
        // ~11 Mbit/s sustained, which a scanning proxy or a branch VPN never gives.
        .timeout(Duration::from_secs(600))
        .send()?
        .error_for_status()?
        .take(release.size + 1)
        .read_to_end(&mut bytes)?;
    check_hash(&release, &bytes)?;
    Ok(Some((release, bytes, rotated)))
}
fn hidden(command: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    #[cfg(not(windows))]
    let _ = command;
}
/// Runs the installed binary's own `--version` and returns what it reported.
fn report_version(target: &Path) -> Option<String> {
    let mut command = Command::new(target);
    command
        .arg("--version")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(Stdio::piped());
    hidden(&mut command);
    let mut child = command.spawn().ok()?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut text = String::new();
                if let Some(output) = child.stdout.take() {
                    let _ = output.take(1024).read_to_string(&mut text);
                }
                if !status.success()
                    || !(text.starts_with("Milvago ")
                        || text.starts_with("Agent Community ")
                        || text.starts_with("Agent Commercial "))
                {
                    return None;
                }
                return Some(text);
            }
            Ok(None) if start.elapsed() < Duration::from_secs(10) => {
                std::thread::sleep(Duration::from_millis(100))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}
fn binary_matches(target: &Path, expected: &str) -> bool {
    report_version(target).is_some_and(|text| text.split_whitespace().any(|part| part == expected))
}
/// The version the installed binary reports about itself.
///
/// The privileged applier must never take the current version from an argument:
/// `verify` only rejects a release older than the installed one, so a caller that
/// understates the installed version turns almost any signed release into an
/// apparent upgrade. Reading it from the binary closes that downgrade path.
pub fn installed_version(target: &Path) -> Result<String> {
    let text = report_version(target).ok_or("installed agent did not report a version")?;
    let candidate = text
        .split_whitespace()
        .next_back()
        .ok_or("empty version report")?;
    version(candidate)?;
    Ok(candidate.into())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Installation {
    format: String,
    edition: String,
    scope: String,
    #[serde(default)]
    version: Option<String>,
}
fn regular_path(path: &Path) -> Result<()> {
    for part in path.ancestors() {
        let metadata = fs::symlink_metadata(part)?;
        if metadata.file_type().is_symlink() {
            return Err("update path cannot contain a symbolic link".into());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err("update path cannot contain a reparse point".into());
            }
        }
    }
    Ok(())
}
fn installation(target: &Path) -> Result<Option<Installation>> {
    let marker = target
        .parent()
        .ok_or("installation directory missing")?
        .join("installation.json");
    match fs::symlink_metadata(&marker) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
        Ok(metadata) if !metadata.is_file() || metadata.len() > 4096 => {
            return Err("installation marker is invalid".into());
        }
        _ => {}
    }
    regular_path(&marker)?;
    let marker: Installation = serde_json::from_slice(&fs::read(marker)?)?;
    if !matches!(marker.format.as_str(), "msi" | "rpm")
        || !matches!(marker.edition.as_str(), "community" | "commercial")
        || !matches!(marker.scope.as_str(), "user" | "machine")
    {
        return Err("installation marker is unsupported".into());
    }
    if let Some(v) = &marker.version {
        version(v)?;
    }
    Ok(Some(marker))
}
/// Composition check for a package update: the installed marker and the release must
/// describe the same MSI product. The *scope* rule lives in `install_msi`, because a
/// per-machine installation may only be updated by the privileged applier.
fn managed_release(target: &Path, release: &Release) -> Result<()> {
    let marker = installation(target)?.ok_or("MSI update requires an existing MSI installation")?;
    if marker.format != "msi"
        || release.format != "msi"
        || release.platform != "windows"
        || marker.edition != release.edition
        || !matches!(marker.scope.as_str(), "user" | "machine")
    {
        return Err("package update composition rejected".into());
    }
    Ok(())
}
/// A per-machine installation lives under ProgramFiles and is driven by Windows
/// Installer: only the LocalSystem applier service can apply it. The unprivileged
/// agent is refused here as well as by the operating system, so a mistake in the
/// caller cannot turn into a silent failure halfway through an install.
fn allowed_scope(target: &Path, privileged: bool) -> Result<()> {
    let marker = installation(target)?.ok_or("MSI update requires an existing MSI installation")?;
    if marker.scope == "machine" && !privileged {
        return Err("a per-machine installation is updated by the applier service".into());
    }
    Ok(())
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Lease {
    expires_at: DateTime<Utc>,
}
/// Whether an update holds a live lease: the agent's own (per-user helper, the
/// agent's preflight) or the privileged applier's, kept beside the journal.
pub fn pending(home: &Path) -> Result<bool> {
    for path in [home.join("update-lease.json"), journal_root(home).join("update-lease.json")] {
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
            Ok(m) if !m.is_file() || m.len() > 1024 => return Err("invalid update lease".into()),
            _ => {}
        }
        regular_path(&path)?;
        let lease: Lease = serde_json::from_slice(&fs::read(path)?)?;
        if lease.expires_at > Utc::now() && lease.expires_at <= Utc::now() + chrono::Duration::minutes(16) {
            return Ok(true);
        }
    }
    Ok(false)
}
struct UpdateLease {
    path: PathBuf,
    remove: bool,
}
impl UpdateLease {
    fn begin(home: &Path) -> Result<Self> {
        fs::create_dir_all(home)?;
        regular_path(home)?;
        let path = home.join("update-lease.json");
        if path.exists() {
            regular_path(&path)?;
        }
        crate::atomic_private(
            &path,
            &serde_json::to_vec(&Lease {
                expires_at: Utc::now() + chrono::Duration::minutes(15),
            })?,
        )?;
        Ok(Self { path, remove: true })
    }
}
impl Drop for UpdateLease {
    fn drop(&mut self) {
        if self.remove {
            let _ = fs::remove_file(&self.path);
        }
    }
}
fn staging_root(target: &Path, edition: &str) -> Result<PathBuf> {
    let parent = target.parent().ok_or("update staging parent missing")?;
    let runtime = parent.parent().ok_or("update staging parent missing")?;
    if runtime.file_name().and_then(|name| name.to_str()) != Some("runtime") {
        return Ok(runtime.to_path_buf());
    }

    let runtime_version = parent
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("runtime version is not UTF-8")?;
    version(runtime_version)?;
    let installation_root = runtime.parent().ok_or("runtime installation root missing")?;
    let (expected_root, expected_binary) = match edition {
        "community" => ("Browser", "milvago-browser-agent.exe"),
        "commercial" => ("Commercial", "milvago-commercial-bridge.exe"),
        _ => return Err("invalid update edition".into()),
    };
    if installation_root.file_name().and_then(|name| name.to_str()) != Some(expected_root) {
        return Err("runtime is outside its edition installation root".into());
    }
    if target.file_name().and_then(|name| name.to_str()) != Some(expected_binary) {
        return Err("runtime target is not this edition's installed binary".into());
    }
    regular_path(target)?;
    let marker_target = installation_root.join("installed-agent");
    let marker = installation(&marker_target)?.ok_or("runtime installation marker missing")?;
    if marker.format != "msi" || marker.edition != edition
        || marker.version.as_deref() != Some(runtime_version) {
        return Err("runtime installation marker differs from target".into());
    }
    installation_root.parent().map(Path::to_path_buf).ok_or_else(|| "update staging parent missing".into())
}
fn staging(target: &Path, edition: &str) -> Result<PathBuf> {
    let root = staging_root(target, edition)?;
    regular_path(&root)?;
    let updates = root.join("Updates");
    match fs::create_dir(&updates) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    regular_path(&updates)?;
    // A failed attempt keeps its package and verbose log for diagnosis until the next one:
    // retried hourly, they otherwise grew by 10-15 MB an hour. A file still in use (an MSI
    // client past its timeout) is left for a later pass.
    for entry in fs::read_dir(&updates)?.flatten() {
        if entry.file_name().to_string_lossy().starts_with("update-")
            && entry.file_type().is_ok_and(|kind| kind.is_dir())
        {
            let _ = fs::remove_dir_all(entry.path());
        }
    }
    let dir = updates.join(format!("update-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    regular_path(&dir)?;
    Ok(dir)
}
#[derive(Debug, PartialEq, Eq)]
pub enum Applied {
    NoUpdate,
    Installed,
    RolledBack,
    #[cfg_attr(not(any(windows, test)), allow(dead_code))]
    RebootRequired,
    Failed,
    TimedOut,
}
impl Applied {
    pub fn is_success(&self) -> bool { matches!(self, Self::Installed | Self::NoUpdate | Self::RebootRequired) }
}
#[cfg(any(windows, test))]
fn msi_result(code: Option<i32>, new_healthy: bool, old_healthy: bool) -> Applied {
    match code {
        Some(0) if new_healthy => Applied::Installed,
        Some(3010 | 1641) => Applied::RebootRequired,
        // A successful transaction with an unhealthy new binary is not rolled
        // back by Windows Installer after commit. Never claim otherwise.
        Some(0) => Applied::Failed,
        Some(_) if old_healthy => Applied::RolledBack,
        Some(_) => Applied::Failed,
        None => Applied::TimedOut,
    }
}
#[cfg(windows)]
fn system_installer() -> Result<PathBuf> {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
    }
    let mut buffer = vec![0u16; 32768];
    let size = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    if size == 0 || size as usize >= buffer.len() {
        return Err("Windows system directory unavailable".into());
    }
    use std::os::windows::ffi::OsStringExt;
    let path =
        PathBuf::from(std::ffi::OsString::from_wide(&buffer[..size as usize])).join("msiexec.exe");
    if !path.is_absolute() {
        return Err("Windows Installer path must be absolute".into());
    }
    regular_path(&path)?;
    Ok(path)
}
/// Read the receipt from the handles whose ownership and ACL were verified.
/// An attacker-created ProgramData directory must never attest a rollback.
#[cfg(windows)]
fn private_receipt(path: &Path) -> Result<Vec<u8>> {
    use std::os::windows::{fs::{OpenOptionsExt, MetadataExt}, io::AsRawHandle};
    use std::ffi::c_void;
    #[repr(C)]
    struct AceHeader { kind: u8, flags: u8, size: u16 }
    #[repr(C)]
    struct Acl { revision: u8, reserved: u8, size: u16, count: u16, reserved2: u16 }
    #[link(name="advapi32")]
    unsafe extern "system" {
        fn GetSecurityInfo(handle: isize, kind: i32, information: u32, owner: *mut *mut c_void, group: *mut *mut c_void, dacl: *mut *mut c_void, sacl: *mut *mut c_void, descriptor: *mut *mut c_void) -> u32;
        fn ConvertSidToStringSidW(sid: *mut c_void, out: *mut *mut u16) -> i32;
        fn GetAce(acl: *const Acl, index: u32, ace: *mut *mut c_void) -> i32;
    }
    #[link(name="kernel32")]
    unsafe extern "system" { fn LocalFree(memory: *mut c_void) -> *mut c_void; }
    struct Allocation(*mut c_void);
    impl Drop for Allocation { fn drop(&mut self) { unsafe { LocalFree(self.0); } } }
    fn privileged(sid: *const c_void) -> Result<bool> {
        if sid.is_null() { return Err("receipt SID is absent".into()); }
        let mut text = std::ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(sid.cast_mut(), &mut text) } == 0 { return Err("receipt SID unavailable".into()); }
        let _memory = Allocation(text.cast());
        let mut len = 0;
        while unsafe { *text.add(len) } != 0 { len += 1; }
        let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(text, len) })?;
        Ok(matches!(sid.as_str(), "S-1-5-18" | "S-1-5-32-544"))
    }
    fn verify(file: &fs::File) -> Result<()> {
        if file.metadata()?.file_attributes() & 0x400 != 0 { return Err("redirected receipt refused".into()); }
        let mut owner = std::ptr::null_mut();
        let mut dacl = std::ptr::null_mut();
        let mut descriptor = std::ptr::null_mut();
        let status = unsafe { GetSecurityInfo(file.as_raw_handle() as isize, 1, 5, &mut owner,
            std::ptr::null_mut(), &mut dacl, std::ptr::null_mut(), &mut descriptor) };
        let _memory = Allocation(descriptor);
        if status != 0 || dacl.is_null() || !privileged(owner)? {
            return Err("receipt owner or ACL is not privileged".into());
        }
        let dacl = dacl as *mut Acl;
        for index in 0..unsafe { (*dacl).count } as u32 {
            let mut ace = std::ptr::null_mut();
            if unsafe { GetAce(dacl, index, &mut ace) } == 0 { return Err("receipt ACL unavailable".into()); }
            let header = unsafe { &*(ace as *const AceHeader) };
            // Deny ACEs grant nothing. Inherit-only ACEs are not effective here.
            if header.kind == 1 || header.flags & 8 != 0 { continue; }
            if header.kind != 0 || header.size < 12 { return Err("unsupported receipt ACL".into()); }
            let mask = unsafe { *((ace as *const u8).add(4) as *const u32) };
            let writes = 0x10000000 | 0x40000000 | 0x000d0156;
            if mask & writes != 0 && !privileged(unsafe { (ace as *const u8).add(8).cast() })? {
                return Err("receipt is writable by an untrusted principal".into());
            }
        }
        Ok(())
    }
    regular_path(path)?;
    let root = path.parent().ok_or("receipt root missing")?;
    let directory = OpenOptions::new().access_mode(0x20080).share_mode(1)
        .custom_flags(0x02000000 | 0x00200000).open(root)?;
    verify(&directory)?;
    let file = OpenOptions::new().access_mode(0x80020000).share_mode(1)
        .custom_flags(0x00200000).open(path)?;
    verify(&file)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > 4096 { return Err("receipt exceeds limit".into()); }
    let mut bytes = Vec::new();
    file.take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 { return Err("receipt exceeds limit".into()); }
    Ok(bytes)
}
#[cfg(windows)]
fn rollback_verified(product: &str, edition: &str, began: DateTime<Utc>, previous: Option<&str>) -> Result<bool> {
    #[derive(Deserialize)]
    struct Receipt { product: String, edition: String, transaction: String, resources_restored: bool, at: DateTime<Utc> }
    let id = uuid::Uuid::parse_str(product.trim_matches(['{', '}']))?;
    let root = std::env::var_os("ProgramData").ok_or("machine data root unavailable")?;
    let path = PathBuf::from(root).join("MilvagoInstallerTransactions")
        .join(format!("{}.result.json", id));
    let receipt: Receipt = serde_json::from_slice(&private_receipt(&path)?)?;
    uuid::Uuid::parse_str(&receipt.transaction)?;
    Ok(uuid::Uuid::parse_str(receipt.product.trim_matches(['{', '}']))? == id && receipt.edition == edition
        && previous != Some(receipt.transaction.as_str())
        && receipt.resources_restored && receipt.at >= began && receipt.at <= Utc::now() + chrono::Duration::seconds(5))
}
#[cfg(not(windows))]
fn rollback_verified(_: &str, _: &str, _: DateTime<Utc>, _: Option<&str>) -> Result<bool> { Ok(false) }
fn install_msi(
    home: &Path,
    target: &Path,
    release: &Release,
    bytes: &[u8],
    current: &str,
    privileged: bool,
) -> Result<Applied> {
    managed_release(target, release)?;
    allowed_scope(target, privileged)?;
    check_hash(release, bytes)?;
    if !bytes.starts_with(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]) {
        return Err("MSI artifact format rejected".into());
    }
    #[cfg(not(windows))]
    {
        let _ = (home, current);
        Err("MSI updates require Windows".into())
    }
    #[cfg(windows)]
    {
        let dir = staging(target, &release.edition)?;
        let package = dir.join("release.msi");
        let mut file = crate::private_file(&package, true)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        let mut command = Command::new(system_installer()?);
        command
            .arg("/i")
            .arg(&package)
            .args(["/qn", "/norestart"])
            .arg("/L*V").arg(dir.join("installer.log"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        hidden(&mut command);
        // Persist the unsettled transaction before starting Windows Installer.
        let identity = identity(home)?;
        let mut pending = UnsettledUpdate {
            edition: release.edition.clone(), version: release.version.clone(),
            boot_marker: boot_marker()?, reason: "installing".into(),
            product_code: crate::bootstrap::msi_product_code(&package)?,
            previous_version: current.into(), began: Utc::now(), previous_receipt: None,
        };
        let receipt_root = std::env::var_os("ProgramData").ok_or("machine data root unavailable")?;
        let receipt_path = PathBuf::from(receipt_root).join("MilvagoInstallerTransactions")
            .join(format!("{}.result.json", pending.product_code.trim_matches(['{', '}']).to_ascii_lowercase()));
        if receipt_path.exists() {
            let value: serde_json::Value = serde_json::from_slice(&private_receipt(&receipt_path)?)?;
            let transaction = value["transaction"].as_str().ok_or("invalid previous rollback receipt")?;
            uuid::Uuid::parse_str(transaction)?;
            pending.previous_receipt = Some(transaction.to_string());
        }
        save_unsettled(home, &identity, Some(pending.clone()))?;
        let began_wall = Utc::now();
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => { save_unsettled(home, &identity, None)?; return Err(error.into()); }
        };
        let began = Instant::now();
        let code = loop {
            match child.try_wait()? {
                Some(status) => break status.code(),
                None if began.elapsed() < Duration::from_secs(12 * 60) => {
                    std::thread::sleep(Duration::from_millis(500))
                }
                None => {
                    // The client is not the server transaction. Killing it would
                    // leave Windows Installer active with an unknown result.
                    break None;
                }
            }
        };
        let result = msi_result(
            code,
            code == Some(0) && service_healthy(target, &release.edition, &release.version),
            code.is_some_and(|n| n != 0 && n != 3010 && n != 1641)
                && rollback_verified(&pending.product_code, &release.edition, began_wall, pending.previous_receipt.as_deref()).unwrap_or(false)
                && service_healthy(target, &release.edition, current),
        );
        if matches!(result, Applied::TimedOut | Applied::RebootRequired) {
            pending.reason = if result == Applied::TimedOut { "timeout" } else { "reboot_required" }.into();
            save_unsettled(home, &identity, Some(pending))?;
        } else {
            save_unsettled(home, &identity, None)?;
        }
        if matches!(result, Applied::Installed | Applied::RebootRequired) {
            let _ = fs::remove_file(package);
            let _ = fs::remove_file(dir.join("installer.log"));
            let _ = fs::remove_dir(dir);
        }
        Ok(result)
    }
}
pub fn install(target: &Path, release: &Release, bytes: &[u8]) -> Result<bool> {
    check_hash(release, bytes)?;
    if release.format != "binary" || installation(target)?.is_some() {
        return Err("managed installation requires its package updater".into());
    }
    if fs::symlink_metadata(target)?.file_type().is_symlink() {
        return Err("symlink update target refused".into());
    }
    let target = target.canonicalize()?;
    let parent = target.parent().ok_or("invalid installation directory")?;
    let staged = parent.join(format!(
        ".milvago-{}.{}",
        uuid::Uuid::new_v4(),
        if cfg!(windows) { "exe" } else { "new" }
    ));
    let backup = parent.join(format!(".milvago-{}.backup", uuid::Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    // Every user's browser runs this binary as its relay: root installs it 0755.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o755);
    }
    let mut file = options.open(&staged)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::copy(&target, &backup)?;
    OpenOptions::new().write(true).open(&backup)?.sync_all()?;
    let start = Instant::now();
    loop {
        match replace(&staged, &target) {
            Ok(()) => break,
            Err(_) if start.elapsed() < Duration::from_secs(20) => {
                std::thread::sleep(Duration::from_millis(250))
            }
            Err(e) => {
                let _ = fs::remove_file(&staged);
                let _ = fs::remove_file(&backup);
                return Err(e);
            }
        }
    }
    if !binary_matches(&target, &release.version) {
        replace(&backup, &target)?;
        return Ok(false);
    }
    // Keep the previous verified executable locally for an operator; never trust an unsigned rollback URL.
    Ok(true)
}
fn replace(source: &Path, target: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
        }
        let from: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
        let to: Vec<u16> = target.as_os_str().encode_wide().chain(Some(0)).collect();
        if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 0x1 | 0x8) } == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    #[cfg(not(windows))]
    {
        fs::rename(source, target)?;
        fs::File::open(target.parent().ok_or("target parent missing")?)?.sync_all()?;
    }
    Ok(())
}
/// Applies whatever release the server currently authorizes. `privileged` is true
/// only when this runs inside the LocalSystem applier service; it is what allows a
/// per-machine installation to be updated. The real enforcement is the operating
/// system (ProgramFiles ACL and Windows Installer): this flag keeps the
/// unprivileged path from ever reaching that code by mistake.
pub fn apply(
    home: &Path,
    target: &Path,
    edition: &str,
    current: &str,
    privileged: bool,
) -> Result<Applied> {
    // The installer-written proxy and HTTPS trust apply to the applier's downloads too.
    // Their directory is the administrators', never the agent account's.
    if privileged { crate::config::open(home); }
    reconcile(home, target, edition)?;
    let _ = flush_reports(home);
    // The privileged lease joins the journal, outside the agent-writable state.
    let mut lease = UpdateLease::begin(&if privileged { journal_root(home) } else { home.to_path_buf() })?;
    let state = identity(home)?;
    let updates = { journal(home, &state)?.1 };
    if updates.unsettled_update.is_some() { return Err("previous Windows Installer outcome requires verification".into()); }
    if updates.update_reports.len() >= 32 { return Err("update report queue is full".into()); }
    // The per-user helper runs as the account that owns the state; only the privileged
    // applier crosses an account boundary, so only it needs the pinned anchor.
    let trust = if privileged { pinned_trust(edition, &state)? } else { Trust::from_state(&state)? };
    let Some((release, bytes, rotated)) = fetch_trusted(&trust, edition, current, true)? else {
        return Ok(Applied::NoUpdate);
    };
    if rotated {
        let next = trust.next.clone().ok_or("rotated release without successor")?;
        if privileged {
            write_anchor(edition, &ReleaseAnchor { update_public_key: next.clone(), server_url: trust.origin.clone() })?;
        }
        // The agent promotes its own copy once a release verifies against its successor.
        if !privileged {
            let store = Store::open(home)?;
            let mut promoted = store.load()?;
            promoted.update_public_key = Some(next);
            promoted.update_public_key_next = None;
            store.save(&promoted)?;
        }
    }
    let attempt = if release.format == "msi" {
        install_msi(home, target, &release, &bytes, current, privileged)
    } else {
        install(target, &release, &bytes).map(|ok| {
            if ok && service_healthy(target, edition, &release.version) {
                Applied::Installed
            } else { Applied::Failed }
        })
    };
    let result = attempt.unwrap_or(Applied::Failed);
    if result == Applied::TimedOut { lease.remove = false; }
    let status = match result {
        Applied::Installed => "installed",
        Applied::RolledBack => "rolled_back",
        Applied::RebootRequired => "reboot_required",
        Applied::Failed | Applied::TimedOut => "failed",
        Applied::NoUpdate => unreachable!(),
    };
    let reported_version = if matches!(result, Applied::Installed | Applied::RebootRequired) {
        &release.version
    } else { current };
    queue_report(home, &state, reported_version, status)?;
    // Delivery failure must not change the local result. The encrypted report
    // stays pending and is retried by the watch loop after connectivity returns.
    let _ = flush_reports(home);
    Ok(result)
}
pub fn launch(home: &Path, edition: &str, current: &str) -> Result<bool> {
    // Reports are delivered by whoever applies updates: the agent only reads the journal,
    // and wakes the applier while one is waiting.
    if journal_read(home, &identity(home)?)?.update_reports.first().is_some() {
        let _ = start_applier(edition);
    }
    if unresolved(home)? {
        // Only SYSTEM can read privileged rollback receipts. Let the applier
        // reconcile, while keeping the agent running to answer its health probe.
        start_applier(edition)?;
        return Ok(false);
    }
    if pending(home)? {
        return Ok(false);
    }
    let target = std::env::current_exe()?;
    let helper: PathBuf =
        target
            .parent()
            .ok_or("installation path missing")?
            .join(if cfg!(windows) {
                "milvago-updater.exe"
            } else {
                "milvago-updater"
            });
    let installed = installation(&target)?;
    let machine = installed.as_ref().is_some_and(|m| m.scope == "machine");
    if !machine && !helper.is_file() { return Ok(false); }
    // Package managers own RPM updates; do not repeatedly download a binary
    // campaign that this installation cannot safely apply.
    if installed.as_ref().is_some_and(|m| m.format == "rpm") {
        return Ok(false);
    }
    // Preflight avoids stopping the collector when no campaign applies. The helper verifies again.
    let release = {
        let mut state = { Store::open(home)?.load()? };
        if state.update_public_key.is_none() {
            return Ok(false);
        }
        // Learn a published successor anchor before looking for a release, so a key
        // rotation reaches the device ahead of the first release signed with it.
        if refresh_anchor(&mut state).unwrap_or(false) {
            let store = Store::open(home)?;
            let mut current = store.load()?;
            if !same_identity(&state, &current)
                || current.update_public_key != state.update_public_key {
                return Err("installation changed during update preflight".into());
            }
            current.update_public_key_next = state.update_public_key_next.clone();
            store.save(&current)?;
        }
        let Some((release, _, _)) = fetch(&state, edition, current, false)? else {
            return Ok(false);
        };
        release
    };
    let managed = installed.is_some();
    if release.format == "msi" {
        managed_release(&target, &release)?;
    } else if managed {
        return Err("managed installation refuses binary release".into());
    }
    // A Linux system service cannot replace its root-owned binary: the root applier
    // does, on request. Without one (an installation that predates it), spawning the
    // helper would only fail and restart the service every minute.
    #[cfg(unix)]
    if !managed {
        if anchor_path(edition)?.exists() {
            return request_root_update(home);
        }
        let parent = std::ffi::CString::new(target.parent().ok_or("installation path missing")?.as_os_str().as_encoded_bytes())?;
        if unsafe { libc::access(parent.as_ptr(), libc::W_OK) } != 0 {
            static REPORTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
            if !REPORTED.swap(true, std::sync::atomic::Ordering::AcqRel) {
                crate::log::info("signed update available, but this installation has no root applier; reinstall with install-browser.sh");
            }
            return Ok(false);
        }
    }
    let mut lease = UpdateLease::begin(home)?;
    // A per-machine installation cannot be applied from this account: ask the
    // privileged applier service instead. It is handed nothing — it re-fetches,
    // re-verifies and re-derives the installed version by itself.
    if machine {
        start_applier(edition)?;
        lease.remove = false;
        return Ok(false);
    }
    let helper = if managed {
        regular_path(&helper)?;
        if fs::metadata(&helper)?.len() > 64 * 1024 * 1024 {
            return Err("update helper exceeds size limit".into());
        }
        let dir = staging(&target, edition)?;
        let staged = dir.join("milvago-updater.exe");
        let bytes = fs::read(&helper)?;
        let mut output = crate::private_file(&staged, true)?;
        output.write_all(&bytes)?;
        output.sync_all()?;
        drop(output);
        staged
    } else {
        helper
    };
    let mut command = Command::new(helper);
    command
        .arg("apply")
        .arg(home)
        .arg(target)
        .arg(edition)
        .arg(current)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    hidden(&mut command);
    command.spawn()?;
    lease.remove = false; // The helper owns cleanup after taking over the lease.
    Ok(true)
}

/// Name of the privileged applier service for an edition. Must match the name
/// `deploy/configure-agent.ps1` registers.
pub fn applier_service(edition: &str) -> String {
    if edition == "commercial" {
        "Milvago Update Applier".into()
    } else {
        "Milvago Update Applier Community".into()
    }
}

/// Asks the applier to run. The agent holds SERVICE_START on this one service and
/// nothing else: no path, no URL, no version and no bytes cross the boundary.
#[cfg(windows)]
fn start_applier(edition: &str) -> Result<()> {
    wake_applier(edition)?;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match crate::ipc::exchange_timeout(
            &applier_channel(edition), crate::ipc::Access::UpdateAgent,
            &serde_json::json!({"protocol":1,"op":"update_apply"}), Duration::from_secs(2),
        ) {
            Ok(answer) if answer["ok"] == true && answer["protocol"] == 1 => return Ok(()),
            Ok(_) => return Err("update service refused explicit request".into()),
            Err(error) if std::time::Instant::now() >= deadline => return Err(error),
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}

pub fn applier_channel(edition: &str) -> String {
    format!("update-control-{}", if edition == "commercial" { "commercial" } else { "community" })
}

/// Starting the service grants no installation authority. StartService arguments
/// are ignored; only the separate service-account IPC request schedules work.
#[cfg(windows)]
pub fn wake_applier(edition: &str) -> Result<()> {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(applier_service(edition), ServiceAccess::START)?;
    match service.start::<&std::ffi::OsStr>(&[]) {
        Ok(()) => Ok(()),
        // Already running: an attempt is in flight, which is what we wanted.
        Err(windows_service::Error::Winapi(e)) if e.raw_os_error() == Some(1056) => Ok(()),
        Err(e) => Err(e.into()),
    }
}
#[cfg(not(windows))]
fn start_applier(_: &str) -> Result<()> {
    Err("a per-machine package installation is updated by the platform package manager".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    fn signed() -> (Release, Envelope, String) {
        let r = Release {
            format: "binary".into(),
            version: "0.2.1".into(),
            edition: "community".into(),
            platform: std::env::consts::OS.into(),
            protocol: 2,
            sha256: crate::sha256_hex(b"candidate"),
            size: 9,
            expires_at: Utc::now() + chrono::Duration::hours(1),
            artifact: format!("/v2/update/artifact/{}", crate::sha256_hex(b"candidate")),
            rollback_from: vec![],
        };
        let key = SigningKey::from_bytes(&[47; 32]);
        let bytes = serde_json::to_vec(&r).unwrap();
        let env = Envelope {
            payload: STANDARD.encode(&bytes),
            signature: STANDARD.encode(key.sign(&bytes).to_bytes()),
        };
        (r, env, STANDARD.encode(key.verifying_key().as_bytes()))
    }
    fn sign_value(value: &serde_json::Value) -> (Envelope, String) {
        let key = SigningKey::from_bytes(&[47; 32]);
        let bytes = serde_json::to_vec(value).unwrap();
        (
            Envelope {
                payload: STANDARD.encode(&bytes),
                signature: STANDARD.encode(key.sign(&bytes).to_bytes()),
            },
            STANDARD.encode(key.verifying_key().as_bytes()),
        )
    }
    fn sign_release(release: &Release, key: &SigningKey) -> Envelope {
        let bytes = serde_json::to_vec(release).unwrap();
        Envelope {
            payload: STANDARD.encode(&bytes),
            signature: STANDARD.encode(key.sign(&bytes).to_bytes()),
        }
    }
    #[test]
    fn the_privileged_journal_is_beside_the_agent_state_never_inside_it() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("state");
        assert_eq!(journal_root(&home), root.path().join("update-journal"));
        // An absent journal or state reads as empty, and reading creates nothing.
        let identity = State { device_id: uuid::Uuid::new_v4().to_string(), ..Default::default() };
        assert!(journal_read(&home, &identity).unwrap().update_reports.is_empty());
        assert!(super::identity(&home).unwrap().credential.is_empty());
        assert!(!home.exists() && !journal_root(&home).exists(), "a read created a directory");
    }
    // The applier reads the agent's state: a state file the agent turned into a
    // junction (the agent account can) is refused, never followed.
    #[cfg(windows)]
    #[test]
    fn a_redirected_state_file_is_never_read() {
        let home = tempfile::tempdir().unwrap();
        crate::Store::open(home.path()).unwrap().save(&State::default()).unwrap();
        let elsewhere = home.path().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        fs::remove_file(home.path().join("state.key")).unwrap();
        let made = Command::new("cmd").args(["/C", "mklink", "/J"]).arg(home.path().join("state.key")).arg(&elsewhere)
            .stdout(Stdio::null()).status().unwrap();
        assert!(made.success());
        assert!(crate::Store::read_existing(home.path()).is_err());
    }
    #[test]
    fn pinned_trust_ignores_the_agent_writable_state() {
        let (release, _, real) = signed();
        let attacker = SigningKey::from_bytes(&[91; 32]);
        let attacker_key = STANDARD.encode(attacker.verifying_key().as_bytes());
        let state = State {
            update_public_key: Some(attacker_key.clone()),
            update_public_key_next: Some(attacker_key),
            server_url: "https://attacker.example/".into(),
            credential: "device-credential".into(),
            ..Default::default()
        };
        let anchor = ReleaseAnchor { update_public_key: real.clone(), server_url: "https://server.example/".into() };
        anchor.validate().unwrap();
        let trust = anchored(anchor, &state);
        assert_eq!(trust.key, real);
        assert!(trust.next.is_none());
        assert_eq!(trust.url("/v2/update").unwrap().host_str(), Some("server.example"));
        assert_eq!(trust.credential, "device-credential");
        let forged = sign_release(&release, &attacker);
        assert!(select_release(&forged, &trust.key, trust.next.as_deref(), "community", std::env::consts::OS, "0.2.0").is_err());
        assert!(ReleaseAnchor { update_public_key: "not-a-key".into(), server_url: "https://server.example/".into() }.validate().is_err());
        assert!(ReleaseAnchor { update_public_key: real, server_url: "http://server.example/".into() }.validate().is_err());
    }
    #[test]
    fn signed_package_format_is_bound_and_platform_limited() {
        let (r, _, _) = signed();
        let mut value = serde_json::to_value(r).unwrap();
        value["platform"] = "windows".into();
        value["format"] = "msi".into();
        value["size"] = (128u64 * 1024 * 1024).into();
        let (mut env, key) = sign_value(&value);
        assert_eq!(
            verify(&env, &key, "community", "windows", "0.2.0")
                .unwrap()
                .format,
            "msi"
        );
        value["format"] = "binary".into();
        env.payload = STANDARD.encode(serde_json::to_vec(&value).unwrap());
        assert!(verify(&env, &key, "community", "windows", "0.2.0").is_err());
        value.as_object_mut().unwrap().remove("format");
        let (env, key) = sign_value(&value);
        assert_eq!(
            verify(&env, &key, "community", "windows", "0.2.0")
                .unwrap()
                .format,
            "binary"
        );
        for (field, invalid) in [
            ("format", serde_json::json!("exe")),
            ("size", serde_json::json!(128u64 * 1024 * 1024 + 1)),
            ("version", serde_json::json!("00.3.0")),
        ] {
            let mut altered = value.clone();
            altered[field] = invalid;
            let (env, key) = sign_value(&altered);
            assert!(verify(&env, &key, "community", "windows", "0.2.0").is_err());
        }
        value["format"] = "msi".into();
        value["platform"] = "linux".into();
        let (env, key) = sign_value(&value);
        assert!(verify(&env, &key, "community", "linux", "0.2.0").is_err());
    }
    #[test]
    fn managed_installs_refuse_raw_wrong_edition_scope_and_artifact_without_execution() {
        let (mut release, _, _) = signed();
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("agent.exe");
        fs::write(&target, b"previous").unwrap();
        let marker = dir.path().join("installation.json");
        for format in ["msi", "rpm"] {
            fs::write(&marker, serde_json::to_vec(&serde_json::json!({"format":format,"edition":"community","scope":"user","version":"0.2.0"})).unwrap()).unwrap();
            assert!(install(&target, &release, b"candidate").is_err());
            assert_eq!(fs::read(&target).unwrap(), b"previous");
        }
        release.format = "msi".into();
        release.platform = "windows".into();
        for (edition, scope, composition, unprivileged) in [
            ("community", "user", true, true),
            ("commercial", "user", false, true),
            // A per-machine installation composes fine but may only be applied by the
            // privileged applier service, never from the agent account.
            ("community", "machine", true, false),
        ] {
            fs::write(
                &marker,
                serde_json::to_vec(
                    &serde_json::json!({"format":"msi","edition":edition,"scope":scope}),
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(managed_release(&target, &release).is_ok(), composition);
            assert_eq!(allowed_scope(&target, false).is_ok(), unprivileged);
            assert!(allowed_scope(&target, true).is_ok());
            // Non-MSI bytes are rejected before any Windows Installer process starts.
            assert!(
                install_msi(dir.path(), &target, &release, b"candidate", "0.2.0", true).is_err()
            );
        }
        fs::write(&marker, b"{}").unwrap();
        assert!(installation(&target).is_err());
    }
    #[test]
    fn lease_staging_and_installer_outcomes_preserve_truthful_state() {
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("Browser");
        let home = install.join("state");
        fs::create_dir_all(&home).unwrap();
        let stage = staging(&install.join("agent.exe"), "community").unwrap();
        assert!(stage.starts_with(dir.path().join("Updates")));
        assert!(!stage.starts_with(&install));
        assert!(!pending(&home).unwrap());
        {
            let _lease = UpdateLease::begin(&home).unwrap();
            assert!(pending(&home).unwrap());
        }
        assert!(!pending(&home).unwrap());
        fs::write(
            home.join("update-lease.json"),
            serde_json::to_vec(&Lease {
                expires_at: Utc::now() - chrono::Duration::seconds(1),
            })
            .unwrap(),
        )
        .unwrap();
        assert!(!pending(&home).unwrap());
        assert_eq!(msi_result(Some(0), true, false), Applied::Installed);
        assert_eq!(msi_result(Some(3010), true, true), Applied::RebootRequired);
        assert_eq!(msi_result(Some(1603), false, true), Applied::RolledBack);
        assert_eq!(msi_result(Some(0), false, true), Applied::Failed);
        assert_eq!(msi_result(Some(1603), false, false), Applied::Failed);
        assert_eq!(msi_result(None, false, true), Applied::TimedOut);
    }
    #[test]
    fn staging_uses_the_edition_sibling_for_legacy_and_versioned_msi_targets() {
        let dir = tempfile::tempdir().unwrap();
        let milvago = dir.path().join("Milvago");
        for (edition, folder, executable) in [
            ("community", "Browser", "milvago-browser-agent.exe"),
            ("commercial", "Commercial", "milvago-commercial-bridge.exe"),
        ] {
            let install = milvago.join(folder);
            fs::create_dir_all(&install).unwrap();
            fs::write(
                install.join("installation.json"),
                serde_json::to_vec(&serde_json::json!({
                    "format": "msi", "scope": "machine", "edition": edition, "version": "0.5.15"
                }))
                .unwrap(),
            )
            .unwrap();

            let legacy = install.join(executable);
            fs::write(&legacy, b"legacy").unwrap();
            let legacy_stage = staging(&legacy, edition).unwrap();
            assert!(legacy_stage.exists());
            assert!(legacy_stage.starts_with(milvago.join("Updates")));
            assert!(!legacy_stage.starts_with(&install));

            let versioned = install.join("runtime").join("0.5.15").join(executable);
            fs::create_dir_all(versioned.parent().unwrap()).unwrap();
            fs::write(&versioned, b"versioned").unwrap();
            fs::write(legacy_stage.join("release.msi"), b"failed attempt").unwrap();
            let versioned_stage = staging(&versioned, edition).unwrap();
            assert!(versioned_stage.exists());
            assert!(versioned_stage.starts_with(milvago.join("Updates")));
            assert!(!versioned_stage.starts_with(&install));
            assert!(!legacy_stage.exists(), "a previous attempt was not purged");
        }
    }
    #[test]
    fn staging_refuses_malformed_or_ambiguous_versioned_runtime() {
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("Milvago").join("Browser");
        fs::create_dir_all(&install).unwrap();
        fs::write(
            install.join("installation.json"),
            serde_json::to_vec(&serde_json::json!({
                "format": "msi", "scope": "machine", "edition": "community", "version": "0.5.15"
            }))
            .unwrap(),
        )
        .unwrap();
        let malformed = install.join("runtime").join("not-a-version").join("milvago-browser-agent.exe");
        fs::create_dir_all(malformed.parent().unwrap()).unwrap();
        fs::write(&malformed, b"runtime").unwrap();
        assert!(staging(&malformed, "community").is_err());

        let mismatched = install.join("runtime").join("0.5.14").join("milvago-browser-agent.exe");
        fs::create_dir_all(mismatched.parent().unwrap()).unwrap();
        fs::write(&mismatched, b"runtime").unwrap();
        assert!(staging(&mismatched, "community").is_err());
    }
    #[cfg(windows)]
    #[test]
    fn user_created_receipt_cannot_attest_privileged_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let receipt = dir.path().join("receipt.json");
        fs::write(&receipt, b"{\"resources_restored\":true}").unwrap();
        assert!(private_receipt(&receipt).is_err(), "user-owned receipt was trusted");
    }
    #[test]
    fn queued_update_result_survives_offline_delivery_and_refuses_identity_substitution() {
        let dir = tempfile::tempdir().unwrap();
        let identity = State { credential: "synthetic-update-secret".into(),
            device_id: uuid::Uuid::new_v4().to_string(), server_url: "http://127.0.0.1:1".into(),
            public_key: "synthetic-update-anchor".into(), ..State::default() };
        { Store::open(dir.path()).unwrap().save(&identity).unwrap(); }
        queue_report(dir.path(), &identity, "1.2.3", "failed").unwrap();
        assert!(flush_reports(dir.path()).is_err());
        let reports = journal(dir.path(), &identity).unwrap().1.update_reports;
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].status, "failed");
        let raw = fs::read(dir.path().join("update-journal").join(&identity.device_id).join("state.bin")).unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("synthetic-update-secret"));
        let mut other = State::default();
        other.credential = "replacement-update-secret".into();
        other.device_id = uuid::Uuid::new_v4().to_string();
        other.server_url = "http://127.0.0.1:1".into();
        { Store::open(dir.path()).unwrap().save(&other).unwrap(); }
        // The new installation has no report to send. Any request to the offline
        // endpoint would fail, so success proves the old result was not sent.
        assert!(flush_reports(dir.path()).is_ok());
        assert!(queue_report(dir.path(), &identity, "1.2.4", "installed").is_err());
        assert_eq!(fs::read(dir.path().join("update-journal").join(&identity.device_id).join("state.bin")).unwrap(), raw);
    }
    #[test]
    fn signed_rollback_metadata_never_authorizes_a_downgrade() {
        let (mut release, _, _) = signed();
        release.rollback_from = vec!["0.3.0".into()];
        let (envelope, key) = sign_value(&serde_json::to_value(release).unwrap());
        assert!(verify(&envelope, &key, "community", std::env::consts::OS, "0.3.0").is_err());
    }
    #[test]
    fn rejects_wrong_edition_signature_and_replay() {
        let (_, mut env, key) = signed();
        assert!(verify(&env, &key, "community", std::env::consts::OS, "0.2.0").is_ok());
        assert!(verify(&env, &key, "commercial", std::env::consts::OS, "0.2.0").is_err());
        assert!(verify(&env, &key, "community", std::env::consts::OS, "0.2.1").is_err());
        assert!(verify(&env, &key, "community", std::env::consts::OS, "0.3.0").is_err());
        env.payload = STANDARD.encode(b"{}");
        assert!(verify(&env, &key, "community", std::env::consts::OS, "0.2.0").is_err());
    }
    #[test]
    fn same_version_returns_no_update_without_trying_successor() {
        let (release, envelope, key) = signed();
        let next = SigningKey::from_bytes(&[48; 32]);
        let next = STANDARD.encode(next.verifying_key().as_bytes());
        let (selected, rotated) = select_release(
            &envelope,
            &key,
            Some(&next),
            "community",
            std::env::consts::OS,
            &release.version,
        )
        .unwrap();
        assert!(selected.is_none());
        assert!(!rotated);
    }
    #[test]
    fn primary_release_constraints_do_not_fall_back_to_successor() {
        let (release, _, key) = signed();
        let signing = SigningKey::from_bytes(&[47; 32]);
        let next = SigningKey::from_bytes(&[48; 32]);
        let next = STANDARD.encode(next.verifying_key().as_bytes());
        let mut wrong_edition = release.clone();
        wrong_edition.edition = "commercial".into();
        let error = select_release(
            &sign_release(&wrong_edition, &signing),
            &key,
            Some(&next),
            "community",
            std::env::consts::OS,
            "0.2.0",
        )
        .err()
        .expect("wrong edition must be rejected")
        .to_string();
        assert_eq!(error, "release constraints rejected");
        let mut expired = release;
        expired.expires_at = Utc::now() - chrono::Duration::seconds(1);
        let error = select_release(
            &sign_release(&expired, &signing),
            &key,
            Some(&next),
            "community",
            std::env::consts::OS,
            "0.2.0",
        )
        .err()
        .expect("expired release must be rejected")
        .to_string();
        assert_eq!(error, "release constraints rejected");
    }
    #[test]
    fn successor_signature_can_authorize_a_newer_release() {
        let (release, _, key) = signed();
        let next = SigningKey::from_bytes(&[48; 32]);
        let next_public = STANDARD.encode(next.verifying_key().as_bytes());
        let (selected, rotated) = select_release(
            &sign_release(&release, &next),
            &key,
            Some(&next_public),
            "community",
            std::env::consts::OS,
            "0.2.0",
        )
        .unwrap();
        assert_eq!(selected.unwrap().version, release.version);
        assert!(rotated);
    }
    #[test]
    fn downgrade_is_refused_without_trying_successor() {
        let (release, envelope, key) = signed();
        let next = SigningKey::from_bytes(&[48; 32]);
        let next = STANDARD.encode(next.verifying_key().as_bytes());
        let error = select_release(
            &envelope,
            &key,
            Some(&next),
            "community",
            std::env::consts::OS,
            "0.3.0",
        )
        .err()
        .expect("downgrade must be rejected")
        .to_string();
        assert_eq!(error, "release downgrade or replay rejected");
        assert_eq!(release.version, "0.2.1");
    }
    #[test]
    fn tampered_artifact_never_replaces_installation() {
        let (r, _, _) = signed();
        let d = tempfile::tempdir().unwrap();
        let target = d.path().join("agent.exe");
        fs::write(&target, b"previous").unwrap();
        assert!(install(&target, &r, b"tampered!").is_err());
        assert_eq!(fs::read(&target).unwrap(), b"previous");
    }
    #[test]
    fn failed_health_check_restores_previous_executable() {
        let (r, _, _) = signed();
        let d = tempfile::tempdir().unwrap();
        let target = d.path().join("agent.exe");
        fs::write(&target, b"previous").unwrap();
        assert!(!install(&target, &r, b"candidate").unwrap());
        assert_eq!(fs::read(&target).unwrap(), b"previous");
    }

    #[test]
    fn msi_health_follows_current_marker_not_retained_runtime() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let name = "agent.exe";
        fs::write(root.join(name), b"legacy").unwrap();
        for revision in ["0.5.5", "0.5.10"] {
            let runtime = root.join("runtime").join(revision);
            fs::create_dir_all(&runtime).unwrap();
            fs::write(runtime.join(name), revision.as_bytes()).unwrap();
        }
        let marker = root.join("installation.json");
        let write_marker = |revision: &str, edition: &str| {
            fs::write(&marker, serde_json::to_vec(&serde_json::json!({
                "format": "msi", "scope": "machine", "edition": edition, "version": revision
            })).unwrap()).unwrap();
        };
        write_marker("0.5.10", "community");
        assert_eq!(health_target_in(root, name, "community", "0.5.10").unwrap(),
            root.join("runtime/0.5.10").join(name));
        assert!(health_target_in(root, name, "community", "0.5.5").is_err());
        assert!(health_target_in(root, name, "commercial", "0.5.10").is_err());
        assert!(health_target_in(root, name, "community", "../0.5.10").is_err());
        write_marker("0.5.5", "community");
        assert_eq!(health_target_in(root, name, "community", "0.5.5").unwrap(),
            root.join("runtime/0.5.5").join(name));
        fs::remove_file(root.join("runtime/0.5.5").join(name)).unwrap();
        assert_eq!(health_target_in(root, name, "community", "0.5.5").unwrap(), root.join(name));
        fs::remove_file(marker).unwrap();
        assert!(health_target_in(root, name, "community", "0.5.5").is_err());
    }

}
