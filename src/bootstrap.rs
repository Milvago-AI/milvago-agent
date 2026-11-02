//! A deployment token can create identities, but is never used as a device credential.
use crate::{Result, State, Store};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{DateTime, Utc};

use serde::{Deserialize, Serialize};
use std::{io::Read, path::Path};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct InstallerProvision {
    pub server_url: String,
    pub policy_public_key: String,
    pub update_public_key: String,
    pub bootstrap_token: String,
    pub profile_id: Uuid,
    pub edition: String,
    pub platform: String,
    pub version: String,
    pub expires_at: DateTime<Utc>,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct PendingInstallation {
    pub(crate) provision: InstallerProvision,
    pub(crate) installation_id: Uuid,
    pub(crate) installation_secret: String,
    pub(crate) hostname: String,
}
/// Where an identity was issued, and the organization package that can issue another.
/// The deployment key is kept here, in the machine-encrypted state, because after the
/// first self-update the cached installer is a generic package that no longer holds it.
#[derive(Serialize, Deserialize, Clone)]
pub struct MachineBinding {
    pub(crate) fingerprint: String,
    /// Machine name when bound, and the device label derived from it (a filter's
    /// label is "<name>-filter"); a clone keeps the suffix under its own name.
    pub(crate) host: String,
    pub(crate) label: String,
    pub(crate) provision: Option<InstallerProvision>,
}

fn machine_name() -> String {
    #[cfg(windows)]
    let name = std::env::var("COMPUTERNAME").unwrap_or_default();
    #[cfg(not(windows))]
    let name = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
    name.trim().chars().filter(|c| !c.is_control()).take(100).collect()
}

/// What changes when a disk is copied to another machine. `None` when it cannot be
/// read this pass: detection then waits, it never guesses.
/// Windows: MachineGuid and the machine account domain SID (sysprep regenerates the
/// latter; which clone tools change which is measured, not assumed — see the notes).
/// Linux: /etc/machine-id, regenerated on first boot of a properly sealed image.
fn machine_fingerprint() -> Option<String> {
    #[cfg(windows)]
    {
        #[link(name = "advapi32")]
        unsafe extern "system" {
            fn RegGetValueW(key: isize, sub: *const u16, value: *const u16, flags: u32, kind: *mut u32, data: *mut std::ffi::c_void, size: *mut u32) -> i32;
            fn LookupAccountNameW(system: *const u16, name: *const u16, sid: *mut std::ffi::c_void, sid_len: *mut u32, domain: *mut u16, domain_len: *mut u32, kind: *mut u32) -> i32;
            fn ConvertSidToStringSidW(sid: *mut std::ffi::c_void, out: *mut *mut u16) -> i32;
        }
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn LocalFree(p: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
        }
        let wide = |text: &str| -> Vec<u16> { text.encode_utf16().chain(Some(0)).collect() };
        let (sub, value) = (wide(r"SOFTWARE\Microsoft\Cryptography"), wide("MachineGuid"));
        let mut guid = [0u16; 64];
        let mut size = (guid.len() * 2) as u32;
        // RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY.
        if unsafe { RegGetValueW(0x80000002u32 as i32 as isize, sub.as_ptr(), value.as_ptr(), 0x0001_0002,
            std::ptr::null_mut(), guid.as_mut_ptr().cast(), &mut size) } != 0 {
            return None;
        }
        let guid = String::from_utf16(&guid[..guid.iter().position(|&c| c == 0)?]).ok()?;
        let name = wide(&machine_name());
        let (mut sid, mut sid_len, mut domain, mut domain_len, mut kind) = ([0u8; 68], 68u32, [0u16; 256], 256u32, 0u32);
        if unsafe { LookupAccountNameW(std::ptr::null(), name.as_ptr(), sid.as_mut_ptr().cast(), &mut sid_len,
            domain.as_mut_ptr(), &mut domain_len, &mut kind) } == 0 {
            return None;
        }
        let mut text = std::ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(sid.as_mut_ptr().cast(), &mut text) } == 0 {
            return None;
        }
        let mut length = 0;
        while unsafe { *text.add(length) } != 0 { length += 1; }
        let machine = String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) }).ok();
        unsafe { LocalFree(text.cast()) };
        let machine = machine?;
        (!guid.is_empty()).then(|| format!("{guid}|{machine}"))
    }
    #[cfg(target_os = "linux")]
    {
        let id = std::fs::read_to_string("/etc/machine-id").ok()?;
        let id = id.trim();
        (id.len() == 32 && id.bytes().all(|c| c.is_ascii_hexdigit())).then(|| id.to_owned())
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    { None }
}

/// A DNS name (any case, returned lower-case) or an Entra tenant ID; `None` otherwise.
fn domain_name(text: &str) -> Option<String> {
    let name = text.trim().trim_end_matches('.').to_ascii_lowercase();
    let label = |l: &str| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-');
    (!name.is_empty() && name.len() <= 253 && name.split('.').all(label)).then_some(name)
}
/// `default_realm` of a krb5.conf (`realm join`, SSSD and winbind all set it).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn krb5_realm(text: &str) -> Option<String> {
    let mut libdefaults = false;
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            libdefaults = line.eq_ignore_ascii_case("[libdefaults]");
        } else if let Some((key, value)) = line.split_once('=').filter(|_| libdefaults) {
            if key.trim() == "default_realm" {
                return domain_name(value);
            }
        }
    }
    None
}

/// The directories this machine declares itself joined to, sent at enrollment so an
/// organization can approve by network *and* domain. Declared, never proven: the server
/// only narrows a network rule with it. Windows: the Active Directory DNS domain and the
/// Entra ID tenant; Linux: the Kerberos realm of `realm join`.
pub fn machine_domains() -> Vec<serde_json::Value> {
    let mut domains = Vec::new();
    #[cfg(windows)]
    {
        #[link(name = "netapi32")]
        unsafe extern "system" {
            fn NetGetJoinInformation(server: *const u16, name: *mut *mut u16, status: *mut u32) -> u32;
            fn NetApiBufferFree(buffer: *mut std::ffi::c_void) -> u32;
        }
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetComputerNameExW(kind: u32, buffer: *mut u16, size: *mut u32) -> i32;
        }
        let (mut name, mut status) = (std::ptr::null_mut(), 0u32);
        let joined = unsafe { NetGetJoinInformation(std::ptr::null(), &mut name, &mut status) } == 0 && status == 3; // NetSetupDomainName
        if !name.is_null() {
            unsafe { NetApiBufferFree(name.cast()) };
        }
        let mut buffer = [0u16; 256];
        let mut size = buffer.len() as u32;
        // ComputerNameDnsDomain: the primary DNS suffix, the AD DNS domain once joined.
        if joined && unsafe { GetComputerNameExW(2, buffer.as_mut_ptr(), &mut size) } != 0 {
            if let Some(dns) = domain_name(&String::from_utf16_lossy(&buffer[..size as usize])) {
                domains.push(serde_json::json!({"kind": "ad", "name": dns}));
            }
        }
        let root = r"SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo";
        for tenant in windows_subkeys(root).into_iter().filter_map(|join| windows_string(&format!(r"{root}\{join}"), "TenantId")) {
            if let Some(tenant) = Uuid::parse_str(tenant.trim()).ok().map(|id| id.to_string()) {
                if !domains.iter().any(|d| d["name"] == tenant) {
                    domains.push(serde_json::json!({"kind": "entra", "name": tenant}));
                }
            }
        }
    }
    #[cfg(target_os = "linux")]
    if let Some(realm) = std::fs::read_to_string("/etc/krb5.conf").ok().as_deref().and_then(krb5_realm) {
        domains.push(serde_json::json!({"kind": "realm", "name": realm}));
    }
    domains.truncate(4);
    domains
}
#[cfg(windows)]
fn windows_subkeys(path: &str) -> Vec<String> {
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn RegOpenKeyExW(key: isize, sub: *const u16, options: u32, access: u32, result: *mut isize) -> i32;
        fn RegEnumKeyExW(key: isize, index: u32, name: *mut u16, len: *mut u32, reserved: *mut u32, class: *mut u16, class_len: *mut u32, time: *mut u64) -> i32;
        fn RegCloseKey(key: isize) -> i32;
    }
    let sub: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    let mut key = 0isize;
    // HKLM, KEY_READ | KEY_WOW64_64KEY.
    if unsafe { RegOpenKeyExW(0x80000002u32 as i32 as isize, sub.as_ptr(), 0, 0x20119, &mut key) } != 0 {
        return Vec::new();
    }
    let mut names = Vec::new();
    for index in 0..16 {
        let (mut name, mut len) = ([0u16; 256], 256u32);
        if unsafe { RegEnumKeyExW(key, index, name.as_mut_ptr(), &mut len, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()) } != 0 {
            break;
        }
        names.push(String::from_utf16_lossy(&name[..len as usize]));
    }
    unsafe { RegCloseKey(key) };
    names
}
#[cfg(windows)]
fn windows_string(path: &str, value: &str) -> Option<String> {
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn RegGetValueW(key: isize, sub: *const u16, value: *const u16, flags: u32, kind: *mut u32, data: *mut std::ffi::c_void, size: *mut u32) -> i32;
    }
    let (sub, name): (Vec<u16>, Vec<u16>) = (path.encode_utf16().chain(Some(0)).collect(), value.encode_utf16().chain(Some(0)).collect());
    let mut data = [0u16; 128];
    let mut size = (data.len() * 2) as u32;
    // RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY.
    (unsafe { RegGetValueW(0x80000002u32 as i32 as isize, sub.as_ptr(), name.as_ptr(), 0x0001_0002, std::ptr::null_mut(), data.as_mut_ptr().cast(), &mut size) } == 0)
        .then(|| String::from_utf16_lossy(&data[..data.iter().position(|&c| c == 0).unwrap_or(data.len())]))
}

/// Bind an identity to this machine the first time it is seen, and turn a copy of it
/// found on another machine into a new installation. The copy's identity is archived
/// before anything else, so two machines never share a credential, even when no
/// deployment key is available to register the copy again.
fn follow_machine(home: &Path, edition: &str, fingerprint: Option<String>, host: &str) -> Result<()> {
    let Some(fingerprint) = fingerprint else { return Ok(()) };
    let (label, provision) = {
        let store = Store::open(home)?;
        let mut state = store.load()?;
        if state.credential.is_empty() && state.pending_installation.is_none() {
            return Ok(());
        }
        let binding = match &state.machine {
            Some(binding) if binding.fingerprint == fingerprint => return Ok(()),
            Some(binding) => binding.clone(),
            None => {
                let pending = state.pending_installation.as_ref();
                state.machine = Some(MachineBinding {
                    fingerprint,
                    host: host.into(),
                    label: pending.map_or_else(|| host.to_string(), |p| p.hostname.clone()),
                    provision: pending.map(|p| p.provision.clone()),
                });
                return store.save(&state);
            }
        };
        crate::log::info("this identity was issued on another machine (cloned image); archived, re-registering as a new device");
        store.archive_identity()?;
        store.save(&State::default())?;
        let label = match binding.label.strip_prefix(binding.host.as_str()) {
            Some(suffix) if !binding.host.is_empty() => format!("{host}{suffix}"),
            _ => host.to_string(),
        };
        (label, binding.provision)
    };
    let store = Store::open(home)?;
    let mut state = store.load()?;
    let provision = provision.filter(|p| p.validate_stored(edition).is_ok());
    if let Some(provision) = &provision {
        let mut secret = [0; 32];
        crate::fill_random(&mut secret);
        state.pending_installation = Some(PendingInstallation {
            provision: provision.clone(),
            installation_id: Uuid::new_v4(),
            installation_secret: URL_SAFE_NO_PAD.encode(secret),
            hostname: label.clone(),
        });
    } else {
        crate::log::error("cloned image: no usable deployment key; reinstall the organization package on this machine");
    }
    state.machine = Some(MachineBinding { fingerprint, host: host.into(), label, provision });
    store.save(&state)
}

impl PendingInstallation {
    pub(crate) fn validate_local(&self, edition: &str) -> Result<()> {
        self.provision.validate_stored(edition)?;
        if self.installation_id.is_nil() || self.installation_secret.is_empty() || self.hostname.is_empty() {
            return Err("invalid pending installation".into());
        }
        Ok(())
    }
}
pub fn validate_organization_package(bytes: &[u8], edition: &str) -> Result<()> {
    let provision: InstallerProvision = serde_json::from_slice(bytes)?;
    provision.validate(edition)
}
impl InstallerProvision {
    pub fn validate(&self, edition: &str) -> Result<()> {
        if self.version != env!("CARGO_PKG_VERSION") { return Err("installer version mismatch".into()); }
        self.validate_stored(edition)
    }
    // Already staged provisioning remains valid after a binary upgrade. Version
    // authorizes a new package at staging, not the lifetime of an offline identity.
    fn validate_stored(&self, edition: &str) -> Result<()> {
        crate::trusted_url(&self.server_url)?;
        for key in [&self.policy_public_key, &self.update_public_key] {
            let raw: [u8; 32] = STANDARD
                .decode(key)?
                .try_into()
                .map_err(|_| "invalid installation trust anchor")?;
            ed25519_dalek::VerifyingKey::from_bytes(&raw)?;
        }
        if self.edition != edition
            || !matches!(edition, "community" | "commercial")
            || self.platform != std::env::consts::OS
            || self.expires_at <= Utc::now()
            || URL_SAFE_NO_PAD.decode(&self.bootstrap_token)?.len() != 32
        {
            return Err("installation provisioning rejected".into());
        }
        Ok(())
    }
}
/// Persist before the first network request, so a dropped response can be retried safely.
///
/// `replace_foreign` is the installer's fresh-installation signal: the product is not
/// installed, an administrator is running an organization installer, and whatever an
/// earlier — since removed — installation left behind must not make the machine
/// un-installable. An identity of the *same* organization is always kept, so a retried
/// or reinstalled machine recovers its device. One that belongs elsewhere (another
/// organization, or the same one on a server that has been re-keyed) is replaced only
/// under this flag and refused otherwise. Upgrades and repairs never pass it.
pub fn stage(
    home: &Path,
    bytes: &[u8],
    hostname: &str,
    edition: &str,
    replace_foreign: bool,
) -> Result<()> {
    if bytes.len() > 16384
        || hostname.is_empty()
        || hostname.len() > 128
        || hostname.chars().any(char::is_control)
    {
        return Err("invalid installation configuration".into());
    }
    // Generic upgrade packages carry no deployment token. They can only repair
    // an already provisioned installation, never create a new identity.
    if serde_json::from_slice::<serde_json::Value>(bytes)? == serde_json::json!({}) {
        let state = Store::open(home)?.load()?;
        return if !state.credential.is_empty() || state.pending_installation.is_some() {
            Ok(())
        } else {
            Err("a preconfigured organization installer is required".into())
        };
    }
    let provision: InstallerProvision = serde_json::from_slice(bytes)?;
    let store = Store::open(home)?;
    let mut state = store.load()?;
    // `installer_identity` is what the server resolves; here the organization is
    // recognised by the two fields that are derived from it and cannot be swapped
    // without changing organization: the instance origin and the per-organization
    // policy anchor.
    let same_organization = |server_url: &str, policy_public_key: &str, other_edition: &str| {
        server_url == provision.server_url
            && policy_public_key == provision.policy_public_key
            && other_edition == provision.edition
    };
    if !state.credential.is_empty() {
        if same_organization(&state.server_url, &state.public_key, edition) {
            // A device enrolled before bindings kept a deployment key gets one from the
            // organization package it is repaired or started with.
            if let Some(binding) = state.machine.as_mut().filter(|b| b.provision.is_none()) {
                if provision.validate_stored(edition).is_ok() {
                    binding.provision = Some(provision.clone());
                    store.save(&state)?;
                }
            }
            // An old/expired package may repair files, but cannot authorize
            // re-enrollment. A current organization MSI records explicit intent
            // without requiring connectivity during installation.
            if provision.version != env!("CARGO_PKG_VERSION") || provision.expires_at <= Utc::now() {
                return Ok(());
            }
            provision.validate(edition)?;
            let pending = state.pending_reinstallation.get_or_insert_with(|| {
                let mut secret = [0; 32];
                crate::fill_random(&mut secret);
                PendingInstallation {
                    provision: provision.clone(), installation_id: Uuid::new_v4(),
                    installation_secret: URL_SAFE_NO_PAD.encode(secret), hostname: hostname.into(),
                }
            });
            pending.provision = provision;
            return store.save(&state);
        }
        if !replace_foreign {
            return Err(
                "existing identity belongs to another organization; reprovision explicitly".into(),
            );
        }
        // Validated before anything is discarded: a rejected package must never cost
        // the machine its identity.
        provision.validate(edition)?;
        eprintln!(
            "Milvago: the identity enrolled with {} is replaced by this fresh installation.",
            state.server_url
        );
        state = State::default();
    }
    if state.pending_installation.as_ref().is_some_and(|pending| {
        !same_organization(
            &pending.provision.server_url,
            &pending.provision.policy_public_key,
            &pending.provision.edition,
        )
    }) {
        if !replace_foreign {
            return Err("another organization's installation is already pending".into());
        }
        provision.validate(edition)?;
        eprintln!(
            "Milvago: a pending installation for another organization is discarded by this fresh installation."
        );
        state.pending_installation = None;
    }
    if let Some(pending) = &state.pending_installation {
        // A pending installation belongs to an organization, not to the deployment key
        // that bought it. After a rotation the token it holds is dead, and refusing to
        // replace it would leave the machine permanently un-installable — a repair that
        // can never succeed and can never be superseded.
        //
        // The identity the agent chose is deliberately kept: the server recognises an
        // installation by that identity, so a retried installation still recovers the
        // same device instead of creating a second one.
        //
        // A package that changes neither organization nor key contributes nothing and
        // is therefore not validated either: a service re-reading the file it was
        // installed with must not fail on a version its binary has since left behind.
        if pending.provision.profile_id == provision.profile_id {
            return Ok(());
        }
        provision.validate(edition)?;
        let renewed = PendingInstallation {
            provision,
            installation_id: pending.installation_id,
            installation_secret: pending.installation_secret.clone(),
            hostname: pending.hostname.clone(),
        };
        state.pending_installation = Some(renewed);
        return store.save(&state);
    }
    provision.validate(edition)?;
    let mut secret = [0; 32];
    crate::fill_random(&mut secret);
    state.pending_installation = Some(PendingInstallation {
        provision,
        installation_id: Uuid::new_v4(),
        installation_secret: URL_SAFE_NO_PAD.encode(secret),
        hostname: hostname.into(),
    });
    store.save(&state)
}
/// The optional trailing `--reprovision` of `bootstrap`, `bootstrap-msi` and the
/// collector's `provision`, at `position` in `args`. The installer passes it on a
/// fresh installation only. Anything else in that position is a mistake worth
/// refusing, never a flag worth ignoring.
pub fn replace_foreign_flag(args: &[String], position: usize) -> Result<bool> {
    match args.get(position).map(String::as_str) {
        None => Ok(false),
        Some("--reprovision") if args.len() == position + 1 => Ok(true),
        Some(other) => Err(format!("unexpected argument: {other}").into()),
    }
}
/// Non-secret deployment origin for registering browser extension updates.
pub fn installation_server(home: &Path) -> Result<String> {
    let store = Store::open(home)?;
    let state = store.load()?;
    let url = if state.server_url.is_empty() {
        &state.pending_installation.as_ref().ok_or("installation not provisioned")?.provision.server_url
    } else {
        &state.server_url
    };
    crate::trusted_url(url)?;
    Ok(url.trim_end_matches('/').to_owned())
}

pub fn resume(home: &Path, edition: &str, capabilities: &[&str]) -> Result<()> {
    follow_machine(home, edition, machine_fingerprint(), &machine_name())?;
    // A failed probe must not interrupt normal policy/event sync for an existing
    // device, for example when a deployment key has been rotated.
    if crate::reinstallation::resume(home, edition).is_err() {
        crate::log::debug("reinstallation confirmation deferred; existing identity retained");
    }
    // No Store lock is held during the bounded network request: every browser exchange
    // needs it, and a slow link would stall them for the whole client timeout. The server
    // answers a retried installation with the same identity, and the state is checked
    // again under the lock before anything is written.
    let state = { Store::open(home)?.load()? };
    if !state.credential.is_empty() {
        return Ok(());
    }
    let Some(pending) = &state.pending_installation else {
        return Ok(());
    };
    pending.provision.validate_stored(edition)?;
    let origin = crate::trusted_url(&pending.provision.server_url)?;
    let response = crate::client()?.post(origin.join("/v2/install")?)
        .bearer_auth(&pending.provision.bootstrap_token)
        .json(&serde_json::json!({"installation_id":pending.installation_id,"installation_secret":pending.installation_secret,
            "hostname":pending.hostname,"platform":std::env::consts::OS,"version":env!("CARGO_PKG_VERSION"),"capabilities":capabilities,
            "machine_domains":machine_domains()}))
        .send()?.error_for_status()?;
    let mut bytes = Vec::new();
    response.take(16385).read_to_end(&mut bytes)?;
    if bytes.len() > 16384 {
        return Err("installation response too large".into());
    }
    #[derive(Deserialize)]
    struct Reply {
        device_id: Uuid,
        credential: String,
    }
    let reply: Reply = serde_json::from_slice(&bytes)?;
    if URL_SAFE_NO_PAD.decode(&reply.credential)?.len() != 32 {
        return Err("invalid device credential".into());
    }
    let store = Store::open(home)?;
    let mut current = store.load()?;
    if !current.credential.is_empty()
        || serde_json::to_vec(&current.pending_installation)? != serde_json::to_vec(&state.pending_installation)? {
        return Err("installation superseded".into());
    }
    current.device_id = reply.device_id.to_string();
    current.credential = reply.credential;
    current.server_url = pending.provision.server_url.clone();
    current.public_key = pending.provision.policy_public_key.clone();
    current.update_public_key = Some(pending.provision.update_public_key.clone());
    current.pending_installation = None;
    // The key that just worked is the one a clone of this machine would register with.
    if let Some(binding) = current.machine.as_mut() {
        binding.provision = Some(pending.provision.clone());
    }
    store.save(&current)
}

/// Read the bounded provisioning stream embedded by the organization package builder.
#[cfg(windows)]
pub fn msi_provision(path: &Path) -> Result<Vec<u8>> { msi_value(path, false) }
#[cfg(windows)]
pub fn msi_product_code(path: &Path) -> Result<String> {
    let value = String::from_utf8(msi_value(path, true)?)?;
    let id = Uuid::parse_str(value.trim_matches(['{', '}']))?;
    Ok(format!("{{{}}}", id.to_string().to_uppercase()))
}
#[cfg(windows)]
fn msi_value(path: &Path, product: bool) -> Result<Vec<u8>> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "msi")]
    unsafe extern "system" {
        fn MsiOpenDatabaseW(path: *const u16, persist: *const u16, handle: *mut u32) -> u32;
        fn MsiDatabaseOpenViewW(db: u32, query: *const u16, view: *mut u32) -> u32;
        fn MsiViewExecute(view: u32, record: u32) -> u32;
        fn MsiViewFetch(view: u32, record: *mut u32) -> u32;
        fn MsiRecordReadStream(record: u32, field: u32, buffer: *mut u8, size: *mut u32) -> u32;
        fn MsiRecordGetStringW(record: u32, field: u32, buffer: *mut u16, size: *mut u32) -> u32;
        fn MsiCloseHandle(handle: u32) -> u32;
    }
    struct Handle(u32);
    impl Drop for Handle {
        fn drop(&mut self) {
            if self.0 != 0 {
                unsafe {
                    MsiCloseHandle(self.0);
                }
            }
        }
    }
    fn checked(code: u32) -> Result<()> {
        if code == 0 {
            Ok(())
        } else {
            Err("installer provisioning stream unavailable".into())
        }
    }
    if !std::fs::metadata(path)?.is_file() || std::fs::metadata(path)?.len() > 128 * 1024 * 1024 {
        return Err("invalid installer package".into());
    }
    let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let query: Vec<u16> = if product { "SELECT `Value` FROM `Property` WHERE `Property` = 'ProductCode'" }
        else { "SELECT `Data` FROM `Binary` WHERE `Name` = 'MilvagoProvision'" }
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut db = Handle(0);
    let mut view = Handle(0);
    let mut record = Handle(0);
    unsafe {
        checked(MsiOpenDatabaseW(path.as_ptr(), std::ptr::null(), &mut db.0))?;
        checked(MsiDatabaseOpenViewW(db.0, query.as_ptr(), &mut view.0))?;
        checked(MsiViewExecute(view.0, 0))?;
        checked(MsiViewFetch(view.0, &mut record.0))?;
        if product {
            let mut buffer = [0u16; 40];
            let mut size = buffer.len() as u32;
            checked(MsiRecordGetStringW(record.0, 1, buffer.as_mut_ptr(), &mut size))?;
            return Ok(String::from_utf16(&buffer[..size as usize])?.into_bytes());
        }
        let mut bytes = vec![0u8; 16385];
        let mut size = bytes.len() as u32;
        checked(MsiRecordReadStream(
            record.0,
            1,
            bytes.as_mut_ptr(),
            &mut size,
        ))?;
        if size > 16384 {
            return Err("installer provisioning exceeds limit".into());
        }
        bytes.truncate(size as usize);
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn provision() -> InstallerProvision {
        let public = STANDARD.encode(
            ed25519_dalek::SigningKey::from_bytes(&[71; 32])
                .verifying_key()
                .as_bytes(),
        );
        InstallerProvision {
            server_url: "http://localhost:1".into(),
            policy_public_key: public.clone(),
            update_public_key: public,
            bootstrap_token: URL_SAFE_NO_PAD.encode([72; 32]),
            profile_id: Uuid::new_v4(),
            edition: "community".into(),
            platform: std::env::consts::OS.into(),
            version: env!("CARGO_PKG_VERSION").into(),
            expires_at: Utc::now() + chrono::Duration::days(1),
        }
    }
    #[test]
    fn declared_domains_are_plain_dns_names_or_tenant_ids() {
        assert_eq!(domain_name(" CORP.Example.COM. ").as_deref(), Some("corp.example.com"));
        assert_eq!(domain_name("3fa85f64-5717-4562-b3fc-2c963f66afa6").as_deref(), Some("3fa85f64-5717-4562-b3fc-2c963f66afa6"));
        for bad in ["", "corp;example.com", "-corp.example.com", "corp..example.com", "c\u{0441}rp.example.com", &"a".repeat(64)] {
            assert!(domain_name(bad).is_none(), "{bad}");
        }
        let krb5 = "[libdefaults]\n  dns_lookup_realm = false\n  default_realm = CORP.EXAMPLE.COM\n[realms]\n default_realm = OTHER.TEST\n";
        assert_eq!(krb5_realm(krb5).as_deref(), Some("corp.example.com"));
        assert!(krb5_realm("[realms]\n default_realm = CORP.EXAMPLE.COM\n").is_none(), "only [libdefaults] names the machine's realm");
        // Read-only on this machine: whatever it declares is well formed and bounded.
        let domains = machine_domains();
        assert!(domains.len() <= 4 && domains.iter().all(|d| d["name"].as_str().and_then(domain_name).is_some()));
    }
    #[test]
    fn a_cloned_identity_is_archived_and_re_registers_under_the_clones_name() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let organization = provision();
        stage(home, &serde_json::to_vec(&organization).unwrap(), "golden-filter", "community", false).unwrap();
        // First sight binds; the same machine changes nothing.
        follow_machine(home, "community", Some("machine-a".into()), "golden").unwrap();
        {
            let store = Store::open(home).unwrap();
            let mut state = store.load().unwrap();
            state.credential = URL_SAFE_NO_PAD.encode([5u8; 32]);
            state.device_id = Uuid::new_v4().to_string();
            state.pending_installation = None;
            store.save(&state).unwrap();
        }
        follow_machine(home, "community", Some("machine-a".into()), "golden").unwrap();
        let original = Store::open(home).unwrap().load().unwrap();
        assert!(!original.credential.is_empty());
        // Unreadable fingerprint: wait, never guess.
        follow_machine(home, "community", None, "clone-7").unwrap();
        assert_eq!(Store::open(home).unwrap().load().unwrap().credential, original.credential);
        follow_machine(home, "community", Some("machine-b".into()), "clone-7").unwrap();
        let cloned = Store::open(home).unwrap().load().unwrap();
        assert!(cloned.credential.is_empty() && cloned.device_id.is_empty(), "the clone kept the original's identity");
        let pending = cloned.pending_installation.expect("the clone re-registers");
        assert_eq!(pending.hostname, "clone-7-filter");
        assert_eq!(pending.provision.bootstrap_token, organization.bootstrap_token);
        assert!(std::fs::read_dir(home).unwrap().flatten().any(|e| e.file_name().to_string_lossy().starts_with("retired-identity-")));
        // A second pass on the clone is stable.
        follow_machine(home, "community", Some("machine-b".into()), "clone-7").unwrap();
        assert_eq!(Store::open(home).unwrap().load().unwrap().pending_installation.unwrap().installation_id, pending.installation_id);
    }
    #[test]
    fn a_clone_without_a_deployment_key_drops_the_identity_and_stays_unregistered() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        {
            let store = Store::open(home).unwrap();
            let mut state = store.load().unwrap();
            state.credential = URL_SAFE_NO_PAD.encode([6u8; 32]);
            store.save(&state).unwrap();
        }
        // Enrolled before bindings existed: bound without a key.
        follow_machine(home, "community", Some("machine-a".into()), "golden").unwrap();
        follow_machine(home, "community", Some("machine-b".into()), "clone").unwrap();
        let state = Store::open(home).unwrap().load().unwrap();
        assert!(state.credential.is_empty() && state.pending_installation.is_none());
        follow_machine(home, "community", Some("machine-c".into()), "clone").unwrap();
        assert!(Store::open(home).unwrap().load().unwrap().machine.unwrap().fingerprint == "machine-b");
    }
    #[test]
    fn existing_offline_provisioning_remains_valid_after_binary_upgrade() {
        let mut original = provision();
        original.version = "0.1.0".into();
        let pending = PendingInstallation { provision: original, installation_id: Uuid::new_v4(),
            installation_secret: URL_SAFE_NO_PAD.encode([39;32]), hostname: "offline-device".into() };
        assert!(pending.provision.validate("community").is_err(), "old packages cannot authorize a new install");
        assert!(pending.validate_local("community").is_ok(), "staged identity survives upgrade");
        assert!(pending.validate_local("commercial").is_err());
    }
    #[test]
    fn generic_package_cannot_authorize_cross_edition_migration() {
        assert!(validate_organization_package(b"{}", "commercial").is_err());
        assert!(validate_organization_package(&serde_json::to_vec(&provision()).unwrap(), "commercial").is_err());
        assert!(validate_organization_package(&serde_json::to_vec(&provision()).unwrap(), "community").is_ok());
    }
    #[test]
    fn offline_installation_is_encrypted_and_retry_identity_is_stable() {
        let dir = tempfile::tempdir().unwrap();
        let p = provision();
        let raw = serde_json::to_vec(&p).unwrap();
        stage(dir.path(), &raw, "test-device", "community", false).unwrap();
        let first = Store::open(dir.path())
            .unwrap()
            .load()
            .unwrap()
            .pending_installation
            .unwrap()
            .installation_id;
        assert!(resume(dir.path(), "community", &[]).is_err());
        stage(dir.path(), &raw, "test-device", "community", false).unwrap();
        let pending = Store::open(dir.path())
            .unwrap()
            .load()
            .unwrap()
            .pending_installation
            .unwrap();
        assert_eq!(first, pending.installation_id);
        let encrypted = std::fs::read(dir.path().join("state.bin")).unwrap();
        assert!(!String::from_utf8_lossy(&encrypted).contains(&p.bootstrap_token));
        assert!(!String::from_utf8_lossy(&encrypted).contains(&pending.installation_secret));
    }
    // A machine that staged an installation while offline keeps it pending. If the
    // organization rotates its deployment key in the meantime, the pending token is
    // dead — and refusing the newer installer would leave that machine permanently
    // un-installable, with a repair that can never succeed and can never be replaced.
    #[test]
    fn a_rotated_key_replaces_a_pending_installation_without_losing_its_identity() {
        let dir = tempfile::tempdir().unwrap();
        let first = provision();
        stage(dir.path(), &serde_json::to_vec(&first).unwrap(), "test-device", "community", false).unwrap();
        assert!(resume(dir.path(), "community", &[]).is_err());
        let before = Store::open(dir.path()).unwrap().load().unwrap().pending_installation.unwrap();

        let mut rotated = provision();
        rotated.profile_id = Uuid::new_v4();
        rotated.bootstrap_token = URL_SAFE_NO_PAD.encode([73; 32]);
        stage(dir.path(), &serde_json::to_vec(&rotated).unwrap(), "test-device", "community", false).unwrap();

        let after = Store::open(dir.path()).unwrap().load().unwrap().pending_installation.unwrap();
        // The new token is adopted, so the installation can complete at all.
        assert_eq!(after.provision.bootstrap_token, rotated.bootstrap_token);
        // The identity the agent chose is kept, so the server still recognises this
        // installation and returns the device it already created rather than a second.
        assert_eq!(after.installation_id, before.installation_id);
        assert_eq!(after.installation_secret, before.installation_secret);
    }

    // The same leniency must not cross an organization boundary.
    #[test]
    fn a_pending_installation_of_another_organization_is_still_refused() {
        let dir = tempfile::tempdir().unwrap();
        stage(dir.path(), &serde_json::to_vec(&provision()).unwrap(), "test-device", "community", false).unwrap();
        assert!(resume(dir.path(), "community", &[]).is_err());
        let mut other = provision();
        other.profile_id = Uuid::new_v4();
        other.policy_public_key = STANDARD.encode(
            ed25519_dalek::SigningKey::from_bytes(&[99; 32]).verifying_key().as_bytes(),
        );
        assert!(stage(dir.path(), &serde_json::to_vec(&other).unwrap(), "test-device", "community", false).is_err());
    }

    #[test]
    fn rejected_configuration_never_creates_state() {
        for mutation in [0, 1, 2] {
            let dir = tempfile::tempdir().unwrap();
            let mut p = provision();
            match mutation {
                0 => p.edition = "commercial".into(),
                1 => p.server_url = "http://untrusted.example".into(),
                _ => p.expires_at = Utc::now() - chrono::Duration::hours(1),
            };
            assert!(
                stage(
                    dir.path(),
                    &serde_json::to_vec(&p).unwrap(),
                    "test-device",
                    "community",
                    false
                )
                .is_err()
            );
            assert!(!dir.path().join("state.bin").exists());
        }
    }
    #[test]
    fn generic_upgrade_requires_existing_identity_and_expired_profile_does_not_disable_it() {
        let dir = tempfile::tempdir().unwrap();
        assert!(stage(dir.path(), b"{}", "test-device", "community", false).is_err());
        let mut p = provision();
        let store = Store::open(dir.path()).unwrap();
        let mut state = store.load().unwrap();
        state.server_url = p.server_url.clone(); state.public_key = p.policy_public_key.clone();
        state.credential = URL_SAFE_NO_PAD.encode([75;32]);
        store.save(&state).unwrap(); drop(store);
        p.expires_at = Utc::now()-chrono::Duration::days(1);
        assert!(stage(dir.path(), &serde_json::to_vec(&p).unwrap(), "test-device", "community", false).is_ok());
        assert!(stage(dir.path(), b"{}", "test-device", "community", false).is_ok());
        assert_eq!(Store::open(dir.path()).unwrap().load().unwrap().credential,state.credential);
    }

    fn foreign_key() -> String {
        STANDARD.encode(
            ed25519_dalek::SigningKey::from_bytes(&[99; 32])
                .verifying_key()
                .as_bytes(),
        )
    }
    // An identity enrolled elsewhere — another organization, or the same one on a
    // server that has since been re-keyed — survives an uninstall by design. Seen from
    // a later installer it is foreign, and the machine was permanently un-installable
    // (2026-09-11: every download after the server was re-keyed failed with a mute
    // 1722). A fresh installation replaces it; without that signal the refusal stands
    // and costs nothing.
    #[test]
    fn a_fresh_installation_replaces_a_foreign_identity_only_when_told_to() {
        let dir = tempfile::tempdir().unwrap();
        let current = provision();
        let store = Store::open(dir.path()).unwrap();
        let mut foreign = store.load().unwrap();
        foreign.server_url = current.server_url.clone();
        foreign.public_key = foreign_key();
        foreign.device_id = Uuid::new_v4().to_string();
        foreign.credential = URL_SAFE_NO_PAD.encode([75; 32]);
        store.save(&foreign).unwrap();
        drop(store);
        let raw = serde_json::to_vec(&current).unwrap();
        assert!(stage(dir.path(), &raw, "test-device", "community", false).is_err());
        let kept = Store::open(dir.path()).unwrap().load().unwrap();
        assert_eq!(kept.credential, foreign.credential);
        assert!(kept.pending_installation.is_none());

        stage(dir.path(), &raw, "test-device", "community", true).unwrap();
        let replaced = Store::open(dir.path()).unwrap().load().unwrap();
        assert!(replaced.credential.is_empty());
        assert!(replaced.device_id.is_empty());
        let pending = replaced.pending_installation.unwrap();
        assert_eq!(pending.provision.policy_public_key, current.policy_public_key);
        assert_eq!(pending.provision.bootstrap_token, current.bootstrap_token);
        // The same signal on the same organization keeps the identity it just created.
        stage(dir.path(), &raw, "test-device", "community", true).unwrap();
        let again = Store::open(dir.path()).unwrap().load().unwrap().pending_installation.unwrap();
        assert_eq!(again.installation_id, pending.installation_id);
    }
    // The signal never turns a rejected package into a way of destroying an identity.
    #[test]
    fn a_rejected_package_costs_no_identity_even_on_a_fresh_installation() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let mut foreign = store.load().unwrap();
        foreign.server_url = "http://localhost:1".into();
        foreign.public_key = foreign_key();
        foreign.credential = URL_SAFE_NO_PAD.encode([75; 32]);
        store.save(&foreign).unwrap();
        drop(store);
        let mut expired = provision();
        expired.expires_at = Utc::now() - chrono::Duration::hours(1);
        assert!(stage(dir.path(), &serde_json::to_vec(&expired).unwrap(), "test-device", "community", true).is_err());
        let kept = Store::open(dir.path()).unwrap().load().unwrap();
        assert_eq!(kept.credential, foreign.credential);
        assert_eq!(kept.public_key, foreign.public_key);
    }
    #[test]
    fn a_fresh_installation_replaces_a_foreign_pending_installation() {
        let dir = tempfile::tempdir().unwrap();
        let mut foreign = provision();
        foreign.policy_public_key = foreign_key();
        stage(dir.path(), &serde_json::to_vec(&foreign).unwrap(), "test-device", "community", false).unwrap();
        assert!(resume(dir.path(), "community", &[]).is_err());
        let current = provision();
        let raw = serde_json::to_vec(&current).unwrap();
        assert!(stage(dir.path(), &raw, "test-device", "community", false).is_err());
        stage(dir.path(), &raw, "test-device", "community", true).unwrap();
        let pending = Store::open(dir.path()).unwrap().load().unwrap().pending_installation.unwrap();
        assert_eq!(pending.provision.policy_public_key, current.policy_public_key);
    }
    #[test]
    fn the_reprovision_flag_is_the_only_accepted_trailing_argument() {
        let base: Vec<String> = ["bootstrap-msi", "state", "package.msi", "host"].iter().map(|s| s.to_string()).collect();
        assert!(!replace_foreign_flag(&base, 4).unwrap());
        let mut flagged = base.clone();
        flagged.push("--reprovision".into());
        assert!(replace_foreign_flag(&flagged, 4).unwrap());
        let mut wrong = base.clone();
        wrong.push("--force".into());
        assert!(replace_foreign_flag(&wrong, 4).is_err());
        flagged.push("extra".into());
        assert!(replace_foreign_flag(&flagged, 4).is_err());
    }

    /// Serves one `POST /v2/install`; `during` runs while the request is in flight.
    fn install_server(during: impl FnOnce() + Send + 'static) -> (String, std::thread::JoinHandle<()>) {
        use std::io::{BufRead, BufReader, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
            let mut reader = BufReader::new(&mut stream);
            let (mut line, mut length) = (String::new(), 0);
            reader.read_line(&mut line).unwrap();
            assert!(line.starts_with("POST /v2/install HTTP/1.1"));
            loop {
                line.clear();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" { break; }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") { length = v.trim().parse().unwrap(); }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            drop(reader);
            during();
            let reply = serde_json::to_vec(&serde_json::json!({"device_id":Uuid::new_v4(),"credential":URL_SAFE_NO_PAD.encode([73;32])})).unwrap();
            write!(stream, "HTTP/1.1 201 Created\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", reply.len()).unwrap();
            stream.write_all(&reply).unwrap();
        });
        (origin, worker)
    }
    fn staged(origin: &str, dir: &Path) {
        let mut p = provision();
        p.server_url = origin.into();
        stage(dir, &serde_json::to_vec(&p).unwrap(), "synthetic-device", "community", false).unwrap();
    }

    #[test]
    fn installation_request_does_not_hold_the_state_lock() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_owned();
        let (origin, worker) = install_server(move || {
            assert!(Store::read_existing(&home).is_ok(), "state lock held during the network request");
        });
        staged(&origin, dir.path());
        resume(dir.path(), "community", &[]).unwrap();
        worker.join().unwrap();
        let state = Store::open(dir.path()).unwrap().load().unwrap();
        assert_eq!(state.credential, URL_SAFE_NO_PAD.encode([73; 32]));
        assert!(state.pending_installation.is_none());
    }

    #[test]
    fn installation_superseded_during_the_request_is_not_saved() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_owned();
        let (origin, worker) = install_server(move || {
            let store = Store::open(&home).unwrap();
            let mut state = store.load().unwrap();
            state.pending_installation.as_mut().unwrap().installation_id = Uuid::new_v4();
            store.save(&state).unwrap();
        });
        staged(&origin, dir.path());
        assert!(resume(dir.path(), "community", &[]).is_err());
        worker.join().unwrap();
        let state = Store::open(dir.path()).unwrap().load().unwrap();
        assert!(state.credential.is_empty());
        assert!(state.pending_installation.is_some());
    }
}
