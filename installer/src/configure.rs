//! ConfigureAgent (Install) and RemoveAgent (Remove). Port of `deploy/configure-agent.ps1`,
//! plus the installer fixes of the 2026-09-23 plan: MSI 7 (a CA staged by a deployment
//! tool is judged on its opened handle and replaces the previous one), m2 (a folder a
//! user planted before a first installation is moved aside), m5 (Entra + MDM counts as
//! managed), m6 (120 s per agent step), and the MSI properties `MILVAGO_PROXY`,
//! `MILVAGO_SYSTEM_STORE`, `MILVAGO_SELF_UPDATE`.
use crate::paths::{self, ADMINISTRATORS, Access, SYSTEM};
use crate::reg::{self, RegValue};
use crate::services::{self, Configuration, Recovery, RecoveryAction};
use crate::win::{self, Failure, Result, fail};
use serde_json::{Value as Json, json};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const FORCED: [&str; 6] = ["Google\\Chrome", "Microsoft\\Edge", "BraveSoftware\\Brave", "Chromium", "Vivaldi", "TheBrowserCompany\\Arc"];
const LEGACY_FORCED: [&str; 1] = ["BraveSoftware\\Brave-Browser"];
pub const NATIVE_HOSTS: [&str; 6] = ["Google\\Chrome", "Microsoft\\Edge", "BraveSoftware\\Brave-Browser", "Chromium", "Vivaldi", "Mozilla"];
const STEP: Duration = Duration::from_secs(120);

pub struct Layout {
    pub commercial: bool,
    pub edition: &'static str,
    pub install: PathBuf,
    pub runtime: PathBuf,
    pub state: PathBuf,
    pub edition_root: PathBuf,
    pub data: PathBuf,
    pub programs: PathBuf,
    pub version: String,
    pub agent: PathBuf,
    pub updater: PathBuf,
    pub relay: PathBuf,
    pub agent_service: &'static str,
    pub applier_service: &'static str,
    pub display: &'static str,
}
pub const COLLECTOR_SERVICE: &str = "Milvago Native Collector";

pub fn layout(edition: &str) -> Result<Layout> {
    let commercial = edition == "commercial";
    let folder = if commercial { "Commercial" } else { "Browser" };
    let (programs, data) = (paths::program_files()?, paths::program_data()?);
    let install = programs.join("Milvago").join(folder);
    let marker: Json = std::fs::read(install.join("installation.json")).ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or(Failure { step: "Installation marker unavailable", detail: String::new() })?;
    let version = marker["version"].as_str().unwrap_or_default().to_owned();
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() != 3 || parts.iter().zip([3usize, 3, 5]).any(|(p, n)| p.is_empty() || p.len() > n || !p.bytes().all(|c| c.is_ascii_digit())) {
        return fail("Invalid installed runtime version");
    }
    let runtime = install.join("runtime").join(&version);
    let edition_root = data.join("Milvago").join(folder);
    Ok(Layout {
        commercial,
        edition: if commercial { "commercial" } else { "community" },
        agent: runtime.join(if commercial { "milvago-commercial-bridge.exe" } else { "milvago-browser-agent.exe" }),
        updater: runtime.join("milvago-updater.exe"),
        relay: runtime.join("milvago-relay.exe"),
        state: edition_root.join("state"),
        edition_root,
        runtime,
        install,
        data,
        programs,
        version,
        agent_service: if commercial { "Milvago Agent Logger" } else { "Milvago Agent Logger Community" },
        applier_service: if commercial { "Milvago Update Applier" } else { "Milvago Update Applier Community" },
        // Only the displayed name carries the edition: the service name, and the
        // service SID derived from it, stay what installed machines already have.
        display: if commercial { "Milvago Agent Logger Enterprise" } else { "Milvago Agent Logger Community" },
    })
}

/// Community must never configure over Enterprise.
pub fn refuse_community_over_enterprise(edition: &str) -> Result<()> {
    if edition != "community" {
        return Ok(());
    }
    let programs = paths::program_files()?;
    for name in ["Milvago Agent Logger", "MilvagoCommercialAgent", COLLECTOR_SERVICE, "MilvagoModelFilter"] {
        if services::exists(name)? {
            return fail("Enterprise is installed; Community configuration refused");
        }
    }
    if programs.join("Milvago").join("Commercial").join("installation.json").exists() {
        return fail("Enterprise is installed; Community configuration refused");
    }
    Ok(())
}

fn agent(step: &'static str, executable: &Path, arguments: &[&str]) -> Result<String> {
    win::run(step, executable, arguments, Instant::now() + STEP)
}
/// `Assert-OwnedService` outside Health: an installed service of that name runs one of
/// this product's executables.
fn assert_owned(l: &Layout, name: &str) -> Result<()> {
    let key = format!(r"SYSTEM\CurrentControlSet\Services\{name}");
    if !win::reg_key_exists(&key) {
        return Ok(());
    }
    if !crate::transaction::service_image(&l.programs, name, &win::reg_string(&key, "ImagePath").unwrap_or_default()) {
        return Err(Failure { step: "Service executable ownership mismatch", detail: name.into() });
    }
    Ok(())
}
fn text(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).map(|t| t.trim().to_owned()).map_err(|_| Failure { step: "Extension identity unavailable", detail: String::new() })
}
fn string(name: &str, data: &str) -> RegValue {
    RegValue { name: name.into(), kind: "String".into(), data: Json::String(data.into()) }
}

// ---- Browser policies (`Set-ForcedExtension` … `Remove-NativeHosts`) ----

fn forcelist_key(vendor: &str) -> String {
    format!(r"Software\Policies\{vendor}\ExtensionInstallForcelist")
}
fn slots(vendor: &str) -> Result<Vec<RegValue>> {
    Ok(reg::read_key(&forcelist_key(vendor))?.unwrap_or_default().into_iter()
        .filter(|v| !v.name.is_empty() && v.name.bytes().all(|c| c.is_ascii_digit())).collect())
}
/// Our entry is matched by identity, never by slot number; a free slot is chosen rather
/// than overwriting someone else's.
fn set_forced(vendor: &str, id: &str, url: &str) -> Result<()> {
    let entry = format!("{id};{url}");
    let current = slots(vendor)?;
    if let Some(slot) = current.iter().find(|s| s.data.as_str().is_some_and(|d| d.starts_with(&format!("{id};")))) {
        if slot.data.as_str() != Some(entry.as_str()) {
            reg::write_value(&forcelist_key(vendor), &string(&slot.name, &entry))?;
        }
        return Ok(());
    }
    let used: Vec<u32> = current.iter().filter_map(|s| s.name.parse().ok()).collect();
    let free = (1..).find(|n| !used.contains(n)).unwrap_or(1);
    reg::write_value(&forcelist_key(vendor), &string(&free.to_string(), &entry))
}
/// Best effort per entry, like PowerShell's `Remove-ItemProperty -ErrorAction
/// SilentlyContinue`: an entry that cannot be removed does not fail an uninstall.
fn remove_forced(id: &str, vendors: &[&str]) -> Result<()> {
    for vendor in vendors {
        for slot in slots(vendor)? {
            if slot.data.as_str().is_some_and(|d| d.starts_with(&format!("{id};"))) {
                let _ = reg::remove_value(&forcelist_key(vendor), &slot.name);
            }
        }
    }
    Ok(())
}
/// `override_update_url` makes a self-hosted extension durable: the forcelist URL is
/// only used for the initial installation.
fn set_extension_settings(vendor: &str, id: &str, url: &str) -> Result<()> {
    let key = format!(r"Software\Policies\{vendor}\ExtensionSettings\{id}");
    reg::write_value(&key, &string("installation_mode", "force_installed"))?;
    reg::write_value(&key, &string("update_url", url))?;
    reg::write_value(&key, &RegValue { name: "override_update_url".into(), kind: "DWord".into(), data: json!(1) })?;
    reg::write_value(&key, &string("toolbar_pin", "force_pinned"))
}
/// Best effort, like PowerShell's `Remove-Item -ErrorAction SilentlyContinue`.
fn remove_extension_settings(id: &str, vendors: &[&str]) -> Result<()> {
    for vendor in vendors {
        let _ = reg::delete_tree(&format!(r"Software\Policies\{vendor}\ExtensionSettings\{id}"));
    }
    Ok(())
}
fn firefox_document() -> Json {
    reg::read_key(r"Software\Policies\Mozilla\Firefox").ok().flatten()
        .and_then(|values| reg::value(&values, "ExtensionSettings"))
        .and_then(|value| {
            let raw: String = match &value.data {
                Json::Array(items) => items.iter().filter_map(Json::as_str).collect(),
                Json::String(s) => s.clone(),
                _ => return None,
            };
            serde_json::from_str::<Json>(&raw).ok().filter(Json::is_object)
        })
        .unwrap_or_else(|| json!({}))
}
fn write_firefox_document(document: &Json) -> Result<()> {
    reg::write_value(r"Software\Policies\Mozilla\Firefox", &RegValue { name: "ExtensionSettings".into(), kind: "MultiString".into(), data: json!([document.to_string()]) })
}
/// Firefox carries all extension policy in one JSON document: ours is merged into it.
fn set_firefox_extension(id: &str, install_url: &str, update_url: &str) -> Result<()> {
    let mut document = firefox_document();
    document[id] = json!({"installation_mode": "force_installed", "install_url": install_url, "update_url": update_url, "updates_disabled": false});
    write_firefox_document(&document)
}
/// Best effort: PowerShell's `Remove-FirefoxExtension` swallowed every failure.
fn remove_firefox_extension(id: &str) -> Result<()> {
    let mut document = firefox_document();
    let Some(map) = document.as_object_mut() else { return Ok(()) };
    if map.remove(id).is_none() {
        return Ok(());
    }
    let _ = if map.is_empty() {
        reg::remove_value(r"Software\Policies\Mozilla\Firefox", "ExtensionSettings")
    } else {
        write_firefox_document(&document)
    };
    Ok(())
}
/// Only our exact certificate path belongs to Milvago; other CA policies stay.
fn set_firefox_certificate(certificate: &str, install: bool) -> Result<()> {
    let key = r"Software\Policies\Mozilla\Firefox\Certificates\Install";
    let values = reg::read_key(key)?;
    if values.is_none() && !install {
        return Ok(());
    }
    for value in values.unwrap_or_default() {
        if value.data.as_str() == Some(certificate) {
            reg::remove_value(key, &value.name)?;
        }
    }
    if install {
        let current = reg::read_key(key)?.unwrap_or_default();
        let slot = (1..).map(|n: u32| n.to_string()).find(|s| reg::value(&current, s).is_none()).unwrap_or_default();
        reg::write_value(key, &string(&slot, certificate))?;
    }
    Ok(())
}
fn managed_pin(l: &Layout) -> Result<Option<String>> {
    let path = l.data.join("MilvagoAuthorization").join(l.edition).join("anchor.json");
    if !path.is_file() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(&path).map_err(|_| Failure { step: "Invalid update authorization pin", detail: String::new() })?;
    if raw.len() > 16384 {
        return fail("Update authorization pin is too large");
    }
    let parsed: Json = serde_json::from_str(&raw).map_err(|_| Failure { step: "Invalid update authorization pin", detail: String::new() })?;
    Ok(Some(parsed.to_string()))
}
fn pin_keys(chromium: &str, gecko: &str) -> Vec<String> {
    let mut keys: Vec<String> = FORCED.iter().map(|v| format!(r"Software\Policies\{v}\3rdparty\extensions\{chromium}\policy")).collect();
    keys.push(format!(r"Software\Policies\Mozilla\Firefox\3rdparty\Extensions\{gecko}"));
    keys
}
fn remove_native_hosts(l: &Layout) -> Result<()> {
    let ours = [l.install.join("native-chromium.json"), l.install.join("native-firefox.json")];
    for browser in NATIVE_HOSTS {
        let key = format!(r"Software\{browser}\NativeMessagingHosts\app.milvago.browser");
        let registered = win::reg_string(&key, "");
        if registered.is_some_and(|r| ours.iter().any(|o| o.to_string_lossy().eq_ignore_ascii_case(&r))) {
            reg::delete_tree(&key)?;
        }
    }
    Ok(())
}

// ---- Directories and authorization cache ----

const FULL: u32 = 0x001F_01FF;
const READ_EXECUTE: u32 = 0x0012_00A9;
const SYNCHRONIZE: u32 = 0x0010_0000;

/// `Set-AuthorizationCacheDirectory`: created protected, or an existing one must carry
/// exactly SYSTEM and Administrators full control (and Authenticated Users read when
/// public), nothing else. Never re-permissioned.
fn authorization_cache_directory(path: &Path, public: bool) -> Result<()> {
    if !path.exists() {
        paths::authorization_directory(path, public)?;
    }
    paths::assert_path(path, &[SYSTEM, ADMINISTRATORS], false)?;
    let security = paths::security(path, "Null installer ancestor ACL refused")?;
    if ![SYSTEM, ADMINISTRATORS].contains(&security.owner.as_str()) {
        return fail("Untrusted update authorization directory owner");
    }
    let mut required: Vec<(&str, u32)> = vec![(SYSTEM, FULL), (ADMINISTRATORS, FULL)];
    if public {
        required.push((paths::AUTHENTICATED_USERS, READ_EXECUTE));
    }
    for ace in security.aces.iter().filter(|a| a.allow) {
        let Some(position) = required.iter().position(|(sid, _)| *sid == ace.sid) else {
            return fail("Unexpected update authorization directory permission");
        };
        if ace.mask & !SYNCHRONIZE != required[position].1 & !SYNCHRONIZE {
            return fail("Unexpected update authorization directory permission");
        }
        required.remove(position);
    }
    if !required.is_empty() {
        return fail("Missing update authorization directory permission");
    }
    Ok(())
}
fn authorization_cache_registry(edition: &str) -> Result<()> {
    let key = format!(r"SOFTWARE\MilvagoAuthorization\{edition}");
    match reg::key_security(&key)? {
        Some((owner, aces)) => {
            if ![SYSTEM, ADMINISTRATORS].contains(&owner.as_str()) {
                return fail("Untrusted update authorization registry key");
            }
            if aces.iter().any(|(sid, mask, allow)| *allow && ![SYSTEM, ADMINISTRATORS].contains(&sid.as_str()) && mask & 0x000F_003F != 0) {
                return fail("Writable update authorization registry key");
            }
            Ok(())
        }
        None => reg::create_protected_key(&key, "O:BAD:P(A;OICI;KA;;;BA)(A;OICI;KA;;;SY)"),
    }
}

/// m2: a directory that a standard user created before the first installation (ProgramData
/// lets any user create one) used to make the installation refuse forever. On a first
/// installation only, SYSTEM moves it aside and starts clean; the rename never follows a
/// redirection (the entry itself is renamed, not its target).
fn set_aside_if_planted(path: &Path, fresh: bool) -> Result<()> {
    // The entry itself, never what it points to: a dangling link does not "exist", and a
    // junction to a SYSTEM directory reports its target's owner. Either left the planted
    // entry in place, and every installation then refused it.
    use std::os::windows::fs::MetadataExt;
    let Ok(metadata) = std::fs::symlink_metadata(path) else { return Ok(()) };
    if !fresh {
        return Ok(());
    }
    let redirected = metadata.file_attributes() & 0x400 != 0;
    if !redirected {
        let security = paths::security(path, "Null installer ancestor ACL refused")?;
        if [SYSTEM, ADMINISTRATORS].contains(&security.owner.as_str()) {
            return Ok(());
        }
    }
    let aside = path.with_file_name(format!("{}.untrusted-{}", path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(), std::process::id()));
    std::fs::rename(path, &aside).map_err(|error| Failure { step: "Planted installer directory could not be set aside", detail: format!("{} ({error})", path.display()) })?;
    win::event(1006, false, "A directory created by a non-administrator before this first installation was renamed aside.");
    Ok(())
}

/// m5: whether Chrome and Edge treat this machine as managed — joined to an AD domain,
/// joined to Microsoft Entra ID, or enrolled in an MDM (Intune). Otherwise they refuse a
/// force-installed extension hosted outside their store. Entra join alone was measured
/// sufficient for both browsers on 2026-10-15; an Entra *registered* (workplace) device
/// is not.
fn managed_machine() -> bool {
    #[link(name = "netapi32")]
    unsafe extern "system" {
        fn NetGetJoinInformation(server: *const u16, name: *mut *mut u16, status: *mut u32) -> u32;
        fn NetApiBufferFree(buffer: *mut std::ffi::c_void) -> u32;
        fn NetGetAadJoinInformation(tenant: *const u16, info: *mut *mut u32) -> i32;
        fn NetFreeAadJoinInformation(info: *mut u32);
    }
    let (mut name, mut status) = (std::ptr::null_mut(), 0u32);
    let joined = unsafe { NetGetJoinInformation(std::ptr::null(), &mut name, &mut status) } == 0 && status == 3; // NetSetupDomainName
    if !name.is_null() {
        unsafe { NetApiBufferFree(name.cast()) };
    }
    // DSREG_JOIN_INFO starts with its DSREG_JOIN_TYPE; 1 is DSREG_DEVICE_JOIN.
    let mut info = std::ptr::null_mut();
    let entra = unsafe { NetGetAadJoinInformation(std::ptr::null(), &mut info) } == 0 && !info.is_null() && entra_device_join(unsafe { *info });
    if !info.is_null() {
        unsafe { NetFreeAadJoinInformation(info) };
    }
    joined || entra || reg::subkey_names(r"SOFTWARE\Microsoft\Enrollments").unwrap_or_default().iter()
        .any(|id| win::reg_string(&format!(r"SOFTWARE\Microsoft\Enrollments\{id}"), "ProviderID").as_deref() == Some("MS DM Server"))
}

fn entra_device_join(join_type: u32) -> bool {
    join_type == 1
}

/// The explicit proxy of `MILVAGO_PROXY`: http(s)://host[:port], no credentials, nothing
/// TOML would need to escape.
fn valid_proxy(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("http://").or_else(|| value.strip_prefix("https://")) else { return false };
    let host = rest.strip_suffix('/').unwrap_or(rest);
    !host.is_empty() && host.len() <= 255 && !host.contains(['@', '/', '?', '#'])
        && host.bytes().all(|c| c.is_ascii_alphanumeric() || b".-:[]".contains(&c))
}

pub struct Install<'a> {
    pub package: &'a str,
    pub fresh: bool,
    pub ca_file: &'a str,
    pub proxy: &'a str,
    pub system_store: &'a str,
    pub self_update: &'a str,
}

/// The MSI properties a run applies. They are Secure, so Windows Installer also hands them
/// to a repair a standard user starts: only a first installation, which takes an
/// administrator, applies them; later runs keep what is configured (`SelfUpdate=0` set
/// by an administrator cannot be undone by a user's repair).
struct Properties<'a> {
    ca_file: &'a str,
    proxy: &'a str,
    system_store: &'a str,
    self_update: &'a str,
}
fn applied_properties<'a>(options: &Install<'a>) -> Properties<'a> {
    if options.fresh {
        Properties { ca_file: options.ca_file, proxy: options.proxy, system_store: options.system_store, self_update: options.self_update }
    } else {
        Properties { ca_file: "", proxy: "", system_store: "", self_update: "" }
    }
}

pub fn install(l: &Layout, options: &Install) -> Result<String> {
    // Properties are validated before anything is written.
    if !options.proxy.is_empty() && !valid_proxy(options.proxy) {
        return fail("MILVAGO_PROXY must be http(s)://host:port without credentials");
    }
    if !matches!(options.system_store, "" | "0" | "1") || !matches!(options.self_update, "" | "0" | "1") {
        return fail("MILVAGO_SYSTEM_STORE and MILVAGO_SELF_UPDATE accept 0 or 1");
    }
    let properties = applied_properties(options);
    // Before anything can fail and need it, as configure-agent.ps1 did.
    win::register_event_source();
    let source = Path::new(options.package);
    if !source.is_file() {
        return fail("Installer package required");
    }
    let reported = agent("Installed agent health check", &l.agent, &["--version"])?;
    let expected_tail = format!(" {}", l.version);
    if !(reported.starts_with(l.display) || reported.starts_with("Milvago ")) || !reported.split_whitespace().any(|w| w == l.version) {
        return Err(Failure { step: "Installed agent health check failed", detail: format!("reported {reported:?}, installed{expected_tail}") });
    }
    let milvago_root = l.edition_root.parent().ok_or(Failure { step: "State root missing", detail: String::new() })?.to_path_buf();
    set_aside_if_planted(&milvago_root, options.fresh)?;
    paths::private_directory(&milvago_root, Access::Read, true, paths::NETWORK_SERVICE)?;
    set_aside_if_planted(&l.edition_root, options.fresh)?;
    let agent_sid = paths::service_sid(l.agent_service);
    paths::private_directory(&l.edition_root, Access::Read, true, &agent_sid)?;
    // SYSTEM reads the package's provisioning several times below, and the original may
    // sit where a standard user can replace it between two reads. Every read below uses
    // one private copy instead; it is removed once the installation is configured.
    let package_root = l.edition_root.join("installer-package");
    paths::private_directory(&package_root, Access::None, false, "")?;
    let provision = stage_provision(options.package, &package_root)?;
    let provision_text = provision.as_ref().map(|p| p.to_string_lossy().into_owned());
    let provision = provision_text.as_deref();
    let package_copy = package_root.join("package.msi");
    copy_package(Path::new(options.package), &package_copy)?;
    let package_copy_text = package_copy.to_string_lossy().into_owned();
    let package = package_copy_text.as_str();
    let migration = l.commercial && (services::exists("Milvago Agent Logger Community")? || services::exists("MilvagoBrowserAgent")?
        || l.programs.join("Milvago").join("Browser").join("installation.json").exists());
    if migration {
        let (verb, file) = provision_source(VALIDATE, provision, package);
        agent("Migration organization provisioning", &l.agent, &[verb, file])?;
    }
    assert_owned(l, l.agent_service)?;
    assert_owned(l, l.applier_service)?;
    if l.commercial {
        assert_owned(l, COLLECTOR_SERVICE)?;
    }
    // Service registered under the pre-renaming name: a stopped auto-start duplicate would
    // fight this one for the state and the pipe at next boot. (Retired per-user tasks are
    // deleted by the transaction before this action runs.)
    let legacy = if l.commercial { "MilvagoCommercialAgent" } else { "MilvagoBrowserAgent" };
    if services::exists(legacy)? {
        let _ = services::request_stop(legacy);
        let _ = services::wait_stopped(legacy, Duration::from_secs(30));
        services::delete(legacy)?;
    }
    set_aside_if_planted(&l.state, options.fresh)?;
    paths::private_directory(&l.state, Access::Write, false, &agent_sid)?;
    // The applier's journal and lease: SYSTEM writes there, so the agent account may only read.
    // A directory the agent can write would let it plant a junction under SYSTEM's writes.
    let update_journal = l.edition_root.join("update-journal");
    paths::private_directory(&update_journal, Access::Read, false, &agent_sid)?;
    // The agent reads but cannot replace its TLS identity; only the installer renews it.
    let tls = l.edition_root.join("tls");
    paths::private_directory(&tls, Access::Read, false, &agent_sid)?;
    agent("Local Firefox TLS identity", &l.agent, &["extension-tls", &tls.to_string_lossy()])?;
    let certificate_path = l.install.join("extension-ca.cer");
    paths::publish(&tls.join("extension-ca.cer"), &certificate_path)?;
    set_firefox_certificate(&certificate_path.to_string_lossy(), true)?;
    // config\ is edited by hand: its directory is verified, its files are never re-owned.
    let (config, certs, logs) = (l.edition_root.join("config"), l.edition_root.join("config").join("certs"), l.edition_root.join("logs"));
    paths::private_directory(&config, Access::Read, true, &agent_sid)?;
    paths::private_directory(&certs, Access::Read, true, &agent_sid)?;
    paths::private_directory(&logs, Access::Write, false, &agent_sid)?;
    // MSI 7: judged on the opened handle, and an explicitly deployed CA replaces the old one.
    let ca = certs.join("ca.pem");
    if !properties.ca_file.is_empty() {
        let pem = paths::read_trusted_source(Path::new(properties.ca_file), 256 * 1024)?;
        if !String::from_utf8_lossy(&pem).contains("-----BEGIN CERTIFICATE-----") {
            return fail("MILVAGO_CA_FILE is not a PEM certificate");
        }
        paths::publish_bytes(&pem, &ca)?;
    }
    // Created once, then left alone: the administrator's settings survive repairs and
    // upgrades. The content comes from the agent, so defaults and applied values agree.
    let config_file = config.join("milvago.toml");
    if !config_file.is_file() {
        let ca_argument = ca.is_file().then_some("certs/ca.pem");
        let mut arguments = vec!["default-configuration"];
        arguments.extend(ca_argument);
        let mut document = agent("Default agent configuration", &l.agent, &arguments)?;
        if !document.contains("\n[logging]") || !document.contains("\n[tls]") || !document.contains("\nsystem_store = false") || !document.contains("\nproxy = \"\"") {
            return fail("Agent produced an unexpected default configuration");
        }
        if properties.system_store == "1" {
            document = document.replacen("\nsystem_store = false", "\nsystem_store = true", 1);
        }
        if !properties.proxy.is_empty() {
            document = document.replacen("\nproxy = \"\"", &format!("\nproxy = \"{}\"", properties.proxy), 1);
        }
        let crlf = document.replace("\r\n", "\n").replace('\n', "\r\n") + "\r\n";
        paths::publish_bytes(crlf.as_bytes(), &config_file)?;
        if !std::fs::read_to_string(&config_file).is_ok_and(|t| t.contains("[tls]")) {
            return fail("Agent configuration could not be read back");
        }
    }
    // A2: the installer's own switch; the policy key (GPO/Intune) is read by the agent too.
    let self_update_key = format!(r"SOFTWARE\Milvago\{}", l.edition);
    match properties.self_update {
        "0" => reg::write_value(&self_update_key, &RegValue { name: "SelfUpdate".into(), kind: "DWord".into(), data: json!(0) })?,
        "1" => reg::remove_value(&self_update_key, "SelfUpdate")?,
        _ => {}
    }
    // Machine identity from the MSI's embedded provisioning; another organization's is
    // replaced on a first installation only.
    let computer = std::env::var("COMPUTERNAME").unwrap_or_default();
    let state = l.state.to_string_lossy().into_owned();
    let (verb, file) = provision_source(BOOTSTRAP, provision, package);
    let mut bootstrap = vec![verb, state.as_str(), file, computer.as_str()];
    if options.fresh {
        bootstrap.push("--reprovision");
    }
    agent("Installer configuration", &l.agent, &bootstrap)?;
    let authorization = l.data.join("MilvagoAuthorization");
    authorization_cache_directory(&authorization, true)?;
    authorization_cache_directory(&authorization.join(l.edition), true)?;
    authorization_cache_directory(&authorization.join(l.edition).join("private"), false)?;
    authorization_cache_registry(l.edition)?;
    // A first installation replaces a pin left by another instance or organization;
    // upgrades and repairs keep it. Any other refusal on a first installation runs
    // connected-only instead of failing.
    let (verb, file) = provision_source(PREPARE_CACHE, provision, package);
    let mut cache = vec![verb, l.edition, file];
    if options.fresh {
        cache.push("--reprovision");
    }
    if let Err(failure) = agent("Update authorization cache", &l.updater, &cache) {
        if !options.fresh {
            return Err(failure);
        }
        win::event(1005, false, "Offline authorization cache not prepared on this first installation (it keeps the identity of an earlier installation). The agent runs connected-only until the cache is reset by an administrator.");
    }
    let id = text(&l.install.join("extension-id.txt"))?;
    let gecko = text(&l.install.join("extension-firefox-id.txt"))?;
    if !crate::browser::chromium_id(&id) || !crate::browser::gecko_id(&gecko) {
        return fail("Invalid extension identity");
    }
    if let Some(pin) = managed_pin(l)? {
        for key in pin_keys(&id, &gecko) {
            reg::write_value(&key, &string("milvago_pin", &pin))?;
        }
    }
    if !l.relay.is_file() {
        return fail("Versioned browser relay missing");
    }
    let relay = l.relay.to_string_lossy().into_owned();
    let chromium_manifest = json!({"name": "app.milvago.browser", "description": "Milvago browser policy bridge", "path": relay, "type": "stdio", "allowed_origins": [format!("chrome-extension://{id}/")]});
    let firefox_manifest = json!({"name": "app.milvago.browser", "description": "Milvago browser policy bridge", "path": relay, "type": "stdio", "allowed_extensions": [gecko]});
    let (chromium_path, firefox_path) = (l.install.join("native-chromium.json"), l.install.join("native-firefox.json"));
    paths::publish_bytes(serde_json::to_string_pretty(&chromium_manifest).unwrap_or_default().as_bytes(), &chromium_path)?;
    paths::publish_bytes(serde_json::to_string_pretty(&firefox_manifest).unwrap_or_default().as_bytes(), &firefox_path)?;
    for browser in NATIVE_HOSTS {
        let manifest = if browser == "Mozilla" { &firefox_path } else { &chromium_path };
        // Endpoint protection often guards NativeMessagingHosts (a known persistence
        // path): the browser is named so a refusal is diagnosable.
        reg::write_value(&format!(r"Software\{browser}\NativeMessagingHosts\app.milvago.browser"), &string("", &manifest.to_string_lossy()))
            .map_err(|failure| Failure { step: "Native messaging registration failed", detail: format!("{browser}: {}", failure.step) })?;
    }
    let local: Json = serde_json::from_str(&agent("Embedded extension channel", &l.agent, &["extension-info"])?)
        .map_err(|_| Failure { step: "Embedded extension identity mismatch", detail: String::new() })?;
    if local["embedded"] != true || local["chromium_id"] != id.as_str() || local["firefox_id"] != gecko.as_str() {
        return fail("Embedded extension identity mismatch");
    }
    let update_url = format!("{}/ext/update.xml", local["origin"].as_str().unwrap_or_default());
    for vendor in FORCED {
        set_forced(vendor, &id, &update_url).and_then(|()| set_extension_settings(vendor, &id, &update_url))
            .map_err(|failure| Failure { step: "Extension force-install failed", detail: format!("{vendor}: {}", failure.step) })?;
    }
    // The obsolete Brave policy path of older releases, scoped to our identity.
    remove_forced(&id, &LEGACY_FORCED)?;
    remove_extension_settings(&id, &LEGACY_FORCED)?;
    set_firefox_extension(&gecko, local["firefox_install_url"].as_str().unwrap_or_default(),
        &format!("{}/ext/updates.json", local["firefox_origin"].as_str().unwrap_or_default()))?;
    if !managed_machine() {
        win::event(1002, false, &format!("Extension policy written for {id} but this computer is not joined to an Active Directory domain or to Microsoft Entra ID, nor enrolled in an MDM. Chrome and Edge may refuse to install an extension hosted outside the Chrome Web Store on such a machine."));
    }
    // Agent service: NetworkService, automatic, restart on failure.
    services::write_configuration(l.agent_service, &Configuration {
        kind: 0x10, start: 2, error: 1,
        binary: format!("\"{}\" service \"{}\"", l.agent.display(), l.state.display()),
        group: String::new(), account: r"NT AUTHORITY\NetworkService".into(), display: l.display.into(),
        dependencies: Vec::new(), delayed_auto: false,
    })?;
    services::set_sid_unrestricted(l.agent_service)?;
    // NetworkService holds SeImpersonatePrivilege, which turns any code execution in the
    // agent into SYSTEM. The agent only identifies pipe clients (SecurityIdentification
    // needs no privilege): keep bypass-traverse and global-object creation, drop the rest.
    services::set_required_privileges(l.agent_service, &["SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege"])?;
    // Default descriptor plus SERVICE_QUERY_STATUS for signed-in accounts: the relay and the
    // CLI hook check the pipe is served by this service's own process.
    services::set_sddl(l.agent_service, "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;LC;;;AU)")?;
    services::write_recovery(l.agent_service, &Recovery {
        reset_period: 86400, reboot_message: String::new(), command: String::new(), non_crash_failures: false,
        actions: [5000, 15000, 60000].into_iter().map(|delay| RecoveryAction { kind: 1, delay }).collect(),
    })?;
    services::write_metadata(l.agent_service, l.display, "Milvago endpoint agent: signed policy, encrypted queue and the local browser-extension bridge.")?;
    // Privileged applier: receives nothing, re-fetches and re-verifies itself. It starts at
    // boot and never stops for idleness (decision of 2026-09-24), so its pipe names are held
    // from boot; recovery, non-crash failures included, restarts it on a new binPath.
    // NetworkService and signed-in users get SERVICE_START only; Administrators keep
    // DELETE so RemoveAgent (SYSTEM, holding it through Administrators) can delete it.
    services::write_configuration(l.applier_service, &Configuration {
        kind: 0x10, start: win::SERVICE_AUTO_START, error: 1,
        binary: format!("\"{}\" service \"{}\" \"{}\" {}", l.updater.display(), l.state.display(), l.agent.display(), l.edition),
        group: String::new(), account: "LocalSystem".into(), display: l.applier_service.into(),
        dependencies: Vec::new(), delayed_auto: false,
    })?;
    services::write_metadata(l.applier_service, l.applier_service, "Milvago update applier: verifies and installs a signed agent release when the agent asks.")?;
    services::set_sddl(l.applier_service, "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRC;;;BA)(A;;RP;;;NS)(A;;RP;;;AU)")?;
    services::write_recovery(l.applier_service, &Recovery {
        reset_period: 86400, reboot_message: String::new(), command: String::new(), non_crash_failures: true,
        actions: [1000, 5000, 60000].into_iter().map(|delay| RecoveryAction { kind: 1, delay }).collect(),
    })?;
    // The private copy has served every provisioning read; only the caller-supplied
    // original is left once the installation is configured.
    let _ = std::fs::remove_dir_all(&package_root);
    // Already running when the applier itself started this installation: then a no-op.
    let _ = services::start(l.applier_service, STEP);
    services::start(l.agent_service, STEP).map_err(|failure| Failure { step: "Agent service did not start", detail: failure.step.into() })?;
    Ok("Agent configured".into())
}

/// `[IO.File]::Copy(..., $true)` of the package into the private folder. CopyFile keeps
/// the source's attributes: a read-only package (a cached or deployment-tool copy) made a
/// read-only copy that the next attempt, after a failed one, could not overwrite.
fn copy_package(source: &Path, destination: &Path) -> Result<()> {
    let writable = |path: &Path| -> std::io::Result<()> {
        let mut permissions = std::fs::symlink_metadata(path)?.permissions();
        if permissions.readonly() {
            #[allow(clippy::permissions_set_readonly_false)]
            permissions.set_readonly(false);
            std::fs::set_permissions(path, permissions)?;
        }
        Ok(())
    };
    if std::fs::symlink_metadata(destination).is_ok() {
        writable(destination).and_then(|()| std::fs::remove_file(destination))
            .map_err(|error| Failure { step: "Stale installer package could not be removed", detail: error.to_string() })?;
    }
    std::fs::copy(source, destination).and_then(|_| writable(destination))
        .map_err(|error| Failure { step: "Installer package could not be copied", detail: error.to_string() })?;
    Ok(())
}

/// Each provisioning verb of the agent binaries, as (staged JSON file,
/// the MSI's own stream).
pub(crate) const VALIDATE: [&str; 2] = ["validate-json", "validate-msi"];
pub(crate) const BOOTSTRAP: [&str; 2] = ["bootstrap", "bootstrap-msi"];
pub(crate) const PREPARE_CACHE: [&str; 2] = ["prepare-cache-file", "prepare-cache-msi"];
/// The staged file when there is one, the package otherwise, with the matching verb.
pub(crate) fn provision_source<'a>(verbs: [&'static str; 2], staged: Option<&'a str>, package: &'a str) -> (&'a str, &'a str) {
    match staged {
        Some(file) => (verbs[0], file),
        None => (verbs[1], package),
    }
}
/// The release MSI is shared by every organization and embeds only `{}`: the deployment
/// script stages this organization's provisioning next to it, as this file.
pub(crate) fn provision_sidecar(package: &str) -> PathBuf {
    PathBuf::from(format!("{package}.provision.json"))
}
const PROVISION_LIMIT: usize = 16384;

/// A private copy of the staged provisioning, taken for the same reason as the package
/// copy; `None` means a generic repair or update, which reads the MSI's own stream.
/// The sidecar sits next to a caller-chosen MSI, so its whole path is judged like
/// PowerShell's `Assert-InstallerPath` (ancestors included; `read_trusted_source` judges
/// only the file), then read once, bounded, through the handle that proved it a plain
/// single-link file: a size checked before an unbounded copy could grow in between.
fn stage_provision(package: &str, package_root: &Path) -> Result<Option<PathBuf>> {
    let copy = package_root.join("provision.json");
    if copy.exists() {
        paths::assert_path(&copy, &[SYSTEM, ADMINISTRATORS], false)?;
        std::fs::remove_file(&copy).map_err(|_| Failure { step: "Stale installer provisioning could not be removed", detail: String::new() })?;
    }
    let source = provision_sidecar(package);
    if !source.is_file() {
        return Ok(None);
    }
    paths::assert_path(&source, &[SYSTEM, ADMINISTRATORS], false)?;
    let bytes = paths::read_plain(&source, PROVISION_LIMIT, "Installer provisioning too large")?;
    paths::publish_bytes(&bytes, &copy)?;
    Ok(Some(copy))
}

/// RemoveAgent: services, registrations and the files this action wrote go; the
/// encrypted identity and queue stay for repair and rollback.
pub fn remove(l: &Layout) -> Result<String> {
    assert_owned(l, l.agent_service)?;
    services::remove_owned(l.agent_service, l.agent.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default().as_str())?;
    // Uninstall wins over an in-flight update.
    assert_owned(l, l.applier_service)?;
    services::remove_owned(l.applier_service, "milvago-updater")?;
    if l.commercial {
        assert_owned(l, COLLECTOR_SERVICE)?;
        services::remove_owned(COLLECTOR_SERVICE, "milvago-collector")?;
    }
    let legacy = if l.commercial { "MilvagoCommercialAgent" } else { "MilvagoBrowserAgent" };
    if services::exists(legacy)? {
        let _ = services::request_stop(legacy);
        let _ = services::wait_stopped(legacy, Duration::from_secs(30));
        services::delete(legacy)?;
    }
    remove_native_hosts(l)?;
    let id = std::fs::read_to_string(l.install.join("extension-id.txt")).map(|t| t.trim().to_owned()).unwrap_or_default();
    let gecko = std::fs::read_to_string(l.install.join("extension-firefox-id.txt")).map(|t| t.trim().to_owned()).unwrap_or_default();
    let all: Vec<&str> = FORCED.iter().chain(LEGACY_FORCED.iter()).copied().collect();
    if crate::browser::chromium_id(&id) {
        remove_forced(&id, &all)?;
        remove_extension_settings(&id, &all)?;
    }
    if crate::browser::gecko_id(&gecko) {
        remove_firefox_extension(&gecko)?;
    }
    if crate::browser::chromium_id(&id) && crate::browser::gecko_id(&gecko) {
        if let Some(pin) = managed_pin(l)? {
            for key in pin_keys(&id, &gecko) {
                let current = reg::read_key(&key)?.and_then(|values| reg::value(&values, "milvago_pin"));
                if current.and_then(|v| v.data.as_str().map(str::to_owned)).as_deref() == Some(pin.as_str()) {
                    reg::remove_value(&key, "milvago_pin")?;
                }
            }
        }
    }
    // Written by this action, not installed by the MSI: RemoveFiles never removes them.
    set_firefox_certificate(&l.install.join("extension-ca.cer").to_string_lossy(), false)?;
    for name in ["native-chromium.json", "native-firefox.json", "extension-ca.cer"] {
        let _ = std::fs::remove_file(l.install.join(name));
    }
    reg::remove_value(&format!(r"SOFTWARE\Milvago\{}", l.edition), "SelfUpdate")?;
    Ok("Agent removed".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_an_entra_device_join_counts_as_managed() {
        assert!(super::entra_device_join(1), "DSREG_DEVICE_JOIN");
        assert!(!super::entra_device_join(2), "a workplace-registered device is not managed");
        assert!(!super::entra_device_join(0));
    }


    #[test]
    fn proxy_values_are_strict() {
        for good in ["http://proxy.example.internal:3128", "https://10.0.0.1:8443/", "http://[2001:db8::1]:3128"] {
            assert!(valid_proxy(good), "{good}");
        }
        for bad in ["", "proxy:3128", "socks5://p:1080", "http://user:pw@p:3128", "http://p:3128/path", "http://p\":3128", "http://p\\x", "http://"] {
            assert!(!valid_proxy(bad), "{bad}");
        }
    }

    #[test]
    fn the_staged_provisioning_sits_next_to_the_package() {
        assert_eq!(provision_sidecar(r"C:\Deploy\milvago.msi"), PathBuf::from(r"C:\Deploy\milvago.msi.provision.json"));
    }

    #[test]
    fn a_staged_file_selects_every_json_verb_and_its_absence_every_msi_verb() {
        let (staged, package) = (r"C:\ProgramData\Milvago\Commercial\installer-package\provision.json", r"C:\x\package.msi");
        let expected = [
            (VALIDATE, "validate-json", "validate-msi"),
            (BOOTSTRAP, "bootstrap", "bootstrap-msi"),
            (PREPARE_CACHE, "prepare-cache-file", "prepare-cache-msi"),
        ];
        for (verbs, json, msi) in expected {
            assert_eq!(provision_source(verbs, Some(staged), package), (json, staged));
            assert_eq!(provision_source(verbs, None, package), (msi, package));
        }
    }

    #[test]
    fn only_a_first_installation_applies_the_msi_properties() {
        let options = |fresh| Install { package: "", fresh, ca_file: r"C:\Deploy\ca.pem", proxy: "http://proxy:3128", system_store: "1", self_update: "0" };
        let first = applied_properties(&options(true));
        assert_eq!((first.ca_file, first.proxy, first.system_store, first.self_update), (r"C:\Deploy\ca.pem", "http://proxy:3128", "1", "0"));
        // A repair or upgrade, which a standard user may start with Secure properties.
        let later = applied_properties(&options(false));
        assert_eq!((later.ca_file, later.proxy, later.system_store, later.self_update), ("", "", "", ""));
    }

    #[test]
    fn a_read_only_package_copy_left_by_a_failed_attempt_is_replaced() {
        let dir = paths::TestDir::new("package");
        let (source, copy) = (dir.join("source.msi"), dir.join("package.msi"));
        std::fs::write(&source, b"new").unwrap();
        let read_only = |path: &Path| {
            let mut permissions = std::fs::metadata(path).unwrap().permissions();
            permissions.set_readonly(true);
            std::fs::set_permissions(path, permissions).unwrap();
        };
        read_only(&source);
        std::fs::write(&copy, b"old").unwrap();
        read_only(&copy);
        // [IO.File]::Copy and std::fs::copy both fail on this read-only leftover.
        assert!(std::fs::copy(&source, &copy).is_err());
        copy_package(&source, &copy).unwrap();
        assert_eq!(std::fs::read(&copy).unwrap(), b"new");
        // The copy is writable, so remove_dir_all of the private folder and the next attempt succeed.
        assert!(!std::fs::metadata(&copy).unwrap().permissions().readonly());
        copy_package(&source, &copy).unwrap();
        assert!(copy_package(&dir.join("absent.msi"), &copy).is_err());
    }
}
