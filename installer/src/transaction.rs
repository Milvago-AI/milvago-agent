//! MSI-owned compensation: Prepare (deferred) snapshots everything the installation may
//! change, Restore (rollback) puts it back and proves it, Commit discards the snapshot.
//! Port of `deploy/installer-transaction.ps1`; record and receipt formats unchanged
//! (the receipt is read by `endpoint/src/update.rs::rollback_verified`).
use crate::browser::{self, BrowserState};
use crate::paths::{self, ADMINISTRATORS, Custody, NETWORK_SERVICE, SYSTEM};
use crate::reg::{self, RegTree};
use crate::services::{self, Configuration, Recovery};
use crate::win::{Failure, Result, fail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Prepare,
    Restore,
    Commit,
}

struct Context {
    edition: String,
    commercial: bool,
    product: String,
    base: PathBuf,
    index: PathBuf,
    blocked: PathBuf,
    receipt: PathBuf,
    programs: PathBuf,
    data: PathBuf,
    paths: Vec<PathBuf>,
    services: Vec<&'static str>,
    custody: Vec<&'static str>,
}

fn context(edition: &str, product: &str) -> Result<Context> {
    let product = paths::canonical_guid(product).ok_or(Failure { step: "Invalid product code", detail: String::new() })?;
    let commercial = edition == "commercial";
    let (programs, data) = (paths::program_files()?, paths::program_data()?);
    let base = data.join("MilvagoInstallerTransactions");
    let folders: &[&str] = if commercial { &["Browser", "Commercial", "Collector", "ModelFilter"] } else { &["Browser"] };
    let mut tree_paths: Vec<PathBuf> = folders.iter().map(|f| data.join("Milvago").join(f)).collect();
    tree_paths.push(programs.join("Milvago").join(if commercial { "Commercial" } else { "Browser" }));
    // ProgramData\MilvagoAuthorization and MilvagoDiscovery are independent
    // authority material: never snapshot, restore or remove their revision floors.
    if commercial {
        tree_paths.push(programs.join("Milvago").join("Browser"));
    }
    let mut service_names = vec!["Milvago Agent Logger Community", "Milvago Update Applier Community", "MilvagoBrowserAgent", "Milvago Discovery Community"];
    if commercial {
        service_names.extend(["Milvago Agent Logger", "Milvago Update Applier", "MilvagoCommercialAgent", "Milvago Native Collector", "MilvagoModelFilter", "Milvago Discovery"]);
    }
    Ok(Context {
        edition: edition.into(),
        commercial,
        index: base.join(format!("{product}.json")),
        blocked: base.join(format!("{product}.blocked")),
        receipt: base.join(format!("{product}.result.json")),
        product,
        base,
        programs,
        data,
        paths: tree_paths,
        services: service_names,
        custody: if commercial { vec!["community", "commercial"] } else { vec!["community"] },
    })
}

fn io(step: &'static str) -> impl Fn(std::io::Error) -> Failure {
    move |error| Failure { step, detail: error.to_string() }
}
fn save(path: &Path, value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|e| Failure { step: "Transaction record could not be written", detail: e.to_string() })?;
    std::fs::write(path, bytes).map_err(io("Transaction record could not be written"))
}
fn load<T: for<'a> Deserialize<'a>>(path: &Path) -> Result<T> {
    let bytes = std::fs::read(path).map_err(io("Transaction record unavailable"))?;
    serde_json::from_slice(&bytes).map_err(|e| Failure { step: "Transaction record invalid", detail: e.to_string() })
}
fn sha256(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path).map_err(io("Snapshot digest unavailable"))?;
    Ok(Sha256::digest(bytes).iter().map(|b| format!("{b:02X}")).collect())
}
fn same(a: &Path, b: &Path) -> bool {
    a.to_string_lossy().eq_ignore_ascii_case(&b.to_string_lossy())
}
fn under(path: &Path, root: &Path) -> bool {
    path.to_string_lossy().to_ascii_lowercase().starts_with(&format!("{}\\", root.to_string_lossy().to_ascii_lowercase()))
}

/// A random v4 GUID (lower case), from the system RNG.
fn new_guid() -> Result<String> {
    #[link(name = "bcrypt")]
    unsafe extern "system" {
        fn BCryptGenRandom(algorithm: *mut std::ffi::c_void, buffer: *mut u8, length: u32, flags: u32) -> i32;
    }
    let mut b = [0u8; 16];
    if unsafe { BCryptGenRandom(std::ptr::null_mut(), b.as_mut_ptr(), 16, 2) } != 0 {
        return fail("System random generator unavailable");
    }
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    Ok(format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32]))
}

/// ISO 8601 UTC with seven fractional digits, like .NET's round-trip "o" format.
pub(crate) fn now_iso() -> String {
    let since = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let (days, seconds) = ((since.as_secs() / 86400) as i64, since.as_secs() % 86400);
    // Civil date from days since 1970-01-01 (proleptic Gregorian).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:07}Z", seconds / 3600, seconds / 60 % 60, seconds % 60, since.subsec_nanos() / 100)
}

/// `Test-InstallerServiceImage`: the service's command line names one of this product's
/// executables, at its root or under a versioned `runtime\<version>\`.
pub fn service_image(programs: &Path, name: &str, image: &str) -> bool {
    let relative = match name {
        "Milvago Agent Logger Community" | "MilvagoBrowserAgent" => r"Browser\milvago-browser-agent.exe",
        "Milvago Update Applier Community" => r"Browser\milvago-updater.exe",
        "Milvago Agent Logger" | "MilvagoCommercialAgent" => r"Commercial\milvago-commercial-bridge.exe",
        "Milvago Update Applier" => r"Commercial\milvago-updater.exe",
        "Milvago Native Collector" => r"Commercial\milvago-collector.exe",
        "MilvagoModelFilter" => r"Commercial\milvago-model-filter.exe",
        "Milvago Discovery Community" => r"Browser\milvago-discovery-system.exe",
        "Milvago Discovery" => r"Commercial\milvago-discovery-system.exe",
        _ => return false,
    };
    let Some(rest) = image.strip_prefix('"') else { return false };
    let Some(end) = rest.find('"') else { return false };
    let (candidate, after) = (&rest[..end], &rest[end + 1..]);
    if !(after.is_empty() || after.starts_with(char::is_whitespace)) || !Path::new(candidate).is_absolute()
        || candidate.contains(r"\..\") || candidate.contains(r"\.\") || candidate.contains('/')
    {
        return false;
    }
    let expected = programs.join("Milvago").join(relative);
    if same(Path::new(candidate), &expected) {
        return true;
    }
    let runtime = expected.parent().map(|p| p.join("runtime")).unwrap_or_default();
    let lower = candidate.to_ascii_lowercase();
    let prefix = format!("{}\\", runtime.to_string_lossy().to_ascii_lowercase());
    let Some(tail) = lower.strip_prefix(&prefix) else { return false };
    let file = expected.file_name().map(|f| f.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    let Some((version, exe)) = tail.split_once('\\') else { return false };
    let parts: Vec<&str> = version.split('.').collect();
    exe == file && parts.len() == 3 && parts.iter().zip([3, 3, 5]).all(|(p, n)| !p.is_empty() && p.len() <= n && p.bytes().all(|c| c.is_ascii_digit()))
}

fn image_path(name: &str) -> Option<String> {
    crate::win::reg_string(&format!(r"SYSTEM\CurrentControlSet\Services\{name}"), "ImagePath")
}
/// `Owned`: false when absent; an error when the name runs someone else's executable.
fn owned(c: &Context, name: &str) -> Result<bool> {
    if !crate::win::reg_key_exists(&format!(r"SYSTEM\CurrentControlSet\Services\{name}")) {
        return Ok(false);
    }
    if service_image(&c.programs, name, &image_path(name).unwrap_or_default()) {
        return Ok(true);
    }
    Err(Failure { step: "Service name belongs to another executable", detail: name.into() })
}
fn is_applier(name: &str) -> bool {
    name.starts_with("Milvago Update Applier")
}
/// File stem of the executable a service of this product runs (`service_image`): the
/// only process a bounded stop may terminate.
fn image_stem(name: &str) -> &'static str {
    match name {
        "Milvago Agent Logger Community" | "MilvagoBrowserAgent" => "milvago-browser-agent",
        "Milvago Agent Logger" | "MilvagoCommercialAgent" => "milvago-commercial-bridge",
        "Milvago Native Collector" => "milvago-collector",
        "MilvagoModelFilter" => "milvago-model-filter",
        "Milvago Discovery Community" | "Milvago Discovery" => "milvago-discovery-system",
        _ => "milvago-updater",
    }
}

fn stop_writers(c: &Context, disable: bool) -> Result<()> {
    for name in &c.services {
        if !owned(c, name)? || is_applier(name) {
            continue; // the one-shot applier owns an active self-update; never kill msiexec's parent.
        }
        if disable {
            let mut configuration = services::read_configuration(name)?;
            configuration.start = 4;
            configuration.delayed_auto = false;
            services::write_configuration(name, &configuration)?;
        }
        // Past 30 s its own process is terminated: a hung stop made Stop-Service fail the
        // transaction, and a failed rollback leaves custody that blocks every later install.
        if !services::wait_stopped(name, Duration::ZERO)? && !services::stop_owned(name, image_stem(name), Duration::from_secs(30))? {
            return Err(Failure { step: "Agent writer did not stop", detail: (*name).into() });
        }
    }
    Ok(())
}

/// Full image paths of the running processes that can be queried.
fn process_images() -> Vec<String> {
    #[repr(C)]
    struct Entry {
        size: u32,
        usage: u32,
        pid: u32,
        heap: usize,
        module: u32,
        threads: u32,
        parent: u32,
        priority: i32,
        flags: u32,
        exe: [u16; 260],
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> isize;
        fn Process32FirstW(snapshot: isize, entry: *mut Entry) -> i32;
        fn Process32NextW(snapshot: isize, entry: *mut Entry) -> i32;
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> isize;
        fn QueryFullProcessImageNameW(process: isize, flags: u32, name: *mut u16, size: *mut u32) -> i32;
        fn CloseHandle(handle: isize) -> i32;
    }
    let mut images = Vec::new();
    let snapshot = unsafe { CreateToolhelp32Snapshot(2, 0) };
    if snapshot == -1 {
        return images;
    }
    let mut entry: Entry = unsafe { std::mem::zeroed() };
    entry.size = size_of::<Entry>() as u32;
    let mut more = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
    while more {
        let process = unsafe { OpenProcess(0x1000, 0, entry.pid) };
        if process != 0 {
            let mut name = [0u16; 1024];
            let mut size = name.len() as u32;
            if unsafe { QueryFullProcessImageNameW(process, 0, name.as_mut_ptr(), &mut size) } != 0 {
                images.push(String::from_utf16_lossy(&name[..size as usize]));
            }
            unsafe { CloseHandle(process) };
        }
        more = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
    }
    unsafe { CloseHandle(snapshot) };
    images
}
fn assert_writers_stopped(c: &Context) -> Result<()> {
    for image in process_images() {
        let quoted = format!("\"{image}\"");
        if c.services.iter().any(|name| !is_applier(name) && service_image(&c.programs, name, &quoted)) {
            return fail("An agent writer remains active after service shutdown");
        }
    }
    Ok(())
}

/// `Tree`: every object in it is plain, single-link and owned/writable only by SYSTEM,
/// Administrators, NetworkService or one of the Milvago service SIDs.
fn tree(path: &Path) -> Result<()> {
    tree_with(path, paths::Rule::Strict)
}
/// `Tree -Repair`, only where PowerShell uses it: Prepare's first check of the live trees,
/// so an administrator's grant (Explorer's "Continue" on `logs\`) is removed, not fatal.
fn tree_with(path: &Path, rule: paths::Rule) -> Result<()> {
    let service_sids = paths::milvago_service_sids();
    let owners: Vec<&str> = [SYSTEM, ADMINISTRATORS, NETWORK_SERVICE].into_iter().chain(service_sids.iter().map(String::as_str)).collect();
    paths::assert_path_with(path, &owners, true, rule)?;
    paths::plain(path)
}
fn updates_excluded(c: &Context, item: &Path) -> bool {
    ["Browser", "Commercial"].iter().any(|f| {
        let directory = c.programs.join("Milvago").join(f).join("runtime").join("Updates");
        same(item, &directory) || under(item, &directory)
    })
}
/// Every descendant, depth first, without following redirections.
fn descendants(path: &Path) -> Result<Vec<(PathBuf, bool)>> {
    let mut items = Vec::new();
    let mut pending = vec![path.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).map_err(io("Snapshot tree unavailable"))? {
            let entry = entry.map_err(io("Snapshot tree unavailable"))?;
            let kind = entry.file_type().map_err(io("Snapshot tree unavailable"))?;
            if kind.is_symlink() {
                return fail("Redirected snapshot entry refused");
            }
            items.push((entry.path(), kind.is_dir()));
            if kind.is_dir() {
                pending.push(entry.path());
            }
        }
    }
    items.sort();
    Ok(items)
}
fn snapshot_items(c: &Context, path: &Path) -> Result<Vec<(PathBuf, bool)>> {
    Ok(descendants(path)?.into_iter().filter(|(item, _)| !updates_excluded(c, item)).collect())
}
fn copy_tree(c: &Context, from: &Path, to: &Path) -> Result<()> {
    tree(from)?;
    paths::plain(to)?;
    std::fs::create_dir_all(to).map_err(io("Snapshot directory could not be created"))?;
    for (item, directory) in snapshot_items(c, from)? {
        let target = to.join(item.strip_prefix(from).map_err(|_| Failure { step: "Snapshot path escaped", detail: String::new() })?);
        if directory {
            paths::plain(&item)?;
            std::fs::create_dir_all(&target).map_err(io("Snapshot directory could not be created"))?;
        } else {
            paths::copy(&item, &target)?;
        }
    }
    tree(to)
}
fn delete_tree(c: &Context, path: &Path) -> Result<()> {
    let guid_leaf = path.file_name().and_then(|n| n.to_str()).is_some_and(|n| paths::canonical_guid(n).as_deref() == Some(n));
    if !c.paths.iter().any(|p| same(p, path)) && !(under(path, &c.base) && guid_leaf) {
        return fail("Removal outside transaction resources refused");
    }
    tree(path)?;
    if path.exists() {
        std::fs::remove_dir_all(path).map_err(io("Transaction resource could not be removed"))?;
    }
    Ok(())
}

fn filter_executable(c: &Context) -> PathBuf {
    let root = c.programs.join("Milvago").join("Commercial");
    let mut filter = root.join("milvago-model-filter.exe");
    if let Ok(marker) = load::<serde_json::Value>(&root.join("installation.json")) {
        if let Some(version) = marker["version"].as_str() {
            let versioned = root.join("runtime").join(version).join("milvago-model-filter.exe");
            if versioned.exists() {
                filter = versioned;
            }
        }
    }
    filter
}
fn filter_config(c: &Context) -> PathBuf {
    c.data.join("Milvago").join("ModelFilter").join("config.json")
}
fn run(step: &'static str, executable: &Path, arguments: &[&str]) -> Result<()> {
    crate::win::run(step, executable, arguments, std::time::Instant::now() + Duration::from_secs(120)).map(|_| ())
}

#[derive(Serialize, Deserialize, Clone)]
struct ServiceRecord {
    name: String,
    image: String,
    running: bool,
    sddl: String,
    display: String,
    description: String,
    recovery: Recovery,
    configuration: Configuration,
    key: RegTree,
}
#[derive(Serialize, Deserialize, Clone)]
struct AclEntry {
    relative: String,
    sddl: String,
    directory: bool,
}
#[derive(Serialize, Deserialize, Clone)]
struct HashEntry {
    relative: String,
    hash: String,
}
#[derive(Serialize, Deserialize, Clone)]
struct TreeRecord {
    exists: bool,
    acls: Vec<AclEntry>,
    hashes: Vec<HashEntry>,
}
#[derive(Serialize, Deserialize, Clone)]
struct Record {
    product: String,
    edition: String,
    transaction: String,
    complete: bool,
    services: Vec<ServiceRecord>,
    trees: Vec<TreeRecord>,
    browser: Option<BrowserState>,
}
#[derive(Serialize, Deserialize)]
struct Pointer {
    product: String,
    edition: String,
    transaction: String,
}

fn description(name: &str) -> String {
    crate::win::reg_string(&format!(r"SYSTEM\CurrentControlSet\Services\{name}"), "Description").unwrap_or_default()
}

fn capture_tree(c: &Context, path: &Path, backup: &Path) -> Result<TreeRecord> {
    let mut entry = TreeRecord { exists: path.exists(), acls: Vec::new(), hashes: Vec::new() };
    if !entry.exists { return Ok(entry); }
    tree(path)?;
    paths::plain(backup)?;
    std::fs::create_dir_all(backup).map_err(io("Snapshot directory could not be created"))?;
    entry.acls.push(AclEntry { relative: String::new(), sddl: paths::sddl_of(path)?, directory: true });
    let items = snapshot_items(c, path)?;
    for (item, directory) in &items {
        let suffix = item.strip_prefix(path).map_err(|_| Failure { step: "Snapshot path escaped", detail: String::new() })?;
        let target = backup.join(suffix);
        let relative = item.to_string_lossy()[path.to_string_lossy().len()..].to_owned();
        if *directory {
            paths::plain(item)?;
            std::fs::create_dir_all(&target).map_err(io("Snapshot directory could not be created"))?;
            entry.acls.push(AclEntry { relative, sddl: paths::sddl_of(item)?, directory: true });
        } else {
            let proof = paths::copy_snapshot(item, &target)?;
            entry.acls.push(AclEntry { relative: relative.clone(), sddl: proof.sddl, directory: false });
            entry.hashes.push(HashEntry { relative, hash: proof.hash });
        }
    }
    if items != snapshot_items(c, path)? { return fail("Snapshot tree changed during capture"); }
    tree(backup)?;
    Ok(entry)
}

fn prepare(c: &Context, chromium: &str, firefox: &str, held: &mut Vec<&'static str>, saved: &mut bool, tx: &mut Option<PathBuf>) -> Result<()> {
    if !c.commercial
        && (["Milvago Agent Logger", "MilvagoCommercialAgent", "Milvago Native Collector", "MilvagoModelFilter", "Milvago Discovery"].iter().any(|n| services::exists(n).unwrap_or(true))
            || c.programs.join("Milvago").join("Commercial").join("installation.json").exists())
    {
        return fail("Enterprise is present; Community operation refused");
    }
    for edition in &c.custody {
        paths::custody(edition, &c.product, Custody::Set)?;
        held.push(edition);
    }
    paths::new_private(&c.base)?;
    if c.index.exists() {
        let _ = std::fs::write(&c.blocked, "Unfinished transaction; no automatic replay");
        return fail("An unfinished transaction requires recovery before retry");
    }
    if c.blocked.exists() {
        return fail("Recovery review required before retry");
    }
    // Retired per-user tasks (before 2026-09-10) are deleted once proved Milvago's and not
    // restored on rollback (decision of 2026-10-15); one not proved still refuses here.
    crate::tasks::remove_legacy(c.commercial, &c.programs)?;
    for path in &c.paths {
        tree_with(path, paths::Rule::Repair)?;
    }
    let id = new_guid()?;
    let dir = c.base.join(&id);
    paths::new_private(&dir)?;
    *tx = Some(dir.clone());
    let mut record = Record { product: c.product.clone(), edition: c.edition.clone(), transaction: id.clone(), complete: false,
        services: Vec::new(), trees: Vec::new(), browser: None };
    for name in &c.services {
        if !owned(c, name)? {
            continue;
        }
        let configuration = services::read_configuration(name)?;
        if !["LocalSystem", r"NT AUTHORITY\NetworkService"].iter().any(|a| a.eq_ignore_ascii_case(&configuration.account)) {
            return fail("Unexpected service account");
        }
        let recovery = services::read_recovery(name)?;
        if recovery.actions.is_empty() && recovery.reset_period != 0 {
            return fail("Service recovery configuration cannot be restored losslessly");
        }
        record.services.push(ServiceRecord {
            name: (*name).into(),
            image: image_path(name).unwrap_or_default(),
            running: services::running(name)?,
            sddl: services::sddl(name)?,
            display: configuration.display.clone(),
            description: description(name),
            recovery,
            configuration,
            key: reg::read_tree(&format!(r"SYSTEM\CurrentControlSet\Services\{name}"))?,
        });
    }
    // Rebuild only a confinement state proved to match the protected original config.
    if c.commercial && record.services.iter().any(|s| s.name == "MilvagoModelFilter") {
        run("Model filter confinement check", &filter_executable(c), &["check", &filter_config(c).to_string_lossy()])?;
    }
    // Journal before the first side effect; an incomplete snapshot only restarts services.
    save(&dir.join("record.json"), &record)?;
    save(&c.index, &Pointer { product: record.product.clone(), edition: c.edition.clone(), transaction: id.clone() })?;
    *saved = true;
    stop_writers(c, true)?;
    assert_writers_stopped(c)?;
    for (i, path) in c.paths.iter().enumerate() {
        record.trees.push(capture_tree(c, path, &dir.join(format!("tree-{i}")))?);
    }
    record.browser = Some(browser::save(chromium, firefox, c.commercial)?);
    record.complete = true;
    save(&dir.join("record.json"), &record)
}

fn read_record(c: &Context) -> Result<Option<(Record, PathBuf)>> {
    paths::private(&c.base, false)?;
    if !c.index.exists() {
        return Ok(None);
    }
    paths::private(&c.index, false)?;
    let pointer: Pointer = load(&c.index)?;
    if pointer.product != c.product || pointer.edition != c.edition || paths::canonical_guid(&pointer.transaction).as_deref() != Some(pointer.transaction.as_str()) {
        return fail("Transaction binding rejected");
    }
    let dir = c.base.join(&pointer.transaction);
    paths::private(&dir, false)?;
    let record: Record = load(&dir.join("record.json"))?;
    if record.product != pointer.product || record.edition != c.edition || record.transaction != pointer.transaction {
        return fail("Snapshot binding rejected");
    }
    Ok(Some((record, dir)))
}

fn saved_service_sid(key: &RegTree) -> Result<u32> {
    let roots: Vec<_> = key.keys.iter().filter(|k| k.relative.is_empty()).collect();
    if !key.exists || roots.len() != 1 { return fail("Invalid saved service SID type"); }
    let values: Vec<_> = roots[0].values.iter().filter(|v| v.name.eq_ignore_ascii_case("ServiceSidType")).collect();
    match values.as_slice() {
        [] => Ok(0),
        [value] if value.kind == "DWord" => match value.data.as_u64() {
            Some(kind @ (0 | 1 | 3)) => Ok(kind as u32),
            _ => fail("Invalid saved service SID type"),
        },
        _ => fail("Invalid saved service SID type"),
    }
}

fn restore(c: &Context, record: &Record, dir: &Path) -> Result<()> {
    // Validate all saved identities before changing any service. Registry import
    // alone does not update SCM's cached SID type after a service was recreated.
    let sid_types = record.services.iter().map(|s| saved_service_sid(&s.key)).collect::<Result<Vec<_>>>()?;
    if record.complete {
        // An interrupted journal capture needs reviewed recovery; never overwrite its evidence.
        for i in 0..c.paths.len() {
            if dir.join(format!("live-journal-{i}")).exists() || dir.join(format!("live-journal-acls-{i}.json")).exists() {
                return fail("Interrupted journal capture requires explicit recovery");
            }
        }
        stop_writers(c, true)?;
        // Services this transaction created are deleted below. The applier among them
        // still runs (stop_writers spares it for a self-update, which cannot be the case
        // for a service absent from the snapshot): stopped first, it holds no handle in
        // the trees removed next, and its deletion completes instead of leaving a service
        // marked for deletion that every later installation fails to configure (1072).
        for name in created_services(c, record)? {
            if !services::stop_owned(name, image_stem(name), Duration::from_secs(30))? {
                return fail("A service created by this installation did not stop");
            }
        }
        assert_writers_stopped(c)?;
        for (i, path) in c.paths.iter().enumerate() {
            let saved_tree = &record.trees[i];
            let backup = dir.join(format!("tree-{i}"));
            let msi_files = ["Browser", "Commercial"].iter().any(|f| same(path, &c.programs.join("Milvago").join(f)));
            if msi_files {
                paths::plain(path)?;
                // Written by the agent configuration, not installed by the MSI.
                for name in ["native-chromium.json", "native-firefox.json", "extension-ca.cer"] {
                    let (destination, saved) = (path.join(name), backup.join(name));
                    if saved.exists() {
                        std::fs::copy(&saved, &destination).map_err(io("Installed file could not be restored"))?;
                    } else if destination.exists() {
                        std::fs::remove_file(&destination).map_err(io("Installed file could not be removed"))?;
                    }
                }
            } else {
                let live = path.join("update-journal");
                let saved = dir.join(format!("live-journal-{i}"));
                let leaf = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                if ["Browser", "Commercial"].contains(&leaf.as_str()) && live.exists() {
                    tree(&live)?;
                    let mut acls = vec![AclEntry { relative: String::new(), sddl: paths::sddl_of(&live)?, directory: true }];
                    for (item, directory) in descendants(&live)? {
                        acls.push(AclEntry { relative: item.to_string_lossy()[live.to_string_lossy().len()..].to_owned(), sddl: paths::sddl_of(&item)?, directory });
                    }
                    save(&dir.join(format!("live-journal-acls-{i}.json")), &acls)?;
                    // New objects, not moved handles: a writer holding the old file cannot keep
                    // access to the protected backup once its ACL changes.
                    paths::new_private(&saved)?;
                    copy_tree(c, &live, &saved)?;
                }
                delete_tree(c, path)?;
            }
            if saved_tree.exists {
                if !msi_files {
                    // Created private first: the children inherit SYSTEM/Administrators only,
                    // never ProgramData\Milvago's read grant to every NetworkService
                    // service, until the saved descriptors are reapplied below.
                    if !path.exists() {
                        paths::new_private(path)?;
                    }
                    copy_tree(c, &backup, path)?;
                }
                for file in &saved_tree.hashes {
                    if sha256(&PathBuf::from(format!("{}{}", path.to_string_lossy(), file.relative)))? != file.hash {
                        return fail("Restored data digest differs");
                    }
                }
                for entry in &saved_tree.acls {
                    paths::set_acl(&PathBuf::from(format!("{}{}", path.to_string_lossy(), entry.relative)), &entry.sddl, entry.directory)?;
                }
            }
        }
        for (i, path) in c.paths.iter().enumerate() {
            let saved = dir.join(format!("live-journal-{i}"));
            if !saved.exists() {
                continue;
            }
            let live = path.join("update-journal");
            if !under(&live, path) {
                return fail("Journal destination outside restored state");
            }
            if live.exists() {
                tree(&live)?;
                std::fs::remove_dir_all(&live).map_err(io("Journal could not be replaced"))?;
            }
            // The journal's parent, as PowerShell's New-Item did; not state\, which a rollback
            // of a first installation would otherwise leave behind, empty.
            std::fs::create_dir_all(path).map_err(io("Journal could not be restored"))?;
            tree(&saved)?;
            paths::private(&saved, false)?;
            std::fs::rename(&saved, &live).map_err(io("Journal could not be restored"))?;
            let acls: Vec<AclEntry> = load(&dir.join(format!("live-journal-acls-{i}.json")))?;
            for entry in acls {
                paths::set_acl(&PathBuf::from(format!("{}{}", live.to_string_lossy(), entry.relative)), &entry.sddl, entry.directory)?;
            }
        }
        if let Some(state) = &record.browser {
            browser::restore(state)?;
        }
        for name in created_services(c, record)? {
            services::delete(name)?;
        }
        for service in &record.services {
            services::write_configuration(&service.name, &service.configuration)?;
            reg::merge_tree(&format!(r"SYSTEM\CurrentControlSet\Services\{}", service.name), &service.key)?;
            services::write_metadata(&service.name, &service.display, &service.description)?;
            services::write_recovery(&service.name, &service.recovery)?;
            services::set_sddl(&service.name, &service.sddl)?;
        }
    }
    for service in record.services.iter().filter(|s| !is_applier(&s.name)) {
        services::write_configuration(&service.name, &service.configuration)?;
    }
    for (service, kind) in record.services.iter().zip(&sid_types) {
        services::set_sid_type(&service.name, *kind)?;
    }
    for service in record.services.iter().filter(|s| s.running) {
        // Preserve an active self-update host. A host recreated by rollback is
        // stopped, however, and must recover its original running state.
        if !is_applier(&service.name) || !services::running(&service.name)? {
            services::start(&service.name, Duration::from_secs(30))?;
        }
    }
    for service in &record.services {
        let configuration = services::read_configuration(&service.name)?;
        if image_path(&service.name).unwrap_or_default() != service.image || !configuration.account.eq_ignore_ascii_case(&service.configuration.account) {
            return fail("Restored service configuration differs");
        }
        if configuration.display != service.display || description(&service.name) != service.description {
            return fail("Restored service metadata differs");
        }
        if service.running && !services::running(&service.name)? {
            return fail("Restored service is unavailable");
        }
        if services::sddl(&service.name)? != service.sddl {
            return fail("Restored service permissions differ");
        }
    }
    let result = serde_json::json!({"product": c.product, "edition": c.edition, "transaction": record.transaction,
        "resources_restored": true, "health_verified": false, "at": now_iso()});
    save(&dir.join("restored.json"), &result)?;
    save(&c.receipt, &result)?;
    std::fs::remove_file(&c.index).map_err(io("Transaction index could not be removed"))?;
    delete_tree(c, dir)?;
    for edition in &c.custody {
        paths::custody(edition, &c.product, Custody::Clear)?;
    }
    Ok(())
}

/// Owned services absent from the snapshot: created by this transaction.
fn created_services<'a>(c: &'a Context, record: &Record) -> Result<Vec<&'a str>> {
    let mut created = Vec::new();
    for name in &c.services {
        if owned(c, name)? && !record.services.iter().any(|s| s.name == *name) {
            created.push(*name);
        }
    }
    Ok(created)
}

fn version_key(name: &str) -> Option<(u32, u32, u32)> {
    let parts: Vec<u32> = name.split('.').map(|p| p.parse().ok()).collect::<Option<_>>()?;
    (parts.len() == 3).then(|| (parts[0], parts[1], parts[2]))
}
/// m7: past a committed upgrade, keep the current runtime and the one before it (its
/// update applier may still be finishing) and remove the older ones, which nothing else
/// ever removed. Best effort: a folder still in use stays for the next commit.
fn prune_runtimes(runtime: &Path, current: &str) {
    let Some(current) = version_key(current) else { return };
    let Ok(entries) = std::fs::read_dir(runtime) else { return };
    let mut versions: Vec<((u32, u32, u32), PathBuf)> = entries.flatten()
        .filter(|e| e.file_type().is_ok_and(|k| k.is_dir()))
        .filter_map(|e| version_key(&e.file_name().to_string_lossy()).map(|v| (v, e.path())))
        .collect();
    versions.sort();
    let previous = versions.iter().map(|(v, _)| *v).filter(|v| *v < current).max();
    for (version, path) in versions {
        if version < current && Some(version) != previous {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}

fn commit(c: &Context, dir: &Path) -> Result<()> {
    // The update host detects its SCM command change and exits with a failure
    // code after active MSI work completes, so SCM starts the new binary.
    // Do not send administrative STOP here: it requests a clean exit and
    // suppresses that recovery, leaving the privileged IPC service stopped.
    // This also avoids mistaking an unrelated updater process for the service.
    delete_tree(c, dir)?;
    std::fs::remove_file(&c.index).map_err(io("Transaction index could not be removed"))?;
    for edition in &c.custody {
        paths::custody(edition, &c.product, Custody::Clear)?;
    }
    // A committed uninstall is the only commit after which the MSI has removed
    // installation.json; only then are the permanent runtime\<version> folders removed.
    let install = c.programs.join("Milvago").join(if c.commercial { "Commercial" } else { "Browser" });
    if let Ok(marker) = load::<serde_json::Value>(&install.join("installation.json")) {
        prune_runtimes(&install.join("runtime"), marker["version"].as_str().unwrap_or_default());
    }
    if !install.join("installation.json").exists() {
        for directory in [install.join("runtime"), install.join("Updates")] {
            let _ = std::fs::remove_dir_all(directory);
        }
        if std::fs::read_dir(&install).is_ok_and(|mut entries| entries.next().is_none()) {
            let _ = std::fs::remove_dir(&install);
        }
        let shared = c.programs.join("Milvago").join("Updates");
        if !c.programs.join("Milvago").join("Browser").join("installation.json").exists()
            && !c.programs.join("Milvago").join("Commercial").join("installation.json").exists()
        {
            let _ = std::fs::remove_dir_all(shared);
        }
    }
    Ok(())
}

pub fn run_operation(operation: Operation, edition: &str, product: &str, chromium: &str, firefox: &str) -> Result<String> {
    let c = context(edition, product)?;
    let (mut held, mut saved, mut tx) = (Vec::new(), false, None);
    let result = (|| -> Result<()> {
        if operation == Operation::Prepare {
            return prepare(&c, chromium, firefox, &mut held, &mut saved, &mut tx);
        }
        if !c.base.exists() {
            return Ok(());
        }
        if c.blocked.exists() {
            return fail("Automatic replay of an earlier transaction refused");
        }
        let Some((record, dir)) = read_record(&c)? else { return Ok(()) };
        tx = Some(dir.clone());
        if operation == Operation::Restore { restore(&c, &record, &dir) } else { commit(&c, &dir) }
    })();
    match result {
        Ok(()) => Ok(format!("Transaction {} complete", match operation { Operation::Prepare => "prepare", Operation::Restore => "restore", Operation::Commit => "commit" })),
        Err(failure) => {
            if operation == Operation::Prepare && !saved {
                for edition in held {
                    let _ = paths::custody(edition, &c.product, Custody::Clear);
                }
            }
            // Numeric/fixed diagnostics only: no snapshot, command, path or credential.
            if let Some(dir) = tx.filter(|d| d.exists() && paths::private(d, false).is_ok()) {
                let _ = save(&dir.join("failure.json"), &serde_json::json!({"operation": match operation { Operation::Prepare => "Prepare", Operation::Restore => "Restore", Operation::Commit => "Commit" }, "failed": true, "at": now_iso(), "step": failure.step}));
            }
            Err(failure)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn snapshot_capture_of_an_absent_tree_creates_no_backup() {
        let dir = paths::TestDir::new("snapshot-absent");
        let c = context("community", "01234567-89ab-4cde-8fab-0123456789ab").unwrap();
        let backup = dir.join("backup");
        let record = capture_tree(&c, &dir.join("absent"), &backup).unwrap();
        assert!(!record.exists);
        assert!(record.acls.is_empty() && record.hashes.is_empty());
        assert!(!backup.exists());
    }

    #[test]
    #[ignore = "elevated disposable protected directories only; no services or registry changed"]
    fn snapshot_capture_keeps_acl_hashes_and_empty_directories() {
        let dir = paths::TestDir::new("snapshot-capture");
        paths::set_acl(&dir, "O:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)", true).unwrap();
        let source = dir.join("source");
        std::fs::create_dir_all(source.join("nested").join("empty")).unwrap();
        std::fs::write(source.join("plain.txt"), b"synthetic snapshot").unwrap();
        std::fs::write(source.join("nested").join("image.bin"), [137,80,78,71,0,255]).unwrap();
        let c = context("community", "01234567-89ab-4cde-8fab-0123456789ab").unwrap();
        let backup = dir.join("backup");
        let record = capture_tree(&c, &source, &backup).unwrap();
        assert!(record.exists);
        assert_eq!(record.hashes.len(), 2);
        assert_eq!(record.acls.len(), 5);
        assert!(backup.join("nested").join("empty").is_dir());
        let decoded: TreeRecord = serde_json::from_slice(&serde_json::to_vec(&record).unwrap()).unwrap();
        let restored = dir.join("restored");
        copy_tree(&c, &backup, &restored).unwrap();
        for file in &decoded.hashes {
            let original = PathBuf::from(format!("{}{}", source.display(), file.relative));
            let recovered = PathBuf::from(format!("{}{}", restored.display(), file.relative));
            assert_eq!(sha256(&original).unwrap(), file.hash);
            assert_eq!(sha256(&recovered).unwrap(), file.hash);
        }
        for item in &decoded.acls {
            let original = PathBuf::from(format!("{}{}", source.display(), item.relative));
            assert_eq!(paths::sddl_of(&original).unwrap(), item.sddl);
        }
    }


    #[test]
    fn saved_service_identity_is_exact_and_rejects_ambiguous_snapshots() {
        let mut key = RegTree { exists: true, keys: vec![reg::RegTreeKey { relative: String::new(), values: vec![] }] };
        assert_eq!(saved_service_sid(&key).unwrap(), 0);
        for kind in [0, 1, 3] {
            key.keys[0].values = vec![reg::RegValue { name: "servicesidtype".into(), kind: "DWord".into(), data: kind.into() }];
            assert_eq!(saved_service_sid(&key).unwrap(), kind);
        }
        for value in [serde_json::json!(-1), serde_json::json!(2), serde_json::json!(4), serde_json::json!("1"), serde_json::json!([1])] {
            key.keys[0].values[0].data = value;
            assert!(saved_service_sid(&key).is_err());
        }
        key.keys[0].values[0].data = 1.into();
        key.keys[0].values[0].kind = "String".into();
        assert!(saved_service_sid(&key).is_err());
        key.keys[0].values[0].kind = "DWord".into();
        let duplicate = key.keys[0].values[0].clone();
        key.keys[0].values.push(duplicate);
        assert!(saved_service_sid(&key).is_err());
        key.keys[0].values.clear();
        let duplicate = key.keys[0].clone();
        key.keys.push(duplicate);
        assert!(saved_service_sid(&key).is_err());
    }


    #[test]
    fn service_images_are_this_products_executables_only() {
        let programs = Path::new(r"C:\Program Files");
        let ok = |name, image: &str| service_image(programs, name, image);
        assert!(ok("Milvago Agent Logger Community", r#""C:\Program Files\Milvago\Browser\runtime\0.5.44\milvago-browser-agent.exe" service "C:\ProgramData\Milvago\Browser\state""#));
        assert!(ok("Milvago Update Applier", r#""C:\Program Files\Milvago\Commercial\milvago-updater.exe""#));
        assert!(ok("Milvago Discovery Community", r#""C:\Program Files\Milvago\Browser\runtime\0.7.1\milvago-discovery-system.exe" service"#));
        assert!(ok("Milvago Discovery", r#""C:\Program Files\Milvago\Commercial\runtime\0.7.1\milvago-discovery-system.exe" service"#));
        assert!(!ok("Milvago Discovery", r#""C:\Program Files\Milvago\Browser\runtime\0.7.1\milvago-discovery-system.exe" service"#));
        assert!(!ok("Milvago Discovery Community", r#""C:\Temp\milvago-discovery-system.exe" service"#));
        assert!(!ok("Milvago Agent Logger Community", r#""C:\Program Files\Milvago\Browser\runtime\0.5.44\..\evil.exe""#));
        assert!(!ok("Milvago Agent Logger Community", r#"C:\Program Files\Milvago\Browser\milvago-browser-agent.exe"#));
        assert!(!ok("Milvago Agent Logger Community", r#""C:\Program Files\Milvago\Browser\runtime\latest\milvago-browser-agent.exe""#));
        assert!(!ok("Milvago Agent Logger", r#""C:\Program Files\Milvago\Browser\milvago-browser-agent.exe""#));
        assert!(!ok("Unknown", r#""C:\Program Files\Milvago\Browser\milvago-browser-agent.exe""#));
    }

    #[test]
    fn only_runtimes_older_than_the_previous_one_are_pruned() {
        let root = paths::TestDir::new("prune");
        for version in ["0.5.9", "0.5.42", "0.5.43", "0.5.44", "not-a-version"] {
            std::fs::create_dir_all(root.join(version)).unwrap();
        }
        prune_runtimes(&root, "0.5.44");
        let mut left: Vec<String> = std::fs::read_dir(&root).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        left.sort();
        assert_eq!(left, ["0.5.43", "0.5.44", "not-a-version"], "numeric order, not text: 0.5.9 < 0.5.42");
    }

    #[test]
    fn a_bounded_stop_may_only_terminate_the_services_own_executable() {
        let programs = Path::new(r"C:\Program Files");
        // Every snapshot service maps to the stem of the image service_image accepts for it.
        for name in ["Milvago Agent Logger Community", "Milvago Update Applier Community", "MilvagoBrowserAgent", "Milvago Agent Logger",
            "Milvago Update Applier", "MilvagoCommercialAgent", "Milvago Native Collector", "MilvagoModelFilter", "Milvago Discovery Community", "Milvago Discovery"] {
            let image = format!(r#""C:\Program Files\Milvago\{}\runtime\0.6.5\{}.exe" service"#,
                if name.contains("Community") || name == "MilvagoBrowserAgent" { "Browser" } else { "Commercial" }, image_stem(name));
            assert!(service_image(programs, name, &image), "{name}: {image}");
        }
    }

    #[test]
    fn times_and_guids_have_the_recorded_shapes() {
        let at = now_iso();
        assert_eq!(at.len(), 28, "{at}");
        assert!(at.ends_with('Z') && at.as_bytes()[10] == b'T');
        let guid = new_guid().unwrap();
        assert_eq!(paths::canonical_guid(&guid).as_deref(), Some(guid.as_str()));
        assert_ne!(guid, new_guid().unwrap());
    }
}
