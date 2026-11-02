//! Locally provisioned guest access. Remote catalogues cannot select credentials,
//! guests, executables or command arguments.
use crate::discovery_system::NativeReader;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use milvago_discovery_collector::{
    self as collector, Budget, MAX_RESPONSE,
    guest::Access,
    system::{Query, Reader},
};
use milvago_discovery_engine::{CoverageStatus, EntityKind, Snapshot};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, io::Read, path::Path};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    version: u32,
    device_id: String,
    connections: Vec<Connection>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Connection {
    hypervisor: Hypervisor,
    vm_id: String,
    credential_file: Option<String>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    vmx_file: Option<String>,
}
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Hypervisor {
    HyperV,
    Libvirt,
    #[serde(rename = "virtualbox")]
    VirtualBox,
    #[serde(rename = "vmware")]
    VMware,
    Wsl,
}
impl Hypervisor {
    fn adapter(self) -> &'static str {
        match self {
            Self::HyperV => "hyper-v",
            Self::Libvirt => "libvirt",
            Self::VirtualBox => "virtualbox",
            Self::VMware => "vmware",
            Self::Wsl => "wsl",
        }
    }
}

fn configuration(bytes: &[u8], device: &str) -> Result<Configuration, &'static str> {
    if bytes.len() > 32768 {
        return Err("configuration_limit");
    }
    let config: Configuration =
        serde_json::from_slice(bytes).map_err(|_| "invalid_configuration")?;
    if config.version != 1
        || device.is_empty()
        || config.device_id != device
        || config.connections.len() > 32
    {
        return Err("invalid_configuration");
    }
    let mut seen = BTreeSet::new();
    for connection in &config.connections {
        let vmware = matches!(connection.hypervisor, Hypervisor::VMware);
        let wsl = matches!(connection.hypervisor, Hypervisor::Wsl);
        if (wsl && crate::discovery_wsl::Identity::parse(&connection.vm_id).is_err())
            || (!vmware
                && !wsl
                && (connection.vm_id.len() != 36
                    || uuid::Uuid::parse_str(&connection.vm_id).is_err()
                    || connection.vm_id != connection.vm_id.to_ascii_lowercase()))
            || (!vmware && connection.vmx_file.is_some())
            || (vmware
                && connection.vmx_file.as_ref().is_none_or(|path| {
                    crate::discovery_vmware::Request {
                        vm_id: connection.vm_id.clone(),
                        vmx_file: path.clone(),
                        credential_file: connection.credential_file.clone().unwrap_or_default(),
                    }
                    .validate()
                    .is_err()
                }))
            || !seen.insert((connection.hypervisor.adapter(), &connection.vm_id))
        {
            return Err("invalid_connection");
        }
        match (connection.hypervisor, &connection.credential_file) {
            (Hypervisor::HyperV, Some(name))
                if credential_leaf(name) && connection.username.is_none() =>
            {
                ()
            }
            (Hypervisor::Libvirt, None) if connection.username.is_none() => (),
            (Hypervisor::Wsl, None) if connection.username.is_none() => (),
            (Hypervisor::VirtualBox, Some(name))
                if secret_leaf(name, ".password")
                    && connection.username.as_deref().is_some_and(guest_username) =>
            {
                ()
            }
            (Hypervisor::VMware, Some(name))
                if secret_leaf(name, ".json") && connection.username.is_none() =>
            {
                ()
            }
            _ => return Err("invalid_connection"),
        }
    }
    Ok(config)
}
fn credential_leaf(name: &str) -> bool {
    secret_leaf(name, ".xml")
}
pub(super) fn guest_username(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 80
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._@-".contains(&b))
}
fn secret_leaf(name: &str, suffix: &str) -> bool {
    name.len() <= 80
        && name.ends_with(suffix)
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && !name.contains("..")
}

// The caller keeps the Windows directory/file leases until all guest operations
// finish. On Unix the opened file is pinned; every ancestor must be root-owned
// and non-writable by unprivileged users, including the local configuration.
pub(crate) fn protected_file(path: &Path, limit: usize) -> Result<std::fs::File, &'static str> {
    #[cfg(windows)]
    let file = {
        let directory =
            crate::cache_windows::Directory::open(path.parent().ok_or("access_denied")?, true)
                .map_err(|_| "access_denied")?;
        directory
            .hold_file(path.file_name().ok_or("access_denied")?)
            .map_err(|_| "access_denied")?
    };
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        if !path.is_absolute() {
            return Err("access_denied");
        }
        for ancestor in path.ancestors() {
            let info = std::fs::symlink_metadata(ancestor).map_err(|_| "access_denied")?;
            if info.file_type().is_symlink() || info.uid() != 0 || info.mode() & 0o022 != 0 {
                return Err("access_denied");
            }
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|_| "access_denied")?;
        let info = file.metadata().map_err(|_| "access_denied")?;
        if info.uid() != 0 || info.mode() & 0o077 != 0 {
            return Err("access_denied");
        }
        file
    };
    #[cfg(not(any(unix, windows)))]
    let file = return Err("unavailable");
    let metadata = file.metadata().map_err(|_| "access_denied")?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err("configuration_limit");
    }
    Ok(file)
}
fn protected(path: &Path, limit: usize) -> Result<Vec<u8>, &'static str> {
    let file = protected_file(path, limit)?;
    let mut bytes = vec![];
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "read_failed")?;
    if bytes.len() > limit {
        return Err("configuration_limit");
    }
    Ok(bytes)
}

// Only projections with explicit boot and process-start identities are accepted.
// Full command lines are wiped locally and never become facts or wire evidence.
fn hyper_v_projection(bytes: &[u8]) -> Result<(String, Vec<u8>, bool), &'static str> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Envelope {
        boot: String,
        processes: Vec<Row>,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Row {
        pid: u64,
        start_time: String,
        executable: String,
        command_line: Option<String>,
    }
    if bytes.len() > MAX_RESPONSE {
        return Err("response_limit");
    }
    let input: Envelope = serde_json::from_slice(bytes).map_err(|_| "invalid_guest_response")?;
    if input.processes.len() > 4096 {
        return Err("process_limit");
    }
    let mut rows = vec![];
    let mut complete = true;
    for mut row in input.processes {
        let executable = collector::host::executable_name(&row.executable);
        if (matches!(executable.as_str(), "node" | "nodejs") || executable.starts_with("python"))
            && row.command_line.as_ref().is_none_or(|line| line.is_empty())
        {
            complete = false;
        }
        #[cfg(windows)]
        let mut tokens: Vec<String> = vec![];
        #[cfg(not(windows))]
        let tokens: Vec<String> = vec![];
        if let Some(mut line) = row.command_line.take() {
            #[cfg(windows)]
            {
                let mut args = collector::system::windows_arguments(&line);
                tokens = collector::host::entry_tokens(&row.executable, &args);
                for argument in &mut args {
                    zeroize::Zeroize::zeroize(argument);
                }
            }
            zeroize::Zeroize::zeroize(&mut line);
        }
        // Win32_Process includes the idle process (PID 0), which has no useful
        // identity; it is intentionally excluded rather than invalidating a VM.
        if row.pid == 0 {
            continue;
        }
        rows.push(serde_json::json!({"pid":row.pid,"start_time":row.start_time,"executable":row.executable,"argument_tokens":tokens}));
    }
    Ok((
        input.boot,
        serde_json::to_vec(&rows).map_err(|_| "invalid_guest_response")?,
        complete,
    ))
}

fn linux_projection(bytes: &[u8]) -> Result<(String, Vec<u8>, bool), &'static str> {
    guest_projection(bytes, false)
}
fn guest_projection(bytes: &[u8], vmware: bool) -> Result<(String, Vec<u8>, bool), &'static str> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Envelope {
        boot: String,
        processes: Vec<serde_json::Value>,
        complete: bool,
    }
    if bytes.len() > MAX_RESPONSE {
        return Err("response_limit");
    }
    let input: Envelope = serde_json::from_slice(bytes).map_err(|_| "invalid_guest_response")?;
    let valid_boot = if vmware {
        input
            .boot
            .strip_prefix("vmware-init/")
            .is_some_and(|value| {
                !value.is_empty()
                    && value.len() <= 20
                    && value.bytes().all(|b| b.is_ascii_digit())
                    && value
                        .parse::<u64>()
                        .is_ok_and(|v| v > 0 && v.to_string() == value)
            })
    } else {
        input.boot.len() == 36 && uuid::Uuid::parse_str(&input.boot).is_ok()
    };
    if !valid_boot {
        return Err("invalid_guest_response");
    }
    if input.processes.len() > 4096 {
        return Err("process_limit");
    }
    Ok((
        input.boot,
        serde_json::to_vec(&input.processes).map_err(|_| "invalid_guest_response")?,
        input.complete,
    ))
}

fn qga(
    reader: &impl Reader,
    vm: &str,
    budget: &Budget<'_>,
) -> Result<(String, Vec<u8>, bool), &'static str> {
    budget.check()?;
    let mut start = reader.read(Query::LibvirtGuestStart(vm.into()), budget)?;
    let parsed = collector::bounded_json(&start);
    start.fill(0);
    let pid = parsed?
        .get("return")
        .and_then(|v| v.get("pid"))
        .and_then(|v| v.as_u64())
        .filter(|p| *p > 0 && *p <= u32::MAX as u64)
        .ok_or("invalid_guest_response")? as u32;
    loop {
        budget.check()?;
        let mut bytes = reader.read(
            Query::LibvirtGuestStatus {
                vm_id: vm.into(),
                pid,
            },
            budget,
        )?;
        let parsed = collector::bounded_json(&bytes);
        bytes.fill(0);
        let mut parsed = parsed?;
        let data = parsed.get_mut("return").ok_or("invalid_guest_response")?;
        match data.get("exited").and_then(|v| v.as_bool()) {
            Some(false) => {
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            }
            Some(true) => (),
            _ => return Err("invalid_guest_response"),
        }
        if data.get("exitcode").and_then(|v| v.as_u64()) != Some(0)
            || data.get("out-truncated").and_then(|v| v.as_bool()) == Some(true)
        {
            return Err("guest_query_failed");
        }
        let mut encoded = match data
            .as_object_mut()
            .ok_or("invalid_guest_response")?
            .remove("out-data")
        {
            Some(serde_json::Value::String(value)) => value,
            _ => return Err("invalid_guest_response"),
        };
        let decoded = STANDARD.decode(&encoded);
        zeroize::Zeroize::zeroize(&mut encoded);
        let mut decoded = decoded.map_err(|_| "invalid_guest_response")?;
        let result = linux_projection(&decoded);
        decoded.fill(0);
        return result;
    }
}

fn collect_running_with(
    snapshot: &mut Snapshot,
    home: &Path,
    device: &str,
    access: Access,
    failures: &mut Vec<String>,
    reader: &impl Reader,
    budget: &Budget<'_>,
    running: &BTreeSet<String>,
) {
    if !access.read || !access.execute {
        collector::coverage(snapshot, "guest-tools", CoverageStatus::Denied, false);
        return;
    }
    let bytes = match protected(&home.join("config/discovery-guests.json"), 32768) {
        Ok(v) => v,
        Err(_) => {
            collector::coverage(snapshot, "guest-tools", CoverageStatus::Denied, false);
            return;
        }
    };
    let mut config = match configuration(&bytes, device) {
        Ok(v) => v,
        Err(_) => {
            collector::coverage(snapshot, "guest-tools", CoverageStatus::Denied, false);
            return;
        }
    };
    // Version this cache contract: old entries could contain a digest derived
    // from credential bytes. Retry tracking must never export such a verifier.
    let generation = format!("guest-access-v3:{}:", hex(&Sha256::digest(&bytes)));
    failures.retain(|key| key.starts_with(&generation));
    if !config.connections.is_empty() {
        let offset = snapshot.sequence as usize % config.connections.len();
        config.connections.rotate_left(offset);
    }
    for connection in config.connections {
        if budget.check().is_err() {
            collector::coverage(snapshot, "guest-tools", CoverageStatus::Timeout, false);
            break;
        }
        let adapter = connection.hypervisor.adapter();
        let vm = collector::identity("vm", &[adapter, "local", &connection.vm_id]);
        if !running.contains(&vm)
            || !snapshot
                .entities
                .iter()
                .any(|e| e.id == vm && matches!(e.kind, EntityKind::Vm | EntityKind::Wsl))
        {
            continue;
        }
        let credential = connection
            .credential_file
            .as_ref()
            .map(|leaf| home.join("config/discovery-secrets").join(leaf));
        let mut fingerprint = Sha256::new();
        fingerprint.update(&bytes);
        fingerprint.update(vm.as_bytes());
        if let Some(path) = &credential {
            if credential_stamp(path, &mut fingerprint).is_err() {
                if let Some(coverage) = snapshot
                    .coverage
                    .iter_mut()
                    .find(|c| c.scope == vm && c.adapter == format!("{adapter}-guest"))
                {
                    coverage.status = CoverageStatus::Denied;
                    coverage.complete = false;
                }
                continue;
            }
        }
        let prefix = format!("{generation}{vm}:");
        let key = format!("{prefix}{}", hex(&fingerprint.finalize()));
        let credentialed = !matches!(connection.hypervisor, Hypervisor::Libvirt | Hypervisor::Wsl);
        failures.retain(|old| !old.starts_with(&prefix) || (credentialed && old == &key));
        let blocked = credentialed && failures.contains(&key);
        let result = if blocked {
            Err("guest_access_latched")
        } else {
            match connection.hypervisor {
                Hypervisor::Libvirt => qga(reader, &connection.vm_id, budget),
                Hypervisor::Wsl => {
                    let identity = crate::discovery_wsl::Identity::parse(&connection.vm_id);
                    match identity.and_then(|identity| {
                        reader.read(
                            Query::WslGuest {
                                owner_sid: identity.owner,
                                distribution_id: identity.distribution,
                            },
                            budget,
                        )
                    }) {
                        Ok(mut bytes) => {
                            let result = linux_projection(&bytes);
                            bytes.fill(0);
                            result
                        }
                        Err(error) => Err(error),
                    }
                }
                Hypervisor::VMware => {
                    match reader.read(
                        Query::VMwareGuest {
                            vm_id: connection.vm_id,
                            vmx_file: connection.vmx_file.unwrap_or_default(),
                            credential_file: credential
                                .map(|p| p.to_string_lossy().into_owned())
                                .unwrap_or_default(),
                        },
                        budget,
                    ) {
                        Ok(mut bytes) => {
                            let result = guest_projection(&bytes, true);
                            bytes.fill(0);
                            result
                        }
                        Err(error) => Err(error),
                    }
                }
                Hypervisor::VirtualBox => {
                    match reader.read(
                        Query::VirtualBoxGuest {
                            vm_id: connection.vm_id,
                            username: connection.username.unwrap_or_default(),
                            credential_file: credential
                                .map(|p| p.to_string_lossy().into_owned())
                                .unwrap_or_default(),
                        },
                        budget,
                    ) {
                        Ok(mut bytes) => {
                            let result = linux_projection(&bytes);
                            bytes.fill(0);
                            result
                        }
                        Err(error) => Err(error),
                    }
                }
                Hypervisor::HyperV => {
                    match reader.read(
                        Query::HyperVGuest {
                            vm_id: connection.vm_id,
                            credential_file: credential
                                .map(|p| p.to_string_lossy().into_owned())
                                .unwrap_or_default(),
                        },
                        budget,
                    ) {
                        Ok(mut bytes) => {
                            let result = hyper_v_projection(&bytes);
                            bytes.fill(0);
                            result
                        }
                        Err(e) => Err(e),
                    }
                }
            }
        };
        let status = match result {
            Ok((boot, mut rows, complete)) => {
                let result = collector::guest::processes(snapshot, &vm, &boot, &rows, access, true);
                rows.fill(0);
                if result.is_ok() && complete {
                    CoverageStatus::Available
                } else {
                    CoverageStatus::Partial
                }
            }
            Err(error) => {
                // Only a confirmed authentication refusal is sticky. Tool startup,
                // transport failures and cancelled collections must retry without
                // requiring an administrator to touch an unchanged credential.
                if credentialed
                    && error == "guest_authentication_denied"
                    && !blocked
                    && failures.len() < 32
                {
                    failures.push(key);
                }
                match error {
                    "cancelled" | "timeout" => CoverageStatus::Timeout,
                    "unavailable"
                    | "query_failed"
                    | "query_stdout"
                    | "vmware_query_failed"
                    | "guest_query_failed"
                    | "vmware_sdk_unavailable"
                    | "vmware_guest_not_running" => CoverageStatus::Unavailable,
                    "invalid_guest_response"
                    | "guest_inventory_partial"
                    | "process_limit"
                    | "response_limit" => CoverageStatus::Partial,
                    _ => CoverageStatus::Denied,
                }
            }
        };
        if let Some(coverage) = snapshot
            .coverage
            .iter_mut()
            .find(|c| c.scope == vm && c.adapter == format!("{adapter}-guest"))
        {
            coverage.status = status;
            coverage.complete = status == CoverageStatus::Available;
        }
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn credential_stamp(path: &Path, fingerprint: &mut Sha256) -> Result<(), &'static str> {
    // Keep the access/size check, but never derive a cache value from a password
    // or its encrypted representation. An administrator can also edit the local
    // configuration to retry when a deployment tool preserves file timestamps.
    let file = protected_file(path, 65536)?;
    let metadata = file.metadata().map_err(|_| "credential_unavailable")?;
    let modified = metadata
        .modified()
        .map_err(|_| "credential_unavailable")?
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "credential_unavailable")?;
    fingerprint.update(metadata.len().to_le_bytes());
    fingerprint.update(modified.as_secs().to_le_bytes());
    fingerprint.update(modified.subsec_nanos().to_le_bytes());
    Ok(())
}
pub fn collect(
    snapshot: &mut Snapshot,
    home: &Path,
    device: &str,
    access: Access,
    failures: &mut Vec<String>,
    budget: &Budget<'_>,
    running: &BTreeSet<String>,
) {
    collect_running_with(
        snapshot,
        home,
        device,
        access,
        failures,
        &NativeReader,
        budget,
        running,
    );
}

#[cfg(test)]
fn collect_with(
    snapshot: &mut Snapshot,
    home: &Path,
    device: &str,
    access: Access,
    failures: &mut Vec<String>,
    reader: &impl Reader,
    budget: &Budget<'_>,
) {
    // Existing fixtures explicitly describe running guests. Production callers
    // always supply the running set returned by hypervisor normalization.
    let running = snapshot
        .entities
        .iter()
        .filter(|entity| matches!(entity.kind, EntityKind::Vm | EntityKind::Wsl))
        .map(|entity| entity.id.clone())
        .collect();
    collect_running_with(
        snapshot, home, device, access, failures, reader, budget, &running,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    const VM: &str = "11111111-1111-4111-8111-111111111111";
    #[test]
    fn wsl_guest_configuration_binds_distribution_to_its_windows_owner() {
        let owner = "S-1-5-21-111-222-333-1001";
        let good = serde_json::json!({"version":1,"device_id":"device","connections":[{"hypervisor":"wsl","vm_id":format!("{owner}/{VM}")}]});
        assert!(configuration(&serde_json::to_vec(&good).unwrap(), "device").is_ok());
        for value in [
            VM.to_string(),
            format!("{owner}/../{VM}"),
            format!("{owner}/{VM}/extra"),
            format!("{owner}/data:image/png"),
            format!("S-1-5-18/{VM}"),
            format!("s-1-5-21-111-222-333-1001/{VM}"),
            format!("S-1-5-21-111-222-333-01001/{VM}"),
        ] {
            let mut bad = good.clone();
            bad["connections"][0]["vm_id"] = value.into();
            assert!(configuration(&serde_json::to_vec(&bad).unwrap(), "device").is_err());
        }
        for field in ["username", "credential_file", "vmx_file", "command"] {
            let mut bad = good.clone();
            bad["connections"][0][field] = "arbitrary".into();
            assert!(configuration(&serde_json::to_vec(&bad).unwrap(), "device").is_err());
        }
    }
    #[cfg(unix)]
    #[test]
    fn wsl_collection_retries_and_keeps_processes_inside_the_running_distribution() {
        use std::{
            cell::Cell, os::unix::fs::PermissionsExt, sync::atomic::AtomicBool, time::Duration,
        };
        let owner = "S-1-5-21-111-222-333-1001";
        let identity = format!("{owner}/{VM}");
        struct Fixture(Cell<usize>);
        impl Reader for Fixture {
            fn read(&self, query: Query, _: &Budget<'_>) -> Result<Vec<u8>, &'static str> {
                match query {
                    Query::WslGuest {
                        owner_sid,
                        distribution_id,
                    } if owner_sid == "S-1-5-21-111-222-333-1001" && distribution_id == VM => {
                        self.0.set(self.0.get() + 1);
                        if self.0.get() == 1 {
                            return Err("timeout");
                        }
                        Ok(serde_json::to_vec(&serde_json::json!({"boot":VM,"complete":true,"processes":[{"pid":41,"start_time":"12345","executable":"openclaw","argument_tokens":[]}]})).unwrap())
                    }
                    _ => panic!("query escaped its declared WSL owner/distribution"),
                }
            }
        }
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir(home.path().join("config")).unwrap();
        let path = home.path().join("config/discovery-guests.json");
        std::fs::write(&path,serde_json::to_vec(&serde_json::json!({"version":1,"device_id":"device","connections":[{"hypervisor":"wsl","vm_id":identity}]})).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let vm = collector::identity("vm", &["wsl", "local", &identity]);
        let snapshot = || {
            let mut s = collector::empty("endpoint", 1, 100);
            s.entities.push(milvago_discovery_engine::Entity {
                id: vm.clone(),
                kind: EntityKind::Wsl,
                display: None,
            });
            s.coverage.push(milvago_discovery_engine::Coverage {
                scope: vm.clone(),
                adapter: "wsl-guest".into(),
                status: CoverageStatus::Partial,
                checked_at: 100,
                complete: false,
            });
            s
        };
        let reader = Fixture(Cell::new(0));
        let mut failures = vec![];
        let stop = AtomicBool::new(false);
        let budget = Budget::new(Duration::from_secs(2), &stop);
        let access = Access {
            read: true,
            execute: true,
        };
        let mut stopped = snapshot();
        collect_running_with(
            &mut stopped,
            home.path(),
            "device",
            access,
            &mut failures,
            &reader,
            &budget,
            &BTreeSet::new(),
        );
        assert_eq!(
            reader.0.get(),
            0,
            "stopped distributions cannot invoke an execution channel"
        );
        let mut first = snapshot();
        collect_running_with(
            &mut first,
            home.path(),
            "device",
            access,
            &mut failures,
            &reader,
            &budget,
            &BTreeSet::from([vm.clone()]),
        );
        assert_eq!(first.coverage[0].status, CoverageStatus::Timeout);
        assert!(failures.is_empty());
        let mut second = snapshot();
        collect_running_with(
            &mut second,
            home.path(),
            "device",
            access,
            &mut failures,
            &reader,
            &budget,
            &BTreeSet::from([vm.clone()]),
        );
        assert_eq!(reader.0.get(), 2);
        assert!(second.coverage[0].complete);
        let process = second
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Process)
            .unwrap();
        assert!(
            second
                .relations
                .iter()
                .any(|r| r.from == vm && r.to == process.id)
        );
        let catalog =
            serde_json::from_slice(include_bytes!("../discovery-engine/catalog/factory.json"))
                .unwrap();
        let evaluation = milvago_discovery_engine::Engine::compile(&catalog)
            .unwrap()
            .evaluate(&second)
            .unwrap();
        assert!(
            evaluation
                .identifications
                .iter()
                .any(|i| i.application_id == "openclaw" && i.entity_id == process.id)
        );
    }
    #[cfg(unix)]
    #[test]
    fn retry_stamp_contains_no_password_derived_verifier() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("guest.password");
        let time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let write = |bytes: &[u8], time| {
            std::fs::write(&path, bytes).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::fs::File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .set_times(std::fs::FileTimes::new().set_modified(time))
                .unwrap();
        };
        let stamp = || {
            let mut hash = Sha256::new();
            credential_stamp(&path, &mut hash).unwrap();
            hash.finalize().to_vec()
        };
        write(b"FIRST-SECRET", time);
        let first = stamp();
        write(b"OTHER-SECRET", time);
        assert_eq!(
            first,
            stamp(),
            "retry stamp must depend on version metadata, not password material"
        );
        write(b"OTHER-SECRET", time + std::time::Duration::from_secs(1));
        assert_ne!(first, stamp());
    }
    #[test]
    fn guest_configuration_is_device_bound_and_closed() {
        let good = serde_json::json!({"version":1,"device_id":"device","connections":[{"hypervisor":"libvirt","vm_id":VM}]});
        let bytes = serde_json::to_vec(&good).unwrap();
        assert!(configuration(&bytes, "device").is_ok());
        assert!(configuration(&bytes, "other").is_err());
        for key in ["command", "image", "credentials"] {
            let mut bad = good.clone();
            bad[key] = "data:image/png".into();
            assert!(configuration(&serde_json::to_vec(&bad).unwrap(), "device").is_err());
        }
        for name in [
            "../secret.xml",
            "C:/secret.xml",
            "secret.xml:stream",
            "..xml",
            "secret.xml\0",
            "folder\\secret.xml",
        ] {
            assert!(!credential_leaf(name));
        }
        assert!(credential_leaf("vm-admin.xml"));
        let mut bad = good.clone();
        bad["connections"]
            .as_array_mut()
            .unwrap()
            .push(good["connections"][0].clone());
        assert!(configuration(&serde_json::to_vec(&bad).unwrap(), "device").is_err());
    }
    #[test]
    fn virtualbox_connections_require_a_local_password_file_and_explicit_user() {
        let valid = serde_json::json!({"version":1,"device_id":"device","connections":[{"hypervisor":"virtualbox","vm_id":VM,"username":"vm-reader","credential_file":"guest.password"}]});
        assert!(configuration(&serde_json::to_vec(&valid).unwrap(), "device").is_ok());
        for (field, value) in [
            ("username", serde_json::json!(null)),
            ("username", serde_json::json!("--password=secret")),
            ("username", serde_json::json!(["reader"])),
            ("credential_file", serde_json::json!("../guest.password")),
            ("credential_file", serde_json::json!("guest.xml")),
            ("vm_id", serde_json::json!("data:image/png")),
            ("command", serde_json::json!("arbitrary")),
        ] {
            let mut invalid = valid.clone();
            invalid["connections"][0][field] = value;
            assert!(
                configuration(&serde_json::to_vec(&invalid).unwrap(), "device").is_err(),
                "{field}"
            );
        }
    }
    #[test]
    fn vmware_configuration_and_boot_projection_are_bound_and_closed() {
        let path = "C:/fixture/guest.vmx";
        let id = collector::identity("vmx", &[path]);
        let valid = serde_json::json!({"version":1,"device_id":"device","connections":[{"hypervisor":"vmware","vm_id":id,"vmx_file":path,"credential_file":"guest.json"}]});
        assert!(configuration(&serde_json::to_vec(&valid).unwrap(), "device").is_ok());
        for (field, value) in [
            ("vm_id", serde_json::json!(VM)),
            ("vmx_file", serde_json::json!("C:/other.vmx")),
            ("credential_file", serde_json::json!("../guest.json")),
            ("username", serde_json::json!("unexpected")),
            ("command", serde_json::json!("arbitrary")),
        ] {
            let mut invalid = valid.clone();
            invalid["connections"][0][field] = value;
            assert!(configuration(&serde_json::to_vec(&invalid).unwrap(), "device").is_err());
        }
        let projection = serde_json::json!({"boot":"vmware-init/123","complete":false,"processes":[{"pid":42,"start_time":"124","executable":"openclaw","argument_tokens":[]}]});
        let bytes = serde_json::to_vec(&projection).unwrap();
        let (boot, rows, complete) = guest_projection(&bytes, true).unwrap();
        assert_eq!(boot, "vmware-init/123");
        assert!(!complete);
        assert!(!rows.is_empty());
        assert!(
            linux_projection(&bytes).is_err(),
            "VIX identity cannot masquerade as a kernel boot UUID"
        );
        for boot in [
            "vmware-init/0",
            "vmware-init/-1",
            "vmware-init/001",
            "data:image/png",
            VM,
        ] {
            let mut invalid = projection.clone();
            invalid["boot"] = boot.into();
            assert!(guest_projection(&serde_json::to_vec(&invalid).unwrap(), true).is_err());
        }
    }
    #[cfg(unix)]
    #[test]
    fn virtualbox_configured_channel_projects_only_the_bound_guest() {
        use std::{cell::Cell, os::unix::fs::PermissionsExt};
        struct Fixture(Cell<usize>, Cell<bool>);
        impl Reader for Fixture {
            fn read(&self, query: Query, _: &Budget<'_>) -> Result<Vec<u8>, &'static str> {
                match query {
                    Query::VirtualBoxGuest {
                        vm_id,
                        username,
                        credential_file,
                    } => {
                        assert_eq!(vm_id, VM);
                        assert_eq!(username, "vm-reader");
                        assert!(credential_file.ends_with("guest.password"));
                    }
                    _ => panic!("unexpected guest query"),
                }
                self.0.set(self.0.get() + 1);
                Ok(serde_json::to_vec(&serde_json::json!({"boot":VM,"complete":self.1.get(),"processes":[{"pid":42,"start_time":"1000","executable":"python3","argument_tokens":["hermes_cli.main"]}]})).unwrap())
            }
        }
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(home.path().join("config/discovery-secrets")).unwrap();
        let config = serde_json::json!({"version":1,"device_id":"device","connections":[{"hypervisor":"virtualbox","vm_id":VM,"username":"vm-reader","credential_file":"guest.password"}]});
        let path = home.path().join("config/discovery-guests.json");
        let secret = home.path().join("config/discovery-secrets/guest.password");
        std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        std::fs::write(&secret, b"DUMMY-GUEST-SECRET").unwrap();
        for p in [&path, &secret] {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let stop = std::sync::atomic::AtomicBool::new(false);
        let budget = Budget::new(std::time::Duration::from_secs(2), &stop);
        let mut snapshot = collector::empty("endpoint", 1, 100);
        let reader = Fixture(Cell::new(0), Cell::new(true));
        let mut failures = vec![];
        let access = Access {
            read: true,
            execute: true,
        };
        collect_with(
            &mut snapshot,
            home.path(),
            "device",
            access,
            &mut failures,
            &reader,
            &budget,
        );
        assert_eq!(reader.0.get(), 0, "unobserved guest must not be queried");
        collector::vm::inventory(
            &mut snapshot,
            collector::vm::Hypervisor::VirtualBox,
            "local",
            &serde_json::to_vec(
                &serde_json::json!([{"uuid":VM,"running":true,"tools_available":true}]),
            )
            .unwrap(),
        )
        .unwrap();
        collect_with(
            &mut snapshot,
            home.path(),
            "device",
            access,
            &mut failures,
            &reader,
            &budget,
        );
        assert_eq!(reader.0.get(), 1);
        assert!(failures.is_empty());
        assert!(
            snapshot
                .coverage
                .iter()
                .any(|c| c.adapter == "virtualbox-guest" && c.complete)
        );
        assert!(
            !serde_json::to_string(&snapshot)
                .unwrap()
                .contains("DUMMY-GUEST-SECRET")
        );
        let factory: milvago_discovery_engine::Catalog =
            serde_json::from_slice(include_bytes!("../discovery-engine/catalog/factory.json"))
                .unwrap();
        let result = milvago_discovery_engine::Engine::compile(&factory)
            .unwrap()
            .evaluate(&snapshot)
            .unwrap();
        assert_eq!(
            result.identifications[0].state,
            milvago_discovery_engine::State::Executed
        );
        let mut partial = snapshot.clone();
        partial.entities.retain(|e| e.kind != EntityKind::Process);
        partial.relations.clear();
        partial.facts.clear();
        reader.1.set(false);
        collect_with(
            &mut partial,
            home.path(),
            "device",
            access,
            &mut failures,
            &reader,
            &budget,
        );
        assert!(
            partial
                .coverage
                .iter()
                .any(|c| c.adapter == "virtualbox-guest"
                    && !c.complete
                    && c.status == CoverageStatus::Partial)
        );
        let result = milvago_discovery_engine::Engine::compile(&factory)
            .unwrap()
            .evaluate(&partial)
            .unwrap();
        assert_eq!(
            result.identifications[0].state,
            milvago_discovery_engine::State::Executed
        );
        assert!(
            failures.is_empty(),
            "a partial successful inventory is not an authentication failure"
        );
    }
    #[test]
    fn guest_projection_binds_boot_and_preserves_partial_positive_evidence() {
        let input = serde_json::json!({"boot":VM,"complete":true,"processes":[{"pid":42,"start_time":"19834","executable":"python3","argument_tokens":["hermes_cli.main"]}]});
        let (boot, rows, complete) =
            linux_projection(&serde_json::to_vec(&input).unwrap()).unwrap();
        assert_eq!(boot, VM);
        assert!(complete);
        assert!(String::from_utf8(rows).unwrap().contains("hermes_cli.main"));
        for value in [
            serde_json::json!("data:image/png"),
            serde_json::json!({"boot":"other","processes":[],"complete":true}),
        ] {
            assert!(linux_projection(&serde_json::to_vec(&value).unwrap()).is_err());
        }
        assert!(hyper_v_projection(br#"{"boot":"123","processes":"image"}"#).is_err());
        let mut partial = input.clone();
        partial["complete"] = false.into();
        let (_, rows, complete) = linux_projection(&serde_json::to_vec(&partial).unwrap()).unwrap();
        assert!(!complete);
        assert!(String::from_utf8(rows).unwrap().contains("hermes_cli.main"));
        let (_,_,complete)=hyper_v_projection(br#"{"boot":"123","processes":[{"pid":42,"start_time":"1000","executable":"python.exe","command_line":null}]}"#).unwrap();
        assert!(
            !complete,
            "unknown interpreter entry cannot prove guest process absence"
        );
    }
    #[cfg(unix)]
    #[test]
    fn vmware_channel_requires_observed_scope_and_keeps_partial_evidence() {
        use std::{cell::Cell, os::unix::fs::PermissionsExt};
        const VMX: &str = "C:/fixture/guest.vmx";
        struct Fixture(Cell<usize>);
        impl Reader for Fixture {
            fn read(&self, query: Query, _: &Budget<'_>) -> Result<Vec<u8>, &'static str> {
                match query {
                    Query::VMwareGuest {
                        vm_id,
                        vmx_file,
                        credential_file,
                    } => {
                        assert_eq!(vm_id, collector::identity("vmx", &[VMX]));
                        assert_eq!(vmx_file, VMX);
                        assert!(credential_file.ends_with("guest.json"));
                    }
                    _ => panic!("unexpected guest query"),
                }
                self.0.set(self.0.get() + 1);
                Ok(serde_json::to_vec(&serde_json::json!({"boot":"vmware-init/123","complete":false,"processes":[{"pid":42,"start_time":"124","executable":"openclaw","argument_tokens":[]}]})).unwrap())
            }
        }
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(home.path().join("config/discovery-secrets")).unwrap();
        let config = home.path().join("config/discovery-guests.json");
        let secret = home.path().join("config/discovery-secrets/guest.json");
        let vm_id = collector::identity("vmx", &[VMX]);
        std::fs::write(&config, serde_json::to_vec(&serde_json::json!({"version":1,"device_id":"device","connections":[{"hypervisor":"vmware","vm_id":vm_id,"vmx_file":VMX,"credential_file":"guest.json"}]})).unwrap()).unwrap();
        std::fs::write(
            &secret,
            br#"{"username":"reader","password":"DUMMY-SECRET"}"#,
        )
        .unwrap();
        for path in [&config, &secret] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let stop = std::sync::atomic::AtomicBool::new(false);
        let budget = Budget::new(std::time::Duration::from_secs(2), &stop);
        let reader = Fixture(Cell::new(0));
        let mut snapshot = collector::empty("endpoint", 1, 100);
        let mut failures = vec![];
        let access = Access {
            read: true,
            execute: true,
        };
        collect_with(
            &mut snapshot,
            home.path(),
            "device",
            access,
            &mut failures,
            &reader,
            &budget,
        );
        assert_eq!(reader.0.get(), 0);
        collector::vm::inventory(
            &mut snapshot,
            collector::vm::Hypervisor::VMware,
            "local",
            &serde_json::to_vec(
                &serde_json::json!([{"uuid":vm_id,"running":true,"tools_available":true}]),
            )
            .unwrap(),
        )
        .unwrap();
        collect_with(
            &mut snapshot,
            home.path(),
            "device",
            access,
            &mut failures,
            &reader,
            &budget,
        );
        assert_eq!(reader.0.get(), 1);
        assert!(failures.is_empty());
        assert!(snapshot.coverage.iter().any(|c| c.adapter == "vmware-guest"
            && c.status == CoverageStatus::Partial
            && !c.complete));
        let catalog =
            serde_json::from_slice(include_bytes!("../discovery-engine/catalog/factory.json"))
                .unwrap();
        let result = milvago_discovery_engine::Engine::compile(&catalog)
            .unwrap()
            .evaluate(&snapshot)
            .unwrap();
        assert!(
            result
                .identifications
                .iter()
                .any(|i| i.state == milvago_discovery_engine::State::Executed)
        );
        assert!(
            !serde_json::to_string(&snapshot)
                .unwrap()
                .contains("DUMMY-SECRET")
        );
        std::fs::remove_file(&secret).unwrap();
        collect_with(
            &mut snapshot,
            home.path(),
            "device",
            access,
            &mut failures,
            &reader,
            &budget,
        );
        assert_eq!(
            reader.0.get(),
            1,
            "missing credentials cannot invoke the reader"
        );
        assert!(snapshot.coverage.iter().any(|c| c.adapter == "vmware-guest"
            && c.status == CoverageStatus::Denied
            && !c.complete));
    }
    #[test]
    fn guest_execution_requires_both_authorizations_before_reader() {
        struct Forbidden;
        impl Reader for Forbidden {
            fn read(&self, _: Query, _: &Budget<'_>) -> Result<Vec<u8>, &'static str> {
                panic!("unauthorized guest access");
            }
        }
        let stop = std::sync::atomic::AtomicBool::new(false);
        let budget = Budget::new(std::time::Duration::from_secs(1), &stop);
        for access in [
            Access::default(),
            Access {
                read: true,
                execute: false,
            },
            Access {
                read: false,
                execute: true,
            },
        ] {
            let mut snapshot = collector::empty("endpoint", 1, 100);
            collect_with(
                &mut snapshot,
                Path::new("/nonexistent"),
                "device",
                access,
                &mut vec![],
                &Forbidden,
                &budget,
            );
            assert_eq!(snapshot.coverage[0].status, CoverageStatus::Denied);
        }
    }

    #[test]
    fn qga_validates_exit_payload_and_honors_cancellation() {
        struct Fixture {
            result: serde_json::Value,
        }
        impl Reader for Fixture {
            fn read(&self, query: Query, _: &Budget<'_>) -> Result<Vec<u8>, &'static str> {
                Ok(serde_json::to_vec(&match query {
                    Query::LibvirtGuestStart(vm) if vm == VM => {
                        serde_json::json!({"return":{"pid":42}})
                    }
                    Query::LibvirtGuestStatus { vm_id, pid } if vm_id == VM && pid == 42 => {
                        self.result.clone()
                    }
                    _ => panic!("unexpected or unbound query"),
                })
                .unwrap())
            }
        }
        let stop = std::sync::atomic::AtomicBool::new(false);
        let budget = Budget::new(std::time::Duration::from_secs(1), &stop);
        let payload = STANDARD.encode(
            serde_json::to_vec(&serde_json::json!({"boot":VM,"complete":true,"processes":[]}))
                .unwrap(),
        );
        let good = serde_json::json!({"return":{"exited":true,"exitcode":0,"out-data":payload}});
        assert!(
            qga(
                &Fixture {
                    result: good.clone()
                },
                VM,
                &budget
            )
            .is_ok()
        );
        for (field, value) in [
            ("exitcode", serde_json::json!(1)),
            ("out-truncated", serde_json::json!(true)),
            ("out-data", serde_json::json!("data:image/png")),
            ("exited", serde_json::json!("true")),
        ] {
            let mut bad = good.clone();
            bad["return"][field] = value;
            assert!(qga(&Fixture { result: bad }, VM, &budget).is_err());
        }
        stop.store(true, std::sync::atomic::Ordering::Release);
        assert_eq!(
            qga(&Fixture { result: good }, VM, &budget).unwrap_err(),
            "cancelled"
        );
    }

    #[cfg(unix)]
    #[test]
    fn stopped_guests_are_not_queried_and_qga_recovers_when_tools_become_ready() {
        use std::{cell::Cell, os::unix::fs::PermissionsExt};
        struct Fixture {
            phase: Cell<u8>,
            calls: Cell<usize>,
        }
        impl Reader for Fixture {
            fn read(&self, query: Query, _: &Budget<'_>) -> Result<Vec<u8>, &'static str> {
                match query {
                    Query::Libvirt => Ok(format!("{VM}\n").into_bytes()),
                    Query::LibvirtState(id) if id == VM => Ok(if self.phase.get() == 0 {
                        b"shut off\n".to_vec()
                    } else {
                        b"running\n".to_vec()
                    }),
                    Query::LibvirtGuestStart(id) if id == VM => {
                        self.calls.set(self.calls.get() + 1);
                        if self.phase.get() < 3 {
                            Err("unavailable")
                        } else {
                            Ok(br#"{"return":{"pid":42}}"#.to_vec())
                        }
                    }
                    Query::LibvirtGuestStatus { vm_id, pid } if vm_id == VM && pid == 42 => {
                        let output=serde_json::to_vec(&serde_json::json!({"boot":VM,"complete":true,"processes":[{"pid":42,"start_time":"1000","executable":"python3.11","argument_tokens":["hermes_cli.main"]}]})).unwrap();
                        Ok(serde_json::to_vec(&serde_json::json!({"return":{"exited":true,"exitcode":0,"out-data":STANDARD.encode(output)}})).unwrap())
                    }
                    _ => Err("unavailable"),
                }
            }
        }
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir(home.path().join("config")).unwrap();
        let path = home.path().join("config/discovery-guests.json");
        std::fs::write(&path,serde_json::to_vec(&serde_json::json!({"version":1,"device_id":"device","connections":[{"hypervisor":"libvirt","vm_id":VM}]})).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let reader = Fixture {
            phase: Cell::new(0),
            calls: Cell::new(0),
        };
        let mut failures = vec![];
        let stop = std::sync::atomic::AtomicBool::new(false);
        for phase in 0..4 {
            reader.phase.set(phase);
            let budget = Budget::new(std::time::Duration::from_secs(2), &stop);
            let mut snapshot = collector::empty("endpoint", phase as u64 + 1, 100);
            let machines = collector::system::virtual_machines(&mut snapshot, &reader, &budget);
            let running = machines
                .iter()
                .map(|machine| machine.entity.clone())
                .collect();
            collect_running_with(
                &mut snapshot,
                home.path(),
                "device",
                Access {
                    read: true,
                    execute: true,
                },
                &mut failures,
                &reader,
                &budget,
                &running,
            );
            assert_eq!(
                reader.calls.get(),
                phase as usize,
                "stopped guests are skipped; QGA retries need no guest credential"
            );
            assert!(failures.is_empty());
            if phase == 1 || phase == 2 {
                assert!(
                    snapshot
                        .coverage
                        .iter()
                        .any(|row| row.adapter == "libvirt-guest"
                            && row.status == CoverageStatus::Unavailable
                            && !row.complete)
                );
            }
            if phase == 3 {
                let catalog = serde_json::from_slice(include_bytes!(
                    "../discovery-engine/catalog/factory.json"
                ))
                .unwrap();
                let result = milvago_discovery_engine::Engine::compile(&catalog)
                    .unwrap()
                    .evaluate(&snapshot)
                    .unwrap();
                assert!(
                    result
                        .identifications
                        .iter()
                        .any(|item| item.application_id == "hermes"
                            && item.state == milvago_discovery_engine::State::Executed)
                );
                assert!(
                    snapshot
                        .coverage
                        .iter()
                        .any(|row| row.adapter == "libvirt-guest" && row.complete)
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn confirmed_guest_authentication_failure_is_latched_until_local_configuration_changes() {
        use std::{cell::Cell, os::unix::fs::PermissionsExt};
        struct Denied(Cell<usize>);
        impl Reader for Denied {
            fn read(&self, query: Query, _: &Budget<'_>) -> Result<Vec<u8>, &'static str> {
                assert!(matches!(query, Query::HyperVGuest { .. }));
                self.0.set(self.0.get() + 1);
                Err("guest_authentication_denied")
            }
        }
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(home.path().join("config/discovery-secrets")).unwrap();
        let path = home.path().join("config/discovery-guests.json");
        let config = serde_json::json!({"version":1,"device_id":"device","connections":[{"hypervisor":"hyper_v","vm_id":VM,"credential_file":"guest.xml"}]});
        let credential = home.path().join("config/discovery-secrets/guest.xml");
        std::fs::write(&credential, b"DUMMY-CREDENTIAL-FIXTURE").unwrap();
        std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let stop = std::sync::atomic::AtomicBool::new(false);
        let budget = Budget::new(std::time::Duration::from_secs(1), &stop);
        let mut failures = vec![];
        let reader = Denied(Cell::new(0));
        let mut snapshot = collector::empty("endpoint", 1, 100);
        collector::vm::inventory(
            &mut snapshot,
            collector::vm::Hypervisor::HyperV,
            "local",
            &serde_json::to_vec(
                &serde_json::json!([{"uuid":VM,"running":true,"tools_available":true}]),
            )
            .unwrap(),
        )
        .unwrap();
        for _ in 0..2 {
            collect_with(
                &mut snapshot,
                home.path(),
                "device",
                Access {
                    read: true,
                    execute: true,
                },
                &mut failures,
                &reader,
                &budget,
            );
        }
        assert_eq!(reader.0.get(), 1);
        assert_eq!(failures.len(), 1);
        assert_eq!(snapshot.coverage[0].status, CoverageStatus::Denied);
        let mut changed = serde_json::to_vec(&config).unwrap();
        changed.push(b'\n');
        std::fs::write(&path, changed).unwrap();
        collect_with(
            &mut snapshot,
            home.path(),
            "device",
            Access {
                read: true,
                execute: true,
            },
            &mut failures,
            &reader,
            &budget,
        );
        assert_eq!(reader.0.get(), 2);
        assert_eq!(failures.len(), 1);
        // Untrusted local configuration is not an authorization source.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        collect_with(
            &mut snapshot,
            home.path(),
            "device",
            Access {
                read: true,
                execute: true,
            },
            &mut failures,
            &reader,
            &budget,
        );
        assert_eq!(reader.0.get(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn transient_credentialed_guest_errors_retry_without_secret_or_configuration_changes() {
        use std::{cell::Cell, os::unix::fs::PermissionsExt};
        struct Fixture {
            error: &'static str,
            calls: Cell<usize>,
        }
        impl Reader for Fixture {
            fn read(&self, _: Query, _: &Budget<'_>) -> Result<Vec<u8>, &'static str> {
                self.calls.set(self.calls.get() + 1);
                Err(self.error)
            }
        }
        for (hypervisor, adapter, secret) in [
            ("hyper_v", "hyper-v", "guest.xml"),
            ("virtualbox", "virtualbox", "guest.password"),
            ("vmware", "vmware", "guest.json"),
        ] {
            for error in [
                "timeout",
                "cancelled",
                "unavailable",
                "query_failed",
                "invalid_guest_response",
                "vmware_sdk_unavailable",
                "vmware_guest_not_running",
            ] {
                let home = tempfile::tempdir().unwrap();
                std::fs::create_dir_all(home.path().join("config/discovery-secrets")).unwrap();
                let vmx = "/protected/fixture.vmx";
                let vm_id = if hypervisor == "vmware" {
                    collector::identity("vmx", &[vmx])
                } else {
                    VM.to_owned()
                };
                let mut connection = serde_json::json!({"hypervisor":hypervisor,"vm_id":vm_id,"credential_file":secret});
                if hypervisor == "virtualbox" {
                    connection["username"] = "fixture-reader".into();
                }
                if hypervisor == "vmware" {
                    connection["vmx_file"] = vmx.into();
                }
                let config = serde_json::json!({"version":1,"device_id":"device","connections":[connection]});
                for (path, bytes) in [
                    (
                        home.path().join("config/discovery-guests.json"),
                        serde_json::to_vec(&config).unwrap(),
                    ),
                    (
                        home.path().join("config/discovery-secrets").join(secret),
                        b"DUMMY-FIXTURE".to_vec(),
                    ),
                ] {
                    std::fs::write(&path, bytes).unwrap();
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                        .unwrap();
                }
                let vm = collector::identity("vm", &[adapter, "local", &vm_id]);
                let running = BTreeSet::from([vm.clone()]);
                let reader = Fixture {
                    error,
                    calls: Cell::new(0),
                };
                let stop = std::sync::atomic::AtomicBool::new(false);
                let budget = Budget::new(std::time::Duration::from_secs(2), &stop);
                let mut failures = vec![];
                for sequence in 1..=2 {
                    let mut snapshot = collector::empty("endpoint", sequence, 100);
                    snapshot.entities.push(milvago_discovery_engine::Entity {
                        id: vm.clone(),
                        kind: EntityKind::Vm,
                        display: None,
                    });
                    snapshot.coverage.push(milvago_discovery_engine::Coverage {
                        scope: vm.clone(),
                        adapter: format!("{adapter}-guest"),
                        status: CoverageStatus::Unavailable,
                        checked_at: 100,
                        complete: false,
                    });
                    collect_running_with(
                        &mut snapshot,
                        home.path(),
                        "device",
                        Access {
                            read: true,
                            execute: true,
                        },
                        &mut failures,
                        &reader,
                        &budget,
                        &running,
                    );
                    let expected = match error {
                        "timeout" | "cancelled" => CoverageStatus::Timeout,
                        "invalid_guest_response" => CoverageStatus::Partial,
                        _ => CoverageStatus::Unavailable,
                    };
                    assert_eq!(
                        snapshot.coverage[0].status, expected,
                        "{hypervisor}: {error} coverage"
                    );
                    assert!(!snapshot.coverage[0].complete);
                }
                assert_eq!(
                    reader.calls.get(),
                    2,
                    "{hypervisor}: {error} must not permanently disable guest discovery"
                );
                assert!(
                    failures.is_empty(),
                    "{hypervisor}: {error} is not confirmed authentication failure"
                );
            }
        }
    }
}
