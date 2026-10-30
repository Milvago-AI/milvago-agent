use crate::*;
use serde::Deserialize;

#[derive(Clone, Debug)]
pub enum Query {
    HyperV,
    Wsl,
    WslUserInventory,
    WslGuest {
        owner_sid: String,
        distribution_id: String,
    },
    VirtualBox,
    VMware,
    Libvirt,
    LibvirtState(String),
    LibvirtInterfaces(String),
    LibvirtAddresses(String),
    LibvirtInterfaceLink {
        vm_id: String,
        interface: String,
    },
    WindowsProcessEntries,
    HyperVGuest {
        vm_id: String,
        credential_file: String,
    },
    VirtualBoxGuest {
        vm_id: String,
        username: String,
        credential_file: String,
    },
    VMwareGuest {
        vm_id: String,
        vmx_file: String,
        credential_file: String,
    },
    LibvirtGuestStart(String),
    LibvirtGuestStatus {
        vm_id: String,
        pid: u32,
    },
}
pub trait Reader {
    fn read(&self, query: Query, budget: &Budget<'_>) -> Result<Vec<u8>, &'static str>;
}

fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VirtualMachine {
    uuid: String,
    running: bool,
    tools_available: bool,
    #[serde(default)]
    display_name: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Machine {
    pub hypervisor: vm::Hypervisor,
    pub uuid: String,
    pub entity: String,
}

pub fn virtual_machines(
    snapshot: &mut Snapshot,
    reader: &impl Reader,
    budget: &Budget<'_>,
) -> Vec<Machine> {
    let mut running = vec![];
    for (query, hypervisor) in [
        (Query::HyperV, vm::Hypervisor::HyperV),
        (Query::Wsl, vm::Hypervisor::Wsl),
        (Query::VirtualBox, vm::Hypervisor::VirtualBox),
        (Query::VMware, vm::Hypervisor::VMware),
        (Query::Libvirt, vm::Hypervisor::Libvirt),
    ] {
        if budget.check().is_err() {
            coverage(
                snapshot,
                hypervisor.adapter(),
                CoverageStatus::Timeout,
                false,
            );
            break;
        }
        let rows = match reader.read(query.clone(), budget) {
            Ok(bytes) => match normalize(query, &bytes, reader, budget) {
                Ok(v) => v,
                Err(_) => {
                    coverage(
                        snapshot,
                        hypervisor.adapter(),
                        CoverageStatus::Partial,
                        false,
                    );
                    continue;
                }
            },
            Err(error) => {
                coverage(
                    snapshot,
                    hypervisor.adapter(),
                    if error == "access_denied" {
                        CoverageStatus::Denied
                    } else {
                        CoverageStatus::Unavailable
                    },
                    false,
                );
                continue;
            }
        };
        match vm::inventory(snapshot, hypervisor, "local", &rows) {
            Ok(_) => {
                if let Ok(machines) = serde_json::from_slice::<Vec<VirtualMachine>>(&rows) {
                    running.extend(machines.into_iter().filter(|m| m.running).map(|m| Machine {
                        hypervisor,
                        entity: vm::entity_id(hypervisor, "local", &m.uuid),
                        uuid: vm::canonical_uuid(&m.uuid),
                    }));
                }
                // Account-scoped CLIs and qemu:///system cannot enumerate every
                // user's registrations or independent libvirt session daemon.
                let partial = matches!(
                    hypervisor,
                    vm::Hypervisor::VirtualBox
                        | vm::Hypervisor::VMware
                        | vm::Hypervisor::Wsl
                        | vm::Hypervisor::Libvirt
                );
                coverage(
                    snapshot,
                    hypervisor.adapter(),
                    if partial {
                        CoverageStatus::Partial
                    } else {
                        CoverageStatus::Available
                    },
                    !partial,
                );
            }
            Err(_) => coverage(
                snapshot,
                hypervisor.adapter(),
                CoverageStatus::Partial,
                false,
            ),
        }
    }
    running
}

#[cfg(windows)]
pub fn process_entries(snapshot: &mut Snapshot, reader: &impl Reader, budget: &Budget<'_>) {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Entry {
        pid: u32,
        start_time: u64,
        executable: Option<String>,
        command_line: Option<String>,
    }
    let mut bytes = match reader.read(Query::WindowsProcessEntries, budget) {
        Ok(v) => v,
        Err(_) => {
            coverage(
                snapshot,
                "windows-interpreter-entries",
                CoverageStatus::Partial,
                false,
            );
            return;
        }
    };
    let rows = serde_json::from_slice::<Vec<Entry>>(&bytes);
    bytes.fill(0);
    let Ok(rows) = rows else {
        coverage(
            snapshot,
            "windows-interpreter-entries",
            CoverageStatus::Partial,
            false,
        );
        return;
    };
    let mut complete = rows.len() <= 1024;
    let mut field_budget = FieldBudget::new(snapshot);
    for entry in rows.into_iter().take(1024) {
        if budget.check().is_err() || snapshot.entities.len() >= MAX_ENTITIES {
            complete = false;
            break;
        }
        let Some(executable) = entry.executable.filter(|v| v.len() <= 1024) else {
            complete = false;
            continue;
        };
        let executable = crate::host::executable_name(&executable);
        if entry.pid == 0 || entry.start_time == 0 {
            complete = false;
            continue;
        }
        let current = crate::host::current_windows_identity(entry.pid);
        let Some(id) = windows_entry_scope(
            snapshot,
            entry.pid,
            entry.start_time,
            &executable,
            current.as_deref(),
        ) else {
            complete = false;
            continue;
        };
        if entry
            .command_line
            .as_ref()
            .is_none_or(|line| line.is_empty())
        {
            complete = false;
            continue;
        }
        let args = entry
            .command_line
            .map(|mut line| {
                let args = windows_arguments(&line);
                let mut bytes = std::mem::take(&mut line).into_bytes();
                bytes.fill(0);
                args
            })
            .unwrap_or_default();
        let tokens = crate::host::entry_tokens(&executable, &args);
        if tokens.is_empty() {
            continue;
        }
        if !field_budget.insert(
            snapshot,
            &id,
            Source::HostProcess,
            BTreeMap::from([
                (Field::Executable, vec![executable]),
                (Field::ArgumentToken, tokens),
            ]),
        ) {
            complete = false;
            break;
        }
    }
    coverage(
        snapshot,
        "windows-interpreter-entries",
        if complete {
            CoverageStatus::Available
        } else {
            CoverageStatus::Partial
        },
        complete,
    );
}

// CIM interpreter entries enrich the kernel process already observed in this
// snapshot. A stale PID, changed creation time or image cannot create a second
// process identity or borrow another process's listening sockets.
#[cfg(any(windows, test))]
fn windows_entry_scope(
    snapshot: &Snapshot,
    pid: u32,
    start: u64,
    executable: &str,
    current: Option<&str>,
) -> Option<String> {
    let id = identity("process", &[&pid.to_string(), &start.to_string()]);
    if current != Some(id.as_str())
        || !snapshot
            .entities
            .iter()
            .any(|entity| entity.id == id && entity.kind == EntityKind::Process)
        || !snapshot.facts.iter().any(|fact| {
            fact.entity_id == id
                && fact.source == Source::HostProcess
                && fact
                    .fields
                    .get(&Field::Executable)
                    .is_some_and(|values| values.iter().any(|value| value == executable))
        })
    {
        return None;
    }
    Some(id)
}

#[cfg(windows)]
pub fn windows_arguments(line: &str) -> Vec<String> {
    if line.len() > 8192 || line.contains('\0') {
        return vec![];
    }
    #[link(name = "shell32")]
    unsafe extern "system" {
        fn CommandLineToArgvW(line: *const u16, count: *mut i32) -> *mut *mut u16;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LocalFree(memory: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    }
    let wide: Vec<u16> = line.encode_utf16().chain(Some(0)).collect();
    let mut count = 0;
    let raw = unsafe { CommandLineToArgvW(wide.as_ptr(), &mut count) };
    if raw.is_null() {
        return vec![];
    }
    struct Allocation(*mut *mut u16);
    impl Drop for Allocation {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0.cast());
            }
        }
    }
    let _allocation = Allocation(raw);
    let mut args = vec![];
    if !(1..=1024).contains(&count) {
        return args;
    }
    for index in 1..count.min(4) {
        let pointer = unsafe { *raw.add(index as usize) };
        if pointer.is_null() {
            return vec![];
        }
        let mut length = 0;
        while length < 8192 && unsafe { *pointer.add(length) } != 0 {
            length += 1;
        }
        if length == 8192 {
            return vec![];
        }
        args.push(String::from_utf16_lossy(unsafe {
            std::slice::from_raw_parts(pointer, length)
        }));
    }
    args
}

fn inventory_label(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty() && value.len() <= 160 && !value.chars().any(char::is_control))
        .then(|| value.to_owned())
}

fn vmware_label(path: &str) -> Option<String> {
    // Use only the registration filename. Parent directories can contain user
    // names or private workspace details and must not enter the display label.
    let file = path.rsplit(['/', '\\']).next()?;
    if !file.to_ascii_lowercase().ends_with(".vmx") {
        return None;
    }
    inventory_label(file.get(..file.len() - 4)?)
}

fn normalize(
    query: Query,
    bytes: &[u8],
    reader: &impl Reader,
    budget: &Budget<'_>,
) -> Result<Vec<u8>, &'static str> {
    if bytes.len() > MAX_RESPONSE {
        return Err("response_limit");
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "invalid_inventory")?;
    match query {
        Query::HyperV | Query::Wsl => {
            let rows: Vec<VirtualMachine> =
                serde_json::from_slice(bytes).map_err(|_| "invalid_inventory")?;
            if rows.len() > 100 || rows.iter().any(|r| !identifier(&r.uuid)) {
                return Err("invalid_inventory");
            }
            let rows:Vec<_>=rows.into_iter().map(|r|serde_json::json!({"uuid":r.uuid,"running":r.running,"tools_available":r.tools_available,"display_name":r.display_name})).collect();
            serde_json::to_vec(&rows).map_err(|_| "invalid_inventory")
        }
        Query::VirtualBox => {
            let mut rows = vec![];
            let mut id = None;
            let mut running = false;
            let mut display_name = None;
            let mut pending_name = None;
            for line in text.lines() {
                if let Some(value) = line.strip_prefix("Name:") {
                    pending_name = inventory_label(value);
                    continue;
                }
                if let Some(value) = line.strip_prefix("UUID:") {
                    if let Some(id) = id.take() {
                        rows.push(serde_json::json!({"uuid":id,"running":running,"tools_available":false,"display_name":display_name.take()}));
                    }
                    let value = value.trim();
                    if !uuid(value) {
                        return Err("invalid_vm_identity");
                    }
                    id = Some(value.to_ascii_lowercase());
                    display_name = pending_name.take();
                    running = false;
                }
                if let Some(value) = line.strip_prefix("State:") {
                    running = value.trim().starts_with("running");
                }
                if rows.len() > 100 {
                    return Err("vm_limit");
                }
            }
            if let Some(id) = id {
                rows.push(serde_json::json!({"uuid":id,"running":running,"tools_available":false,"display_name":display_name.take()}));
            }
            serde_json::to_vec(&rows).map_err(|_| "invalid_inventory")
        }
        Query::VMware => {
            // vmrun lists only running guests. A missing entry is not proof that a VM does not exist.
            let mut rows = vec![];
            for line in text.lines().skip(1).filter(|l| !l.trim().is_empty()) {
                if rows.len() >= 100 || line.len() > 4096 {
                    return Err("vm_limit");
                }
                rows.push(serde_json::json!({"uuid":identity("vmx",&[line.trim()]),"running":true,"tools_available":false,"display_name":vmware_label(line.trim())}));
            }
            serde_json::to_vec(&rows).map_err(|_| "invalid_inventory")
        }
        Query::Libvirt => {
            let ids: Vec<_> = text
                .lines()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .take(101)
                .collect();
            let mut seen = std::collections::BTreeSet::new();
            if ids.len() > 100
                || ids
                    .iter()
                    .any(|id| !uuid(id) || !seen.insert(id.to_ascii_lowercase()))
            {
                return Err("invalid_vm_identity");
            }
            let mut rows = vec![];
            for value in ids {
                budget.check()?;
                let state = reader.read(Query::LibvirtState(value.into()), budget);
                budget.check()?;
                // The system list already proves registration. A vanished or
                // denied state must not erase siblings or authorize guest access.
                // Libvirt inventory coverage remains partial for every run.
                let running = state.as_deref().is_ok_and(|bytes| {
                    bytes.len() <= 80
                        && std::str::from_utf8(bytes).is_ok_and(|text| text.trim() == "running")
                });
                rows.push(serde_json::json!({"uuid":value.to_ascii_lowercase(),"running":running,"tools_available":false}));
            }
            serde_json::to_vec(&rows).map_err(|_| "invalid_inventory")
        }
        _ => Err("unsupported_query"),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn interpreter_metadata_cannot_create_or_reassign_a_kernel_process() {
        let mut snapshot = crate::empty("endpoint", 1, 100);
        let id = identity("process", &["42", "1000"]);
        assert!(super::windows_entry_scope(&snapshot, 42, 1000, "python3", Some(&id)).is_none());
        snapshot.entities.push(Entity {
            display: None,
            id: id.clone(),
            kind: EntityKind::Process,
        });
        assert!(super::windows_entry_scope(&snapshot, 42, 1000, "python3", Some(&id)).is_none());
        fact(
            &mut snapshot,
            &id,
            Source::HostProcess,
            BTreeMap::from([(Field::Executable, vec!["python3".into()])]),
        );
        assert_eq!(
            super::windows_entry_scope(&snapshot, 42, 1000, "python3", Some(&id)),
            Some(id.clone())
        );
        for (pid, start, image, current) in [
            (42, 1001, "python3", Some(id.as_str())),
            (43, 1000, "python3", Some(id.as_str())),
            (42, 1000, "node", Some(id.as_str())),
            (42, 1000, "python3", None),
        ] {
            assert!(super::windows_entry_scope(&snapshot, pid, start, image, current).is_none());
        }
        assert_eq!(snapshot.entities.len(), 1);
        assert_eq!(snapshot.facts.len(), 1);
    }
    use super::*;
    use std::{sync::atomic::AtomicBool, time::Duration};
    struct Fixture;
    #[test]
    fn libvirt_one_unreadable_state_does_not_hide_other_machines() {
        const UNKNOWN: &str = "11111111-1111-4111-8111-111111111111";
        const STOPPED: &str = "22222222-2222-4222-8222-222222222222";
        const RUNNING: &str = "33333333-3333-4333-8333-333333333333";
        struct States(Result<Vec<u8>, &'static str>);
        impl Reader for States {
            fn read(&self, query: Query, _: &Budget<'_>) -> Result<Vec<u8>, &'static str> {
                match query {
                    Query::Libvirt => Ok(format!("{UNKNOWN}\n{STOPPED}\n{RUNNING}\n").into_bytes()),
                    Query::LibvirtState(id) if id == UNKNOWN => self.0.clone(),
                    Query::LibvirtState(id) if id == STOPPED => Ok(b"shut off\n".to_vec()),
                    Query::LibvirtState(id) if id == RUNNING => Ok(b"running\n".to_vec()),
                    _ => Err("unavailable"),
                }
            }
        }
        for response in [
            Err("access_denied"),
            Err("unavailable"),
            Ok(vec![0xff]),
            Ok(vec![b'x'; MAX_RESPONSE + 1]),
            Ok(b"running-invalid\n".to_vec()),
            Ok(b"running\nshut off\n".to_vec()),
        ] {
            let stop = AtomicBool::new(false);
            let budget = Budget::new(Duration::from_secs(2), &stop);
            let mut snapshot = empty("endpoint", 1, 100);
            let machines = virtual_machines(&mut snapshot, &States(response), &budget);
            assert_eq!(
                snapshot.entities.len(),
                3,
                "known VM presence must survive a state failure"
            );
            assert_eq!(
                machines.len(),
                1,
                "only confirmed running guests can be queried"
            );
            assert_eq!(machines[0].uuid, RUNNING);
            assert!(snapshot.facts.is_empty());
            assert!(
                snapshot
                    .coverage
                    .iter()
                    .any(|row| row.adapter == "libvirt" && !row.complete)
            );
            assert!(snapshot.coverage.iter().any(|row| row.scope
                == vm::entity_id(vm::Hypervisor::Libvirt, "local", UNKNOWN)
                && row.adapter == "libvirt-guest"
                && !row.complete));
            validate_snapshot(&snapshot).unwrap();
        }
    }

    #[test]
    fn libvirt_rejects_invalid_lists_before_any_per_guest_query() {
        struct Forbidden;
        impl Reader for Forbidden {
            fn read(&self, _: Query, _: &Budget<'_>) -> Result<Vec<u8>, &'static str> {
                panic!("invalid inventory must not trigger guest queries");
            }
        }
        let vm = "11111111-1111-4111-8111-111111111111";
        let stop = AtomicBool::new(false);
        let budget = Budget::new(Duration::from_secs(2), &stop);
        for input in [
            format!("{vm}\ninvalid\n"),
            format!("{vm}\n{vm}\n"),
            (0..101)
                .map(|index| format!("{index:08x}-1111-4111-8111-111111111111\n"))
                .collect(),
        ] {
            assert!(normalize(Query::Libvirt, input.as_bytes(), &Forbidden, &budget).is_err());
        }
    }

    #[test]
    fn libvirt_state_failures_do_not_swallow_cancellation() {
        struct Cancel<'a>(&'a AtomicBool);
        impl Reader for Cancel<'_> {
            fn read(&self, _: Query, _: &Budget<'_>) -> Result<Vec<u8>, &'static str> {
                self.0.store(true, std::sync::atomic::Ordering::Release);
                Err("access_denied")
            }
        }
        let stop = AtomicBool::new(false);
        let budget = Budget::new(Duration::from_secs(2), &stop);
        assert_eq!(
            normalize(
                Query::Libvirt,
                b"11111111-1111-4111-8111-111111111111\n",
                &Cancel(&stop),
                &budget
            )
            .unwrap_err(),
            "cancelled"
        );
    }

    #[test]
    fn libvirt_system_inventory_does_not_claim_user_session_visibility() {
        struct SystemOnly(bool);
        impl Reader for SystemOnly {
            fn read(&self, query: Query, _: &Budget<'_>) -> Result<Vec<u8>, &'static str> {
                match query {
                    Query::Libvirt => Ok(if self.0 {
                        b"11111111-1111-4111-8111-111111111111\n".to_vec()
                    } else {
                        vec![]
                    }),
                    Query::LibvirtState(_) => Ok(b"running\n".to_vec()),
                    _ => Err("unavailable"),
                }
            }
        }
        for populated in [false, true] {
            let stop = AtomicBool::new(false);
            let budget = Budget::new(Duration::from_secs(2), &stop);
            let mut snapshot = empty("endpoint", 1, 100);
            let running = virtual_machines(&mut snapshot, &SystemOnly(populated), &budget);
            assert_eq!(running.len(), usize::from(populated));
            assert_eq!(snapshot.entities.len(), usize::from(populated));
            assert!(snapshot.facts.is_empty());
            assert!(snapshot.coverage.iter().any(|row| {
                row.adapter == "libvirt" && row.status == CoverageStatus::Partial && !row.complete
            }));
            validate_snapshot(&snapshot).unwrap();
        }
    }
    #[test]
    fn native_vendor_inventory_formats_preserve_running_and_unknown_guest_visibility() {
        let stop = AtomicBool::new(false);
        let budget = Budget::new(Duration::from_secs(2), &stop);
        for (input, running) in [
            (
                include_bytes!("../tests/fixtures/virtualbox-7.2-stopped.txt").as_slice(),
                false,
            ),
            (
                include_bytes!("../tests/fixtures/virtualbox-7.2-running.txt").as_slice(),
                true,
            ),
        ] {
            let bytes = normalize(Query::VirtualBox, input, &Fixture, &budget).unwrap();
            let rows: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(rows.as_array().unwrap().len(), 1);
            assert_eq!(rows[0]["running"], running);
            assert_eq!(rows[0]["tools_available"], false);
            assert_eq!(rows[0]["uuid"], "11111111-1111-4111-8111-111111111111");
            assert_eq!(rows[0]["display_name"], "Synthetic guest");
        }
        let bytes = normalize(
            Query::VMware,
            include_bytes!("../tests/fixtures/vmware-workstation-running.txt"),
            &Fixture,
            &budget,
        )
        .unwrap();
        let rows: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(rows.as_array().unwrap().len(), 1);
        assert_eq!(rows[0]["running"], true);
        assert_eq!(rows[0]["tools_available"], false);
        assert_eq!(rows[0]["display_name"], "guest");
        let mut snapshot = empty("endpoint", 1, 100);
        virtual_machines(&mut snapshot, &Fixture, &budget);
        assert!(snapshot.facts.is_empty());
        assert!(snapshot.coverage.iter().any(|c| c.adapter == "virtualbox"
            && c.status == CoverageStatus::Partial
            && !c.complete));
    }
    impl Reader for Fixture {
        fn read(&self, query: Query, _: &Budget<'_>) -> Result<Vec<u8>, &'static str> {
            Ok(match query{
        Query::HyperV|Query::Wsl=>br#"[{"uuid":"11111111-1111-4111-8111-111111111111","running":true,"tools_available":false}]"#.to_vec(),
        Query::VirtualBox=>b"UUID: 11111111-1111-4111-8111-111111111111\nState: running (since fixture)\n".to_vec(),
        Query::VMware=>b"Total running VMs: 1\n/fixture/guest.vmx\n".to_vec(),
        Query::Libvirt=>b"11111111-1111-4111-8111-111111111111\n".to_vec(),
        Query::LibvirtState(_)=>b"running\n".to_vec(),_=>return Err("unavailable")})
        }
    }
    #[test]
    fn every_hypervisor_normalizes_only_inventory_not_guest_applications() {
        let stop = AtomicBool::new(false);
        let budget = Budget::new(Duration::from_secs(5), &stop);
        let mut snapshot = empty("endpoint", 1, 100);
        virtual_machines(&mut snapshot, &Fixture, &budget);
        assert_eq!(snapshot.entities.len(), 5);
        assert!(snapshot.facts.is_empty());
        assert!(
            snapshot
                .coverage
                .iter()
                .any(|c| c.adapter == "vmware-guest" && !c.complete)
        );
        validate_snapshot(&snapshot).unwrap();
    }
    #[test]
    fn vm_names_stay_with_their_registration_and_never_become_application_evidence() {
        let first = "11111111-1111-4111-8111-111111111111";
        let second = "22222222-2222-4222-8222-222222222222";
        let stop = AtomicBool::new(false);
        let budget = Budget::new(Duration::from_secs(2), &stop);
        let input = format!(
            "Name: OpenClaw lab\nUUID: {first}\nState: running\nName: Other VM\nUUID: {second}\nState: powered off\n"
        );
        let bytes = normalize(Query::VirtualBox, input.as_bytes(), &Fixture, &budget).unwrap();
        let rows: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(rows[0]["display_name"], "OpenClaw lab");
        assert_eq!(rows[1]["display_name"], "Other VM");
        assert_eq!(rows[0]["running"], true);
        assert_eq!(rows[1]["running"], false);
        let mut snapshot = empty("endpoint", 1, 100);
        vm::inventory(&mut snapshot, vm::Hypervisor::VirtualBox, "local", &bytes).unwrap();
        assert_eq!(
            snapshot.entities[0].id,
            vm::entity_id(vm::Hypervisor::VirtualBox, "local", first)
        );
        assert_eq!(
            snapshot.entities[0]
                .display
                .as_ref()
                .unwrap()
                .name
                .as_deref(),
            Some("OpenClaw lab")
        );
        let catalog = serde_json::from_slice(include_bytes!(
            "../../discovery-engine/catalog/factory.json"
        ))
        .unwrap();
        assert!(
            Engine::compile(&catalog)
                .unwrap()
                .evaluate(&snapshot)
                .unwrap()
                .identifications
                .is_empty()
        );

        let input = "Total running VMs: 2\nC:\\PRIVATE_DIRECTORY\\VMs\\OpenClaw lab.VMX\n/another-private-directory/OpenClaw lab.vmx\n";
        let bytes = normalize(Query::VMware, input.as_bytes(), &Fixture, &budget).unwrap();
        let mut snapshot = empty("endpoint", 1, 100);
        vm::inventory(&mut snapshot, vm::Hypervisor::VMware, "local", &bytes).unwrap();
        assert_eq!(snapshot.entities.len(), 2);
        assert_ne!(
            snapshot.entities[0].id, snapshot.entities[1].id,
            "labels cannot merge registrations"
        );
        assert!(
            snapshot
                .entities
                .iter()
                .all(|entity| entity.display.as_ref().unwrap().name.as_deref()
                    == Some("OpenClaw lab"))
        );
        let output = serde_json::to_string(&snapshot).unwrap();
        assert!(!output.contains("PRIVATE_DIRECTORY"));
        assert!(!output.contains("another-private-directory"));
        assert!(
            Engine::compile(&catalog)
                .unwrap()
                .evaluate(&snapshot)
                .unwrap()
                .identifications
                .is_empty()
        );
    }

    #[test]
    fn unsafe_or_missing_inventory_labels_keep_the_uuid_fallback() {
        let stop = AtomicBool::new(false);
        let budget = Budget::new(Duration::from_secs(2), &stop);
        let vm = "11111111-1111-4111-8111-111111111111";
        for label in [
            "".to_owned(),
            "x".repeat(161),
            "é".repeat(81),
            "label\tvalue".to_owned(),
            "label\u{1b}value".to_owned(),
        ] {
            let input = format!("Name: {label}\nUUID: {vm}\nState: running\n");
            let bytes = normalize(Query::VirtualBox, input.as_bytes(), &Fixture, &budget).unwrap();
            let rows: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert!(rows[0]["display_name"].is_null());
            let mut snapshot = empty("endpoint", 1, 100);
            vm::inventory(&mut snapshot, vm::Hypervisor::VirtualBox, "local", &bytes).unwrap();
            assert_eq!(
                snapshot.entities[0]
                    .display
                    .as_ref()
                    .unwrap()
                    .name
                    .as_deref(),
                Some(format!("virtualbox · {vm}").as_str())
            );
        }
        for path in [
            "/private/.vmx",
            "/private/not-a-vmx",
            "/private/control\tlabel.vmx",
        ] {
            assert!(vmware_label(path).is_none());
        }
    }

    #[test]
    fn malformed_virtualbox_and_libvirt_identifiers_are_rejected() {
        let stop = AtomicBool::new(false);
        let budget = Budget::new(Duration::from_secs(5), &stop);
        for query in [Query::VirtualBox, Query::Libvirt] {
            assert!(
                normalize(query, b"UUID: ../../unexpected; command", &Fixture, &budget).is_err()
            );
        }
    }
}
