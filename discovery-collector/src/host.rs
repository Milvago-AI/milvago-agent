use crate::*;
use std::{
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
};

#[derive(Clone, Debug)]
pub struct Listener {
    pub address: SocketAddr,
    pub owner: Option<String>,
}

pub fn executable_name(path: &str) -> String {
    let name = path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    name.strip_suffix(".exe").unwrap_or(&name).to_string()
}

// Only the entry script/module is projected; arbitrary arguments can contain prompts and credentials.
pub fn is_interpreter(name: &str) -> bool {
    matches!(name, "node" | "nodejs" | "python" | "python3")
        || name.strip_prefix("python3.").is_some_and(|minor| {
            (1..=2).contains(&minor.len()) && minor.bytes().all(|byte| byte.is_ascii_digit())
        })
}

pub fn entry_tokens(executable: &str, args: &[String]) -> Vec<String> {
    let name = executable_name(executable);
    if !is_interpreter(&name) {
        return vec![];
    }
    let Some(first) = args.first() else {
        return vec![];
    };
    let entry = if first == "-m" && name.starts_with("python") {
        args.get(1).map(String::as_str)
    } else if !first.starts_with('-') {
        Some(first.as_str())
    } else {
        None
    };
    let Some(entry) = entry else {
        return vec![];
    };
    if entry.len() > 1024 || entry.chars().any(char::is_control) {
        return vec![];
    }
    let components: Vec<_> = entry.split(['/', '\\']).filter(|p| !p.is_empty()).collect();
    let Some(last) = components.last() else {
        return vec![];
    };
    let mut tokens = vec![last.to_ascii_lowercase()];
    // Node package entry points frequently end in a generic filename.
    for pair in components.windows(2) {
        if pair[0] == "node_modules" && matches!(pair[1], "openclaw" | "ollama") {
            tokens.push(pair[1].into());
        }
        if name.starts_with("python") && pair == ["hermes_cli", "main.py"] {
            tokens.push("hermes_cli.main".into());
        }
    }
    tokens.sort();
    tokens.dedup();
    tokens
}

#[cfg(test)]
mod interpreter_tests {
    #[test]
    fn versioned_python_entries_are_recognized_without_accepting_prefix_impostors() {
        for executable in [
            "python",
            "python3",
            "python3.9",
            "python3.10",
            "python3.11",
            "python3.15",
            "C:\\Python\\python3.11.exe",
        ] {
            assert_eq!(
                super::entry_tokens(
                    executable,
                    &["-m".into(), "hermes_cli.main".into(), "PRIVATE".into()]
                ),
                vec!["hermes_cli.main"]
            );
        }
        for executable in [
            "python2",
            "python3.",
            "python3.111",
            "python3.11evil",
            "python3.１",
            "python3.1\n",
        ] {
            assert!(
                super::entry_tokens(executable, &["-m".into(), "hermes_cli.main".into()])
                    .is_empty()
            );
        }
        for (path, expected) in [
            (
                "/opt/agent/hermes_cli/main.py",
                vec!["hermes_cli.main", "main.py"],
            ),
            ("/opt/agent/not_hermes_cli/main.py", vec!["main.py"]),
            ("/opt/agent/hermes_cli/main.py.evil", vec!["main.py.evil"]),
        ] {
            assert_eq!(
                super::entry_tokens("python3.11", &[path.into(), "PRIVATE".into()]),
                expected
            );
        }
        assert_eq!(
            super::entry_tokens("node", &["/opt/hermes_cli/main.py".into()]),
            vec!["main.py"]
        );
    }
}

pub fn read_limited(path: &Path, limit: usize) -> Result<Vec<u8>, &'static str> {
    let file = std::fs::File::open(path).map_err(|_| "read_denied")?;
    let mut output = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut output)
        .map_err(|_| "read_failed")?;
    if output.len() > limit {
        return Err("response_limit");
    }
    Ok(output)
}

pub fn collect(snapshot: &mut Snapshot, budget: &Budget<'_>) -> Vec<Listener> {
    #[cfg(target_os = "linux")]
    {
        linux::collect(snapshot, budget)
    }
    #[cfg(windows)]
    {
        windows::collect(snapshot, budget)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = budget;
        coverage(snapshot, "host", CoverageStatus::Unavailable, false);
        vec![]
    }
}

#[cfg(windows)]
pub(crate) fn current_windows_identity(pid: u32) -> Option<String> {
    windows::current_identity(pid)
}

#[cfg(all(windows, test))]
mod native_windows_tests {
    use super::*;
    #[test]
    fn live_custom_listener_is_bound_to_the_current_process_without_handle_growth() {
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessHandleCount};
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let stop = AtomicBool::new(false);
        let mut baseline = 0;
        for iteration in 0..8 {
            let budget = Budget::new(Duration::from_secs(2), &stop);
            let mut snapshot = crate::empty("native-test", iteration + 1, 100);
            let rows = collect(&mut snapshot, &budget);
            let row = rows
                .iter()
                .find(|row| row.address == address)
                .expect("live ephemeral port must be collected");
            let owner = row
                .owner
                .as_ref()
                .expect("the current process can be corroborated");
            assert!(
                snapshot
                    .entities
                    .iter()
                    .any(|entity| &entity.id == owner && entity.kind == EntityKind::Process)
            );
            assert!(snapshot.relations.iter().any(
                |relation| &relation.to == owner && relation.source == "windows-process-table"
            ));
            let mut handles = 0;
            assert_ne!(
                unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut handles) },
                0
            );
            if iteration == 0 {
                baseline = handles;
            }
            assert!(
                handles <= baseline + 2,
                "per-process and TCP queries must release native handles"
            );
        }
    }
}

pub fn parse_tcp_endpoint(value: &str) -> Option<SocketAddr> {
    let (address, port) = value.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let ip = match address.len() {
        8 => IpAddr::V4(Ipv4Addr::from(
            u32::from_str_radix(address, 16).ok()?.to_le_bytes(),
        )),
        32 => {
            let mut bytes = [0u8; 16];
            for (index, chunk) in bytes.chunks_mut(4).enumerate() {
                chunk.copy_from_slice(
                    &u32::from_str_radix(&address[index * 8..index * 8 + 8], 16)
                        .ok()?
                        .to_le_bytes(),
                );
            }
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// Parse the fixed OWNER_PID listener layouts without creating references to
/// Windows' trailing one-element arrays (the empty table contains only a count).
pub fn windows_tcp_listeners(
    bytes: &[u8],
    ipv6: bool,
) -> Result<Vec<(SocketAddr, u32)>, &'static str> {
    if bytes.len() < 4 || bytes.len() > MAX_RESPONSE {
        return Err("invalid_tcp_table");
    }
    let read = |offset: usize| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
    let count = read(0) as usize;
    let row_size = if ipv6 { 56 } else { 24 };
    if count > 2048 || 4 + count * row_size > bytes.len() {
        return Err("invalid_tcp_table");
    }
    let mut listeners = Vec::with_capacity(count);
    for index in 0..count {
        let offset = 4 + index * row_size;
        let state = read(offset + if ipv6 { 48 } else { 0 });
        if state != 2 {
            return Err("invalid_listener_state");
        }
        let port = offset + if ipv6 { 20 } else { 8 };
        let port = u16::from_be_bytes([bytes[port], bytes[port + 1]]);
        let address = if ipv6 {
            SocketAddr::V6(std::net::SocketAddrV6::new(
                Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[offset..offset + 16]).unwrap()),
                port,
                0,
                read(offset + 16),
            ))
        } else {
            SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(
                    <[u8; 4]>::try_from(&bytes[offset + 4..offset + 8]).unwrap(),
                )),
                port,
            )
        };
        let pid = read(offset + if ipv6 { 52 } else { 20 });
        if port != 0 {
            listeners.push((address, pid));
        }
    }
    Ok(listeners)
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    fn process_start(path: &Path) -> Option<String> {
        let stat = read_limited(&path.join("stat"), 4096).ok()?;
        let stat = std::str::from_utf8(&stat).ok()?;
        let end = stat.rfind(')')?;
        let start = stat[end + 1..].split_whitespace().nth(19)?;
        if start.is_empty() || start.len() > 20 || !start.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        Some(start.into())
    }
    fn same_process(path: &Path, start: &str, executable: &Path) -> bool {
        process_start(path).as_deref() == Some(start)
            && std::fs::read_link(path.join("exe")).is_ok_and(|current| current == executable)
    }
    struct Owner {
        entity: String,
        process: std::path::PathBuf,
        start: String,
        executable: std::path::PathBuf,
        descriptor: std::path::PathBuf,
    }
    impl Owner {
        fn current(&self, inode: &str) -> bool {
            same_process(&self.process, &self.start, &self.executable)
                && std::fs::read_link(&self.descriptor)
                    .is_ok_and(|link| link.to_str() == Some(&format!("socket:[{inode}]")))
        }
    }
    pub fn collect(snapshot: &mut Snapshot, budget: &Budget<'_>) -> Vec<Listener> {
        let boot = match read_limited(Path::new("/proc/sys/kernel/random/boot_id"), 80) {
            Ok(value) => String::from_utf8_lossy(&value).trim().to_string(),
            Err(_) => {
                coverage(snapshot, "host", CoverageStatus::Denied, false);
                return vec![];
            }
        };
        let host_id = identity("host", &[&snapshot.scope]);
        if !snapshot.entities.iter().any(|e| e.id == host_id) {
            snapshot.entities.push(Entity {
                display: None,
                id: host_id.clone(),
                kind: EntityKind::Host,
            });
        }
        let Ok(entries) = std::fs::read_dir("/proc") else {
            coverage(snapshot, "host", CoverageStatus::Denied, false);
            return vec![];
        };
        let mut complete = true;
        let mut field_budget = FieldBudget::new(snapshot);
        let mut processed = 0;
        let mut owners: BTreeMap<String, Option<Owner>> = BTreeMap::new();
        for entry in entries.flatten() {
            if budget.check().is_err() {
                complete = false;
                break;
            }
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
            else {
                continue;
            };
            processed += 1;
            if processed > 10_000 || snapshot.entities.len() >= MAX_ENTITIES - 1 {
                complete = false;
                break;
            }
            let path = entry.path();
            let Some(start) = process_start(&path) else {
                complete = false;
                continue;
            };
            let executable_path = match std::fs::read_link(path.join("exe")) {
                Ok(value) => value,
                Err(_) => {
                    complete = false;
                    continue;
                }
            };
            let executable = executable_name(&executable_path.to_string_lossy());
            let entity = identity("process", &[&boot, &pid.to_string(), &start]);
            let mut fields = BTreeMap::from([(Field::Executable, vec![executable.clone()])]);
            if let Ok(command) = read_limited(&path.join("cmdline"), 8192) {
                let args: Vec<_> = command
                    .split(|b| *b == 0)
                    .skip(1)
                    .take(3)
                    .map(|v| String::from_utf8_lossy(v).to_string())
                    .collect();
                let tokens = entry_tokens(&executable, &args);
                if !tokens.is_empty() {
                    fields.insert(Field::ArgumentToken, tokens);
                }
            }
            if !same_process(&path, &start, &executable_path) {
                complete = false;
                continue;
            }
            snapshot.entities.push(Entity {
                display: None,
                id: entity.clone(),
                kind: EntityKind::Process,
            });
            if !field_budget.insert(snapshot, &entity, Source::HostProcess, fields) {
                complete = false;
                break;
            }
            snapshot.relations.push(Relation {
                from: host_id.clone(),
                to: entity.clone(),
                kind: RelationKind::Contains,
                source: "procfs".into(),
            });
            if let Ok(fds) = std::fs::read_dir(path.join("fd")) {
                for (index, fd) in fds.flatten().enumerate() {
                    if index >= 256 || budget.check().is_err() {
                        complete = false;
                        break;
                    }
                    if let Ok(link) = std::fs::read_link(fd.path()) {
                        if let Some(inode) = link
                            .to_str()
                            .and_then(|s| s.strip_prefix("socket:["))
                            .and_then(|s| s.strip_suffix(']'))
                        {
                            if owners.len() < 16_384 {
                                owners
                                    .entry(inode.into())
                                    .and_modify(|owner| {
                                        if owner.as_ref().map(|p| &p.entity) != Some(&entity) {
                                            *owner = None;
                                        }
                                    })
                                    .or_insert_with(|| {
                                        Some(Owner {
                                            entity: entity.clone(),
                                            process: path.clone(),
                                            start: start.clone(),
                                            executable: executable_path.clone(),
                                            descriptor: fd.path(),
                                        })
                                    });
                            } else {
                                complete = false;
                            }
                        }
                    }
                }
            }
        }
        let mut listeners = vec![];
        for file in ["/proc/net/tcp", "/proc/net/tcp6"] {
            let rows = match read_limited(Path::new(file), MAX_RESPONSE) {
                Ok(v) => v,
                Err(_) => {
                    complete = false;
                    continue;
                }
            };
            for row in String::from_utf8_lossy(&rows).lines().skip(1) {
                if budget.check().is_err() || listeners.len() >= 2048 {
                    complete = false;
                    break;
                }
                let columns: Vec<_> = row.split_whitespace().take(11).collect();
                if columns.len() < 10 || columns[3] != "0A" {
                    continue;
                }
                if let Some(address) = parse_tcp_endpoint(columns[1]) {
                    listeners.push(Listener {
                        address,
                        owner: owners
                            .get(columns[9])
                            .and_then(Option::as_ref)
                            .filter(|owner| owner.current(columns[9]))
                            .map(|owner| owner.entity.clone()),
                    });
                }
            }
        }
        coverage(
            snapshot,
            "host",
            if complete {
                CoverageStatus::Available
            } else {
                CoverageStatus::Partial
            },
            complete,
        );
        listeners
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn process_and_socket_reuse_do_not_keep_an_old_owner() {
            let dir = std::env::temp_dir().join(format!("discovery-proc-{}", std::process::id()));
            std::fs::create_dir(&dir).unwrap();
            std::fs::create_dir(dir.join("fd")).unwrap();
            let stat = |start: u64| {
                format!(
                    "123 (name with ) parentheses) {} {start}",
                    vec!["0"; 19].join(" ")
                )
            };
            std::fs::write(dir.join("stat"), stat(41)).unwrap();
            std::os::unix::fs::symlink("/fixture/openclaw", dir.join("exe")).unwrap();
            std::os::unix::fs::symlink("socket:[73]", dir.join("fd/1")).unwrap();
            let owner = Owner {
                entity: "process/fixture".into(),
                process: dir.clone(),
                start: "41".into(),
                executable: "/fixture/openclaw".into(),
                descriptor: dir.join("fd/1"),
            };
            assert!(owner.current("73"));
            std::fs::write(dir.join("stat"), stat(42)).unwrap();
            assert!(!owner.current("73"));
            std::fs::write(dir.join("stat"), stat(41)).unwrap();
            std::fs::remove_file(dir.join("exe")).unwrap();
            std::os::unix::fs::symlink("/fixture/other", dir.join("exe")).unwrap();
            assert!(!owner.current("73"));
            std::fs::remove_file(dir.join("exe")).unwrap();
            std::os::unix::fs::symlink("/fixture/openclaw", dir.join("exe")).unwrap();
            std::fs::remove_file(dir.join("fd/1")).unwrap();
            std::os::unix::fs::symlink("socket:[74]", dir.join("fd/1")).unwrap();
            assert!(!owner.current("73"));
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use windows_sys::Win32::{
        Foundation::{CloseHandle, FILETIME, INVALID_HANDLE_VALUE},
        NetworkManagement::IpHelper::{GetExtendedTcpTable, TCP_TABLE_OWNER_PID_LISTENER},
        Networking::WinSock::{AF_INET, AF_INET6},
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
                TH32CS_SNAPPROCESS,
            },
            Threading::{
                GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
                QueryFullProcessImageNameW,
            },
        },
    };
    struct Handle(windows_sys::Win32::Foundation::HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    pub(super) fn current_identity(pid: u32) -> Option<String> {
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if process.is_null() {
            return None;
        }
        let process = Handle(process);
        let mut times = [FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        }; 4];
        if unsafe {
            GetProcessTimes(
                process.0,
                &mut times[0],
                &mut times[1],
                &mut times[2],
                &mut times[3],
            )
        } == 0
        {
            return None;
        }
        let start = ((times[0].dwHighDateTime as u64) << 32) | times[0].dwLowDateTime as u64;
        if start == 0 {
            return None;
        }
        Some(identity("process", &[&pid.to_string(), &start.to_string()]))
    }
    pub fn collect(snapshot: &mut Snapshot, budget: &Budget<'_>) -> Vec<Listener> {
        let host = identity("host", &[&snapshot.scope]);
        if !snapshot.entities.iter().any(|e| e.id == host) {
            snapshot.entities.push(Entity {
                display: None,
                id: host.clone(),
                kind: EntityKind::Host,
            });
        }
        let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if raw == INVALID_HANDLE_VALUE {
            coverage(snapshot, "host", CoverageStatus::Denied, false);
            return vec![];
        }
        let handle = Handle(raw);
        let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut present = unsafe { Process32FirstW(handle.0, &mut entry) } != 0;
        let mut complete = true;
        let mut field_budget = FieldBudget::new(snapshot);
        let mut owners = BTreeMap::new();
        while present {
            if budget.check().is_err() || owners.len() >= 10_000 {
                complete = false;
                break;
            }
            let process =
                unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, entry.th32ProcessID) };
            if !process.is_null() {
                let process = Handle(process);
                let mut times = [FILETIME {
                    dwLowDateTime: 0,
                    dwHighDateTime: 0,
                }; 4];
                if unsafe {
                    GetProcessTimes(
                        process.0,
                        &mut times[0],
                        &mut times[1],
                        &mut times[2],
                        &mut times[3],
                    )
                } != 0
                {
                    let start =
                        ((times[0].dwHighDateTime as u64) << 32) | times[0].dwLowDateTime as u64;
                    let id = identity(
                        "process",
                        &[&entry.th32ProcessID.to_string(), &start.to_string()],
                    );
                    let mut image = [0u16; 32768];
                    let mut length = image.len() as u32;
                    // The image and creation time must come from the same live
                    // handle, rather than a possibly stale Toolhelp PID entry.
                    if start == 0
                        || unsafe {
                            QueryFullProcessImageNameW(
                                process.0,
                                0,
                                image.as_mut_ptr(),
                                &mut length,
                            )
                        } == 0
                        || length == 0
                        || length as usize > image.len()
                    {
                        complete = false;
                        present = unsafe { Process32NextW(handle.0, &mut entry) } != 0;
                        continue;
                    }
                    let name =
                        executable_name(&String::from_utf16_lossy(&image[..length as usize]));
                    snapshot.entities.push(Entity {
                        display: None,
                        id: id.clone(),
                        kind: EntityKind::Process,
                    });
                    snapshot.relations.push(Relation {
                        from: host.clone(),
                        to: id.clone(),
                        kind: RelationKind::Contains,
                        source: "windows-process-table".into(),
                    });
                    if !field_budget.insert(
                        snapshot,
                        &id,
                        Source::HostProcess,
                        BTreeMap::from([(Field::Executable, vec![name])]),
                    ) {
                        complete = false;
                        break;
                    }
                    owners.insert(entry.th32ProcessID, id);
                } else {
                    complete = false;
                }
            } else if entry.th32ProcessID != 0 {
                complete = false;
            }
            present = unsafe { Process32NextW(handle.0, &mut entry) } != 0;
        }
        let mut listeners = vec![];
        for (family, ipv6) in [(AF_INET, false), (AF_INET6, true)] {
            if budget.check().is_err() {
                complete = false;
                break;
            }
            let mut length = 0u32;
            let status = unsafe {
                GetExtendedTcpTable(
                    std::ptr::null_mut(),
                    &mut length,
                    0,
                    family as u32,
                    TCP_TABLE_OWNER_PID_LISTENER,
                    0,
                )
            };
            if !matches!(status, 0 | 122) || length < 4 || length > MAX_RESPONSE as u32 {
                complete = false;
                continue;
            }
            let mut memory = vec![0u64; (length as usize).div_ceil(8)];
            if unsafe {
                GetExtendedTcpTable(
                    memory.as_mut_ptr().cast(),
                    &mut length,
                    0,
                    family as u32,
                    TCP_TABLE_OWNER_PID_LISTENER,
                    0,
                )
            } != 0
                || length as usize > memory.len() * 8
            {
                complete = false;
                continue;
            }
            let bytes = unsafe {
                std::slice::from_raw_parts(memory.as_ptr().cast::<u8>(), length as usize)
            };
            match windows_tcp_listeners(bytes, ipv6) {
                Ok(rows) => {
                    for (address, pid) in rows {
                        if budget.check().is_err() {
                            complete = false;
                            break;
                        }
                        let current = current_identity(pid);
                        listeners.push(Listener {
                            address,
                            owner: owners
                                .get(&pid)
                                .filter(|known| current.as_ref() == Some(known))
                                .cloned(),
                        });
                    }
                }
                Err(_) => complete = false,
            }
        }
        coverage(
            snapshot,
            "host",
            if complete {
                CoverageStatus::Available
            } else {
                CoverageStatus::Partial
            },
            complete,
        );
        listeners
    }
}
