//! Fixed system queries and separately authorized guest metadata commands.
//! Catalogue data never selects programs or arguments.
use milvago_discovery_collector::{
    Budget, MAX_RESPONSE,
    system::{Query, Reader},
};
use std::{
    io::Read,
    path::PathBuf,
    process::{Command, Stdio},
    time::Duration,
};

pub struct NativeReader;

#[cfg(windows)]
struct Lease {
    _directory: crate::cache_windows::Directory,
    _file: std::fs::File,
    _credential: Option<(crate::cache_windows::Directory, std::fs::File)>,
}
#[cfg(not(windows))]
struct Lease;

fn program(names: &[&str]) -> Result<(PathBuf, Lease), &'static str> {
    #[cfg(windows)]
    {
        let windows = PathBuf::from(std::env::var_os("SystemRoot").ok_or("unavailable")?);
        let files = std::env::var_os("ProgramFiles").map(PathBuf::from);
        let files32 = std::env::var_os("ProgramFiles(x86)").map(PathBuf::from);
        let mut candidates = vec![];
        for name in names {
            match *name {
                "powershell" => {
                    candidates.push(windows.join("System32/WindowsPowerShell/v1.0/powershell.exe"))
                }
                "vbox" => {
                    if let Some(root) = &files {
                        candidates.push(root.join("Oracle/VirtualBox/VBoxManage.exe"));
                    }
                }
                "vmrun" => {
                    for root in [&files, &files32].into_iter().flatten() {
                        candidates.push(root.join("VMware/VMware Workstation/vmrun.exe"));
                    }
                }
                "self" => {
                    if let Ok(path) = std::env::current_exe() {
                        candidates.push(path);
                    }
                }
                _ => (),
            }
        }
        for path in candidates {
            let Some(parent) = path.parent() else {
                continue;
            };
            let Ok(directory) = crate::cache_windows::Directory::installed(parent) else {
                continue;
            };
            let Some(name) = path.file_name() else {
                continue;
            };
            if let Ok(file) = directory.hold_file(name) {
                return Ok((
                    path,
                    Lease {
                        _directory: directory,
                        _file: file,
                        _credential: None,
                    },
                ));
            }
        }
        Err("unavailable")
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        for name in names {
            let candidates = match *name {
                "vbox" => vec!["/usr/bin/VBoxManage", "/usr/local/bin/VBoxManage"],
                "vmrun" => vec!["/usr/bin/vmrun", "/usr/local/bin/vmrun"],
                "virsh" => vec!["/usr/bin/virsh", "/usr/local/bin/virsh"],
                _ => vec![],
            };
            for candidate in candidates {
                let Ok(path) = std::fs::canonicalize(candidate) else {
                    continue;
                };
                let trusted = path.ancestors().all(|p| {
                    std::fs::symlink_metadata(p).is_ok_and(|m| {
                        m.uid() == 0 && m.mode() & 0o022 == 0 && !m.file_type().is_symlink()
                    })
                });
                if trusted && path.is_file() {
                    return Ok((path, Lease));
                }
            }
        }
        Err("unavailable")
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = names;
        Err("unavailable")
    }
}

fn query(query: Query) -> Result<(Command, Lease), &'static str> {
    #[cfg(windows)]
    let mut guest_input: Option<String> = None;
    #[cfg(windows)]
    let mut credential_guard = None;
    let (name, args): (&str, Vec<String>) = match query {
        Query::VirtualBox => ("vbox", vec!["list".into(), "--long".into(), "vms".into()]),
        Query::VMware => ("vmrun", vec!["list".into()]),
        Query::Libvirt => (
            "virsh",
            vec![
                "--connect".into(),
                "qemu:///system".into(),
                "--readonly".into(),
                "list".into(),
                "--all".into(),
                "--uuid".into(),
            ],
        ),
        Query::LibvirtState(id) => {
            if id.len() != 36 || uuid::Uuid::parse_str(&id).is_err() {
                return Err("invalid_vm_identity");
            }
            (
                "virsh",
                vec![
                    "--connect".into(),
                    "qemu:///system".into(),
                    "--readonly".into(),
                    "domstate".into(),
                    id,
                ],
            )
        }
        Query::LibvirtInterfaces(id) => {
            if id.len() != 36 || uuid::Uuid::parse_str(&id).is_err() {
                return Err("invalid_vm_identity");
            }
            (
                "virsh",
                vec![
                    "--connect".into(),
                    "qemu:///system".into(),
                    "--readonly".into(),
                    "domiflist".into(),
                    id,
                ],
            )
        }
        Query::LibvirtAddresses(id) => {
            if id.len() != 36 || uuid::Uuid::parse_str(&id).is_err() {
                return Err("invalid_vm_identity");
            }
            (
                "virsh",
                vec![
                    "--connect".into(),
                    "qemu:///system".into(),
                    "--readonly".into(),
                    "domifaddr".into(),
                    id,
                    "--full".into(),
                    "--source".into(),
                    "lease".into(),
                ],
            )
        }
        Query::LibvirtInterfaceLink { vm_id, interface } => {
            if vm_id.len() != 36
                || uuid::Uuid::parse_str(&vm_id).is_err()
                || interface.is_empty()
                || interface.len() > 15
                || !interface
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
                || matches!(interface.as_str(), "." | "..")
            {
                return Err("invalid_vm_interface");
            }
            (
                "virsh",
                vec![
                    "--connect".into(),
                    "qemu:///system".into(),
                    "--readonly".into(),
                    "domif-getlink".into(),
                    vm_id,
                    interface,
                ],
            )
        }
        Query::LibvirtGuestStart(id) => {
            if id.len() != 36 || uuid::Uuid::parse_str(&id).is_err() {
                return Err("invalid_vm_identity");
            }
            let call=serde_json::json!({"execute":"guest-exec","arguments":{"path":"/usr/bin/python3","arg":["-I","-S","-c",include_str!("discovery_guest_linux.py")],"capture-output":true}}).to_string();
            (
                "virsh",
                vec![
                    "--connect".into(),
                    "qemu:///system".into(),
                    "qemu-agent-command".into(),
                    id,
                    call,
                    "--timeout".into(),
                    "5".into(),
                ],
            )
        }
        Query::LibvirtGuestStatus { vm_id, pid } => {
            if vm_id.len() != 36 || uuid::Uuid::parse_str(&vm_id).is_err() || pid == 0 {
                return Err("invalid_vm_identity");
            }
            let call = serde_json::json!({"execute":"guest-exec-status","arguments":{"pid":pid}})
                .to_string();
            (
                "virsh",
                vec![
                    "--connect".into(),
                    "qemu:///system".into(),
                    "qemu-agent-command".into(),
                    vm_id,
                    call,
                    "--timeout".into(),
                    "5".into(),
                ],
            )
        }
        #[cfg(windows)]
        Query::HyperV => ("powershell", powershell(HYPER_V)),
        #[cfg(windows)]
        Query::Wsl => ("powershell", powershell(WSL)),
        #[cfg(windows)]
        Query::WslUserInventory => {
            guest_input = Some(
                serde_json::to_string(&crate::discovery_wsl::Request::Inventory {})
                    .map_err(|_| "invalid_wsl_request")?,
            );
            ("self", vec!["discovery-wsl-probe".into()])
        }
        #[cfg(windows)]
        Query::WslGuest {
            owner_sid,
            distribution_id,
        } => {
            let request = crate::discovery_wsl::Request::Processes {
                owner_sid,
                distribution_id,
            };
            request.validate()?;
            guest_input = Some(serde_json::to_string(&request).map_err(|_| "invalid_wsl_request")?);
            ("self", vec!["discovery-wsl-probe".into()])
        }
        #[cfg(windows)]
        Query::WindowsProcessEntries => ("powershell", powershell(PROCESSES)),
        #[cfg(windows)]
        Query::HyperVGuest {
            vm_id,
            credential_file,
        } => {
            if vm_id.len() != 36 || uuid::Uuid::parse_str(&vm_id).is_err() {
                return Err("invalid_vm_identity");
            }
            let path = PathBuf::from(&credential_file);
            let parent = path.parent().ok_or("credential_unavailable")?;
            let name = path.file_name().ok_or("credential_unavailable")?;
            if !path.is_absolute() || path.extension().and_then(|v| v.to_str()) != Some("xml") {
                return Err("credential_unavailable");
            }
            let directory = crate::cache_windows::Directory::open(parent, true)
                .map_err(|_| "credential_unavailable")?;
            let file = directory
                .hold_file(name)
                .map_err(|_| "credential_unavailable")?;
            if file.metadata().map_err(|_| "credential_unavailable")?.len() > 65536 {
                return Err("credential_unavailable");
            }
            credential_guard = Some((directory, file));
            guest_input = Some(
                serde_json::json!({"vm_id":vm_id,"credential_file":credential_file}).to_string(),
            );
            ("powershell", powershell(HYPER_V_GUEST))
        }
        #[cfg(windows)]
        Query::VirtualBoxGuest {
            vm_id,
            username,
            credential_file,
        } => {
            let args = virtualbox_guest_arguments(&vm_id, &username, &credential_file)?;
            let path = PathBuf::from(&credential_file);
            let directory = crate::cache_windows::Directory::open(
                path.parent().ok_or("credential_unavailable")?,
                true,
            )
            .map_err(|_| "credential_unavailable")?;
            let file = directory
                .hold_file(path.file_name().ok_or("credential_unavailable")?)
                .map_err(|_| "credential_unavailable")?;
            let size = file.metadata().map_err(|_| "credential_unavailable")?.len();
            if size == 0 || size > 4096 {
                return Err("credential_unavailable");
            }
            credential_guard = Some((directory, file));
            ("vbox", args)
        }
        #[cfg(windows)]
        Query::VMwareGuest {
            vm_id,
            vmx_file,
            credential_file,
        } => {
            let request = crate::discovery_vmware::Request {
                vm_id,
                vmx_file,
                credential_file,
            };
            request.validate()?;
            guest_input =
                Some(serde_json::to_string(&request).map_err(|_| "invalid_vmware_request")?);
            ("self", vec!["discovery-vmware-probe".into()])
        }
        #[cfg(not(windows))]
        _ => return Err("unavailable"),
    };
    let (path, lease) = program(&[name])?;
    #[cfg(windows)]
    let mut lease = lease;
    let mut command = Command::new(&path);
    command
        .args(args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    if let Some(input) = guest_input {
        command.env("MILVAGO_GUEST_INPUT", input);
    }
    #[cfg(windows)]
    {
        lease._credential = credential_guard;
    }
    if let Some(parent) = path.parent() {
        command.current_dir(parent);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let windows = std::env::var_os("SystemRoot").ok_or("unavailable")?;
        command
            .env("SystemRoot", &windows)
            .env("PATH", PathBuf::from(&windows).join("System32"))
            .env(
                "PSModulePath",
                PathBuf::from(windows).join("System32/WindowsPowerShell/v1.0/Modules"),
            )
            .creation_flags(0x08000000);
        // The isolated VMware helper discovers only protected installed SDKs.
        for name in ["ProgramFiles", "ProgramFiles(x86)"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
    }
    Ok((command, lease))
}

#[cfg(any(windows, test))]
fn virtualbox_guest_arguments(
    vm: &str,
    user: &str,
    credential: &str,
) -> Result<Vec<String>, &'static str> {
    let path = PathBuf::from(credential);
    if vm.len() != 36
        || uuid::Uuid::parse_str(vm).is_err()
        || vm != vm.to_ascii_lowercase()
        || !crate::discovery_guests::guest_username(user)
        || !path.is_absolute()
        || path.extension().and_then(|v| v.to_str()) != Some("password")
        || credential.len() > 4096
        || credential.chars().any(char::is_control)
    {
        return Err("invalid_guest_connection");
    }
    Ok(vec![
        "guestcontrol".into(),
        vm.into(),
        "run".into(),
        "--quiet".into(),
        "--exe=/usr/bin/python3".into(),
        "--arg0=python3".into(),
        format!("--username={user}"),
        format!("--passwordfile={credential}"),
        "--timeout=5000".into(),
        "--wait-stdout".into(),
        "--no-wait-stderr".into(),
        "--".into(),
        "-I".into(),
        "-S".into(),
        "-c".into(),
        include_str!("discovery_guest_linux.py").into(),
    ])
}

#[cfg(test)]
mod guest_command_tests {
    use super::*;
    #[test]
    fn only_explicit_guest_authentication_errors_use_the_sticky_failure_protocol() {
        assert_eq!(
            guest_exit_error(true, false, Some(77), b""),
            "guest_authentication_denied"
        );
        assert_eq!(
            guest_exit_error(
                false,
                true,
                Some(1),
                b"VBox: VERR_AUTHENTICATION_FAILURE (-89)"
            ),
            "guest_authentication_denied"
        );
        for code in [None, Some(1), Some(18), Some(124)] {
            assert_eq!(guest_exit_error(true, false, code, b""), "query_failed");
        }
        for bytes in [
            b"tools not ready".as_slice(),
            b"VERR_ACCESS_DENIED",
            b"NOT_VERR_AUTHENTICATION_FAILURE",
            b"VERR_AUTHENTICATION_FAILURE_OTHER",
        ] {
            assert_eq!(
                guest_exit_error(false, true, Some(1), bytes),
                "query_failed"
            );
        }
        assert_eq!(
            guest_exit_error(false, false, Some(77), b"VERR_AUTHENTICATION_FAILURE"),
            "query_failed"
        );
    }
    #[test]
    fn virtualbox_guest_command_is_fixed_and_uses_a_password_file() {
        let vm = "11111111-1111-4111-8111-111111111111";
        let path = if cfg!(windows) {
            "C:/private/guest.password"
        } else {
            "/private/guest.password"
        };
        let args = virtualbox_guest_arguments(vm, "vm-reader", path).unwrap();
        assert_eq!(&args[..3], &["guestcontrol", vm, "run"]);
        assert!(args.contains(&format!("--passwordfile={path}")));
        assert!(!args.iter().any(|a| a.starts_with("--password=")));
        assert_eq!(
            args.last().unwrap(),
            include_str!("discovery_guest_linux.py")
        );
        let separator = args.iter().position(|a| a == "--").unwrap();
        assert_eq!(&args[separator + 1..separator + 4], &["-I", "-S", "-c"]);
        assert!(args.contains(&"--arg0=python3".to_string()));
        for user in [
            "",
            "--password=secret",
            "reader\nother",
            "data:image/png",
            "reader guest",
        ] {
            assert!(virtualbox_guest_arguments(vm, user, path).is_err());
        }
        for bad in [
            "../guest.password",
            "guest.password",
            "data:image/png",
            "/private/guest.xml",
            "\0.password",
        ] {
            assert!(virtualbox_guest_arguments(vm, "reader", bad).is_err());
        }
        assert!(virtualbox_guest_arguments("../../other", "reader", path).is_err());
    }
}

#[cfg(windows)]
fn powershell(script: &str) -> Vec<String> {
    vec![
        "-NoLogo".into(),
        "-NoProfile".into(),
        "-NonInteractive".into(),
        "-Command".into(),
        format!(
            "$ErrorActionPreference='Stop';[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false);{script}"
        ),
    ]
}

#[cfg(windows)]
const HYPER_V: &str = r#"$rows=@(Get-CimInstance -Namespace root/virtualization/v2 -ClassName Msvm_ComputerSystem | Where-Object {$_.Name -match '^[a-fA-F0-9-]{36}$'} | Select-Object -First 101 | ForEach-Object {@{uuid=$_.Name;display_name=$_.ElementName;running=($_.EnabledState -eq 2);tools_available=$false}});ConvertTo-Json -InputObject $rows -Compress"#;
#[cfg(windows)]
const WSL: &str = r#"$rows=@(Get-ChildItem Registry::HKEY_USERS | ForEach-Object {$sid=$_.PSChildName;$path=('Registry::HKEY_USERS\'+$sid+'\Software\Microsoft\Windows\CurrentVersion\Lxss');if(Test-Path -LiteralPath $path){Get-ChildItem -LiteralPath $path | Select-Object -First 101 | ForEach-Object {@{uuid=($sid+'/'+$_.PSChildName.Trim('{}').ToLowerInvariant());display_name=(Get-ItemProperty -LiteralPath $_.PSPath).DistributionName;running=$false;tools_available=$false}}}});ConvertTo-Json -InputObject $rows -Compress"#;
#[cfg(windows)]
const PROCESSES: &str = r#"$rows=@(Get-CimInstance Win32_Process -Filter "Name='node.exe' OR Name='nodejs.exe' OR Name LIKE 'python%.exe'" | Select-Object -First 1025 | ForEach-Object {@{pid=$_.ProcessId;start_time=([DateTime]$_.CreationDate).ToFileTimeUtc();executable=$_.ExecutablePath;command_line=$_.CommandLine}});ConvertTo-Json -InputObject $rows -Compress"#;
#[cfg(windows)]
const HYPER_V_GUEST: &str = r#"try{$ErrorActionPreference='Stop';$request=$env:MILVAGO_GUEST_INPUT|ConvertFrom-Json;$credential=Import-Clixml -LiteralPath $request.credential_file;if($credential -isnot [System.Management.Automation.PSCredential]){throw 'credential_unavailable'};$result=Invoke-Command -VMId ([Guid]$request.vm_id) -Credential $credential -ScriptBlock {$ErrorActionPreference='Stop';$boot=([DateTime](Get-CimInstance Win32_OperatingSystem).LastBootUpTime).ToFileTimeUtc().ToString();$rows=@(Get-CimInstance Win32_Process | Select-Object -First 4097 | ForEach-Object {$entry=$null;if($_.Name -match '^(node|nodejs|python[^.]*)\.exe$'){$entry=$_.CommandLine};@{pid=$_.ProcessId;start_time=([DateTime]$_.CreationDate).ToFileTimeUtc().ToString();executable=$_.Name;command_line=$entry}});ConvertTo-Json -InputObject @{boot=$boot;processes=$rows} -Depth 5 -Compress};[Console]::Write($result)}catch{$e=$_.Exception;for($i=0;$null -ne $e -and $i -lt 8;$i++){if($e.HResult -eq -2147023570){exit 77};$e=$e.InnerException};exit 1}"#;

#[cfg(windows)]
fn available(stdout: &impl std::os::windows::io::AsRawHandle) -> Result<usize, &'static str> {
    let mut bytes = 0;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn PeekNamedPipe(
            pipe: isize,
            buffer: *mut u8,
            size: u32,
            read: *mut u32,
            available: *mut u32,
            left: *mut u32,
        ) -> i32;
    }
    if unsafe {
        PeekNamedPipe(
            stdout.as_raw_handle() as isize,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            &mut bytes,
            std::ptr::null_mut(),
        )
    } == 0
    {
        let error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        return if matches!(error, 109 | 232) {
            Ok(0)
        } else {
            Err("query_stdout")
        };
    };
    Ok(bytes as usize)
}
#[cfg(not(windows))]
fn available(_: &impl Read) -> Result<usize, &'static str> {
    Ok(8192)
}

// Exit 77 is reserved by our fixed helpers for a confirmed logon refusal.
// VBox has a generic failure exit, so use only its explicit IPRT error token.
fn guest_exit_error(
    structured: bool,
    vbox: bool,
    code: Option<i32>,
    diagnostic: &[u8],
) -> &'static str {
    let token = b"VERR_AUTHENTICATION_FAILURE";
    let vbox_auth = vbox
        && diagnostic
            .split(|byte| !(byte.is_ascii_alphanumeric() || *byte == b'_'))
            .any(|part| part == token);
    if (structured && code == Some(77)) || vbox_auth {
        "guest_authentication_denied"
    } else {
        "query_failed"
    }
}

#[cfg(windows)]
fn guest_diagnostic(
    stderr: &mut std::process::ChildStderr,
    bytes: &mut Vec<u8>,
) -> Result<(), &'static str> {
    let mut buffer = [0u8; 1024];
    loop {
        let count = available(stderr)?.min(buffer.len());
        if count == 0 {
            return Ok(());
        }
        let read = stderr
            .read(&mut buffer[..count])
            .map_err(|_| "query_stdout")?;
        if read == 0 {
            return Ok(());
        }
        if bytes.len() + read > 16384 {
            buffer.fill(0);
            return Err("response_limit");
        }
        bytes.extend_from_slice(&buffer[..read]);
        buffer.fill(0);
    }
}

impl Reader for NativeReader {
    fn read(&self, operation: Query, budget: &Budget<'_>) -> Result<Vec<u8>, &'static str> {
        budget.check()?;
        #[cfg(windows)]
        if let Some(result) = crate::discovery_wsl::system_query(&operation, budget) {
            return result;
        }
        #[cfg(windows)]
        let wsl_live = if matches!(&operation, Query::Wsl) {
            self.read(Query::WslUserInventory, budget).ok()
        } else {
            None
        };
        let vbox = matches!(&operation, Query::VirtualBoxGuest { .. });
        let structured = matches!(
            &operation,
            Query::HyperVGuest { .. } | Query::VMwareGuest { .. }
        );
        let (mut command, _lease) = query(operation)?;
        #[cfg(windows)]
        if vbox {
            command.stderr(Stdio::piped());
        }
        let mut child = command.spawn().map_err(|_| "access_denied")?;
        #[cfg(windows)]
        let mut stderr = child.stderr.take();
        #[cfg_attr(not(windows), allow(unused_mut))]
        let mut diagnostic = zeroize::Zeroizing::new(Vec::<u8>::new());
        let Some(mut stdout) = child.stdout.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return Err("query_stdout");
        };
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = stdout.as_raw_fd();
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
            {
                let _ = child.kill();
                let _ = child.wait();
                return Err("query_stdout");
            }
        }
        let mut bytes = vec![];
        let mut buffer = [0u8; 8192];
        let mut exited = false;
        let result = loop {
            if let Err(error) = budget.check() {
                break Err(error);
            }
            #[cfg(windows)]
            if let Some(stderr) = stderr.as_mut() {
                if let Err(error) = guest_diagnostic(stderr, &mut diagnostic) {
                    break Err(error);
                }
            }
            let count = match available(&stdout) {
                Ok(n) => n.min(buffer.len()),
                Err(error) => break Err(error),
            };
            if count > 0 {
                match stdout.read(&mut buffer[..count]) {
                    Ok(0) => (),
                    Ok(n) => {
                        if bytes.len() + n > MAX_RESPONSE {
                            break Err("response_limit");
                        };
                        bytes.extend_from_slice(&buffer[..n]);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
                    Err(_) => break Err("query_stdout"),
                }
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    exited = true;
                    #[cfg(windows)]
                    if let Some(stderr) = stderr.as_mut() {
                        if let Err(error) = guest_diagnostic(stderr, &mut diagnostic) {
                            break Err(error);
                        }
                    }
                    // Drain only already available bytes; an inherited pipe must not hold the worker open.
                    let mut overflow = false;
                    loop {
                        let count = match available(&stdout) {
                            Ok(n) => n.min(buffer.len()),
                            Err(_) => 0,
                        };
                        if count == 0 {
                            break;
                        };
                        match stdout.read(&mut buffer[..count]) {
                            Ok(0) => break,
                            Ok(n) => {
                                if bytes.len() + n > MAX_RESPONSE {
                                    overflow = true;
                                    break;
                                };
                                bytes.extend_from_slice(&buffer[..n]);
                            }
                            Err(_) => break,
                        }
                    }
                    break if overflow {
                        Err("response_limit")
                    } else if status.success() {
                        Ok(bytes)
                    } else {
                        Err(guest_exit_error(
                            structured,
                            vbox,
                            status.code(),
                            &diagnostic,
                        ))
                    };
                }
                Ok(None) => (),
                Err(_) => break Err("query_failed"),
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        if result.is_err() && !exited {
            #[cfg(unix)]
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            let _ = child.kill();
        }
        let _ = child.wait();
        #[cfg(windows)]
        if let (Ok(registered), Some(live)) = (&result, wsl_live) {
            // A denied owner's probe does not erase registrations of other users.
            return crate::discovery_wsl::merge_inventory(registered, &live);
        }
        result
    }
}
