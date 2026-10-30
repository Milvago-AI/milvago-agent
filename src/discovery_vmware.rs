//! Bounded, local VMware Tools metadata projection. No guest command is run.
use milvago_discovery_collector as collector;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub vm_id: String,
    pub vmx_file: String,
    pub credential_file: String,
}

impl Request {
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if self.vmx_file.is_empty()
            || self.vmx_file.len() > 4096
            || self.credential_file.is_empty()
            || self.credential_file.len() > 4096
            || self.vmx_file.chars().any(char::is_control)
            || self.credential_file.chars().any(char::is_control)
            || self.vm_id != collector::identity("vmx", &[&self.vmx_file])
            || !self.vmx_file.to_ascii_lowercase().ends_with(".vmx")
            || !self.credential_file.ends_with(".json")
        {
            return Err("invalid_vmware_connection");
        }
        Ok(())
    }
}

#[cfg(windows)]
#[derive(Serialize)]
struct Projection {
    boot: String,
    processes: Vec<Process>,
    complete: bool,
}
#[cfg(windows)]
#[derive(Serialize)]
struct Process {
    pid: u64,
    start_time: String,
    executable: String,
    argument_tokens: Vec<String>,
}

// ListProcesses returns a human-readable command, not an argv array. Recognize
// only an unambiguous interpreter prefix; never infer shell quoting or retain
// business arguments. Ambiguous/missing entries keep coverage partial.
#[cfg(any(windows, test))]
fn entry(executable: &str, command: &str) -> Option<Vec<String>> {
    let interpreter = collector::host::is_interpreter(executable);
    if !interpreter {
        return Some(vec![]);
    }
    if command.len() > 8192
        || command.contains(['\'', '"', '\\'])
        || command.chars().any(char::is_control)
    {
        return None;
    }
    let mut words = command.split_whitespace();
    if words
        .next()
        .map(collector::host::executable_name)
        .as_deref()
        != Some(executable)
    {
        return None;
    }
    let args = zeroize::Zeroizing::new(words.take(2).map(str::to_owned).collect::<Vec<_>>());
    if args.is_empty() {
        return None;
    }
    // A -c/-e program is intentionally opaque, rather than an absent module.
    if args[0].starts_with('-') && args[0] != "-m" {
        return None;
    }
    let tokens = collector::host::entry_tokens(executable, &args);
    (!tokens.is_empty()).then_some(tokens)
}

// VIX_ERROR_CODE is the low 16 bits; tools and permission failures do not
// establish that the supplied guest credential was rejected.
#[cfg(any(windows, test))]
fn vix_error(error: u64) -> &'static str {
    match error & 0xffff {
        3024 => "guest_authentication_denied",
        3006 => "vmware_guest_not_running",
        3016 => "unavailable",
        _ => "vmware_query_failed",
    }
}
#[test]
fn vix_transient_and_permission_errors_are_not_authentication_refusals() {
    assert_eq!(vix_error(3024), "guest_authentication_denied");
    assert_eq!(
        vix_error((7u64 << 32) | 3024),
        "guest_authentication_denied"
    );
    for error in [1, 3006, 3014, 3015, 3016, 3017, 4000] {
        assert_ne!(vix_error(error), "guest_authentication_denied");
    }
}

#[cfg(windows)]
pub fn probe() -> crate::Result<()> {
    use std::io::Write;
    let input = std::env::var("MILVAGO_GUEST_INPUT").map_err(|_| "missing_vmware_request")?;
    if input.len() > 16384 {
        return Err("vmware_request_limit".into());
    }
    let request: Request = serde_json::from_str(&input).map_err(|_| "invalid_vmware_request")?;
    request.validate()?;
    let output = match native::query(&request) {
        Ok(output) => output,
        Err("guest_authentication_denied") => std::process::exit(77),
        Err(error) => return Err(error.into()),
    };
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(&output)?);
    if bytes.len() > collector::MAX_RESPONSE {
        return Err("vmware_response_limit".into());
    }
    std::io::stdout().write_all(&bytes)?;
    Ok(())
}

#[cfg(windows)]
mod native {
    use super::*;
    use std::{
        ffi::{c_char, c_void},
        io::Read,
        path::{Path, PathBuf},
        time::{Duration, Instant},
    };
    use zeroize::{Zeroize, Zeroizing};
    type Error = u64;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LoadLibraryExW(path: *const u16, file: *mut c_void, flags: u32) -> *mut c_void;
        fn FreeLibrary(module: *mut c_void) -> i32;
        fn GetProcAddress(module: *mut c_void, name: *const c_char) -> *mut c_void;
        fn AddDllDirectory(path: *const u16) -> *mut c_void;
        fn RemoveDllDirectory(cookie: *mut c_void) -> i32;
        fn GetDriveTypeW(root: *const u16) -> u32;
        fn CreateJobObjectW(attributes: *mut c_void, name: *const u16) -> *mut c_void;
        fn SetInformationJobObject(
            job: *mut c_void,
            class: i32,
            info: *const c_void,
            size: u32,
        ) -> i32;
        fn AssignProcessToJobObject(job: *mut c_void, process: *mut c_void) -> i32;
        fn GetCurrentProcess() -> *mut c_void;
    }
    fn wide(value: &std::ffi::OsStr) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        value.encode_wide().chain(Some(0)).collect()
    }
    fn fixed_local(path: &str) -> Result<PathBuf, &'static str> {
        let bytes = path.as_bytes();
        if bytes.len() < 4
            || !bytes[0].is_ascii_alphabetic()
            || bytes[1] != b':'
            || !matches!(bytes[2], b'/' | b'\\')
            || path[2..].contains(':')
            || path.starts_with("\\\\")
            || path.chars().any(char::is_control)
            || Path::new(path)
                .components()
                .any(|p| matches!(p, std::path::Component::ParentDir))
        {
            return Err("local_vmware_path_required");
        }
        let root = std::ffi::OsString::from(format!("{}:\\", bytes[0] as char));
        if unsafe { GetDriveTypeW(wide(&root).as_ptr()) } != 3 {
            return Err("local_vmware_path_required");
        }
        Ok(PathBuf::from(path))
    }
    fn trusted_parents(path: &Path) -> Result<Vec<crate::cache_windows::Directory>, &'static str> {
        let mut leases = vec![];
        for directory in path
            .ancestors()
            .take_while(|directory| directory.parent().is_some())
        {
            if leases.len() >= 32 {
                return Err("untrusted_vmware_path");
            }
            leases.push(
                crate::cache_windows::Directory::installed(directory)
                    .map_err(|_| "untrusted_vmware_path")?,
            );
        }
        if leases.is_empty() {
            return Err("untrusted_vmware_path");
        }
        Ok(leases)
    }
    #[repr(C)]
    #[derive(Default)]
    struct BasicLimits {
        process_time: i64,
        job_time: i64,
        flags: u32,
        min_working: usize,
        max_working: usize,
        active: u32,
        affinity: usize,
        priority: u32,
        scheduling: u32,
    }
    #[repr(C)]
    #[derive(Default)]
    struct Limits {
        basic: BasicLimits,
        io: [u64; 6],
        process_memory: usize,
        job_memory: usize,
        peak_process: usize,
        peak_job: usize,
    }
    const _: [(); 144] = [(); std::mem::size_of::<Limits>()];
    struct Job(*mut c_void);
    impl Job {
        fn constrain() -> Result<Self, &'static str> {
            let job = Self(unsafe { CreateJobObjectW(std::ptr::null_mut(), std::ptr::null()) });
            if job.0.is_null() {
                return Err("vmware_job_unavailable");
            }
            let limits = Limits {
                basic: BasicLimits {
                    process_time: 30_000_000,
                    flags: 0x2 | 0x8 | 0x100,
                    active: 1,
                    ..Default::default()
                },
                process_memory: 96 * 1024 * 1024,
                ..Default::default()
            };
            if unsafe {
                SetInformationJobObject(
                    job.0,
                    9,
                    (&limits as *const Limits).cast(),
                    std::mem::size_of::<Limits>() as u32,
                )
            } == 0
                || unsafe { AssignProcessToJobObject(job.0, GetCurrentProcess()) } == 0
            {
                return Err("vmware_job_unavailable");
            }
            Ok(job)
        }
    }
    impl Drop for Job {
        fn drop(&mut self) {
            unsafe {
                windows_sys::Win32::Foundation::CloseHandle(self.0);
            }
        }
    }
    #[cfg(test)]
    mod job_tests {
        use super::*;
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn QueryInformationJobObject(
                job: *mut c_void,
                class: i32,
                info: *mut c_void,
                size: u32,
                returned: *mut u32,
            ) -> i32;
        }
        #[test]
        #[ignore = "requires an isolated Windows administrator filesystem"]
        fn protected_leaf_cannot_hide_a_user_writable_ancestor() {
            let windows = PathBuf::from(std::env::var_os("SystemRoot").unwrap());
            let tool = windows.join("System32/icacls.exe");
            let public = PathBuf::from("C:/Users/Public");
            assert!(public.is_dir());
            let name = format!("MilvagoGuestGuard-{}", uuid::Uuid::new_v4());
            let leaf = public.join(&name);
            std::fs::create_dir(&leaf).unwrap();
            for arguments in [
                vec![
                    "/inheritance:r",
                    "/grant:r",
                    "*S-1-5-18:(OI)(CI)F",
                    "*S-1-5-32-544:(OI)(CI)F",
                ],
                vec!["/setowner", "*S-1-5-32-544"],
            ] {
                let status = std::process::Command::new(&tool)
                    .arg(&leaf)
                    .args(arguments)
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .unwrap();
                assert!(status.success());
            }
            let guard = crate::cache_windows::Directory::installed(&leaf)
                .expect("the leaf alone is administrator-controlled");
            assert!(
                trusted_parents(&leaf).is_err(),
                "a mutable ancestor cannot redirect a privileged SDK lookup"
            );
            drop(guard);
            assert_eq!(leaf.parent(), Some(public.as_path()));
            std::fs::remove_dir(&leaf).unwrap();
            let installed = PathBuf::from(std::env::var_os("ProgramFiles").unwrap()).join(&name);
            std::fs::create_dir(&installed).unwrap();
            let guards = trusted_parents(&installed)
                .expect("protected installed directories remain supported");
            drop(guards);
            std::fs::remove_dir(&installed).unwrap();
        }
        #[test]
        #[ignore = "one-shot child; started only by the native job parent test"]
        fn isolated_job_child() {
            assert_eq!(
                std::env::var("MILVAGO_QA_VIX_JOB_CHILD").as_deref(),
                Ok("1")
            );
            let job = Job::constrain().unwrap();
            if std::env::var("MILVAGO_QA_VIX_JOB_MODE").as_deref() == Ok("cpu") {
                loop {
                    std::hint::black_box(1u64.wrapping_mul(3));
                }
            }
            let mut actual = Limits::default();
            assert_ne!(
                unsafe {
                    QueryInformationJobObject(
                        job.0,
                        9,
                        (&mut actual as *mut Limits).cast(),
                        std::mem::size_of::<Limits>() as u32,
                        std::ptr::null_mut(),
                    )
                },
                0
            );
            assert_eq!(actual.basic.active, 1);
            assert_eq!(actual.basic.process_time, 30_000_000);
            assert_eq!(actual.process_memory, 96 * 1024 * 1024);
            assert_eq!(actual.basic.flags & (0x2 | 0x8 | 0x100), 0x2 | 0x8 | 0x100);
            let command = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap())
                .join("System32/cmd.exe");
            assert!(
                std::process::Command::new(command)
                    .args(["/d", "/c", "exit", "0"])
                    .spawn()
                    .is_err(),
                "SDK helper cannot create another process"
            );
            let mut allocation = Vec::<u8>::new();
            assert!(
                allocation.try_reserve_exact(128 * 1024 * 1024).is_err(),
                "helper memory ceiling must be enforced by Windows"
            );
        }
        #[test]
        fn native_vmware_job_enforces_memory_cpu_and_child_process_limits() {
            for mode in ["probe", "cpu"] {
                let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "discovery_vmware::native::job_tests::isolated_job_child",
                        "--ignored",
                        "--test-threads=1",
                    ])
                    .env_clear()
                    .env("SystemRoot", std::env::var_os("SystemRoot").unwrap())
                    .env("MILVAGO_QA_VIX_JOB_CHILD", "1")
                    .env("MILVAGO_QA_VIX_JOB_MODE", mode)
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .unwrap();
                let started = Instant::now();
                let deadline = started + Duration::from_secs(10);
                loop {
                    if let Some(status) = child.try_wait().unwrap() {
                        if mode == "cpu" {
                            assert!(
                                !status.success(),
                                "CPU exhaustion must terminate the helper"
                            );
                            assert!(
                                started.elapsed() >= Duration::from_secs(2),
                                "a loader failure is not CPU-limit enforcement"
                            );
                        } else {
                            assert!(status.success(), "isolated job enforcement check failed");
                        }
                        break;
                    }
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        panic!("isolated job enforcement check exceeded its deadline");
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
    }
    struct DirectoryCookie(*mut c_void);
    impl Drop for DirectoryCookie {
        fn drop(&mut self) {
            unsafe {
                RemoveDllDirectory(self.0);
            }
        }
    }
    struct Library {
        module: *mut c_void,
        _leases: Vec<crate::cache_windows::Directory>,
        _file: std::fs::File,
        _cookies: Vec<DirectoryCookie>,
    }
    impl Drop for Library {
        fn drop(&mut self) {
            unsafe {
                FreeLibrary(self.module);
            }
        }
    }
    impl Library {
        fn open() -> Result<Self, &'static str> {
            let mut candidates = vec![];
            for variable in ["ProgramFiles", "ProgramFiles(x86)"] {
                if let Some(root) = std::env::var_os(variable) {
                    candidates.push(PathBuf::from(root).join("VMware/VMware Workstation"));
                }
            }
            for root in candidates {
                let Ok(root) = fixed_local(&root.to_string_lossy()) else {
                    continue;
                };
                let Ok(ancestors) = trusted_parents(&root) else {
                    continue;
                };
                let Ok(directory) = crate::cache_windows::Directory::installed(&root) else {
                    continue;
                };
                let Ok(file) = directory.hold_file(std::ffi::OsStr::new("vix.dll")) else {
                    continue;
                };
                let mut leases = ancestors;
                leases.push(directory);
                let mut cookies = vec![];
                for path in [root.clone(), root.join("x64")] {
                    let directory = crate::cache_windows::Directory::installed(&path)
                        .map_err(|_| "untrusted_vmware_sdk")?;
                    let cookie = unsafe { AddDllDirectory(wide(path.as_os_str()).as_ptr()) };
                    if cookie.is_null() {
                        return Err("vmware_sdk_unavailable");
                    }
                    leases.push(directory);
                    cookies.push(DirectoryCookie(cookie));
                }
                // Only the held vendor directories and System32 participate.
                let module = unsafe {
                    LoadLibraryExW(
                        wide(root.join("vix.dll").as_os_str()).as_ptr(),
                        std::ptr::null_mut(),
                        0x0d00,
                    )
                };
                if module.is_null() {
                    return Err("vmware_sdk_unavailable");
                }
                return Ok(Self {
                    module,
                    _leases: leases,
                    _file: file,
                    _cookies: cookies,
                });
            }
            Err("vmware_sdk_unavailable")
        }
    }
    type Connect = unsafe extern "C" fn(
        i32,
        i32,
        *const c_char,
        i32,
        *const c_char,
        *const c_char,
        i32,
        i32,
        *mut c_void,
        *mut c_void,
    ) -> i32;
    type Open = unsafe extern "C" fn(i32, *const c_char, i32, i32, *mut c_void, *mut c_void) -> i32;
    type Login = unsafe extern "C" fn(
        i32,
        *const c_char,
        *const c_char,
        i32,
        *mut c_void,
        *mut c_void,
    ) -> i32;
    type List = unsafe extern "C" fn(i32, i32, *mut c_void, *mut c_void) -> i32;
    type Check = unsafe extern "C" fn(i32, *mut i8) -> Error;
    type JobError = unsafe extern "C" fn(i32) -> Error;
    type Count = unsafe extern "C" fn(i32, i32) -> i32;
    type Properties = unsafe extern "C" fn(i32, i32, ...) -> Error;
    type Nth = unsafe extern "C" fn(i32, i32, i32, ...) -> Error;
    type Release = unsafe extern "C" fn(i32);
    type Free = unsafe extern "C" fn(*mut c_void);
    struct Api<'a> {
        _library: &'a Library,
        connect: Connect,
        open: Open,
        login: Login,
        list: List,
        check: Check,
        error: JobError,
        count: Count,
        get: Properties,
        nth: Nth,
        release: Release,
        disconnect: Release,
        free: Free,
    }
    impl<'a> Api<'a> {
        fn load(library: &'a Library) -> Result<Self, &'static str> {
            macro_rules! symbol {
                ($name:literal,$kind:ty) => {{
                    let pointer = unsafe {
                        GetProcAddress(library.module, concat!($name, "\0").as_ptr().cast())
                    };
                    if pointer.is_null() {
                        return Err("vmware_sdk_unavailable");
                    }
                    unsafe { std::mem::transmute::<*mut c_void, $kind>(pointer) }
                }};
            }
            Ok(Self {
                _library: library,
                connect: symbol!("VixHost_Connect", Connect),
                open: symbol!("VixHost_OpenVM", Open),
                login: symbol!("VixVM_LoginInGuest", Login),
                list: symbol!("VixVM_ListProcessesInGuest", List),
                check: symbol!("VixJob_CheckCompletion", Check),
                error: symbol!("VixJob_GetError", JobError),
                count: symbol!("VixJob_GetNumProperties", Count),
                get: symbol!("Vix_GetProperties", Properties),
                nth: symbol!("VixJob_GetNthProperties", Nth),
                release: symbol!("Vix_ReleaseHandle", Release),
                disconnect: symbol!("VixHost_Disconnect", Release),
                free: symbol!("Vix_FreeBuffer", Free),
            })
        }
        fn handle(&self, raw: i32, host: bool) -> Result<Handle<'_>, &'static str> {
            if raw == 0 {
                Err("invalid_vmware_handle")
            } else {
                Ok(Handle {
                    api: self,
                    raw,
                    host,
                })
            }
        }
        fn wait(&self, job: &Handle<'_>, deadline: Instant) -> Result<(), &'static str> {
            loop {
                if Instant::now() >= deadline {
                    return Err("timeout");
                }
                let mut done = 0i8;
                if unsafe { (self.check)(job.raw, &mut done) } != 0 {
                    return Err("vmware_query_failed");
                }
                if done != 0 {
                    break;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            let error = unsafe { (self.error)(job.raw) };
            if error != 0 {
                return Err(vix_error(error));
            }
            Ok(())
        }
        fn result(
            &self,
            raw: i32,
            host: bool,
            deadline: Instant,
        ) -> Result<Handle<'_>, &'static str> {
            let job = self.handle(raw, false)?;
            self.wait(&job, deadline)?;
            let mut handle = 0i32;
            if unsafe { (self.get)(job.raw, 3010, &mut handle as *mut i32, 0i32) } != 0 {
                return Err("vmware_query_failed");
            }
            self.handle(handle, host)
        }
    }
    struct Handle<'a> {
        api: &'a Api<'a>,
        raw: i32,
        host: bool,
    }
    impl Drop for Handle<'_> {
        fn drop(&mut self) {
            unsafe {
                if self.host {
                    (self.api.disconnect)(self.raw)
                } else {
                    (self.api.release)(self.raw)
                }
            }
        }
    }
    struct Buffer<'a> {
        api: &'a Api<'a>,
        pointer: *mut c_char,
        length: usize,
    }
    impl<'a> Buffer<'a> {
        fn read(&mut self, limit: usize) -> Result<Zeroizing<Vec<u8>>, &'static str> {
            if self.pointer.is_null() {
                return Ok(Zeroizing::new(vec![]));
            }
            // SDK strings are NUL-terminated by contract. Guest-controlled sizes
            // are bounded here, and all SDK allocations are also job-limited.
            for index in 0..=limit {
                if unsafe { *self.pointer.add(index) } == 0 {
                    self.length = index;
                    return Ok(Zeroizing::new(
                        unsafe { std::slice::from_raw_parts(self.pointer.cast::<u8>(), index) }
                            .to_vec(),
                    ));
                }
                self.length = index + 1;
            }
            Err("vmware_string_limit")
        }
    }
    impl Drop for Buffer<'_> {
        fn drop(&mut self) {
            if !self.pointer.is_null() {
                unsafe { std::slice::from_raw_parts_mut(self.pointer.cast::<u8>(), self.length) }
                    .zeroize();
                unsafe { (self.api.free)(self.pointer.cast()) }
            }
        }
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Credentials {
        username: String,
        password: String,
    }
    impl Drop for Credentials {
        fn drop(&mut self) {
            self.username.zeroize();
            self.password.zeroize();
        }
    }
    fn cstring(value: &str) -> Result<Zeroizing<Vec<u8>>, &'static str> {
        if value.is_empty() || value.len() > 4096 || value.as_bytes().contains(&0) {
            return Err("invalid_vmware_credential");
        }
        let mut value = Zeroizing::new(value.as_bytes().to_vec());
        value.push(0);
        Ok(value)
    }
    pub(super) fn query(request: &Request) -> Result<Projection, &'static str> {
        let _job = Job::constrain()?;
        let vmx = fixed_local(&request.vmx_file)?;
        // Opening a user-writable VMX with a privileged vendor SDK could follow
        // attacker-controlled paths. Until an owner-token broker is available,
        // accept only administrator-controlled registrations, held against
        // replacement throughout this read. User-owned guests remain unknown.
        let vmx_directories =
            trusted_parents(vmx.parent().ok_or("untrusted_vmware_registration")?)?;
        let _vmx_file = vmx_directories[0]
            .hold_file(vmx.file_name().ok_or("untrusted_vmware_registration")?)
            .map_err(|_| "untrusted_vmware_registration")?;
        let credential = fixed_local(&request.credential_file)?;
        let directory = crate::cache_windows::Directory::open(
            credential.parent().ok_or("credential_unavailable")?,
            true,
        )
        .map_err(|_| "credential_unavailable")?;
        let file = directory
            .hold_file(credential.file_name().ok_or("credential_unavailable")?)
            .map_err(|_| "credential_unavailable")?;
        if file.metadata().map_err(|_| "credential_unavailable")?.len() > 16384 {
            return Err("credential_limit");
        }
        let mut bytes = Zeroizing::new(vec![]);
        (&file)
            .take(16385)
            .read_to_end(&mut bytes)
            .map_err(|_| "credential_unavailable")?;
        if bytes.len() > 16384 {
            return Err("credential_limit");
        }
        let credentials: Credentials =
            serde_json::from_slice(&bytes).map_err(|_| "invalid_vmware_credential")?;
        if credentials.username.len() > 256 || credentials.username.chars().any(char::is_control) {
            return Err("invalid_vmware_credential");
        }
        let username = cstring(&credentials.username)?;
        let password = cstring(&credentials.password)?;
        let path = cstring(&vmx.to_string_lossy())?;
        let library = Library::open()?;
        let api = Api::load(&library)?;
        let deadline = Instant::now() + Duration::from_secs(3);
        let null = std::ptr::null_mut();
        let host = api.result(
            unsafe {
                (api.connect)(
                    -1,
                    3,
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    std::ptr::null(),
                    0,
                    0,
                    null,
                    null,
                )
            },
            true,
            deadline,
        )?;
        let vm = api.result(
            unsafe { (api.open)(host.raw, path.as_ptr().cast(), 0, 0, null, null) },
            false,
            deadline,
        )?;
        let mut power = 0i32;
        if unsafe { (api.get)(vm.raw, 129, &mut power as *mut i32, 0i32) } != 0 || power & 8 == 0 {
            return Err("vmware_guest_not_running");
        }
        let mut returned = Buffer {
            api: &api,
            pointer: std::ptr::null_mut(),
            length: 0,
        };
        if unsafe { (api.get)(vm.raw, 103, &mut returned.pointer as *mut *mut c_char, 0i32) } != 0 {
            // Failed SDK getters do not establish ownership of their out-pointers.
            returned.pointer = std::ptr::null_mut();
            return Err("unverified_vmware_guest");
        }
        let returned = returned.read(4096)?;
        let returned = std::str::from_utf8(&returned).map_err(|_| "unverified_vmware_guest")?;
        if returned.replace('/', "\\").to_ascii_lowercase()
            != request.vmx_file.replace('/', "\\").to_ascii_lowercase()
        {
            return Err("unverified_vmware_guest");
        }
        let login = api.handle(
            unsafe {
                (api.login)(
                    vm.raw,
                    username.as_ptr().cast(),
                    password.as_ptr().cast(),
                    0,
                    null,
                    null,
                )
            },
            false,
        )?;
        api.wait(&login, deadline)?;
        let job = api.handle(unsafe { (api.list)(vm.raw, 0, null, null) }, false)?;
        api.wait(&job, deadline)?;
        let count = unsafe { (api.count)(job.raw, 3051) };
        if !(0..=4096).contains(&count) {
            return Err("process_limit");
        }
        let mut processes = vec![];
        let mut seen = std::collections::BTreeSet::new();
        let mut boot = None;
        let mut complete = true;
        for index in 0..count {
            if Instant::now() >= deadline {
                return Err("timeout");
            }
            let mut name = Buffer {
                api: &api,
                pointer: std::ptr::null_mut(),
                length: 0,
            };
            let mut command = Buffer {
                api: &api,
                pointer: std::ptr::null_mut(),
                length: 0,
            };
            let mut pid = 0u64;
            let mut start = 0u64;
            if unsafe {
                (api.nth)(
                    job.raw,
                    index,
                    3035,
                    &mut name.pointer as *mut *mut c_char,
                    3051i32,
                    &mut pid as *mut u64,
                    3055i32,
                    &mut start as *mut u64,
                    3053i32,
                    &mut command.pointer as *mut *mut c_char,
                    0i32,
                )
            } != 0
            {
                name.pointer = std::ptr::null_mut();
                command.pointer = std::ptr::null_mut();
                return Err("invalid_guest_response");
            }
            if pid == 0 || start == 0 {
                complete = false;
                continue;
            }
            if !seen.insert(pid) {
                return Err("invalid_guest_response");
            }
            if pid == 1 {
                boot = Some(start);
            }
            let name = name.read(1024)?;
            let name = std::str::from_utf8(&name).map_err(|_| "invalid_guest_response")?;
            let executable = collector::host::executable_name(name);
            if executable.is_empty() || executable.chars().any(char::is_control) {
                return Err("invalid_guest_response");
            }
            let command = command.read(8192)?;
            let tokens = std::str::from_utf8(&command)
                .ok()
                .and_then(|command| entry(&executable, command));
            if tokens.is_none() {
                complete = false;
            }
            processes.push(Process {
                pid,
                start_time: start.to_string(),
                executable,
                argument_tokens: tokens.unwrap_or_default(),
            });
        }
        let boot = boot.ok_or("linux_guest_boot_identity_required")?;
        Ok(Projection {
            boot: format!("vmware-init/{boot}"),
            processes,
            complete,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn vmware_requests_are_bound_to_the_inventory_path_and_have_closed_fields() {
        let path = "C:/fixture/guest.vmx";
        let request = Request {
            vm_id: collector::identity("vmx", &[path]),
            vmx_file: path.into(),
            credential_file: "C:/private/guest.json".into(),
        };
        assert!(request.validate().is_ok());
        let mut value = serde_json::to_value(&request).unwrap();
        value["password"] = "data:image/png".into();
        assert!(serde_json::from_value::<Request>(value).is_err());
        for path in ["other.vmx", "C:/fixture/guest.vmx\n", "data:image/png"] {
            let mut value = serde_json::to_value(&request).unwrap();
            value["vmx_file"] = path.into();
            assert!(
                serde_json::from_value::<Request>(value)
                    .unwrap()
                    .validate()
                    .is_err()
            );
        }
    }
    #[test]
    fn vmware_human_commands_never_infer_quoted_or_opaque_interpreter_entries() {
        assert_eq!(
            entry("python3", "/usr/bin/python3 -m hermes_cli.main PRIVATE").unwrap(),
            vec!["hermes_cli.main"]
        );
        assert_eq!(
            entry("openclaw", "anything PRIVATE").unwrap(),
            Vec::<String>::new()
        );
        for line in [
            "",
            "python3 -c PRIVATE",
            "python3 -m 'hermes_cli.main'",
            "node /app/openclaw",
            "python3 -m hermes_cli.main\nPRIVATE",
        ] {
            assert!(entry("python3", line).is_none());
        }
    }
}
