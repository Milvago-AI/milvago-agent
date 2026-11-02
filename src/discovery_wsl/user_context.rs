//! SYSTEM selects a kernel-owned session token; the WSL client itself stays unprivileged.
use super::{Identity, Request, native::token_identity};
use milvago_discovery_collector::{Budget, MAX_RESPONSE, system::Query};
use std::{
    collections::BTreeMap,
    ffi::c_void,
    os::windows::io::AsRawHandle,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{GetTokenInformation, SECURITY_ATTRIBUTES, TokenElevation, TokenLinkedToken},
    System::{JobObjects::*, RemoteDesktop::*, Threading::*},
};
type Result<T> = std::result::Result<T, &'static str>;
#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreatePipe(
        read: *mut HANDLE,
        write: *mut HANDLE,
        attributes: *const SECURITY_ATTRIBUTES,
        size: u32,
    ) -> i32;
    fn PeekNamedPipe(
        pipe: isize,
        buffer: *mut u8,
        size: u32,
        read: *mut u32,
        available: *mut u32,
        left: *mut u32,
    ) -> i32;
    fn ReadFile(
        file: isize,
        buffer: *mut u8,
        size: u32,
        read: *mut u32,
        overlapped: *mut c_void,
    ) -> i32;
}
struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn probe_stage(stage: &'static str) -> &'static str {
    if cfg!(feature = "windows-qualification") {
        stage
    } else {
        "user_probe_unavailable"
    }
}

fn elevated(token: &Handle) -> Result<bool> {
    let mut value = 0u32;
    let mut length = 0;
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            (&mut value as *mut u32).cast(),
            4,
            &mut length,
        )
    } == 0
        || length != 4
    {
        return Err("access_denied");
    }
    Ok(value != 0)
}

fn limited_token(token: Handle) -> Result<Handle> {
    let owner = token_identity(token.0)?;
    if !elevated(&token)? {
        super::validate_owner_token(&owner, &owner, false)?;
        return Ok(token);
    }
    // WTS may return the administrator's full token. Only the linked token
    // created by UAC is eligible; never construct or relax a token ourselves.
    let mut linked = std::ptr::null_mut();
    let mut length = 0;
    let status = unsafe {
        GetTokenInformation(
            token.0,
            TokenLinkedToken,
            (&mut linked as *mut HANDLE).cast(),
            std::mem::size_of::<HANDLE>() as u32,
            &mut length,
        )
    };
    let linked = Handle(linked);
    if status == 0 || length as usize != std::mem::size_of::<HANDLE>() || linked.0.is_null() {
        return Err("access_denied");
    }
    super::validate_owner_token(&owner, &token_identity(linked.0)?, elevated(&linked)?)?;
    Ok(linked)
}

fn session_tokens() -> Result<Vec<(String, Handle)>> {
    let mut rows = std::ptr::null_mut();
    let mut count = 0;
    if unsafe { WTSEnumerateSessionsW(std::ptr::null_mut(), 0, 1, &mut rows, &mut count) } == 0 {
        return Err("access_denied");
    }
    struct Rows(*mut WTS_SESSION_INFOW);
    impl Drop for Rows {
        fn drop(&mut self) {
            unsafe {
                WTSFreeMemory(self.0.cast());
            }
        }
    }
    let rows = Rows(rows);
    if count > 128 || count > 0 && rows.0.is_null() {
        return Err("wsl_session_limit");
    }
    let mut result = vec![];
    let mut seen = std::collections::BTreeSet::new();
    for index in 0..count as usize {
        let row = unsafe { &*rows.0.add(index) };
        if row.SessionId == 0 || ![WTSActive, WTSConnected, WTSDisconnected].contains(&row.State) {
            continue;
        }
        let mut token = std::ptr::null_mut();
        if unsafe { WTSQueryUserToken(row.SessionId, &mut token) } == 0 {
            continue;
        }
        let Ok(token) = limited_token(Handle(token)) else {
            continue;
        };
        let Ok(sid) = token_identity(token.0) else {
            continue;
        };
        if Identity::parse(&format!("{sid}/11111111-1111-4111-8111-111111111111")).is_err() {
            continue;
        }
        if seen.insert(sid.clone()) {
            result.push((sid, token));
        }
    }
    result.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(result)
}

struct Attributes {
    memory: Vec<usize>,
    initialized: bool,
}
impl Attributes {
    fn new(handles: &mut [HANDLE]) -> Result<Self> {
        let mut bytes = 0;
        unsafe {
            InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut bytes);
        }
        if bytes == 0 || bytes > 4096 {
            return Err("user_probe_unavailable");
        }
        let mut value = Self {
            memory: vec![0; bytes.div_ceil(std::mem::size_of::<usize>())],
            initialized: false,
        };
        if unsafe {
            InitializeProcThreadAttributeList(value.memory.as_mut_ptr().cast(), 1, 0, &mut bytes)
        } == 0
        {
            return Err("user_probe_unavailable");
        }
        value.initialized = true;
        if unsafe {
            UpdateProcThreadAttribute(
                value.memory.as_mut_ptr().cast(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_mut_ptr().cast(),
                std::mem::size_of_val(handles),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err("user_probe_unavailable");
        }
        Ok(value)
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        if self.initialized {
            unsafe {
                DeleteProcThreadAttributeList(self.memory.as_mut_ptr().cast());
            }
        }
    }
}
struct Process {
    process: Handle,
    thread: Handle,
}
impl Drop for Process {
    fn drop(&mut self) {
        unsafe {
            TerminateProcess(self.process.0, 125);
            WaitForSingleObject(self.process.0, 1000);
        }
    }
}

fn launch(
    token: &Handle,
    expected: &str,
    request: Request,
    budget: &Budget<'_>,
) -> Result<Vec<u8>> {
    launch_with_input(token, expected, request, budget, None)
}

fn launch_with_input(
    token: &Handle,
    expected: &str,
    request: Request,
    budget: &Budget<'_>,
    input: Option<&[u8]>,
) -> Result<Vec<u8>> {
    budget.check()?;
    request.validate()?;
    if token_identity(token.0)? != expected {
        return Err("access_denied");
    }
    let path = std::env::current_exe().map_err(|_| "user_probe_unavailable")?;
    let parent = path.parent().ok_or("user_probe_unavailable")?;
    let directory =
        crate::cache_windows::Directory::installed(parent).map_err(|_| "access_denied")?;
    let _image = directory
        .hold_file(path.file_name().ok_or("user_probe_unavailable")?)
        .map_err(|_| "access_denied")?;
    let application = wide(path.to_str().ok_or("user_probe_unavailable")?);
    let operation = if input.is_some() {
        "discovery-observer-probe"
    } else {
        "discovery-wsl-probe"
    };
    let mut command = wide(&format!(
        "\"{}\" {operation}",
        path.to_str().ok_or("user_probe_unavailable")?
    ));
    let section = input.map(super::input_section::Input::new).transpose()?;
    let mut environment = BTreeMap::new();
    for name in ["SystemRoot", "ProgramFiles", "ProgramFiles(x86)"] {
        if let Some(value) = std::env::var_os(name) {
            environment.insert(
                name.to_string(),
                value.into_string().map_err(|_| "user_probe_unavailable")?,
            );
        }
    }
    let windows = environment
        .get("SystemRoot")
        .ok_or("user_probe_unavailable")?
        .clone();
    environment.insert("PATH".into(), format!("{windows}\\System32"));
    environment.insert("PATHEXT".into(), ".COM;.EXE;.BAT;.CMD".into());
    environment.insert(
        "MILVAGO_GUEST_INPUT".into(),
        serde_json::to_string(&request).map_err(|_| "invalid_wsl_request")?,
    );
    if let Some(section) = &section {
        environment.insert("MILVAGO_OBSERVER_INPUT".into(), section.descriptor());
    }
    let mut block = Vec::new();
    for (key, value) in environment {
        if value.contains('\0') || value.len() > 4096 {
            return Err("user_probe_unavailable");
        }
        block.extend(wide(&format!("{key}={value}")));
    }
    block.push(0);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    let (mut read, mut write) = (std::ptr::null_mut(), std::ptr::null_mut());
    if unsafe { CreatePipe(&mut read, &mut write, &attributes, 8192) } == 0 {
        return Err("user_probe_unavailable");
    }
    let read = Handle(read);
    let write = Handle(write);
    if unsafe { SetHandleInformation(read.0, HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err("user_probe_unavailable");
    }
    let null = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("NUL")
        .map_err(|_| "user_probe_unavailable")?;
    let null_handle = null.as_raw_handle();
    if unsafe { SetHandleInformation(null_handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } == 0 {
        return Err("user_probe_unavailable");
    }
    let mut inherited = vec![write.0, null_handle];
    if let Some(section) = &section {
        inherited.push(section.child);
    }
    let mut attributes =
        Attributes::new(&mut inherited).map_err(|_| probe_stage("qa_probe_attributes"))?;
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = null_handle;
    startup.StartupInfo.hStdError = null_handle;
    startup.StartupInfo.hStdOutput = write.0;
    startup.lpAttributeList = attributes.memory.as_mut_ptr().cast();
    let job = Handle(unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) });
    if job.0.is_null() {
        return Err(probe_stage("qa_probe_job_create"));
    }
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_JOB_MEMORY
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    limits.BasicLimitInformation.ActiveProcessLimit = 8;
    limits.JobMemoryLimit = 128 * 1024 * 1024;
    if unsafe {
        SetInformationJobObject(
            job.0,
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            std::mem::size_of_val(&limits) as u32,
        )
    } == 0
    {
        return Err(probe_stage("qa_probe_job_limits"));
    }
    let mut cpu = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION::default();
    cpu.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
    cpu.Anonymous.CpuRate = 1000;
    if unsafe {
        SetInformationJobObject(
            job.0,
            JobObjectCpuRateControlInformation,
            (&cpu as *const JOBOBJECT_CPU_RATE_CONTROL_INFORMATION).cast(),
            std::mem::size_of_val(&cpu) as u32,
        )
    } == 0
    {
        return Err(probe_stage("qa_probe_job_cpu"));
    }
    let mut process = PROCESS_INFORMATION::default();
    let working = wide(parent.to_str().ok_or("user_probe_unavailable")?);
    let flags = CREATE_SUSPENDED
        | CREATE_NO_WINDOW
        | CREATE_UNICODE_ENVIRONMENT
        | EXTENDED_STARTUPINFO_PRESENT;
    if unsafe {
        CreateProcessAsUserW(
            token.0,
            application.as_ptr(),
            command.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            flags,
            block.as_ptr().cast(),
            working.as_ptr(),
            &startup.StartupInfo,
            &mut process,
        )
    } == 0
    {
        return Err(probe_stage("qa_probe_create_process"));
    }
    let process = Process {
        process: Handle(process.hProcess),
        thread: Handle(process.hThread),
    };
    if unsafe { AssignProcessToJobObject(job.0, process.process.0) } == 0
        || unsafe { ResumeThread(process.thread.0) } == u32::MAX
    {
        return Err(probe_stage("qa_probe_assign_or_resume"));
    }
    drop(write);
    let mut output = vec![];
    let mut buffer = [0u8; 8192];
    loop {
        budget.check()?;
        let mut available = 0;
        let pending = unsafe {
            PeekNamedPipe(
                read.0 as isize,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut available,
                std::ptr::null_mut(),
            )
        };
        if pending == 0 && unsafe { GetLastError() } != ERROR_BROKEN_PIPE {
            return Err("query_stdout");
        }
        if available > 0 {
            let mut received = 0;
            if unsafe {
                ReadFile(
                    read.0 as isize,
                    buffer.as_mut_ptr(),
                    available.min(buffer.len() as u32),
                    &mut received,
                    std::ptr::null_mut(),
                )
            } == 0
            {
                return Err("query_stdout");
            }
            if received == 0 || output.len() + received as usize > MAX_RESPONSE {
                return Err("response_limit");
            }
            output.extend_from_slice(&buffer[..received as usize]);
            continue;
        }
        match unsafe { WaitForSingleObject(process.process.0, 0) } {
            WAIT_OBJECT_0 => {
                let mut code = 1;
                if unsafe { GetExitCodeProcess(process.process.0, &mut code) } == 0 || code != 0 {
                    return Err("guest_query_failed");
                }
                if matches!(request, Request::Inventory {}) {
                    super::validate_inventory_owner(&output, expected)?;
                }
                return Ok(output);
            }
            WAIT_TIMEOUT => std::thread::sleep(Duration::from_millis(10)),
            _ => return Err("user_probe_unavailable"),
        }
    }
}

pub(crate) fn system_query(operation: &Query, budget: &Budget<'_>) -> Option<Result<Vec<u8>>> {
    if !matches!(operation, Query::WslUserInventory | Query::WslGuest { .. }) {
        return None;
    }
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), 8, &mut token) } == 0 {
        return Some(Err("access_denied"));
    }
    let current = Handle(token);
    match token_identity(current.0) {
        Ok(sid) if sid == "S-1-5-18" => {}
        Ok(_) => return None,
        Err(error) => return Some(Err(error)),
    }
    Some((|| {
        let tokens = session_tokens()?;
        match operation {
            Query::WslUserInventory => {
                static NEXT: AtomicUsize = AtomicUsize::new(0);
                if tokens.is_empty() {
                    return Err("unavailable");
                }
                let selected = NEXT.fetch_add(1, Ordering::Relaxed) % tokens.len();
                let (sid, token) = &tokens[selected];
                launch(token, sid, Request::Inventory {}, budget)
            }
            Query::WslGuest {
                owner_sid,
                distribution_id,
            } => {
                Identity::parse(&format!("{owner_sid}/{distribution_id}"))?;
                let (_, token) = tokens
                    .iter()
                    .find(|(sid, _)| sid == owner_sid)
                    .ok_or("access_denied")?;
                launch(
                    token,
                    owner_sid,
                    Request::Processes {
                        owner_sid: owner_sid.clone(),
                        distribution_id: distribution_id.clone(),
                    },
                    budget,
                )
            }
            _ => Err("unavailable"),
        }
    })())
}

pub(super) fn observer_query(
    owner_sid: &str,
    distribution_id: &str,
    input: &[u8],
    budget: &Budget<'_>,
) -> Result<Vec<u8>> {
    budget.check()?;
    Identity::parse(&format!("{owner_sid}/{distribution_id}"))?;
    if input.is_empty() || input.len() > 24 * 1024 {
        return Err("request_limit");
    }
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), 8, &mut token) } == 0 {
        return Err("access_denied");
    }
    let token = Handle(token);
    if token_identity(token.0)? != "S-1-5-18" {
        return Err("access_denied");
    }
    let tokens = session_tokens()?;
    let (_, token) = tokens
        .iter()
        .find(|(sid, _)| sid == owner_sid)
        .ok_or("access_denied")?;
    launch_with_input(
        token,
        owner_sid,
        Request::Processes {
            owner_sid: owner_sid.into(),
            distribution_id: distribution_id.into(),
        },
        budget,
        Some(input),
    )
}
