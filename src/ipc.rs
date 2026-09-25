//! Local IPC between the browser-launched native-messaging relay shim and the
//! machine agent service.
//!
//! The persistent agent runs as a Windows service (or systemd system service),
//! so it cannot be the browser's native-messaging host (browsers spawn that in
//! the user's session). A tiny relay shim, launched by the browser, forwards the
//! Native-Messaging frames to this IPC endpoint served by the service.
//!
//! Windows: a named pipe with a protected security descriptor (SYSTEM /
//! Administrators / serving service SID full control, Authenticated Users
//! read+write without instance creation) created with FILE_FLAG_FIRST_PIPE_INSTANCE to defeat name
//! squatting. Unix: a datagram-less stream socket under a root-owned directory.
//!
//! The exposed operations are exactly the safe browser subset served by the
//! handler (policy/event/inspect/enforcement/associate/status); the machine
//! identity is never supplied by the client. If the shim cannot reach the
//! service it answers `{"ok":false,"error":"agent_unavailable"}` so the
//! extension fails closed.

use crate::{Result, frame, write_frame};
use serde_json::{Value, json};
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const MAX_CONNECTIONS: usize = 32;
/// Concurrent connections a single local caller may hold. The global cap alone let
/// one unprivileged process take every slot and starve the browser decision path,
/// which fails closed — a machine-wide AI outage available to any local user.
const MAX_CONNECTIONS_PER_CALLER: usize = 8;
/// Identity recorded when the caller cannot be determined. Undetermined callers
/// share one budget rather than escaping the cap.
const UNKNOWN_CALLER: &str = "unknown";

/// Requests a caller may make per second, sustained, and in one burst. Every request
/// decrypts the state under its exclusive lock: unbounded, one local user could hold
/// that lock and fail every other browser closed. A browser needs a few per prompt.
const REQUESTS_PER_SECOND: f64 = 20.0;
const REQUEST_BURST: f64 = 60.0;

/// Concurrent-connection and request-rate accounting per local caller identity.
#[derive(Default)]
struct Callers(
    std::sync::Mutex<std::collections::HashMap<String, usize>>,
    std::sync::Mutex<std::collections::HashMap<String, (f64, std::time::Instant)>>,
);

impl Callers {
    /// Token bucket, per caller rather than per connection: reconnecting or opening
    /// more connections buys no extra budget.
    fn allow(&self, caller: &str) -> bool {
        let mut rates = self.1.lock().unwrap_or_else(|e| e.into_inner());
        let now = std::time::Instant::now();
        if rates.len() >= 1024 && !rates.contains_key(caller) {
            rates.retain(|_, (_, at)| now.duration_since(*at).as_secs_f64() * REQUESTS_PER_SECOND < REQUEST_BURST);
        }
        let (tokens, at) = rates.entry(caller.to_string()).or_insert((REQUEST_BURST, now));
        *tokens = (*tokens + now.duration_since(*at).as_secs_f64() * REQUESTS_PER_SECOND).min(REQUEST_BURST);
        *at = now;
        if *tokens < 1.0 {
            return false;
        }
        *tokens -= 1.0;
        true
    }
    fn admit(&self, caller: &str) -> bool {
        let mut held = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let slot = held.entry(caller.to_string()).or_insert(0);
        if *slot >= MAX_CONNECTIONS_PER_CALLER {
            return false;
        }
        *slot += 1;
        true
    }
    fn release(&self, caller: &str) {
        let mut held = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(slot) = held.get_mut(caller) {
            *slot = slot.saturating_sub(1);
            if *slot == 0 {
                held.remove(caller);
            }
        }
    }
}

struct ConnectionSlot {callers:Arc<Callers>,caller:String,active:Arc<AtomicUsize>}
impl Drop for ConnectionSlot {
    fn drop(&mut self){self.callers.release(&self.caller);self.active.fetch_sub(1,Ordering::AcqRel);}
}

/// Who may reach a channel, and how strictly its peer is checked.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Reachable by any signed-in user's browser relay shim. The served operations
    /// are the safe browser subset and the identity is always the service's own.
    /// The client verifies service ownership; undetermined ownership fails closed.
    Browser,
    /// Reachable only by service accounts, where both ends are machine services and
    /// the operating system's access control *is* the authentication. A failure to
    /// determine the peer therefore refuses instead of trusting.
    Service,
    #[cfg(windows)]
    CacheBrowser,
    #[cfg(windows)]
    UpdateAgent,
}

fn frame_budget(access:Access)->usize {
    #[cfg(windows)]
    match access {Access::UpdateAgent=>return 2*1024*1024,Access::CacheBrowser=>return 1024*1024,_=>{}}
    let _=access;128*1024
}
/// Handler invoked for each request frame received from a relayed client.
pub type Handler = dyn Fn(&Path, Value) -> Result<Value> + Send + Sync + 'static;

fn dispatch(handler: &Handler, home: &Path, request: Value) -> Value {
    // Every relayed request passes through here, so it is the one place a refusal can
    // be recorded without scattering log calls through the handlers. A saturated queue
    // is reported by default because real events are being held back; the rest —
    // malformed frames, a policy not yet delivered — is routine and stays at debug.
    handler(home, request).unwrap_or_else(|error| {
        let reason = crate::watch::cause(&*error);
        let level = if reason.contains("queue is saturated") {
            crate::log::Level::Warn
        } else {
            crate::log::Level::Debug
        };
        crate::log::write(level, &format!("browser request refused: {reason}"));
        json!({"ok":false,"error":"operation_refused"})
    })
}

/// Serve the IPC endpoint until `stop` is set. Blocks.
pub fn serve(
    home: &Path,
    channel: &str,
    access: Access,
    stop: Arc<AtomicBool>,
    handler: Arc<Handler>,
) -> Result<()> {
    #[cfg(windows)]
    {
        windows::serve(home, channel, access, stop, handler)
    }
    #[cfg(unix)]
    {
        unix::serve(home, channel, access, stop, handler)
    }
}

/// One request/answer exchange with a channel served elsewhere.
pub fn exchange(channel: &str, access: Access, request: &Value) -> Result<Value> {
    let mut conn = connect(channel, access)?;
    write_frame(&mut conn, request)?;
    crate::frame_limit(&mut conn,frame_budget(access))?.ok_or_else(|| "no answer".into())
}

/// Bounded health exchange; peer authentication and ACLs are unchanged.
pub fn exchange_timeout(channel: &str, access: Access, request: &Value, timeout: std::time::Duration) -> Result<Value> {
    let deadline = std::time::Instant::now() + timeout;
    #[cfg(windows)]
    let mut conn = windows::connect(channel, access)?;
    #[cfg(unix)]
    let mut conn = unix::connect(channel, access)?;
    conn.deadline = conn.deadline.min(deadline);
    write_frame(&mut conn, request)?;
    crate::frame_limit(&mut conn,frame_budget(access))?.ok_or_else(|| "no health answer".into())
}

/// SYSTEM verifies the exact main service SID before trusting a liveness probe.
#[cfg(windows)]
pub fn exchange_agent(channel: &str, edition: &str, request: &Value, timeout: std::time::Duration) -> Result<Value> {
    windows::exchange_agent(channel, edition, request, timeout)
}

/// Relay Native-Messaging frames from stdin/stdout to the service IPC endpoint.
/// Fails closed (answers `agent_unavailable`) when the service is unreachable.
pub fn relay(channel: &str) -> Result<()> {
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    while let Some(request) = frame(&mut input)? {
        let answer = round_trip(channel, &request)
            .unwrap_or_else(|| json!({"ok":false,"error":"agent_unavailable"}));
        write_frame(&mut output, &answer)?;
    }
    Ok(())
}

fn round_trip(channel: &str, request: &Value) -> Option<Value> {
    let mut conn = connect(channel, Access::Browser).ok()?;
    write_frame(&mut conn, request).ok()?;
    frame(&mut conn).ok().flatten()
}

fn connect(channel: &str, access: Access) -> Result<Box<dyn ReadWrite>> {
    #[cfg(windows)]
    {
        Ok(Box::new(windows::connect(channel, access)?))
    }
    #[cfg(unix)]
    {
        Ok(Box::new(unix::connect(channel, access)?))
    }
}

/// One absolute budget for the whole connection, including partial frames. Every
/// underlying stream is nonblocking, so neither a slow reader nor a slow writer
/// can indefinitely retain its caller's admission slot.
struct DeadlineStream<S> {
    inner: S,
    deadline: std::time::Instant,
    stop: Arc<AtomicBool>,
}
impl<S> DeadlineStream<S> {
    fn new(inner: S, access: Access, stop: Arc<AtomicBool>) -> Self {
        let seconds = if matches!(access, Access::Service) { 120 } else { 10 };
        Self { inner, deadline: std::time::Instant::now() + std::time::Duration::from_secs(seconds), stop }
    }
    fn check(&self) -> io::Result<()> {
        if self.stop.load(Ordering::Acquire) {
            return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "IPC service stopped"));
        }
        if std::time::Instant::now() >= self.deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "IPC connection deadline exceeded"));
        }
        Ok(())
    }
}
impl<S: Read> Read for DeadlineStream<S> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            self.check()?;
            match self.inner.read(buffer) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::thread::sleep(std::time::Duration::from_millis(5)),
                value => return value,
            }
        }
    }
}
impl<S: Write> Write for DeadlineStream<S> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        loop {
            self.check()?;
            match self.inner.write(buffer) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::thread::sleep(std::time::Duration::from_millis(5)),
                value => return value,
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> { self.check()?; self.inner.flush() }
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

/// Serve one connection, reading at most `limit` bytes per frame. `account` is the OS
/// user behind it as the operating system reports it (the pipe client's token, the
/// socket peer's uid). It is written into every request under `caller`, replacing
/// whatever the client put there, so a handler attributing records reads the system's
/// word and never the browser's. Undetermined stays an empty string: the key is always
/// ours.
fn handle_limit<S:Read+Write>(mut stream:S,home:&Path,handler:&Handler,account:Option<String>,limit:usize){
    let caller = json!({"user": account.unwrap_or_default()});
    while let Ok(Some(mut request)) = crate::frame_limit(&mut stream,limit) {
        if let Some(object) = request.as_object_mut() {
            object.insert("caller".into(), caller.clone());
        }
        let answer = dispatch(handler, home, request);
        if write_frame(&mut stream, &answer).is_err() {
            break;
        }
    }
}

// ------------------------------- Windows --------------------------------
#[cfg(windows)]
mod windows {
    use super::*;
    use std::ffi::c_void;
    use std::thread;

    type Handle = isize;
    const INVALID_HANDLE_VALUE: Handle = -1;
    const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;
    const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
    const PIPE_TYPE_BYTE: u32 = 0x0000_0000;
    const PIPE_READMODE_BYTE: u32 = 0x0000_0000;
    const PIPE_NOWAIT: u32 = 0x0000_0001;
    const PIPE_REJECT_REMOTE_CLIENTS: u32 = 0x0000_0008;
    const PIPE_UNLIMITED_INSTANCES: u32 = 255;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const OPEN_EXISTING: u32 = 3;
    const SECURITY_SQOS_PRESENT: u32 = 0x0010_0000;
    const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;
    const SDDL_REVISION_1: u32 = 1;
    const ERROR_PIPE_CONNECTED: u32 = 535;
    const ERROR_BROKEN_PIPE: u32 = 109;
    const ERROR_PIPE_BUSY: u32 = 231;
    const ERROR_NO_DATA: u32 = 232;
    const ERROR_PIPE_LISTENING: u32 = 536;
    const NMPWAIT_TIMEOUT_MS: u32 = 2000;
    const BUFFER: u32 = 64 * 1024;

    #[repr(C)]
    struct SecurityAttributes {
        n_length: u32,
        security_descriptor: *mut c_void,
        inherit_handle: i32,
    }

    unsafe extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl: *const u16,
            revision: u32,
            psd: *mut *mut c_void,
            size: *mut u32,
        ) -> i32;
        fn LocalFree(p: *mut c_void) -> *mut c_void;
        fn CreateNamedPipeW(
            name: *const u16,
            open_mode: u32,
            pipe_mode: u32,
            max_instances: u32,
            out_buffer: u32,
            in_buffer: u32,
            default_timeout: u32,
            security: *const SecurityAttributes,
        ) -> Handle;
        fn ConnectNamedPipe(handle: Handle, overlapped: *mut c_void) -> i32;
        fn DisconnectNamedPipe(handle: Handle) -> i32;
        fn CreateFileW(
            name: *const u16,
            access: u32,
            share: u32,
            security: *const c_void,
            disposition: u32,
            flags: u32,
            template: Handle,
        ) -> Handle;
        fn WaitNamedPipeW(name: *const u16, timeout: u32) -> i32;
        fn ReadFile(
            handle: Handle,
            buffer: *mut u8,
            len: u32,
            read: *mut u32,
            overlapped: *mut c_void,
        ) -> i32;
        fn WriteFile(
            handle: Handle,
            buffer: *const u8,
            len: u32,
            written: *mut u32,
            overlapped: *mut c_void,
        ) -> i32;
        fn SetNamedPipeHandleState(handle: Handle, mode: *const u32, count: *const u32, timeout: *const u32) -> i32;
        fn CloseHandle(handle: Handle) -> i32;
        fn GetLastError() -> u32;
        fn GetNamedPipeServerProcessId(pipe: Handle, id: *mut u32) -> i32;
        fn GetNamedPipeClientProcessId(pipe: Handle, id: *mut u32) -> i32;
        fn GetNamedPipeClientSessionId(pipe: Handle, id: *mut u32) -> i32;
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
        fn GetCurrentThread() -> Handle;
    }
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
        fn OpenThreadToken(thread: Handle, access: u32, open_as_self: i32, token: *mut Handle) -> i32;
        fn ImpersonateNamedPipeClient(pipe: Handle) -> i32;
        fn RevertToSelf() -> i32;
        fn GetTokenInformation(
            token: Handle,
            class: i32,
            info: *mut c_void,
            len: u32,
            ret: *mut u32,
        ) -> i32;
        fn ConvertSidToStringSidW(sid: *mut c_void, out: *mut *mut u16) -> i32;
        fn ConvertStringSidToSidW(text: *const u16, sid: *mut *mut c_void) -> i32;
        fn LookupAccountSidW(
            system: *const u16,
            sid: *mut c_void,
            name: *mut u16,
            name_len: *mut u32,
            domain: *mut u16,
            domain_len: *mut u32,
            kind: *mut i32,
        ) -> i32;
        fn GetSecurityInfo(
            handle: Handle,
            object_type: i32,
            information: u32,
            owner: *mut *mut c_void,
            group: *mut *mut c_void,
            dacl: *mut *mut c_void,
            sacl: *mut *mut c_void,
            descriptor: *mut *mut c_void,
        ) -> u32;
    }
    const SE_KERNEL_OBJECT: i32 = 6;
    const OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_USER_CLASS: i32 = 1;

    fn wide_to_string(ptr: *mut u16) -> String {
        let mut len = 0isize;
        while unsafe { *ptr.offset(len) } != 0 {
            len += 1;
        }
        let slice = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
        String::from_utf16_lossy(slice)
    }

    /// TOKEN_USER of a process, or `None` when it cannot be read. The buffer holds the
    /// SID_AND_ATTRIBUTES header followed by the SID it points into.
    fn process_token_user(pid: u32) -> Option<Vec<u8>> {
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if process == 0 {
            return None;
        }
        let mut token: Handle = 0;
        let opened = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) };
        unsafe { CloseHandle(process) };
        if opened == 0 {
            return None;
        }
        let result = token_user(token);
        unsafe { CloseHandle(token) };
        result
    }

    fn token_user(token: Handle) -> Option<Vec<u8>> {
        let mut len = 0u32;
        unsafe { GetTokenInformation(token, TOKEN_USER_CLASS, std::ptr::null_mut(), 0, &mut len) };
        if len == 0 || len > 65536 {
            return None;
        }
        let mut buffer = vec![0u8; len as usize];
        let got = unsafe {
            GetTokenInformation(
                token,
                TOKEN_USER_CLASS,
                buffer.as_mut_ptr() as *mut c_void,
                len,
                &mut len,
            )
        };
        (got != 0).then_some(buffer)
    }

    /// Authenticate the last frame's kernel token, not the client's process DACL.
    /// NetworkService cannot query a SYSTEM process even though its pipe message
    /// is legitimate. Identification-level SQOS permits this token query without
    /// granting the server the ability to act as the client.
    fn pipe_client_identity(pipe: Handle) -> Result<String> {
        struct Revert;
        impl Drop for Revert {
            fn drop(&mut self) {
                // Never dispatch or continue with a client's thread identity.
                if unsafe { RevertToSelf() } == 0 { std::process::abort(); }
            }
        }
        let buffer = {
            if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
                return Err("pipe client identity unavailable".into());
            }
            let _revert = Revert;
            let mut token = 0;
            if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } == 0 {
                return Err("pipe client token unavailable".into());
            }
            let buffer = token_user(token);
            unsafe { CloseHandle(token) };
            buffer.ok_or("pipe client token rejected")?
        };
        let sid = token_sid(&buffer).ok_or("pipe client SID absent")?;
        let mut text = std::ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
            return Err("pipe client SID conversion failed".into());
        }
        let identity = wide_to_string(text);
        unsafe { LocalFree(text.cast()); }
        Ok(identity)
    }
    // TOKEN_USER begins with SID_AND_ATTRIBUTES whose first field is the SID pointer,
    // into the same buffer.
    fn token_sid(buffer: &[u8]) -> Option<*mut c_void> {
        if buffer.len() < std::mem::size_of::<*mut c_void>() { return None; }
        let sid = unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast::<*mut c_void>()) };
        (!sid.is_null()).then_some(sid)
    }

    /// Textual SID of the account owning a process, or `None` when it cannot be
    /// determined. Callers decide what an undetermined identity means.
    pub(super) fn process_sid(pid: u32) -> Option<String> {
        let buffer = process_token_user(pid)?;
        let sid = token_sid(&buffer)?;
        let mut text_ptr: *mut u16 = std::ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(sid, &mut text_ptr) } == 0 {
            return None;
        }
        let text = wide_to_string(text_ptr);
        unsafe { LocalFree(text_ptr as *mut c_void) };
        Some(text)
    }

    const SID_TYPE_USER: i32 = 1;
    /// Account name of a textual SID — the bare user name, as the heartbeat reports
    /// the interactive session — or `None` when it cannot be determined or is not a
    /// user account. Informational: it attributes browser records to the person
    /// signed in behind the browser and grants nothing.
    pub(super) fn sid_account(text: &str) -> Option<String> {
        struct Sid(*mut c_void);
        impl Drop for Sid { fn drop(&mut self) { unsafe { LocalFree(self.0); } } }
        let mut raw = std::ptr::null_mut();
        if unsafe { ConvertStringSidToSidW(wide(text).as_ptr(), &mut raw) } == 0 {
            return None;
        }
        let sid = Sid(raw);
        let sid = sid.0;
        let mut name = [0u16; 256];
        let mut domain = [0u16; 256];
        let mut name_len = name.len() as u32;
        let mut domain_len = domain.len() as u32;
        let mut kind = 0i32;
        let found = unsafe {
            LookupAccountSidW(
                std::ptr::null(),
                sid,
                name.as_mut_ptr(),
                &mut name_len,
                domain.as_mut_ptr(),
                &mut domain_len,
                &mut kind,
            )
        };
        if found == 0 || kind != SID_TYPE_USER || name_len == 0 {
            return None;
        }
        Some(String::from_utf16_lossy(&name[..name_len as usize]))
    }

    /// Process id the service control manager reports for a running service. Reading
    /// it needs only SERVICE_QUERY_STATUS, which interactive users hold by default.
    fn service_pid(service: &str) -> Option<u32> {
        #[link(name = "advapi32")]
        unsafe extern "system" {
            fn OpenSCManagerW(machine: *const u16, database: *const u16, access: u32) -> Handle;
            fn OpenServiceW(manager: Handle, name: *const u16, access: u32) -> Handle;
            fn QueryServiceStatusEx(service: Handle, level: i32, buffer: *mut u8, size: u32, needed: *mut u32) -> i32;
            fn CloseServiceHandle(handle: Handle) -> i32;
        }
        struct Service(Handle);
        impl Drop for Service { fn drop(&mut self) { unsafe { CloseServiceHandle(self.0); } } }
        let manager = Service(unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), 0x0001) });
        if manager.0 == 0 { return None; }
        let opened = Service(unsafe { OpenServiceW(manager.0, wide(service).as_ptr(), 0x0004) });
        if opened.0 == 0 { return None; }
        // SERVICE_STATUS_PROCESS: dwProcessId at byte 28 of 36.
        let mut status = [0u8; 36];
        let mut needed = 0u32;
        if unsafe { QueryServiceStatusEx(opened.0, 0, status.as_mut_ptr(), status.len() as u32, &mut needed) } == 0 {
            return None;
        }
        let pid = u32::from_ne_bytes(status[28..32].try_into().ok()?);
        (pid != 0).then_some(pid)
    }

    /// Owner of the pipe object, as recorded when it was created.
    ///
    /// This is the check that actually holds against squatting. Reading the server
    /// *process* token requires privileges an ordinary user does not have over a
    /// service, so that lookup fails for legitimate servers and cannot be required;
    /// the object's owner, by contrast, is readable by any client that opened a
    /// handle to it, and an unprivileged squatter cannot forge it — a process can
    /// only set an owner its token holds.
    fn pipe_owner_sid(handle: Handle) -> Result<String> {
        let mut owner: *mut c_void = std::ptr::null_mut();
        let mut descriptor: *mut c_void = std::ptr::null_mut();
        let status = unsafe {
            GetSecurityInfo(
                handle,
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut descriptor,
            )
        };
        if status != 0 || owner.is_null() {
            if !descriptor.is_null() {
                unsafe { LocalFree(descriptor) };
            }
            return Err(format!("GetSecurityInfo failed: win32={status}, information=OWNER_SECURITY_INFORMATION").into());
        }
        let mut text_ptr: *mut u16 = std::ptr::null_mut();
        let converted = unsafe { ConvertSidToStringSidW(owner, &mut text_ptr) };
        let text = (converted != 0).then(|| {
            let value = wide_to_string(text_ptr);
            unsafe { LocalFree(text_ptr as *mut c_void) };
            value
        });
        unsafe { LocalFree(descriptor) };
        text.ok_or_else(|| "ConvertSidToStringSidW failed for pipe owner".into())
    }

    // Reject a pipe that is not owned by a machine account (pipe squatting).
    //
    // This now fails **closed** on both channels. The previous version trusted a
    // pipe whose server could not be identified, and the attacker controls
    // identifiability: create the pipe, hand the handle to a helper, exit, and the
    // recorded server pid stops resolving. Since the same channel answers
    // `policy_v3`, a squatter that is trusted can hand the extension a policy with
    // every service disabled.
    fn server_is_trusted(handle: Handle, access: Access) -> Result<bool> {
        let owner = pipe_owner_sid(handle)?;
        let owned_by_a_service = match access {
            // The Browser services run as NetworkService; Administrators appears as the
            // default owner of an object created by an elevated installer. No other
            // account can join: only the serving service SID may create instances.
            Access::Browser => matches!(
                owner.as_str(),
                "S-1-5-18" | "S-1-5-20" | "S-1-5-32-544"
            ),
            // Only LocalSystem serves a service channel.
            Access::Service | Access::CacheBrowser | Access::UpdateAgent => owner == "S-1-5-18",
        };
        if !owned_by_a_service {
            return Ok(false);
        }
        // When the server process is identifiable as well, it must agree. It usually
        // is not, from an unprivileged client, which is why it cannot stand alone.
        let mut pid = 0u32;
        if unsafe { GetNamedPipeServerProcessId(handle, &mut pid) } == 0 {
            return Ok(true);
        }
        Ok(match process_sid(pid) {
            None => true,
            Some(text) => match access {
                Access::Browser => matches!(text.as_str(), "S-1-5-18" | "S-1-5-20"),
                Access::Service | Access::CacheBrowser | Access::UpdateAgent => text == "S-1-5-18",
            },
        })
    }

    /// Identity charged for a connection's share of the per-caller budget. An
    /// undetermined caller is charged to the shared unknown budget rather than
    /// escaping the cap.
    ///
    /// The client's session, which the kernel records for the pipe itself, keeps one
    /// user from spending every other user's budget. It comes first: whether
    /// NetworkService can open the client's process depends on a DACL the client
    /// sets, so keying on the process SID when readable let one user hold two budgets.
    fn caller_identity(handle: Handle) -> String {
        let mut session = 0u32;
        if unsafe { GetNamedPipeClientSessionId(handle, &mut session) } != 0 {
            return format!("session:{session}");
        }
        let mut pid = 0u32;
        if unsafe { GetNamedPipeClientProcessId(handle, &mut pid) } != 0 {
            if let Some(sid) = process_sid(pid) {
                return sid;
            }
        }
        UNKNOWN_CALLER.to_string()
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }
    fn pipe_name(channel: &str) -> String {
        format!(r"\\.\pipe\milvago-{channel}")
    }
    /// Names a channel is served under, preferred first. `ProtectedPrefix\<group>` is a
    /// pipe namespace in which only members of that group may create a pipe: a standard
    /// user is refused there (measured 2026-09-24), where it can create the plain name
    /// first while the service restarts and hold every browser of the machine failing
    /// closed. The plain name remains the fallback for a server the system keeps out of
    /// the namespace (a console run, the tests) and for a client meeting an older server
    /// during an update; the owner and service-process checks still guard it.
    fn pipe_names(channel: &str, access: Access) -> [String; 2] {
        let group = if access == Access::Browser { "NetworkService" } else { "Administrators" };
        [format!(r"\\.\pipe\ProtectedPrefix\{group}\milvago-{channel}"), pipe_name(channel)]
    }

    struct PipeStream(Handle);
    impl Read for PipeStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let mut read = 0u32;
            let ok = unsafe {
                ReadFile(
                    self.0,
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                    &mut read,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                let err = unsafe { GetLastError() };
                if err == ERROR_BROKEN_PIPE {
                    return Ok(0);
                }
                if err == ERROR_NO_DATA {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                return Err(io::Error::from_raw_os_error(err as i32));
            }
            Ok(read as usize)
        }
    }
    impl Write for PipeStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let mut written = 0u32;
            let ok = unsafe {
                WriteFile(
                    self.0,
                    buf.as_ptr(),
                    buf.len() as u32,
                    &mut written,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(io::Error::from_raw_os_error(unsafe { GetLastError() } as i32));
            }
            if written == 0 && !buf.is_empty() {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            Ok(written as usize)
        }
        fn flush(&mut self) -> io::Result<()> {
            // WriteFile has copied the bytes. FlushFileBuffers waits for the
            // remote reader and has no deadline; the next read keeps the server
            // handle alive until the peer closes, bounded by DeadlineStream.
            Ok(())
        }
    }
    impl Drop for PipeStream {
        fn drop(&mut self) {
            unsafe {
                DisconnectNamedPipe(self.0);
                CloseHandle(self.0);
            }
        }
    }

    // A connected-client handle that must not DisconnectNamedPipe (it is the
    // client side opened via CreateFileW).
    pub(crate) struct ClientStream(Handle);
    impl Read for ClientStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let mut read = 0u32;
            let ok = unsafe {
                ReadFile(
                    self.0,
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                    &mut read,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                let err = unsafe { GetLastError() };
                if err == ERROR_BROKEN_PIPE {
                    return Ok(0);
                }
                if err == ERROR_NO_DATA {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                return Err(io::Error::from_raw_os_error(err as i32));
            }
            Ok(read as usize)
        }
    }
    impl Write for ClientStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let mut written = 0u32;
            let ok = unsafe {
                WriteFile(
                    self.0,
                    buf.as_ptr(),
                    buf.len() as u32,
                    &mut written,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(io::Error::from_raw_os_error(unsafe { GetLastError() } as i32));
            }
            if written == 0 && !buf.is_empty() {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            Ok(written as usize)
        }
        fn flush(&mut self) -> io::Result<()> {
            // WriteFile has copied the bytes. FlushFileBuffers waits for the
            // remote reader and has no deadline; the next read keeps the server
            // handle alive until the peer closes, bounded by DeadlineStream.
            Ok(())
        }
    }
    impl Drop for ClientStream {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }
    struct Descriptor(*mut c_void);
    impl Drop for Descriptor {
        fn drop(&mut self) {
            unsafe { LocalFree(self.0) };
        }
    }

    // Explicit owner is required: a SYSTEM token may default new objects to Administrators.
    // Keep client authentication restricted to SYSTEM; do not broaden it to that default.
    //
    // Clients get CLIENT, never GENERIC_WRITE: on a pipe GENERIC_WRITE carries
    // FILE_APPEND_DATA, which is FILE_CREATE_PIPE_INSTANCE. Every instance of a name
    // shares the first one's descriptor, so a client holding that right could serve
    // its own instances under the service's owner and read another user's frames.
    const CLIENT: &str = "0x0012019b"; // FILE_GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA
    fn pipe_sddl(access: Access, edition: &str, server: &str) -> Result<String> {
        Ok(match access {
            Access::Browser => format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{server})(A;;{CLIENT};;;AU)"),
            // The agent service alone, not every NetworkService service: the collector's
            // channel hands out and acknowledges the native queue.
            Access::Service => format!("O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;{CLIENT};;;{})", crate::cache_peer::service_sid(edition)?),
            Access::CacheBrowser => format!("O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;{CLIENT};;;AU)"),
            Access::UpdateAgent => format!("O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;{CLIENT};;;{})", crate::cache_peer::service_sid(edition)?),
        })
    }
    /// Who may create instances of a Browser channel: the one service that serves it,
    /// never NetworkService as such, which every NetworkService service shares. A
    /// channel no service owns (tests, a console run) is left to its creator.
    fn browser_service(channel: &str) -> Option<&'static str> {
        Some(match channel {
            "browser" => "Milvago Agent Logger Community",
            "commercial" => "Milvago Agent Logger",
            "filter-commercial" => "MilvagoModelFilter",
            _ => return None,
        })
    }
    fn browser_server(channel: &str) -> String {
        let Some(service) = browser_service(channel) else { return "OW".into() };
        crate::cache_peer::named_service_sid(service).unwrap_or_else(|_| {
            crate::log::warn(&format!("service SID of {service} unavailable; pipe instances left to NetworkService"));
            "NS".into()
        })
    }

    /// The process serving a pipe name we could not create, for the operator's log.
    /// Opened as an anonymous client (SecurityAnonymous): the squatter learns nothing of
    /// this service's token and receives no data.
    fn squatter(name: &[u16]) -> Option<u32> {
        const SECURITY_ANONYMOUS: u32 = 0;
        let handle = unsafe {
            CreateFileW(name.as_ptr(), GENERIC_READ, 0, std::ptr::null(), OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS, 0)
        };
        if handle == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut pid = 0u32;
        let found = unsafe { GetNamedPipeServerProcessId(handle, &mut pid) } != 0;
        unsafe { CloseHandle(handle) };
        found.then_some(pid)
    }

    pub fn serve(
        home: &Path,
        channel: &str,
        access: Access,
        stop: Arc<AtomicBool>,
        handler: Arc<Handler>,
    ) -> Result<()> {
        // Browser: SYSTEM, Administrators and the serving service's SID full; Authenticated
        // Users read+write without instance creation (any signed-in user's browser shim). Service: no Authenticated
        // Users ACE at all — the access control is the authentication, and the agent
        // account gets read+write only. Protected (P): no inherited ACE weakens it.
        let edition = if channel.ends_with("commercial") { "commercial" } else { "community" };
        let server = if access == Access::Browser { browser_server(channel) } else { String::new() };
        let sddl = wide(&pipe_sddl(access, edition, &server)?);
        let mut psd: *mut c_void = std::ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut psd,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err("security descriptor construction failed".into());
        }
        let descriptor = Descriptor(psd);
        let [protected, plain] = pipe_names(channel, access);
        let mut name = wide(&protected);
        let active = Arc::new(AtomicUsize::new(0));
        let callers: Arc<Callers> = Arc::default();
        let create = |name: &[u16], first: bool| {
            let sa = SecurityAttributes {
                n_length: std::mem::size_of::<SecurityAttributes>() as u32,
                security_descriptor: descriptor.0,
                inherit_handle: 0,
            };
            let open_mode =
                PIPE_ACCESS_DUPLEX | if first { FILE_FLAG_FIRST_PIPE_INSTANCE } else { 0 };
            unsafe {
                CreateNamedPipeW(
                    name.as_ptr(),
                    open_mode,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
                    PIPE_UNLIMITED_INSTANCES,
                    BUFFER,
                    BUFFER,
                    0,
                    &sa,
                )
            }
        };
        // The name must never be left without an instance of ours: in that gap anyone
        // could create it first. Instances are therefore replaced while others are still
        // held, and only an instance created with FIRST_PIPE_INSTANCE starts again from
        // nothing (it can never join a squatter). Several listen at once: with a single
        // one, any local process connecting and closing in a loop kept taking it before
        // a browser relay could, and every browser of the machine failed closed.
        const LISTENING: usize = 4;
        let mut pool: Vec<Handle> = Vec::new();
        let protected_first = create(&name, true);
        if protected_first != INVALID_HANDLE_VALUE {
            pool.push(protected_first);
        } else {
            let error = unsafe { GetLastError() };
            crate::log::warn(&format!("protected pipe namespace refused (OS {error}); serving {plain}"));
            name = wide(&plain);
        }
        let mut squat_wait = std::time::Duration::from_secs(5);
        while !stop.load(Ordering::Acquire) {
            if pool.is_empty() {
                let first = create(&name, true);
                if first != INVALID_HANDLE_VALUE {
                    pool.push(first);
                    squat_wait = std::time::Duration::from_secs(5);
                } else {
                    // Another process already owns the pipe name (squatting). Never share it,
                    // but never exit either: SCM gives up after three restarts, and a standard
                    // user could keep every browser on the machine failing closed for a day.
                    let error = unsafe { GetLastError() };
                    crate::log::error(&format!("pipe name unavailable (OS {error}), held by process {}; retrying in {}s",
                        squatter(&name).map_or_else(|| "unknown".into(), |pid| pid.to_string()), squat_wait.as_secs()));
                    let resume = std::time::Instant::now() + squat_wait;
                    while std::time::Instant::now() < resume && !stop.load(Ordering::Acquire) {
                        thread::sleep(std::time::Duration::from_millis(200));
                    }
                    squat_wait = (squat_wait * 2).min(std::time::Duration::from_secs(60));
                    continue;
                }
            }
            // Joins our own pipe: the instances already held keep the name alive.
            while pool.len() < LISTENING {
                let next = create(&name, false);
                if next == INVALID_HANDLE_VALUE {
                    break;
                }
                pool.push(next);
            }
            // The first instance with a peer, or one whose peer already left.
            let mut ready = None;
            for (index, &instance) in pool.iter().enumerate() {
                let connected = unsafe { ConnectNamedPipe(instance, std::ptr::null_mut()) };
                let error = if connected == 0 { unsafe { GetLastError() } } else { 0 };
                if error == ERROR_PIPE_CONNECTED {
                    ready = Some((index, true));
                    break;
                }
                // The first nonblocking call can succeed while only marking the
                // instance as listening. Only PIPE_CONNECTED proves a peer.
                if connected != 0 || error == ERROR_PIPE_LISTENING {
                    continue;
                }
                ready = Some((index, false));
                break;
            }
            let Some((index, connected)) = ready else {
                thread::sleep(std::time::Duration::from_millis(5));
                continue;
            };
            let handle = pool.swap_remove(index);
            if !connected {
                unsafe {
                    DisconnectNamedPipe(handle);
                    CloseHandle(handle);
                }
                continue;
            }
            let authenticated = match access {
                Access::CacheBrowser | Access::UpdateAgent => {
                    let mut pid = 0;
                    if unsafe { GetNamedPipeClientProcessId(handle, &mut pid) } == 0 { false }
                    else if access == Access::CacheBrowser { crate::cache_peer::relay(pid, edition).is_ok() }
                    else { crate::cache_peer::agent(pid, edition).is_ok() }
                }
                _ => true,
            };
            if !authenticated {
                unsafe { DisconnectNamedPipe(handle); CloseHandle(handle); }
                continue;
            }
            let caller = caller_identity(handle);
            if active.load(Ordering::Acquire) >= MAX_CONNECTIONS || !callers.admit(&caller) {
                unsafe {
                    DisconnectNamedPipe(handle);
                    CloseHandle(handle);
                }
                continue;
            }
            active.fetch_add(1, Ordering::AcqRel);
            let home = home.to_path_buf();
            let original_handler = handler.clone();
            let rate_callers = callers.clone();
            let rate_caller = caller.clone();
            let handler: Arc<Handler> = Arc::new(move |home, mut request| {
                if !rate_callers.allow(&rate_caller) {
                    return Err("IPC request rate exceeded".into());
                }
                // handle_limit has read the complete frame before this callback.
                // Always revert inside the query before entering product code.
                let principal = pipe_client_identity(handle)?;
                let object=request.as_object_mut().ok_or("IPC object required")?;
                let caller=object.get_mut("caller").and_then(Value::as_object_mut).ok_or("IPC caller absent")?;
                caller.insert("system".into(),json!(principal == "S-1-5-18"));
                // The account comes from the same kernel token as the SID, never from a
                // process id the client could have recycled.
                caller.insert("user".into(),json!(sid_account(&principal).unwrap_or_default()));
                caller.insert("sid".into(),json!(principal));
                original_handler(home, request)
            });
            let active_clone = active.clone();
            let callers_clone = callers.clone();
            let connection_stop = stop.clone();
            thread::spawn(move || {
                let _slot=ConnectionSlot{callers:callers_clone,caller,active:active_clone};
                super::handle_limit(DeadlineStream::new(PipeStream(handle), access, connection_stop), &home, handler.as_ref(), None,frame_budget(access));
            });
        }
        for instance in pool {
            unsafe { CloseHandle(instance) };
        }
        drop(descriptor);
        Ok(())
    }

    #[cfg(test)]
    mod pipe_tests {
        use super::*;
        #[test]
        fn privileged_pipe_descriptors_explicitly_own_system() {
            unsafe extern "system" {
                fn GetSecurityDescriptorOwner(descriptor: *mut c_void, owner: *mut *mut c_void, defaulted: *mut i32) -> i32;
            }
            let mut checked=0;
            for access in [Access::Service, Access::CacheBrowser, Access::UpdateAgent] {
                // The agent's service SID resolves only where the service is installed.
                if matches!(access, Access::UpdateAgent | Access::Service) && crate::cache_peer::service_sid("community").is_err() { continue; }
                let text=pipe_sddl(access,"community","").unwrap();
                let mut raw=std::ptr::null_mut();
                assert_ne!(unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(wide(&text).as_ptr(),
                    SDDL_REVISION_1,&mut raw,std::ptr::null_mut()) },0);
                let descriptor=Descriptor(raw);
                let mut owner=std::ptr::null_mut();let mut defaulted=1;
                assert_ne!(unsafe { GetSecurityDescriptorOwner(descriptor.0,&mut owner,&mut defaulted) },0);
                assert!(!owner.is_null(),"privileged pipe owner is implicit");
                let mut owner_text=std::ptr::null_mut();
                assert_ne!(unsafe { ConvertSidToStringSidW(owner,&mut owner_text) },0);
                let owner_sid=wide_to_string(owner_text);
                unsafe { LocalFree(owner_text.cast()); }
                assert_eq!(owner_sid,"S-1-5-18");
                assert_eq!(defaulted,0);
                checked+=1;
            }
            assert!(checked>=1);
            assert_eq!(pipe_sddl(Access::Browser,"community","OW").unwrap(),
                "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)(A;;0x0012019b;;;AU)");
            // No client ACE may carry FILE_CREATE_PIPE_INSTANCE (0x4) or GENERIC_WRITE.
            for access in [Access::Browser, Access::Service, Access::CacheBrowser] {
                if access == Access::Service && crate::cache_peer::service_sid("community").is_err() { continue; }
                let text=pipe_sddl(access,"community","OW").unwrap();
                assert!(!text.contains("GW"), "generic write granted: {text}");
                assert_eq!(u32::from_str_radix(CLIENT.trim_start_matches("0x"),16).unwrap()&0x4,0);
            }
            assert_eq!(browser_server("test-channel"),"OW");
        }

        // The kernel decides: a principal granted only the client ACE cannot serve its
        // own instance of the name, where the former GENERIC_WRITE grant let it.
        #[test]
        fn a_client_principal_cannot_add_a_pipe_instance() {
            let join = |sddl: &str| -> u32 {
                let name = wide(&pipe_name(&format!("test-{}", uuid::Uuid::new_v4())));
                let text = wide(sddl);
                let mut raw = std::ptr::null_mut();
                assert_ne!(unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(text.as_ptr(), SDDL_REVISION_1, &mut raw, std::ptr::null_mut()) }, 0);
                let descriptor = Descriptor(raw);
                let sa = SecurityAttributes { n_length: std::mem::size_of::<SecurityAttributes>() as u32, security_descriptor: descriptor.0, inherit_handle: 0 };
                let create = |mode: u32| unsafe { CreateNamedPipeW(name.as_ptr(), PIPE_ACCESS_DUPLEX | mode,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS, PIPE_UNLIMITED_INSTANCES, BUFFER, BUFFER, 0, &sa) };
                let served = create(FILE_FLAG_FIRST_PIPE_INSTANCE);
                assert_ne!(served, INVALID_HANDLE_VALUE);
                let joined = create(0);
                let error = if joined == INVALID_HANDLE_VALUE { unsafe { GetLastError() } } else { unsafe { CloseHandle(joined) }; 0 };
                unsafe { CloseHandle(served) };
                error
            };
            // SYSTEM stands for the serving service; this test account is only a client.
            let hardened = format!("D:P(A;;FA;;;SY)(A;;{CLIENT};;;AU)");
            let former = "D:P(A;;FA;;;SY)(A;;GRGW;;;AU)";
            assert_eq!(join(former), 0, "the former descriptor no longer reproduces the defect");
            assert_eq!(join(&hardened), 5, "a client principal joined the served pipe");
        }

        // The squatting defence rests on the kernel refusing the protected namespace to a
        // standard account, which can still create the plain name. An elevated test run
        // belongs to Administrators and proves nothing: it says so and stops.
        #[test]
        fn a_standard_account_cannot_take_a_protected_pipe_name() {
            for access in [Access::Browser, Access::Service] {
                let [protected, plain] = pipe_names(&format!("test-{}", uuid::Uuid::new_v4()), access);
                let create = |name: &str| {
                    let name = wide(name);
                    let handle = unsafe { CreateNamedPipeW(name.as_ptr(), PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT, 1, BUFFER, BUFFER, 0, std::ptr::null()) };
                    let error = if handle == INVALID_HANDLE_VALUE { unsafe { GetLastError() } } else { unsafe { CloseHandle(handle) }; 0 };
                    error
                };
                assert_eq!(create(&plain), 0, "the plain name is no longer creatable: the test proves nothing");
                let refused = create(&protected);
                if refused == 0 {
                    eprintln!("elevated test account: protected namespace check skipped");
                    return;
                }
                assert_eq!(refused, 5, "unexpected refusal for {protected}");
            }
        }

        fn raw_client(channel: &str, server_done: &std::sync::mpsc::Receiver<Result<()>>) -> DeadlineStream<ClientStream> {
            raw_client_level(channel, server_done, SECURITY_IDENTIFICATION)
        }

        fn raw_client_level(channel: &str, server_done: &std::sync::mpsc::Receiver<Result<()>>, level: u32) -> DeadlineStream<ClientStream> {
            let name = wide(&pipe_name(channel));
            let until = std::time::Instant::now() + std::time::Duration::from_secs(3);
            let handle = loop {
                let handle = unsafe { CreateFileW(name.as_ptr(), GENERIC_READ | GENERIC_WRITE,
                    0, std::ptr::null(), OPEN_EXISTING, SECURITY_SQOS_PRESENT | level, 0) };
                if handle != INVALID_HANDLE_VALUE { break handle; }
                let error = unsafe { GetLastError() };
                if let Ok(result) = server_done.try_recv() {
                    panic!("pipe server exited before client connected: {result:?}; client CreateFileW OS {error}");
                }
                assert!(std::time::Instant::now() < until,
                    "client CreateFileW failed: OS {error}; pipe server has not exited");
                thread::sleep(std::time::Duration::from_millis(5));
            };
            assert_ne!(unsafe { SetNamedPipeHandleState(handle, &PIPE_NOWAIT, std::ptr::null(), std::ptr::null()) }, 0);
            DeadlineStream::new(ClientStream(handle), Access::Browser,
                Arc::new(AtomicBool::new(false)))
        }

        #[test]
        fn eight_idle_or_partial_same_account_pipes_expire_and_real_request_recovers() {
            let channel = format!("test-{}", uuid::Uuid::new_v4());
            let service_channel = channel.clone();
            let stop = Arc::new(AtomicBool::new(false));
            let service_stop = stop.clone();
            let calls = Arc::new(AtomicUsize::new(0));
            let handler_calls = calls.clone();
            let home = tempfile::tempdir().unwrap();
            let path = home.path().to_path_buf();
            let (completed, done) = std::sync::mpsc::channel();
            let worker = thread::spawn(move || {
                let result = serve(&path, &service_channel, Access::Browser, service_stop,
                    Arc::new(move |_, request| {
                        handler_calls.fetch_add(1, Ordering::AcqRel);
                        Ok(json!({"ok":true,"value":request["value"]}))
                    }));
                completed.send(result).unwrap();
            });
            let mut hostile = Vec::new();
            for index in 0..MAX_CONNECTIONS_PER_CALLER {
                let mut stream = raw_client(&channel, &done);
                if index % 2 != 0 { stream.write_all(&[32]).unwrap(); }
                hostile.push(stream);
            }
            // Connecting the next instance proves that the preceding eight were
            // accepted by the actual server, not merely inserted in a test map.
            let mut refused = raw_client(&channel, &done);
            let sent = write_frame(&mut refused, &json!({"value":7}));
            if sent.is_ok() {
                assert!(frame(&mut refused).ok().flatten().is_none());
            }
            assert_eq!(calls.load(Ordering::Acquire), 0, "same-account budget was not filled");
            drop(refused);
            thread::sleep(std::time::Duration::from_millis(400));
            for (index, stream) in hostile.iter_mut().enumerate() {
                if index % 2 != 0 { stream.write_all(&[0]).unwrap(); }
            }
            // Partial progress cannot renew the server's original ten seconds.
            thread::sleep(std::time::Duration::from_millis(10_200));
            let mut legitimate = raw_client(&channel, &done);
            write_frame(&mut legitimate, &json!({"value":42})).unwrap();
            assert_eq!(frame(&mut legitimate).unwrap().unwrap()["value"], 42);
            assert_eq!(calls.load(Ordering::Acquire), 1);
            drop(legitimate);
            stop.store(true, Ordering::Release);
            done.recv_timeout(std::time::Duration::from_secs(3)).unwrap().unwrap();
            worker.join().unwrap();
        }

        #[test]
        fn real_pipe_roundtrip_and_stop_release_pending_accept() {
            let channel = format!("test-{}", uuid::Uuid::new_v4());
            let service_channel = channel.clone();
            let stop = Arc::new(AtomicBool::new(false));
            let service_stop = stop.clone();
            let home = tempfile::tempdir().unwrap();
            let path = home.path().to_path_buf();
            let (completed, done) = std::sync::mpsc::channel();
            let worker = thread::spawn(move || {
                completed.send(serve(&path, &service_channel, Access::Browser,
                    service_stop, Arc::new(|_, request| Ok(json!({"ok":true,"value":request["value"]}))))).unwrap();
            });
            // Raw client is deliberate: a unit-test account is not a service and
            // production connect must reject its ownership.
            let mut stream = raw_client(&channel, &done);
            write_frame(&mut stream, &json!({"value":42})).unwrap();
            assert_eq!(frame(&mut stream).unwrap().unwrap()["value"], 42);
            drop(stream);
            stop.store(true, Ordering::Release);
            done.recv_timeout(std::time::Duration::from_secs(3)).unwrap().unwrap();
            worker.join().unwrap();
        }

        #[test]
        fn a_squatted_pipe_name_is_waited_out_never_shared_and_never_fatal() {
            let channel = format!("test-{}", uuid::Uuid::new_v4());
            let service_channel = channel.clone();
            let name = wide(&pipe_name(&channel));
            let squat = unsafe { CreateNamedPipeW(name.as_ptr(), PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT, 1, BUFFER, BUFFER, 0, std::ptr::null()) };
            assert_ne!(squat, INVALID_HANDLE_VALUE);
            let stop = Arc::new(AtomicBool::new(false));
            let service_stop = stop.clone();
            let home = tempfile::tempdir().unwrap();
            let path = home.path().to_path_buf();
            let (completed, done) = std::sync::mpsc::channel();
            let worker = thread::spawn(move || {
                completed.send(serve(&path, &service_channel, Access::Browser, service_stop,
                    Arc::new(|_, request| Ok(json!({"ok":true,"value":request["value"]}))))).unwrap();
            });
            assert!(done.recv_timeout(std::time::Duration::from_millis(1500)).is_err(), "squat made the service exit");
            // Once the squatter leaves, the service takes the name at its next attempt.
            unsafe { CloseHandle(squat) };
            // First retry is due five seconds after the refusal; the client waits three.
            thread::sleep(std::time::Duration::from_millis(2500));
            let mut stream = raw_client(&channel, &done);
            write_frame(&mut stream, &json!({"value":7})).unwrap();
            assert_eq!(frame(&mut stream).unwrap().unwrap()["value"], 7);
            drop(stream);
            stop.store(true, Ordering::Release);
            done.recv_timeout(std::time::Duration::from_secs(3)).unwrap().unwrap();
            worker.join().unwrap();
        }

        #[test]
        fn pipe_frame_identity_replaces_forged_authority_and_reverts_before_dispatch() {
            let channel = format!("test-{}", uuid::Uuid::new_v4());
            let service_channel = channel.clone();
            let stop = Arc::new(AtomicBool::new(false));
            let service_stop = stop.clone();
            let home = tempfile::tempdir().unwrap();
            let path = home.path().to_path_buf();
            let expected = process_sid(std::process::id()).expect("test process SID unavailable");
            let (completed, done) = std::sync::mpsc::channel();
            let worker = thread::spawn(move || {
                completed.send(serve(&path, &service_channel, Access::Browser, service_stop,
                    Arc::new(|_, request| {
                        let mut token = 0;
                        let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) };
                        let error = unsafe { GetLastError() };
                        if opened != 0 { unsafe { CloseHandle(token); } }
                        assert_eq!(opened, 0, "handler inherited a client token");
                        assert_eq!(error, 1008, "expected ERROR_NO_TOKEN after reversion");
                        Ok(json!({"ok":true,"caller":request["caller"]}))
                    }))).unwrap();
            });
            let mut stream = raw_client(&channel, &done);
            for forged_system in [true, false] {
                write_frame(&mut stream, &json!({"caller":{"sid":"forged","system":forged_system}})).unwrap();
                let answer = frame(&mut stream).unwrap().unwrap();
                assert_eq!(answer["ok"], true);
                assert_eq!(answer["caller"]["sid"], expected);
                assert_eq!(answer["caller"]["system"], expected == "S-1-5-18");
            }
            drop(stream);
            // An anonymous client cannot manufacture an authenticated identity.
            let mut anonymous = raw_client_level(&channel, &done, 0);
            write_frame(&mut anonymous, &json!({"caller":{"sid":"S-1-5-18","system":true}})).unwrap();
            let refused = frame(&mut anonymous).unwrap().unwrap();
            assert_eq!(refused["ok"], false);
            assert_eq!(refused["error"], "operation_refused");
            assert!(refused.get("caller").is_none(), "anonymous request reached product handler");
            drop(anonymous);
            stop.store(true, Ordering::Release);
            done.recv_timeout(std::time::Duration::from_secs(3)).unwrap().unwrap();
            worker.join().unwrap();
        }
    }

    pub fn exchange_agent(channel: &str, edition: &str, request: &Value, timeout: std::time::Duration) -> Result<Value> {
        let mut stream = connect(channel, Access::Browser)?;
        let mut pid = 0;
        if unsafe { GetNamedPipeServerProcessId(stream.inner.0, &mut pid) } == 0 { return Err("agent process unavailable".into()); }
        crate::cache_peer::agent(pid, edition)?;
        stream.deadline = std::time::Instant::now() + timeout;
        write_frame(&mut stream, request)?;
        (crate::frame_limit(&mut stream,if request["op"]=="broker_cache_source"{2*1024*1024}else{1024*1024})?).ok_or_else(|| "agent response absent".into())
    }
    pub fn connect(channel: &str, access: Access) -> Result<DeadlineStream<ClientStream>> {
        let names = pipe_names(channel, access).map(|name| wide(&name));
        let open = |name: &[u16]| unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                // Identification, not impersonation: the server may learn who we are
                // and may not act as us.
                SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                0,
            )
        };
        // Every instance taken by another client (a local process may connect and close in
        // a loop) or the name between two instances is not an absent agent: retried until
        // a bounded deadline, waiting for a free instance, before reporting unavailable.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let handle = loop {
            let mut name = &names[0];
            let mut handle = open(name);
            let mut err = if handle == INVALID_HANDLE_VALUE { unsafe { GetLastError() } } else { 0 };
            // The plain name only when no protected instance exists at all: a busy
            // protected server is waited for, never traded for whoever holds the plain name.
            if err == 2 {
                name = &names[1];
                handle = open(name);
                err = if handle == INVALID_HANDLE_VALUE { unsafe { GetLastError() } } else { 0 };
            }
            if handle != INVALID_HANDLE_VALUE {
                break handle;
            }
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            // ERROR_FILE_NOT_FOUND: no instance at this instant; ERROR_PIPE_BUSY: all taken.
            if left.is_zero() || !(err == ERROR_PIPE_BUSY || err == 2) {
                if err == ERROR_PIPE_BUSY {
                    return Err("CreateFileW agent pipe busy: win32=231, access=0xc0000000".into());
                }
                return Err(format!("CreateFileW agent pipe failed: win32={err}, access=0xc0000000").into());
            }
            if err == ERROR_PIPE_BUSY {
                unsafe { WaitNamedPipeW(name.as_ptr(), (left.as_millis() as u32).clamp(1, NMPWAIT_TIMEOUT_MS)) };
            } else {
                thread::sleep(std::time::Duration::from_millis(20).min(left));
            }
        };
        // Anti-squat: only trust a pipe served by a service account.
        match server_is_trusted(handle, access) {
            Ok(true) => {},
            result => {
                unsafe { CloseHandle(handle) };
                return Err(result.err().unwrap_or_else(|| "agent pipe owner is not an authorized service account".into()));
            }
        }
        // Every NetworkService service can own a pipe: one that created the name first
        // (at boot, during a restart) would pass the owner check. The server must be the
        // very process the service control manager runs for this channel.
        if access == Access::Browser {
            if let Some(service) = browser_service(channel) {
                let mut pid = 0u32;
                let served = unsafe { GetNamedPipeServerProcessId(handle, &mut pid) } != 0;
                if !served || service_pid(service) != Some(pid) {
                    unsafe { CloseHandle(handle) };
                    return Err("agent pipe is not served by its service".into());
                }
            }
        }
        if unsafe { SetNamedPipeHandleState(handle, &PIPE_NOWAIT, std::ptr::null(), std::ptr::null()) } == 0 {
            let error = unsafe { GetLastError() };
            unsafe { CloseHandle(handle) };
            return Err(format!("SetNamedPipeHandleState failed: win32={error}, mode=PIPE_NOWAIT").into());
        }
        Ok(DeadlineStream::new(ClientStream(handle), access, Arc::new(AtomicBool::new(false))))
    }
}

// -------------------------------- Unix ----------------------------------
#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;
    use std::thread;
    use std::time::Duration;

    /// Peer uid of a connected socket.
    ///
    /// `UnixStream::peer_cred` is still unstable (rust-lang/rust#42839), so the
    /// credential is read directly. An undetermined peer is charged to the shared
    /// unknown budget rather than escaping the per-caller cap.
    #[cfg(target_os = "linux")]
    fn peer_uid(stream: &UnixStream) -> Option<u32> {
        use std::os::fd::AsRawFd;
        let mut credential = libc::ucred { pid: 0, uid: 0, gid: 0 };
        let mut length = size_of::<libc::ucred>() as libc::socklen_t;
        let read = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                std::ptr::from_mut(&mut credential).cast(),
                &mut length,
            )
        };
        (read == 0 && length as usize == size_of::<libc::ucred>()).then_some(credential.uid)
    }

    #[cfg(not(target_os = "linux"))]
    fn peer_uid(_stream: &UnixStream) -> Option<u32> {
        None
    }

    /// The model filter runs as its own account and cannot write the agent's
    /// /run/milvago; its unit owns /run/milvago-filter (RuntimeDirectory). A service
    /// channel is served by root: its socket lives in root's own /run/milvago-collector,
    /// never in the agent-owned /run/milvago, where the agent could swap the socket for a
    /// link between root's bind and chmod.
    fn socket_dir(channel: &str, access: Access) -> PathBuf {
        PathBuf::from(if access == Access::Service { "/run/milvago-collector" } else if channel.starts_with("filter-") { "/run/milvago-filter" } else { "/run/milvago" })
    }
    /// Account name of a uid through NSS, for attributing the records a connection
    /// produces: domain users (SSSD, winbind) are not in /etc/passwd. Informational;
    /// `None` when unknown.
    fn account_for_uid(uid: u32) -> Option<String> {
        let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result = std::ptr::null_mut();
        let mut buffer = vec![0u8; 16384];
        let status = unsafe { libc::getpwuid_r(uid, &mut entry, buffer.as_mut_ptr().cast(), buffer.len(), &mut result) };
        if status != 0 || result.is_null() || entry.pw_name.is_null() {
            return None;
        }
        let name = unsafe { std::ffi::CStr::from_ptr(entry.pw_name) }.to_str().ok()?;
        (!name.is_empty() && name.len() <= 128).then(|| name.to_string())
    }
    fn socket_path(channel: &str, access: Access) -> PathBuf {
        socket_dir(channel, access).join(format!("{channel}.sock"))
    }

    pub fn serve(
        home: &Path,
        channel: &str,
        access: Access,
        stop: Arc<AtomicBool>,
        handler: Arc<Handler>,
    ) -> Result<()> {
        let dir = socket_dir(channel, access);
        std::fs::create_dir_all(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))?;
        let path = socket_path(channel, access);
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path)?;
        // Browser: any signed-in local user's browser shim may connect; the served
        // ops are the safe browser subset and the identity is the service's own.
        // Service: not world-writable — the directory is owned by the service
        // account, so only a peer the deployment granted access can reach it.
        std::fs::set_permissions(
            &path,
            std::fs::Permissions::from_mode(match access {
                Access::Browser => 0o666,
                Access::Service => 0o660,
            }),
        )?;
        listener.set_nonblocking(true)?;
        let active = Arc::new(AtomicUsize::new(0));
        let callers: Arc<Callers> = Arc::default();
        while !stop.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((stream, _)) => {
                    // The socket is world-writable so any signed-in user's browser
                    // shim can relay; the peer's uid is what bounds its share.
                    let uid = peer_uid(&stream);
                    let caller = uid.map_or_else(|| UNKNOWN_CALLER.to_string(), |uid| uid.to_string());
                    if active.load(Ordering::Acquire) >= MAX_CONNECTIONS
                        || !callers.admit(&caller)
                    {
                        continue;
                    }
                    if stream.set_nonblocking(true).is_err() {
                        callers.release(&caller);
                        continue;
                    }
                    let account = uid.and_then(account_for_uid);
                    active.fetch_add(1, Ordering::AcqRel);
                    let home = home.to_path_buf();
                    let original_handler = handler.clone();
                    let rate_callers = callers.clone();
                    let rate_caller = caller.clone();
                    let handler: Arc<Handler> = Arc::new(move |home, request| {
                        if !rate_callers.allow(&rate_caller) {
                            return Err("IPC request rate exceeded".into());
                        }
                        original_handler(home, request)
                    });
                    let active_clone = active.clone();
                    let callers_clone = callers.clone();
                    let connection_stop = stop.clone();
                    thread::spawn(move || {
                        let _slot=ConnectionSlot{callers:callers_clone,caller,active:active_clone};
                        super::handle_limit(DeadlineStream::new(stream, access, connection_stop), &home, handler.as_ref(), account, super::frame_budget(access));
                    });
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(200));
                }
                Err(_) => thread::sleep(Duration::from_millis(200)),
            }
        }
        let _ = std::fs::remove_file(&path);
        Ok(())
    }

    pub fn connect(channel: &str, access: Access) -> Result<DeadlineStream<UnixStream>> {
        let path = socket_path(channel, access);
        if access == Access::Service {
            // Anti-squat, failing closed: a service channel is served by root and by
            // nothing else.
            use std::os::unix::fs::MetadataExt;
            if std::fs::metadata(&path).map(|m| m.uid()).unwrap_or(u32::MAX) != 0 {
                return Err("service socket is not owned by root".into());
            }
        }
        let stream = UnixStream::connect(path)?;
        stream.set_nonblocking(true)?;
        Ok(DeadlineStream::new(stream, access, Arc::new(AtomicBool::new(false))))
    }
}

#[cfg(test)]
mod tests {
    use super::{Callers, MAX_CONNECTIONS_PER_CALLER, UNKNOWN_CALLER};

    fn tcp_pair() -> (std::net::TcpStream, std::net::TcpStream) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        server.set_nonblocking(true).unwrap();
        (client, server)
    }

    #[test]
    fn slow_partial_frame_releases_same_callers_slots_by_absolute_deadline() {
        use std::io::Write;
        use std::sync::{Arc, atomic::AtomicBool};
        use std::time::{Duration, Instant};
        let callers = Arc::new(Callers::default());
        let mut clients = Vec::new();
        let mut workers = Vec::new();
        for _ in 0..MAX_CONNECTIONS_PER_CALLER {
            assert!(callers.admit("same-user"));
            let (mut client, server) = tcp_pair();
            // A real partial length header, not a mocked timeout result.
            client.write_all(&[32]).unwrap();
            clients.push(client);
            let callers = callers.clone();
            workers.push(std::thread::spawn(move || {
                let mut stream = super::DeadlineStream::new(server, super::Access::Browser,
                    Arc::new(AtomicBool::new(false)));
                stream.deadline = Instant::now() + Duration::from_millis(200);
                let result = crate::frame(&mut stream);
                assert!(result.is_err(), "partial frame must not be accepted");
                callers.release("same-user");
            }));
        }
        assert!(!callers.admit("same-user"));
        // More bytes do not renew the absolute deadline.
        std::thread::sleep(Duration::from_millis(80));
        for client in &mut clients { let _ = client.write_all(&[0]); }
        for worker in workers { worker.join().unwrap(); }
        assert!(callers.admit("same-user"), "the legitimate browser can reconnect");
    }

    #[test]
    fn stopped_connection_aborts_incomplete_read_without_retry_spin() {
        use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
        use std::io::Write;
        let (mut client, server) = tcp_pair();
        client.write_all(&[32]).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let mut stream = super::DeadlineStream::new(server, super::Access::Browser, stop.clone());
        stop.store(true, Ordering::Release);
        assert!(crate::frame(&mut stream).is_err());
    }

    #[test]
    fn reader_that_never_consumes_cannot_hold_writer_forever() {
        use std::sync::{Arc, atomic::AtomicBool};
        use std::time::{Duration, Instant};
        use std::io::Write;
        let (_client, server) = tcp_pair();
        let mut stream = super::DeadlineStream::new(server, super::Access::Browser,
            Arc::new(AtomicBool::new(false)));
        stream.deadline = Instant::now() + Duration::from_millis(200);
        let chunk = [0; 64 * 1024];
        let error = loop {
            if let Err(error) = stream.write_all(&chunk) { break error; }
        };
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    }

    // Records are attributed to the account behind the connection. That account is
    // the operating system's answer, written by the server into every request; a
    // client naming one itself is overwritten, and an undetermined one leaves the key
    // empty rather than absent, so a handler never falls back to the client's value.
    #[test]
    fn the_caller_account_is_stamped_by_the_server_never_taken_from_the_client() {
        use std::sync::{Arc, Mutex, atomic::AtomicBool};
        for (account, expected) in [(Some("real-user".to_string()), "real-user"), (None, "")] {
            let (mut client, server) = tcp_pair();
            crate::write_frame(&mut client, &serde_json::json!({"op":"probe","caller":{"user":"spoofed"}})).unwrap();
            client.shutdown(std::net::Shutdown::Write).unwrap();
            let seen: Arc<Mutex<Option<serde_json::Value>>> = Arc::default();
            let sink = seen.clone();
            let handler: Arc<super::Handler> = Arc::new(move |_home, request| {
                *sink.lock().unwrap() = Some(request);
                Ok(serde_json::json!({"ok":true}))
            });
            let stream = super::DeadlineStream::new(server, super::Access::Browser, Arc::new(AtomicBool::new(false)));
            super::handle_limit(stream, std::path::Path::new("."), handler.as_ref(), account, 128 * 1024);
            let request = seen.lock().unwrap().clone().expect("the request reached the handler");
            assert_eq!(request["caller"]["user"], expected);
            assert_eq!(request["op"], "probe");
        }
    }

    // The account of a process is the one Windows names for its token: for this very
    // test process, the signed-in user running the tests.
    #[cfg(windows)]
    #[test]
    fn own_process_account_is_the_signed_in_user() {
        let sid = super::windows::process_sid(std::process::id()).expect("own SID resolves");
        let account = super::windows::sid_account(&sid).expect("own account resolves");
        assert_eq!(account.to_lowercase(), std::env::var("USERNAME").unwrap().to_lowercase());
    }

    #[test]
    fn one_caller_request_burst_does_not_spend_another_callers_budget() {
        let callers = Callers::default();
        let granted = (0..1000).filter(|_| callers.allow("session:7")).count();
        assert!(granted >= super::REQUEST_BURST as usize && granted < super::REQUEST_BURST as usize + 10, "burst not bounded: {granted}");
        assert!(!callers.allow("session:7"));
        assert!(callers.allow("session:8"), "another caller was starved");
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(callers.allow("session:7"), "the budget never refills");
    }

    #[test]
    fn one_caller_cannot_take_every_slot() {
        let callers = Callers::default();
        for _ in 0..MAX_CONNECTIONS_PER_CALLER {
            assert!(callers.admit("S-1-5-21-hostile"));
        }
        assert!(!callers.admit("S-1-5-21-hostile"));
        // A different local caller still gets served while the first is at its cap.
        assert!(callers.admit("S-1-5-21-legitimate"));
    }

    #[test]
    fn a_released_connection_frees_its_slot() {
        let callers = Callers::default();
        for _ in 0..MAX_CONNECTIONS_PER_CALLER {
            assert!(callers.admit("S-1-5-21-hostile"));
        }
        callers.release("S-1-5-21-hostile");
        assert!(callers.admit("S-1-5-21-hostile"));
        assert!(!callers.admit("S-1-5-21-hostile"));
    }

    #[test]
    fn undetermined_callers_share_one_budget_instead_of_escaping_the_cap() {
        let callers = Callers::default();
        for _ in 0..MAX_CONNECTIONS_PER_CALLER {
            assert!(callers.admit(UNKNOWN_CALLER));
        }
        assert!(!callers.admit(UNKNOWN_CALLER));
    }

    #[test]
    fn releasing_more_than_admitted_does_not_underflow() {
        let callers = Callers::default();
        assert!(callers.admit("S-1-5-21-hostile"));
        callers.release("S-1-5-21-hostile");
        callers.release("S-1-5-21-hostile");
        for _ in 0..MAX_CONNECTIONS_PER_CALLER {
            assert!(callers.admit("S-1-5-21-hostile"));
        }
        assert!(!callers.admit("S-1-5-21-hostile"));
    }
}
