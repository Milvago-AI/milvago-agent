//! The few Win32 calls the installer actions need, declared directly like the rest of
//! the code base. Every registry access uses the 64-bit view: the MSI runs the action
//! as a 64-bit process, and the agent and browsers read the same view.
use std::ffi::c_void;
use std::time::{Duration, Instant};

pub type Result<T> = std::result::Result<T, Failure>;

/// `step` is a fixed phrase, safe for the public event log. `detail` may carry process
/// output and goes to the action's standard error only.
#[derive(Debug)]
pub struct Failure {
    pub step: &'static str,
    pub detail: String,
}
pub fn fail<T>(step: &'static str) -> Result<T> {
    Err(Failure { step, detail: String::new() })
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}
fn from_wide(data: &[u16]) -> String {
    String::from_utf16_lossy(&data[..data.iter().position(|&c| c == 0).unwrap_or(data.len())])
}

const HKLM: isize = 0x80000002u32 as i32 as isize;
const KEY_READ_64: u32 = 0x20119;
const RRF_RT_ANY_64: u32 = 0x0001_ffff;
const REG_SZ: u32 = 1;
const REG_DWORD: u32 = 4;
const REG_MULTI_SZ: u32 = 7;

#[link(name = "advapi32")]
unsafe extern "system" {
    fn RegOpenKeyExW(key: isize, sub: *const u16, options: u32, access: u32, result: *mut isize) -> i32;
    fn RegGetValueW(key: isize, sub: *const u16, value: *const u16, flags: u32, kind: *mut u32, data: *mut c_void, size: *mut u32) -> i32;
    fn RegEnumValueW(key: isize, index: u32, name: *mut u16, name_len: *mut u32, reserved: *mut u32, kind: *mut u32, data: *mut u8, data_len: *mut u32) -> i32;
    fn RegCloseKey(key: isize) -> i32;
    fn OpenSCManagerW(machine: *const u16, database: *const u16, access: u32) -> isize;
    fn OpenServiceW(manager: isize, name: *const u16, access: u32) -> isize;
    fn CloseServiceHandle(handle: isize) -> i32;
    fn QueryServiceConfigW(handle: isize, config: *mut c_void, size: u32, needed: *mut u32) -> i32;
    fn QueryServiceObjectSecurity(handle: isize, info: u32, descriptor: *mut c_void, size: u32, needed: *mut u32) -> i32;
    fn GetSecurityDescriptorDacl(descriptor: *const c_void, present: *mut i32, dacl: *mut *mut c_void, defaulted: *mut i32) -> i32;
    fn GetAce(acl: *const c_void, index: u32, ace: *mut *mut c_void) -> i32;
    fn ConvertSidToStringSidW(sid: *const c_void, text: *mut *mut u16) -> i32;
    fn RegisterEventSourceW(server: *const u16, source: *const u16) -> isize;
    fn ReportEventW(log: isize, kind: u16, category: u16, id: u32, sid: *const c_void, count: u16, size: u32, strings: *const *const u16, data: *const c_void) -> i32;
    fn DeregisterEventSource(log: isize) -> i32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetLastError() -> u32;
    fn LocalFree(p: *mut c_void) -> *mut c_void;
}

/// A value of `HKLM\<path>`: strings (expanded) and multi-strings as text, DWORDs as
/// their decimal. `None` when the key or the value is absent.
fn reg_raw(path: &str, value: &str) -> Option<(u32, Vec<u16>)> {
    let (sub, name) = (wide(path), wide(value));
    let mut size = 0u32;
    let mut kind = 0u32;
    if unsafe { RegGetValueW(HKLM, sub.as_ptr(), name.as_ptr(), RRF_RT_ANY_64, &mut kind, std::ptr::null_mut(), &mut size) } != 0 {
        return None;
    }
    let mut data = vec![0u16; (size as usize).div_ceil(2) + 1];
    let mut size = (data.len() * 2) as u32;
    if unsafe { RegGetValueW(HKLM, sub.as_ptr(), name.as_ptr(), RRF_RT_ANY_64, &mut kind, data.as_mut_ptr().cast(), &mut size) } != 0 {
        return None;
    }
    data.truncate(size as usize / 2);
    Some((kind, data))
}
pub fn reg_string(path: &str, value: &str) -> Option<String> {
    let (kind, data) = reg_raw(path, value)?;
    // REG_EXPAND_SZ comes back expanded.
    matches!(kind, REG_SZ | 2).then(|| from_wide(&data))
}
/// A multi-string joined without separator, as PowerShell's `-join ''` did.
pub fn reg_multi_joined(path: &str, value: &str) -> Option<String> {
    let (kind, data) = reg_raw(path, value)?;
    match kind {
        REG_MULTI_SZ => Some(data.split(|&c| c == 0).map(String::from_utf16_lossy).collect()),
        REG_SZ => Some(from_wide(&data)),
        _ => None,
    }
}
pub fn reg_dword(path: &str, value: &str) -> Option<u32> {
    let (kind, data) = reg_raw(path, value)?;
    (kind == REG_DWORD && data.len() >= 2).then(|| u32::from(data[0]) | (u32::from(data[1]) << 16))
}
pub fn reg_key_exists(path: &str) -> bool {
    let sub = wide(path);
    let mut key = 0isize;
    let opened = unsafe { RegOpenKeyExW(HKLM, sub.as_ptr(), 0, KEY_READ_64, &mut key) } == 0;
    if opened {
        unsafe { RegCloseKey(key) };
    }
    opened
}
/// String values of a key, as (name, data). Empty when the key is absent.
pub fn reg_string_values(path: &str) -> Vec<(String, String)> {
    let sub = wide(path);
    let mut key = 0isize;
    let mut values = Vec::new();
    if unsafe { RegOpenKeyExW(HKLM, sub.as_ptr(), 0, KEY_READ_64, &mut key) } != 0 {
        return values;
    }
    for index in 0..4096 {
        let (mut name, mut name_len) = ([0u16; 256], 256u32);
        let mut data = [0u16; 2048];
        let (mut kind, mut data_len) = (0u32, (data.len() * 2) as u32);
        let status = unsafe { RegEnumValueW(key, index, name.as_mut_ptr(), &mut name_len, std::ptr::null_mut(),
            &mut kind, data.as_mut_ptr().cast(), &mut data_len) };
        if status == 259 {
            break; // ERROR_NO_MORE_ITEMS
        }
        if status == 0 && kind == REG_SZ {
            values.push((String::from_utf16_lossy(&name[..name_len as usize]),
                from_wide(&data[..(data_len as usize / 2).min(data.len())])));
        }
    }
    unsafe { RegCloseKey(key) };
    values
}

#[repr(C)]
struct QueryServiceConfig {
    kind: u32,
    start: u32,
    error_control: u32,
    binary: *mut u16,
    group: *mut u16,
    tag: u32,
    dependencies: *mut u16,
    account: *mut u16,
    display: *mut u16,
}

pub struct Service(isize);
impl Drop for Service {
    fn drop(&mut self) {
        unsafe { CloseServiceHandle(self.0) };
    }
}
pub struct ServiceConfig {
    pub start: u32,
    pub account: String,
}

pub const SERVICE_AUTO_START: u32 = 2;

impl Service {
    /// `None` when no such service is installed.
    pub fn open(name: &str) -> Result<Option<Service>> {
        let manager = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), 1) };
        if manager == 0 {
            return fail("Service control manager unavailable");
        }
        let name = wide(name);
        // SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_START | READ_CONTROL.
        let handle = unsafe { OpenServiceW(manager, name.as_ptr(), 0x0002_0015) };
        let error = unsafe { GetLastError() };
        unsafe { CloseServiceHandle(manager) };
        match (handle, error) {
            (0, 1060) => Ok(None), // ERROR_SERVICE_DOES_NOT_EXIST
            (0, _) => fail("Service could not be opened"),
            (handle, _) => Ok(Some(Service(handle))),
        }
    }
    pub fn config(&self) -> Result<ServiceConfig> {
        let mut needed = 0u32;
        unsafe { QueryServiceConfigW(self.0, std::ptr::null_mut(), 0, &mut needed) };
        let mut buffer = vec![0u64; (needed as usize).div_ceil(8) + 1];
        if unsafe { QueryServiceConfigW(self.0, buffer.as_mut_ptr().cast(), (buffer.len() * 8) as u32, &mut needed) } == 0 {
            return fail("Service configuration unavailable");
        }
        let config = unsafe { &*buffer.as_ptr().cast::<QueryServiceConfig>() };
        let account = if config.account.is_null() {
            String::new()
        } else {
            let mut length = 0;
            while unsafe { *config.account.add(length) } != 0 { length += 1; }
            String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(config.account, length) })
        };
        Ok(ServiceConfig { start: config.start, account })
    }
    /// The allowed ACEs of the service's DACL, as (SID, access mask).
    pub fn allowed_aces(&self) -> Result<Vec<(String, u32)>> {
        let mut needed = 0u32;
        unsafe { QueryServiceObjectSecurity(self.0, 4, std::ptr::null_mut(), 0, &mut needed) };
        let mut buffer = vec![0u64; (needed as usize).div_ceil(8) + 1];
        if unsafe { QueryServiceObjectSecurity(self.0, 4, buffer.as_mut_ptr().cast(), (buffer.len() * 8) as u32, &mut needed) } == 0 {
            return fail("Update applier permissions unavailable");
        }
        let (mut present, mut dacl, mut defaulted) = (0i32, std::ptr::null_mut(), 0i32);
        if unsafe { GetSecurityDescriptorDacl(buffer.as_ptr().cast(), &mut present, &mut dacl, &mut defaulted) } == 0
            || present == 0 || dacl.is_null()
        {
            return fail("Update applier permissions unavailable");
        }
        let count = unsafe { *dacl.cast::<u8>().add(4).cast::<u16>() };
        let mut aces = Vec::new();
        for index in 0..u32::from(count) {
            let mut ace = std::ptr::null_mut();
            if unsafe { GetAce(dacl, index, &mut ace) } == 0 {
                return fail("Update applier permissions unavailable");
            }
            // ACCESS_ALLOWED_ACE: header (type, flags, size), mask, SID.
            if unsafe { *ace.cast::<u8>() } != 0 {
                continue;
            }
            let mask = unsafe { *ace.cast::<u8>().add(4).cast::<u32>() };
            let mut text = std::ptr::null_mut();
            if unsafe { ConvertSidToStringSidW(ace.cast::<u8>().add(8).cast(), &mut text) } == 0 {
                return fail("Update applier permissions unavailable");
            }
            let mut length = 0;
            while unsafe { *text.add(length) } != 0 { length += 1; }
            aces.push((String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) }), mask));
            unsafe { LocalFree(text.cast()) };
        }
        Ok(aces)
    }
}

/// Run one of the installed agent binaries and return its standard output. Its reason
/// for refusing is on standard error; both are kept for the action's own error output,
/// never for the public event log.
pub fn run(step: &'static str, executable: &std::path::Path, arguments: &[&str], deadline: Instant) -> Result<String> {
    use std::io::Read;
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    let mut child = Command::new(executable)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
        .spawn()
        .map_err(|error| Failure { step, detail: error.to_string() })?;
    let mut stdout = child.stdout.take().expect("piped");
    let mut stderr = child.stderr.take().expect("piped");
    let out = std::thread::spawn(move || { let mut text = String::new(); let _ = stdout.read_to_string(&mut text); text });
    let err = std::thread::spawn(move || { let mut text = String::new(); let _ = stderr.read_to_string(&mut text); text });
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Failure { step, detail: "timed out".into() });
            }
        }
    };
    let (out, err) = (out.join().unwrap_or_default(), err.join().unwrap_or_default());
    let err = err.split_whitespace().collect::<Vec<_>>().join(" ");
    if !status.success() {
        return Err(Failure { step, detail: format!("exit {:?}: {} {}", status.code(), err, out.trim()) });
    }
    if !err.is_empty() {
        event(1004, false, &format!("{step}: {err}"));
    }
    Ok(out.trim().to_owned())
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenProcessToken(process: isize, access: u32, token: *mut isize) -> i32;
    fn LookupPrivilegeValueW(system: *const u16, name: *const u16, luid: *mut [u32; 2]) -> i32;
    // TOKEN_PRIVILEGES with one entry: count, LUID (low, high), attributes — 4-byte aligned.
    fn AdjustTokenPrivileges(token: isize, disable: i32, state: *const [u32; 4], length: u32, previous: *mut [u32; 4], returned: *mut u32) -> i32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentProcess() -> isize;
    fn CloseHandle(handle: isize) -> i32;
}

/// A privilege enabled for the life of the value (SeRestorePrivilege to restore a saved
/// foreign owner, SeShutdownPrivilege to configure a reboot recovery action); the
/// token's previous state is put back on drop.
pub struct Privilege(isize, [u32; 4]);
impl Privilege {
    pub fn enable(name: &str) -> Result<Self> {
        let mut token = 0;
        // TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY.
        if unsafe { OpenProcessToken(GetCurrentProcess(), 0x28, &mut token) } == 0 {
            return fail("Privilege token unavailable");
        }
        let text = wide(name);
        let mut luid = [0u32; 2];
        let mut previous = [0u32; 4];
        let mut returned = 0u32;
        let ok = unsafe { LookupPrivilegeValueW(std::ptr::null(), text.as_ptr(), &mut luid) } != 0
            && unsafe { AdjustTokenPrivileges(token, 0, &[1, luid[0], luid[1], 2], 16, &mut previous, &mut returned) } != 0
            && unsafe { GetLastError() } == 0;
        if !ok {
            unsafe { CloseHandle(token) };
            return fail("Privilege not assigned");
        }
        Ok(Self(token, previous))
    }
}
impl Drop for Privilege {
    fn drop(&mut self) {
        let mut ignored = [0u32; 4];
        let mut returned = 0u32;
        unsafe { AdjustTokenPrivileges(self.0, 0, &self.1, 16, &mut ignored, &mut returned) };
        unsafe { CloseHandle(self.0) };
    }
}

const EVENT_SOURCE_KEY: &str = r"SYSTEM\CurrentControlSet\Services\EventLog\Application\Milvago";
/// The message file `EventLog.CreateEventSource` registers: .NET's EventLogMessages.dll,
/// whose every message is "%1", so an event reads as the text written. Relative to
/// %SystemRoot%, 64-bit runtime first; `None` when neither runtime is present.
fn event_message_file(system_root: &str, exists: impl Fn(&str) -> bool) -> Option<String> {
    ["Framework64", "Framework"].iter()
        .map(|folder| format!(r"Microsoft.NET\{folder}\v4.0.30319\EventLogMessages.dll"))
        .find(|relative| exists(&format!(r"{system_root}\{relative}")))
        .map(|relative| format!(r"%SystemRoot%\{relative}"))
}
/// Register the `Milvago` source of the Application log when it is absent, as every
/// PowerShell action did (`CreateEventSource`). The agent, running as NetworkService,
/// reports its own log failures to this source and cannot create the key itself; without
/// it Event Viewer shows "the description cannot be found". Never fatal.
pub fn register_event_source() {
    if reg_key_exists(EVENT_SOURCE_KEY) {
        return;
    }
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    if let Some(file) = event_message_file(&root, |path| std::path::Path::new(path).is_file()) {
        let value = crate::reg::RegValue { name: "EventMessageFile".into(), kind: "ExpandString".into(), data: serde_json::Value::String(file) };
        let _ = crate::reg::write_value(EVENT_SOURCE_KEY, &value);
    }
}

/// Application log, source `Milvago` (readable from any session). Best effort.
pub fn event(id: u32, error: bool, message: &str) {
    let source = wide("Milvago");
    let log = unsafe { RegisterEventSourceW(std::ptr::null(), source.as_ptr()) };
    if log == 0 {
        return;
    }
    let sanitized: String = message.chars().map(|c| if c.is_control() { ' ' } else { c }).take(800).collect();
    let text = wide(&sanitized);
    let strings = [text.as_ptr()];
    // EVENTLOG_ERROR_TYPE or EVENTLOG_INFORMATION_TYPE.
    unsafe { ReportEventW(log, if error { 1 } else { 4 }, 0, id, std::ptr::null(), 1, 0, strings.as_ptr(), std::ptr::null()) };
    unsafe { DeregisterEventSource(log) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_event_source_uses_the_dotnet_message_file_that_exists() {
        let only = |present: &'static str| move |path: &str| path == present;
        assert_eq!(event_message_file(r"C:\Windows", only(r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\EventLogMessages.dll")).as_deref(),
            Some(r"%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\EventLogMessages.dll"));
        assert_eq!(event_message_file(r"D:\Win", only(r"D:\Win\Microsoft.NET\Framework\v4.0.30319\EventLogMessages.dll")).as_deref(),
            Some(r"%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\EventLogMessages.dll"));
        assert_eq!(event_message_file(r"C:\Windows", |_| false), None);
        // On this machine (any supported Windows ships .NET Framework 4.8).
        let root = std::env::var("SystemRoot").unwrap();
        assert!(event_message_file(&root, |path| std::path::Path::new(path).is_file()).is_some());
    }
}
