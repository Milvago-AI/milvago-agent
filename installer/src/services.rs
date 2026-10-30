//! Service configuration through the service control manager, never `sc.exe`. Port of
//! `deploy/installer-service-recovery.ps1` and of the `sc.exe` calls of
//! `configure-agent.ps1` / `installer-transaction.ps1`. Snapshot records keep the field
//! names the PowerShell transaction wrote. Every write is read back and compared.
use crate::win::{Failure, Result, fail};
use serde::{Deserialize, Serialize};
use std::ffi::c_void;
use std::time::{Duration, Instant};

const LIMIT: usize = 8192;

#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenSCManagerW(machine: *const u16, database: *const u16, access: u32) -> isize;
    fn OpenServiceW(manager: isize, name: *const u16, access: u32) -> isize;
    fn CloseServiceHandle(handle: isize) -> i32;
    fn CreateServiceW(manager: isize, name: *const u16, display: *const u16, access: u32, kind: u32, start: u32, error: u32,
        binary: *const u16, group: *const u16, tag: *mut u32, dependencies: *const u16, account: *const u16, password: *const u16) -> isize;
    fn ChangeServiceConfigW(service: isize, kind: u32, start: u32, error: u32, binary: *const u16, group: *const u16,
        tag: *mut u32, dependencies: *const u16, account: *const u16, password: *const u16, display: *const u16) -> i32;
    fn QueryServiceConfigW(service: isize, config: *mut c_void, size: u32, needed: *mut u32) -> i32;
    fn QueryServiceConfig2W(service: isize, level: u32, buffer: *mut c_void, size: u32, needed: *mut u32) -> i32;
    fn ChangeServiceConfig2W(service: isize, level: u32, info: *const c_void) -> i32;
    fn QueryServiceObjectSecurity(service: isize, info: u32, descriptor: *mut c_void, size: u32, needed: *mut u32) -> i32;
    fn SetServiceObjectSecurity(service: isize, info: u32, descriptor: *const c_void) -> i32;
    fn ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor: *const c_void, revision: u32, info: u32, text: *mut *mut u16, length: *mut u32) -> i32;
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl: *const u16, revision: u32, descriptor: *mut *mut c_void, size: *mut u32) -> i32;
    fn ControlService(service: isize, control: u32, status: *mut [u32; 7]) -> i32;
    fn QueryServiceStatusEx(service: isize, level: u32, buffer: *mut u8, size: u32, needed: *mut u32) -> i32;
    fn StartServiceW(service: isize, count: u32, args: *const *const u16) -> i32;
    fn DeleteService(service: isize) -> i32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetLastError() -> u32;
    fn LocalFree(p: *mut c_void) -> *mut c_void;
    fn CloseHandle(handle: isize) -> i32;
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> isize;
    fn QueryFullProcessImageNameW(process: isize, flags: u32, name: *mut u16, size: *mut u32) -> i32;
    fn TerminateProcess(process: isize, code: u32) -> i32;
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}
fn error(step: &'static str) -> Failure {
    Failure { step, detail: format!("win32={}", unsafe { GetLastError() }) }
}
fn valid_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 256 || name.contains('\0') {
        return fail("Invalid service name");
    }
    Ok(())
}
fn valid_text(value: &str) -> Result<()> {
    if value.encode_utf16().count() > 4095 || value.contains('\0') {
        return fail("Invalid service text");
    }
    Ok(())
}

struct Handle(isize);
impl Drop for Handle {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe { CloseServiceHandle(self.0) };
        }
    }
}
fn manager(access: u32) -> Result<Handle> {
    let handle = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), access) };
    if handle == 0 { Err(error("Service control manager unavailable")) } else { Ok(Handle(handle)) }
}
/// `None` when the service does not exist.
fn open(name: &str, access: u32) -> Result<Option<Handle>> {
    valid_name(name)?;
    let scm = manager(1)?; // SC_MANAGER_CONNECT
    let text = wide(name);
    let handle = unsafe { OpenServiceW(scm.0, text.as_ptr(), access) };
    if handle != 0 {
        return Ok(Some(Handle(handle)));
    }
    if unsafe { GetLastError() } == 1060 { Ok(None) } else { Err(error("Service could not be opened")) }
}
fn open_existing(name: &str, access: u32) -> Result<Handle> {
    open(name, access)?.ok_or(Failure { step: "Service does not exist", detail: name.into() })
}
pub fn exists(name: &str) -> Result<bool> {
    Ok(open(name, 4)?.is_some()) // SERVICE_QUERY_STATUS
}

/// A MULTI_SZ inside a query buffer (a list of NUL-terminated strings, ending on an empty
/// one); null means absent and reads as empty.
fn read_multi_string(buffer: &[u64], pointer: *const u16) -> Result<Vec<String>> {
    if pointer.is_null() {
        return Ok(Vec::new());
    }
    let start = buffer.as_ptr() as usize;
    let offset = (pointer as usize).wrapping_sub(start);
    let bytes = buffer.len() * 8;
    if (pointer as usize) < start || offset >= bytes || offset % 2 != 0 {
        return fail("Service response pointer exceeds buffer");
    }
    let available = ((bytes - offset) / 2).min(4096);
    let slice = unsafe { std::slice::from_raw_parts(pointer, available) };
    let mut items = Vec::new();
    let mut cursor = 0;
    loop {
        let end = slice[cursor..].iter().position(|&c| c == 0).map(|p| p + cursor)
            .ok_or(Failure { step: "Unterminated service string", detail: String::new() })?;
        if end == cursor {
            return Ok(items); // empty entry: end of the MULTI_SZ
        }
        if items.len() >= 256 {
            return fail("Too many service privileges");
        }
        items.push(String::from_utf16_lossy(&slice[cursor..end]));
        cursor = end + 1;
    }
}

/// A string inside a query buffer; null means absent and reads as empty.
fn read_string(buffer: &[u64], pointer: *const u16) -> Result<String> {
    if pointer.is_null() {
        return Ok(String::new());
    }
    let start = buffer.as_ptr() as usize;
    let offset = (pointer as usize).wrapping_sub(start);
    let bytes = buffer.len() * 8;
    if (pointer as usize) < start || offset >= bytes || offset % 2 != 0 {
        return fail("Service response pointer exceeds buffer");
    }
    let available = ((bytes - offset) / 2).min(4096);
    let slice = unsafe { std::slice::from_raw_parts(pointer, available) };
    let end = slice.iter().position(|&c| c == 0).ok_or(Failure { step: "Unterminated service string", detail: String::new() })?;
    Ok(String::from_utf16_lossy(&slice[..end]))
}

#[repr(C)]
struct RawConfig {
    kind: u32,
    start: u32,
    error: u32,
    binary: *const u16,
    group: *const u16,
    tag: u32,
    dependencies: *const u16,
    account: *const u16,
    display: *const u16,
}

/// `ConfigurationRecord` of the PowerShell transaction.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Configuration {
    #[serde(rename = "Type")]
    pub kind: u32,
    pub start: u32,
    pub error: u32,
    pub binary: String,
    pub group: String,
    pub account: String,
    pub display: String,
    pub dependencies: Vec<String>,
    pub delayed_auto: bool,
}
impl Configuration {
    fn validate(&self) -> Result<()> {
        if self.dependencies.len() > 256 {
            return fail("Invalid service configuration");
        }
        for value in [&self.binary, &self.group, &self.account, &self.display] {
            valid_text(value)?;
        }
        if self.kind != 0x10 || !(2..=4).contains(&self.start) || self.error > 3 || self.binary.is_empty()
            || self.display.is_empty() || self.display.len() > 256 || (self.delayed_auto && self.start != 2)
        {
            return fail("Unsupported service configuration");
        }
        if !["LocalSystem", r"NT AUTHORITY\LocalService", r"NT AUTHORITY\NetworkService"].iter().any(|a| a.eq_ignore_ascii_case(&self.account)) {
            return fail("A custom service account cannot be restored without its credential");
        }
        for dependency in &self.dependencies {
            valid_text(dependency)?;
            if dependency.is_empty() || dependency.len() > 256 {
                return fail("Invalid service dependency");
            }
        }
        Ok(())
    }
    fn same(&self, other: &Self) -> bool {
        self.kind == other.kind && self.start == other.start && self.error == other.error && self.binary == other.binary
            && self.group == other.group && self.account.eq_ignore_ascii_case(&other.account) && self.display == other.display
            && self.delayed_auto == other.delayed_auto && self.dependencies.len() == other.dependencies.len()
            && self.dependencies.iter().zip(&other.dependencies).all(|(a, b)| a.eq_ignore_ascii_case(b))
    }
}

pub fn read_configuration(name: &str) -> Result<Configuration> {
    let service = open_existing(name, 1)?; // SERVICE_QUERY_CONFIG
    let mut buffer = vec![0u64; LIMIT / 8];
    let mut needed = 0u32;
    if unsafe { QueryServiceConfigW(service.0, buffer.as_mut_ptr().cast(), LIMIT as u32, &mut needed) } == 0 {
        return Err(error("Service configuration unavailable"));
    }
    let raw = unsafe { &*buffer.as_ptr().cast::<RawConfig>() };
    if raw.tag != 0 {
        return fail("A service load-order tag cannot be recreated exactly");
    }
    let mut dependencies = Vec::new();
    let mut pointer = raw.dependencies;
    if !pointer.is_null() {
        loop {
            let item = read_string(&buffer, pointer)?;
            if item.is_empty() {
                break;
            }
            if dependencies.len() >= 256 {
                return fail("Too many service dependencies");
            }
            pointer = unsafe { pointer.add(item.encode_utf16().count() + 1) };
            dependencies.push(item);
        }
    }
    let mut record = Configuration {
        kind: raw.kind, start: raw.start, error: raw.error,
        binary: read_string(&buffer, raw.binary)?, group: read_string(&buffer, raw.group)?,
        account: read_string(&buffer, raw.account)?, display: read_string(&buffer, raw.display)?,
        dependencies, delayed_auto: false,
    };
    let mut flag = [0u64; 1];
    if unsafe { QueryServiceConfig2W(service.0, 3, flag.as_mut_ptr().cast(), 8, &mut needed) } == 0 {
        return Err(error("Service delayed start unavailable"));
    }
    let delayed = flag[0] as u32;
    if delayed > 1 {
        return fail("Invalid delayed start flag");
    }
    record.delayed_auto = delayed != 0;
    // Refuse an unrestorable baseline before anything is changed.
    record.validate()?;
    Ok(record)
}

/// Create the service, or change it to exactly `record`.
pub fn write_configuration(name: &str, record: &Configuration) -> Result<()> {
    valid_name(name)?;
    record.validate()?;
    let mut dependencies: Vec<u16> = Vec::new();
    for dependency in &record.dependencies {
        dependencies.extend(dependency.encode_utf16());
        dependencies.push(0);
    }
    // A double-NUL empty list removes old dependencies; NULL would leave them.
    dependencies.extend([0, 0]);
    let (binary, group, account, display, empty) = (wide(&record.binary), wide(&record.group), wide(&record.account), wide(&record.display), wide(""));
    let scm = manager(3)?; // CONNECT | CREATE_SERVICE
    let text = wide(name);
    let create = || unsafe { CreateServiceW(scm.0, text.as_ptr(), display.as_ptr(), 2, record.kind, record.start, record.error,
        binary.as_ptr(), group.as_ptr(), std::ptr::null_mut(), dependencies.as_ptr(), account.as_ptr(), empty.as_ptr()) };
    let mut service = unsafe { OpenServiceW(scm.0, text.as_ptr(), 2) }; // SERVICE_CHANGE_CONFIG
    if service == 0 {
        if unsafe { GetLastError() } != 1060 {
            return Err(error("Service could not be opened"));
        }
        service = create();
        if service == 0 {
            return Err(error("Service could not be created"));
        }
    } else if unsafe { ChangeServiceConfigW(service, record.kind, record.start, record.error, binary.as_ptr(), group.as_ptr(),
        std::ptr::null_mut(), dependencies.as_ptr(), account.as_ptr(), empty.as_ptr(), display.as_ptr()) } == 0
    {
        let code = unsafe { GetLastError() };
        unsafe { CloseServiceHandle(service) };
        if !marked_for_deletion(code) {
            return Err(Failure { step: "Service configuration could not be changed", detail: format!("win32={code}") });
        }
        // A rollback or an uninstall deleted the service while its process still ran:
        // it stays, unconfigurable, until that process exits. PowerShell's sc.exe failed
        // here with 1072 on every later installation until a reboot.
        await_deletion(name, Duration::from_secs(30))?;
        service = create();
        if service == 0 {
            return Err(error("Service could not be created"));
        }
    }
    let service = Handle(service);
    let flag = u32::from(record.delayed_auto);
    if unsafe { ChangeServiceConfig2W(service.0, 3, std::ptr::from_ref(&flag).cast()) } == 0 {
        return Err(error("Service delayed start could not be changed"));
    }
    if !record.same(&read_configuration(name)?) {
        return fail("Service configuration readback differs");
    }
    Ok(())
}

/// `RecoveryRecord` of the PowerShell transaction (snake_case JSON).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Recovery {
    pub reset_period: u32,
    #[serde(default)]
    pub reboot_message: String,
    #[serde(default)]
    pub command: String,
    pub actions: Vec<RecoveryAction>,
    pub non_crash_failures: bool,
}
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryAction {
    #[serde(rename = "type")]
    pub kind: u32,
    pub delay: u32,
}
#[repr(C)]
struct RawFailureActions {
    reset: u32,
    reboot: *const u16,
    command: *const u16,
    count: u32,
    actions: *const [u32; 2],
}

pub fn read_recovery(name: &str) -> Result<Recovery> {
    let service = open_existing(name, 1)?;
    let mut buffer = vec![0u64; LIMIT / 8];
    let mut needed = 0u32;
    if unsafe { QueryServiceConfig2W(service.0, 2, buffer.as_mut_ptr().cast(), LIMIT as u32, &mut needed) } == 0 {
        return Err(error("Service recovery unavailable"));
    }
    let raw = unsafe { &*buffer.as_ptr().cast::<RawFailureActions>() };
    if raw.count > 256 {
        return fail("Too many service recovery actions");
    }
    let mut actions = Vec::new();
    if raw.count != 0 {
        let start = buffer.as_ptr() as usize;
        let offset = (raw.actions as usize).wrapping_sub(start);
        if raw.actions.is_null() || (raw.actions as usize) < start || offset + raw.count as usize * 8 > LIMIT {
            return fail("Service recovery response pointer exceeds buffer");
        }
        for index in 0..raw.count as usize {
            let [kind, delay] = unsafe { *raw.actions.add(index) };
            if kind > 3 {
                return fail("Unknown service recovery action");
            }
            actions.push(RecoveryAction { kind, delay });
        }
    }
    let record = Recovery {
        reset_period: raw.reset,
        reboot_message: read_string(&buffer, raw.reboot)?,
        command: read_string(&buffer, raw.command)?,
        actions,
        non_crash_failures: false,
    };
    let mut flag = [0u64; 1];
    if unsafe { QueryServiceConfig2W(service.0, 4, flag.as_mut_ptr().cast(), 8, &mut needed) } == 0 {
        return Err(error("Service recovery flag unavailable"));
    }
    let flag = flag[0] as u32;
    if flag > 1 {
        return fail("Invalid service recovery flag");
    }
    Ok(Recovery { non_crash_failures: flag != 0, ..record })
}

pub fn write_recovery(name: &str, record: &Recovery) -> Result<()> {
    if record.actions.len() > 256 {
        return fail("Invalid service recovery record");
    }
    valid_text(&record.reboot_message)?;
    valid_text(&record.command)?;
    if record.actions.is_empty() && record.reset_period != 0 {
        return fail("An empty action array cannot preserve a nonzero reset period");
    }
    if record.actions.iter().any(|action| action.kind > 3) {
        return fail("Invalid service recovery action");
    }
    let reboot = record.actions.iter().any(|action| action.kind == 2);
    let service = open_existing(name, 0x12)?; // SERVICE_CHANGE_CONFIG | SERVICE_START
    let _privilege = if reboot { Some(crate::win::Privilege::enable("SeShutdownPrivilege")?) } else { None };
    // Empty strings remove previous values; an allocated empty array removes the
    // actions and reset period, where NULL would silently keep them.
    let (message, command) = (wide(&record.reboot_message), wide(&record.command));
    let mut actions: Vec<[u32; 2]> = record.actions.iter().map(|a| [a.kind, a.delay]).collect();
    if actions.is_empty() {
        actions.push([0, 0]);
    }
    let info = RawFailureActions { reset: record.reset_period, reboot: message.as_ptr(), command: command.as_ptr(),
        count: record.actions.len() as u32, actions: actions.as_ptr() };
    if unsafe { ChangeServiceConfig2W(service.0, 2, std::ptr::from_ref(&info).cast()) } == 0 {
        return Err(error("Service recovery could not be changed"));
    }
    let flag = u32::from(record.non_crash_failures);
    if unsafe { ChangeServiceConfig2W(service.0, 4, std::ptr::from_ref(&flag).cast()) } == 0 {
        return Err(error("Service recovery flag could not be changed"));
    }
    if read_recovery(name)? != *record {
        return fail("Service recovery readback differs");
    }
    Ok(())
}

/// Display name and description, read back.
pub fn write_metadata(name: &str, display: &str, description: &str) -> Result<()> {
    valid_text(display)?;
    valid_text(description)?;
    if display.len() > 256 {
        return fail("Service metadata exceeds limit");
    }
    let service = open_existing(name, 2)?;
    let display_text = wide(display);
    if unsafe { ChangeServiceConfigW(service.0, u32::MAX, u32::MAX, u32::MAX, std::ptr::null(), std::ptr::null(),
        std::ptr::null_mut(), std::ptr::null(), std::ptr::null(), std::ptr::null(), display_text.as_ptr()) } == 0
    {
        return Err(error("Service display name could not be changed"));
    }
    let description_text = wide(description);
    let info: *const u16 = description_text.as_ptr();
    if unsafe { ChangeServiceConfig2W(service.0, 1, std::ptr::from_ref(&info).cast()) } == 0 {
        return Err(error("Service description could not be changed"));
    }
    drop(service);
    let service = open_existing(name, 1)?;
    let mut buffer = vec![0u64; LIMIT / 8];
    let mut needed = 0u32;
    if unsafe { QueryServiceConfig2W(service.0, 1, buffer.as_mut_ptr().cast(), LIMIT as u32, &mut needed) } == 0 {
        return Err(error("Service description unavailable"));
    }
    let actual = read_string(&buffer, unsafe { *buffer.as_ptr().cast::<*const u16>() })?;
    if actual != description || read_configuration(name)?.display != display {
        return fail("Service metadata readback differs");
    }
    Ok(())
}

/// `sc sidtype <name> unrestricted`.
pub fn set_sid_unrestricted(name: &str) -> Result<()> {
    set_sid_type(name, 1)
}

pub(crate) fn sid_type(name: &str) -> Result<u32> {
    let service = open_existing(name, 1)?;
    let mut kind = 0u32;
    let mut needed = 0u32;
    if unsafe { QueryServiceConfig2W(service.0, 5, std::ptr::from_mut(&mut kind).cast(), 4, &mut needed) } == 0 {
        return Err(error("Service SID type unavailable"));
    }
    if !matches!(kind, 0 | 1 | 3) { return fail("Unsupported service SID type"); }
    Ok(kind)
}

pub(crate) fn set_sid_type(name: &str, kind: u32) -> Result<()> {
    if !matches!(kind, 0 | 1 | 3) { return fail("Unsupported service SID type"); }
    let service = open_existing(name, 2)?;
    if unsafe { ChangeServiceConfig2W(service.0, 5, std::ptr::from_ref(&kind).cast()) } == 0 {
        return Err(error("Service SID type could not be changed"));
    }
    drop(service);
    if sid_type(name)? != kind { return fail("Service SID type readback differs"); }
    Ok(())
}

/// `SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO` (level 6): the exact set of privileges the
/// service's token is restricted to.
pub fn required_privileges(name: &str) -> Result<Vec<String>> {
    let service = open_existing(name, 1)?; // SERVICE_QUERY_CONFIG
    let mut buffer = vec![0u64; LIMIT / 8];
    let mut needed = 0u32;
    if unsafe { QueryServiceConfig2W(service.0, 6, buffer.as_mut_ptr().cast(), LIMIT as u32, &mut needed) } == 0 {
        return Err(error("Service privileges unavailable"));
    }
    read_multi_string(&buffer, unsafe { *buffer.as_ptr().cast::<*const u16>() })
}

/// `sc privs <name> <p1>/<p2>/...`: SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO (level 6), a
/// MULTI_SZ. NetworkService holds SeImpersonatePrivilege, which turns any code execution
/// in a service running as that account into SYSTEM; a service that only needs to
/// identify pipe clients (SecurityIdentification needs no privilege) keeps none of that.
pub fn set_required_privileges(name: &str, privileges: &[&str]) -> Result<()> {
    let mut text: Vec<u16> = Vec::new();
    for privilege in privileges {
        text.extend(privilege.encode_utf16());
        text.push(0);
    }
    text.push(0);
    let service = open_existing(name, 2)?; // SERVICE_CHANGE_CONFIG
    let info: *const u16 = text.as_ptr();
    if unsafe { ChangeServiceConfig2W(service.0, 6, std::ptr::from_ref(&info).cast()) } == 0 {
        return Err(error("Service privilege configuration could not be changed"));
    }
    drop(service);
    if required_privileges(name)?.iter().map(String::as_str).ne(privileges.iter().copied()) {
        return fail("Service privilege readback differs");
    }
    Ok(())
}

/// The service's DACL as SDDL (`sc sdshow`, DACL part).
pub fn sddl(name: &str) -> Result<String> {
    let service = open_existing(name, 0x0002_0000)?; // READ_CONTROL
    let mut buffer = vec![0u64; LIMIT / 8];
    let mut needed = 0u32;
    if unsafe { QueryServiceObjectSecurity(service.0, 4, buffer.as_mut_ptr().cast(), LIMIT as u32, &mut needed) } == 0 {
        return Err(error("Service permissions unavailable"));
    }
    let (mut text, mut length) = (std::ptr::null_mut(), 0u32);
    if unsafe { ConvertSecurityDescriptorToStringSecurityDescriptorW(buffer.as_ptr().cast(), 1, 4, &mut text, &mut length) } == 0 {
        return Err(error("Service permissions unavailable"));
    }
    let mut end = 0;
    while unsafe { *text.add(end) } != 0 { end += 1; }
    let value = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, end) });
    unsafe { LocalFree(text.cast()) };
    Ok(value)
}

/// `sc sdset <name> <sddl>`: replace the service's DACL. SYSTEM owns service objects
/// and keeps WRITE_DAC whatever the DACL grants.
pub fn set_sddl(name: &str, sddl: &str) -> Result<()> {
    let service = open_existing(name, 0x0004_0000)?; // WRITE_DAC
    let text = wide(sddl);
    let mut descriptor = std::ptr::null_mut();
    if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(text.as_ptr(), 1, &mut descriptor, std::ptr::null_mut()) } == 0 {
        return fail("Invalid service permission descriptor");
    }
    let applied = unsafe { SetServiceObjectSecurity(service.0, 4, descriptor) } != 0;
    let failure = error("Service permissions could not be changed");
    unsafe { LocalFree(descriptor) };
    if applied { Ok(()) } else { Err(failure) }
}

/// Current state and process of a service (SERVICE_STATUS_PROCESS).
fn status(name: &str) -> Result<Option<(u32, u32)>> {
    let Some(service) = open(name, 4)? else { return Ok(None) };
    let mut buffer = [0u8; 36];
    let mut needed = 0u32;
    if unsafe { QueryServiceStatusEx(service.0, 0, buffer.as_mut_ptr(), 36, &mut needed) } == 0 {
        return Err(error("Service status unavailable"));
    }
    let word = |i: usize| u32::from_le_bytes([buffer[i * 4], buffer[i * 4 + 1], buffer[i * 4 + 2], buffer[i * 4 + 3]]);
    Ok(Some((word(1), word(7))))
}
/// `name=state/exit/pid` for a failure report: a service that stopped right after its
/// start shows its Win32 or service-specific exit code here.
pub fn summary(name: &str) -> String {
    let Ok(Some(service)) = open(name, 4) else { return format!("{name}=absent") };
    let mut buffer = [0u8; 36];
    let mut needed = 0u32;
    if unsafe { QueryServiceStatusEx(service.0, 0, buffer.as_mut_ptr(), 36, &mut needed) } == 0 {
        return format!("{name}=unknown");
    }
    let word = |i: usize| u32::from_le_bytes([buffer[i * 4], buffer[i * 4 + 1], buffer[i * 4 + 2], buffer[i * 4 + 3]]);
    let state = match word(1) { 1 => "stopped", 2 => "starting", 3 => "stopping", 4 => "running", _ => "other" };
    format!("{name}={state}/exit {}/{}/pid {}", word(3), word(4), word(7))
}
pub fn running(name: &str) -> Result<bool> {
    Ok(status(name)?.is_some_and(|(state, _)| state == 4))
}

/// ERROR_SERVICE_MARKED_FOR_DELETE.
fn marked_for_deletion(code: u32) -> bool {
    code == 1072
}
/// Stop a service already deleted and wait until the service control manager forgets it.
fn await_deletion(name: &str, timeout: Duration) -> Result<()> {
    let _ = request_stop(name);
    let deadline = Instant::now() + timeout;
    while open(name, 4)?.is_some() {
        if Instant::now() >= deadline {
            return Err(Failure { step: "Service is marked for deletion and still in use (close the Services console or restart Windows)", detail: name.into() });
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Ok(())
}

/// What `start` does next, from the state it reads (`SERVICE_STATUS.dwCurrentState`) and
/// the start requests it has made.
#[derive(Debug, PartialEq, Eq)]
enum StartStep {
    Done,
    Wait,
    /// Stopped although a start was asked: once more. StartService answers 1056 for a
    /// service still STOP_PENDING (an applier exiting to run its new binPath, a recovery
    /// in progress), which reads as "already running" and then shows STOPPED.
    StartAgain,
    Failed,
}
const START_ATTEMPTS: u32 = 3;
fn start_step(state: u32, attempts: u32) -> StartStep {
    match state {
        4 => StartStep::Done,
        1 if attempts < START_ATTEMPTS => StartStep::StartAgain,
        1 => StartStep::Failed,
        _ => StartStep::Wait,
    }
}

/// `Start-Service`: start and wait until running. A service that keeps stopping after
/// it was started still fails.
pub fn start(name: &str, timeout: Duration) -> Result<()> {
    let service = open_existing(name, 0x14)?; // SERVICE_START | SERVICE_QUERY_STATUS
    let request = || -> Result<()> {
        if unsafe { StartServiceW(service.0, 0, std::ptr::null()) } == 0 && unsafe { GetLastError() } != 1056 {
            return Err(error("Service could not be started"));
        }
        Ok(())
    };
    request()?;
    let (deadline, mut attempts) = (Instant::now() + timeout, 1);
    loop {
        let state = status(name)?.map_or(1, |(state, _)| state);
        match start_step(state, attempts) {
            StartStep::Done => return Ok(()),
            StartStep::Failed => return fail("Service stopped during start"),
            _ if Instant::now() >= deadline => return fail("Service did not start in time"),
            StartStep::StartAgain => {
                std::thread::sleep(Duration::from_millis(500));
                request()?;
                attempts += 1;
            }
            StartStep::Wait => std::thread::sleep(Duration::from_millis(250)),
        }
    }
}

/// Ask a service to stop (1061/1062 — already stopping or stopped — are not failures).
pub fn request_stop(name: &str) -> Result<()> {
    let Some(service) = open(name, 0x20)? else { return Ok(()) }; // SERVICE_STOP
    let mut state = [0u32; 7];
    if unsafe { ControlService(service.0, 1, &mut state) } == 0 && !matches!(unsafe { GetLastError() }, 1061 | 1062) {
        return Err(error("Service could not be stopped"));
    }
    Ok(())
}
/// Wait until stopped or absent.
pub fn wait_stopped(name: &str, timeout: Duration) -> Result<bool> {
    let deadline = Instant::now() + timeout;
    loop {
        match status(name)? {
            None | Some((1, _)) => return Ok(true),
            _ if Instant::now() >= deadline => return Ok(false),
            _ => std::thread::sleep(Duration::from_millis(500)),
        }
    }
}

fn terminate_if_image(pid: u32, image: &str) {
    // PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION.
    let process = unsafe { OpenProcess(0x1001, 0, pid) };
    if process == 0 {
        return;
    }
    let mut name = [0u16; 1024];
    let mut size = name.len() as u32;
    if unsafe { QueryFullProcessImageNameW(process, 0, name.as_mut_ptr(), &mut size) } != 0 {
        let path = String::from_utf16_lossy(&name[..size as usize]);
        let stem = std::path::Path::new(&path).file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        if stem.eq_ignore_ascii_case(image) {
            unsafe { TerminateProcess(process, 1) };
        }
    }
    unsafe { CloseHandle(process) };
}

/// `Remove-OwnedService`: uninstall always wins. The DACL is rewritten first
/// (Administrators get DELETE, nobody may start it again), the stop is bounded to 30 s
/// because the update applier defers a stop while busy, then only the service's own
/// process is terminated. 1072 (already marked for deletion) is a success.
pub fn remove_owned(name: &str, image: &str) -> Result<()> {
    if !exists(name)? {
        return Ok(());
    }
    set_sddl(name, "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)")?;
    let _ = stop_owned(name, image, Duration::from_secs(30))?;
    delete(name)
}
/// Stop within `timeout`; past it, only the service's own process (`image`, its file
/// stem) is terminated. Whether it is stopped (or gone) at the end.
pub fn stop_owned(name: &str, image: &str, timeout: Duration) -> Result<bool> {
    let _ = request_stop(name);
    if wait_stopped(name, timeout)? {
        return Ok(true);
    }
    if let Some((state, pid)) = status(name)? && state != 1 && pid > 0 {
        terminate_if_image(pid, image);
    }
    wait_stopped(name, Duration::from_secs(10))
}
/// `sc delete`, 1072 accepted.
pub fn delete(name: &str) -> Result<()> {
    let Some(service) = open(name, 0x0001_0000)? else { return Ok(()) }; // DELETE
    if unsafe { DeleteService(service.0) } == 0 && unsafe { GetLastError() } != 1072 {
        return Err(error("Service could not be deleted"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readers_parse_a_real_system_service_without_changing_it() {
        // Read-only: query rights on a service every Windows has.
        assert!(exists("EventLog").unwrap());
        assert!(!exists("milvago-installer-test-absent").unwrap());
        let recovery = read_recovery("EventLog").unwrap();
        assert!(recovery.actions.iter().all(|action| action.kind <= 3));
        assert!(sddl("EventLog").unwrap().starts_with("D:"));
        // A shared-process service is not something the installer can restore.
        assert_eq!(read_configuration("EventLog").unwrap_err().step, "Unsupported service configuration");
    }

    #[test]
    fn a_start_retries_a_service_found_stopped_and_gives_up_after_three_requests() {
        assert_eq!(start_step(4, 1), StartStep::Done);
        // START_PENDING, STOP_PENDING: wait for the service to settle.
        assert_eq!(start_step(2, 1), StartStep::Wait);
        assert_eq!(start_step(3, 1), StartStep::Wait);
        // Stopped after the first request (1056 on a STOP_PENDING applier): ask again.
        assert_eq!(start_step(1, 1), StartStep::StartAgain);
        assert_eq!(start_step(1, 2), StartStep::StartAgain);
        // A service that keeps stopping still fails.
        assert_eq!(start_step(1, 3), StartStep::Failed);
    }

    #[test]
    fn only_a_service_marked_for_deletion_is_recreated() {
        assert!(marked_for_deletion(1072));
        // Access denied or an invalid parameter is reported, never worked around.
        assert!(!marked_for_deletion(5) && !marked_for_deletion(87) && !marked_for_deletion(1060));
        // An absent service needs no wait.
        await_deletion("milvago-installer-test-absent", Duration::ZERO).unwrap();
    }
}
