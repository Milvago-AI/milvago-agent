//! Retired per-user scheduled tasks (the family before 2026-09-10). The PowerShell
//! transaction captured, disabled and restored them; since 2026-10-15 they are deleted
//! once proved Milvago's, and never restored: that family is gone for good. Deletion goes
//! through the Task Scheduler COM API, never `schtasks.exe` or a PowerShell child, which
//! endpoint protection reads as persistence tampering.
use crate::paths::{self, ADMINISTRATORS, SYSTEM};
use crate::win::{Failure, Result, fail};
use std::ffi::c_void;
use std::path::Path;

/// Same "can change it" rights as the installer path rule (`paths::WRITE_RIGHTS`).
const WRITE_RIGHTS: u32 = 0x500D_0156;

/// Each retired task name with its edition. Enterprise also clears Community's tasks: a
/// migration replaces that edition.
fn names(commercial: bool) -> Vec<(&'static str, &'static str)> {
    let mut names = vec![("Agent Community", "community"), ("Milvago Community Agent", "community"), ("Milvago Browser Watch", "community")];
    if commercial {
        names.extend([("Agent Commercial", "commercial"), ("Milvago Commercial Agent", "commercial")]);
    }
    names
}

/// `(?i)^(?:-NoProfile\s+)?(?:-NonInteractive\s+)?(?:-ExecutionPolicy\s+(?:Bypass|RemoteSigned)\s+)?(?:-WindowStyle\s+Hidden\s+)?-File\s+"<script>"\s+-Edition\s+<edition>\s*$`,
/// the PowerShell ownership pattern, without a regex engine. Each optional group starts
/// with its own literal and ends with mandatory whitespace, so taking it greedily never
/// loses a match the regex would find.
pub(crate) fn arguments_owned(arguments: &str, script: &str, edition: &str) -> bool {
    fn word<'a>(text: &'a str, literal: &str) -> Option<&'a str> {
        let head = text.get(..literal.len())?;
        head.eq_ignore_ascii_case(literal).then(|| &text[literal.len()..])
    }
    fn spaces(text: &str) -> Option<&str> {
        let rest = text.trim_start();
        (rest.len() < text.len()).then_some(rest)
    }
    let mut rest = arguments;
    // (switch, accepted values; none for a bare switch), in the pattern's order.
    let optional: [(&str, &[&str]); 4] = [("-NoProfile", &[]), ("-NonInteractive", &[]), ("-ExecutionPolicy", &["Bypass", "RemoteSigned"]), ("-WindowStyle", &["Hidden"])];
    for (switch, values) in optional {
        let Some(after) = word(rest, switch).and_then(spaces) else { continue };
        let taken = if values.is_empty() { Some(after) } else { values.iter().find_map(|v| word(after, v).and_then(spaces)) };
        if let Some(after) = taken {
            rest = after;
        }
    }
    let quoted = format!("\"{script}\"");
    let tail = word(rest, "-File").and_then(spaces).and_then(|r| word(r, &quoted)).and_then(spaces)
        .and_then(|r| word(r, "-Edition")).and_then(spaces).and_then(|r| word(r, edition));
    tail.is_some_and(|r| r.trim_start().is_empty())
}

/// The five predefined XML entities; any other reference makes the text unreadable here.
fn unescape(text: &str) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        let end = rest[at..].find(';')? + at;
        out.push(match &rest[at + 1..end] {
            "quot" => '"',
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "apos" => '\'',
            _ => return None,
        });
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    Some(out)
}
/// Text of the single `<name>` element in `body`; `None` if absent or repeated.
fn element(body: &str, name: &str) -> Option<String> {
    let (open, close) = (format!("<{name}>"), format!("</{name}>"));
    let start = body.find(&open)? + open.len();
    if body[start..].contains(&open) {
        return None;
    }
    unescape(&body[start..start + body[start..].find(&close)?])
}

/// The task definition (`IRegisteredTask::get_Xml`) is Milvago's: it has actions, and
/// every one is an `Exec` of Windows PowerShell running this edition's session script
/// with the arguments the retired package wrote. Anything unreadable is not proved.
pub(crate) fn definition_owned(xml: &str, shell: &str, script: &str, edition: &str) -> bool {
    let Some(start) = xml.find("<Actions") else { return false };
    if xml[start + 1..].contains("<Actions") {
        return false;
    }
    let Some(body_start) = xml[start..].find('>').map(|i| start + i + 1) else { return false };
    let Some(body_end) = xml[body_start..].find("</Actions>").map(|i| body_start + i) else { return false };
    let mut rest = xml[body_start..body_end].trim_start();
    let mut actions = 0;
    while !rest.is_empty() {
        // Only `<Exec>` or `<Exec Id="...">`: a COM handler, mail or message action is not ours.
        if !(rest.starts_with("<Exec>") || rest.starts_with("<Exec ")) {
            return false;
        }
        let Some(end) = rest.find("</Exec>") else { return false };
        let body = &rest[..end];
        let (Some(command), Some(arguments)) = (element(body, "Command"), element(body, "Arguments")) else { return false };
        if !command.eq_ignore_ascii_case(shell) || !arguments_owned(&arguments, script, edition) {
            return false;
        }
        actions += 1;
        rest = rest[end + "</Exec>".len()..].trim_start();
    }
    actions > 0
}

/// The task's security descriptor: owned by SYSTEM or Administrators, a DACL of basic
/// ACEs only, and no write grant to anyone else.
pub(crate) fn security_owned(sddl: &str) -> bool {
    let Ok((owner, Some(aces))) = paths::parse_sddl(sddl) else { return false };
    let trusted = [SYSTEM, ADMINISTRATORS];
    owner.is_some_and(|o| trusted.contains(&o.as_str()))
        && !aces.iter().any(|ace| ace.allow && !trusted.contains(&ace.sid.as_str()) && ace.mask & WRITE_RIGHTS != 0)
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Milvago's definition under trusted security: deleted.
    Remove,
    /// Not Milvago's definition: any user can create a root task under a retired name, so
    /// such a task is left alone and logged, never a reason to refuse every installation.
    Ignore,
    /// Milvago's definition that someone else may rewrite: neither deleted (it may not be
    /// what it seems by the time it runs) nor ignored (it runs the retired agent).
    Refuse,
}
pub(crate) fn verdict(xml: &str, sddl: &str, shell: &str, script: &str, edition: &str) -> Verdict {
    if !definition_owned(xml, shell, script, edition) {
        Verdict::Ignore
    } else if security_owned(sddl) {
        Verdict::Remove
    } else {
        Verdict::Refuse
    }
}

// ---- Task Scheduler 2.0 COM, declared by hand like the rest of the Win32 calls ----

#[repr(C)]
struct Guid(u32, u16, u16, [u8; 8]);
const CLSID_TASK_SCHEDULER: Guid = Guid(0x0F87_369F, 0xA4E5, 0x4CFC, [0xBD, 0x3E, 0x73, 0xE6, 0x15, 0x45, 0x72, 0xDD]);
const IID_ITASK_SERVICE: Guid = Guid(0x2FAB_A4C7, 0x4DA9, 0x4013, [0x96, 0x97, 0x20, 0xCC, 0x3F, 0xD4, 0x0F, 0x85]);
/// VARIANT: VT_EMPTY when zeroed; 16 bytes on x86, 24 on x64.
#[repr(C)]
#[derive(Default)]
struct Variant {
    vt: u16,
    reserved: [u16; 3],
    data: [usize; 2],
}

#[link(name = "ole32")]
unsafe extern "system" {
    fn CoInitializeEx(reserved: *mut c_void, model: u32) -> i32;
    fn CoUninitialize();
    fn CoCreateInstance(clsid: *const Guid, outer: *mut c_void, context: u32, iid: *const Guid, object: *mut *mut c_void) -> i32;
}
#[link(name = "oleaut32")]
unsafe extern "system" {
    fn SysAllocString(text: *const u16) -> *mut u16;
    fn SysFreeString(text: *mut u16);
    fn SysStringLen(text: *const u16) -> u32;
}

struct Apartment(bool);
impl Drop for Apartment {
    fn drop(&mut self) {
        if self.0 {
            unsafe { CoUninitialize() };
        }
    }
}
struct Bstr(*mut u16);
impl Bstr {
    fn new(text: &str) -> Self {
        let wide: Vec<u16> = text.encode_utf16().chain(Some(0)).collect();
        Self(unsafe { SysAllocString(wide.as_ptr()) })
    }
    fn text(&self) -> String {
        if self.0.is_null() {
            return String::new();
        }
        String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(self.0, SysStringLen(self.0) as usize) })
    }
}
impl Drop for Bstr {
    fn drop(&mut self) {
        unsafe { SysFreeString(self.0) };
    }
}
/// An interface pointer; slot numbers count IUnknown (3) and IDispatch (4) first.
struct Interface(*mut c_void);
impl Interface {
    fn slot(&self, index: usize) -> usize {
        unsafe { *(*(self.0 as *const *const usize)).add(index) }
    }
    fn get_bstr(&self, index: usize) -> std::result::Result<Bstr, i32> {
        let call: extern "system" fn(*mut c_void, *mut *mut u16) -> i32 = unsafe { std::mem::transmute(self.slot(index)) };
        let mut text = std::ptr::null_mut();
        let hr = call(self.0, &mut text);
        if hr < 0 { Err(hr) } else { Ok(Bstr(text)) }
    }
}
impl Drop for Interface {
    fn drop(&mut self) {
        let release: extern "system" fn(*mut c_void) -> u32 = unsafe { std::mem::transmute(self.slot(2)) };
        release(self.0);
    }
}
fn checked(hr: i32, step: &'static str) -> Result<()> {
    if hr < 0 { Err(Failure { step, detail: format!("hresult={:#010x}", hr as u32) }) } else { Ok(()) }
}

/// The root task folder, through a connected `ITaskService`.
fn root_folder() -> Result<(Interface, Interface)> {
    let mut service = std::ptr::null_mut();
    // CLSCTX_INPROC_SERVER.
    checked(unsafe { CoCreateInstance(&CLSID_TASK_SCHEDULER, std::ptr::null_mut(), 1, &IID_ITASK_SERVICE, &mut service) }, "Task Scheduler unavailable")?;
    let service = Interface(service);
    // ITaskService::Connect(serverName, user, domain, password): all VT_EMPTY, this machine.
    let connect: extern "system" fn(*mut c_void, Variant, Variant, Variant, Variant) -> i32 = unsafe { std::mem::transmute(service.slot(10)) };
    checked(connect(service.0, Variant::default(), Variant::default(), Variant::default(), Variant::default()), "Task Scheduler unavailable")?;
    // ITaskService::GetFolder.
    let get_folder: extern "system" fn(*mut c_void, *mut u16, *mut *mut c_void) -> i32 = unsafe { std::mem::transmute(service.slot(7)) };
    let (path, mut folder) = (Bstr::new("\\"), std::ptr::null_mut());
    checked(get_folder(service.0, path.0, &mut folder), "Task Scheduler unavailable")?;
    Ok((service, Interface(folder)))
}

/// Delete every retired per-user task of this edition proved Milvago's (definition and
/// security descriptor). A task that is not Milvago's is left and logged; one that is but
/// whose security is untrusted leaves them all in place and the transaction refuses.
/// Returns the names removed.
pub fn remove_legacy(commercial: bool, programs: &Path) -> Result<Vec<&'static str>> {
    // The scheduler's own cache answers "is there any" without starting COM at all.
    let present: Vec<(&str, &str)> = names(commercial).into_iter()
        .filter(|(name, _)| crate::win::reg_key_exists(&format!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\{name}")))
        .collect();
    if present.is_empty() {
        return Ok(Vec::new());
    }
    let system_root = std::env::var("SystemRoot").map_err(|_| Failure { step: "System root unavailable", detail: String::new() })?;
    let shell = format!(r"{system_root}\System32\WindowsPowerShell\v1.0\powershell.exe");
    // COINIT_MULTITHREADED; an apartment the process already has is used as it is.
    let hr = unsafe { CoInitializeEx(std::ptr::null_mut(), 0) };
    let _apartment = Apartment(hr >= 0);
    let (_service, folder) = root_folder()?;
    // IRegisteredTask slots: get_Xml 20, GetSecurityDescriptor 21, Stop 23.
    let get_task: extern "system" fn(*mut c_void, *mut u16, *mut *mut c_void) -> i32 = unsafe { std::mem::transmute(folder.slot(13)) };
    let (mut proved, mut ignored) = (Vec::new(), Vec::new());
    for (name, edition) in present {
        let (bstr, mut task) = (Bstr::new(name), std::ptr::null_mut());
        let hr = get_task(folder.0, bstr.0, &mut task);
        // ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND: a stale cache entry, nothing to remove.
        if matches!(hr as u32, 0x8007_0002 | 0x8007_0003) {
            continue;
        }
        checked(hr, "Historical task unavailable")?;
        let task = Interface(task);
        let folder_name = if edition == "commercial" { "Commercial" } else { "Browser" };
        let script = programs.join("Milvago").join(folder_name).join("agent-session.ps1");
        let xml = task.get_bstr(20).map_err(|_| Failure { step: "Historical task unavailable", detail: String::new() })?.text();
        let get_security: extern "system" fn(*mut c_void, i32, *mut *mut u16) -> i32 = unsafe { std::mem::transmute(task.slot(21)) };
        let mut sddl = std::ptr::null_mut();
        // OWNER | GROUP | DACL.
        checked(get_security(task.0, 7, &mut sddl), "Historical task security unavailable")?;
        match verdict(&xml, &Bstr(sddl).text(), &shell, &script.to_string_lossy(), edition) {
            Verdict::Remove => proved.push((name, task)),
            Verdict::Ignore => ignored.push(name),
            Verdict::Refuse => return fail("Historical per-user Milvago task security is untrusted; remove it manually"),
        }
    }
    let delete: extern "system" fn(*mut c_void, *mut u16, i32) -> i32 = unsafe { std::mem::transmute(folder.slot(15)) };
    let mut removed = Vec::new();
    for (name, task) in proved {
        // A running instance would keep the retired agent alive past the deletion.
        let stop: extern "system" fn(*mut c_void, i32) -> i32 = unsafe { std::mem::transmute(task.slot(23)) };
        let _ = stop(task.0, 0);
        drop(task);
        checked(delete(folder.0, Bstr::new(name).0, 0), "Historical task could not be removed")?;
        removed.push(name);
    }
    if !ignored.is_empty() {
        crate::win::event(1007, false, &format!("Scheduled tasks named like retired Milvago tasks but not Milvago's were left in place: {}.", ignored.join(", ")));
    }
    if !removed.is_empty() {
        crate::win::event(1007, false, &format!("Retired per-user Milvago scheduled tasks removed: {}.", removed.join(", ")));
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHELL: &str = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    const SCRIPT: &str = r"C:\Program Files\Milvago\Browser\agent-session.ps1";

    fn task(actions: &str) -> String {
        format!(r#"<?xml version="1.0" encoding="UTF-16"?><Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType></Principal></Principals><Actions Context="Author">{actions}</Actions></Task>"#)
    }
    fn exec(command: &str, arguments: &str) -> String {
        format!("\n    <Exec>\n      <Command>{command}</Command>\n      <Arguments>{arguments}</Arguments>\n    </Exec>\n  ")
    }

    #[test]
    fn the_retired_session_arguments_are_recognised_in_every_written_form() {
        for good in [
            format!(r#"-File "{SCRIPT}" -Edition community"#),
            format!(r#"-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "{SCRIPT}" -Edition community"#),
            format!(r#"-noprofile  -executionpolicy remotesigned -file "{}" -edition COMMUNITY  "#, SCRIPT.to_uppercase()),
        ] {
            assert!(arguments_owned(&good, SCRIPT, "community"), "{good}");
        }
        for bad in [
            format!(r#"-File "{SCRIPT}" -Edition commercial"#),
            format!(r#"-File "{SCRIPT}" -Edition community -Command evil"#),
            format!(r#"-ExecutionPolicy Unrestricted -File "{SCRIPT}" -Edition community"#),
            format!(r#"-WindowStyle Hidden -NoProfile -File "{SCRIPT}" -Edition community"#),
            format!(r#"-File {SCRIPT} -Edition community"#),
            r#"-File "C:\Users\Public\agent-session.ps1" -Edition community"#.to_owned(),
            format!(r#"-File "{SCRIPT}"-Edition community"#),
            String::new(),
        ] {
            assert!(!arguments_owned(&bad, SCRIPT, "community"), "{bad}");
        }
    }

    #[test]
    fn only_a_definition_made_of_the_session_exec_qualifies() {
        let arguments = format!("-NoProfile -File &quot;{SCRIPT}&quot; -Edition community");
        assert!(definition_owned(&task(&exec(SHELL, &arguments)), SHELL, SCRIPT, "community"));
        // Twice the same action is still ours; a literal quote is the same text.
        let literal = format!(r#"-File "{SCRIPT}" -Edition community"#);
        assert!(definition_owned(&task(&(exec(SHELL, &arguments) + &exec(&SHELL.to_lowercase(), &literal))), SHELL, SCRIPT, "community"));
        // Another executable, another action type, no action, or an unknown entity is not.
        assert!(!definition_owned(&task(&exec(r"C:\Users\Public\powershell.exe", &arguments)), SHELL, SCRIPT, "community"));
        assert!(!definition_owned(&task(&format!("\"{SHELL}\"")), SHELL, SCRIPT, "community"));
        let com = r#"<ComHandler><ClassId>{00000000-0000-0000-0000-000000000000}</ClassId></ComHandler>"#;
        assert!(!definition_owned(&task(&(exec(SHELL, &arguments) + com)), SHELL, SCRIPT, "community"));
        assert!(!definition_owned(&task(""), SHELL, SCRIPT, "community"));
        assert!(!definition_owned(&task(&exec(SHELL, &format!("-File &#34;{SCRIPT}&#34; -Edition community"))), SHELL, SCRIPT, "community"));
        assert!(!definition_owned("<Task></Task>", SHELL, SCRIPT, "community"));
        // The commercial edition's script is not the community one.
        assert!(!definition_owned(&task(&exec(SHELL, &arguments)), SHELL, r"C:\Program Files\Milvago\Commercial\agent-session.ps1", "community"));
    }

    #[test]
    fn the_hand_declared_scheduler_slots_answer_as_documented() {
        // Read-only: connect, look a missing task up, read a built-in one's definition.
        let hr = unsafe { CoInitializeEx(std::ptr::null_mut(), 0) };
        let _apartment = Apartment(hr >= 0);
        let (_service, folder) = root_folder().unwrap();
        let get_task: extern "system" fn(*mut c_void, *mut u16, *mut *mut c_void) -> i32 = unsafe { std::mem::transmute(folder.slot(13)) };
        let mut task = std::ptr::null_mut();
        let hr = get_task(folder.0, Bstr::new("milvago-test-no-such-task").0, &mut task);
        assert!(matches!(hr as u32, 0x8007_0002 | 0x8007_0003), "hresult={:#010x}", hr as u32);
        let mut task = std::ptr::null_mut();
        let hr = get_task(folder.0, Bstr::new(r"Microsoft\Windows\Defrag\ScheduledDefrag").0, &mut task);
        if hr >= 0 {
            let task = Interface(task);
            assert!(task.get_bstr(20).unwrap().text().contains("<Actions"), "get_Xml slot");
            assert_eq!(task.get_bstr(8).unwrap().text(), r"\Microsoft\Windows\Defrag\ScheduledDefrag", "get_Path slot");
            let get_security: extern "system" fn(*mut c_void, i32, *mut *mut u16) -> i32 = unsafe { std::mem::transmute(task.slot(21)) };
            let mut sddl = std::ptr::null_mut();
            if get_security(task.0, 7, &mut sddl) >= 0 {
                assert!(paths::parse_sddl(&Bstr(sddl).text()).unwrap().0.is_some(), "GetSecurityDescriptor slot");
            }
        }
    }

    #[test]
    fn a_foreign_task_is_ignored_and_only_an_exposed_milvago_task_refuses() {
        let ours = task(&exec(SHELL, &format!("-File &quot;{SCRIPT}&quot; -Edition community")));
        let foreign = task(&exec(r"C:\Users\Public\tool.exe", ""));
        let trusted = "O:BAG:SYD:(A;;FA;;;BA)(A;;FA;;;SY)";
        let exposed = "O:S-1-5-21-1-2-3-1001G:SYD:(A;;FA;;;S-1-5-21-1-2-3-1001)";
        assert_eq!(verdict(&ours, trusted, SHELL, SCRIPT, "community"), Verdict::Remove);
        assert_eq!(verdict(&ours, exposed, SHELL, SCRIPT, "community"), Verdict::Refuse);
        // A standard user's task under a retired name blocks nothing, whatever its security.
        assert_eq!(verdict(&foreign, exposed, SHELL, SCRIPT, "community"), Verdict::Ignore);
        assert_eq!(verdict(&foreign, trusted, SHELL, SCRIPT, "community"), Verdict::Ignore);
    }

    #[test]
    fn only_a_task_administrators_own_and_alone_can_write_qualifies() {
        assert!(security_owned("O:BAG:SYD:(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;S-1-5-21-1-2-3-1001)"));
        assert!(!security_owned("O:S-1-5-21-1-2-3-1001G:SYD:(A;;FA;;;BA)(A;;FA;;;SY)"));
        assert!(!security_owned("O:BAG:SYD:(A;;FA;;;BA)(A;;FA;;;S-1-5-21-1-2-3-1001)"));
        assert!(!security_owned("O:BAG:SY"), "a null DACL qualified");
        assert!(!security_owned("not an sddl"));
    }
}
