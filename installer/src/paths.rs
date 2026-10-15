//! Installer path boundary. Port of `deploy/installer-paths.ps1`: reject an existing
//! hostile object rather than take ownership of a tree while a former owner can still
//! mutate its children; set permissions and copy through the same opened, verified
//! handle so a concurrent hard link or junction cannot be substituted.
use crate::win::{Failure, Result, fail};
use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub const SYSTEM: &str = "S-1-5-18";
pub const ADMINISTRATORS: &str = "S-1-5-32-544";
pub const NETWORK_SERVICE: &str = "S-1-5-20";
pub const AUTHENTICATED_USERS: &str = "S-1-5-11";
const TRUSTED_INSTALLER: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
const CREATOR_OWNER: &str = "S-1-3-0";
/// Owner Rights: replaces the implicit right an object's owner has to rewrite its own
/// DACL, for a file a NetworkService service creates (owned by NetworkService, shared by
/// every NetworkService service) — see `private_sddl`.
const OWNER_RIGHTS: &str = "S-1-3-4";
const PATH_UNAVAILABLE: &str = "Installer path unavailable";
/// Every right that lets a principal change an object or what it contains.
const WRITE_RIGHTS: u32 = 0x500D_0156;
const REPARSE: u32 = 0x400;

#[link(name = "advapi32")]
unsafe extern "system" {
    fn GetNamedSecurityInfoW(name: *const u16, kind: u32, info: u32, owner: *mut *mut c_void, group: *mut *mut c_void,
        dacl: *mut *mut c_void, sacl: *mut *mut c_void, descriptor: *mut *mut c_void) -> u32;
    fn GetAce(acl: *const c_void, index: u32, ace: *mut *mut c_void) -> i32;
    fn ConvertSidToStringSidW(sid: *const c_void, text: *mut *mut u16) -> i32;
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl: *const u16, revision: u32, descriptor: *mut *mut c_void, size: *mut u32) -> i32;
    fn GetSecurityDescriptorControl(descriptor: *const c_void, control: *mut u16, revision: *mut u32) -> i32;
    fn GetSecurityDescriptorOwner(descriptor: *const c_void, owner: *mut *mut c_void, defaulted: *mut i32) -> i32;
    fn GetSecurityDescriptorGroup(descriptor: *const c_void, group: *mut *mut c_void, defaulted: *mut i32) -> i32;
    fn GetSecurityDescriptorDacl(descriptor: *const c_void, present: *mut i32, dacl: *mut *mut c_void, defaulted: *mut i32) -> i32;
    fn SetKernelObjectSecurity(handle: isize, info: u32, descriptor: *const c_void) -> i32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn LocalFree(p: *mut c_void) -> *mut c_void;
    fn CreateFileW(name: *const u16, access: u32, share: u32, security: *const c_void, disposition: u32, flags: u32, template: isize) -> isize;
    fn CloseHandle(handle: isize) -> i32;
    fn GetFileInformationByHandle(handle: isize, info: *mut FileInformation) -> i32;
    fn GetFinalPathNameByHandleW(handle: isize, path: *mut u16, length: u32, flags: u32) -> u32;
    fn GetLastError() -> u32;
    fn CreateDirectoryW(path: *const u16, security: *const SecurityAttributes) -> i32;
    fn ReplaceFileW(replaced: *const u16, replacement: *const u16, backup: *const u16, flags: u32, exclude: *mut c_void, reserved: *mut c_void) -> i32;
    fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
    fn LockFile(handle: isize, low: u32, high: u32, bytes_low: u32, bytes_high: u32) -> i32;
    fn UnlockFile(handle: isize, low: u32, high: u32, bytes_low: u32, bytes_high: u32) -> i32;
}

#[repr(C)]
#[derive(Default)]
struct FileInformation {
    attributes: u32,
    // FILETIMEs are two DWORDs: 4-byte aligned, never u64.
    creation: [u32; 2],
    access: [u32; 2],
    write: [u32; 2],
    volume: u32,
    size_high: u32,
    size_low: u32,
    links: u32,
    index_high: u32,
    index_low: u32,
}
#[repr(C)]
struct SecurityAttributes {
    length: u32,
    descriptor: *mut c_void,
    inherit: i32,
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}
fn sid_text(sid: *const c_void) -> Option<String> {
    let mut text = std::ptr::null_mut();
    if sid.is_null() || unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return None;
    }
    let mut length = 0;
    while unsafe { *text.add(length) } != 0 { length += 1; }
    let value = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) });
    unsafe { LocalFree(text.cast()) };
    Some(value)
}
fn same(a: &Path, b: &Path) -> bool {
    a.as_os_str().to_string_lossy().eq_ignore_ascii_case(&b.as_os_str().to_string_lossy())
}

pub fn program_files() -> Result<PathBuf> {
    std::env::var_os("ProgramW6432").or_else(|| std::env::var_os("ProgramFiles")).map(PathBuf::from)
        .ok_or(Failure { step: "Program Files unavailable", detail: String::new() })
}
pub fn program_data() -> Result<PathBuf> {
    std::env::var_os("ProgramData").map(PathBuf::from)
        .ok_or(Failure { step: "ProgramData unavailable", detail: String::new() })
}

pub struct Ace {
    pub sid: String,
    pub mask: u32,
    pub allow: bool,
    pub inherit_only: bool,
}
pub struct Security {
    pub owner: String,
    pub aces: Vec<Ace>,
}

/// Owner and DACL of an existing object. A null DACL grants everyone everything.
pub fn security(path: &Path, null_step: &'static str) -> Result<Security> {
    let name = wide(path);
    let (mut owner, mut dacl, mut descriptor) = (std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut());
    // SE_FILE_OBJECT; OWNER | DACL.
    let status = unsafe { GetNamedSecurityInfoW(name.as_ptr(), 1, 5, &mut owner, std::ptr::null_mut(), &mut dacl, std::ptr::null_mut(), &mut descriptor) };
    if status != 0 {
        return Err(Failure { step: "Installer path permissions unavailable", detail: format!("{} (Win32 error {status})", path.display()) });
    }
    let result = (|| {
        if dacl.is_null() {
            return fail(null_step);
        }
        let owner = sid_text(owner).ok_or(Failure { step: "Installer path permissions unavailable", detail: String::new() })?;
        Ok(Security { owner, aces: aces_of(dacl)? })
    })();
    unsafe { LocalFree(descriptor) };
    result
}
fn aces_of(dacl: *mut c_void) -> Result<Vec<Ace>> {
    let count = unsafe { *dacl.cast::<u8>().add(4).cast::<u16>() };
    let mut aces = Vec::new();
    for index in 0..u32::from(count) {
        let mut ace = std::ptr::null_mut();
        if unsafe { GetAce(dacl, index, &mut ace) } == 0 {
            return fail("Installer path permissions unavailable");
        }
        let (kind, flags) = unsafe { (*ace.cast::<u8>(), *ace.cast::<u8>().add(1)) };
        // Only the basic allow/deny ACEs exist on files; anything else is refused.
        if kind > 1 {
            return fail("Installer path permissions unavailable");
        }
        aces.push(Ace {
            sid: sid_text(unsafe { ace.cast::<u8>().add(8).cast() }).ok_or(Failure { step: "Installer path permissions unavailable", detail: String::new() })?,
            mask: unsafe { *ace.cast::<u8>().add(4).cast::<u32>() },
            allow: kind == 0,
            inherit_only: flags & 0x08 != 0,
        });
    }
    Ok(aces)
}
/// Owner and DACL (`None`: null DACL) of a security descriptor in SDDL form, parsed by
/// Windows itself, so a decision on a saved or repaired SDDL reads it as the kernel will.
pub fn parse_sddl(sddl: &str) -> Result<(Option<String>, Option<Vec<Ace>>)> {
    let descriptor = descriptor(sddl)?;
    let (mut owner, mut defaulted) = (std::ptr::null_mut(), 0i32);
    unsafe { GetSecurityDescriptorOwner(descriptor.0, &mut owner, &mut defaulted) };
    let (mut present, mut dacl) = (0i32, std::ptr::null_mut());
    unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted) };
    let aces = if present == 0 || dacl.is_null() { None } else { Some(aces_of(dacl)?) };
    Ok((sid_text(owner), aces))
}

/// Owner, group and DACL of an object as SDDL (`(Get-Acl).Sddl`), for a snapshot that
/// `set_acl` restores exactly.
pub fn sddl_of(path: &Path) -> Result<String> {
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor: *const c_void, revision: u32, info: u32, text: *mut *mut u16, length: *mut u32) -> i32;
    }
    let name = wide(path);
    let mut descriptor = std::ptr::null_mut();
    // OWNER | GROUP | DACL.
    if unsafe { GetNamedSecurityInfoW(name.as_ptr(), 1, 7, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), &mut descriptor) } != 0 {
        return fail("Installer path permissions unavailable");
    }
    let (mut text, mut length) = (std::ptr::null_mut(), 0u32);
    let converted = unsafe { ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, 1, 7, &mut text, &mut length) } != 0;
    unsafe { LocalFree(descriptor) };
    if !converted {
        return fail("Installer path permissions unavailable");
    }
    let mut end = 0;
    while unsafe { *text.add(end) } != 0 { end += 1; }
    let value = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, end) });
    unsafe { LocalFree(text.cast()) };
    Ok(value)
}

/// `Plain`: no existing component of the path, up to the drive root, is a reparse point.
pub fn plain(path: &Path) -> Result<()> {
    for part in path.ancestors() {
        if reparse(part)? == Some(true) {
            return fail("Redirected installer path refused");
        }
    }
    Ok(())
}

/// `Private`: owned by SYSTEM or Administrators and writable by nobody else (readable by
/// others only with `allow_read`).
pub fn private(path: &Path, allow_read: bool) -> Result<()> {
    plain(path)?;
    let security = security(path, "Null transaction ACL refused")?;
    if ![SYSTEM, ADMINISTRATORS].contains(&security.owner.as_str()) {
        return fail("Untrusted transaction owner");
    }
    if security.aces.iter().any(|ace| ace.allow && ![SYSTEM, ADMINISTRATORS].contains(&ace.sid.as_str()) && (!allow_read || ace.mask & WRITE_RIGHTS != 0)) {
        return fail("Writable transaction directory refused");
    }
    Ok(())
}
/// `NewPrivate`: create a SYSTEM/Administrators-only directory, or accept an existing
/// one that already is.
pub fn new_private(path: &Path) -> Result<()> {
    plain(path)?;
    if !path.exists() {
        create_directory(path, "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")?;
    }
    private(path, false)
}

fn reparse(path: &Path) -> Result<Option<bool>> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata.file_attributes() & REPARSE != 0)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => fail(PATH_UNAVAILABLE),
    }
}

/// The switches of `Assert-InstallerPath` that relax or act; never combined by a caller.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    Strict,
    /// `-Repair`: write grants to untrusted principals on an object whose owner is trusted
    /// are removed instead of refused. An administrator's grant, such as Explorer's
    /// "Continue" to read a log, would otherwise block every later upgrade and uninstall.
    /// The owner check still refuses, and the ACL read back after the repair is verified.
    /// ponytail: a handle opened before the repair keeps its access until it is closed.
    Repair,
}
/// Write grants that open nothing to a non-administrator are not unsafe: TrustedInstaller
/// (servicing, above Administrators) and an inherit-only CREATOR OWNER template.
fn unsafe_write(ace: &Ace, owners: &[&str]) -> bool {
    ace.allow && !owners.contains(&ace.sid.as_str()) && ace.mask & WRITE_RIGHTS != 0
        && ace.sid != TRUSTED_INSTALLER && !(ace.sid == CREATOR_OWNER && ace.inherit_only)
}

/// Byte ranges of the DACL's ACE strings in `sddl`, in DACL order.
fn dacl_spans(sddl: &str) -> Result<Vec<(usize, usize)>> {
    let bytes = sddl.as_bytes();
    let mut i = sddl.find("D:").ok_or(Failure { step: "Installer path permissions unavailable", detail: String::new() })? + 2;
    // DACL flags (P, AI, AR...) precede the first ACE.
    while i < bytes.len() && bytes[i].is_ascii_uppercase() {
        i += 1;
    }
    let mut spans = Vec::new();
    while bytes.get(i) == Some(&b'(') {
        let (begin, mut depth) = (i, 0usize);
        // Conditional ACEs nest parentheses; the ACE ends where the depth returns to zero.
        loop {
            match bytes.get(i) {
                Some(b'(') => depth += 1,
                Some(b')') => depth -= 1,
                None => return fail("Installer path permissions unavailable"),
                _ => {}
            }
            i += 1;
            if depth == 0 {
                break;
            }
        }
        spans.push((begin, i));
    }
    Ok(spans)
}
/// `-Repair`'s new SDDL: `sddl` without its allow ACEs that `unsafe_write` refuses, or
/// `None` when there is none. Which ACEs go is decided on the DACL Windows parses from
/// this same text, and the text is only cut when both count the same ACEs.
pub(crate) fn repaired_sddl(sddl: &str, owners: &[&str]) -> Result<Option<String>> {
    let (_, aces) = parse_sddl(sddl)?;
    let Some(aces) = aces else { return Ok(None) };
    let spans = dacl_spans(sddl)?;
    if spans.len() != aces.len() {
        return fail("Installer path permissions unavailable");
    }
    if !aces.iter().any(|ace| unsafe_write(ace, owners)) {
        return Ok(None);
    }
    let (mut kept, mut from) = (String::with_capacity(sddl.len()), 0);
    for (ace, &(begin, end)) in aces.iter().zip(&spans) {
        if unsafe_write(ace, owners) {
            kept.push_str(&sddl[from..begin]);
            from = end;
        }
    }
    kept.push_str(&sddl[from..]);
    Ok(Some(kept))
}
/// `dropGrants`: rewrite the DACL of `path` without its unsafe write grants, through the
/// verified handle of `set_acl`, and say so in the Application log (event 1006).
fn drop_grants(path: &Path, owners: &[&str], directory: bool) -> Result<()> {
    if let Some(sddl) = repaired_sddl(&sddl_of(path)?, owners)? {
        set_acl(path, &sddl, directory)?;
        crate::win::event(1006, false, &format!("Installer removed write grants to untrusted principals: {}", path.display()));
    }
    Ok(())
}

/// A path refusal with what was refused: the object, and its owner or the principal its
/// ACL lets write. Event 1001 carries it; a fixed phrase alone left a refused installation
/// with nothing to act on. SIDs and paths only, never content.
fn refused<T>(step: &'static str, path: &Path, why: &str) -> Result<T> {
    let detail = if why.is_empty() { path.display().to_string() } else { format!("{}: {why}", path.display()) };
    Err(Failure { step, detail })
}

/// `Assert-InstallerPath`: every existing object from `path` up to (not including)
/// ProgramData or Program Files is a plain object owned by an allowed owner that no
/// untrusted principal can write; with `recurse`, every descendant too, and each file
/// has a single link.
pub fn assert_path(path: &Path, allowed_owners: &[&str], recurse: bool) -> Result<()> {
    assert_path_with(path, allowed_owners, recurse, Rule::Strict)
}
pub fn assert_path_with(path: &Path, allowed_owners: &[&str], recurse: bool, rule: Rule) -> Result<()> {
    if !path.is_absolute() {
        return fail("Installer path must be absolute");
    }
    let program_root = program_files()?.join("Milvago");
    let program_tree = same(path, &program_root) || path.starts_with(&program_root);
    let mut owners: Vec<&str> = allowed_owners.to_vec();
    if program_tree {
        owners.push(TRUSTED_INSTALLER);
    }
    let guard = PathGuard { owners: &owners, rule };
    guard.check_ancestors(path)?;
    if reparse(path)?.is_none() {
        return Ok(());
    }
    let items = if recurse { descendants(path)? } else { vec![path.to_path_buf()] };
    for item in &items {
        guard.check_item(item)?;
    }
    Ok(())
}

fn unavailable<E>(_: E) -> Failure {
    Failure { step: PATH_UNAVAILABLE, detail: String::new() }
}

/// `path` and, breadth first, everything below it. A reparse point is listed but never
/// entered: the caller refuses it rather than follow it.
fn descendants(path: &Path) -> Result<Vec<PathBuf>> {
    let mut items = vec![path.to_path_buf()];
    let mut index = 0;
    while index < items.len() {
        let item = items[index].clone();
        index += 1;
        let metadata = std::fs::symlink_metadata(&item).map_err(unavailable)?;
        if metadata.is_dir() && metadata.file_attributes() & REPARSE == 0 {
            for entry in std::fs::read_dir(&item).map_err(unavailable)? {
                items.push(entry.map_err(unavailable)?.path());
            }
        }
    }
    Ok(items)
}

/// The owners and folder rule one `assert_path_with` call checks every object against.
struct PathGuard<'a> {
    owners: &'a [&'a str],
    rule: Rule,
}
impl PathGuard<'_> {
    /// Read again after a repair: the check is on what the object now carries.
    fn checked(&self, item: &Path, null_step: &'static str, directory: bool) -> Result<Security> {
        let security = security(item, null_step)?;
        if self.rule != Rule::Repair || !self.owners.contains(&security.owner.as_str()) {
            return Ok(security);
        }
        drop_grants(item, self.owners, directory)?;
        self::security(item, null_step)
    }

    /// Every existing ancestor up to ProgramData or Program Files, `path` itself included.
    fn check_ancestors(&self, path: &Path) -> Result<()> {
        let roots = [program_data()?, program_files()?];
        let mut cursor = Some(path);
        while let Some(current) = cursor {
            if roots.iter().any(|root| same(root, current)) {
                break;
            }
            if let Some(redirected) = reparse(current)? {
                self.check_ancestor(current, redirected)?;
            }
            cursor = current.parent();
        }
        Ok(())
    }

    fn check_ancestor(&self, current: &Path, redirected: bool) -> Result<()> {
        if redirected {
            return refused("Redirected installer path refused", current, "");
        }
        let directory = std::fs::symlink_metadata(current).is_ok_and(|m| m.is_dir());
        let security = self.checked(current, "Null installer ancestor ACL refused", directory)?;
        if !self.owners.contains(&security.owner.as_str()) {
            return refused("Installer path has an untrusted owner", current, &format!("owner {}", security.owner));
        }
        // PowerShell applies the folder rule to every ancestor, `path` itself included.
        if let Some(ace) = security.aces.iter().find(|ace| unsafe_write(ace, self.owners)) {
            return refused("Installer ancestor is writable by an untrusted principal", current, &format!("{} {:#x}", ace.sid, ace.mask));
        }
        Ok(())
    }

    fn check_item(&self, item: &Path) -> Result<()> {
        let metadata = std::fs::symlink_metadata(item).map_err(unavailable)?;
        if metadata.file_attributes() & REPARSE != 0 {
            return refused("Redirected installer child refused", item, "");
        }
        let directory = metadata.is_dir();
        let security = self.checked(item, "Null installer child ACL refused", directory)?;
        if !self.owners.contains(&security.owner.as_str()) {
            return refused("Installer child has an untrusted owner", item, &format!("owner {}", security.owner));
        }
        if let Some(ace) = security.aces.iter().find(|ace| unsafe_write(ace, self.owners)) {
            return refused("Installer child is writable by an untrusted principal", item, &format!("{} {:#x}", ace.sid, ace.mask));
        }
        if !directory && links(item)? != 1 {
            return refused("Hard-linked installer child refused", item, "");
        }
        Ok(())
    }
}

/// Number of hard links of a file, read from the object itself (no `fsutil`).
fn links(path: &Path) -> Result<u32> {
    let name = wide(path);
    // FILE_READ_ATTRIBUTES, full sharing, FILE_FLAG_BACKUP_SEMANTICS | OPEN_REPARSE_POINT.
    let handle = unsafe { CreateFileW(name.as_ptr(), 0x80, 7, std::ptr::null(), 3, 0x0220_0000, 0) };
    if handle == -1 {
        return fail(PATH_UNAVAILABLE);
    }
    let mut info = FileInformation::default();
    let read = unsafe { GetFileInformationByHandle(handle, &mut info) } != 0;
    unsafe { CloseHandle(handle) };
    if !read {
        return fail(PATH_UNAVAILABLE);
    }
    Ok(info.links)
}

struct Descriptor(*mut c_void);
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}
fn descriptor(sddl: &str) -> Result<Descriptor> {
    let text: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut raw = std::ptr::null_mut();
    if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(text.as_ptr(), 1, &mut raw, std::ptr::null_mut()) } == 0 {
        return fail("Invalid permission descriptor");
    }
    Ok(Descriptor(raw))
}

/// Resolve an opened handle's path and require it to be the path that was asked for.
fn final_path_is(handle: isize, expected: &Path, step: &'static str) -> Result<()> {
    let mut buffer = vec![0u16; 32768];
    let length = unsafe { GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), buffer.len() as u32, 0) } as usize;
    if length == 0 || length >= buffer.len() {
        return fail(step);
    }
    let resolved = String::from_utf16_lossy(&buffer[..length]);
    let resolved = resolved.strip_prefix(r"\\?\").unwrap_or(&resolved);
    if !resolved.eq_ignore_ascii_case(&expected.to_string_lossy()) {
        return fail(step);
    }
    Ok(())
}

/// `SetAcl`: apply `sddl` through a handle that denies replacement, after proving the
/// handle is the plain object asked for (no reparse point, a single link for a file,
/// the same final path).
pub fn set_acl(path: &Path, sddl: &str, directory: bool) -> Result<()> {
    let name = wide(path);
    // WRITE_DAC | WRITE_OWNER | READ_CONTROL, FILE_SHARE_READ, OPEN_EXISTING,
    // FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT.
    let handle = unsafe { CreateFileW(name.as_ptr(), 0x000E_0000, 1, std::ptr::null(), 3, 0x0220_0000, 0) };
    if handle == -1 {
        let code = unsafe { GetLastError() };
        return Err(Failure { step: "Permission target cannot be locked", detail: format!("{}: win32={code}", path.display()) });
    }
    let result = (|| {
        let mut info = FileInformation::default();
        if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 || info.attributes & REPARSE != 0 || (!directory && info.links != 1) {
            return fail("Permission target redirected");
        }
        final_path_is(handle, path, "Permission target escaped")?;
        let descriptor = descriptor(sddl)?;
        let (mut present, mut dacl, mut defaulted) = (0i32, std::ptr::null_mut(), 0i32);
        unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted) };
        if present == 0 || dacl.is_null() {
            return fail("Null permission descriptor refused");
        }
        let (mut owner, mut group) = (std::ptr::null_mut(), std::ptr::null_mut());
        unsafe { GetSecurityDescriptorOwner(descriptor.0, &mut owner, &mut defaulted) };
        unsafe { GetSecurityDescriptorGroup(descriptor.0, &mut group, &mut defaulted) };
        let (mut control, mut revision) = (0u16, 0u32);
        unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) };
        let mut flags = 4u32;
        if !owner.is_null() { flags |= 1; }
        if !group.is_null() { flags |= 2; }
        // SE_DACL_PROTECTED → PROTECTED_DACL_SECURITY_INFORMATION, else UNPROTECTED.
        flags |= if control & 0x1000 != 0 { 0x8000_0000 } else { 0x2000_0000 };
        if unsafe { SetKernelObjectSecurity(handle, flags, descriptor.0) } == 0 {
            let error = unsafe { GetLastError() };
            if error != 1307 {
                return Err(Failure { step: "Permission restoration failed", detail: format!("win32={error}") });
            }
            // Restoring a saved foreign owner needs the restore privilege; the verified
            // handle stays locked meanwhile and the token is put back afterwards.
            let _privilege = crate::win::Privilege::enable("SeRestorePrivilege")?;
            if unsafe { SetKernelObjectSecurity(handle, flags, descriptor.0) } == 0 {
                return Err(Failure { step: "Permission restoration failed", detail: format!("win32={}", unsafe { GetLastError() }) });
            }
        }
        Ok(())
    })();
    unsafe { CloseHandle(handle) };
    // Which object could not take its permissions: the step alone named none.
    result.map_err(|mut failure| {
        failure.detail = if failure.detail.is_empty() { path.display().to_string() } else { format!("{}: {}", path.display(), failure.detail) };
        failure
    })
}

/// `Copy`: read the source through a handle that denies writers, after proving it is a
/// plain single-link file at the asked path; write a new destination.
pub fn copy(source: &Path, destination: &Path) -> Result<()> {
    use std::io::Write;
    let mut input = open_plain(source)?;
    let mut output = std::fs::OpenOptions::new().write(true).create_new(true).open(destination)
        .map_err(|error| Failure { step: "Snapshot destination unavailable", detail: error.to_string() })?;
    std::io::copy(&mut input, &mut output).map_err(|error| Failure { step: "Snapshot copy failed", detail: error.to_string() })?;
    output.flush().and_then(|()| output.sync_all()).map_err(|error| Failure { step: "Snapshot copy failed", detail: error.to_string() })
}
/// The source side of `copy`: writers denied for the handle's whole life, and the
/// opened object proved a plain single-link file at the asked path.
fn open_plain(source: &Path) -> Result<std::fs::File> {
    use std::os::windows::io::FromRawHandle;
    let name = wide(source);
    // GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT.
    let handle = unsafe { CreateFileW(name.as_ptr(), 0x8000_0000, 1, std::ptr::null(), 3, 0x0020_0000, 0) };
    if handle == -1 {
        return fail("Snapshot source cannot be locked");
    }
    let input = unsafe { std::fs::File::from_raw_handle(handle as *mut c_void) };
    let mut info = FileInformation::default();
    if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 || info.attributes & 0x410 != 0 || info.links != 1 {
        return fail("Snapshot source is not a plain single-link file");
    }
    final_path_is(handle, source, "Snapshot source redirected")?;
    Ok(input)
}
/// At most `limit` bytes of `source`, read through the handle `open_plain` verified. A
/// size checked before an unbounded read could grow in between; this bound cannot.
pub fn read_plain(source: &Path, limit: usize, too_large: &'static str) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    open_plain(source)?.take(limit as u64 + 1).read_to_end(&mut bytes).map_err(|error| Failure { step: "Snapshot copy failed", detail: error.to_string() })?;
    if bytes.len() > limit {
        return fail(too_large);
    }
    Ok(bytes)
}

/// Read a caller-named file (a deployment tool's staging folder: SCCM cache, Intune
/// content, `C:\Deploy`) whose *ancestors* are not ours to judge. What is judged is the
/// opened object itself, through the handle that is read, with writers denied for its
/// whole life: a plain single-link file owned by SYSTEM or Administrators that no other
/// principal may write. A substitution before the open is caught by the handle checks,
/// one after it by the sharing mode. Replaces the ancestor rule for `MILVAGO_CA_FILE`.
pub fn read_trusted_source(source: &Path, limit: usize) -> Result<Vec<u8>> {
    use std::io::Read;
    use std::os::windows::io::FromRawHandle;
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn GetSecurityInfo(handle: isize, kind: u32, info: u32, owner: *mut *mut c_void, group: *mut *mut c_void,
            dacl: *mut *mut c_void, sacl: *mut *mut c_void, descriptor: *mut *mut c_void) -> u32;
    }
    if !source.is_absolute() {
        return fail("Caller-supplied file must be absolute");
    }
    let name = wide(source);
    // GENERIC_READ | READ_CONTROL, FILE_SHARE_READ, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT.
    let handle = unsafe { CreateFileW(name.as_ptr(), 0x8002_0000, 1, std::ptr::null(), 3, 0x0020_0000, 0) };
    if handle == -1 {
        return fail("Caller-supplied file unavailable");
    }
    let file = unsafe { std::fs::File::from_raw_handle(handle as *mut c_void) };
    let mut info = FileInformation::default();
    if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 || info.attributes & 0x410 != 0 || info.links != 1 {
        return fail("Caller-supplied file is not a plain single-link file");
    }
    let (mut owner, mut dacl, mut descriptor) = (std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut());
    if unsafe { GetSecurityInfo(handle, 1, 5, &mut owner, std::ptr::null_mut(), &mut dacl, std::ptr::null_mut(), &mut descriptor) } != 0 {
        return fail("Caller-supplied file permissions unavailable");
    }
    let verdict = (|| {
        let owner = sid_text(owner).unwrap_or_default();
        if dacl.is_null() || ![SYSTEM, ADMINISTRATORS].contains(&owner.as_str()) {
            return fail("Caller-supplied file has an untrusted owner");
        }
        let count = unsafe { *dacl.cast::<u8>().add(4).cast::<u16>() };
        for index in 0..u32::from(count) {
            let mut ace = std::ptr::null_mut();
            if unsafe { GetAce(dacl, index, &mut ace) } == 0 {
                return fail("Caller-supplied file permissions unavailable");
            }
            let (kind, flags) = unsafe { (*ace.cast::<u8>(), *ace.cast::<u8>().add(1)) };
            let mask = unsafe { *ace.cast::<u8>().add(4).cast::<u32>() };
            let sid = sid_text(unsafe { ace.cast::<u8>().add(8).cast() }).unwrap_or_default();
            if kind == 0 && flags & 0x08 == 0 && mask & WRITE_RIGHTS != 0 && ![SYSTEM, ADMINISTRATORS, TRUSTED_INSTALLER].contains(&sid.as_str()) {
                return fail("Caller-supplied file is writable by an untrusted principal");
            }
        }
        Ok(())
    })();
    unsafe { LocalFree(descriptor) };
    verdict?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes).map_err(|_| Failure { step: "Caller-supplied file unavailable", detail: String::new() })?;
    if bytes.len() > limit {
        return fail("Caller-supplied file is too large");
    }
    Ok(bytes)
}

/// Write `bytes` to `destination` through a temporary file in the same directory, then
/// an atomic replacement (the destination directory is ours and already verified).
pub fn publish_bytes(bytes: &[u8], destination: &Path) -> Result<()> {
    use std::io::Write;
    assert_path(destination, &[SYSTEM, ADMINISTRATORS], false)?;
    let directory = destination.parent().ok_or(Failure { step: "Publication directory unavailable", detail: String::new() })?;
    let temporary = directory.join(format!(".milvago-publish-{}.tmp", std::process::id()));
    let _ = std::fs::remove_file(&temporary);
    let result = std::fs::OpenOptions::new().write(true).create_new(true).open(&temporary)
        .and_then(|mut file| file.write_all(bytes).and_then(|()| file.sync_all()))
        .map_err(|_| Failure { step: "Publication failed", detail: String::new() })
        .and_then(|()| {
            let (to, from) = (wide(destination), wide(&temporary));
            // MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH.
            if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 0x9) } != 0 { Ok(()) } else { fail("Publication failed") }
        });
    if temporary.exists() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

/// `Publish-InstallerFile`: validated copy to a temporary file in the destination
/// directory, then an atomic replacement.
pub fn publish(source: &Path, destination: &Path) -> Result<()> {
    assert_path(source, &[SYSTEM, ADMINISTRATORS], false)?;
    assert_path(destination, &[SYSTEM, ADMINISTRATORS], false)?;
    let directory = destination.parent().ok_or(Failure { step: "Publication directory unavailable", detail: String::new() })?;
    let unique = format!("{}{:?}", std::process::id(), std::time::SystemTime::now());
    let temporary = directory.join(format!(".milvago-publish-{:x}.tmp", unique.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3))));
    let result = copy(source, &temporary).and_then(|()| {
        let (to, from) = (wide(destination), wide(&temporary));
        let done = if destination.exists() {
            (unsafe { ReplaceFileW(to.as_ptr(), from.as_ptr(), std::ptr::null(), 0, std::ptr::null_mut(), std::ptr::null_mut()) }) != 0
        } else {
            (unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 0) }) != 0
        };
        if done { Ok(()) } else { Err(Failure { step: "Publication failed", detail: format!("win32={}", unsafe { GetLastError() }) }) }
    });
    if temporary.exists() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

/// SHA-1 of `message` (FIPS 180-4), used only to derive a per-service SID the way Windows
/// does (`service_sid` below). A local implementation, since neither this crate's
/// dependencies nor the standard library offer SHA-1 (`sha2`, used elsewhere here for
/// tamper-evident snapshots, is the SHA-2 family only).
fn sha1(message: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];
    let bit_length = (message.len() as u64) * 8;
    let mut padded = message.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_length.to_be_bytes());
    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, word) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A82_7999),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let temporary = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temporary;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut digest = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        digest[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

/// `Get-ServiceSid`: `NT SERVICE\<name>`'s SID, computed the way Windows does — SHA-1 of
/// the upper-cased UTF-16LE name, read back as five little-endian DWORDs — so an ACL can
/// name a service before it is registered. Must equal `sc showsid <name>`.
pub fn service_sid(name: &str) -> String {
    let upper: Vec<u16> = name.to_uppercase().encode_utf16().collect();
    let mut message = Vec::with_capacity(upper.len() * 2);
    for unit in upper {
        message.extend_from_slice(&unit.to_le_bytes());
    }
    let digest = sha1(&message);
    let groups = (0..5).map(|i| u32::from_le_bytes(digest[i * 4..i * 4 + 4].try_into().unwrap()).to_string());
    format!("S-1-5-80-{}", groups.collect::<Vec<_>>().join("-"))
}

/// Every Milvago service that runs as NetworkService. Their private directories name the
/// service SID, never NetworkService itself, which every NetworkService service shares.
pub fn milvago_service_sids() -> [String; 3] {
    ["Milvago Agent Logger", "Milvago Agent Logger Community", "MilvagoModelFilter"].map(service_sid)
}

/// Protected SDDL of a private directory: Administrators owner, Administrators and
/// SYSTEM full control, `service_sid` as `access` says, and — for `Write` — an
/// inheritable Owner Rights ACE limited to READ_CONTROL. The service creates files here,
/// owned by NetworkService, and an owner may rewrite a DACL: any other NetworkService
/// service could then open them; Owner Rights replaces that implicit right with
/// read-permissions only.
pub fn private_sddl(access: Access, service_sid: &str) -> String {
    let service = match access {
        Access::None => String::new(),
        Access::Read => format!("(A;OICI;0x1200a9;;;{service_sid})"),
        Access::Write => format!("(A;OICI;FA;;;{service_sid})"),
    };
    let owner_rights = if access == Access::Write { format!("(A;OICI;0x20000;;;{OWNER_RIGHTS})") } else { String::new() };
    format!("O:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY){service}{owner_rights}")
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Access {
    None,
    Read,
    Write,
}

fn create_directory(path: &Path, sddl: &str) -> Result<()> {
    let descriptor = descriptor(sddl)?;
    let attributes = SecurityAttributes { length: size_of::<SecurityAttributes>() as u32, descriptor: descriptor.0, inherit: 0 };
    let name = wide(path);
    if unsafe { CreateDirectoryW(name.as_ptr(), &attributes) } == 0 {
        // Read once: formatting the detail may run code that resets the thread's last error.
        let code = unsafe { GetLastError() };
        if code != 183 {
            return Err(Failure { step: "Private directory could not be created", detail: format!("{} (Win32 error {code})", path.display()) });
        }
    }
    Ok(())
}
/// The ancestors of `path` that do not exist, outermost first. An entry that exists as a
/// link, dangling or not, is present: it is refused by the path check, never created over.
fn missing_ancestors(path: &Path, present: impl Fn(&Path) -> bool) -> Vec<PathBuf> {
    let mut missing: Vec<PathBuf> = path.ancestors().skip(1).take_while(|p| p.parent().is_some() && !present(p)).map(Path::to_path_buf).collect();
    missing.reverse();
    missing
}
/// Create `path` with its final security descriptor, so it never exists with inherited
/// rights, and refuse one that already exists: someone else created it in between.
pub fn create_directory_new(path: &Path, sddl: &str) -> Result<()> {
    let descriptor = descriptor(sddl)?;
    let attributes = SecurityAttributes { length: size_of::<SecurityAttributes>() as u32, descriptor: descriptor.0, inherit: 0 };
    let name = wide(path);
    if unsafe { CreateDirectoryW(name.as_ptr(), &attributes) } == 0 {
        let code = unsafe { GetLastError() };
        return Err(Failure { step: if code == 183 { "Directory appeared while it was being created" } else { "Directory could not be created" }, detail: format!("{} (Win32 error {code})", path.display()) });
    }
    Ok(())
}

/// `Set-InstallerPrivateDirectory`. `service_sid` is `NETWORK_SERVICE` for a directory
/// still shared across services (the ProgramData\Milvago root) and a per-service SID
/// (`service_sid` above) everywhere else; ignored when `access` is `None`. `S-1-5-20`
/// stays an allowed owner of existing children in a `Write` directory too: a file a
/// NetworkService service creates is owned by NetworkService, whichever service it is.
pub fn private_directory(path: &Path, access: Access, container_only: bool, service_sid: &str) -> Result<()> {
    let mut owners = vec![SYSTEM, ADMINISTRATORS];
    if access == Access::Write {
        owners.push(NETWORK_SERVICE);
        owners.push(service_sid);
    }
    assert_path(path, &owners, !container_only)?;
    let sddl = private_sddl(access, service_sid);
    if !path.exists() {
        // CreateDirectoryW makes one level only, where PowerShell's
        // [IO.Directory]::CreateDirectory made the parents too (Browser\state on a
        // first installation). Missing parents are born private to SYSTEM and
        // Administrators and must not appear meanwhile; the result is then re-checked.
        let missing = missing_ancestors(path, |p| std::fs::symlink_metadata(p).is_ok());
        for p in &missing {
            create_directory_new(p, &private_sddl(Access::None, ""))?;
        }
        create_directory(path, &sddl)?;
        if !missing.is_empty() {
            assert_path(path, &owners, false)?;
        }
    }
    set_acl(path, &sddl, true)?;
    if container_only {
        return Ok(());
    }
    // Existing explicit child ACEs or owners cannot keep access to private state.
    let mut pending = vec![path.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).map_err(|_| Failure { step: "Private directory unavailable", detail: String::new() })? {
            let child = entry.map_err(|_| Failure { step: "Private directory unavailable", detail: String::new() })?.path();
            let is_dir = std::fs::symlink_metadata(&child).map(|m| m.is_dir()).unwrap_or(false);
            set_acl(&child, &sddl, is_dir)?;
            if is_dir {
                pending.push(child);
            }
        }
    }
    Ok(())
}

/// `Set-InstallerAuthorizationDirectory`: an existing directory is inspected, never
/// re-permissioned — accepting a permissive one would let a lower-privileged writer
/// forge an active transaction marker.
pub fn authorization_directory(path: &Path, public: bool) -> Result<()> {
    assert_path(path, &[SYSTEM, ADMINISTRATORS], false)?;
    if !path.exists() {
        let sddl = format!("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA){}", if public { "(A;OICI;0x1200a9;;;AU)" } else { "" });
        create_directory(path, &sddl)?;
        set_acl(path, &sddl, true)?;
    }
    let security = security(path, "Null installer ancestor ACL refused")?;
    if ![SYSTEM, ADMINISTRATORS].contains(&security.owner.as_str()) {
        return fail("Untrusted authorization directory owner");
    }
    let (mut system, mut admins, mut users) = (false, false, false);
    for ace in security.aces.iter().filter(|ace| ace.allow) {
        match ace.sid.as_str() {
            SYSTEM => system = true,
            ADMINISTRATORS => admins = true,
            AUTHENTICATED_USERS if public => {
                if ace.mask & WRITE_RIGHTS != 0 {
                    return fail("Authorization public directory is writable by users");
                }
                users = true;
            }
            _ => return fail("Unexpected authorization directory permission"),
        }
    }
    if !system || !admins || (public && !users) {
        return fail("Authorization directory permission missing");
    }
    Ok(())
}

fn assert_custody_file(path: &Path) -> Result<()> {
    assert_path(path, &[SYSTEM, ADMINISTRATORS], false)?;
    let metadata = std::fs::symlink_metadata(path).map_err(|_| Failure { step: "Invalid custody file type", detail: String::new() })?;
    if metadata.is_dir() || metadata.file_attributes() & REPARSE != 0 {
        return fail("Invalid custody file type");
    }
    if links(path)? != 1 {
        return fail("Custody file link count refused");
    }
    let security = security(path, "Null installer child ACL refused")?;
    if ![SYSTEM, ADMINISTRATORS].contains(&security.owner.as_str()) {
        return fail("Untrusted custody file owner");
    }
    let (mut system, mut admins) = (false, false);
    for ace in &security.aces {
        match ace.sid.as_str() {
            SYSTEM => system = true,
            ADMINISTRATORS => admins = true,
            _ => return fail("Unexpected custody file permission"),
        }
    }
    if !system || !admins {
        return fail("Custody file permission missing");
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Custody {
    Set,
    Clear,
}

/// `Use-InstallerCustody`: the cross-product marker that tells the update service a
/// Windows Installer transaction owns this edition, under a one-byte file lock.
pub fn custody(edition: &str, product: &str, operation: Custody) -> Result<()> {
    use std::io::Write;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    if !matches!(edition, "community" | "commercial") {
        return fail("Invalid custody edition");
    }
    let canonical = canonical_guid(product).ok_or(Failure { step: "Invalid custody product", detail: String::new() })?;
    let root = program_data()?.join("MilvagoAuthorization");
    let edition_root = root.join(edition);
    let private = edition_root.join("private");
    authorization_directory(&root, true)?;
    authorization_directory(&edition_root, true)?;
    authorization_directory(&private, false)?;
    let (lock_path, marker) = (private.join("custody.lock"), private.join("custody.json"));
    let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let lock = loop {
        // FILE_SHARE_READ | FILE_SHARE_WRITE, like the PowerShell FileStream.
        let file = std::fs::OpenOptions::new().read(true).write(true).create(true).share_mode(3).open(&lock_path);
        match file {
            Ok(file) => {
                assert_custody_file(&lock_path)?;
                if unsafe { LockFile(file.as_raw_handle() as isize, 0, 0, 1, 0) } != 0 {
                    break file;
                }
            }
            Err(error) if error.raw_os_error() != Some(32) => return fail("Custody lock unavailable"),
            Err(_) => {}
        }
        if std::time::Instant::now() >= until {
            return fail("Custody acknowledgement lock remained busy");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    let result = (|| {
        if marker.exists() {
            assert_custody_file(&marker)?;
            let current: serde_json::Value = std::fs::read(&marker).ok().and_then(|b| serde_json::from_slice(&b).ok())
                .ok_or(Failure { step: "Invalid custody marker", detail: String::new() })?;
            let current_product = current["product"].as_str().and_then(canonical_guid);
            if current["edition"] != edition || current["active"] != true || current_product.is_none() {
                return fail("Invalid custody marker");
            }
            if current_product.as_deref() != Some(canonical.as_str()) {
                return fail(if operation == Custody::Clear { "Custody marker belongs to another product" } else { "Another product has active custody" });
            }
            if operation == Custody::Clear {
                return std::fs::remove_file(&marker).map_err(|_| Failure { step: "Custody marker could not be removed", detail: String::new() });
            }
        } else if operation == Custody::Clear {
            return fail("Custody marker is missing");
        }
        let json = serde_json::json!({"edition": edition, "product": canonical, "active": true}).to_string();
        let mut writer = std::fs::OpenOptions::new().write(true).create(true).truncate(true).share_mode(1).open(&marker)
            .map_err(|_| Failure { step: "Custody marker could not be written", detail: String::new() })?;
        writer.write_all(json.as_bytes()).and_then(|()| writer.sync_all())
            .map_err(|_| Failure { step: "Custody marker could not be written", detail: String::new() })?;
        drop(writer);
        assert_custody_file(&marker)
    })();
    unsafe { UnlockFile(lock.as_raw_handle() as isize, 0, 0, 1, 0) };
    result
}

/// Lower-case hyphenated GUID, with or without braces; `None` otherwise.
pub fn canonical_guid(text: &str) -> Option<String> {
    let bare = text.trim().trim_start_matches('{').trim_end_matches('}');
    let groups: Vec<&str> = bare.split('-').collect();
    let shape = [8, 4, 4, 4, 12];
    (groups.len() == 5 && groups.iter().zip(shape).all(|(g, n)| g.len() == n && g.bytes().all(|c| c.is_ascii_hexdigit())))
        .then(|| bare.to_ascii_lowercase())
}

/// A test folder under ProgramData, like every real target (the ancestor walk stops
/// there), removed when dropped: also when the test panics, so a failed assertion leaves
/// no `milvago-installer-test-*` folder behind.
#[cfg(test)]
pub(crate) struct TestDir(PathBuf);
#[cfg(test)]
impl TestDir {
    pub(crate) fn new(label: &str) -> Self {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = program_data().unwrap().join(format!("milvago-installer-test-{label}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}
#[cfg(test)]
impl std::ops::Deref for TestDir {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}
#[cfg(test)]
impl AsRef<Path> for TestDir {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}
#[cfg(test)]
impl Drop for TestDir {
    fn drop(&mut self) {
        // remove_dir_all removes a junction itself, never what it points to.
        if std::fs::remove_dir_all(&self.0).is_err() {
            // A test may have left a read-only file: clear it and try once more.
            let mut pending = vec![self.0.clone()];
            while let Some(directory) = pending.pop() {
                for entry in std::fs::read_dir(&directory).into_iter().flatten().flatten() {
                    let path = entry.path();
                    if entry.file_type().is_ok_and(|t| t.is_dir()) {
                        pending.push(path);
                    } else if let Ok(metadata) = std::fs::symlink_metadata(&path) {
                        let mut permissions = metadata.permissions();
                        #[allow(clippy::permissions_set_readonly_false)]
                        permissions.set_readonly(false);
                        let _ = std::fs::set_permissions(&path, permissions);
                    }
                }
            }
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn current_user() -> String {
        // The test process's own SID owns what it creates in a temporary directory.
        let probe = TestDir::new("probe");
        security(&probe, "null").unwrap().owner
    }
    fn tempfile_dir() -> TestDir {
        TestDir::new("paths")
    }

    #[test]
    fn only_the_missing_ancestors_are_created_outermost_first() {
        let path = Path::new(r"C:\ProgramData\Milvago\Browser\state");
        let present = |existing: &'static [&'static str]| move |p: &Path| existing.iter().any(|e| Path::new(e) == p);
        // A first installation: Browser is missing below an existing Milvago root.
        assert_eq!(missing_ancestors(path, present(&[r"C:\ProgramData\Milvago", r"C:\ProgramData", r"C:\"])), vec![PathBuf::from(r"C:\ProgramData\Milvago\Browser")]);
        // Nothing at all under ProgramData: Milvago first, then Browser.
        assert_eq!(missing_ancestors(path, present(&[r"C:\ProgramData", r"C:\"])),
            vec![PathBuf::from(r"C:\ProgramData\Milvago"), PathBuf::from(r"C:\ProgramData\Milvago\Browser")]);
        // Every parent present (a repair): nothing to create.
        assert!(missing_ancestors(path, present(&[r"C:\ProgramData\Milvago\Browser", r"C:\ProgramData\Milvago", r"C:\ProgramData", r"C:\"])).is_empty());
        // A drive root is never a candidate, even when reported absent.
        assert_eq!(missing_ancestors(Path::new(r"C:\x"), |_| false), Vec::<PathBuf>::new());
    }

    #[test]
    fn a_private_directory_is_created_with_its_missing_parents_and_stays_private() {
        // Not as an administrator: the owner cannot become Administrators, so this checks
        // the creation (the bug of 2026-10-15) up to the first permission step.
        let dir = tempfile_dir();
        let nested = dir.join("Browser").join("state");
        let missing = missing_ancestors(&nested, |p| std::fs::symlink_metadata(p).is_ok());
        assert_eq!(missing, vec![dir.join("Browser")]);
        let me = current_user();
        for p in &missing {
            create_directory_new(p, &format!("D:P(A;OICI;FA;;;{me})(A;OICI;FA;;;SY)")).unwrap();
        }
        create_directory(&nested, &format!("D:P(A;OICI;FA;;;{me})(A;OICI;FA;;;SY)")).unwrap();
        assert!(nested.is_dir());
        // The parent was born with its own protected descriptor: no inherited Users grant.
        assert!(security(&dir.join("Browser"), "null").unwrap().aces.iter().all(|ace| ace.sid == me || ace.sid == SYSTEM));
        // An existing directory is accepted (ERROR_ALREADY_EXISTS), a missing parent reported with its path and code.
        create_directory(&nested, &format!("D:P(A;OICI;FA;;;{me})")).unwrap();
        let failure = create_directory(&dir.join("absent").join("child"), &format!("D:P(A;OICI;FA;;;{me})")).unwrap_err();
        assert_eq!(failure.step, "Private directory could not be created");
        assert!(failure.detail.contains("absent") && failure.detail.ends_with("(Win32 error 3)"), "{}", failure.detail);
    }

    #[test]
    fn a_test_folder_is_removed_even_when_the_test_panics() {
        let path = std::panic::catch_unwind(|| {
            let dir = TestDir::new("panic");
            std::fs::write(dir.join("x"), b"x").unwrap();
            let mut permissions = std::fs::metadata(dir.join("x")).unwrap().permissions();
            permissions.set_readonly(true);
            std::fs::set_permissions(dir.join("x"), permissions).unwrap();
            let path = dir.to_path_buf();
            if !path.as_os_str().is_empty() {
                panic!("{}", path.display());
            }
            path
        });
        let message = path.unwrap_err();
        let text = message.downcast_ref::<String>().cloned().unwrap_or_default();
        assert!(text.contains("milvago-installer-test-panic"), "{text}");
        assert!(!Path::new(&text).exists(), "debris left at {text}");
    }

    #[test]
    fn guids_are_canonical_or_refused() {
        assert_eq!(canonical_guid("{8C2F3DA1-7A5B-4E3C-8F4D-2B3C4D5E6F70}").as_deref(), Some("8c2f3da1-7a5b-4e3c-8f4d-2b3c4d5e6f70"));
        assert!(canonical_guid("8c2f3da1-7a5b-4e3c-8f4d-2b3c4d5e6f7").is_none());
        assert!(canonical_guid("..\\x").is_none());
    }

    #[test]
    fn a_hard_linked_or_foreign_owned_child_is_refused() {
        let me = current_user();
        let dir = tempfile_dir();
        // Created under ProgramData, it inherits Users' write grant: refused as it should be.
        assert_eq!(assert_path(&dir, &[me.as_str()], true).unwrap_err().step, "Installer ancestor is writable by an untrusted principal");
        set_acl(&dir, &format!("D:P(A;OICI;FA;;;{me})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"), true).unwrap();
        let file = dir.join("state.bin");
        std::fs::write(&file, b"x").unwrap();
        // A user-owned temporary tree passes when that user is an allowed owner...
        assert_path(&dir, &[me.as_str(), SYSTEM, ADMINISTRATORS], true).unwrap();
        // ...and not when only SYSTEM and Administrators are.
        assert_eq!(assert_path(&dir, &[SYSTEM, ADMINISTRATORS], true).unwrap_err().step, "Installer path has an untrusted owner");
        // The refusal names the object and its owner, for event 1001.
        let foreign = assert_path(&dir, &[SYSTEM, ADMINISTRATORS], true).unwrap_err();
        assert_eq!(foreign.detail, format!("{}: owner {me}", dir.display()));
        std::fs::hard_link(&file, dir.join("alias.bin")).unwrap();
        let linked = assert_path(&dir, &[me.as_str(), SYSTEM, ADMINISTRATORS], true).unwrap_err();
        assert_eq!(linked.step, "Hard-linked installer child refused");
        assert!(linked.detail.ends_with("alias.bin") || linked.detail.ends_with("state.bin"), "{}", linked.detail);
    }

    #[test]
    fn a_copy_refuses_a_hard_linked_source_and_never_overwrites() {
        let dir = tempfile_dir();
        let source = dir.join("source.bin");
        std::fs::write(&source, b"payload").unwrap();
        let destination = dir.join("copy.bin");
        copy(&source, &destination).unwrap();
        assert_eq!(std::fs::read(&destination).unwrap(), b"payload");
        assert!(copy(&source, &destination).is_err(), "an existing destination was overwritten");
        std::fs::hard_link(&source, dir.join("alias.bin")).unwrap();
        assert_eq!(copy(&source, &dir.join("other.bin")).unwrap_err().step, "Snapshot source is not a plain single-link file");
    }

    #[test]
    fn permissions_are_applied_through_the_verified_handle() {
        let me = current_user();
        let dir = tempfile_dir();
        let target = dir.join("private");
        std::fs::create_dir(&target).unwrap();
        // Owner stays the test user (cannot assign Administrators unprivileged).
        let sddl = format!("D:P(A;OICI;FA;;;{me})(A;OICI;FA;;;SY)");
        set_acl(&target, &sddl, true).unwrap();
        let applied = security(&target, "null").unwrap();
        assert!(applied.aces.iter().all(|ace| ace.sid == me || ace.sid == SYSTEM), "inherited ACEs survived a protected DACL");
        let file = target.join("a.bin");
        std::fs::write(&file, b"x").unwrap();
        std::fs::hard_link(&file, target.join("b.bin")).unwrap();
        let redirected = set_acl(&file, &sddl, false).unwrap_err();
        assert_eq!((redirected.step, redirected.detail), ("Permission target redirected", file.display().to_string()));
        let absent = set_acl(&target.join("absent"), &sddl, false).unwrap_err();
        assert_eq!(absent.step, "Permission target cannot be locked");
        assert!(absent.detail.ends_with("absent: win32=2"), "{}", absent.detail);
    }

    #[test]
    fn a_repaired_sddl_loses_only_the_untrusted_write_grants() {
        let sddl = "O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1301bf;;;S-1-5-21-1-2-3-1001)(A;OICI;0x1200a9;;;BU)(A;OICIIO;FA;;;CO)(D;;FA;;;S-1-5-21-1-2-3-1002)";
        let repaired = repaired_sddl(sddl, &[SYSTEM, ADMINISTRATORS]).unwrap().unwrap();
        assert_eq!(repaired, "O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;OICIIO;FA;;;CO)(D;;FA;;;S-1-5-21-1-2-3-1002)");
        assert!(repaired_sddl(&repaired, &[SYSTEM, ADMINISTRATORS]).unwrap().is_none(), "a clean DACL was rewritten");
        // An allowed owner's grant is kept, and the last ACE can go too.
        let last = "O:BAD:P(A;;FA;;;BA)(A;;FA;;;NS)";
        assert!(repaired_sddl(last, &[ADMINISTRATORS, NETWORK_SERVICE]).unwrap().is_none());
        assert_eq!(repaired_sddl(last, &[ADMINISTRATORS]).unwrap().unwrap(), "O:BAD:P(A;;FA;;;BA)");
    }

    #[test]
    fn repair_mode_removes_a_write_grant_on_a_trusted_object_and_verifies_it() {
        let me = current_user();
        let dir = tempfile_dir();
        let owners = [me.as_str(), SYSTEM, ADMINISTRATORS];
        set_acl(&dir, &format!("D:P(A;OICI;FA;;;{me})(A;OICI;FA;;;SY)"), true).unwrap();
        let log = dir.join("logs");
        std::fs::create_dir(&log).unwrap();
        // What Explorer's "Continue" leaves: an explicit grant to another account.
        set_acl(&log, &format!("D:PAI(A;OICI;FA;;;{me})(A;OICI;FA;;;SY)(A;OICI;0x1301bf;;;BU)"), true).unwrap();
        assert_eq!(assert_path(&dir, &owners, true).unwrap_err().step, "Installer child is writable by an untrusted principal");
        assert_path_with(&dir, &owners, true, Rule::Repair).unwrap();
        assert!(security(&log, "null").unwrap().aces.iter().all(|ace| ace.sid != "S-1-5-32-545"), "the grant survived the repair");
        assert_path(&dir, &owners, true).unwrap();
    }

    #[test]
    fn a_new_directory_is_born_with_its_descriptor_and_never_reused() {
        let me = current_user();
        let dir = tempfile_dir();
        let target = dir.join("child");
        let sddl = format!("D:P(A;OICI;FA;;;{me})(A;OICI;0x1200a9;;;BU)");
        create_directory_new(&target, &sddl).unwrap();
        let born = security(&target, "null").unwrap();
        // No inherited Users create right from ProgramData, not even for an instant.
        assert!(born.aces.iter().all(|ace| ace.sid != "S-1-5-32-545" || ace.mask & WRITE_RIGHTS == 0), "inherited write right on creation");
        assert_eq!(create_directory_new(&target, &sddl).unwrap_err().step, "Directory appeared while it was being created");
    }

    #[test]
    fn a_bounded_read_refuses_one_byte_more_than_its_limit() {
        let dir = tempfile_dir();
        let file = dir.join("provision.json");
        std::fs::write(&file, vec![b'x'; 16]).unwrap();
        assert_eq!(read_plain(&file, 16, "too large").unwrap().len(), 16);
        assert_eq!(read_plain(&file, 15, "too large").unwrap_err().step, "too large");
    }

    #[test]
    fn the_service_sid_matches_a_known_windows_account() {
        // TrustedInstaller's own service SID is public (TRUSTED_INSTALLER above); `sc
        // showsid TrustedInstaller` reports the same value.
        assert_eq!(service_sid("TrustedInstaller"), TRUSTED_INSTALLER);
    }

    #[test]
    fn a_write_directory_grants_only_the_service_sid_and_owner_rights_read_control() {
        let sid = service_sid("Milvago Agent Logger");
        let sddl = private_sddl(Access::Write, &sid);
        assert!(sddl.contains(&format!(";;;{sid})")), "missing service SID: {sddl}");
        assert!(sddl.contains(&format!("(A;OICI;0x20000;;;{OWNER_RIGHTS})")), "missing Owner Rights READ_CONTROL: {sddl}");
        assert!(!sddl.contains(&format!(";;;{NETWORK_SERVICE})")), "unexpected NetworkService ACE: {sddl}");
    }
}
