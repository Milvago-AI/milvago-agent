//! Typed HKLM registry access (64-bit view) for snapshots that must restore exactly what
//! they captured. Value kinds and JSON shapes follow the PowerShell transaction
//! (`Browser-ReadKey` / `Browser-WriteValue`): strings as text, DWORD/QWORD as numbers,
//! multi-strings as arrays, binary as arrays of bytes.
use crate::win::{Failure, Result, fail};
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use std::ffi::c_void;

const HKLM: isize = 0x80000002u32 as i32 as isize;
const WOW64_64: u32 = 0x0100;
const KEY_READ: u32 = 0x20019;
/// KEY_READ | KEY_SET_VALUE | KEY_CREATE_SUB_KEY: what writing a value needs, like
/// PowerShell's Set-ItemProperty. KEY_ALL_ACCESS also asked WRITE_DAC and WRITE_OWNER,
/// which a policy key restricted by its manager may withhold even from SYSTEM.
const KEY_WRITE_VALUES: u32 = 0x2001F;
/// DELETE | KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_ENUMERATE_SUB_KEYS (RegDeleteTreeW).
const KEY_DELETE_TREE: u32 = 0x1000B;

#[link(name = "advapi32")]
unsafe extern "system" {
    fn RegOpenKeyExW(key: isize, sub: *const u16, options: u32, access: u32, result: *mut isize) -> i32;
    fn RegCreateKeyExW(key: isize, sub: *const u16, reserved: u32, class: *const u16, options: u32, access: u32,
        security: *const c_void, result: *mut isize, disposition: *mut u32) -> i32;
    fn RegEnumValueW(key: isize, index: u32, name: *mut u16, name_len: *mut u32, reserved: *mut u32, kind: *mut u32, data: *mut u8, data_len: *mut u32) -> i32;
    fn RegEnumKeyExW(key: isize, index: u32, name: *mut u16, name_len: *mut u32, reserved: *mut u32, class: *mut u16, class_len: *mut u32, time: *mut u64) -> i32;
    fn RegQueryInfoKeyW(key: isize, class: *mut u16, class_len: *mut u32, reserved: *mut u32, subkeys: *mut u32, max_subkey: *mut u32,
        max_class: *mut u32, values: *mut u32, max_value_name: *mut u32, max_value: *mut u32, security: *mut u32, time: *mut u64) -> i32;
    fn RegSetValueExW(key: isize, name: *const u16, reserved: u32, kind: u32, data: *const u8, size: u32) -> i32;
    fn RegDeleteValueW(key: isize, name: *const u16) -> i32;
    fn RegDeleteTreeW(key: isize, sub: *const u16) -> i32;
    fn RegCloseKey(key: isize) -> i32;
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}
/// `HKLM:\Software\...` (the PowerShell form) or a bare `SOFTWARE\...` path.
fn relative(path: &str) -> Result<&str> {
    let path = path.strip_prefix("HKLM:\\").unwrap_or(path);
    if path.is_empty() || path.contains(['\0', '/']) || path.split('\\').any(|part| part.is_empty() || part == "..") {
        return fail("Unexpected registry path");
    }
    Ok(path)
}

struct Key(isize);
impl Drop for Key {
    fn drop(&mut self) {
        unsafe { RegCloseKey(self.0) };
    }
}
fn open(path: &str, access: u32) -> Result<Option<Key>> {
    let sub = wide(relative(path)?);
    let mut key = 0;
    match unsafe { RegOpenKeyExW(HKLM, sub.as_ptr(), 0, access | WOW64_64, &mut key) } {
        0 => Ok(Some(Key(key))),
        2 => Ok(None),
        _ => fail("Registry key unavailable"),
    }
}
/// Open or create `path` and every missing key above it (RegCreateKeyExW, like
/// `New-Item -Force`).
fn create(path: &str) -> Result<Key> {
    create_with(path, KEY_WRITE_VALUES)
}
fn create_with(path: &str, access: u32) -> Result<Key> {
    let sub = wide(relative(path)?);
    let (mut key, mut disposition) = (0, 0u32);
    let status = unsafe { RegCreateKeyExW(HKLM, sub.as_ptr(), 0, std::ptr::null(), 0, access | WOW64_64, std::ptr::null(), &mut key, &mut disposition) };
    if status != 0 {
        return Err(Failure { step: "Registry key could not be created", detail: format!("win32={status}") });
    }
    Ok(Key(key))
}

/// One named value, as the snapshot records it.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RegValue {
    pub name: String,
    pub kind: String,
    pub data: Json,
}

fn decode(kind: u32, bytes: &[u8]) -> Result<(String, Json)> {
    let words = || -> Vec<u16> { bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect() };
    let text = |w: &[u16]| String::from_utf16_lossy(&w[..w.iter().position(|&c| c == 0).unwrap_or(w.len())]);
    Ok(match kind {
        1 => ("String".into(), Json::String(text(&words()))),
        2 => ("ExpandString".into(), Json::String(text(&words()))),
        4 if bytes.len() == 4 => ("DWord".into(), Json::from(i32::from_le_bytes(bytes.try_into().unwrap()))),
        11 if bytes.len() == 8 => ("QWord".into(), Json::from(i64::from_le_bytes(bytes.try_into().unwrap()))),
        7 => {
            let w = words();
            let mut items: Vec<Json> = w.split(|&c| c == 0).map(|s| Json::String(String::from_utf16_lossy(s))).collect();
            // A MULTI_SZ ends with two NULs; drop the empty tail they produce.
            while items.last().is_some_and(|v| v.as_str() == Some("")) {
                items.pop();
            }
            ("MultiString".into(), Json::Array(items))
        }
        3 => ("Binary".into(), Json::Array(bytes.iter().map(|&b| Json::from(b)).collect())),
        0 => ("None".into(), Json::Array(bytes.iter().map(|&b| Json::from(b)).collect())),
        // Any other type, or a DWORD/QWORD of another size, kept as its type and bytes:
        // reading a foreign value next to ours must not fail (`reg export` took every
        // type), and a snapshot restores it exactly.
        other => (format!("Raw:{other}"), Json::Array(bytes.iter().map(|&b| Json::from(b)).collect())),
    })
}
fn encode(value: &RegValue) -> Result<(u32, Vec<u8>)> {
    let utf16 = |text: &str| -> Vec<u8> { text.encode_utf16().chain(Some(0)).flat_map(u16::to_le_bytes).collect() };
    let text = || value.data.as_str().ok_or(Failure { step: "Invalid registry snapshot value", detail: String::new() });
    let bytes = || -> Result<Vec<u8>> {
        value.data.as_array().ok_or(Failure { step: "Invalid registry snapshot value", detail: String::new() })?
            .iter().map(|b| b.as_u64().and_then(|b| u8::try_from(b).ok()).ok_or(Failure { step: "Invalid registry snapshot value", detail: String::new() }))
            .collect()
    };
    Ok(match value.kind.as_str() {
        "String" => (1, utf16(text()?)),
        "ExpandString" => (2, utf16(text()?)),
        "DWord" => (4, (value.data.as_i64().ok_or(Failure { step: "Invalid registry snapshot value", detail: String::new() })? as i32).to_le_bytes().to_vec()),
        "QWord" => (11, value.data.as_i64().ok_or(Failure { step: "Invalid registry snapshot value", detail: String::new() })?.to_le_bytes().to_vec()),
        "MultiString" => {
            let items = value.data.as_array().ok_or(Failure { step: "Invalid registry snapshot value", detail: String::new() })?;
            let mut data = Vec::new();
            for item in items {
                data.extend(utf16(item.as_str().ok_or(Failure { step: "Invalid registry snapshot value", detail: String::new() })?));
            }
            data.extend([0, 0]);
            (7, data)
        }
        "Binary" => (3, bytes()?),
        "None" => (0, bytes()?),
        raw => match raw.strip_prefix("Raw:").and_then(|n| n.parse::<u32>().ok()) {
            Some(kind) => (kind, bytes()?),
            None => return fail("Unsupported registry value type"),
        },
    })
}

/// Values of a key; `None` when the key does not exist. Expandable strings are kept
/// unexpanded (DoNotExpandEnvironmentNames).
pub fn read_key(path: &str) -> Result<Option<Vec<RegValue>>> {
    let Some(key) = open(path, KEY_READ)? else { return Ok(None) };
    let (mut max_name, mut max_data, mut count) = (0u32, 0u32, 0u32);
    if unsafe { RegQueryInfoKeyW(key.0, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(),
        std::ptr::null_mut(), std::ptr::null_mut(), &mut count, &mut max_name, &mut max_data, std::ptr::null_mut(), std::ptr::null_mut()) } != 0
    {
        return fail("Registry key unavailable");
    }
    let mut values = Vec::new();
    for index in 0..count {
        let mut name = vec![0u16; max_name as usize + 1];
        let mut name_len = name.len() as u32;
        let mut data = vec![0u8; max_data as usize + 2];
        let (mut kind, mut data_len) = (0u32, data.len() as u32);
        if unsafe { RegEnumValueW(key.0, index, name.as_mut_ptr(), &mut name_len, std::ptr::null_mut(), &mut kind, data.as_mut_ptr(), &mut data_len) } != 0 {
            return fail("Registry value unavailable");
        }
        let (kind, data) = decode(kind, &data[..data_len as usize])?;
        values.push(RegValue { name: String::from_utf16_lossy(&name[..name_len as usize]), kind, data });
    }
    Ok(Some(values))
}
pub fn value(values: &[RegValue], name: &str) -> Option<RegValue> {
    values.iter().find(|v| v.name.eq_ignore_ascii_case(name)).cloned()
}
pub fn write_value(path: &str, value: &RegValue) -> Result<()> {
    let key = create(path)?;
    let (kind, data) = encode(value)?;
    let name = wide(&value.name);
    if unsafe { RegSetValueExW(key.0, name.as_ptr(), 0, kind, data.as_ptr(), data.len() as u32) } != 0 {
        return fail("Registry value could not be written");
    }
    Ok(())
}
pub fn remove_value(path: &str, name: &str) -> Result<()> {
    let Some(key) = open(path, 0x0003)? else { return Ok(()) }; // KEY_QUERY_VALUE | KEY_SET_VALUE
    let name = wide(name);
    match unsafe { RegDeleteValueW(key.0, name.as_ptr()) } {
        0 | 2 => Ok(()),
        _ => fail("Registry value could not be removed"),
    }
}
pub fn delete_tree(path: &str) -> Result<()> {
    let relative = relative(path)?;
    let (parent, leaf) = relative.rsplit_once('\\').ok_or(Failure { step: "Unexpected registry path", detail: String::new() })?;
    let Some(key) = open(parent, KEY_DELETE_TREE)? else { return Ok(()) };
    let leaf = wide(leaf);
    match unsafe { RegDeleteTreeW(key.0, leaf.as_ptr()) } {
        0 | 2 => Ok(()),
        _ => fail("Registry key could not be removed"),
    }
}

/// Owner and allowed ACEs (SID, mask) of a key; `None` when absent. A null DACL fails.
pub fn key_security(path: &str) -> Result<Option<(String, Vec<(String, u32, bool)>)>> {
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn GetSecurityInfo(handle: isize, kind: u32, info: u32, owner: *mut *mut c_void, group: *mut *mut c_void,
            dacl: *mut *mut c_void, sacl: *mut *mut c_void, descriptor: *mut *mut c_void) -> u32;
        fn GetAce(acl: *const c_void, index: u32, ace: *mut *mut c_void) -> i32;
        fn ConvertSidToStringSidW(sid: *const c_void, text: *mut *mut u16) -> i32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LocalFree(p: *mut c_void) -> *mut c_void;
    }
    let sid = |sid: *const c_void| -> Option<String> {
        let mut text = std::ptr::null_mut();
        if sid.is_null() || unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 { return None; }
        let mut n = 0;
        while unsafe { *text.add(n) } != 0 { n += 1; }
        let value = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, n) });
        unsafe { LocalFree(text.cast()) };
        Some(value)
    };
    let Some(key) = open(path, 0x0002_0000)? else { return Ok(None) }; // READ_CONTROL
    let (mut owner, mut dacl, mut descriptor) = (std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut());
    // SE_REGISTRY_KEY; OWNER | DACL.
    if unsafe { GetSecurityInfo(key.0, 4, 5, &mut owner, std::ptr::null_mut(), &mut dacl, std::ptr::null_mut(), &mut descriptor) } != 0 {
        return fail("Registry key permissions unavailable");
    }
    let result = (|| {
        if dacl.is_null() {
            return fail("Untrusted update authorization registry key");
        }
        let owner = sid(owner).ok_or(Failure { step: "Registry key permissions unavailable", detail: String::new() })?;
        let count = unsafe { *dacl.cast::<u8>().add(4).cast::<u16>() };
        let mut aces = Vec::new();
        for index in 0..u32::from(count) {
            let mut ace = std::ptr::null_mut();
            if unsafe { GetAce(dacl, index, &mut ace) } == 0 {
                return fail("Registry key permissions unavailable");
            }
            let kind = unsafe { *ace.cast::<u8>() };
            let mask = unsafe { *ace.cast::<u8>().add(4).cast::<u32>() };
            let principal = sid(unsafe { ace.cast::<u8>().add(8).cast() }).ok_or(Failure { step: "Registry key permissions unavailable", detail: String::new() })?;
            aces.push((principal, mask, kind == 0));
        }
        Ok(Some((owner, aces)))
    })();
    unsafe { LocalFree(descriptor) };
    result
}

/// Create a key whose protected DACL is `sddl` (owner included).
pub fn create_protected_key(path: &str, sddl: &str) -> Result<()> {
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl: *const u16, revision: u32, descriptor: *mut *mut c_void, size: *mut u32) -> i32;
        fn RegSetKeySecurity(key: isize, info: u32, descriptor: *const c_void) -> i32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LocalFree(p: *mut c_void) -> *mut c_void;
    }
    // WRITE_DAC | WRITE_OWNER on top of the value rights.
    let key = create_with(path, KEY_WRITE_VALUES | 0x000C_0000)?;
    let text = wide(sddl);
    let mut descriptor = std::ptr::null_mut();
    if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(text.as_ptr(), 1, &mut descriptor, std::ptr::null_mut()) } == 0 {
        return fail("Invalid registry permission descriptor");
    }
    // OWNER | DACL | PROTECTED_DACL.
    let status = unsafe { RegSetKeySecurity(key.0, 0x8000_0005, descriptor) };
    unsafe { LocalFree(descriptor) };
    if status != 0 {
        return fail("Registry key permissions could not be set");
    }
    Ok(())
}
pub fn subkey_names(path: &str) -> Result<Vec<String>> {
    subkeys(path)
}

/// A key and every subkey, as (relative path from `path`, values). `None` when absent.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RegTree {
    pub exists: bool,
    pub keys: Vec<RegTreeKey>,
}
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RegTreeKey {
    pub relative: String,
    pub values: Vec<RegValue>,
}
fn subkeys(path: &str) -> Result<Vec<String>> {
    let Some(key) = open(path, KEY_READ)? else { return Ok(Vec::new()) };
    let mut names = Vec::new();
    for index in 0..65536 {
        let (mut name, mut name_len) = ([0u16; 256], 256u32);
        match unsafe { RegEnumKeyExW(key.0, index, name.as_mut_ptr(), &mut name_len, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()) } {
            0 => names.push(String::from_utf16_lossy(&name[..name_len as usize])),
            259 => break,
            _ => return fail("Registry subkeys unavailable"),
        }
    }
    Ok(names)
}
pub fn read_tree(path: &str) -> Result<RegTree> {
    let Some(root) = read_key(path)? else { return Ok(RegTree { exists: false, keys: Vec::new() }) };
    let mut keys = vec![RegTreeKey { relative: String::new(), values: root }];
    let mut pending = vec![String::new()];
    while let Some(prefix) = pending.pop() {
        for name in subkeys(&format!("{path}{prefix}"))? {
            let relative = format!("{prefix}\\{name}");
            let values = read_key(&format!("{path}{relative}"))?.unwrap_or_default();
            keys.push(RegTreeKey { relative: relative.clone(), values });
            pending.push(relative);
        }
    }
    Ok(RegTree { exists: true, keys })
}
/// Write every captured key and value, keeping what else exists (`reg import` semantics).
pub fn merge_tree(path: &str, tree: &RegTree) -> Result<()> {
    for key in &tree.keys {
        if !key.relative.is_empty() && (!key.relative.starts_with('\\') || key.relative.split('\\').any(|p| p == "..")) {
            return fail("Invalid registry snapshot path");
        }
        let target = format!("{path}{}", key.relative);
        drop(create(&target)?);
        for value in &key.values {
            write_value(&target, value)?;
        }
    }
    Ok(())
}
/// `Browser-RestoreTree`: replace the key with exactly the captured tree, then verify.
pub fn restore_tree(path: &str, tree: &RegTree) -> Result<()> {
    delete_tree(path)?;
    if tree.exists {
        merge_tree(path, tree)?;
    }
    let actual = read_tree(path)?;
    if actual.exists != tree.exists || actual.keys.len() != tree.keys.len() {
        return fail("Extension policy tree restoration failed");
    }
    for key in &tree.keys {
        let found = actual.keys.iter().find(|k| k.relative.eq_ignore_ascii_case(&key.relative))
            .ok_or(Failure { step: "Extension policy values differ", detail: String::new() })?;
        if found.values.len() != key.values.len() {
            return fail("Extension policy values differ");
        }
        for wanted in &key.values {
            if value(&found.values, &wanted.name).as_ref() != Some(wanted) {
                return fail("Extension policy value restoration failed");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_value_kind_round_trips_through_the_snapshot_shape() {
        for (kind, data) in [
            ("String", serde_json::json!("a;b")), ("ExpandString", serde_json::json!("%ProgramData%\\x")),
            ("DWord", serde_json::json!(-1)), ("QWord", serde_json::json!(1_i64 << 40)),
            ("MultiString", serde_json::json!(["{\"a\":1}", "second"])), ("Binary", serde_json::json!([0, 255, 7])),
            ("None", serde_json::json!([])), ("Raw:5", serde_json::json!([0, 0, 0, 1])), ("Raw:10", serde_json::json!([9])),
        ] {
            let value = RegValue { name: "v".into(), kind: kind.into(), data };
            let (code, bytes) = encode(&value).unwrap();
            let (back_kind, back) = decode(code, &bytes).unwrap();
            assert_eq!((back_kind.as_str(), &back), (kind, &value.data), "{kind}");
        }
    }

    #[test]
    fn a_foreign_value_of_any_type_or_size_is_read_and_restored_exactly() {
        // REG_DWORD_BIG_ENDIAN, REG_LINK, REG_RESOURCE_LIST, a three-byte DWORD, a short QWORD.
        for (kind, bytes) in [(5u32, vec![0u8, 0, 0, 1]), (6, vec![b'x', 0]), (8, vec![1, 2]), (4, vec![1, 2, 3]), (11, vec![1])] {
            let (name, data) = decode(kind, &bytes).unwrap();
            assert_eq!(name, format!("Raw:{kind}"));
            let (back_kind, back) = encode(&RegValue { name: "v".into(), kind: name, data }).unwrap();
            assert_eq!((back_kind, back), (kind, bytes));
        }
        for bad in ["Raw:", "Raw:x", "Raw:-1", "Link"] {
            assert!(encode(&RegValue { name: "v".into(), kind: bad.into(), data: serde_json::json!([]) }).is_err(), "{bad}");
        }
    }

    #[test]
    fn paths_cannot_leave_the_named_key() {
        for path in ["", "SOFTWARE\\..\\SAM", "SOFTWARE\\\\x", "SOFTWARE/x"] {
            assert!(relative(path).is_err(), "{path}");
        }
        assert_eq!(relative("HKLM:\\Software\\Policies").unwrap(), "Software\\Policies");
    }

    #[test]
    fn a_real_key_reads_without_error() {
        let values = read_key(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion").unwrap().unwrap();
        assert!(value(&values, "CurrentBuild").is_some());
        assert!(read_key(r"SOFTWARE\MilvagoInstallerTestAbsent").unwrap().is_none());
    }
}
