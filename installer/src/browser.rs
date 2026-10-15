//! Browser registrations owned by this product: native-messaging defaults, Chromium
//! force-install entries and extension trees, the Firefox ExtensionSettings entries and
//! local CA policy. Port of `deploy/installer-browser-state.ps1`: only Milvago
//! identities are captured or restored; everything else in those keys is preserved.
use crate::reg::{self, RegTree, RegValue};
use crate::win::{Failure, Result, fail};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as Json};
use std::path::PathBuf;

const VENDORS: [&str; 7] = ["Google\\Chrome", "Microsoft\\Edge", "BraveSoftware\\Brave-Browser", "BraveSoftware\\Brave", "Chromium", "Vivaldi", "TheBrowserCompany\\Arc"];
const FIREFOX: &str = r"Software\Policies\Mozilla\Firefox";
const CERTIFICATES: &str = r"Software\Policies\Mozilla\Firefox\Certificates\Install";

pub fn chromium_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|c| (b'a'..=b'p').contains(&c))
}
pub fn gecko_id(id: &str) -> bool {
    id.strip_suffix("@milvago.app").is_some_and(|name| !name.is_empty() && name.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'.' || c == b'-'))
}
fn owned(value: &RegValue, ids: &[String]) -> bool {
    let data = value.data.as_str().unwrap_or_default();
    ids.iter().any(|id| id == data.split(';').next().unwrap_or_default())
}
fn text(value: &RegValue) -> String {
    match &value.data {
        Json::String(s) => s.clone(),
        Json::Array(items) => items.iter().filter_map(Json::as_str).collect(),
        other => other.to_string(),
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Native {
    vendor: String,
    value: Option<RegValue>,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct Settings {
    id: String,
    tree: RegTree,
    pin: RegTree,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct Chromium {
    vendor: String,
    forced: Vec<RegValue>,
    settings: Vec<Settings>,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct Firefox {
    id: String,
    exists: bool,
    json: Option<String>,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct BrowserState {
    chromium_ids: Vec<String>,
    firefox_ids: Vec<String>,
    manifest_paths: Vec<String>,
    native: Vec<Native>,
    chromium: Vec<Chromium>,
    firefox: Vec<Firefox>,
    certificate_paths: Vec<String>,
    certificates: Vec<RegValue>,
    firefox_kind: String,
    firefox_value_existed: bool,
    /// The value existed and was empty; restored as such (`firefox_value_empty` of the
    /// PowerShell snapshot).
    #[serde(default)]
    firefox_value_empty: bool,
}

fn native_path(vendor: &str) -> String {
    format!(r"Software\{vendor}\NativeMessagingHosts\app.milvago.browser")
}
fn firefox_document(value: Option<&RegValue>) -> Result<Map<String, Json>> {
    let Some(value) = value else { return Ok(Map::new()) };
    if !matches!(value.kind.as_str(), "String" | "MultiString") {
        return fail("Unexpected Firefox ExtensionSettings registry type");
    }
    // An empty value is an unset policy, as PowerShell read it: not invalid JSON.
    if text(value).is_empty() {
        return Ok(Map::new());
    }
    match serde_json::from_str::<Json>(&text(value)) {
        Ok(Json::Object(document)) => Ok(document),
        Ok(_) => fail("Firefox ExtensionSettings must be a JSON object"),
        Err(_) => fail("Invalid Firefox ExtensionSettings JSON; refusing to overwrite"),
    }
}
fn programs() -> Result<PathBuf> {
    crate::paths::program_files()
}

/// `Save-BrowserState`: the packaged identities plus any previous one found in the
/// installed trees (which the enclosing transaction has already validated).
pub fn save(chromium: &str, firefox: &str, commercial: bool) -> Result<BrowserState> {
    if !chromium_id(chromium) || !gecko_id(firefox) {
        return fail("Invalid packaged extension identities");
    }
    let (mut chromium_ids, mut firefox_ids) = (vec![chromium.to_owned()], vec![firefox.to_owned()]);
    let folders: &[&str] = if commercial { &["Browser", "Commercial"] } else { &["Browser"] };
    let mut manifest_paths = Vec::new();
    for folder in folders {
        let root = programs()?.join("Milvago").join(folder);
        for file in ["native-chromium.json", "native-firefox.json"] {
            manifest_paths.push(root.join(file).to_string_lossy().into_owned());
        }
        if let Ok(id) = std::fs::read_to_string(root.join("extension-id.txt")) {
            let id = id.trim().to_owned();
            if !chromium_id(&id) {
                return fail("Invalid previous Chromium extension identity");
            }
            if !chromium_ids.contains(&id) {
                chromium_ids.push(id);
            }
        }
        if let Ok(id) = std::fs::read_to_string(root.join("extension-firefox-id.txt")) {
            let id = id.trim().to_owned();
            if !gecko_id(&id) {
                return fail("Invalid previous Firefox extension identity");
            }
            if !firefox_ids.contains(&id) {
                firefox_ids.push(id);
            }
        }
    }
    let mut native = Vec::new();
    for vendor in VENDORS.iter().copied().chain(["Mozilla"]) {
        let value = reg::read_key(&native_path(vendor))?.and_then(|values| reg::value(&values, ""));
        native.push(Native { vendor: vendor.into(), value });
    }
    let mut chromium_state = Vec::new();
    for vendor in VENDORS {
        let base = format!(r"Software\Policies\{vendor}");
        let forced = reg::read_key(&format!(r"{base}\ExtensionInstallForcelist"))?.unwrap_or_default()
            .into_iter().filter(|v| owned(v, &chromium_ids)).collect();
        let mut settings = Vec::new();
        for id in &chromium_ids {
            settings.push(Settings {
                id: id.clone(),
                tree: reg::read_tree(&format!(r"{base}\ExtensionSettings\{id}"))?,
                pin: reg::read_tree(&format!(r"{base}\3rdparty\extensions\{id}\policy"))?,
            });
        }
        chromium_state.push(Chromium { vendor: vendor.into(), forced, settings });
    }
    let value = reg::read_key(FIREFOX)?.and_then(|values| reg::value(&values, "ExtensionSettings"));
    let document = firefox_document(value.as_ref())?;
    let firefox_state = firefox_ids.iter().map(|id| Firefox {
        id: id.clone(),
        exists: document.contains_key(id),
        json: document.get(id).map(Json::to_string),
    }).collect();
    let certificate_paths: Vec<String> = folders.iter()
        .map(|f| programs().map(|p| p.join("Milvago").join(f).join("extension-ca.cer").to_string_lossy().into_owned()))
        .collect::<Result<_>>()?;
    let certificates = reg::read_key(CERTIFICATES)?.unwrap_or_default().into_iter()
        .filter(|v| certificate_paths.iter().any(|p| Some(p.as_str()) == v.data.as_str())).collect();
    Ok(BrowserState {
        chromium_ids, firefox_ids, manifest_paths, native, chromium: chromium_state, firefox: firefox_state,
        certificate_paths, certificates,
        firefox_kind: value.as_ref().map_or_else(|| "MultiString".into(), |v| v.kind.clone()),
        firefox_value_existed: value.is_some(),
        firefox_value_empty: value.as_ref().is_some_and(|v| text(v).is_empty()),
    })
}

fn first_free(values: &[RegValue]) -> String {
    (1..).map(|n: u32| n.to_string()).find(|slot| reg::value(values, slot).is_none()).unwrap_or_default()
}

/// `Restore-BrowserState`.
pub fn restore(state: &BrowserState) -> Result<()> {
    let allowed: Vec<String> = ["Browser", "Commercial"].iter()
        .map(|f| programs().map(|p| p.join("Milvago").join(f).join("extension-ca.cer").to_string_lossy().into_owned()))
        .collect::<Result<_>>()?;
    if !state.certificate_paths.is_empty() {
        if state.certificate_paths.iter().any(|p| !allowed.contains(p)) {
            return fail("Foreign CA path in snapshot");
        }
        for value in reg::read_key(CERTIFICATES)?.unwrap_or_default() {
            if state.certificate_paths.iter().any(|p| Some(p.as_str()) == value.data.as_str()) {
                reg::remove_value(CERTIFICATES, &value.name)?;
            }
        }
        for value in &state.certificates {
            if !state.certificate_paths.iter().any(|p| Some(p.as_str()) == value.data.as_str()) {
                return fail("Foreign CA in snapshot");
            }
            let slot = first_free(&reg::read_key(CERTIFICATES)?.unwrap_or_default());
            reg::write_value(CERTIFICATES, &RegValue { name: slot.clone(), ..value.clone() })?;
            let actual = reg::read_key(CERTIFICATES)?.and_then(|values| reg::value(&values, &slot));
            if actual.map(|a| a.data) != Some(value.data.clone()) {
                return fail("Firefox CA policy restoration failed");
            }
        }
    }
    if state.chromium_ids.iter().any(|id| !chromium_id(id)) {
        return fail("Invalid Chromium identity in snapshot");
    }
    if state.firefox_ids.iter().any(|id| !gecko_id(id)) {
        return fail("Invalid Firefox identity in snapshot");
    }
    for entry in &state.native {
        if !VENDORS.contains(&entry.vendor.as_str()) && entry.vendor != "Mozilla" {
            return fail("Invalid browser in snapshot");
        }
        let path = native_path(&entry.vendor);
        let current = reg::read_key(&path)?.and_then(|values| reg::value(&values, ""));
        if let Some(current) = &current {
            let foreign = !state.manifest_paths.iter().any(|p| Some(p.as_str()) == current.data.as_str());
            if entry.value.as_ref().map(|v| &v.data) != Some(&current.data) && foreign {
                return fail("Native messaging host changed to a foreign owner; preserved");
            }
        }
        match &entry.value {
            Some(value) => reg::write_value(&path, value)?,
            None => reg::remove_value(&path, "")?,
        }
        let actual = reg::read_key(&path)?.and_then(|values| reg::value(&values, ""));
        if actual.as_ref().map(|a| (&a.kind, &a.data)) != entry.value.as_ref().map(|v| (&v.kind, &v.data)) {
            return fail("Native messaging default value restoration failed");
        }
    }
    for entry in &state.chromium {
        if !VENDORS.contains(&entry.vendor.as_str()) {
            return fail("Invalid browser in snapshot");
        }
        let base = format!(r"Software\Policies\{}", entry.vendor);
        let path = format!(r"{base}\ExtensionInstallForcelist");
        for value in reg::read_key(&path)?.unwrap_or_default() {
            if owned(&value, &state.chromium_ids) {
                reg::remove_value(&path, &value.name)?;
            }
        }
        let mut restored = Vec::new();
        for value in &entry.forced {
            if !owned(value, &state.chromium_ids) {
                return fail("Foreign forced extension in snapshot");
            }
            let current = reg::read_key(&path)?.unwrap_or_default();
            let slot = if reg::value(&current, &value.name).is_some() { first_free(&current) } else { value.name.clone() };
            let restored_value = RegValue { name: slot, ..value.clone() };
            reg::write_value(&path, &restored_value)?;
            restored.push(restored_value);
        }
        let actual: Vec<RegValue> = reg::read_key(&path)?.unwrap_or_default().into_iter().filter(|v| owned(v, &state.chromium_ids)).collect();
        if actual.len() != restored.len() {
            return fail("Forced extension restoration count differs");
        }
        for value in &restored {
            if reg::value(&actual, &value.name).as_ref() != Some(value) {
                return fail("Forced extension restoration failed");
            }
        }
        for setting in &entry.settings {
            if !state.chromium_ids.contains(&setting.id) {
                return fail("Foreign extension tree in snapshot");
            }
            reg::restore_tree(&format!(r"{base}\ExtensionSettings\{}", setting.id), &setting.tree)?;
            reg::restore_tree(&format!(r"{base}\3rdparty\extensions\{}\policy", setting.id), &setting.pin)?;
        }
    }
    let value = reg::read_key(FIREFOX)?.and_then(|values| reg::value(&values, "ExtensionSettings"));
    let mut document = firefox_document(value.as_ref())?;
    for entry in &state.firefox {
        if !state.firefox_ids.contains(&entry.id) {
            return fail("Foreign Firefox identity in snapshot");
        }
        if entry.exists {
            let json = entry.json.as_deref().ok_or(Failure { step: "Invalid Firefox snapshot", detail: String::new() })?;
            document.insert(entry.id.clone(), serde_json::from_str(json).map_err(|_| Failure { step: "Invalid Firefox snapshot", detail: String::new() })?);
        } else {
            document.remove(&entry.id);
        }
    }
    if document.is_empty() && !state.firefox_value_existed {
        reg::remove_value(FIREFOX, "ExtensionSettings")?;
    } else if document.is_empty() && state.firefox_value_empty {
        let data = if state.firefox_kind == "MultiString" { Json::Array(Vec::new()) } else { Json::String(String::new()) };
        reg::write_value(FIREFOX, &RegValue { name: "ExtensionSettings".into(), kind: state.firefox_kind.clone(), data })?;
    } else {
        let json = Json::Object(document.clone()).to_string();
        let kind = value.as_ref().map_or_else(|| state.firefox_kind.clone(), |v| v.kind.clone());
        let data = if kind == "MultiString" { Json::Array(vec![Json::String(json)]) } else { Json::String(json) };
        reg::write_value(FIREFOX, &RegValue { name: "ExtensionSettings".into(), kind, data })?;
    }
    let actual = firefox_document(reg::read_key(FIREFOX)?.and_then(|values| reg::value(&values, "ExtensionSettings")).as_ref())?;
    for entry in &state.firefox {
        if actual.contains_key(&entry.id) != entry.exists {
            return fail("Firefox extension restoration differs");
        }
        if entry.exists && entry.json.as_deref().and_then(|j| serde_json::from_str::<Json>(j).ok()).as_ref() != actual.get(&entry.id) {
            return fail("Firefox extension policy restoration failed");
        }
    }
    // The complete merged document, foreign entries included.
    if actual != document {
        return fail("Firefox foreign policy changed during restoration");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identities_follow_the_packaged_shapes() {
        assert!(chromium_id("nfeckglpbmfpflcdfciakndkopnpaffc"));
        assert!(!chromium_id("NFECKGLPBMFPFLCDFCIAKNDKOPNPAFFC"));
        assert!(!chromium_id("nfeckglpbmfpflcdfciakndkopnpaffq"));
        assert!(gecko_id("browser-community@milvago.app"));
        assert!(!gecko_id("@milvago.app") && !gecko_id("x@milvago.app.evil") && !gecko_id("X@milvago.app"));
    }

    #[test]
    fn only_our_forced_entries_are_owned() {
        let ids = vec!["nfeckglpbmfpflcdfciakndkopnpaffc".to_owned()];
        let ours = RegValue { name: "1".into(), kind: "String".into(), data: Json::String("nfeckglpbmfpflcdfciakndkopnpaffc;http://127.0.0.1/ext/update.xml".into()) };
        let theirs = RegValue { data: Json::String("aaaabbbbccccddddeeeeffffgggghhhh;https://clients2.google.com/service/update2/crx".into()), ..ours.clone() };
        assert!(owned(&ours, &ids) && !owned(&theirs, &ids));
    }

    #[test]
    fn a_firefox_document_that_is_not_an_object_is_refused() {
        let value = |data: Json, kind: &str| RegValue { name: "ExtensionSettings".into(), kind: kind.into(), data };
        assert!(firefox_document(Some(&value(Json::Array(vec![Json::String("{\"a\":{}".into()), Json::String("}".into())]), "MultiString"))).is_ok());
        assert!(firefox_document(Some(&value(Json::String("[1]".into()), "String"))).is_err());
        assert!(firefox_document(Some(&value(Json::String("{".into()), "String"))).is_err());
        assert!(firefox_document(Some(&value(Json::from(1), "DWord"))).is_err());
    }

    #[test]
    fn an_empty_firefox_value_is_an_unset_policy_not_invalid_json() {
        let value = |data: Json, kind: &str| RegValue { name: "ExtensionSettings".into(), kind: kind.into(), data };
        // Prepare refused these (and so the whole installation) where PowerShell read an empty policy.
        assert!(firefox_document(Some(&value(Json::Array(Vec::new()), "MultiString"))).unwrap().is_empty());
        assert!(firefox_document(Some(&value(Json::Array(vec![Json::String(String::new())]), "MultiString"))).unwrap().is_empty());
        assert!(firefox_document(Some(&value(Json::String(String::new()), "String"))).unwrap().is_empty());
        // Whitespace is not empty: still refused rather than overwritten.
        assert!(firefox_document(Some(&value(Json::String(" ".into()), "String"))).is_err());
        // A snapshot written before this field existed reads as "not empty".
        let old = r#"{"chromium_ids":[],"firefox_ids":[],"manifest_paths":[],"native":[],"chromium":[],"firefox":[],"certificate_paths":[],"certificates":[],"firefox_kind":"MultiString","firefox_value_existed":false}"#;
        assert!(!serde_json::from_str::<BrowserState>(old).unwrap().firefox_value_empty);
    }
}
