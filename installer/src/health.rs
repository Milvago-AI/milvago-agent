//! CheckHealth: prove the installed release is the one running and fully wired, before
//! Windows Installer commits. Port of `deploy/configure-agent.ps1 -Operation Health`,
//! with the budget raised from 60 to 120 s (a first run held by Defender's cloud check).
use crate::services;
use crate::win::{self, Failure, Result, Service, fail};
use serde_json::Value;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::configure::{FORCED, NATIVE_HOSTS, layout};

/// The service, when installed, must run exactly this release's executable (which also
/// satisfies the path-shape rule of `Test-InstallerServiceImage`).
fn owned(name: &str, executable: &Path) -> Result<()> {
    let Some(image) = win::reg_string(&format!(r"SYSTEM\CurrentControlSet\Services\{name}"), "ImagePath") else {
        if win::reg_key_exists(&format!(r"SYSTEM\CurrentControlSet\Services\{name}")) {
            return fail("Service executable ownership mismatch");
        }
        return Ok(());
    };
    let quoted = format!("\"{}\"", executable.display());
    let image_lower = image.to_lowercase();
    let quoted_lower = quoted.to_lowercase();
    if image_lower != quoted_lower && !image_lower.starts_with(&(quoted_lower + " ")) {
        return fail("Configured service runtime differs from installed release");
    }
    Ok(())
}

fn remaining(deadline: Instant) -> Result<Instant> {
    if Instant::now() >= deadline {
        return fail("Local readiness deadline exceeded");
    }
    Ok(deadline)
}

fn text(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).map(|value| value.trim().to_owned())
        .map_err(|_| Failure { step: "Extension identity unavailable", detail: String::new() })
}

fn json(step: &'static str, output: &str) -> Result<Value> {
    serde_json::from_str(output).map_err(|error| Failure { step, detail: error.to_string() })
}

fn forcelist(vendor: &str) -> Vec<String> {
    win::reg_string_values(&format!(r"SOFTWARE\Policies\{vendor}\ExtensionInstallForcelist"))
        .into_iter()
        .filter(|(name, _)| !name.is_empty() && name.bytes().all(|c| c.is_ascii_digit()))
        .map(|(_, value)| value)
        .collect()
}

pub fn run(edition: &str) -> Result<String> {
    let deadline = Instant::now() + Duration::from_secs(120);
    let l = layout(edition)?;
    let agent = l.agent.clone();
    owned(l.agent_service, &agent)?;
    owned(l.applier_service, &l.runtime.join("milvago-updater.exe"))?;
    // The applier runs from boot and holds its pipe names: started and checked too.
    let mut started = vec![l.agent_service, l.applier_service];
    if l.commercial {
        owned("Milvago Native Collector", &l.runtime.join("milvago-collector.exe"))?;
        owned("MilvagoModelFilter", &l.runtime.join("milvago-model-filter.exe"))?;
        started.extend(["Milvago Native Collector", "MilvagoModelFilter"]);
    }
    for name in started {
        Service::open(name)?.ok_or(Failure { step: "Required service missing", detail: name.into() })?;
        // Started is not running: waits for RUNNING (1056, already running, tolerated), so
        // a service that fails right after StartService fails Health.
        services::start(name, deadline.saturating_duration_since(Instant::now()).min(Duration::from_secs(30)))?;
    }
    let applier = Service::open(l.applier_service)?.ok_or(Failure { step: "Update applier configuration invalid", detail: String::new() })?;
    let config = applier.config()?;
    if !config.account.eq_ignore_ascii_case("LocalSystem") || config.start != win::SERVICE_AUTO_START {
        return fail("Update applier configuration invalid");
    }
    let (mut network_start, mut authenticated_start) = (false, false);
    for (sid, mask) in applier.allowed_aces()? {
        match sid.as_str() {
            "S-1-5-20" => { if mask != 16 { return fail("Excessive update applier permissions"); } network_start = true; }
            "S-1-5-11" => { if mask != 16 { return fail("Excessive update applier permissions"); } authenticated_start = true; }
            "S-1-5-18" | "S-1-5-32-544" => {}
            _ => return fail("Unexpected update applier principal"),
        }
    }
    if !network_start || !authenticated_start {
        return fail("Update applier start permissions invalid");
    }
    // Registry value, never sc.exe's possibly localized text. 1 = unrestricted.
    if win::reg_dword(&format!(r"SYSTEM\CurrentControlSet\Services\{}", l.agent_service), "ServiceSidType") != Some(1) {
        return fail("Agent service SID type is not unrestricted");
    }
    // NetworkService holds SeImpersonatePrivilege; the agent keeps only what identifying
    // pipe clients needs.
    if services::required_privileges(l.agent_service)?.iter().map(String::as_str).ne(["SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege"]) {
        return fail("Agent service privileges are not exactly the required set");
    }
    if l.commercial && win::reg_dword(r"SYSTEM\CurrentControlSet\Services\MilvagoModelFilter", "ServiceSidType") != Some(1) {
        return fail("Filter service SID type is not unrestricted");
    }
    if l.commercial && services::required_privileges("MilvagoModelFilter")?.iter().map(String::as_str).ne(["SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege"]) {
        return fail("Filter service privileges are not exactly the required set");
    }
    let names: Vec<&str> = if l.commercial {
        vec![l.agent_service, l.applier_service, "Milvago Native Collector", "MilvagoModelFilter"]
    } else {
        vec![l.agent_service, l.applier_service]
    };
    let output = win::run("Local operational health", &agent, &["health"], remaining(deadline)?).map_err(|mut failure| {
        // Which link failed (from the agent) and how each service stands right now.
        let states: Vec<String> = names.iter().map(|name| services::summary(name)).collect();
        failure.detail = format!("{} | {}", failure.detail, states.join(", "));
        failure
    })?;
    let health = json("Local operational health mismatch", &output)?;
    if health["ok"] != true || health["ready"] != true || health["edition"] != edition || health["version"] != l.version.as_str() {
        return fail("Local operational health mismatch");
    }
    if l.commercial && (health["collector_ready"] != true || health["filter_ready"] != true) {
        return fail("Enterprise service chain unavailable");
    }
    for browser in NATIVE_HOSTS {
        let wanted = l.install.join(if browser == "Mozilla" { "native-firefox.json" } else { "native-chromium.json" });
        if win::reg_string(&format!(r"SOFTWARE\{browser}\NativeMessagingHosts\app.milvago.browser"), "").as_deref()
            != Some(wanted.to_string_lossy().as_ref())
        {
            return fail("Native messaging registration mismatch");
        }
    }
    let id = text(&l.install.join("extension-id.txt"))?;
    let gecko = text(&l.install.join("extension-firefox-id.txt"))?;
    let state = l.state.to_string_lossy().into_owned();
    let origin = json("Registered deployment origin missing",
        &win::run("Registered deployment origin", &agent, &["installation-info", &state], remaining(deadline)?)?)?;
    if origin["server_url"].as_str().is_none_or(str::is_empty) {
        return fail("Registered deployment origin missing");
    }
    let local = json("Embedded extension mismatch", &win::run("Embedded extension channel", &agent, &["extension-info"], remaining(deadline)?)?)?;
    if local["embedded"] != true || local["chromium_id"] != id.as_str() {
        return fail("Embedded extension mismatch");
    }
    let url = format!("{}/ext/update.xml", local["origin"].as_str().unwrap_or_default());
    let entry = format!("{id};{url}");
    for vendor in FORCED {
        if forcelist(vendor).iter().filter(|value| **value == entry).count() != 1 {
            return fail("Extension force-install policy missing or duplicated");
        }
        let settings = format!(r"SOFTWARE\Policies\{vendor}\ExtensionSettings\{id}");
        if win::reg_string(&settings, "installation_mode").as_deref() != Some("force_installed")
            || win::reg_string(&settings, "update_url").as_deref() != Some(url.as_str())
            || win::reg_dword(&settings, "override_update_url") != Some(1)
        {
            return fail("Extension update policy mismatch");
        }
    }
    let firefox: Value = win::reg_multi_joined(r"SOFTWARE\Policies\Mozilla\Firefox", "ExtensionSettings")
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .ok_or(Failure { step: "Firefox installation policy mismatch", detail: String::new() })?;
    let entry = &firefox[gecko.as_str()];
    if entry["installation_mode"] != "force_installed"
        || entry["install_url"] != local["firefox_install_url"]
        || entry["update_url"].as_str() != Some(format!("{}/ext/updates.json", local["firefox_origin"].as_str().unwrap_or_default()).as_str())
    {
        return fail("Firefox installation policy mismatch");
    }
    let certificate = l.install.join("extension-ca.cer");
    let certificate_text = certificate.to_string_lossy().into_owned();
    if !win::reg_string_values(r"SOFTWARE\Policies\Mozilla\Firefox\Certificates\Install").iter().any(|(_, value)| *value == certificate_text) {
        return fail("Firefox local CA policy missing");
    }
    if !certificate.is_file() {
        return fail("Firefox local CA file missing");
    }
    remaining(deadline)?;
    Ok("Local operational health verified".into())
}

