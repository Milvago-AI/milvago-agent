//! Separate discovery authority; no identity is adopted from the agent's store.
use crate::{
    configure::{self, Layout},
    paths,
    services::{self, Configuration, Recovery, RecoveryAction},
    win::{self, Failure, Result, fail},
};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub fn service_name(edition: &str) -> Result<&'static str> {
    match edition {
        "community" => Ok("Milvago Discovery Community"),
        "commercial" => Ok("Milvago Discovery"),
        _ => fail("Invalid discovery edition"),
    }
}
fn configuration(edition: &str, executable: &Path, configured: bool) -> Result<Configuration> {
    let name = service_name(edition)?;
    Ok(Configuration {
        kind: 0x10,
        start: if configured { 2 } else { 3 },
        error: 1,
        binary: format!("\"{}\" service", executable.display()),
        group: String::new(),
        account: "LocalSystem".into(),
        display: name.into(),
        // Independent startup also lets MSI stop the browser service first.
        dependencies: Vec::new(),
        delayed_auto: false,
    })
}
pub fn home(l: &Layout) -> PathBuf {
    l.data.join("MilvagoDiscovery").join(l.edition)
}

pub fn install(l: &Layout, fresh: bool) -> Result<()> {
    let name = service_name(l.edition)?;
    configure::assert_owned(l, name)?;
    let executable = l.runtime.join("milvago-discovery-system.exe");
    paths::assert_path(&executable, &[paths::SYSTEM, paths::ADMINISTRATORS], false)?;
    let output = win::run(
        "Discovery runtime identity",
        &executable,
        &["--capabilities"],
        Instant::now() + Duration::from_secs(15),
    )?;
    let capability: serde_json::Value = serde_json::from_str(&output).map_err(|_| Failure {
        step: "Invalid discovery runtime identity",
        detail: String::new(),
    })?;
    if capability.as_object().map_or(true, |v| v.len() != 5)
        || capability["version"] != l.version
        || capability["edition"] != l.edition
        || capability["service"] != name
        || capability["discovery_protocol"] != 1
        || capability["additional_driver"] != false
    {
        return fail("Discovery runtime edition or version mismatch");
    }
    let parent = l.data.join("MilvagoDiscovery");
    configure::set_aside_if_planted(&parent, fresh)?;
    // Existing authority is inspected, never made trustworthy by changing its ACL.
    paths::authorization_directory(&parent, false)?;
    let root = home(l);
    configure::set_aside_if_planted(&root, fresh)?;
    paths::authorization_directory(&root, false)?;
    let configured = root.join("anchor.json").try_exists().map_err(|_| Failure {
        step: "Discovery binding unavailable",
        detail: String::new(),
    })?;
    services::write_configuration(name, &configuration(l.edition, &executable, configured)?)?;
    services::set_sid_unrestricted(name)?;
    services::set_required_privileges(
        name,
        &[
            "SeChangeNotifyPrivilege",
            "SeCreateGlobalPrivilege",
            "SeTcbPrivilege",
            "SeAssignPrimaryTokenPrivilege",
            "SeIncreaseQuotaPrivilege",
        ],
    )?;
    services::set_sddl(
        name,
        "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;LC;;;AU)",
    )?;
    services::write_recovery(
        name,
        &Recovery {
            reset_period: 86400,
            reboot_message: String::new(),
            command: String::new(),
            non_crash_failures: false,
            actions: [5000, 15000, 60000]
                .into_iter()
                .map(|delay| RecoveryAction { kind: 1, delay })
                .collect(),
        },
    )?;
    services::write_metadata(
        name,
        name,
        "Milvago discovery: administrator-bound, signed source permissions, no additional driver.",
    )
}
pub fn start_configured(l: &Layout) -> Result<()> {
    if home(l)
        .join("anchor.json")
        .try_exists()
        .map_err(|_| Failure {
            step: "Discovery binding unavailable",
            detail: String::new(),
        })?
    {
        services::start(service_name(l.edition)?, Duration::from_secs(40))?;
    }
    Ok(())
}
pub fn remove(l: &Layout) -> Result<()> {
    let name = service_name(l.edition)?;
    configure::assert_owned(l, name)?;
    // Binding and anti-replay journal survive removal, just like authorization custody.
    services::remove_owned(name, "milvago-discovery-system")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unbound_discovery_is_manual_and_never_runs_under_the_browser_account() {
        for (edition, expected) in [
            ("community", "Milvago Discovery Community"),
            ("commercial", "Milvago Discovery"),
        ] {
            for bound in [false, true] {
                let value=configuration(edition,Path::new(r"C:\Program Files\Milvago\Browser\runtime\0.7.1\milvago-discovery-system.exe"),bound).unwrap();
                assert_eq!(value.start, if bound { 2 } else { 3 });
                assert_eq!(value.account, "LocalSystem");
                assert!(value.dependencies.is_empty());
                assert_eq!(value.display, expected);
                assert!(value.binary.ends_with("\" service"));
            }
        }
        assert!(service_name("data:image/png").is_err());
    }
}
