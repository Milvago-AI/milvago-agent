//! Distribution identities include their Windows owner; display names are never selectors.
#[cfg(windows)]
const OBSERVER_QUALIFIED: bool = true;
#[cfg(windows)]
const SYSTEM_OBSERVER_QUALIFIED: bool = true;

/// Build capability only; the installed WSL version still passes its ABI guard.
pub fn observer_transport_qualified() -> bool {
    #[cfg(windows)]
    {
        OBSERVER_QUALIFIED && SYSTEM_OBSERVER_QUALIFIED
    }
    #[cfg(not(windows))]
    {
        false
    }
}
#[cfg(windows)]
pub use milvago_discovery_collector::Budget as ObservationBudget;
#[cfg(any(windows, test))]
use serde::{Deserialize, Serialize};

#[cfg(any(windows, test))]
#[derive(Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Request {
    Inventory {},
    Processes {
        owner_sid: String,
        distribution_id: String,
    },
}

#[cfg(any(windows, test))]
impl Request {
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::Inventory {} => Ok(()),
            Self::Processes {
                owner_sid,
                distribution_id,
            } => Identity::parse(&format!("{owner_sid}/{distribution_id}")).map(|_| ()),
        }
    }
}

// The service IDL is private. Never dispatch a guessed vtable on another build.
#[cfg(any(windows, test))]
fn supported_abi(version: [u16; 4]) -> bool {
    version == [2, 6, 3, 0]
}

#[cfg(any(windows, test))]
fn validate_owner_token(expected: &str, actual: &str, elevated: bool) -> Result<(), &'static str> {
    Identity::parse(&format!("{expected}/11111111-1111-4111-8111-111111111111"))?;
    if expected != actual || elevated {
        return Err("access_denied");
    }
    Ok(())
}

#[cfg(any(windows, test))]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InventoryRow {
    uuid: String,
    running: bool,
    tools_available: bool,
    #[serde(default)]
    display_name: Option<String>,
}

#[cfg(any(windows, test))]
fn validate_inventory_owner(bytes: &[u8], owner: &str) -> Result<(), &'static str> {
    if bytes.len() > 65536 {
        return Err("response_limit");
    }
    Identity::parse(&format!("{owner}/11111111-1111-4111-8111-111111111111"))?;
    let rows: Vec<InventoryRow> = serde_json::from_slice(bytes).map_err(|_| "invalid_inventory")?;
    if rows.len() > 100 {
        return Err("vm_limit");
    }
    let mut seen = std::collections::BTreeSet::new();
    for row in rows {
        if Identity::parse(&row.uuid)?.owner != owner || !seen.insert(row.uuid) {
            return Err("invalid_inventory_owner");
        }
    }
    Ok(())
}

#[cfg(any(windows, test))]
pub(crate) fn merge_inventory(registered: &[u8], live: &[u8]) -> Result<Vec<u8>, &'static str> {
    if registered.len() > milvago_discovery_collector::MAX_RESPONSE || live.len() > 65536 {
        return Err("response_limit");
    }
    let rows: Vec<InventoryRow> =
        serde_json::from_slice(registered).map_err(|_| "invalid_inventory")?;
    let live: Vec<InventoryRow> = serde_json::from_slice(live).map_err(|_| "invalid_inventory")?;
    if rows.len() > 100 || live.len() > 100 {
        return Err("vm_limit");
    }
    let mut output = std::collections::BTreeMap::new();
    for row in rows {
        Identity::parse(&row.uuid)?;
        if output.insert(row.uuid.clone(), row).is_some() {
            return Err("invalid_inventory");
        }
    }
    let mut owner = None;
    let mut seen = std::collections::BTreeSet::new();
    for row in live {
        let identity = Identity::parse(&row.uuid)?;
        if owner.as_ref().is_some_and(|old| old != &identity.owner)
            || !seen.insert(row.uuid.clone())
        {
            return Err("invalid_inventory");
        }
        owner = Some(identity.owner);
        output.insert(row.uuid.clone(), row);
    }
    if output.len() > 100 {
        return Err("vm_limit");
    }
    serde_json::to_vec(&output.into_values().collect::<Vec<_>>()).map_err(|_| "invalid_inventory")
}

#[cfg(any(windows, test))]
mod exit_status;
#[cfg(windows)]
mod input_section;
#[cfg(windows)]
mod native;
#[cfg(windows)]
mod user_context;

#[cfg(windows)]
pub(crate) use user_context::system_query;

#[cfg(all(windows, feature = "windows-qualification"))]
mod system_qualification;
#[cfg(all(windows, feature = "windows-qualification"))]
pub use system_qualification::run as qualify_system_transport;
#[cfg(all(windows, feature = "windows-qualification"))]
pub use system_qualification::{
    handoff as qualify_system_handoff, handoff_probe as qualify_handoff_probe,
    owner_inventory as qualify_owner_inventory, owner_observe as qualify_owner_observe,
};

#[cfg(windows)]
pub fn probe() -> crate::Result<()> {
    use std::{io::Write, sync::atomic::AtomicBool, time::Duration};
    let input = std::env::var("MILVAGO_GUEST_INPUT").map_err(|_| "missing_wsl_request")?;
    if input.len() > 1024 {
        return Err("wsl_request_limit".into());
    }
    let request: Request = serde_json::from_str(&input).map_err(|_| "invalid_wsl_request")?;
    request.validate()?;
    let stop = AtomicBool::new(false);
    let budget = milvago_discovery_collector::Budget::new(Duration::from_secs(5), &stop);
    let output = native::query(request, &budget)?;
    std::io::stdout().write_all(&output)?;
    Ok(())
}

/// A compiled observer may inspect only the current owner's already-running
/// distribution, as its configured Linux account. No runtime-supplied program.
#[cfg(windows)]
pub fn observe_current(
    identity: &str,
    program: &'static str,
    input: &[u8],
    budget: &milvago_discovery_collector::Budget<'_>,
) -> Result<Vec<u8>, &'static str> {
    // Separate qualification: discovery's root process inventory proves neither
    // the default-user selector nor the private stdin transport.
    if !OBSERVER_QUALIFIED {
        return Err("unavailable");
    }
    native::observe(identity, program, input, budget)
}

/// SYSTEM delegates to a fixed helper of its own protected executable, using
/// only a real owner's non-elevated session token and anonymous read-only input.
#[cfg(windows)]
pub fn observe_owner(
    owner_sid: &str,
    distribution_id: &str,
    input: &[u8],
    budget: &milvago_discovery_collector::Budget<'_>,
) -> Result<Vec<u8>, &'static str> {
    if !SYSTEM_OBSERVER_QUALIFIED {
        return Err("unavailable");
    }
    user_context::observer_query(owner_sid, distribution_id, input, budget)
}

/// Entrypoint for binaries that embed one fixed observer; no program or command
/// is accepted from the caller. Production remains closed until qualification.
#[cfg(windows)]
pub fn observer_probe(program: &'static str) -> crate::Result<()> {
    if !SYSTEM_OBSERVER_QUALIFIED && !cfg!(feature = "windows-qualification") {
        return Err("unavailable".into());
    }
    let raw = std::env::var("MILVAGO_GUEST_INPUT").map_err(|_| "missing_wsl_request")?;
    if raw.len() > 1024 {
        return Err("request_limit".into());
    }
    let request: Request = serde_json::from_str(&raw).map_err(|_| "invalid_wsl_request")?;
    request.validate()?;
    let Request::Processes {
        owner_sid,
        distribution_id,
    } = request
    else {
        return Err("invalid_wsl_request".into());
    };
    let descriptor =
        std::env::var("MILVAGO_OBSERVER_INPUT").map_err(|_| "missing_observer_input")?;
    let input = input_section::receive(&descriptor)?;
    let stop = std::sync::atomic::AtomicBool::new(false);
    let budget = milvago_discovery_collector::Budget::new(std::time::Duration::from_secs(5), &stop);
    let output = zeroize::Zeroizing::new(native::observe(
        &format!("{owner_sid}/{distribution_id}"),
        program,
        &input,
        &budget,
    )?);
    std::io::Write::write_all(&mut std::io::stdout(), &output)?;
    Ok(())
}

#[cfg(windows)]
pub fn observer_inventory(
    budget: &milvago_discovery_collector::Budget<'_>,
) -> Result<Vec<u8>, &'static str> {
    if !SYSTEM_OBSERVER_QUALIFIED {
        return Err("unavailable");
    }
    user_context::system_query(
        &milvago_discovery_collector::system::Query::WslUserInventory,
        budget,
    )
    .unwrap_or(Err("access_denied"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Identity {
    pub owner: String,
    pub distribution: String,
}

impl Identity {
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        let (owner, distribution) = value.split_once('/').ok_or("invalid_wsl_identity")?;
        let parts: Vec<_> = owner.split('-').collect();
        if parts.len() != 8
            || parts[..4] != ["S", "1", "5", "21"] && parts[..4] != ["S", "1", "12", "1"]
        {
            return Err("invalid_wsl_identity");
        }
        for part in &parts[4..] {
            if part.is_empty()
                || part.len() > 10
                || part.starts_with('0') && *part != "0"
                || !part.bytes().all(|b| b.is_ascii_digit())
                || part.parse::<u32>().is_err()
            {
                return Err("invalid_wsl_identity");
            }
        }
        if owner.len() > 80
            || distribution.len() != 36
            || distribution != distribution.to_ascii_lowercase()
            || uuid::Uuid::parse_str(distribution).map_or(true, |id| id.is_nil())
        {
            return Err("invalid_wsl_identity");
        }
        Ok(Self {
            owner: owner.into(),
            distribution: distribution.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn wsl_reader_terminates_with_its_parent_and_control_stays_alive_without_guard() {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let mut child = Command::new("/usr/bin/python3")
            .args([
                "-I",
                "-S",
                "-c",
                include_str!("discovery_wsl/lifetime_test.py"),
            ])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(include_bytes!("discovery_wsl/process_lifetime.py"))
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
            serde_json::json!({"guarded_reader_terminated":true,"unguarded_reader_survived":true})
        );
    }

    #[test]
    fn owner_token_must_be_the_same_canonical_account_and_unelevated() {
        let owner = "S-1-5-21-1-2-3-1001";
        assert!(validate_owner_token(owner, owner, false).is_ok());
        for (expected, actual, elevated) in [
            (owner, owner, true),
            (owner, "S-1-5-21-1-2-3-1002", false),
            (owner, "s-1-5-21-1-2-3-1001", false),
            ("S-1-5-18", "S-1-5-18", false),
            ("data:image/png", "data:image/png", false),
        ] {
            assert!(validate_owner_token(expected, actual, elevated).is_err());
        }
    }
    #[test]
    fn user_probe_cannot_claim_another_windows_accounts_distributions() {
        let owner = "S-1-5-21-1-2-3-1001";
        let other = "S-1-5-21-1-2-3-1002";
        let row = |owner: &str| {
            serde_json::json!({
                "uuid": format!("{owner}/11111111-1111-4111-8111-111111111111"),
                "running": true, "tools_available": true,
            })
        };
        let bytes = serde_json::to_vec(&[row(owner)]).unwrap();
        assert!(validate_inventory_owner(&bytes, owner).is_ok());
        assert!(validate_inventory_owner(&bytes, other).is_err());
        for invalid in [
            vec![row(other)],
            vec![row(owner), row(other)],
            vec![row(owner), row(owner)],
        ] {
            assert!(
                validate_inventory_owner(&serde_json::to_vec(&invalid).unwrap(), owner).is_err()
            );
        }
        assert!(validate_inventory_owner(&vec![b'x'; 65537], owner).is_err());
        assert!(validate_inventory_owner(b"[]", "S-1-5-18").is_err());
    }
    #[test]
    fn live_inventory_does_not_hide_other_accounts_or_accept_mixed_owners() {
        let distro = "11111111-1111-4111-8111-111111111111";
        let one = format!("S-1-5-21-1-2-3-1001/{distro}");
        let two = format!("S-1-5-21-1-2-3-1002/{distro}");
        let row = |id: &str, running| serde_json::json!({"uuid":id,"running":running,"tools_available":running,"display_name":"Synthetic distro"});
        let registered = serde_json::to_vec(&vec![row(&one, false), row(&two, false)]).unwrap();
        let live = serde_json::to_vec(&vec![row(&one, true)]).unwrap();
        let merged = merge_inventory(&registered, &live).unwrap();
        let rows: Vec<InventoryRow> = serde_json::from_slice(&merged).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().any(|r| r.uuid == one && r.running));
        assert!(rows.iter().any(|r| r.uuid == two && !r.running));
        for live in [
            vec![row(&one, true), row(&two, true)],
            vec![row(&one, true), row(&one, false)],
            vec![row("data:image/png", true)],
        ] {
            assert!(merge_inventory(&registered, &serde_json::to_vec(&live).unwrap()).is_err());
        }
        assert!(merge_inventory(&registered, &vec![b'x'; 65537]).is_err());
        assert!(merge_inventory(&registered, b"{\"image\":\"binary\"}").is_err());
        assert!(Identity::parse(&format!("S-1-12-1-1-2-3-4/{distro}")).is_ok());
        assert!(
            Identity::parse("S-1-5-21-1-2-3-1001/00000000-0000-0000-0000-000000000000").is_err()
        );
    }
    #[test]
    fn owner_and_distribution_are_canonical_and_never_a_name_or_command() {
        let distribution = "11111111-1111-4111-8111-111111111111";
        let identity = Identity::parse(&format!("S-1-5-21-1-2-3-1001/{distribution}")).unwrap();
        assert_eq!(identity.owner, "S-1-5-21-1-2-3-1001");
        assert_eq!(identity.distribution, distribution);
        for owner in [
            "S-1-5-18",
            "s-1-5-21-1-2-3-1001",
            "S-1-5-21-1-2-3-01001",
            "S-1-5-21-1-2-3-4294967296",
            "S-1-5-21-1-2-3-+1001",
            "S-1-5-21-1-2-3-1001/extra",
        ] {
            assert!(Identity::parse(&format!("{owner}/{distribution}")).is_err());
        }
        for distribution in [
            "Ubuntu",
            "--exec",
            "../",
            "data:image/png",
            "{11111111-1111-4111-8111-111111111111}",
        ] {
            assert!(Identity::parse(&format!("S-1-5-21-1-2-3-1001/{distribution}")).is_err());
        }
    }
    #[test]
    fn private_abi_and_request_are_closed_before_dispatch() {
        assert!(supported_abi([2, 6, 3, 0]));
        for version in [
            [0, 0, 0, 0],
            [2, 6, 3, 1],
            [2, 6, 4, 0],
            [3, 0, 0, 0],
            [10, 0, 26100, 0],
        ] {
            assert!(!supported_abi(version));
        }
        assert!(
            serde_json::from_str::<Request>(r#"{"operation":"inventory"}"#)
                .unwrap()
                .validate()
                .is_ok()
        );
        for raw in [
            r#"{"operation":"inventory","command":"arbitrary"}"#,
            r#"{"operation":"shutdown"}"#,
            r#"{"operation":"processes","owner_sid":"S-1-5-18","distribution_id":"11111111-1111-4111-8111-111111111111"}"#,
            r#"{"operation":"processes","owner_sid":[],"distribution_id":"image"}"#,
        ] {
            assert!(
                serde_json::from_str::<Request>(raw)
                    .map_err(|_| ())
                    .and_then(|r| r.validate().map_err(|_| ()))
                    .is_err()
            );
        }
    }
}
