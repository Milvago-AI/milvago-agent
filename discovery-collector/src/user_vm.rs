//! Owner-scoped metadata from a non-elevated Windows session helper.
//! Neither a registration nor an API name proves execution inside a guest.
use crate::{MAX_RESPONSE, system::Query, vm::Hypervisor};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Desktop {
    VirtualBox,
    Vmware,
}
impl Desktop {
    pub fn query(self) -> Query {
        match self { Self::VirtualBox => Query::VirtualBox, Self::Vmware => Query::VMware }
    }
    pub fn hypervisor(self) -> Hypervisor {
        match self { Self::VirtualBox => Hypervisor::VirtualBox, Self::Vmware => Hypervisor::VMware }
    }
    fn valid_id(self, id: &str) -> bool {
        match self {
            Self::VirtualBox => id.len() == 36 && id.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) { b == b'-' } else { b.is_ascii_digit() || (b'a'..=b'f').contains(&b) }
            }) && id.bytes().any(|b| b != b'0' && b != b'-'),
            Self::Vmware => id.strip_prefix("vmx/").is_some_and(|hash| hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))),
        }
    }
}

pub fn valid_owner(owner: &str) -> bool {
    let parts: Vec<_> = owner.split('-').collect();
    owner.len() <= 80 && parts.len() == 8
        && (parts[..4] == ["S", "1", "5", "21"] || parts[..4] == ["S", "1", "12", "1"])
        && parts[4..].iter().all(|part| !part.is_empty() && part.len() <= 10
            && (!part.starts_with('0') || *part == "0")
            && part.bytes().all(|b| b.is_ascii_digit()) && part.parse::<u32>().is_ok())
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Row {
    uuid: String,
    running: bool,
    tools_available: bool,
    #[serde(default)]
    display_name: Option<String>,
}
fn rows(bytes: &[u8]) -> Result<Vec<Row>, &'static str> {
    if bytes.len() > MAX_RESPONSE { return Err("response_limit"); }
    let rows: Vec<Row> = serde_json::from_slice(bytes).map_err(|_| "invalid_inventory")?;
    if rows.len() > 100 { return Err("vm_limit"); }
    if rows.iter().any(|row| row.display_name.as_ref().is_some_and(|name| name.is_empty() || name.len() > 160 || name.chars().any(char::is_control))) {
        return Err("invalid_inventory");
    }
    Ok(rows)
}

/// The caller obtains `owner` from the process token, never from a user file.
pub fn scope(bytes: &[u8], owner: &str, desktop: Desktop) -> Result<Vec<u8>, &'static str> {
    if !valid_owner(owner) { return Err("invalid_owner"); }
    let mut rows = rows(bytes)?;
    let mut seen = BTreeSet::new();
    for row in &mut rows {
        if !desktop.valid_id(&row.uuid) || !seen.insert(row.uuid.clone()) { return Err("invalid_vm_identity"); }
        if row.display_name.is_none() { row.display_name = Some(format!("{} · {}", desktop.hypervisor().adapter(), row.uuid)); }
        row.uuid = format!("{owner}/{}", row.uuid);
        // A successful inventory does not establish guest-tool accessibility.
        row.tools_available = false;
    }
    serde_json::to_vec(&rows).map_err(|_| "invalid_inventory")
}

/// Parent revalidates every row against the selected kernel-owned session SID.
/// `None` is used only when normalizing a previously authenticated result.
pub fn validate(bytes: &[u8], owner: Option<&str>, desktop: Desktop) -> Result<(), &'static str> {
    if owner.is_some_and(|owner| !valid_owner(owner)) { return Err("invalid_owner"); }
    let mut seen = BTreeSet::new();
    let mut selected = None;
    for row in rows(bytes)? {
        let (sid, id) = row.uuid.split_once('/').ok_or("invalid_vm_identity")?;
        if !valid_owner(sid) || !desktop.valid_id(id) || row.tools_available
            || owner.is_some_and(|expected| expected != sid)
            || selected.as_deref().is_some_and(|previous| previous != sid)
            || !seen.insert(row.uuid.clone()) { return Err("invalid_inventory_owner"); }
        selected = Some(sid.to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const A: &str = "S-1-5-21-1-2-3-1000";
    const B: &str = "S-1-5-21-1-2-3-1001";
    const VM: &str = "11111111-1111-4111-8111-111111111111";
    fn input(id: &str) -> Vec<u8> { serde_json::to_vec(&serde_json::json!([{"uuid":id,"running":true,"tools_available":true}])).unwrap() }

    #[test]
    fn desktop_inventory_is_owner_scoped_and_never_confers_guest_access() {
        for (desktop, id) in [(Desktop::VirtualBox, VM.to_string()), (Desktop::Vmware, format!("vmx/{}", "a".repeat(64)))] {
            let first = scope(&input(&id), A, desktop).unwrap();
            let second = scope(&input(&id), B, desktop).unwrap();
            validate(&first, Some(A), desktop).unwrap();
            assert!(validate(&first, Some(B), desktop).is_err());
            assert!(validate(&input(&id), Some(A), desktop).is_err());
            let a = rows(&first).unwrap().remove(0); let b = rows(&second).unwrap().remove(0);
            assert!(!a.tools_available);
            assert!(!a.display_name.unwrap().contains(A));
            assert_ne!(crate::vm::entity_id(desktop.hypervisor(), "local", &a.uuid), crate::vm::entity_id(desktop.hypervisor(), "local", &b.uuid));
            struct NoFollowup;
            impl crate::system::Reader for NoFollowup {
                fn read(&self, _: Query, _: &crate::Budget<'_>) -> Result<Vec<u8>, &'static str> { panic!("An inventory must not query or execute anything in a guest"); }
            }
            let stop = std::sync::atomic::AtomicBool::new(false);
            let budget = crate::Budget::new(std::time::Duration::from_secs(1), &stop);
            assert_eq!(crate::system::normalize(desktop.query(), &first, &NoFollowup, &budget).unwrap(), first);
            let mut snapshot = crate::empty("device", 1, 1);
            crate::vm::inventory(&mut snapshot, desktop.hypervisor(), "local", &first).unwrap();
            assert!(snapshot.facts.is_empty());
            assert!(snapshot.coverage.iter().all(|entry| !entry.complete && entry.status == milvago_discovery_engine::CoverageStatus::Unavailable));
            for _ in 0..1000 { assert_eq!(scope(&input(&id), A, desktop).unwrap(), first); }
        }
    }
    #[test]
    fn desktop_inventory_rejects_forged_mixed_and_oversized_metadata() {
        for owner in ["S-1-5-18", "S-1-5-21-01-2-3-4", "S-1-5-21-4294967296-2-3-4", "S-1-5-21-1-2-3-4/extra", ""] {
            assert!(scope(&input(VM), owner, Desktop::VirtualBox).is_err());
        }
        for id in ["00000000-0000-0000-0000-000000000000", "../guest", "--help", "11111111-1111-4111-8111-11111111111A"] {
            assert!(scope(&input(id), A, Desktop::VirtualBox).is_err());
        }
        let a = scope(&input(VM), A, Desktop::VirtualBox).unwrap();
        let b = scope(&input(VM), B, Desktop::VirtualBox).unwrap();
        let mut mixed = rows(&a).unwrap(); mixed.extend(rows(&b).unwrap());
        assert!(validate(&serde_json::to_vec(&mixed).unwrap(), None, Desktop::VirtualBox).is_err());
        let mut duplicate = rows(&a).unwrap(); duplicate.extend(rows(&a).unwrap());
        assert!(validate(&serde_json::to_vec(&duplicate).unwrap(), Some(A), Desktop::VirtualBox).is_err());
        let many: Vec<_> = (0..101).map(|_| serde_json::json!({"uuid":VM,"running":false,"tools_available":false})).collect();
        assert!(scope(&serde_json::to_vec(&many).unwrap(), A, Desktop::VirtualBox).is_err());
        assert!(scope(&vec![b' '; MAX_RESPONSE + 1], A, Desktop::VirtualBox).is_err());
        for value in [r#"[{"uuid":{"image":"x"},"running":true,"tools_available":false}]"#, r#"[{"uuid":"x","running":true,"tools_available":false,"command":"whoami"}]"#] {
            assert!(scope(value.as_bytes(), A, Desktop::VirtualBox).is_err());
        }
    }
}
