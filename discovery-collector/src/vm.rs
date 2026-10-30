use crate::*;
use serde::Deserialize;

#[derive(Clone, Copy, Debug)]
pub enum Hypervisor {
    HyperV,
    VMware,
    VirtualBox,
    Libvirt,
    Wsl,
}
impl Hypervisor {
    pub fn adapter(self) -> &'static str {
        match self {
            Self::HyperV => "hyper-v",
            Self::VMware => "vmware",
            Self::VirtualBox => "virtualbox",
            Self::Libvirt => "libvirt",
            Self::Wsl => "wsl",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Guest {
    uuid: String,
    running: bool,
    tools_available: bool,
    #[serde(default)]
    display_name: Option<String>,
}

pub fn canonical_uuid(value: &str) -> String {
    if value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
    {
        value.to_ascii_lowercase()
    } else {
        value.into()
    }
}
pub fn entity_id(hypervisor: Hypervisor, scope: &str, uuid: &str) -> String {
    identity("vm", &[hypervisor.adapter(), scope, &canonical_uuid(uuid)])
}

pub fn inventory(
    snapshot: &mut Snapshot,
    hypervisor: Hypervisor,
    scope: &str,
    bytes: &[u8],
) -> Result<Vec<String>, &'static str> {
    if !identifier(scope) || bytes.len() > MAX_RESPONSE {
        return Err("invalid_vm_scope");
    }
    let rows: Vec<Guest> = serde_json::from_slice::<Vec<Guest>>(bytes)
        .map_err(|_| "invalid_vm_inventory")?
        .into_iter()
        .map(|mut row| {
            row.uuid = canonical_uuid(&row.uuid);
            row.display_name = row
                .display_name
                .filter(|s| !s.is_empty() && s.len() <= 160 && !s.chars().any(char::is_control));
            row
        })
        .collect();
    if rows.len() > 100 {
        return Err("vm_limit");
    }
    let mut ids: std::collections::BTreeSet<_> =
        snapshot.entities.iter().map(|e| e.id.clone()).collect();
    if snapshot.entities.len().saturating_add(rows.len()) > MAX_ENTITIES
        || snapshot.relations.len().saturating_add(rows.len()) > MAX_ENTITIES
    {
        return Err("vm_limit");
    }
    for row in &rows {
        if !identifier(&row.uuid) || !ids.insert(entity_id(hypervisor, scope, &row.uuid)) {
            return Err("invalid_vm_identity");
        }
    }
    let mut guests = vec![];
    for row in rows {
        let id = entity_id(hypervisor, scope, &row.uuid);
        snapshot.entities.push(Entity {
            display: Some(EntityDisplay {
                name: Some(row.display_name.unwrap_or_else(|| {
                    format!("{} · {}", hypervisor.adapter(), row.uuid)
                        .chars()
                        .take(160)
                        .collect()
                })),
                ..Default::default()
            }),
            id: id.clone(),
            kind: if matches!(hypervisor, Hypervisor::Wsl) {
                EntityKind::Wsl
            } else {
                EntityKind::Vm
            },
        });
        let parent = snapshot
            .entities
            .iter()
            .find(|e| e.id == scope && matches!(e.kind, EntityKind::Vm | EntityKind::Wsl))
            .or_else(|| {
                if scope == "local" {
                    snapshot
                        .entities
                        .iter()
                        .find(|e| e.kind == EntityKind::Host)
                } else {
                    None
                }
            });
        if let Some(parent) = parent {
            snapshot.relations.push(Relation {
                from: parent.id.clone(),
                to: id.clone(),
                kind: RelationKind::Contains,
                source: hypervisor.adapter().into(),
            });
        }
        if row.running {
            guests.push(id.clone());
        }
        if snapshot.coverage.len() < 256 {
            snapshot.coverage.push(Coverage {
                scope: id,
                adapter: format!("{}-guest", hypervisor.adapter()),
                status: if row.running && row.tools_available {
                    CoverageStatus::Partial
                } else {
                    CoverageStatus::Unavailable
                },
                checked_at: snapshot.observed_at,
                complete: false,
            });
        }
    }
    Ok(guests)
}
