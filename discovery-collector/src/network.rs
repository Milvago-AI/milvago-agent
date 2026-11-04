use crate::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Visibility {
    Host,
    VmBeforeNat,
    RuntimeBackend,
    ContainerNamespace,
}

pub struct Witness {
    pub entity: String,
    pub visibility: Visibility,
    pub remote_host: String,
    pub port: u16,
    pub observed_at: i64,
    pub connection_observed: bool,
    pub hostname_bound_to_connection: bool,
}

pub fn add(snapshot: &mut Snapshot, witness: Witness) -> Result<bool, &'static str> {
    let mut field_budget = FieldBudget::new(snapshot);
    add_with_budget(snapshot, witness, &mut field_budget)
}

pub fn add_with_budget(
    snapshot: &mut Snapshot,
    witness: Witness,
    field_budget: &mut FieldBudget,
) -> Result<bool, &'static str> {
    if !witness.connection_observed || !witness.hostname_bound_to_connection {
        return Ok(false);
    }
    if witness.port == 0
        || witness.observed_at < 0
        || witness.observed_at > snapshot.observed_at
        || snapshot.observed_at - witness.observed_at > 3600
        || witness.remote_host.len() > 253
    {
        return Err("invalid_network_witness");
    }
    let entity = snapshot
        .entities
        .iter()
        .find(|e| e.id == witness.entity)
        .ok_or("unknown_network_origin")?;
    let source = match (witness.visibility, entity.kind) {
        (Visibility::Host, EntityKind::Host | EntityKind::Process) => Source::HostFlow,
        (Visibility::VmBeforeNat, EntityKind::Vm | EntityKind::Wsl) => Source::VmFlow,
        (Visibility::RuntimeBackend, EntityKind::Runtime) => Source::RuntimeFlow,
        (Visibility::ContainerNamespace, EntityKind::Container) => Source::ContainerFlow,
        _ => return Err("network_scope_mismatch"),
    };
    let host = witness
        .remote_host
        .strip_suffix('.')
        .unwrap_or(&witness.remote_host)
        .to_ascii_lowercase();
    if !host.is_ascii()
        || host.is_empty()
        || host.split('.').any(|l| {
            l.is_empty()
                || l.len() > 63
                || l.starts_with('-')
                || l.ends_with('-')
                || !l.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
    {
        return Err("invalid_network_host");
    }
    let accepted = field_budget.insert(
        snapshot,
        &witness.entity,
        source,
        BTreeMap::from([
            (Field::RemoteHost, vec![host]),
            (Field::RemotePort, vec![witness.port.to_string()]),
        ]),
    );
    if accepted {
        snapshot
            .facts
            .last_mut()
            .expect("inserted fact")
            .observed_at = witness.observed_at;
    }
    Ok(accepted)
}
