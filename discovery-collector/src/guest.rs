use crate::*;
use serde::Deserialize;

#[derive(Clone, Copy, Debug, Default)]
pub struct Access {
    pub read: bool,
    pub execute: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Process {
    pid: u64,
    start_time: String,
    executable: String,
    #[serde(default)]
    argument_tokens: Vec<String>,
}

// Normalized projections from authenticated guest channels contain no environment or command line.
pub fn processes(
    snapshot: &mut Snapshot,
    vm: &str,
    boot: &str,
    bytes: &[u8],
    access: Access,
    required_execution: bool,
) -> Result<(), &'static str> {
    if !access.read || (required_execution && !access.execute) {
        return Err("guest_access_denied");
    }
    if !identifier(boot)
        || !snapshot
            .entities
            .iter()
            .any(|e| e.id == vm && matches!(e.kind, EntityKind::Vm | EntityKind::Wsl))
    {
        return Err("invalid_guest_scope");
    }
    if bytes.len() > MAX_RESPONSE {
        return Err("response_limit");
    }
    let rows: Vec<Process> = serde_json::from_slice(bytes).map_err(|_| "invalid_guest_response")?;
    if rows.len() > 4096 {
        return Err("process_limit");
    }
    // Validate the whole projection before mutating the snapshot: malformed guests
    // must not leave a partially successful inventory behind.
    let mut seen = std::collections::BTreeSet::new();
    for row in &rows {
        if row.pid == 0
            || row.start_time.is_empty()
            || row.start_time.len() > 80
            || row.executable.len() > 1024
            || row.executable.chars().any(char::is_control)
            || row.executable.is_empty()
            || row.start_time.chars().any(char::is_control)
            || row.argument_tokens.len() > 4
            || row
                .argument_tokens
                .iter()
                .any(|v| v.is_empty() || v.len() > 1024 || v.chars().any(char::is_control))
            || !seen.insert(row.pid)
        {
            return Err("invalid_guest_process");
        }
    }
    if snapshot.entities.len().saturating_add(rows.len()) > MAX_ENTITIES
        || snapshot.relations.len().saturating_add(rows.len()) > MAX_ENTITIES
        || snapshot.facts.len().saturating_add(rows.len()) > MAX_FACTS
    {
        return Err("process_limit");
    }
    let mut field_budget = FieldBudget::new(snapshot);
    for row in rows {
        let id = identity(
            "process",
            &[vm, boot, &row.pid.to_string(), &row.start_time],
        );
        snapshot.entities.push(Entity {
            display: None,
            id: id.clone(),
            kind: EntityKind::Process,
        });
        snapshot.relations.push(Relation {
            from: vm.into(),
            to: id.clone(),
            kind: RelationKind::Contains,
            source: "guest-channel".into(),
        });
        let mut fields = BTreeMap::from([(
            Field::Executable,
            vec![crate::host::executable_name(&row.executable)],
        )]);
        if !row.argument_tokens.is_empty() {
            fields.insert(Field::ArgumentToken, row.argument_tokens);
        }
        if !field_budget.insert(snapshot, &id, Source::GuestProcess, fields) {
            return Err("fact_limit");
        }
    }
    Ok(())
}
