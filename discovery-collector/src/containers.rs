use crate::*;
use serde_json::Value;
use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Debug)]
pub struct PublishedPort {
    pub entity_id: String,
    pub address: SocketAddr,
}

fn string(value: &Value, key: &str, limit: usize) -> Option<String> {
    let text = value.get(key)?.as_str()?;
    if text.len() > limit || text.chars().any(char::is_control) {
        None
    } else {
        Some(text.into())
    }
}

pub fn repository(image: &str) -> Option<String> {
    if image.len() > 512
        || image.is_empty()
        || image.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return None;
    }
    let without_digest = image.split('@').next()?;
    let (prefix, last) = without_digest
        .rsplit_once('/')
        .unwrap_or(("", without_digest));
    let last = last.split(':').next()?;
    let result = if prefix.is_empty() {
        last.into()
    } else {
        format!("{prefix}/{last}")
    };
    Some(result)
}

// Listing APIs exclude environment variables, mounts and authentication material returned by inspect.
pub fn docker_list(
    snapshot: &mut Snapshot,
    runtime: &str,
    bytes: &[u8],
    budget: &Budget<'_>,
) -> Result<Vec<PublishedPort>, &'static str> {
    if !identifier(runtime) {
        return Err("invalid_runtime");
    }
    let value = bounded_json(bytes)?;
    let rows = value.as_array().ok_or("invalid_response")?;
    if rows.len() > 1000 {
        return Err("container_limit");
    }
    let new_runtime = !snapshot.entities.iter().any(|e| e.id == runtime);
    if snapshot
        .entities
        .len()
        .saturating_add(rows.len())
        .saturating_add(usize::from(new_runtime))
        > MAX_ENTITIES
        || snapshot.relations.len().saturating_add(rows.len()) > MAX_ENTITIES
        || snapshot.facts.len().saturating_add(rows.len()) > MAX_FACTS
    {
        return Err("container_limit");
    }
    if !snapshot.entities.iter().any(|e| e.id == runtime) {
        snapshot.entities.push(Entity {
            display: Some(EntityDisplay {
                name: Some("Docker / Podman".into()),
                ..Default::default()
            }),
            id: runtime.into(),
            kind: EntityKind::Runtime,
        });
    }
    let mut ports = vec![];
    let mut field_budget = FieldBudget::new(snapshot);
    for row in rows {
        budget.check()?;
        let id = string(row, "Id", 128)
            .filter(|v| v.len() >= 12 && v.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or("invalid_container_id")?;
        let entity = identity("container", &[runtime, &id]);
        let mut fields = BTreeMap::new();
        if let Some(image) = string(row, "Image", 512).and_then(|i| repository(&i)) {
            fields.insert(Field::ImageRepository, vec![image]);
        }
        if let Some(digest) = string(row, "ImageID", 128) {
            if digest.starts_with("sha256:")
                && digest.len() == 71
                && digest[7..].bytes().all(|c| c.is_ascii_hexdigit())
            {
                fields.insert(Field::ImageDigest, vec![digest]);
            }
        }
        if let Some(names) = row.get("Names").and_then(Value::as_array) {
            let names: Vec<_> = names
                .iter()
                .take(16)
                .filter_map(Value::as_str)
                .filter(|n| n.len() <= 160 && !n.chars().any(char::is_control))
                .map(|n| n.trim_start_matches('/').to_string())
                .collect();
            fields.insert(Field::ContainerName, names);
        }
        if let Some(state) = string(row, "State", 32) {
            fields.insert(Field::ContainerState, vec![state]);
        }
        // Labels may contain secrets; only keys are projected, never arbitrary values.
        if let Some(labels) = row.get("Labels").and_then(Value::as_object) {
            let keys: Vec<_> = labels
                .keys()
                .take(64)
                .filter(|k| k.len() <= 160 && !k.chars().any(char::is_control))
                .cloned()
                .collect();
            fields.insert(Field::Label, keys);
        }
        snapshot.entities.push(Entity {
            display: Some(EntityDisplay {
                name: fields
                    .get(&Field::ContainerName)
                    .and_then(|v| v.first())
                    .filter(|s| !s.is_empty())
                    .cloned(),
                image: fields
                    .get(&Field::ImageRepository)
                    .and_then(|v| v.first())
                    .cloned(),
                ..Default::default()
            }),
            id: entity.clone(),
            kind: EntityKind::Container,
        });
        snapshot.relations.push(Relation {
            from: runtime.into(),
            to: entity.clone(),
            kind: RelationKind::Contains,
            source: "container-api".into(),
        });
        if !field_budget.insert(snapshot, &entity, Source::ContainerMetadata, fields) {
            return Err("fact_limit");
        }
        if let Some(published) = row.get("Ports").and_then(Value::as_array) {
            if published.len() > 128 {
                return Err("port_limit");
            }
            for port in published {
                if port.get("Type").and_then(Value::as_str) != Some("tcp") {
                    continue;
                }
                let Some(public) = port
                    .get("PublicPort")
                    .and_then(Value::as_u64)
                    .and_then(|p| u16::try_from(p).ok())
                    .filter(|p| *p > 0)
                else {
                    continue;
                };
                let Some(ip) = port
                    .get("IP")
                    .and_then(Value::as_str)
                    .and_then(|v| v.parse::<IpAddr>().ok())
                else {
                    continue;
                };
                if ports.len() >= 2048 {
                    return Err("port_limit");
                }
                ports.push(PublishedPort {
                    entity_id: entity.clone(),
                    address: SocketAddr::new(ip, public),
                });
            }
        }
    }
    Ok(ports)
}

// Rootless API command strings are not execution evidence. Only their bounded
// PID list is used to locate independently corroborated kernel processes.
#[cfg(target_os = "linux")]
pub(crate) fn docker_top_pids(bytes: &[u8], podman: bool) -> Result<Vec<u32>, &'static str> {
    let value = bounded_json(bytes)?;
    let titles = value
        .get("Titles")
        .and_then(Value::as_array)
        .ok_or("invalid_response")?;
    let rows = value
        .get("Processes")
        .and_then(Value::as_array)
        .ok_or("invalid_response")?;
    if titles.len() > 32 || rows.len() > 1024 {
        return Err("process_limit");
    }
    let pid = titles
        .iter()
        .position(|title| {
            title.as_str().is_some_and(|value| {
                value.eq_ignore_ascii_case(if podman { "HPID" } else { "PID" })
            })
        })
        .ok_or("missing_process_identity")?;
    let mut output = std::collections::BTreeSet::new();
    for row in rows {
        let value = row
            .as_array()
            .and_then(|row| row.get(pid))
            .and_then(Value::as_str)
            .ok_or("invalid_process_identity")?;
        let pid = value
            .parse::<u32>()
            .ok()
            .filter(|pid| *pid > 0 && pid.to_string() == value)
            .ok_or("invalid_process_identity")?;
        if !output.insert(pid) {
            return Err("invalid_process_identity");
        }
    }
    Ok(output.into_iter().collect())
}

pub fn docker_top(
    snapshot: &mut Snapshot,
    runtime: &str,
    container: &str,
    bytes: &[u8],
) -> Result<(), &'static str> {
    if !identifier(runtime)
        || !identifier(container)
        || !snapshot
            .entities
            .iter()
            .any(|e| e.id == container && e.kind == EntityKind::Container)
        || !snapshot
            .relations
            .iter()
            .any(|r| r.from == runtime && r.to == container && r.kind == RelationKind::Contains)
    {
        return Err("invalid_container_scope");
    }
    let value = bounded_json(bytes)?;
    let titles = value
        .get("Titles")
        .and_then(Value::as_array)
        .ok_or("invalid_response")?;
    let rows = value
        .get("Processes")
        .and_then(Value::as_array)
        .ok_or("invalid_response")?;
    if rows.len() > 1024 || titles.len() > 32 {
        return Err("process_limit");
    }
    let pid = titles
        .iter()
        .position(|v| v.as_str().is_some_and(|s| s.eq_ignore_ascii_case("PID")))
        .ok_or("missing_process_identity")?;
    let start = titles
        .iter()
        .position(|v| {
            v.as_str().is_some_and(|s| {
                s.eq_ignore_ascii_case("LSTART") || s.eq_ignore_ascii_case("STARTED")
            })
        })
        .ok_or("missing_process_identity")?;
    let command = titles
        .iter()
        .position(|v| {
            v.as_str().is_some_and(|s| {
                s.eq_ignore_ascii_case("COMMAND")
                    || s.eq_ignore_ascii_case("CMD")
                    || s.eq_ignore_ascii_case("ARGS")
            })
        })
        .ok_or("invalid_response")?;
    let mut projected = vec![];
    let mut seen = std::collections::BTreeSet::new();
    for row in rows {
        let columns = row.as_array().ok_or("invalid_response")?;
        let get = |index| {
            columns
                .get(index)
                .and_then(Value::as_str)
                .filter(|s| s.len() <= 8192)
                .ok_or("invalid_response")
        };
        let pid_value = get(pid)?;
        if pid_value
            .parse::<u64>()
            .ok()
            .is_none_or(|pid| pid == 0 || pid.to_string() != pid_value)
            || !seen.insert(pid_value)
        {
            return Err("invalid_process_identity");
        }
        let start = get(start)?;
        if start.is_empty() || start.len() > 80 || start.chars().any(char::is_control) {
            return Err("invalid_process_identity");
        }
        let command = get(command)?;
        if command.chars().any(char::is_control) {
            return Err("invalid_process_command");
        }
        let (start, command) = top_start_and_command(start, command)?;
        let entity = identity("process", &[runtime, container, pid_value, &start]);
        let mut words = command.split_whitespace();
        let executable =
            crate::host::executable_name(words.next().ok_or("invalid_process_command")?);
        if executable.is_empty() || executable.len() > 1024 {
            return Err("invalid_process_command");
        }
        // Project only the first interpreter entry point. Shell quoting is not
        // inferred from ps output; ambiguous tokens are omitted.
        let args: Vec<_> = words.take(2).map(str::to_owned).collect();
        let tokens = if args.iter().any(|arg| arg.contains(['\'', '"', '\\'])) {
            vec![]
        } else {
            crate::host::entry_tokens(&executable, &args)
        };
        let mut fields = BTreeMap::from([(Field::Executable, vec![executable])]);
        if !tokens.is_empty() {
            fields.insert(Field::ArgumentToken, tokens);
        }
        projected.push((entity, fields));
    }
    if snapshot.entities.len().saturating_add(projected.len()) > MAX_ENTITIES
        || snapshot.relations.len().saturating_add(projected.len()) > MAX_ENTITIES
        || snapshot.facts.len().saturating_add(projected.len()) > MAX_FACTS
    {
        return Err("process_limit");
    }
    let mut field_budget = FieldBudget::new(snapshot);
    for (entity, fields) in projected {
        snapshot.entities.push(Entity {
            display: None,
            id: entity.clone(),
            kind: EntityKind::Process,
        });
        snapshot.relations.push(Relation {
            from: container.into(),
            to: entity.clone(),
            kind: RelationKind::Contains,
            source: "container-top".into(),
        });
        if !field_budget.insert(snapshot, &entity, Source::ContainerProcess, fields) {
            return Err("fact_limit");
        }
    }
    Ok(())
}

fn top_start_and_command<'a>(
    start: &str,
    command: &'a str,
) -> Result<(String, &'a str), &'static str> {
    // Moby splits ps output on whitespace and merges excess words into the
    // last column. With pid,lstart,args, STARTED contains only the weekday;
    // COMMAND begins with the other four date fields. Recover only that exact
    // date grammar so a month cannot be misreported as the executable.
    if !["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"].contains(&start) {
        return Ok((start.into(), command));
    }
    let mut remaining = command;
    let mut parts = Vec::with_capacity(4);
    for _ in 0..4 {
        remaining = remaining.trim_start_matches(char::is_whitespace);
        let split = remaining
            .find(char::is_whitespace)
            .ok_or("invalid_process_identity")?;
        parts.push(&remaining[..split]);
        remaining = &remaining[split..];
    }
    let month = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]
    .iter()
    .position(|month| *month == parts[0])
    .ok_or("invalid_process_identity")?;
    let number = |value: &str| {
        value
            .bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| value.parse::<u32>().ok())
            .flatten()
    };
    if parts[3].len() != 4 || !(1..=2).contains(&parts[1].len()) {
        return Err("invalid_process_identity");
    }
    let year = number(parts[3])
        .filter(|year| (1970..=9999).contains(year))
        .ok_or("invalid_process_identity")?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ][month];
    number(parts[1])
        .filter(|day| (1..=days).contains(day))
        .ok_or("invalid_process_identity")?;
    let clock: Vec<_> = parts[2].split(':').collect();
    if clock.len() != 3
        || clock.iter().any(|part| part.len() != 2)
        || number(clock[0]).is_none_or(|hour| hour > 23)
        || number(clock[1]).is_none_or(|minute| minute > 59)
        || number(clock[2]).is_none_or(|second| second > 59)
    {
        return Err("invalid_process_identity");
    }
    let command = remaining.trim_start_matches(char::is_whitespace);
    if command.is_empty() {
        return Err("invalid_process_command");
    }
    Ok((format!("{start} {}", parts.join(" ")), command))
}

#[cfg(all(test, target_os = "linux"))]
mod host_pid_tests {
    use super::*;
    #[test]
    fn podman_host_pid_never_falls_back_to_container_pid_or_command() {
        let both =
            br#"{"Titles":["PID","HPID","COMMAND"],"Processes":[["1","1234","PRIVATE_FIXTURE"]]}"#;
        assert_eq!(docker_top_pids(both, true).unwrap(), vec![1234]);
        assert_eq!(docker_top_pids(both, false).unwrap(), vec![1]);
        assert!(docker_top_pids(br#"{"Titles":["PID"],"Processes":[["1"]]}"#, true).is_err());
        assert!(docker_top_pids(br#"{"Titles":["HPID"],"Processes":[["1234"]]}"#, false).is_err());
        for value in ["0", "01", "-1", "4294967296", "image/png"] {
            let body = serde_json::json!({"Titles":["HPID"],"Processes":[[value]]});
            assert!(docker_top_pids(&serde_json::to_vec(&body).unwrap(), true).is_err());
        }
        assert!(
            docker_top_pids(br#"{"Titles":["HPID"],"Processes":[["12"],["12"]]}"#, true).is_err()
        );
    }
}
