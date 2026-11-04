//! HTTP responses read inside an explicitly authorized guest channel.
use crate::*;
use serde::Deserialize;
use std::collections::BTreeSet;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Responses {
    pub complete: bool,
    pub responses: Vec<Response>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub port: u16,
    pub path: String,
    pub status: u16,
    pub content_type: Option<String>,
    pub body: String,
}

pub fn valid_paths(paths: &[String]) -> bool {
    !paths.is_empty()
        && paths.len() <= MAX_HTTP_PATHS
        && paths.iter().all(|path| valid_http_path(path))
        && paths.iter().collect::<BTreeSet<_>>().len() == paths.len()
}

/// The caller authenticates the guest channel and supplies the signed HTTP
/// policy. A hostname, DHCP lease or host socket is never used as guest proof.
pub fn project(
    snapshot: &mut Snapshot,
    vm: &str,
    boot: &str,
    responses: Responses,
    paths: &[String],
    access: guest::Access,
) -> Result<(), &'static str> {
    if !access.read || !access.execute {
        return Err("guest_access_denied");
    }
    if !valid_paths(paths)
        || !identifier(boot)
        || snapshot
            .entities
            .iter()
            .filter(|e| e.id == vm && e.kind == EntityKind::Vm)
            .count()
            != 1
    {
        return Err("invalid_guest_scope");
    }
    if responses.responses.len() > 128 {
        return Err("response_limit");
    }
    let mut seen = BTreeSet::new();
    let mut ports = BTreeSet::new();
    let mut bytes = 0usize;
    for row in &responses.responses {
        bytes = bytes.saturating_add(row.body.len());
        if row.port == 0
            || !(100..=599).contains(&row.status)
            || (300..=399).contains(&row.status)
            || !paths.contains(&row.path)
            || row.body.len() > 65536
            || bytes > 131072
            || row
                .content_type
                .as_ref()
                .is_some_and(|value| value.len() > 256 || value.chars().any(char::is_control))
            || !seen.insert((row.port, row.path.as_str()))
        {
            return Err("invalid_guest_http_response");
        }
        ports.insert(row.port);
    }
    if ports.len() > 16
        || snapshot.entities.len().saturating_add(ports.len()) > MAX_ENTITIES
        || snapshot.relations.len().saturating_add(ports.len()) > MAX_ENTITIES
        || snapshot
            .facts
            .len()
            .saturating_add(responses.responses.len())
            > MAX_FACTS
    {
        return Err("response_limit");
    }
    // Bound and validate the full response before appending anything. Loopback
    // belongs to this guest boot, never to the physical host or another VM.
    let ids: BTreeMap<_, _> = ports
        .iter()
        .map(|port| {
            (
                *port,
                identity("endpoint", &[vm, boot, "guest-http", &port.to_string()]),
            )
        })
        .collect();
    if ids
        .values()
        .any(|id| snapshot.entities.iter().any(|e| &e.id == id))
    {
        return Err("invalid_guest_http_response");
    }
    let mut admission = FieldBudget::new(snapshot);
    let original_entities = snapshot.entities.len();
    let original_relations = snapshot.relations.len();
    let original_facts = snapshot.facts.len();
    for (port, id) in &ids {
        snapshot.entities.push(Entity {
            id: id.clone(),
            kind: EntityKind::Endpoint,
            display: Some(EntityDisplay {
                address: Some(std::net::SocketAddr::from(([127, 0, 0, 1], *port))),
                ..Default::default()
            }),
        });
        snapshot.relations.push(Relation {
            from: vm.into(),
            to: id.clone(),
            kind: RelationKind::ObservedOrigin,
            source: "guest-channel-http-connection".into(),
        });
    }
    for row in responses.responses {
        let mut fields = BTreeMap::from([
            (Field::HttpStatus, vec![row.status.to_string()]),
            (Field::HttpPath, vec![row.path]),
            (Field::HttpBody, vec![row.body]),
        ]);
        if let Some(content_type) = row.content_type {
            fields.insert(Field::HttpContentType, vec![content_type]);
        }
        if !admission.insert(snapshot, &ids[&row.port], Source::Http, fields) {
            snapshot.entities.truncate(original_entities);
            snapshot.relations.truncate(original_relations);
            snapshot.facts.truncate(original_facts);
            return Err("fact_limit");
        }
    }
    if snapshot.coverage.len() < 256 {
        snapshot.coverage.push(Coverage {
            scope: vm.into(),
            adapter: "guest-http".into(),
            // This adapter covers IPv4 HTTP in one guest network namespace.
            // A guest's completeness claim cannot expand that known boundary.
            status: CoverageStatus::Partial,
            checked_at: snapshot.observed_at,
            complete: false,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response() -> Responses {
        serde_json::from_str(r#"{"complete":false,"responses":[{"port":32145,"path":"/","status":200,"content_type":"text/plain","body":"Ollama is running"}]}"#).unwrap()
    }
    fn snapshot() -> Snapshot {
        let mut snapshot = empty("endpoint", 1, 100);
        snapshot.entities.push(Entity {
            id: "vm/fixture".into(),
            kind: EntityKind::Vm,
            display: None,
        });
        snapshot
    }
    #[test]
    fn private_guest_endpoint_is_recognized_at_its_actual_port_without_host_attribution() {
        let access = guest::Access {
            read: true,
            execute: true,
        };
        let mut snapshot = snapshot();
        project(
            &mut snapshot,
            "vm/fixture",
            "boot/one",
            response(),
            &["/".into()],
            access,
        )
        .unwrap();
        validate_snapshot(&snapshot).unwrap();
        let catalog: Catalog = serde_json::from_slice(include_bytes!(
            "../../discovery-engine/catalog/factory.json"
        ))
        .unwrap();
        let result = Engine::compile(&catalog)
            .unwrap()
            .evaluate(&snapshot)
            .unwrap();
        assert!(
            result.identifications.iter().any(
                |row| row.application_id == "ollama" && row.state == State::InterfaceRecognized
            )
        );
        assert_eq!(
            snapshot.entities[1]
                .display
                .as_ref()
                .unwrap()
                .address
                .unwrap()
                .port(),
            32145
        );
        assert_eq!(snapshot.relations.len(), 1);
        assert_eq!(snapshot.relations[0].from, "vm/fixture");
        assert_eq!(snapshot.relations[0].kind, RelationKind::ObservedOrigin);
        assert_eq!(snapshot.coverage[0].scope, "vm/fixture");
        assert!(result.communications.is_empty());
    }
    #[test]
    fn guest_http_refuses_unrequested_paths_and_malformed_data_before_mutation() {
        let access = guest::Access {
            read: true,
            execute: true,
        };
        for mode in 0..8 {
            let mut input = response();
            match mode {
                0 => input.responses[0].path = "/not-requested".into(),
                1 => input.responses[0].port = 0,
                2 => input.responses[0].status = 302,
                3 => input.responses[0].body = "x".repeat(65537),
                4 => input.responses[0].content_type = Some("text/plain\r\nSecret: fixture".into()),
                5 => input.responses.push(response().responses.remove(0)),
                6 => input.responses[0].status = 600,
                _ => input.responses[0].path = "data:image/png".into(),
            }
            let mut snapshot = snapshot();
            let before = serde_json::to_vec(&snapshot).unwrap();
            assert!(
                project(
                    &mut snapshot,
                    "vm/fixture",
                    "boot/one",
                    input,
                    &["/".into()],
                    access
                )
                .is_err()
            );
            assert_eq!(serde_json::to_vec(&snapshot).unwrap(), before);
        }
        for access in [
            guest::Access {
                read: false,
                execute: true,
            },
            guest::Access {
                read: true,
                execute: false,
            },
        ] {
            assert!(
                project(
                    &mut snapshot(),
                    "vm/fixture",
                    "boot/one",
                    response(),
                    &["/".into()],
                    access
                )
                .is_err()
            );
        }
        assert!(
            project(
                &mut snapshot(),
                "vm/absent",
                "boot/one",
                response(),
                &["/".into()],
                access
            )
            .is_err()
        );
    }
    #[test]
    fn guest_endpoint_identity_changes_with_vm_and_boot() {
        let access = guest::Access {
            read: true,
            execute: true,
        };
        let mut ids = BTreeSet::new();
        for (vm, boot) in [
            ("vm/fixture", "boot/one"),
            ("vm/fixture", "boot/two"),
            ("vm/other", "boot/one"),
        ] {
            let mut snapshot = snapshot();
            snapshot.entities[0].id = vm.into();
            project(&mut snapshot, vm, boot, response(), &["/".into()], access).unwrap();
            ids.insert(snapshot.entities[1].id.clone());
        }
        assert_eq!(ids.len(), 3);
    }

    #[test]
    fn guest_completeness_cannot_claim_coverage_of_unobserved_protocols() {
        let mut input = response();
        input.complete = true;
        let mut snapshot = snapshot();
        project(
            &mut snapshot,
            "vm/fixture",
            "boot/one",
            input,
            &["/".into()],
            guest::Access {
                read: true,
                execute: true,
            },
        )
        .unwrap();
        assert_eq!(snapshot.coverage[0].status, CoverageStatus::Partial);
        assert!(!snapshot.coverage[0].complete);
    }

    #[test]
    fn exhausted_shared_field_budget_leaves_no_partial_guest_endpoint() {
        let mut snapshot = snapshot();
        snapshot.entities.push(Entity {
            id: "endpoint/existing".into(),
            kind: EntityKind::Endpoint,
            display: None,
        });
        let mut admission = FieldBudget::new(&snapshot);
        for index in 0..32 {
            assert!(admission.insert(
                &mut snapshot,
                "endpoint/existing",
                Source::Http,
                BTreeMap::from([(
                    Field::HttpBody,
                    vec!["x".repeat(if index == 31 { 65535 } else { 65536 })]
                )])
            ));
        }
        let before = serde_json::to_vec(&snapshot).unwrap();
        assert_eq!(
            project(
                &mut snapshot,
                "vm/fixture",
                "boot/one",
                response(),
                &["/".into()],
                guest::Access {
                    read: true,
                    execute: true
                }
            ),
            Err("fact_limit")
        );
        assert_eq!(serde_json::to_vec(&snapshot).unwrap(), before);
        validate_snapshot(&snapshot).unwrap();
    }
}
