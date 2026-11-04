use milvago_discovery_collector::{
    coverage, empty,
    network::{self, Visibility, Witness},
};
use milvago_discovery_engine::*;
use std::collections::BTreeMap;

fn fixture() -> (Snapshot, Engine) {
    let mut snapshot = empty("endpoint", 1, 100);
    for (id, kind, name) in [
        ("host/local", EntityKind::Host, "Synthetic host"),
        ("vm/first", EntityKind::Vm, "OpenClaw"),
        ("vm/second", EntityKind::Vm, "Hermes"),
        ("runtime/shared", EntityKind::Runtime, "Docker Desktop"),
        ("container/hidden", EntityKind::Container, "openclaw"),
    ] {
        snapshot.entities.push(Entity {
            id: id.into(),
            kind,
            display: Some(EntityDisplay {
                name: Some(name.into()),
                ..Default::default()
            }),
        });
    }
    for (from, to) in [
        ("host/local", "vm/first"),
        ("host/local", "vm/second"),
        ("host/local", "runtime/shared"),
        ("runtime/shared", "container/hidden"),
    ] {
        snapshot.relations.push(Relation {
            from: from.into(),
            to: to.into(),
            kind: RelationKind::Contains,
            source: "fixture-inventory".into(),
        });
    }
    snapshot.facts.push(Fact {
        id: "fact/dns".into(),
        entity_id: "host/local".into(),
        source: Source::HostDnsQuery,
        observed_at: 100,
        fields: BTreeMap::from([(Field::RemoteHost, vec!["api.openai.com".into()])]),
    });
    coverage(
        &mut snapshot,
        "vm-network-attribution",
        CoverageStatus::Unavailable,
        false,
    );
    let catalog: Catalog = serde_json::from_slice(include_bytes!(
        "../../discovery-engine/catalog/factory.json"
    ))
    .unwrap();
    (snapshot, Engine::compile(&catalog).unwrap())
}

fn witness(entity: &str, visibility: Visibility) -> Witness {
    Witness {
        entity: entity.into(),
        visibility,
        remote_host: "api.openai.com".into(),
        port: 443,
        observed_at: 100,
        connection_observed: true,
        hostname_bound_to_connection: true,
    }
}

#[test]
fn opaque_inventory_names_and_host_dns_do_not_identify_a_guest_application() {
    let (snapshot, engine) = fixture();
    let result = engine.evaluate(&snapshot).unwrap();
    assert!(result.identifications.is_empty());
    assert!(result.communications.is_empty());
    assert_eq!(result.queries.len(), 1);
    assert_eq!(result.queries[0].entity_id, "host/local");
    assert_eq!(result.queries[0].provider, "openai");
    assert_eq!(result.queries[0].evidence.source, Source::HostDnsQuery);
    let pages = report::pages(&snapshot, &result, 1, 1).unwrap();
    assert!(pages.iter().all(|page| !page.complete));
    assert!(pages.iter().flat_map(|page| &page.coverage).any(|row| {
        row.adapter == "vm-network-attribution"
            && row.status == CoverageStatus::Unavailable
            && !row.complete
    }));
    assert!(pages.iter().all(|page| {
        page.result.communications.is_empty() && page.result.identifications.is_empty()
    }));
}

#[test]
fn opaque_dns_correlation_does_not_fill_in_missing_network_proof_in_any_scope() {
    for (entity, visibility) in [
        ("host/local", Visibility::Host),
        ("vm/first", Visibility::VmBeforeNat),
        ("runtime/shared", Visibility::RuntimeBackend),
        ("container/hidden", Visibility::ContainerNamespace),
    ] {
        for (connection_observed, hostname_bound_to_connection) in
            [(false, false), (false, true), (true, false)]
        {
            let (mut snapshot, engine) = fixture();
            let mut candidate = witness(entity, visibility);
            candidate.connection_observed = connection_observed;
            candidate.hostname_bound_to_connection = hostname_bound_to_connection;
            assert!(!network::add(&mut snapshot, candidate).unwrap());
            let result = engine.evaluate(&snapshot).unwrap();
            assert!(result.communications.is_empty());
            assert!(result.identifications.is_empty());
            assert_eq!(result.queries.len(), 1);
            assert_eq!(result.queries[0].entity_id, "host/local");
        }
    }
}

#[test]
fn opaque_host_connection_is_not_copied_to_nearby_vms_or_containers() {
    let (mut snapshot, engine) = fixture();
    assert!(network::add(&mut snapshot, witness("host/local", Visibility::Host)).unwrap());
    let result = engine.evaluate(&snapshot).unwrap();
    assert_eq!(result.communications.len(), 1);
    assert_eq!(result.communications[0].entity_id, "host/local");
    assert_eq!(result.communications[0].evidence.source, Source::HostFlow);
    assert!(result.identifications.is_empty());
}

#[test]
fn opaque_attested_vm_connection_names_only_its_origin_and_provider() {
    let (mut snapshot, engine) = fixture();
    assert!(network::add(&mut snapshot, witness("vm/first", Visibility::VmBeforeNat)).unwrap());
    let result = engine.evaluate(&snapshot).unwrap();
    assert_eq!(result.communications.len(), 1);
    assert_eq!(result.communications[0].entity_id, "vm/first");
    assert_eq!(result.communications[0].provider, "openai");
    assert_eq!(result.communications[0].evidence.source, Source::VmFlow);
    assert!(result.identifications.is_empty());
    assert_eq!(result.queries[0].entity_id, "host/local");
}

#[test]
fn opaque_relabeling_host_dns_as_guest_evidence_is_rejected() {
    for entity in [
        "vm/first",
        "vm/second",
        "runtime/shared",
        "container/hidden",
    ] {
        let (mut snapshot, engine) = fixture();
        snapshot.facts[0].entity_id = entity.into();
        assert!(engine.evaluate(&snapshot).is_err());
    }
}
