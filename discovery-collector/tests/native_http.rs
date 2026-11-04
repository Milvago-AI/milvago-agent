//! Opt-in qualification against a real vendor adapter in a dedicated offline namespace.
#[cfg(target_os = "linux")]
#[test]
fn real_vendor_on_a_custom_port_preserves_recognition_and_resource_bounds() {
    use milvago_discovery_collector::{Budget, empty, http};
    use milvago_discovery_engine::{Catalog, Engine, EntityKind, State, validate_snapshot};
    use std::{sync::atomic::AtomicBool, time::Duration};

    assert_eq!(std::env::var("MILVAGO_HTTP_QA").as_deref(), Ok("offline-vendor-adapter"));
    let fixture: serde_json::Value = serde_json::from_slice(
        &std::fs::read("/run/milvago-http-qa/ready.json").expect("dedicated fixture marker"),
    ).unwrap();
    let application = fixture["application"].as_str().unwrap();
    assert!(matches!(application, "hermes" | "openclaw" | "ollama"));
    assert_eq!(fixture, serde_json::json!({"profile":"offline-vendor-adapter","application":application,"port":32145}));
    let catalog: Catalog = serde_json::from_slice(include_bytes!("../../discovery-engine/catalog/factory.json")).unwrap();
    let engine = Engine::compile(&catalog).unwrap();
    let address = "127.0.0.1:32145".parse().unwrap();
    let processes = std::env::var("MILVAGO_VENDOR_PROCESS_QA").as_deref() == Ok("1");
    if processes { assert!(matches!(application, "openclaw" | "ollama")); }
    let descriptors = || std::fs::read_dir("/proc/self/fd").unwrap().count();
    let tasks = || std::fs::read_dir("/proc/self/task").unwrap().count();
    let mut baseline = None;
    let mut previous = None;
    for sequence in 1..=6 {
        let stop = AtomicBool::new(false);
        let budget = Budget::new(Duration::from_secs(5), &stop);
        let mut snapshot = empty("vendor-qualification", sequence, 100);
        let owner = if processes {
            let listeners = milvago_discovery_collector::host::collect(&mut snapshot, &budget);
            Some(listeners.iter().find(|row| row.address == address)
                .expect("real gateway listener on the custom port").owner.clone()
                .expect("kernel listener ownership in the dedicated PID namespace"))
        } else { None };
        assert_eq!(http::collect_paths_with_connections(&mut snapshot, &[http::Target {
            address, origin: owner, published: false,
        }], &[], &catalog.http_paths, &budget).0, 1);
        validate_snapshot(&snapshot).unwrap();
        let result = engine.evaluate(&snapshot).unwrap();
        let matches: Vec<_> = result.identifications.iter().filter(|row| row.application_id == application
            && row.state == State::InterfaceRecognized).collect();
        assert_eq!(matches.len(), 1, "real vendor response must be recognized");
        assert_eq!(matches[0].state, State::InterfaceRecognized);
        assert_eq!(snapshot.entities.iter().filter(|row| row.kind == EntityKind::Endpoint).count(), 1);
        assert!(snapshot.entities.iter().any(|row| row.id == matches[0].entity_id
            && row.display.as_ref().is_some_and(|display| display.address == Some(address))));
        if processes {
            assert!(result.identifications.iter().any(|row| row.application_id == application
                && row.state == State::Executed), "the real running gateway process must be recognized");
            if sequence == 1 {
                let output = std::process::Command::new("/usr/bin/python3")
                    .args(["-I", "-S", "-c", include_str!("../../src/discovery_guest_linux.py")])
                    .env_clear().env("PATH", "/usr/bin:/bin").env("HOME", "/scratch/home")
                    .env("TMPDIR", "/scratch/tmp").output().unwrap();
                assert!(output.status.success());
                let guest: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
                assert!(guest["processes"].as_array().unwrap().iter().any(|row| {
                    if application == "ollama" { row["executable"] == "ollama" } else {
                        matches!(row["executable"].as_str(), Some("node" | "nodejs"))
                            && row["argument_tokens"].as_array().unwrap().iter().any(|token| token == "openclaw")
                    }
                }));
                assert!(!String::from_utf8(output.stdout).unwrap().contains("milvago-offline-fixture-only"));
                if application == "openclaw" {
                    use milvago_discovery_engine::{Entity, Relation, RelationKind};
                    let top = std::fs::read("/run/milvago-http-qa/top.json").unwrap();
                    let mut container = empty("vendor-qualification", sequence, 100);
                    container.entities.push(Entity { id: "runtime/vendor".into(), kind: EntityKind::Runtime, display: None });
                    container.entities.push(Entity { id: "container/vendor".into(), kind: EntityKind::Container, display: None });
                    container.relations.push(Relation { from: "runtime/vendor".into(), to: "container/vendor".into(),
                        kind: RelationKind::Contains, source: "docker".into() });
                    milvago_discovery_collector::containers::docker_top(&mut container, "runtime/vendor", "container/vendor", &top).unwrap();
                    validate_snapshot(&container).unwrap();
                    let result = engine.evaluate(&container).unwrap();
                    assert!(result.identifications.iter().any(|row| row.signature_id == "openclaw.gateway"
                        && row.state == State::Executed), "real Docker top gateway must be recognized");
                    assert!(result.communications.is_empty());
                    assert!(result.queries.is_empty());
                }
            }
        } else {
            assert!(result.identifications.iter().all(|row| row.state != State::Executed));
        }
        assert!(result.communications.is_empty());
        assert!(result.queries.is_empty());
        if !processes {
            assert!(snapshot.relations.is_empty(), "a loopback HTTP response cannot prove a VM or process origin");
        }
        if let Some(previous) = &previous { assert_eq!(previous, &matches[0].entity_id); }
        previous = Some(matches[0].entity_id.clone());
        if let Some((fds, threads)) = baseline {
            assert!(descriptors() <= fds + 2, "HTTP descriptors accumulated");
            assert!(tasks() <= threads + 2, "HTTP workers accumulated");
        } else { baseline = Some((descriptors(), tasks())); }
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires metadata collected from an owned offline VM running the real vendor"]
fn real_guest_vendor_projection_preserves_vm_origin_and_consent() {
    use milvago_discovery_collector::{empty, guest, guest_http};
    use milvago_discovery_engine::{Catalog, Engine, Entity, EntityKind, State, validate_snapshot};
    assert_eq!(std::env::var("MILVAGO_GUEST_VENDOR_QA").as_deref(), Ok("offline-openclaw-vm"));
    let bytes = std::fs::read("/run/milvago-guest-vendor/collections.json").unwrap();
    assert!(bytes.len() <= 512 * 1024);
    assert!(!String::from_utf8_lossy(&bytes).contains("milvago-offline-fixture-only"));
    let fixture: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(fixture["profile"], "offline-openclaw-vm");
    assert_eq!(fixture["transport"], "virtualbox-guest-control");
    let vm = fixture["vm_entity"].as_str().unwrap();
    assert!(vm.starts_with("vm/") && vm.len() <= 160);
    let collections = fixture["collections"].as_array().unwrap();
    assert_eq!(collections.len(), 3);
    let catalog: Catalog = serde_json::from_slice(include_bytes!("../../discovery-engine/catalog/factory.json")).unwrap();
    let engine = Engine::compile(&catalog).unwrap();
    let paths = vec!["/".into(), "/health".into()];
    let mut previous = None;
    for (index, payload) in collections.iter().enumerate() {
        let boot = payload["boot"].as_str().unwrap();
        let processes = serde_json::to_vec(&payload["processes"]).unwrap();
        let mut snapshot = empty("vendor-guest", index as u64 + 1, 100);
        snapshot.entities.push(Entity { id: vm.into(), kind: EntityKind::Vm, display: None });
        let access = guest::Access { read: true, execute: true };
        guest::processes(&mut snapshot, vm, boot, &processes, access, true).unwrap();
        guest_http::project(&mut snapshot, vm, boot,
            serde_json::from_value(payload["http"].clone()).unwrap(), &paths, access).unwrap();
        validate_snapshot(&snapshot).unwrap();
        let result = engine.evaluate(&snapshot).unwrap();
        let executed: Vec<_> = result.identifications.iter().filter(|row|
            row.application_id == "openclaw" && row.state == State::Executed).collect();
        // Bootstrap and gateway processes can coexist. Preserve each actual
        // identity, including the script token used before process.title changes.
        let mut expected = std::collections::BTreeSet::new();
        let witnessed: std::collections::BTreeSet<_> = payload["_qa_vendor_pids"].as_array().unwrap()
            .iter().map(|pid| pid.as_u64().unwrap()).collect();
        for process in payload["processes"].as_array().unwrap() {
            let executable = milvago_discovery_collector::host::executable_name(process["executable"].as_str().unwrap());
            let tagged = process["argument_tokens"].as_array().is_some_and(|tokens|
                tokens.iter().any(|token| matches!(token.as_str(), Some("openclaw" | "openclaw.mjs"))));
            if tagged || ["openclaw", "openclaw-gateway"].contains(&executable.as_str()) {
                let pid = process["pid"].as_u64().unwrap();
                assert!(witnessed.contains(&pid), "the recognized process must belong to the real vendor cgroup");
                expected.insert(milvago_discovery_collector::identity("process",
                    &[vm, boot, &pid.to_string(), process["start_time"].as_str().unwrap()]));
            }
        }
        assert!(!expected.is_empty(), "real guest gateway title must survive projection");
        let actual: std::collections::BTreeSet<_> = executed.iter().map(|row| row.entity_id.clone()).collect();
        assert_eq!(actual.len(), executed.len(), "one execution per actual process identity");
        assert_eq!(actual, expected, "every witnessed real vendor process must survive projection");
        let interfaces: Vec<_> = result.identifications.iter().filter(|row|
            row.application_id == "openclaw" && row.state == State::InterfaceRecognized).collect();
        assert_eq!(interfaces.len(), 1, "real guest HTTP response must be recognized");
        for row in executed.iter().copied().chain(std::iter::once(interfaces[0])) {
            assert!(snapshot.relations.iter().any(|relation| relation.from == vm && relation.to == row.entity_id));
        }
        assert!(result.communications.is_empty() && result.queries.is_empty());
        let identities = (actual, interfaces[0].entity_id.clone());
        if let Some(previous) = &previous { assert_eq!(previous, &identities); }
        previous = Some(identities);
        for access in [guest::Access { read: false, execute: true }, guest::Access { read: true, execute: false }] {
            let mut denied = empty("vendor-guest", 1, 100);
            denied.entities.push(Entity { id: vm.into(), kind: EntityKind::Vm, display: None });
            assert!(guest::processes(&mut denied, vm, boot, &processes, access, true).is_err());
            assert!(guest_http::project(&mut denied, vm, boot,
                serde_json::from_value(payload["http"].clone()).unwrap(), &paths, access).is_err());
            assert_eq!(denied.entities.len(), 1);
            assert!(denied.facts.is_empty() && denied.relations.is_empty());
        }
    }
}
