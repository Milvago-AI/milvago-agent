//! Explicit qualification against dedicated daemons in an offline OS VM.
//! Never point this test at a developer's or production runtime socket.
#[cfg(target_os = "linux")]
mod linux {
    use milvago_discovery_collector::{Budget, containerd, docker, empty, identity};
    use milvago_discovery_engine::{Catalog, Engine, EntityKind, RelationKind, Source, State};
    use std::{path::PathBuf, sync::atomic::AtomicBool, time::Duration};

    #[test]
    fn dedicated_runtime_daemons_preserve_metadata_and_process_evidence() {
        assert_eq!(
            std::env::var("MILVAGO_DISCOVERY_RUNTIME_QA").as_deref(),
            Ok("offline-os-vm")
        );
        let fixture: serde_json::Value = serde_json::from_slice(
            &std::fs::read("/run/milvago-runtime-qa/ready.json")
                .expect("dedicated VM fixture marker"),
        )
        .unwrap();
        assert_eq!(fixture["profile"], "offline-os-vm");
        let catalog: Catalog = serde_json::from_slice(include_bytes!(
            "../../discovery-engine/catalog/factory.json"
        ))
        .unwrap();
        let engine = Engine::compile(&catalog).unwrap();
        let descriptors = || std::fs::read_dir("/proc/self/fd").unwrap().count();
        let tasks = || std::fs::read_dir("/proc/self/task").unwrap().count();
        let before = (descriptors(), tasks());
        for daemon in ["docker", "podman", "podman-rootless"] {
            if daemon == "podman-rootless" {
                assert_eq!(fixture[daemon]["uid"], 1000);
                assert_eq!(fixture[daemon]["rootless"], true);
                assert!(
                    docker::local_engines().iter().any(|channel| {
                        channel.socket == PathBuf::from("/run/user/1000/podman/podman.sock")
                    }),
                    "running rootless API must be discovered without a custom channel"
                );
            }
            let running = fixture[daemon]["running"].as_str().unwrap();
            let stopped = fixture[daemon]["stopped"].as_str().unwrap();
            for id in [running, stopped] {
                assert_eq!(id.len(), 64);
                assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
            }
            assert_ne!(running, stopped);
            let channel = docker::LocalEngine {
                socket: PathBuf::from(format!("/run/milvago-runtime-qa/{daemon}.sock")),
                scope: format!("qa-{daemon}"),
            };
            let alias = docker::LocalEngine {
                socket: PathBuf::from(format!("/run/milvago-runtime-qa/{daemon}-alias.sock")),
                scope: format!("qa-{daemon}-alias"),
            };
            let channels = [channel, alias];
            let mut cursor = docker::Cursor::default();
            let mut previous = None;
            for sequence in 1..=8 {
                let stop = AtomicBool::new(false);
                let budget = Budget::new(Duration::from_secs(5), &stop);
                let mut snapshot = empty("endpoint", sequence, 100);
                let ports =
                    docker::collect_with_cursor(&mut snapshot, &channels, &budget, &mut cursor);
                assert!(ports.is_empty());
                assert!(
                    snapshot
                        .coverage
                        .iter()
                        .any(|row| row.adapter == "containers"
                            && row.complete == (daemon != "podman-rootless")),
                    "{daemon} collection {sequence}: {:?}",
                    snapshot.coverage
                );
                let runtimes: Vec<_> = snapshot
                    .entities
                    .iter()
                    .filter(|e| e.kind == EntityKind::Runtime)
                    .collect();
                assert_eq!(runtimes.len(), 1);
                assert_eq!(
                    snapshot
                        .entities
                        .iter()
                        .filter(|e| e.kind == EntityKind::Container)
                        .count(),
                    if daemon == "podman-rootless" { 3 } else { 2 }
                );
                let runtime = &runtimes[0].id;
                let running_entity = identity("container", &[runtime, running]);
                let stopped_entity = identity("container", &[runtime, stopped]);
                if daemon == "podman-rootless" {
                    let opaque = fixture[daemon]["opaque"].as_str().unwrap();
                    assert_eq!(opaque.len(), 64);
                    assert_ne!(opaque, running);
                    let entity = identity("container", &[runtime, opaque]);
                    assert!(snapshot.entities.iter().any(|row| row.id == entity));
                    assert!(
                        !snapshot.relations.iter().any(|row| {
                            row.from == entity && row.kind == RelationKind::Contains
                        }),
                        "rootless container without an exact kernel cgroup must stay unproven"
                    );
                    assert!(snapshot.coverage.iter().any(|row| {
                        row.adapter == "containers"
                            && !row.complete
                            && row.status == milvago_discovery_engine::CoverageStatus::Partial
                    }));
                }
                let result = engine.evaluate(&snapshot).unwrap();
                assert!(result.identifications.iter().any(|identification| {
                    identification.application_id == "openclaw"
                        && identification.state == State::Executed
                        && snapshot.relations.iter().any(|relation| {
                            relation.from == running_entity
                                && relation.to == identification.entity_id
                                && relation.kind == RelationKind::Contains
                        })
                }));
                assert!(
                    result
                        .identifications
                        .iter()
                        .any(|i| i.application_id == "ollama"
                            && i.entity_id == stopped_entity
                            && i.state == State::Indication)
                );
                assert!(
                    !snapshot
                        .relations
                        .iter()
                        .any(|r| r.from == stopped_entity && r.kind == RelationKind::Contains)
                );
                assert!(snapshot.facts.iter().all(|fact| matches!(
                    fact.source,
                    Source::ContainerMetadata | Source::ContainerProcess
                )));
                assert!(
                    !serde_json::to_string(&snapshot)
                        .unwrap()
                        .contains("PRIVATE_FIXTURE")
                );
                let mut ids: Vec<_> = snapshot.entities.iter().map(|e| e.id.clone()).collect();
                ids.sort();
                if let Some(previous) = &previous {
                    assert_eq!(
                        &ids, previous,
                        "daemon IDs must not churn between collections"
                    );
                }
                previous = Some(ids);
            }
        }
        // Exercise the real protobuf API independently of Docker listing/top.
        assert_containerd(
            &engine,
            fixture["docker"]["running"].as_str().unwrap(),
            None,
        );
        assert!(descriptors() <= before.0 + 4, "runtime sockets leaked");
        assert!(tasks() <= before.1 + 2, "runtime workers leaked");
    }
    #[test]
    fn dedicated_standalone_containerd_preserves_task_and_stopped_image_evidence() {
        assert_eq!(
            std::env::var("MILVAGO_DISCOVERY_RUNTIME_QA").as_deref(),
            Ok("offline-os-vm")
        );
        let fixture: serde_json::Value =
            serde_json::from_slice(&std::fs::read("/run/milvago-runtime-qa/ready.json").unwrap())
                .unwrap();
        assert_eq!(fixture["profile"], "offline-os-vm");
        assert_eq!(fixture["standalone"]["namespace"], "qa-shadow");
        let running = fixture["standalone"]["running"].as_str().unwrap();
        let stopped = fixture["standalone"]["stopped"].as_str().unwrap();
        assert_ne!(running, stopped);
        for id in [running, stopped] {
            assert_eq!(id.len(), 64);
            assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
        }
        let catalog: Catalog = serde_json::from_slice(include_bytes!(
            "../../discovery-engine/catalog/factory.json"
        ))
        .unwrap();
        let descriptors = || std::fs::read_dir("/proc/self/fd").unwrap().count();
        let tasks = || std::fs::read_dir("/proc/self/task").unwrap().count();
        let before = (descriptors(), tasks());
        assert_containerd(&Engine::compile(&catalog).unwrap(), running, Some(stopped));
        assert!(
            descriptors() <= before.0 + 4,
            "standalone runtime sockets leaked"
        );
        assert!(tasks() <= before.1 + 2, "standalone runtime workers leaked");
    }

    #[test]
    fn dedicated_rootless_containerd_preserves_task_and_stopped_image_evidence() {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            std::env::var("MILVAGO_DISCOVERY_RUNTIME_QA").as_deref(),
            Ok("offline-os-vm")
        );
        let fixture: serde_json::Value =
            serde_json::from_slice(&std::fs::read("/run/milvago-runtime-qa/ready.json").unwrap())
                .unwrap();
        assert_eq!(fixture["profile"], "offline-os-vm");
        let daemon = &fixture["containerd-rootless"];
        assert_eq!(daemon["uid"], 1000);
        assert_eq!(daemon["rootless"], true);
        let pid = daemon["pid"].as_u64().unwrap();
        assert!((1..=u32::MAX as u64).contains(&pid));
        assert_eq!(
            std::fs::metadata(format!("/proc/{pid}")).unwrap().uid(),
            1000
        );
        assert_eq!(
            std::fs::metadata("/run/user/1000/containerd-rootless/containerd.sock")
                .unwrap()
                .uid(),
            1000
        );
        let mapping = std::fs::read_to_string(format!("/proc/{pid}/uid_map")).unwrap();
        assert!(
            mapping
                .lines()
                .any(|line| { line.split_whitespace().collect::<Vec<_>>() == ["0", "1000", "1"] })
        );
        let running = daemon["running"].as_str().unwrap();
        let stopped = daemon["stopped"].as_str().unwrap();
        for id in [running, stopped] {
            assert_eq!(id.len(), 64);
            assert!(id.bytes().all(|byte| byte.is_ascii_hexdigit()));
        }
        assert_ne!(running, stopped);
        let descriptors = || std::fs::read_dir("/proc/self/fd").unwrap().count();
        let tasks = || std::fs::read_dir("/proc/self/task").unwrap().count();
        let before = (descriptors(), tasks());
        let catalog: Catalog = serde_json::from_slice(include_bytes!(
            "../../discovery-engine/catalog/factory.json"
        ))
        .unwrap();
        assert_containerd(&Engine::compile(&catalog).unwrap(), running, Some(stopped));
        assert!(
            descriptors() <= before.0 + 4,
            "rootless runtime sockets leaked"
        );
        assert!(tasks() <= before.1 + 2, "rootless runtime workers leaked");
    }

    fn assert_containerd(engine: &Engine, running: &str, stopped: Option<&str>) {
        let mut previous = None;
        for sequence in 1..=8 {
            let stop = AtomicBool::new(false);
            let budget = Budget::new(Duration::from_secs(5), &stop);
            let mut snapshot = empty("endpoint", sequence, 100);
            assert!(containerd::collect(&mut snapshot, &budget).is_empty());
            for adapter in ["containerd-metadata", "containerd-processes"] {
                assert!(
                    snapshot
                        .coverage
                        .iter()
                        .any(|row| row.adapter == adapter && row.complete),
                    "dedicated native source must be complete: {adapter}: {:?}",
                    snapshot.coverage
                );
            }
            let result = engine.evaluate(&snapshot).unwrap();
            assert!(
                result.identifications.iter().any(|identification| {
                    identification.application_id == "openclaw"
                        && identification.state == State::Executed
                        && snapshot.relations.iter().any(|relation| {
                            relation.to == identification.entity_id
                                && relation.kind == RelationKind::Contains
                                && snapshot.facts.iter().any(|fact| {
                                    fact.entity_id == relation.from
                                        && fact.source == Source::ContainerMetadata
                                        && fact
                                            .fields
                                            .get(&milvago_discovery_engine::Field::ContainerName)
                                            .is_some_and(|names| {
                                                names.iter().any(|name| name == running)
                                            })
                                })
                        })
                }),
                "containerd must corroborate the active fixture process"
            );
            assert!(
                !serde_json::to_string(&snapshot)
                    .unwrap()
                    .contains("PRIVATE_FIXTURE")
            );
            if let Some(stopped) = stopped {
                assert!(result.identifications.iter().any(|item| {
                    item.application_id == "ollama"
                        && item.state == State::Indication
                        && snapshot.facts.iter().any(|fact| {
                            fact.entity_id == item.entity_id
                                && fact.source == Source::ContainerMetadata
                                && fact
                                    .fields
                                    .get(&milvago_discovery_engine::Field::ContainerName)
                                    .is_some_and(|names| names.iter().any(|name| name == stopped))
                        })
                }));
                assert!(!snapshot.relations.iter().any(|relation| relation.kind
                    == RelationKind::Contains
                    && snapshot.facts.iter().any(|fact| {
                        fact.entity_id == relation.from
                            && fact.source == Source::ContainerMetadata
                            && fact
                                .fields
                                .get(&milvago_discovery_engine::Field::ContainerName)
                                .is_some_and(|names| names.iter().any(|name| name == stopped))
                    })));
            }
            let mut ids: Vec<_> = snapshot
                .entities
                .iter()
                .map(|entity| entity.id.clone())
                .collect();
            ids.sort();
            if let Some(previous) = &previous {
                assert_eq!(
                    &ids, previous,
                    "containerd identity changed between collections"
                );
            }
            previous = Some(ids);
        }
    }
}
