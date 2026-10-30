use milvago_discovery_collector::{
    containers::*,
    guest::Access,
    network::{Visibility, Witness},
    vm::Hypervisor,
    *,
};
use milvago_discovery_engine::*;
use std::{net::SocketAddr, sync::atomic::AtomicBool, time::Duration};

#[test]
fn moby_split_lstart_columns_do_not_hide_the_real_container_command() {
    let mut snapshot = empty("endpoint", 1, 100);
    snapshot.entities.extend([
        Entity {
            id: "runtime/fixture".into(),
            kind: EntityKind::Runtime,
            display: None,
        },
        Entity {
            id: "container/fixture".into(),
            kind: EntityKind::Container,
            display: None,
        },
    ]);
    snapshot.relations.push(Relation {
        from: "runtime/fixture".into(),
        to: "container/fixture".into(),
        kind: RelationKind::Contains,
        source: "fixture".into(),
    });
    let base = snapshot.clone();
    let response = |start: &str, command: &str| {
        serde_json::to_vec(&serde_json::json!({"Titles":["PID","STARTED","COMMAND"],"Processes":[["42", start, command]]})).unwrap()
    };
    docker_top(
        &mut snapshot,
        "runtime/fixture",
        "container/fixture",
        &response(
            "Tue",
            "Oct 27 01:44:51 2026 /usr/bin/node /app/openclaw.mjs PRIVATE_FIXTURE",
        ),
    )
    .unwrap();
    let catalog: Catalog = serde_json::from_slice(include_bytes!(
        "../../discovery-engine/catalog/factory.json"
    ))
    .unwrap();
    let result = Engine::compile(&catalog)
        .unwrap()
        .evaluate(&snapshot)
        .unwrap();
    assert_eq!(result.identifications[0].application_id, "openclaw");
    assert_eq!(result.identifications[0].state, State::Executed);
    assert!(
        !serde_json::to_string(&snapshot)
            .unwrap()
            .contains("PRIVATE_FIXTURE")
    );
    let identity = snapshot.entities.last().unwrap().id.clone();
    let mut structured = base.clone();
    docker_top(
        &mut structured,
        "runtime/fixture",
        "container/fixture",
        &response(
            "Tue Oct 27 01:44:51 2026",
            "/usr/bin/node /app/openclaw.mjs PRIVATE_FIXTURE",
        ),
    )
    .unwrap();
    assert_eq!(structured.entities.last().unwrap().id, identity);
    for command in [
        "Oct 27 01:44:51 2026",
        "Oct 32 01:44:51 2026 openclaw",
        "Feb 29 01:44:51 2025 openclaw",
        "Oct 27 25:44:51 2026 openclaw",
        "Oct 27 01:44:51 image/png openclaw",
        "Oct 27 01:44:51 2026\nopenclaw",
    ] {
        let mut invalid = base.clone();
        assert!(
            docker_top(
                &mut invalid,
                "runtime/fixture",
                "container/fixture",
                &response("Tue", command)
            )
            .is_err()
        );
        assert_eq!(
            serde_json::to_vec(&invalid).unwrap(),
            serde_json::to_vec(&base).unwrap()
        );
    }
}

#[test]
fn full_relationship_graph_does_not_discard_prior_application_evidence() {
    let mut snapshot = empty("endpoint", 1, 100);
    for (id, kind) in [
        ("vm/fixture", EntityKind::Vm),
        ("runtime/fixture", EntityKind::Runtime),
        ("container/fixture", EntityKind::Container),
        ("process/known", EntityKind::Process),
    ] {
        snapshot.entities.push(Entity {
            id: id.into(),
            kind,
            display: None,
        });
    }
    snapshot.relations.push(Relation {
        from: "runtime/fixture".into(),
        to: "container/fixture".into(),
        kind: RelationKind::Contains,
        source: "fixture".into(),
    });
    for n in 0..129 {
        snapshot.entities.push(Entity {
            id: format!("host/{n}"),
            kind: EntityKind::Host,
            display: None,
        });
    }
    for n in 0..127 {
        snapshot.entities.push(Entity {
            id: format!("endpoint/{n}"),
            kind: EntityKind::Endpoint,
            display: None,
        });
    }
    for from in 0..129 {
        for to in 0..127 {
            snapshot.relations.push(Relation {
                from: format!("host/{from}"),
                to: format!("endpoint/{to}"),
                kind: RelationKind::OwnsEndpoint,
                source: "fixture".into(),
            });
        }
    }
    assert_eq!(snapshot.relations.len(), MAX_ENTITIES);
    assert!(fact(
        &mut snapshot,
        "process/known",
        Source::HostProcess,
        std::collections::BTreeMap::from([(Field::Executable, vec!["openclaw".into()])])
    ));
    validate_snapshot(&snapshot).unwrap();
    let before = serde_json::to_vec(&snapshot).unwrap();
    assert_eq!(
        guest::processes(
            &mut snapshot,
            "vm/fixture",
            "boot/fixture",
            br#"[{"pid":42,"start_time":"1","executable":"hermes"}]"#,
            Access {
                read: true,
                execute: true
            },
            true
        ),
        Err("process_limit")
    );
    assert_eq!(serde_json::to_vec(&snapshot).unwrap(), before);
    assert_eq!(
        docker_top(
            &mut snapshot,
            "runtime/fixture",
            "container/fixture",
            br#"{"Titles":["PID","STARTED","COMMAND"],"Processes":[["42","1","hermes"]]}"#
        ),
        Err("process_limit")
    );
    assert_eq!(serde_json::to_vec(&snapshot).unwrap(), before);
    let stop = AtomicBool::new(false);
    let budget = Budget::new(Duration::from_secs(2), &stop);
    assert_eq!(
        docker_list(
            &mut snapshot,
            "runtime/new",
            br#"[{"Id":"0123456789abcdef","Image":"ollama/ollama","State":"running"}]"#,
            &budget
        )
        .unwrap_err(),
        "container_limit"
    );
    assert_eq!(serde_json::to_vec(&snapshot).unwrap(), before);
    let catalog: Catalog = serde_json::from_slice(include_bytes!(
        "../../discovery-engine/catalog/factory.json"
    ))
    .unwrap();
    let result = Engine::compile(&catalog)
        .unwrap()
        .evaluate(&snapshot)
        .unwrap();
    assert!(
        result
            .identifications
            .iter()
            .any(|i| i.application_id == "openclaw" && i.state == State::Executed)
    );
}

#[test]
fn escaped_metadata_cannot_overflow_the_system_collector_frame() {
    let mut snapshot = empty("endpoint", 1, 100);
    snapshot.entities.push(Entity {
        id: "endpoint/fixture".into(),
        kind: EntityKind::Endpoint,
        display: None,
    });
    let mut admission = FieldBudget::new(&snapshot);
    let body = std::collections::BTreeMap::from([(Field::HttpBody, vec!["\0".repeat(65536)])]);
    let mut accepted = 0;
    while admission.insert(
        &mut snapshot,
        "endpoint/fixture",
        Source::Http,
        body.clone(),
    ) {
        accepted += 1;
        assert!(accepted < 32);
    }
    assert!(accepted > 0);
    validate_snapshot(&snapshot).unwrap();
    assert!(serde_json::to_vec(&snapshot).unwrap().len() < 6 * 1024 * 1024);
}

#[test]
fn a_large_fact_batch_does_not_rescan_all_previous_fields_for_each_record() {
    let mut snapshot = empty("endpoint", 1, 100);
    snapshot.entities.push(Entity {
        id: "process/fixture".into(),
        kind: EntityKind::Process,
        display: None,
    });
    let mut admission = FieldBudget::new(&snapshot);
    let started = std::time::Instant::now();
    for _ in 0..10_000 {
        assert!(admission.insert(
            &mut snapshot,
            "process/fixture",
            Source::HostProcess,
            std::collections::BTreeMap::from([(Field::ArgumentToken, vec!["x".into(); 64])])
        ));
    }
    assert_eq!(snapshot.facts.len(), 10_000);
    validate_snapshot(&snapshot).unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "metadata admission must remain bounded at the collector's process limit"
    );
}

#[test]
fn independently_bounded_sources_share_one_fact_byte_budget() {
    let mut snapshot = empty("endpoint", 1, 100);
    snapshot.entities.extend([
        Entity {
            id: "process/known".into(),
            kind: EntityKind::Process,
            display: None,
        },
        Entity {
            id: "endpoint/large".into(),
            kind: EntityKind::Endpoint,
            display: None,
        },
    ]);
    assert!(fact(
        &mut snapshot,
        "process/known",
        Source::HostProcess,
        std::collections::BTreeMap::from([(Field::Executable, vec!["openclaw".into()])])
    ));
    let large = std::collections::BTreeMap::from([(Field::HttpBody, vec!["x".repeat(65536)])]);
    let mut admission = FieldBudget::new(&snapshot);
    for _ in 0..31 {
        assert!(admission.insert(&mut snapshot, "endpoint/large", Source::Http, large.clone()));
    }
    let before = snapshot.facts.len();
    assert!(!fact(&mut snapshot, "endpoint/large", Source::Http, large));
    assert_eq!(snapshot.facts.len(), before);
    assert_eq!(
        snapshot.facts[0].fields[&Field::Executable],
        vec!["openclaw"]
    );
    validate_snapshot(&snapshot).unwrap();
    // The rejection does not latch the buffer full: a small later observation
    // can still fit in the remaining shared budget.
    assert!(fact(
        &mut snapshot,
        "process/known",
        Source::HostProcess,
        std::collections::BTreeMap::from([(Field::Executable, vec!["hermes".into()])])
    ));
    validate_snapshot(&snapshot).unwrap();
    assert!(!admission.insert(
        &mut snapshot,
        "endpoint/large",
        Source::Http,
        std::collections::BTreeMap::from([(Field::HttpBody, vec!["x".repeat(65536)])])
    ));
}

#[test]
fn guest_process_projection_is_atomic_and_preserves_entry_point_evidence() {
    let mut snapshot = empty("host", 1, 100);
    let vms = vm::inventory(
        &mut snapshot,
        Hypervisor::Libvirt,
        "local",
        br#"[{"uuid":"vm-1","running":true,"tools_available":true}]"#,
    )
    .unwrap();
    let access = Access {
        read: true,
        execute: true,
    };
    for bytes in [
        br#"[{"pid":42,"start_time":"1","executable":"hermes"},{"pid":0,"start_time":"1","executable":"invalid"}]"#.as_slice(),
        br#"[{"pid":42,"start_time":"1","executable":"hermes"},{"pid":42,"start_time":"2","executable":"openclaw"}]"#.as_slice(),
        br#"[{"pid":42,"start_time":"1","executable":"hermes","argument_tokens":"data:image/png"}]"#.as_slice(),
    ] {
        assert!(guest::processes(&mut snapshot,&vms[0],"boot-1",bytes,access,true).is_err());
        assert_eq!(snapshot.entities.len(),1);assert!(snapshot.facts.is_empty());
    }
    guest::processes(&mut snapshot,&vms[0],"boot-1",br#"[{"pid":42,"start_time":"19834","executable":"python3","argument_tokens":["hermes_cli.main"]}]"#,access,true).unwrap();
    assert_eq!(
        snapshot.facts[0].fields[&Field::ArgumentToken],
        vec!["hermes_cli.main"]
    );
    let factory: Catalog = serde_json::from_slice(include_bytes!(
        "../../discovery-engine/catalog/factory.json"
    ))
    .unwrap();
    let result = Engine::compile(&factory)
        .unwrap()
        .evaluate(&snapshot)
        .unwrap();
    assert!(
        result
            .identifications
            .iter()
            .any(|i| i.application_id == "hermes" && i.state == State::Executed)
    );
}

#[test]
fn docker_desktop_podman_and_rancher_scopes_do_not_merge() {
    let bytes = br#"[{"Id":"0123456789abcdef","Names":["/openclaw"],"Image":"ghcr.io/openclaw/openclaw:latest","State":"running","Labels":{"secret":"fixture-secret"},"Ports":[{"IP":"0.0.0.0","PrivatePort":18789,"PublicPort":32145,"Type":"tcp"}]}]"#;
    let stop = AtomicBool::new(false);
    let budget = Budget::new(Duration::from_secs(5), &stop);
    let mut snapshot = empty("host", 1, 100);
    let mut ids = vec![];
    for runtime in [
        "docker-desktop",
        "podman-rootless-user-a",
        "podman-rootless-user-b",
        "rancher-containerd-namespace-a",
    ] {
        let ports = docker_list(&mut snapshot, runtime, bytes, &budget).unwrap();
        assert_eq!(ports[0].address.port(), 32145);
        ids.push(ports[0].entity_id.clone());
    }
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 4);
    validate_snapshot(&snapshot).unwrap();
    assert!(
        !serde_json::to_string(&snapshot)
            .unwrap()
            .contains("fixture-secret")
    );
    for fact in &snapshot.facts {
        assert_eq!(fact.source, Source::ContainerMetadata);
    }
}

#[test]
fn containers_without_published_ports_still_have_inventory() {
    let stop = AtomicBool::new(false);
    let budget = Budget::new(Duration::from_secs(5), &stop);
    let mut snapshot = empty("host", 1, 100);
    assert!(docker_list(&mut snapshot,"runtime",br#"[{"Id":"0123456789abcdef","Image":"local-build:test","State":"running","Ports":[]}]"#,&budget).unwrap().is_empty());
    assert_eq!(snapshot.facts.len(), 1);
    assert_eq!(
        snapshot.facts[0].fields[&Field::ImageRepository],
        vec!["local-build"]
    );
    assert_eq!(
        repository("registry.invalid:5000/team/image:tag"),
        Some("registry.invalid:5000/team/image".into())
    );
}

#[test]
fn container_top_recognizes_interpreter_entry_points_without_prompt_arguments() {
    let stop = AtomicBool::new(false);
    let budget = Budget::new(Duration::from_secs(1), &stop);
    let mut snapshot = empty("endpoint", 1, 100);
    let rows=br#"[{"Id":"0123456789abcdef","Names":["/generic"],"Image":"python:fixture","State":"running","Labels":{},"Ports":[]}]"#;
    docker_list(&mut snapshot, "runtime/fixture", rows, &budget).unwrap();
    let container = snapshot
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Container)
        .unwrap()
        .id
        .clone();
    docker_top(&mut snapshot,"runtime/fixture",&container,br#"{"Titles":["PID","STARTED","COMMAND"],"Processes":[["42","Mon Oct 26 12:00:00 2026","python3 -m hermes_cli.main --prompt PRIVATE"],["43","Mon Oct 26 12:00:01 2026","node /opt/node_modules/openclaw/dist/index.js --token PRIVATE"]]}"#).unwrap();
    let factory: Catalog = serde_json::from_slice(include_bytes!(
        "../../discovery-engine/catalog/factory.json"
    ))
    .unwrap();
    let result = Engine::compile(&factory)
        .unwrap()
        .evaluate(&snapshot)
        .unwrap();
    assert!(
        result
            .identifications
            .iter()
            .any(|i| i.application_id == "hermes" && i.state == State::Executed)
    );
    assert!(
        result
            .identifications
            .iter()
            .any(|i| i.application_id == "openclaw" && i.state == State::Executed)
    );
    assert!(
        !serde_json::to_string(&snapshot.facts)
            .unwrap()
            .contains("PRIVATE")
    );
    let before = snapshot.facts.len();
    for processes in [
        serde_json::json!([["0", "now", "openclaw"]]),
        serde_json::json!([["50", "now", "hermes"], ["50", "later", "openclaw"]]),
        serde_json::json!([["50", "", "openclaw"]]),
    ] {
        let response = serde_json::to_vec(
            &serde_json::json!({"Titles":["PID","STARTED","COMMAND"],"Processes":processes}),
        )
        .unwrap();
        assert!(docker_top(&mut snapshot, "runtime/fixture", &container, &response).is_err());
        assert_eq!(snapshot.facts.len(), before);
    }
}

#[test]
fn guest_tools_read_and_execution_require_separate_authorization() {
    for hypervisor in [
        Hypervisor::VMware,
        Hypervisor::HyperV,
        Hypervisor::VirtualBox,
        Hypervisor::Libvirt,
        Hypervisor::Wsl,
    ] {
        let mut snapshot = empty("host", 1, 100);
        let vms = vm::inventory(
            &mut snapshot,
            hypervisor,
            "local",
            br#"[{"uuid":"fixture-vm-1","running":true,"tools_available":true}]"#,
        )
        .unwrap();
        let bytes =
            br#"[{"pid":42,"start_time":"boot-1-tick-100","executable":"/usr/bin/openclaw"}]"#;
        assert!(
            guest::processes(
                &mut snapshot,
                &vms[0],
                "boot-1",
                bytes,
                Access::default(),
                false
            )
            .is_err()
        );
        assert!(
            guest::processes(
                &mut snapshot,
                &vms[0],
                "boot-1",
                bytes,
                Access {
                    read: true,
                    execute: false
                },
                true
            )
            .is_err()
        );
        assert_eq!(snapshot.facts.len(), 0);
        guest::processes(
            &mut snapshot,
            &vms[0],
            "boot-1",
            bytes,
            Access {
                read: true,
                execute: false,
            },
            false,
        )
        .unwrap();
        assert_eq!(snapshot.facts.len(), 1);
        assert_eq!(
            snapshot.facts[0].fields[&Field::Executable],
            vec!["openclaw"]
        );
        validate_snapshot(&snapshot).unwrap();
    }
}

#[test]
fn absent_guest_tools_is_unknown_application_coverage() {
    let mut snapshot = empty("host", 1, 100);
    vm::inventory(
        &mut snapshot,
        Hypervisor::VMware,
        "local",
        br#"[{"uuid":"vm-1","running":true,"tools_available":false}]"#,
    )
    .unwrap();
    assert_eq!(snapshot.coverage[0].status, CoverageStatus::Unavailable);
    assert!(!snapshot.coverage[0].complete);
    assert!(snapshot.facts.is_empty());
}

fn witness(entity: &str, visibility: Visibility) -> Witness {
    Witness {
        entity: entity.into(),
        visibility,
        remote_host: "api.openai.com".into(),
        port: 443,
        observed_at: 99,
        connection_observed: true,
        hostname_bound_to_connection: true,
    }
}

#[test]
fn hidden_vm_openai_and_shared_docker_backend_preserve_attribution_scope() {
    let mut snapshot = empty("host", 1, 100);
    snapshot.entities = vec![
        Entity {
            display: None,
            id: "vm/1".into(),
            kind: EntityKind::Vm,
        },
        Entity {
            display: None,
            id: "runtime/1".into(),
            kind: EntityKind::Runtime,
        },
        Entity {
            display: None,
            id: "container/1".into(),
            kind: EntityKind::Container,
        },
    ];
    network::add(&mut snapshot, witness("vm/1", Visibility::VmBeforeNat)).unwrap();
    network::add(
        &mut snapshot,
        witness("runtime/1", Visibility::RuntimeBackend),
    )
    .unwrap();
    assert!(
        network::add(
            &mut snapshot,
            witness("container/1", Visibility::RuntimeBackend)
        )
        .is_err()
    );
    let engine = Engine::compile(&Catalog {
        http_paths: default_http_paths(),
        http_ports: default_http_ports(),
        providers: default_providers(),
        version: 1,
        revision: 1,
        signatures: vec![],
    })
    .unwrap();
    let result = engine.evaluate(&snapshot).unwrap();
    assert!(result.identifications.is_empty());
    assert_eq!(result.communications.len(), 2);
    assert_eq!(result.communications[0].entity_id, "vm/1");
    assert_eq!(result.communications[1].entity_id, "runtime/1");
}

#[test]
fn dns_only_unbound_host_and_expired_witness_are_not_connections() {
    let mut snapshot = empty("host", 1, 100);
    snapshot.entities.push(Entity {
        display: None,
        id: "vm/1".into(),
        kind: EntityKind::Vm,
    });
    let mut dns = witness("vm/1", Visibility::VmBeforeNat);
    dns.connection_observed = false;
    assert!(!network::add(&mut snapshot, dns).unwrap());
    let mut unbound = witness("vm/1", Visibility::VmBeforeNat);
    unbound.hostname_bound_to_connection = false;
    assert!(!network::add(&mut snapshot, unbound).unwrap());
    let mut old = witness("vm/1", Visibility::VmBeforeNat);
    old.observed_at = 1;
    snapshot.observed_at = 3701;
    assert!(network::add(&mut snapshot, old).is_err());
    assert!(snapshot.facts.is_empty());
}

#[test]
fn process_projection_does_not_scan_arbitrary_prompt_arguments() {
    assert_eq!(
        host::executable_name(r"C:\Program Files\Fixture\OpenClaw.EXE"),
        "openclaw"
    );
    assert_eq!(host::executable_name("openclaw.exe.exe"), "openclaw.exe");
    assert_eq!(
        host::entry_tokens("node", &["/opt/node_modules/openclaw/dist/index.js".into()]),
        vec!["index.js", "openclaw"]
    );
    assert_eq!(
        host::entry_tokens("python3", &["-m".into(), "hermes_cli.main".into()]),
        vec!["hermes_cli.main"]
    );
    assert!(host::entry_tokens("echo", &["openclaw".into()]).is_empty());
    assert!(host::entry_tokens("python", &["-c".into(), "print('openclaw')".into()]).is_empty());
    assert_eq!(
        host::entry_tokens(
            "node",
            &["unrelated.js".into(), "--prompt".into(), "openclaw".into()]
        ),
        vec!["unrelated.js"]
    );
}

#[test]
fn actual_socket_addresses_include_ipv6_and_custom_ports() {
    assert_eq!(
        host::parse_tcp_endpoint("0100007F:7D91")
            .unwrap()
            .to_string(),
        "127.0.0.1:32145"
    );
    assert_eq!(
        host::parse_tcp_endpoint("00000000000000000000000001000000:2CAA")
            .unwrap()
            .to_string(),
        "[::1]:11434"
    );
    assert!(host::parse_tcp_endpoint("data:image/png").is_none());
}

#[test]
fn windows_tcp_tables_cover_empty_truncated_and_scoped_ipv6_listeners() {
    assert!(
        host::windows_tcp_listeners(&[0, 0, 0, 0], false)
            .unwrap()
            .is_empty()
    );
    for ipv6 in [false, true] {
        let size = if ipv6 { 56 } else { 24 };
        let mut bytes = vec![0; 4 + size];
        bytes[0] = 1;
        let state = 4 + if ipv6 { 48 } else { 0 };
        bytes[state] = 2;
        let port = 4 + if ipv6 { 20 } else { 8 };
        bytes[port..port + 2].copy_from_slice(&32145u16.to_be_bytes());
        let pid = 4 + if ipv6 { 52 } else { 20 };
        bytes[pid..pid + 4].copy_from_slice(&42u32.to_le_bytes());
        if ipv6 {
            bytes[4 + 15] = 1;
            bytes[4 + 16..4 + 20].copy_from_slice(&3u32.to_le_bytes());
        } else {
            bytes[8..12].copy_from_slice(&[127, 0, 0, 1]);
        }
        let rows = host::windows_tcp_listeners(&bytes, ipv6).unwrap();
        assert_eq!(rows[0].1, 42);
        assert_eq!(rows[0].0.port(), 32145);
        if let SocketAddr::V6(address) = rows[0].0 {
            assert_eq!(address.scope_id(), 3);
            assert_eq!(address.ip(), &std::net::Ipv6Addr::LOCALHOST);
        }
        for limit in 0..bytes.len() {
            assert!(host::windows_tcp_listeners(&bytes[..limit], ipv6).is_err());
        }
        bytes[state] = 5;
        assert!(host::windows_tcp_listeners(&bytes, ipv6).is_err());
    }
    assert!(host::windows_tcp_listeners(&u32::MAX.to_le_bytes(), true).is_err());
}

#[test]
fn http_scope_blocks_metadata_remote_and_unspecified_targets() {
    assert!(http::admitted("127.0.0.1:32145".parse().unwrap(), &[]));
    assert!(http::admitted("[::1]:32145".parse().unwrap(), &[]));
    for address in [
        "169.254.169.254:80",
        "0.0.0.0:80",
        "8.8.8.8:443",
        "224.0.0.1:80",
    ] {
        assert!(!http::admitted(address.parse().unwrap(), &[]));
    }
    assert!(!http::admitted(
        "169.254.169.254:80".parse().unwrap(),
        &["169.254.169.254".parse().unwrap()]
    ));
}

#[test]
fn cancelled_collectors_do_not_continue_processing() {
    let stop = AtomicBool::new(true);
    let budget = Budget::new(Duration::from_secs(5), &stop);
    let mut snapshot = empty("host", 1, 100);
    assert!(
        docker_list(
            &mut snapshot,
            "runtime",
            br#"[{"Id":"0123456789abcdef"}]"#,
            &budget
        )
        .is_err()
    );
    assert!(snapshot.facts.is_empty());
    assert!(budget.remaining().is_err());
}

#[test]
fn child_budgets_share_the_parent_deadline_and_cancellation() {
    let stop = AtomicBool::new(false);
    let parent = Budget::new(Duration::ZERO, &stop);
    assert_eq!(
        parent.child(Duration::from_secs(30)).check(),
        Err("timeout")
    );
    let parent = Budget::new(Duration::from_secs(30), &stop);
    assert_eq!(parent.child(Duration::ZERO).check(), Err("timeout"));
    let child = parent.child(Duration::from_secs(30));
    assert!(child.check().is_ok());
    stop.store(true, std::sync::atomic::Ordering::Release);
    assert_eq!(child.check(), Err("cancelled"));
}

#[test]
fn vm_image_and_binary_inputs_are_rejected() {
    let mut snapshot = empty("host", 1, 100);
    for bytes in [
        b"\x89PNG".as_slice(),
        b"null",
        b"[1]",
        br#"[{"uuid":"../bad?","running":true,"tools_available":true}]"#,
    ] {
        assert!(vm::inventory(&mut snapshot, Hypervisor::VMware, "local", bytes).is_err());
    }
}

#[test]
fn a_bad_or_duplicate_vm_cannot_pollute_other_sources() {
    for bytes in [
        br#"[{"uuid":"good","running":true,"tools_available":true},{"uuid":"../bad?","running":false,"tools_available":false}]"#.as_slice(),
        br#"[{"uuid":"good","running":true,"tools_available":true},{"uuid":"good","running":false,"tools_available":false}]"#,
    ] {
        let mut snapshot = empty("host", 1, 100);
        assert!(vm::inventory(&mut snapshot, Hypervisor::Libvirt, "local", bytes).is_err());
        assert!(snapshot.entities.is_empty());
        assert!(snapshot.relations.is_empty());
        assert!(snapshot.coverage.is_empty());
        validate_snapshot(&snapshot).unwrap();
    }
}

#[test]
fn hypervisor_uuid_case_and_a_malformed_display_name_do_not_hide_guest_identity() {
    let mut snapshot = empty("endpoint", 1, 100);
    let raw=br#"[{"uuid":"AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA","running":true,"tools_available":true,"display_name":"bad\nname"}]"#;
    let ids = vm::inventory(&mut snapshot, Hypervisor::HyperV, "local", raw).unwrap();
    assert_eq!(
        ids[0],
        vm::entity_id(
            Hypervisor::HyperV,
            "local",
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        )
    );
    validate_snapshot(&snapshot).unwrap();
    assert!(
        !snapshot.entities[0]
            .display
            .as_ref()
            .unwrap()
            .name
            .as_ref()
            .unwrap()
            .contains('\n')
    );
    let raw=br#"[{"uuid":"AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA","running":true,"tools_available":true},{"uuid":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","running":true,"tools_available":true}]"#;
    let mut snapshot = empty("endpoint", 1, 100);
    assert!(vm::inventory(&mut snapshot, Hypervisor::HyperV, "local", raw).is_err());
    assert!(snapshot.entities.is_empty());
}

#[test]
fn http_routes_and_ports_share_one_request_ceiling() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::Arc,
        time::Instant,
    };
    let listeners: Vec<_> = (0..9)
        .map(|_| {
            let socket = TcpListener::bind("127.0.0.1:0").unwrap();
            socket.set_nonblocking(true).unwrap();
            socket
        })
        .collect();
    let targets: Vec<_> = listeners
        .iter()
        .map(|socket| http::Target {
            address: socket.local_addr().unwrap(),
            origin: None,
            published: false,
        })
        .collect();
    let ended = Arc::new(AtomicBool::new(false));
    let stopped = ended.clone();
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(8);
        let mut requests = 0;
        while !stopped.load(std::sync::atomic::Ordering::Acquire) {
            assert!(Instant::now() < deadline);
            for listener in &listeners {
                if let Ok((mut stream, _)) = listener.accept() {
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(1)))
                        .unwrap();
                    stream
                        .set_write_timeout(Some(Duration::from_secs(1)))
                        .unwrap();
                    let mut bytes = vec![];
                    let mut buffer = [0; 512];
                    while !bytes.windows(4).any(|part| part == b"\r\n\r\n") {
                        let n = stream.read(&mut buffer).unwrap();
                        assert!(n > 0);
                        bytes.extend_from_slice(&buffer[..n]);
                        assert!(bytes.len() <= 4096);
                    }
                    assert!(bytes.starts_with(b"GET /p"));
                    requests += 1;
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                        )
                        .unwrap();
                }
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        requests
    });
    let stop = AtomicBool::new(false);
    let budget = Budget::new(Duration::from_secs(8), &stop);
    let mut snapshot = empty("endpoint", 1, 100);
    let paths: Vec<String> = (0..16).map(|index| format!("/p{index}")).collect();
    let (consumed, _) =
        http::collect_paths_with_connections(&mut snapshot, &targets, &[], &paths, &budget);
    ended.store(true, std::sync::atomic::Ordering::Release);
    assert_eq!(server.join().unwrap(), 128);
    assert_eq!(consumed, 8);
    assert_eq!(snapshot.facts.len(), 128);
    assert!(
        snapshot
            .coverage
            .iter()
            .any(|source| source.adapter == "http" && !source.complete)
    );
    validate_snapshot(&snapshot).unwrap();
}

#[test]
fn configured_health_routes_share_one_endpoint_and_never_follow_redirects_or_send_credentials() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        time::Instant,
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    assert_ne!(address.port(), 8642);
    listener.set_nonblocking(true).unwrap();
    let trap = TcpListener::bind("127.0.0.1:0").unwrap();
    trap.set_nonblocking(true).unwrap();
    let redirect = trap.local_addr().unwrap();
    let paths: Vec<String> = ["/", "/health", "/v1/health", "/redirect", "/private"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let expected = paths.clone();
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(8);
        for path in expected {
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline);
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("{error}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut bytes = vec![];
            let mut buffer = [0; 512];
            while !bytes.windows(4).any(|part| part == b"\r\n\r\n") {
                let size = stream.read(&mut buffer).unwrap();
                assert!(size > 0);
                bytes.extend_from_slice(&buffer[..size]);
                assert!(bytes.len() <= 4096);
            }
            let request = String::from_utf8(bytes).unwrap();
            assert!(request.starts_with(&format!("GET {path} HTTP/1.1\r\n")));
            let lower = request.to_ascii_lowercase();
            assert!(!lower.contains("authorization:") && !lower.contains("cookie:"));
            let (status, body) = match path.as_str() {
                "/health" => (
                    "200 OK",
                    r#"{"status":"ok","platform":"hermes-agent","version":"fixture"}"#,
                ),
                "/v1/health" => (
                    "200 OK",
                    r#"{ "version": "fixture", "platform": "hermes-agent", "status": "ok" }"#,
                ),
                "/redirect" => ("302 Found", ""),
                "/private" => ("401 Unauthorized", r#"{"error":"authentication required"}"#),
                _ => ("404 Not Found", "{}"),
            };
            let location = if path == "/redirect" {
                format!("Location: http://{redirect}/must-not-be-requested\r\n")
            } else {
                String::new()
            };
            write!(stream,"HTTP/1.1 {status}\r\nContent-Type: Application/JSON; charset=utf-8\r\nContent-Length: {}\r\n{location}Connection: close\r\n\r\n{body}",body.len()).unwrap();
        }
    });
    let stop = AtomicBool::new(false);
    let budget = Budget::new(Duration::from_secs(8), &stop);
    let mut snapshot = empty("endpoint", 5, 100);
    snapshot.entities.push(Entity {
        id: "host/fixture".into(),
        kind: EntityKind::Host,
        display: None,
    });
    let (consumed, _) = http::collect_paths_with_connections(
        &mut snapshot,
        &[http::Target {
            address,
            origin: Some("host/fixture".into()),
            published: false,
        }],
        &[],
        &paths,
        &budget,
    );
    server.join().unwrap();
    assert_eq!(consumed, 1);
    assert_eq!(
        snapshot
            .entities
            .iter()
            .filter(|entity| entity.kind == EntityKind::Endpoint)
            .count(),
        1
    );
    assert_eq!(snapshot.relations.len(), 1);
    assert_eq!(snapshot.facts.len(), 4);
    assert_eq!(
        trap.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    validate_snapshot(&snapshot).unwrap();
    let catalog: Catalog = serde_json::from_slice(include_bytes!(
        "../../discovery-engine/catalog/factory.json"
    ))
    .unwrap();
    let result = Engine::compile(&catalog)
        .unwrap()
        .evaluate(&snapshot)
        .unwrap();
    let matched = result
        .identifications
        .iter()
        .find(|item| item.application_id == "hermes")
        .unwrap();
    assert_eq!(matched.state, State::InterfaceRecognized);
    assert_eq!(matched.evidence.len(), 2);
    assert!(
        snapshot
            .coverage
            .iter()
            .any(|source| source.adapter == "http"
                && source.status == CoverageStatus::Partial
                && !source.complete)
    );
}

#[test]
fn http_paths_do_not_switch_protocol_after_the_first_response() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        time::Instant,
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let ended = std::sync::Arc::new(AtomicBool::new(false));
    let finished = ended.clone();
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(4);
        let mut requests = 0;
        let mut tls = false;
        while Instant::now() < deadline && !finished.load(std::sync::atomic::Ordering::Acquire) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(1)))
                        .unwrap();
                    stream
                        .set_write_timeout(Some(Duration::from_secs(1)))
                        .unwrap();
                    let mut bytes = Vec::new();
                    let mut buffer = [0u8; 512];
                    while !bytes.windows(4).any(|part| part == b"\r\n\r\n") {
                        let size = stream.read(&mut buffer).unwrap();
                        assert!(size > 0);
                        bytes.extend_from_slice(&buffer[..size]);
                        assert!(bytes.len() <= 4096);
                        if bytes.first() == Some(&22) {
                            break;
                        }
                    }
                    requests += 1;
                    if bytes.first() == Some(&22) {
                        tls = true;
                        continue;
                    }
                    let request = std::str::from_utf8(&bytes).unwrap();
                    assert!(
                        request.starts_with("GET / HTTP/1.1")
                            || request.starts_with("GET /health HTTP/1.1")
                    );
                    let status = if request.starts_with("GET /health ") {
                        "400 Bad Request"
                    } else {
                        "200 OK"
                    };
                    write!(
                        stream,
                        "HTTP/1.1 {status}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
                    )
                    .unwrap();
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(error) => panic!("{error}"),
            }
        }
        (requests, tls)
    });
    let stop = AtomicBool::new(false);
    let budget = Budget::new(Duration::from_secs(3), &stop);
    let mut snapshot = empty("endpoint", 2, 100);
    http::collect_paths_with_connections(
        &mut snapshot,
        &[http::Target {
            address,
            origin: None,
            published: false,
        }],
        &[],
        &["/".into(), "/health".into()],
        &budget,
    );
    ended.store(true, std::sync::atomic::Ordering::Release);
    let (requests, tls) = server.join().unwrap();
    assert_eq!(
        requests, 2,
        "the collector changed transport inside one endpoint"
    );
    assert!(!tls);
    assert_eq!(snapshot.facts.len(), 2);
    validate_snapshot(&snapshot).unwrap();
}

#[test]
fn reviewed_http_fingerprints_work_through_the_bounded_socket_collector() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        time::Instant,
    };
    let catalog: Catalog = serde_json::from_slice(include_bytes!(
        "../../discovery-engine/catalog/factory.json"
    ))
    .unwrap();
    let cases: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../discovery-engine/tests/fixtures/julius-http.json"
    ))
    .unwrap();
    let engine = Engine::compile(&catalog).unwrap();
    for (index, case) in cases.as_array().unwrap().iter().enumerate() {
        let expected = case["signature_id"].as_str().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let responses = case["responses"].as_array().unwrap().clone();
        let ended = std::sync::Arc::new(AtomicBool::new(false));
        let finished = ended.clone();
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(4);
            let mut requests = 0;
            while !finished.load(std::sync::atomic::Ordering::Acquire) && Instant::now() < deadline
            {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        stream
                            .set_read_timeout(Some(Duration::from_secs(1)))
                            .unwrap();
                        stream
                            .set_write_timeout(Some(Duration::from_secs(1)))
                            .unwrap();
                        let mut request = Vec::new();
                        let mut buffer = [0; 512];
                        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                            let n = stream.read(&mut buffer).unwrap();
                            assert!(n > 0);
                            request.extend_from_slice(&buffer[..n]);
                            assert!(request.len() <= 4096);
                        }
                        let text = std::str::from_utf8(&request).unwrap();
                        assert!(text.starts_with("GET "));
                        let path = text.split_whitespace().nth(1).unwrap();
                        let found = responses
                            .iter()
                            .find(|row| row["path"].as_str() == Some(path));
                        let (mut status, body, mime) =
                            found.map_or(("404 Not Found", "{}", "application/json"), |row| {
                                (
                                    "200 OK",
                                    row["body"].as_str().unwrap(),
                                    row["content_type"].as_str().unwrap(),
                                )
                            });
                        if mime == "application/manifest+json"
                            && !text
                                .to_ascii_lowercase()
                                .contains("application/manifest+json")
                        {
                            status = "406 Not Acceptable";
                        }
                        write!(stream,"HTTP/1.1 {status}\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
                        requests += 1;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1))
                    }
                    Err(error) => panic!("{error}"),
                }
            }
            requests
        });
        let stop = AtomicBool::new(false);
        let budget = Budget::new(Duration::from_secs(3), &stop);
        let mut snapshot = empty("endpoint", index as u64 + 1, 100);
        let (consumed, _) = http::collect_paths_with_connections(
            &mut snapshot,
            &[http::Target {
                address,
                origin: None,
                published: false,
            }],
            &[],
            &catalog.http_paths,
            &budget,
        );
        ended.store(true, std::sync::atomic::Ordering::Release);
        let requests = server.join().unwrap();
        assert_eq!(consumed, 1, "{expected}");
        assert_eq!(requests, 16, "{expected}");
        let result = engine.evaluate(&snapshot).unwrap();
        let found = result
            .identifications
            .iter()
            .find(|row| row.signature_id == expected)
            .unwrap_or_else(|| panic!("collector did not identify {expected}"));
        assert_eq!(
            found.evidence.len(),
            case["responses"].as_array().unwrap().len(),
            "{expected}"
        );
        for page in milvago_discovery_engine::report::pages(&snapshot, &result, 1, 1).unwrap() {
            milvago_discovery_engine::report::validate(&page, &catalog).unwrap();
        }
    }
}

#[test]
fn invalid_http_paths_are_rejected_before_any_socket_is_opened() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let stop = AtomicBool::new(false);
    let budget = Budget::new(Duration::from_secs(1), &stop);
    for path in [
        "http://example.test/",
        "//example.test/",
        "/../private",
        "/%2e%2e/",
        "/health?token=secret",
        "/health\n",
    ] {
        let mut snapshot = empty("endpoint", 1, 100);
        assert_eq!(
            http::collect_paths_with_connections(
                &mut snapshot,
                &[http::Target {
                    address: listener.local_addr().unwrap(),
                    origin: None,
                    published: false
                }],
                &[],
                &[path.into()],
                &budget
            )
            .0,
            0
        );
        assert!(snapshot.facts.is_empty());
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

#[test]
fn real_http_fixture_on_dynamic_port_is_read_without_following_redirects() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut bytes = [0u8; 2048];
        let n = stream.read(&mut bytes).unwrap();
        assert!(
            std::str::from_utf8(&bytes[..n])
                .unwrap()
                .starts_with("GET / HTTP/1.1")
        );
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\nConnection: close\r\n\r\nOllama is running").unwrap();
    });
    let stop = AtomicBool::new(false);
    let budget = Budget::new(Duration::from_secs(5), &stop);
    let mut snapshot = empty("host", 1, 100);
    http::collect(
        &mut snapshot,
        &[http::Target {
            address,
            origin: None,
            published: false,
        }],
        &[],
        &budget,
    );
    server.join().unwrap();
    assert_eq!(snapshot.facts.len(), 1);
    assert_eq!(
        snapshot.facts[0].fields[&Field::HttpBody],
        vec!["Ollama is running"]
    );
    assert_eq!(
        snapshot.entities[0].display.as_ref().unwrap().address,
        Some(address)
    );
}

#[test]
fn oversized_docker_top_executable_cannot_poison_other_snapshot_sources() {
    for length in [1025, 8192] {
        let mut snapshot = empty("endpoint", 1, 100);
        snapshot.entities.extend([
            Entity {
                id: "runtime/fixture".into(),
                kind: EntityKind::Runtime,
                display: None,
            },
            Entity {
                id: "container/fixture".into(),
                kind: EntityKind::Container,
                display: None,
            },
        ]);
        snapshot.relations.push(Relation {
            from: "runtime/fixture".into(),
            to: "container/fixture".into(),
            kind: RelationKind::Contains,
            source: "fixture".into(),
        });
        let before = serde_json::to_vec(&snapshot).unwrap();
        let bytes=serde_json::to_vec(&serde_json::json!({"Titles":["PID","STARTED","COMMAND"],"Processes":[["42","1000","x".repeat(length)]]})).unwrap();
        assert!(
            docker_top(
                &mut snapshot,
                "runtime/fixture",
                "container/fixture",
                &bytes
            )
            .is_err()
        );
        assert_eq!(serde_json::to_vec(&snapshot).unwrap(), before);
        validate_snapshot(&snapshot).unwrap();
    }
}

#[test]
fn custom_routes_after_the_factory_are_really_probed_with_bounded_requests() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::{Duration, Instant},
    };
    for count in [17, 32] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let ended = Arc::new(AtomicBool::new(false));
        let end = ended.clone();
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut requests = 0;
            while !end.load(Ordering::Acquire) && Instant::now() < deadline && requests < count {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(1)))
                            .unwrap();
                        stream
                            .set_write_timeout(Some(Duration::from_secs(1)))
                            .unwrap();
                        let mut request = vec![];
                        let mut buffer = [0; 512];
                        while !request.windows(4).any(|row| row == b"\r\n\r\n") {
                            let read = stream.read(&mut buffer).unwrap();
                            assert!(read > 0);
                            request.extend_from_slice(&buffer[..read]);
                            assert!(request.len() <= 4096);
                        }
                        assert!(request.starts_with(b"GET "));
                        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").unwrap();
                        requests += 1;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1))
                    }
                    Err(error) => panic!("{error}"),
                }
            }
            requests
        });
        let catalog: milvago_discovery_engine::Catalog = serde_json::from_slice(include_bytes!(
            "../../discovery-engine/catalog/factory.json"
        ))
        .unwrap();
        let mut paths = catalog.http_paths;
        while paths.len() < count {
            paths.push(format!("/custom/route-{}", paths.len()));
        }
        let custom = paths.last().unwrap().clone();
        let stop = AtomicBool::new(false);
        let budget = Budget::new(Duration::from_secs(4), &stop);
        let mut sample = empty("endpoint", 1, 100);
        let (consumed, _) = http::collect_paths_with_connections(
            &mut sample,
            &[http::Target {
                address,
                origin: None,
                published: false,
            }],
            &[],
            &paths,
            &budget,
        );
        ended.store(true, Ordering::Release);
        let requests = server.join().unwrap();
        assert_eq!(
            consumed, 1,
            "extended route plan was rejected before probing"
        );
        assert_eq!(requests, count);
        assert!(requests <= 128);
        assert!(sample.facts.iter().any(|row| {
            row.fields
                .get(&Field::HttpPath)
                .is_some_and(|paths| paths.contains(&custom))
        }));
        validate_snapshot(&sample).unwrap();
    }
}
