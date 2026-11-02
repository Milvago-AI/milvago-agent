#![cfg(unix)]

use milvago_discovery_collector::{Budget, docker, empty};
use milvago_discovery_engine::{Catalog, CoverageStatus, Engine, EntityKind, State};
use std::{
    io::{Read, Write},
    os::unix::net::UnixListener,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

struct Fixture {
    root: PathBuf,
    stop: Arc<AtomicBool>,
    requests: Arc<AtomicUsize>,
    servers: Vec<thread::JoinHandle<()>>,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "discovery-alias-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        Self {
            root,
            stop: Arc::new(AtomicBool::new(false)),
            requests: Arc::new(AtomicUsize::new(0)),
            servers: vec![],
        }
    }
    fn serve(&mut self, name: &str) -> PathBuf {
        self.serve_with_cancel(name, None)
    }
    fn serve_with_cancel(&mut self, name: &str, cancel: Option<Arc<AtomicBool>>) -> PathBuf {
        self.serve_projection(name, cancel, false)
    }
    fn serve_projection(
        &mut self,
        name: &str,
        cancel: Option<Arc<AtomicBool>>,
        top_denied: bool,
    ) -> PathBuf {
        let socket = self.root.join(name);
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = self.stop.clone();
        let requests = self.requests.clone();
        self.servers.push(thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(12);
            while !stop.load(Ordering::Acquire) && Instant::now() < deadline {
                let (mut stream, _) = match listener.accept() {
                    Ok(value) => value,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => panic!("fixture accept: {error}"),
                };
                stream.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
                stream.set_write_timeout(Some(Duration::from_secs(1))).unwrap();
                let mut input = vec![];
                while !input.ends_with(b"\r\n\r\n") {
                    assert!(input.len() < 8192);
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    input.push(byte[0]);
                }
                requests.fetch_add(1, Ordering::AcqRel);
                if let Some(cancel) = &cancel {
                    cancel.store(true, Ordering::Release);
                }
                let line = std::str::from_utf8(&input).unwrap().lines().next().unwrap();
                let body = if line.starts_with("GET /info ") {
                    if top_denied { serde_json::json!({"ID":"same-claimed-id","BuildahVersion":"fixture","DockerRootDir":"/fixture/rootless","Rootless":true}) }
                    else { serde_json::json!({"ID":"same-claimed-id"}) }
                } else if line.starts_with("GET /containers/json?all=1 ") {
                    serde_json::json!([{"Id":"0123456789abcdef","Names":["/fixture"],"Image":if top_denied {"ghcr.io/openclaw/openclaw:fixture"}else{"alpine:fixture"},"State":"running","Ports":[]}])
                } else {
                    assert!(line.starts_with("GET /containers/0123456789abcdef/top?ps_args="));
                    if top_denied {serde_json::json!({"cause":"this container does not have a cgroup","message":"cannot run top on container as it did not create a cgroup","response":500})}
                    else {serde_json::json!({"Titles":["PID","STARTED","COMMAND"],"Processes":[["1","fixture-start","/usr/bin/openclaw PRIVATE_FIXTURE"]]})}
                }.to_string();
                let status = if top_denied && line.contains("/top?") { "500 Internal Server Error" } else { "200 OK" };
                write!(stream,"HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
            }
        }));
        socket
    }
    fn engine(socket: &Path, scope: &str) -> docker::LocalEngine {
        docker::LocalEngine {
            socket: socket.into(),
            scope: scope.into(),
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn rootless_top_without_cgroup_preserves_indication_without_inventing_execution() {
    let descriptors = || std::fs::read_dir("/proc/self/fd").unwrap().count();
    let before = descriptors();
    {
        let mut fixture = Fixture::new();
        let socket = fixture.serve_projection("rootless.sock", None, true);
        let channels = [Fixture::engine(&socket, "rootless")];
        let catalog: Catalog = serde_json::from_slice(include_bytes!(
            "../../discovery-engine/catalog/factory.json"
        ))
        .unwrap();
        let engine = Engine::compile(&catalog).unwrap();
        let stop = AtomicBool::new(false);
        let mut previous = None;
        for sequence in 1..=8 {
            let mut snapshot = empty("endpoint", sequence, 100);
            let budget = Budget::new(Duration::from_secs(2), &stop);
            assert!(docker::collect(&mut snapshot, &channels, &budget).is_empty());
            assert!(
                snapshot
                    .coverage
                    .iter()
                    .any(|row| row.adapter == "containers"
                        && row.status == CoverageStatus::Partial
                        && !row.complete)
            );
            assert!(
                !snapshot
                    .entities
                    .iter()
                    .any(|entity| entity.kind == EntityKind::Process)
            );
            let result = engine.evaluate(&snapshot).unwrap();
            assert_eq!(result.identifications.len(), 1);
            assert_eq!(result.identifications[0].application_id, "openclaw");
            assert_eq!(result.identifications[0].state, State::Indication);
            let ids: Vec<_> = snapshot
                .entities
                .iter()
                .map(|entity| entity.id.clone())
                .collect();
            if let Some(previous) = &previous {
                assert_eq!(previous, &ids);
            }
            previous = Some(ids);
        }
        assert_eq!(fixture.requests.load(Ordering::Acquire), 24);
    }
    assert!(
        descriptors() <= before + 2,
        "partial rootless collection leaked sockets"
    );
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        for server in self.servers.drain(..) {
            server.join().unwrap();
        }
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn symbolic_socket_aliases_keep_one_runtime_and_stable_evidence() {
    let mut fixture = Fixture::new();
    let real = fixture.serve("real.sock");
    let alias = fixture.root.join("alias.sock");
    std::os::unix::fs::symlink(&real, &alias).unwrap();
    let original = Fixture::engine(&real, "original-path-scope");
    let linked = Fixture::engine(&alias, "alias-path-scope");
    let stop = AtomicBool::new(false);
    let catalog: Catalog = serde_json::from_slice(include_bytes!(
        "../../discovery-engine/catalog/factory.json"
    ))
    .unwrap();
    let engine = Engine::compile(&catalog).unwrap();
    let mut previous = None;
    let mut cursor = docker::Cursor::default();
    for (index, channels) in [
        vec![original.clone(), linked.clone()],
        vec![linked.clone()],
        vec![original],
    ]
    .into_iter()
    .enumerate()
    {
        let budget = Budget::new(Duration::from_secs(3), &stop);
        let mut snapshot = empty("endpoint", index as u64 + 1, 100);
        assert!(
            docker::collect_with_cursor(&mut snapshot, &channels, &budget, &mut cursor).is_empty()
        );
        assert_eq!(
            snapshot
                .entities
                .iter()
                .filter(|e| e.kind == EntityKind::Runtime)
                .count(),
            1
        );
        assert!(
            snapshot
                .coverage
                .iter()
                .any(|c| c.adapter == "containers" && c.complete)
        );
        assert!(
            engine
                .evaluate(&snapshot)
                .unwrap()
                .identifications
                .iter()
                .any(|i| i.application_id == "openclaw" && i.state == State::Executed)
        );
        assert!(
            !serde_json::to_string(&snapshot)
                .unwrap()
                .contains("PRIVATE_FIXTURE")
        );
        let mut ids: Vec<_> = snapshot.entities.iter().map(|e| e.id.clone()).collect();
        ids.sort();
        if let Some(previous) = &previous {
            assert_eq!(&ids, previous);
        }
        previous = Some(ids);
    }
    assert_eq!(
        fixture.requests.load(Ordering::Acquire),
        9,
        "aliases repeated API work"
    );
    assert_eq!(cursor.containers.len(), 1);
}

#[test]
fn distinct_channels_cannot_hide_each_other_with_the_same_daemon_id() {
    let mut fixture = Fixture::new();
    let first = fixture.serve("first.sock");
    let second = fixture.serve("second.sock");
    let engines = [
        Fixture::engine(&first, "shared-claimed-scope"),
        Fixture::engine(&second, "shared-claimed-scope"),
    ];
    let stop = AtomicBool::new(false);
    let budget = Budget::new(Duration::from_secs(3), &stop);
    let mut snapshot = empty("endpoint", 1, 100);
    docker::collect(&mut snapshot, &engines, &budget);
    assert_eq!(
        snapshot
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Runtime)
            .count(),
        2
    );
    assert_eq!(
        snapshot
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Process)
            .count(),
        2
    );
    assert_eq!(fixture.requests.load(Ordering::Acquire), 6);
    assert!(
        snapshot
            .coverage
            .iter()
            .any(|c| c.adapter == "containers" && c.complete)
    );
}

#[test]
fn unresolved_alias_stays_a_partial_source_instead_of_disappearing() {
    let mut fixture = Fixture::new();
    let real = fixture.serve("real.sock");
    let alias = fixture.root.join("broken.sock");
    std::os::unix::fs::symlink(fixture.root.join("missing.sock"), &alias).unwrap();
    let engines = [
        Fixture::engine(&real, "real"),
        Fixture::engine(&alias, "missing"),
    ];
    let stop = AtomicBool::new(false);
    let budget = Budget::new(Duration::from_secs(3), &stop);
    let mut snapshot = empty("endpoint", 1, 100);
    docker::collect(&mut snapshot, &engines, &budget);
    assert_eq!(
        snapshot
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Runtime)
            .count(),
        1
    );
    assert!(
        snapshot.coverage.iter().any(|c| c.adapter == "containers"
            && c.status == CoverageStatus::Partial
            && !c.complete)
    );
}

#[test]
fn cancellation_does_not_advance_past_channels_that_were_not_queried() {
    let mut fixture = Fixture::new();
    let cancelled = Arc::new(AtomicBool::new(false));
    let first = fixture.serve_with_cancel("a.sock", Some(cancelled.clone()));
    let second = fixture.serve("b.sock");
    let third = fixture.serve("c.sock");
    let channels = [
        Fixture::engine(&first, "a"),
        Fixture::engine(&second, "b"),
        Fixture::engine(&third, "c"),
    ];
    let budget = Budget::new(Duration::from_secs(3), &cancelled);
    let mut cursor = docker::Cursor::default();
    docker::collect_with_cursor(
        &mut empty("endpoint", 1, 100),
        &channels,
        &budget,
        &mut cursor,
    );
    assert_eq!(cursor.next_engine, 1);
    assert_eq!(fixture.requests.load(Ordering::Acquire), 1);
}

#[test]
fn retargeting_an_alias_does_not_reuse_the_previous_channel_identity() {
    let mut fixture = Fixture::new();
    let first = fixture.serve("first.sock");
    let second = fixture.serve("second.sock");
    let alias = fixture.root.join("alias.sock");
    let stop = AtomicBool::new(false);
    let mut ids = vec![];
    for (index, socket) in [&first, &second].into_iter().enumerate() {
        std::os::unix::fs::symlink(socket, &alias).unwrap();
        let budget = Budget::new(Duration::from_secs(3), &stop);
        let mut snapshot = empty("endpoint", index as u64 + 1, 100);
        docker::collect(
            &mut snapshot,
            &[Fixture::engine(&alias, "unchanged-alias")],
            &budget,
        );
        ids.push(
            snapshot
                .entities
                .iter()
                .find(|entity| entity.kind == EntityKind::Runtime)
                .unwrap()
                .id
                .clone(),
        );
        std::fs::remove_file(&alias).unwrap();
    }
    assert_ne!(ids[0], ids[1]);
}
