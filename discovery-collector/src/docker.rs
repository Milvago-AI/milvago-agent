use crate::*;
#[cfg(all(unix, not(target_os = "linux")))]
use std::io::Read;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct LocalEngine {
    pub socket: PathBuf,
    // Unix collection derives its scope from the resolved socket, preventing
    // caller-supplied labels from merging independent local channels.
    pub scope: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Authority {
    Unverified,
    #[cfg(target_os = "linux")]
    Local(crate::docker_socket::Guard),
}
pub(super) struct LocalResponse {
    pub(super) body: Vec<u8>,
    pub(super) authority: Authority,
}
impl Authority {
    fn current(&self) -> bool {
        match self {
            #[cfg(target_os = "linux")]
            Self::Local(guard) => guard.current(),
            _ => false,
        }
    }
    fn project(
        &self,
        snapshot: &mut Snapshot,
        runtime: &str,
        container: &str,
        id: &str,
        bytes: &[u8],
        budget: &Budget<'_>,
        podman: bool,
    ) -> Result<bool, &'static str> {
        let checkpoint = (
            snapshot.entities.len(),
            snapshot.facts.len(),
            snapshot.relations.len(),
        );
        let result = (|| {
            #[cfg(target_os = "linux")]
            if let Self::Local(guard) = self {
                if !guard.current() {
                    return Err("unverified_engine_peer");
                }
                if podman || !guard.root_trusted() {
                    let pids = containers::docker_top_pids(bytes, podman)?;
                    let mut complete = true;
                    for pid in pids {
                        budget.check()?;
                        let before = (
                            snapshot.entities.len(),
                            snapshot.facts.len(),
                            snapshot.relations.len(),
                        );
                        match crate::containerd_process::docker_project(
                            snapshot,
                            &guard.peer,
                            container,
                            id,
                            pid,
                            budget,
                            podman,
                        ) {
                            Ok(projection) => complete &= projection.complete,
                            Err(_) => {
                                snapshot.entities.truncate(before.0);
                                snapshot.facts.truncate(before.1);
                                snapshot.relations.truncate(before.2);
                                complete = false;
                            }
                        }
                    }
                    validate_snapshot(snapshot).map_err(|_| "invalid_container_snapshot")?;
                    return Ok(complete);
                }
                containers::docker_top(snapshot, runtime, container, bytes)?;
                validate_snapshot(snapshot).map_err(|_| "invalid_container_snapshot")?;
                return Ok(true);
            }
            let _ = (runtime, container, id, bytes, budget, podman);
            Err("unverified_engine_peer")
        })();
        if result.is_err() {
            snapshot.entities.truncate(checkpoint.0);
            snapshot.facts.truncate(checkpoint.1);
            snapshot.relations.truncate(checkpoint.2);
        }
        result
    }
}

#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct Cursor {
    pub next_engine: usize,
    pub containers: BTreeMap<String, usize>,
}
fn schedule(length: usize, start: usize, limit: usize) -> Vec<usize> {
    if length == 0 {
        return vec![];
    }
    (0..length.min(limit))
        .map(|offset| (start % length + offset) % length)
        .collect()
}

#[cfg(unix)]
fn resolved_engine(engine: &LocalEngine) -> LocalEngine {
    use sha2::{Digest, Sha256};
    use std::os::unix::ffi::OsStrExt;
    // Resolve before both identification and connection. A mutable alias cannot
    // claim another channel's scope while requests still use the original path.
    // Failed resolution remains a candidate so access failures stay visible.
    let socket = std::fs::canonicalize(&engine.socket).unwrap_or_else(|_| engine.socket.clone());
    let digest = Sha256::digest(socket.as_os_str().as_bytes());
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    let scope = format!("runtime-scope/{hex}");
    LocalEngine { socket, scope }
}

#[cfg(not(unix))]
fn resolved_engine(engine: &LocalEngine) -> LocalEngine {
    engine.clone()
}

fn listing(
    snapshot: &mut Snapshot,
    runtime: &str,
    bytes: &[u8],
    budget: &Budget<'_>,
) -> Result<Vec<containers::PublishedPort>, &'static str> {
    let checkpoint = (
        snapshot.entities.len(),
        snapshot.facts.len(),
        snapshot.relations.len(),
    );
    let result = containers::docker_list(snapshot, runtime, bytes, budget).and_then(|ports| {
        validate_snapshot(snapshot)
            .map(|_| ports)
            .map_err(|_| "invalid_container_snapshot")
    });
    if result.is_err() {
        snapshot.entities.truncate(checkpoint.0);
        snapshot.facts.truncate(checkpoint.1);
        snapshot.relations.truncate(checkpoint.2);
    }
    result
}

#[cfg(unix)]
pub fn local_engines() -> Vec<LocalEngine> {
    let mut paths = vec![
        PathBuf::from("/var/run/docker.sock"),
        PathBuf::from("/run/podman/podman.sock"),
    ];
    if let Ok(users) = std::fs::read_dir("/run/user") {
        for user in users.flatten().take(64) {
            if user
                .file_name()
                .to_str()
                .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            {
                paths.push(user.path().join("podman/podman.sock"));
                paths.push(user.path().join("docker.sock"));
            }
        }
    }
    paths
        .into_iter()
        .filter(|p| p.exists())
        .map(|socket| LocalEngine {
            scope: identity("runtime-scope", &[&socket.to_string_lossy()]),
            socket,
        })
        .collect()
}

#[cfg(windows)]
pub fn local_engines() -> Vec<LocalEngine> {
    [
        r"\\.\pipe\dockerDesktopLinuxEngine",
        r"\\.\pipe\docker_engine",
        r"\\.\pipe\podman-machine-default",
    ]
    .into_iter()
    .map(|p| LocalEngine {
        socket: PathBuf::from(p),
        scope: identity("runtime-scope", &[p]),
    })
    .collect()
}

#[cfg(not(any(unix, windows)))]
pub fn local_engines() -> Vec<LocalEngine> {
    vec![]
}

fn instance_key(info: &serde_json::Value) -> Option<String> {
    // Podman's Docker-compatible /info generates a new ID on every request.
    // Keep its logical store stable within the local access channel instead of
    // inventing a new runtime/container graph on every collection interval.
    if let Some(version) = info.get("BuildahVersion") {
        let version = version.as_str()?;
        let root = info.get("DockerRootDir")?.as_str()?;
        if version.is_empty()
            || version.len() > 80
            || root.is_empty()
            || root.len() > 4096
            || root.chars().any(char::is_control)
        {
            return None;
        }
        let mode = match info.get("Rootless") {
            None => "unspecified",
            Some(serde_json::Value::Bool(true)) => "rootless",
            Some(serde_json::Value::Bool(false)) => "rootful",
            _ => return None,
        };
        return Some(identity("podman-store", &[root, mode]));
    }
    info.get("ID")
        .and_then(serde_json::Value::as_str)
        .filter(|id| !id.is_empty() && id.len() <= 256)
        .map(str::to_owned)
}

pub fn collect(
    snapshot: &mut Snapshot,
    engines: &[LocalEngine],
    budget: &Budget<'_>,
) -> Vec<containers::PublishedPort> {
    collect_with_cursor(snapshot, engines, budget, &mut Cursor::default())
}
pub fn collect_with_cursor(
    snapshot: &mut Snapshot,
    engines: &[LocalEngine],
    budget: &Budget<'_>,
    cursor: &mut Cursor,
) -> Vec<containers::PublishedPort> {
    let mut ports = vec![];
    let mut complete = engines.len() <= 64;
    let mut seen = std::collections::BTreeSet::new();
    let mut engines: Vec<_> = engines.iter().collect();
    engines.sort_by(|a, b| a.socket.cmp(&b.socket));
    let order = schedule(engines.len(), cursor.next_engine, 64);
    let mut channels = Vec::new();
    let mut paths = std::collections::BTreeSet::new();
    for index in order {
        if budget.check().is_err() {
            complete = false;
            break;
        }
        let engine = resolved_engine(engines[index]);
        paths.insert(engine.socket.clone());
        channels.push((index, engine));
    }
    let per_engine = (128 / paths.len().clamp(1, 64)).max(1);
    let mut top_calls = 0;
    let mut visited = std::collections::BTreeSet::new();
    for (index, engine) in &channels {
        if budget.check().is_err() {
            complete = false;
            break;
        }
        cursor.next_engine = (index + 1) % engines.len();
        if !visited.insert(engine.socket.clone()) {
            continue;
        }
        let (info, authority) = match request(engine, "/info", budget).and_then(|response| {
            bounded_json(&response.body).map(|info| (info, response.authority))
        }) {
            Ok(v) => v,
            Err(_) => {
                complete = false;
                continue;
            }
        };
        let Some(id) = instance_key(&info) else {
            complete = false;
            continue;
        };
        // A daemon ID is scoped to its local access channel: an unprivileged
        // rootless API must not hide another daemon by claiming the same ID.
        if !seen.insert((engine.scope.clone(), id.to_owned())) {
            continue;
        }
        let runtime = identity("runtime", &[&engine.scope, &id]);
        let bytes = match request(engine, "/containers/json?all=1", budget) {
            Ok(response) if response.authority == authority => response.body,
            Ok(_) => {
                complete = false;
                continue;
            }
            Err(_) => {
                complete = false;
                continue;
            }
        };
        let before = snapshot.entities.len();
        match listing(snapshot, &runtime, &bytes, budget) {
            Ok(mut found) => ports.append(&mut found),
            Err(_) => {
                complete = false;
                continue;
            }
        }
        let rows = match bounded_json(&bytes) {
            Ok(serde_json::Value::Array(v)) => v,
            _ => {
                complete = false;
                continue;
            }
        };
        let mut rows: Vec<_> = rows
            .iter()
            .filter(|row| row.get("State").and_then(serde_json::Value::as_str) == Some("running"))
            .collect();
        rows.sort_by_key(|row| {
            row.get("Id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
        });
        if !authority.current() {
            // API names/images remain indications; an unverified local channel
            // cannot promote its own process claims to executed software.
            complete = false;
            continue;
        }
        let podman = info.get("BuildahVersion").is_some();
        let start = cursor.containers.get(&runtime).copied().unwrap_or(0);
        for index in schedule(rows.len(), start, per_engine) {
            if top_calls >= 128 || budget.check().is_err() {
                complete = false;
                break;
            }
            top_calls += 1;
            if !cursor.containers.contains_key(&runtime) && cursor.containers.len() >= 64 {
                if let Some(key) = cursor.containers.keys().next().cloned() {
                    cursor.containers.remove(&key);
                }
            }
            cursor
                .containers
                .insert(runtime.clone(), (index + 1) % rows.len());
            let row = rows[index];
            if row.get("State").and_then(serde_json::Value::as_str) != Some("running") {
                continue;
            }
            let Some(container_id) =
                row.get("Id")
                    .and_then(serde_json::Value::as_str)
                    .filter(|v| {
                        v.len() >= 12 && v.len() <= 128 && v.bytes().all(|b| b.is_ascii_hexdigit())
                    })
            else {
                complete = false;
                continue;
            };
            let entity = identity("container", &[&runtime, container_id]);
            if !snapshot.entities[before..].iter().any(|e| e.id == entity) {
                complete = false;
                continue;
            }
            // Podman's PID column is relative to the container. The hpid descriptor
            // reads host identity without running ps inside its namespaces.
            let path = if podman {
                format!("/containers/{container_id}/top?ps_args=hpid")
            } else {
                format!("/containers/{container_id}/top?ps_args=-eo%20pid,lstart,args")
            };
            match request(engine, &path, budget).and_then(|mut response| {
                if response.authority != authority {
                    return Err("engine_peer_changed");
                }
                let result = authority.project(
                    snapshot,
                    &runtime,
                    &entity,
                    container_id,
                    &response.body,
                    budget,
                    podman,
                );
                response.body.fill(0);
                result
            }) {
                Ok(true) => (),
                _ => complete = false,
            }
        }
        if rows.len() > per_engine {
            complete = false;
        }
    }
    coverage(
        snapshot,
        "containers",
        if complete {
            CoverageStatus::Available
        } else {
            CoverageStatus::Partial
        },
        complete,
    );
    ports
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::atomic::AtomicBool, time::Duration};
    #[cfg(unix)]
    #[test]
    fn opaque_socket_paths_cannot_share_a_lossy_text_identity() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};
        let first = PathBuf::from(OsString::from_vec(b"/unavailable/socket-\xff".to_vec()));
        let second = PathBuf::from(OsString::from_vec(b"/unavailable/socket-\xfe".to_vec()));
        assert_eq!(first.to_string_lossy(), second.to_string_lossy());
        let scope = |socket| {
            resolved_engine(&LocalEngine {
                socket,
                scope: "untrusted-claim".into(),
            })
            .scope
        };
        assert_ne!(scope(first), scope(second));
    }
    #[test]
    fn podman_compatibility_ids_do_not_churn_runtime_or_container_identity() {
        let mut info = serde_json::json!({"ID":"first-random-id","BuildahVersion":"1.42.0","DockerRootDir":"/fixture/rootless/store","Rootless":true});
        let first = instance_key(&info).unwrap();
        info["ID"] = "different-random-id".into();
        assert_eq!(first, instance_key(&info).unwrap());
        info["Rootless"] = false.into();
        assert_ne!(first, instance_key(&info).unwrap());
        info["Rootless"] = true.into();
        info["DockerRootDir"] = "/fixture/other/store".into();
        assert_ne!(first, instance_key(&info).unwrap());
        for (field, value) in [
            ("BuildahVersion", serde_json::json!([])),
            ("DockerRootDir", serde_json::json!("")),
            ("DockerRootDir", serde_json::json!("private\nstore")),
            ("Rootless", serde_json::json!("image/png")),
        ] {
            let mut invalid = info.clone();
            invalid[field] = value;
            assert!(instance_key(&invalid).is_none());
        }
        assert_eq!(
            instance_key(&serde_json::json!({"ID":"stable-docker-id"})).unwrap(),
            "stable-docker-id"
        );
        assert_ne!(
            identity("runtime", &["channel-a", &first]),
            identity("runtime", &["channel-b", &first]),
            "one user-controlled channel cannot hide another engine"
        );
    }
    #[cfg(unix)]
    #[test]
    fn repeated_podman_collections_keep_one_store_and_one_container() {
        use std::{
            io::{Read, Write},
            os::unix::net::UnixListener,
            time::{Instant, SystemTime, UNIX_EPOCH},
        };
        let directory = std::env::temp_dir().join(format!(
            "milvago-podman-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let socket = directory.join("api.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(8);
            for request in 0..6 {
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error)
                            if error.kind() == std::io::ErrorKind::WouldBlock
                                && Instant::now() < deadline =>
                        {
                            std::thread::sleep(Duration::from_millis(2))
                        }
                        Err(error) => panic!("fixture accept: {error}"),
                    }
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let mut header = vec![];
                let mut byte = [0];
                while !header.ends_with(b"\r\n\r\n") {
                    assert!(header.len() < 8192);
                    stream.read_exact(&mut byte).unwrap();
                    header.push(byte[0]);
                }
                let first = std::str::from_utf8(&header)
                    .unwrap()
                    .lines()
                    .next()
                    .unwrap();
                let body=match request%3 {
                    0=>{assert!(first.starts_with("GET /info "));serde_json::json!({"ID":format!("random-id-{request}"),"BuildahVersion":"1.42.0","Rootless":true,"DockerRootDir":"/private-fixture-store"})},
                    1=>{assert!(first.starts_with("GET /containers/json?all=1 "));serde_json::json!([{"Id":"0123456789abcdef","Names":["/fixture"],"Image":"ollama/ollama:latest","State":"running","Ports":[]}])},
                    _=>{assert!(first.starts_with("GET /containers/0123456789abcdef/top?ps_args="));serde_json::json!({"Titles":["HPID"],"Processes":[]})},
                }.to_string();
                write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
            }
        });
        let engines = [LocalEngine {
            scope: "fixture-local-channel".into(),
            socket: socket.clone(),
        }];
        let stop = AtomicBool::new(false);
        let mut cursor = Cursor::default();
        let mut prior = None;
        for sequence in 1..=2 {
            let budget = Budget::new(Duration::from_secs(4), &stop);
            let mut snapshot = empty("endpoint", sequence, 100);
            collect_with_cursor(&mut snapshot, &engines, &budget, &mut cursor);
            let ids: Vec<_> = snapshot
                .entities
                .iter()
                .filter(|entity| matches!(entity.kind, EntityKind::Runtime | EntityKind::Container))
                .map(|entity| entity.id.clone())
                .collect();
            assert_eq!(ids.len(), 2);
            if let Some(prior) = &prior {
                assert_eq!(&ids, prior);
            } else {
                prior = Some(ids);
            }
            assert_eq!(cursor.containers.len(), 1);
            assert!(
                !serde_json::to_string(&snapshot)
                    .unwrap()
                    .contains("private-fixture-store")
            );
        }
        server.join().unwrap();
        std::fs::remove_file(socket).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
    #[test]
    fn bounded_rotation_eventually_visits_every_runtime_and_process_candidate() {
        for (length, limit) in [(500usize, 128usize), (100, 64)] {
            let mut seen = std::collections::BTreeSet::new();
            let mut cursor = 0;
            for _ in 0..length.div_ceil(limit) {
                let selected = schedule(length, cursor, limit);
                assert!(selected.len() <= limit);
                cursor = (selected.last().copied().unwrap() + 1) % length;
                seen.extend(selected);
            }
            assert_eq!(seen.len(), length);
        }
        assert!(schedule(0, usize::MAX, 128).is_empty());
        assert_eq!(schedule(3, usize::MAX, 2).len(), 2);
    }
    #[test]
    fn malformed_daemon_inventory_rolls_back_without_destroying_other_sources() {
        let stop = AtomicBool::new(false);
        let budget = Budget::new(Duration::from_secs(1), &stop);
        let mut snapshot = empty("endpoint", 1, 100);
        snapshot.entities.push(Entity {
            display: None,
            id: "process/host".into(),
            kind: EntityKind::Process,
        });
        fact(
            &mut snapshot,
            "process/host",
            Source::HostProcess,
            BTreeMap::from([(Field::Executable, vec!["openclaw".into()])]),
        );
        for body in [
            br#"[{"Id":"0123456789abcdef"},{"Id":"malformed"}]"#.as_slice(),
            br#"[{"Id":"0123456789abcdef"},{"Id":"0123456789abcdef"}]"#.as_slice(),
        ] {
            assert!(listing(&mut snapshot, "runtime/fixture", body, &budget).is_err());
            assert_eq!(snapshot.entities.len(), 1);
            assert_eq!(snapshot.facts.len(), 1);
            assert!(snapshot.relations.is_empty());
            validate_snapshot(&snapshot).unwrap();
        }
    }
    #[cfg(unix)]
    #[test]
    fn writable_runtime_parent_cannot_attest_container_execution() {
        use std::{
            io::{Read, Write},
            os::unix::{fs::PermissionsExt, net::UnixListener},
            sync::{Arc, atomic::Ordering},
            time::{Instant, SystemTime, UNIX_EPOCH},
        };
        let directory = std::env::temp_dir().join(format!(
            "milvago-untrusted-api-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o777)).unwrap();
        let socket = directory.join("api.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let ended = Arc::new(AtomicBool::new(false));
        let done = ended.clone();
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(4);
            while !done.load(Ordering::Acquire) && Instant::now() < deadline {
                let mut stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => panic!("fixture accept:{error}"),
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let mut header = vec![];
                let mut byte = [0];
                while !header.ends_with(b"\r\n\r\n") && header.len() < 8192 {
                    if stream.read_exact(&mut byte).is_err() {
                        break;
                    }
                    header.push(byte[0]);
                }
                let header = String::from_utf8_lossy(&header);
                let body=if header.starts_with("GET /info "){serde_json::json!({"ID":"untrusted-fixture"})}
                    else if header.starts_with("GET /containers/json?"){serde_json::json!([{"Id":"0123456789abcdef","Image":"openclaw/openclaw:latest","State":"running","Ports":[]}])}
                    else {serde_json::json!({"Titles":["PID","STARTED","COMMAND"],"Processes":[["42","1000","openclaw"]]})}.to_string();
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        let stop = AtomicBool::new(false);
        let budget = Budget::new(Duration::from_secs(2), &stop);
        let mut snapshot = empty("endpoint", 1, 100);
        collect(
            &mut snapshot,
            &[LocalEngine {
                socket: socket.clone(),
                scope: "fixture".into(),
            }],
            &budget,
        );
        ended.store(true, Ordering::Release);
        server.join().unwrap();
        std::fs::remove_file(socket).unwrap();
        std::fs::remove_dir(directory).unwrap();
        validate_snapshot(&snapshot).unwrap();
        assert!(
            !snapshot
                .facts
                .iter()
                .any(|fact| fact.source == Source::ContainerProcess),
            "a replaceable local API cannot attest executed software"
        );
        assert!(
            !snapshot
                .coverage
                .iter()
                .any(|source| source.adapter == "containers" && source.complete)
        );
    }
}

#[cfg(target_os = "linux")]
fn request(
    engine: &LocalEngine,
    path: &str,
    budget: &Budget<'_>,
) -> Result<LocalResponse, &'static str> {
    crate::docker_socket::request(&engine.socket, path, budget)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn request(
    engine: &LocalEngine,
    path: &str,
    budget: &Budget<'_>,
) -> Result<LocalResponse, &'static str> {
    let client = reqwest::blocking::Client::builder()
        .unix_socket(engine.socket.clone())
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(budget.remaining()?)
        .build()
        .map_err(|_| "engine_transport")?;
    let response = client
        .get(format!("http://localhost{path}"))
        .send()
        .map_err(|_| "engine_transport")?;
    if !response.status().is_success() {
        return Err("engine_denied");
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_RESPONSE as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "engine_transport")?;
    if bytes.len() > MAX_RESPONSE {
        return Err("response_limit");
    }
    Ok(LocalResponse {
        body: bytes,
        authority: Authority::Unverified,
    })
}

#[cfg(windows)]
fn request(
    engine: &LocalEngine,
    path: &str,
    budget: &Budget<'_>,
) -> Result<LocalResponse, &'static str> {
    // A pipe owner SID does not identify the process serving an instance:
    // FILE_CREATE_PIPE_INSTANCE can let another principal serve the same name.
    // Without an independently verified server principal, API data is metadata.
    crate::pipe::http(&engine.socket, path, budget).map(|body| LocalResponse {
        body,
        authority: Authority::Unverified,
    })
}

#[cfg(not(any(unix, windows)))]
fn request(_: &LocalEngine, _: &str, _: &Budget<'_>) -> Result<LocalResponse, &'static str> {
    Err("unsupported_platform")
}
