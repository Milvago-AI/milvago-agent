//! Linux kernel corroboration for the read-only containerd task API.
use crate::*;
use std::{
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Peer {
    pid: u32,
    uid: u32,
    start: String,
    namespace: PathBuf,
}

fn start(path: &Path) -> Option<String> {
    let bytes = host::read_limited(&path.join("stat"), 4096).ok()?;
    let value = std::str::from_utf8(&bytes).ok()?;
    let value = value[value.rfind(')')? + 1..].split_whitespace().nth(19)?;
    (!value.is_empty() && value.len() <= 20 && value.bytes().all(|b| b.is_ascii_digit()))
        .then(|| value.into())
}

impl Peer {
    pub(super) fn read(pid: u32, uid: u32) -> Option<Self> {
        if pid == 0 {
            return None;
        }
        let path = PathBuf::from(format!("/proc/{pid}"));
        let first = start(&path)?;
        let namespace = std::fs::read_link(path.join("ns/pid")).ok()?;
        if namespace != std::fs::read_link("/proc/self/ns/pid").ok()?
            || std::fs::metadata(&path).ok()?.uid() != uid
            || start(&path)? != first
        {
            return None;
        }
        Some(Self {
            pid,
            uid,
            start: first,
            namespace,
        })
    }
    pub(super) fn current(&self) -> bool {
        Self::read(self.pid, self.uid).as_ref() == Some(self)
    }
}

// Compare a complete leaf, never an ID substring or an arbitrary ancestor.
fn cgroup_matches(bytes: &[u8], id: &str) -> bool {
    let Ok(value) = std::str::from_utf8(bytes) else {
        return false;
    };
    value.lines().any(|line| {
        let Some(path) = line.splitn(3, ':').nth(2) else {
            return false;
        };
        let Some(leaf) = path.rsplit('/').next() else {
            return false;
        };
        leaf == id || leaf == format!("cri-containerd-{id}.scope")
    })
}

#[derive(Debug)]
pub(super) struct Projection {
    pub(super) listeners: Vec<host::Listener>,
    pub(super) complete: bool,
}

/// Read a current task without entering namespaces or executing guest code.
/// Only host-reachable listeners are returned for HTTP; private ports remain
/// endpoint metadata in the container graph and are never loopback candidates.
pub(super) fn project(
    snapshot: &mut Snapshot,
    peer: &Peer,
    container: &str,
    id: &str,
    pid: u32,
    budget: &Budget<'_>,
) -> Result<Projection, &'static str> {
    project_at(
        snapshot,
        peer,
        container,
        id,
        pid,
        budget,
        Path::new("/proc"),
    )
}

fn project_at(
    snapshot: &mut Snapshot,
    peer: &Peer,
    container: &str,
    id: &str,
    pid: u32,
    budget: &Budget<'_>,
    proc: &Path,
) -> Result<Projection, &'static str> {
    project_at_kind(snapshot, peer, container, id, pid, budget, proc, None)
}

pub(super) fn docker_project(
    snapshot: &mut Snapshot,
    peer: &Peer,
    container: &str,
    id: &str,
    pid: u32,
    budget: &Budget<'_>,
    podman: bool,
) -> Result<Projection, &'static str> {
    project_at_kind(
        snapshot,
        peer,
        container,
        id,
        pid,
        budget,
        Path::new("/proc"),
        Some(podman),
    )
}

fn docker_cgroup_matches(bytes: &[u8], id: &str, podman: bool) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let prefix = if podman { "libpod-" } else { "docker-" };
    text.lines().any(|line| {
        line.splitn(3, ':')
            .nth(2)
            .and_then(|path| path.rsplit('/').next())
            .is_some_and(|leaf| {
                leaf == id
                    || leaf == format!("{prefix}{id}.scope")
                    || (podman
                        && (leaf == format!("libpod-{id}")
                            || leaf == format!("libpod-payload-{id}")))
            })
    })
}

fn project_at_kind(
    snapshot: &mut Snapshot,
    peer: &Peer,
    container: &str,
    id: &str,
    pid: u32,
    budget: &Budget<'_>,
    proc: &Path,
    kind: Option<bool>,
) -> Result<Projection, &'static str> {
    let cgroup_matches = |bytes: &[u8], id: &str| match kind {
        Some(podman) => docker_cgroup_matches(bytes, id, podman),
        None => cgroup_matches(bytes, id),
    };
    budget.check()?;
    if pid == 0 || !peer.current() {
        return Err("unverified_task");
    }
    let path = proc.join(pid.to_string());
    let initial = start(&path).ok_or("process_unavailable")?;
    let executable_path =
        std::fs::read_link(path.join("exe")).map_err(|_| "process_unavailable")?;
    let owner = std::fs::metadata(&path)
        .map_err(|_| "process_unavailable")?
        .uid();
    if (peer.uid != 0 && peer.uid != owner)
        || !cgroup_matches(&host::read_limited(&path.join("cgroup"), 16384)?, id)
    {
        return Err("unverified_task");
    }
    let netns = std::fs::read_link(path.join("ns/net")).map_err(|_| "process_unavailable")?;
    let reachable = std::fs::read_link(proc.join("self/ns/net")).is_ok_and(|v| v == netns);
    let boot = host::read_limited(&proc.join("sys/kernel/random/boot_id"), 80)?;
    let boot = std::str::from_utf8(&boot)
        .map_err(|_| "process_unavailable")?
        .trim();
    let process = identity("process", &[container, boot, &pid.to_string(), &initial]);
    if snapshot.entities.iter().any(|e| e.id == process) {
        return Ok(Projection {
            listeners: vec![],
            complete: true,
        });
    }
    let executable = host::executable_name(&executable_path.to_string_lossy());
    let mut fields = BTreeMap::from([(Field::Executable, vec![executable.clone()])]);
    if let Ok(command) = host::read_limited(&path.join("cmdline"), 8192) {
        let args = command
            .split(|b| *b == 0)
            .skip(1)
            .take(3)
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .collect::<Vec<_>>();
        let tokens = host::entry_tokens(&executable, &args);
        if !tokens.is_empty() {
            fields.insert(Field::ArgumentToken, tokens);
        }
    }
    // Port visibility is independent of the already corroborated process.
    // Discard incomplete socket evidence, while keeping positive execution
    // metadata if the final process/peer checks and authorization still hold.
    let scanned_ports = (|| -> Result<Vec<std::net::SocketAddr>, &'static str> {
        let mut descriptors = BTreeMap::new();
        let mut complete = true;
        for (index, fd) in std::fs::read_dir(path.join("fd"))
            .map_err(|_| "process_unavailable")?
            .enumerate()
        {
            budget.check()?;
            if index >= 256 {
                complete = false;
                break;
            }
            let fd = fd.map_err(|_| "process_unavailable")?;
            let link = std::fs::read_link(fd.path()).map_err(|_| "socket_unavailable")?;
            if let Some(inode) = link
                .to_str()
                .and_then(|s| s.strip_prefix("socket:["))
                .and_then(|s| s.strip_suffix(']'))
            {
                descriptors.insert(inode.to_owned(), fd.path());
            }
        }
        if !complete {
            return Err("descriptor_limit");
        }
        let mut ports = vec![];
        for table in ["net/tcp", "net/tcp6"] {
            budget.check()?;
            let bytes = host::read_limited(&path.join(table), MAX_RESPONSE)?;
            for row in String::from_utf8_lossy(&bytes).lines().skip(1) {
                budget.check()?;
                let columns = row.split_whitespace().take(11).collect::<Vec<_>>();
                if columns.len() < 10 || columns[3] != "0A" {
                    continue;
                }
                let Some(fd) = descriptors.get(columns[9]) else {
                    continue;
                };
                let Some(address) = host::parse_tcp_endpoint(columns[1]).filter(|a| a.port() != 0)
                else {
                    continue;
                };
                if !std::fs::read_link(fd)
                    .is_ok_and(|s| s.to_str() == Some(&format!("socket:[{}]", columns[9])))
                {
                    return Err("process_changed");
                }
                ports.push(address);
                if ports.len() > 128 {
                    return Err("port_limit");
                }
            }
        }
        ports.sort();
        ports.dedup();
        Ok(ports)
    })();
    budget.check()?;
    let complete = scanned_ports.is_ok();
    let ports = scanned_ports.unwrap_or_default();
    if start(&path).as_deref() != Some(&initial)
        || !std::fs::read_link(path.join("exe")).is_ok_and(|v| v == executable_path)
        || !std::fs::read_link(path.join("ns/net")).is_ok_and(|v| v == netns)
        || !cgroup_matches(&host::read_limited(&path.join("cgroup"), 16384)?, id)
        || !peer.current()
    {
        return Err("process_changed");
    }
    if snapshot.entities.len() + ports.len() + 1 > MAX_ENTITIES
        || snapshot.relations.len() + ports.len() + 1 > MAX_ENTITIES
        || snapshot.facts.len() >= MAX_FACTS
    {
        return Err("process_limit");
    }
    snapshot.entities.push(Entity {
        display: None,
        id: process.clone(),
        kind: EntityKind::Process,
    });
    snapshot.relations.push(Relation {
        from: container.into(),
        to: process.clone(),
        kind: RelationKind::Contains,
        source: if kind.is_some() {
            "docker-procfs"
        } else {
            "containerd-procfs"
        }
        .into(),
    });
    if !fact(snapshot, &process, Source::ContainerProcess, fields) {
        return Err("fact_limit");
    }
    for address in &ports {
        let endpoint = identity("endpoint", &[&process, &address.to_string()]);
        snapshot.entities.push(Entity {
            display: Some(EntityDisplay {
                address: Some(*address),
                ..Default::default()
            }),
            id: endpoint.clone(),
            kind: EntityKind::Endpoint,
        });
        snapshot.relations.push(Relation {
            from: process.clone(),
            to: endpoint,
            kind: RelationKind::OwnsEndpoint,
            source: if kind.is_some() {
                "docker-procfs"
            } else {
                "containerd-procfs"
            }
            .into(),
        });
    }
    Ok(Projection {
        complete,
        listeners: if reachable {
            ports
                .into_iter()
                .map(|address| host::Listener {
                    address,
                    owner: Some(process.clone()),
                })
                .collect()
        } else {
            vec![]
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_cgroup_leaf_never_accepts_prefix_ancestor_or_host_root() {
        for path in [
            "0::/tenant/openclaw",
            "1:cpu:/cri-containerd-openclaw.scope",
        ] {
            assert!(cgroup_matches(path.as_bytes(), "openclaw"));
        }
        for path in [
            "0::/",
            "0::/tenant/openclaw-other",
            "0::/openclaw/other",
            "0::/prefix-openclaw",
            "0::/cri-containerd-openclaw.scope.other",
        ] {
            assert!(!cgroup_matches(path.as_bytes(), "openclaw"));
        }
        assert!(!cgroup_matches(&[255], "openclaw"));
    }
    #[test]
    fn podman_kernel_membership_accepts_only_exact_supported_leaves() {
        let id = "0123456789abcdef";
        for leaf in [
            id.to_string(),
            format!("libpod-{id}"),
            format!("libpod-{id}.scope"),
            format!("libpod-payload-{id}"),
        ] {
            let line = format!("0::/delegated/{leaf}");
            assert!(docker_cgroup_matches(line.as_bytes(), id, true));
            assert!(!docker_cgroup_matches(
                format!("{line}/child").as_bytes(),
                id,
                true
            ));
            assert!(!docker_cgroup_matches(
                format!("{line}-other").as_bytes(),
                id,
                true
            ));
        }
        assert!(!docker_cgroup_matches(b"0::/", id, true));
        assert!(!docker_cgroup_matches(
            b"0::/libpod-0123456789abcdef",
            id,
            false
        ));
        assert!(!docker_cgroup_matches(&[255], id, true));
    }
    #[test]
    fn peer_requires_current_kernel_uid_pid_start_and_namespace() {
        let pid = std::process::id();
        let uid = std::fs::metadata(format!("/proc/{pid}")).unwrap().uid();
        let mut peer = Peer::read(pid, uid).unwrap();
        assert!(peer.current());
        peer.start.push('0');
        assert!(!peer.current());
        assert!(Peer::read(pid, uid.wrapping_add(1)).is_none());
        assert!(Peer::read(0, uid).is_none());
    }
    #[test]
    fn task_projection_proves_cgroup_socket_namespace_and_keeps_arguments_private() {
        use std::{os::unix::fs::symlink, sync::atomic::AtomicBool, time::Duration};
        let root = std::env::temp_dir().join(format!(
            "discovery-containerd-proc-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(root.clone());
        for p in [
            "123/ns",
            "123/fd",
            "123/net",
            "self/ns",
            "sys/kernel/random",
        ] {
            std::fs::create_dir_all(root.join(p)).unwrap();
        }
        std::fs::write(root.join("sys/kernel/random/boot_id"), "fixture-boot").unwrap();
        std::fs::write(
            root.join("123/stat"),
            format!("123 (python) {} 41", vec!["0"; 19].join(" ")),
        )
        .unwrap();
        std::fs::write(
            root.join("123/cgroup"),
            "0::/tenant/cri-containerd-fixture.scope",
        )
        .unwrap();
        std::fs::write(
            root.join("123/cmdline"),
            b"python3\0-m\0hermes_cli.main\0PRIVATE-CREDENTIAL\0",
        )
        .unwrap();
        symlink("/usr/bin/python3", root.join("123/exe")).unwrap();
        symlink("net:[1]", root.join("123/ns/net")).unwrap();
        symlink("net:[2]", root.join("self/ns/net")).unwrap();
        symlink("socket:[73]", root.join("123/fd/1")).unwrap();
        std::fs::write(root.join("123/net/tcp"), "header\n0: 0100007F:7531 00000000:0000 0A 0 0 0 0 0 73\n0: 0100007F:7532 00000000:0000 0A 0 0 0 0 0 74\n").unwrap();
        std::fs::write(root.join("123/net/tcp6"), "header\n").unwrap();
        let peer = Peer::read(
            std::process::id(),
            std::fs::metadata("/proc/self").unwrap().uid(),
        )
        .unwrap();
        let stop = AtomicBool::new(false);
        let budget = Budget::new(Duration::from_secs(2), &stop);
        let make = || {
            let mut snapshot = empty("endpoint", 1, 100);
            snapshot.entities.push(Entity {
                id: "container/fixture".into(),
                kind: EntityKind::Container,
                display: None,
            });
            snapshot
        };
        let mut snapshot = make();
        let listeners = project_at(
            &mut snapshot,
            &peer,
            "container/fixture",
            "fixture",
            123,
            &budget,
            &root,
        )
        .unwrap();
        assert!(
            listeners.listeners.is_empty(),
            "private netns cannot become a host HTTP candidate"
        );
        assert!(listeners.complete);
        assert_eq!(
            snapshot
                .entities
                .iter()
                .filter(|e| e.kind == EntityKind::Endpoint)
                .count(),
            1
        );
        assert!(
            !serde_json::to_string(&snapshot)
                .unwrap()
                .contains("PRIVATE")
        );
        let factory: Catalog = serde_json::from_slice(include_bytes!(
            "../../discovery-engine/catalog/factory.json"
        ))
        .unwrap();
        let report = Engine::compile(&factory)
            .unwrap()
            .evaluate(&snapshot)
            .unwrap();
        assert_eq!(report.identifications[0].state, State::Executed);
        std::fs::remove_file(root.join("123/net/tcp6")).unwrap();
        let mut without_ipv6 = make();
        let incomplete = project_at(
            &mut without_ipv6,
            &peer,
            "container/fixture",
            "fixture",
            123,
            &budget,
            &root,
        )
        .expect("an unavailable port table must not erase corroborated running software");
        assert!(!incomplete.complete);
        assert!(incomplete.listeners.is_empty());
        assert!(
            !without_ipv6
                .entities
                .iter()
                .any(|entity| entity.kind == EntityKind::Endpoint)
        );
        assert_eq!(
            Engine::compile(&factory)
                .unwrap()
                .evaluate(&without_ipv6)
                .unwrap()
                .identifications[0]
                .state,
            State::Executed
        );
        // A file that cannot be read as a socket table has the same partial
        // visibility semantics; neither case invents an HTTP probe target.
        std::fs::create_dir(root.join("123/net/tcp6")).unwrap();
        let mut unreadable_ports = make();
        let incomplete = project_at(
            &mut unreadable_ports,
            &peer,
            "container/fixture",
            "fixture",
            123,
            &budget,
            &root,
        )
        .unwrap();
        assert!(!incomplete.complete && incomplete.listeners.is_empty());
        assert_eq!(
            Engine::compile(&factory)
                .unwrap()
                .evaluate(&unreadable_ports)
                .unwrap()
                .identifications[0]
                .state,
            State::Executed
        );
        assert!(
            !unreadable_ports
                .entities
                .iter()
                .any(|entity| entity.kind == EntityKind::Endpoint)
        );
        std::fs::remove_dir(root.join("123/net/tcp6")).unwrap();
        std::fs::write(root.join("123/net/tcp6"), "header\n").unwrap();
        std::fs::remove_file(root.join("123/fd/1")).unwrap();
        std::fs::remove_dir(root.join("123/fd")).unwrap();
        let mut missing_descriptors = make();
        let incomplete = project_at(
            &mut missing_descriptors,
            &peer,
            "container/fixture",
            "fixture",
            123,
            &budget,
            &root,
        )
        .unwrap();
        assert!(!incomplete.complete && incomplete.listeners.is_empty());
        assert_eq!(
            Engine::compile(&factory)
                .unwrap()
                .evaluate(&missing_descriptors)
                .unwrap()
                .identifications[0]
                .state,
            State::Executed
        );
        std::fs::create_dir(root.join("123/fd")).unwrap();
        std::fs::write(root.join("123/fd/1"), "not a readable descriptor link").unwrap();
        let mut unreadable_descriptor = make();
        let incomplete = project_at(
            &mut unreadable_descriptor,
            &peer,
            "container/fixture",
            "fixture",
            123,
            &budget,
            &root,
        )
        .unwrap();
        assert!(!incomplete.complete && incomplete.listeners.is_empty());
        assert_eq!(
            Engine::compile(&factory)
                .unwrap()
                .evaluate(&unreadable_descriptor)
                .unwrap()
                .identifications[0]
                .state,
            State::Executed
        );
        std::fs::remove_file(root.join("123/fd/1")).unwrap();
        symlink("socket:[73]", root.join("123/fd/1")).unwrap();
        crate::test_support::fill_relationships(&mut snapshot);
        let before = serde_json::to_vec(&snapshot).unwrap();
        std::fs::write(
            root.join("123/stat"),
            format!("123 (python) {} 42", vec!["0"; 19].join(" ")),
        )
        .unwrap();
        assert_eq!(
            project_at(
                &mut snapshot,
                &peer,
                "container/fixture",
                "fixture",
                123,
                &budget,
                &root
            )
            .unwrap_err(),
            "process_limit"
        );
        assert_eq!(serde_json::to_vec(&snapshot).unwrap(), before);
        assert_eq!(
            Engine::compile(&factory)
                .unwrap()
                .evaluate(&snapshot)
                .unwrap()
                .identifications[0]
                .state,
            State::Executed
        );
        std::fs::remove_file(root.join("self/ns/net")).unwrap();
        symlink("net:[1]", root.join("self/ns/net")).unwrap();
        let listeners = project_at(
            &mut make(),
            &peer,
            "container/fixture",
            "fixture",
            123,
            &budget,
            &root,
        )
        .unwrap();
        assert!(listeners.complete);
        assert_eq!(listeners.listeners.len(), 1);
        assert_eq!(listeners.listeners[0].address.port(), 30001);
        for cgroup in ["0::/", "0::/fixture/other", "0::/not-fixture"] {
            std::fs::write(root.join("123/cgroup"), cgroup).unwrap();
            let mut snapshot = make();
            assert!(
                project_at(
                    &mut snapshot,
                    &peer,
                    "container/fixture",
                    "fixture",
                    123,
                    &budget,
                    &root
                )
                .is_err()
            );
            assert_eq!(snapshot.entities.len(), 1);
            assert!(snapshot.facts.is_empty());
        }
        stop.store(true, std::sync::atomic::Ordering::Release);
        assert!(
            project_at(
                &mut make(),
                &peer,
                "container/fixture",
                "fixture",
                123,
                &budget,
                &root
            )
            .is_err()
        );
    }
}
