//! Local system-collector protocol. Neither requests nor signed catalogues carry
//! executable names, paths, credentials or arbitrary collection operations.
use super::{Anchor, Authority, Decision, Ledger, files::Directory, peer_uid};
use crate::{
    Envelope, Result,
    discovery::{Acquisition, Cache, Policy},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

const MAGIC: &[u8; 8] = b"MVDS0001";
const REQUEST_MAX: usize = 384 * 1024;
const RESPONSE_MAX: usize = 8 * 1024 * 1024;

pub use crate::discovery_system_protocol::{Request, Response};

fn receive<T: serde::de::DeserializeOwned>(stream: &mut UnixStream, limit: usize) -> Result<T> {
    let deadline = Instant::now() + stream.read_timeout()?.unwrap_or(Duration::from_secs(5));
    let mut header = [0u8; 12];
    read_until(stream, &mut header, deadline)?;
    let length = u32::from_be_bytes(header[8..].try_into().unwrap()) as usize;
    if &header[..8] != MAGIC || length == 0 || length > limit {
        return Err("invalid system discovery frame".into());
    }
    let mut bytes = zeroize::Zeroizing::new(vec![0; length]);
    read_until(stream, &mut bytes, deadline)?;
    Ok(serde_json::from_slice(&bytes)?)
}
// Socket timeouts alone apply to each syscall. A peer sending a byte before
// every timeout must not keep the collector occupied indefinitely.
fn read_until(stream: &mut UnixStream, mut bytes: &mut [u8], deadline: Instant) -> Result<()> {
    while !bytes.is_empty() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("system discovery frame timed out".into());
        }
        stream.set_read_timeout(Some(remaining))?;
        match stream.read(bytes) {
            Ok(0) => return Err("incomplete system discovery frame".into()),
            Ok(length) => bytes = &mut bytes[length..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => (),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}
fn write_until(stream: &mut UnixStream, mut bytes: &[u8], deadline: Instant) -> Result<()> {
    while !bytes.is_empty() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("system discovery frame timed out".into());
        }
        stream.set_write_timeout(Some(remaining))?;
        match stream.write(bytes) {
            Ok(0) => return Err("incomplete system discovery frame".into()),
            Ok(length) => bytes = &bytes[length..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => (),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}
fn send<T: Serialize>(stream: &mut UnixStream, value: &T, limit: usize) -> Result<()> {
    if crate::shadow::serialized_size(value)? > limit {
        return Err("system discovery response exceeds its budget".into());
    }
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(value)?);
    let deadline = Instant::now() + stream.write_timeout()?.unwrap_or(Duration::from_secs(5));
    write_until(stream, MAGIC, deadline)?;
    write_until(stream, &(bytes.len() as u32).to_be_bytes(), deadline)?;
    write_until(stream, &bytes, deadline)
}

struct Socket {
    path: PathBuf,
    device: u64,
    inode: u64,
}
impl Drop for Socket {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path).is_ok_and(|m| {
            m.dev() == self.device && m.ino() == self.inode && m.file_type().is_socket()
        }) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AcquisitionState {
    binding: String,
    cache: Cache,
}

struct Collector {
    configuration: Directory,
    anchor_bytes: Vec<u8>,
    authority: Authority,
    state: Directory,
    home: PathBuf,
    cache: Cache,
    observer: Option<crate::discovery_network::Observer>,
    active: Option<(Policy, Instant)>,
}
impl Collector {
    fn check_anchor(&self) -> Result<()> {
        if self.configuration.read("anchor.json", 16384)? != self.anchor_bytes {
            return Err("system discovery anchor changed".into());
        }
        Ok(())
    }
    fn persist_cache(&self) -> Result<()> {
        self.state.write(
            "acquisition.json",
            &serde_json::to_vec(&AcquisitionState {
                binding: self.authority.ledger.binding.clone(),
                cache: cache_copy(&self.cache)?,
            })?,
        )
    }
    fn observation(&mut self, policy: &Policy, deadline: Instant) -> Result<()> {
        if policy.configuration.network {
            if !self.observer.as_ref().is_some_and(|o| {
                o.authorize(
                    &policy.catalog,
                    policy.revision,
                    policy.expires_at.timestamp(),
                )
            }) {
                self.observer = None;
                self.observer = Some(crate::discovery_network::Observer::start(
                    &policy.catalog,
                    policy.revision,
                    policy.expires_at.timestamp(),
                )?);
            }
        } else {
            self.observer = None;
        }
        self.active = Some((policy.clone(), deadline));
        Ok(())
    }
    fn refresh_interfaces(&mut self, stop: &AtomicBool) {
        let Some((policy, deadline)) = &self.active else {
            return;
        };
        if policy.expires_at <= Utc::now() || Instant::now() >= *deadline {
            self.observer = None;
            self.active = None;
            return;
        }
        if policy.configuration.virtual_machines && policy.configuration.network {
            if let Some(observer) = self.observer.as_ref() {
                observer.refresh_interfaces(
                    &crate::discovery_system::NativeReader,
                    &milvago_discovery_collector::Budget::new(Duration::from_secs(2), stop),
                );
            }
        }
    }
    fn handle(
        &mut self,
        stream: &mut UnixStream,
        request: Request,
        stop: &AtomicBool,
    ) -> Result<()> {
        self.check_anchor()?;
        if request.version != 1
            || (request.collect && (request.sequence == 0 || request.sequence > i64::MAX as u64))
        {
            return Err("invalid system discovery request".into());
        }
        if !request.collect
            && request.sequence == 0
            && request.authorization.payload.is_empty()
            && request.authorization.signature.is_empty()
        {
            // The kernel-authenticated bridge may withdraw its own collection,
            // including after HTTP 401. This operation never grants access.
            if peer_uid(stream)? != self.authority.anchor.agent_uid {
                return Err("system discovery peer rejected".into());
            }
            self.observer = None;
            self.active = None;
            return send(
                stream,
                &Response {
                    version: 1,
                    revision: 0,
                    catalog_revision: 0,
                    status: "withdrawn".into(),
                    retry_after: 0,
                    snapshot: None,
                },
                RESPONSE_MAX,
            );
        }
        let state = &self.state;
        let persist = |ledger: &Ledger| state.write("authority.json", &serde_json::to_vec(ledger)?);
        let decision = if request.collect {
            self.authority
                .authorize(stream, &request.authorization, persist)?
        } else {
            self.authority
                .refresh(stream, &request.authorization, persist)?
        };
        let (policy, status, retry, snapshot) = match decision {
            Decision::Disabled { policy } => {
                self.observer = None;
                self.active = None;
                (policy, "disabled", 0, None)
            }
            Decision::Wait {
                policy,
                retry_after,
            } => {
                let validity = (policy.expires_at - Utc::now())
                    .to_std()
                    .unwrap_or_default()
                    .min(Duration::from_secs(600));
                self.observation(&policy, Instant::now() + validity)?;
                (
                    policy,
                    "waiting",
                    retry_after
                        .as_secs()
                        .saturating_add(u64::from(retry_after.subsec_nanos() > 0)),
                    None,
                )
            }
            Decision::Collect { policy, deadline } => {
                if request.sequence <= self.cache.sequence {
                    return Err("stale system discovery sequence".into());
                }
                self.cache.sequence = request.sequence;
                self.persist_cache()?;
                self.check_anchor()?;
                self.observation(&policy, deadline)?;
                let state = &self.state;
                let mut persist_guest = |failures: &[String]| {
                    state.write("guest-failures.json", &serde_json::to_vec(failures)?)
                };
                let snapshot = crate::discovery::acquire(
                    Acquisition {
                        policy: &policy,
                        home: &self.home,
                        device_id: &self.authority.anchor.device_id,
                        sequence: request.sequence,
                        cache: &mut self.cache,
                        stop,
                        observer: &mut self.observer,
                    },
                    &mut persist_guest,
                )?;
                self.persist_cache()?;
                if Instant::now() >= deadline || policy.expires_at <= Utc::now() {
                    return Err("system discovery authorization expired".into());
                }
                self.check_anchor()?;
                let response = Response {
                    version: 1,
                    revision: policy.revision,
                    catalog_revision: policy.catalog.revision,
                    status: "collected".into(),
                    retry_after: 0,
                    snapshot: None,
                };
                // Serialize the wiping guard by reference; do not clone raw fields.
                #[derive(Serialize)]
                struct CollectedResponse<'a> {
                    version: u32,
                    revision: u64,
                    catalog_revision: u64,
                    status: &'static str,
                    retry_after: u64,
                    snapshot: &'a milvago_discovery_engine::Snapshot,
                }
                return send(
                    stream,
                    &CollectedResponse {
                        version: response.version,
                        revision: response.revision,
                        catalog_revision: response.catalog_revision,
                        status: "collected",
                        retry_after: 0,
                        snapshot: &snapshot,
                    },
                    RESPONSE_MAX,
                );
            }
        };
        send(
            stream,
            &Response {
                version: 1,
                revision: policy.revision,
                catalog_revision: policy.catalog.revision,
                status: status.into(),
                retry_after: retry,
                snapshot,
            },
            RESPONSE_MAX,
        )
    }
}

fn cache_copy(cache: &Cache) -> Result<Cache> {
    Ok(serde_json::from_slice(&serde_json::to_vec(cache)?)?)
}

pub fn request(runtime: &Path, request: &Request) -> Result<Response> {
    let _directory = Directory::open(runtime)?;
    let mut stream = connect(&runtime.join("collector.sock"))?;
    if peer_uid(&stream)? != 0 {
        return Err("system discovery server is not trusted".into());
    }
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    stream.set_read_timeout(Some(Duration::from_secs(if request.collect {
        35
    } else {
        5
    })))?;
    send(&mut stream, request, REQUEST_MAX)?;
    let response: Response = receive(&mut stream, RESPONSE_MAX)?;
    if response.version != 1 {
        return Err("unsupported system discovery protocol".into());
    }
    Ok(response)
}

fn connect(path: &Path) -> Result<UnixStream> {
    use std::os::{fd::FromRawFd, unix::ffi::OsStrExt};
    let bytes = path.as_os_str().as_bytes();
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.is_empty() || bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
        return Err("invalid system discovery socket path".into());
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (target, byte) in address.sun_path.iter_mut().zip(bytes) {
        *target = *byte as libc::c_char;
    }
    let descriptor = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let stream = unsafe { UnixStream::from_raw_fd(descriptor) };
    // A full Unix accept queue must fail this attempt immediately rather than
    // blocking the discovery worker before its framed I/O deadlines apply.
    if unsafe {
        libc::connect(
            descriptor,
            (&address as *const libc::sockaddr_un).cast(),
            (std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1)
                as libc::socklen_t,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    stream.set_nonblocking(false)?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};

    struct Process(Child);
    impl Drop for Process {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    fn completed(child: &mut Process) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                assert!(status.success());
                return;
            }
            assert!(Instant::now() < deadline, "isolated RPC child timed out");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn rpc_fixture() -> (Anchor, serde_json::Value, ed25519_dalek::SigningKey) {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let key = ed25519_dalek::SigningKey::from_bytes(&[44; 32]);
        let anchor = Anchor {
            version: 1,
            agent_uid: 1000,
            server_url: "https://server.example.test".into(),
            public_key: STANDARD.encode(key.verifying_key().to_bytes()),
            device_id: "11111111-1111-4111-8111-111111111111".into(),
        };
        let now = Utc::now();
        let catalog: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../discovery-engine/catalog/factory.json"
        ))
        .unwrap();
        let policy = serde_json::json!({"kind":"discovery_policy","version":1,"device_id":anchor.device_id,"revision":7,"issued_at":now,"expires_at":now+chrono::Duration::minutes(10),"configuration":{"host":true,"containers":false,"virtual_machines":false,"guest_read":false,"guest_execute":false,"http":false,"network":false,"interval_seconds":300},"catalog":catalog,"runs":[]});
        (anchor, policy, key)
    }
    fn rpc_envelope(value: &serde_json::Value, key: &ed25519_dalek::SigningKey) -> Envelope {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use ed25519_dalek::Signer;
        let bytes = serde_json::to_vec(value).unwrap();
        Envelope {
            payload: STANDARD.encode(&bytes),
            signature: STANDARD.encode(key.sign(&bytes).to_bytes()),
        }
    }
    #[cfg(all(target_os = "linux", feature = "systemd-qualification"))]
    fn systemd_vm_client(runtime: &Path) {
        use milvago_discovery_collector as collector;
        use milvago_discovery_engine::{Catalog, Engine, EntityKind, RelationKind, Source};
        assert_eq!(unsafe { libc::geteuid() }, 1000);
        let id = std::env::var("MILVAGO_SYSTEMD_QA_ID").unwrap();
        assert!(uuid::Uuid::parse_str(&id).is_ok());
        assert_eq!(fs::read_to_string("/opt/qa/id").unwrap(), id);
        assert_eq!(
            fs::read_to_string("/proc/1/comm").unwrap().trim(),
            "systemd"
        );
        assert_eq!(
            fs::read_to_string("/proc/sys/kernel/hostname")
                .unwrap()
                .trim(),
            "systemd-fixture"
        );
        assert_eq!(runtime, Path::new("/opt/qa/rpc/runtime"));
        let (_, mut policy, key) = rpc_fixture();
        policy["revision"] = 10.into();
        policy["configuration"]["host"] = false.into();
        policy["configuration"]["virtual_machines"] = true.into();
        policy["configuration"]["http"] = true.into();
        policy["configuration"]["network"] = true.into();
        policy["catalog"]["http_ports"] = serde_json::json!([32145]);
        policy["catalog"]["http_paths"] = serde_json::json!(["/"]);
        let catalog: Catalog = serde_json::from_value(policy["catalog"].clone()).unwrap();
        let engine = Engine::compile(&catalog).unwrap();
        let mut observed_vm = None;
        for (sequence, run) in [
            (5, "55555555-5555-4555-8555-555555555555"),
            (6, "66666666-6666-4666-8666-666666666666"),
        ] {
            policy["runs"] = serde_json::json!([run]);
            let response = request(
                runtime,
                &Request {
                    version: 1,
                    collect: true,
                    sequence,
                    authorization: rpc_envelope(&policy, &key),
                },
            )
            .unwrap();
            assert_eq!(response.status, "collected");
            let snapshot = response.snapshot.as_ref().unwrap();
            assert_eq!(snapshot.sequence, sequence);
            milvago_discovery_engine::validate_snapshot(snapshot).unwrap();
            assert!(!snapshot.facts.iter().any(|fact| matches!(
                fact.source,
                Source::HostProcess | Source::ContainerProcess | Source::ContainerMetadata
            )));
            let vm = snapshot
                .entities
                .iter()
                .find(|entity| entity.kind == EntityKind::Vm)
                .expect("native libvirt inventory missing");
            if let Some(previous) = observed_vm.as_ref() {
                assert_eq!(&vm.id, previous);
            }
            observed_vm = Some(vm.id.clone());
            let endpoint = collector::identity(
                "endpoint",
                &[&snapshot.scope, "[fd42:246::2]:32145", &vm.id],
            );
            assert!(
                snapshot
                    .relations
                    .iter()
                    .any(|edge| edge.kind == RelationKind::ObservedOrigin
                        && edge.from == vm.id
                        && edge.to == endpoint),
                "installed service did not prove VM HTTP origin"
            );
            let result = engine.evaluate(snapshot).unwrap();
            assert_eq!(result.identifications.len(), 1);
            assert_eq!(result.identifications[0].application_id, "ollama");
            assert_eq!(result.identifications[0].entity_id, endpoint);
            if sequence == 5 {
                assert!(result.communications.is_empty());
                fs::write("/opt/qa/vm-source/ready", b"1").unwrap();
                let deadline = Instant::now() + Duration::from_secs(5);
                while !Path::new("/opt/qa/vm-source/collect").exists() {
                    assert!(
                        Instant::now() < deadline,
                        "service VM capture marker timed out"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
            } else {
                assert_eq!(
                    result.communications.len(),
                    1,
                    "installed service lost VM ClientHello metadata"
                );
                assert_eq!(result.communications[0].provider, "openai");
                assert_eq!(result.communications[0].entity_id, vm.id);
                assert!(
                    snapshot
                        .facts
                        .iter()
                        .any(|fact| fact.source == Source::VmFlow && fact.entity_id == vm.id)
                );
                assert!(
                    !result
                        .identifications
                        .iter()
                        .any(|identification| identification.entity_id == vm.id),
                    "provider destination invented a guest application"
                );
            }
        }
        // The responder has closed after two GETs. A new policy observes only
        // metadata; no exposed HTTP interface or guest credential is available.
        policy["revision"] = 11.into();
        policy["configuration"]["http"] = false.into();
        for (sequence, run) in [
            (7, "77777777-7777-4777-8777-777777777777"),
            (8, "88888888-8888-4888-8888-888888888888"),
        ] {
            policy["runs"] = serde_json::json!([run]);
            let response = request(
                runtime,
                &Request {
                    version: 1,
                    collect: true,
                    sequence,
                    authorization: rpc_envelope(&policy, &key),
                },
            )
            .unwrap();
            assert_eq!(response.status, "collected");
            let snapshot = response.snapshot.as_ref().unwrap();
            assert_eq!(snapshot.sequence, sequence);
            milvago_discovery_engine::validate_snapshot(snapshot).unwrap();
            assert!(!snapshot.entities.iter().any(|entity| matches!(
                entity.kind,
                EntityKind::Endpoint | EntityKind::Process | EntityKind::Container
            )));
            assert!(!snapshot.facts.iter().any(|fact| matches!(
                fact.source,
                Source::Http
                    | Source::HostProcess
                    | Source::ContainerProcess
                    | Source::ContainerMetadata
            )));
            let result = engine.evaluate(snapshot).unwrap();
            assert!(
                result.identifications.is_empty(),
                "network-only guest invented an application"
            );
            if sequence == 7 {
                assert!(result.communications.is_empty());
                fs::write("/opt/qa/vm-source/ready-flow", b"1").unwrap();
                let deadline = Instant::now() + Duration::from_secs(5);
                while !Path::new("/opt/qa/vm-source/collect-flow").exists() {
                    assert!(
                        Instant::now() < deadline,
                        "network-only VM capture marker timed out"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
            } else {
                assert_eq!(
                    result.communications.len(),
                    1,
                    "network-only VM destination missing"
                );
                assert_eq!(result.communications[0].provider, "openai");
                assert_eq!(
                    Some(&result.communications[0].entity_id),
                    observed_vm.as_ref()
                );
                assert!(
                    snapshot
                        .facts
                        .iter()
                        .any(|fact| fact.source == Source::VmFlow
                            && Some(&fact.entity_id) == observed_vm.as_ref())
                );
            }
        }
        let withdrawn = request(
            runtime,
            &Request {
                version: 1,
                collect: false,
                sequence: 0,
                authorization: Envelope {
                    payload: String::new(),
                    signature: String::new(),
                },
            },
        )
        .unwrap();
        assert_eq!(withdrawn.status, "withdrawn");
    }

    #[test]
    #[ignore = "Helper process of the required isolated two-UID RPC qualification"]
    fn isolated_rpc_child() {
        let role =
            std::env::var("MILVAGO_DISCOVERY_RPC_ROLE").expect("qualification role required");
        let root = PathBuf::from(std::env::var_os("MILVAGO_DISCOVERY_RPC_ROOT").unwrap());
        let runtime = root.join("runtime");
        #[cfg(all(target_os = "linux", feature = "systemd-qualification"))]
        if role == "systemd-vm" {
            systemd_vm_client(&runtime);
            return;
        }
        if role == "seed-import" {
            crate::discovery_privileged::enrollment::exercise_import(&root.join("imports/bridge"));
            return;
        }
        if matches!(role.as_str(), "server" | "server-revocation") {
            assert_eq!(unsafe { libc::geteuid() }, 0);
            let stop = std::sync::Arc::new(AtomicBool::new(false));
            let stopped = stop.clone();
            std::thread::spawn(move || {
                let _ = std::io::stdin().read(&mut [0]);
                stopped.store(true, Ordering::Release);
            });
            let result = run(&root.join("config"), &root.join("state"), &runtime, &stop);
            if role == "server" {
                result.unwrap();
            } else {
                assert!(result.is_err());
            }
            return;
        }
        let (_, mut policy, key) = rpc_fixture();
        let operation = |policy: &serde_json::Value, collect, sequence| {
            request(
                &runtime,
                &Request {
                    version: 1,
                    collect,
                    sequence,
                    authorization: rpc_envelope(policy, &key),
                },
            )
        };
        if role == "arm-revocation" {
            assert_eq!(unsafe { libc::geteuid() }, 1000);
            policy["revision"] = 2000.into();
            policy["configuration"]["network"] = true.into();
            assert_eq!(operation(&policy, false, 0).unwrap().status, "waiting");
            return;
        }
        if role == "fallback" {
            assert_eq!(unsafe { libc::geteuid() }, 1000);
            assert!(
                !Path::new("/run/milvago-discovery").exists(),
                "fallback qualification requires its isolated namespace"
            );
            policy["configuration"]["host"] = false.into();
            policy["configuration"]["network"] = true.into();
            let (anchor, _, _) = rpc_fixture();
            let state = crate::State {
                device_id: anchor.device_id.clone(),
                public_key: anchor.public_key,
                server_url: anchor.server_url,
                ..Default::default()
            };
            let policy =
                crate::discovery::verify(&rpc_envelope(&policy, &key), &state, Utc::now()).unwrap();
            let mut cache = Cache::default();
            let mut observer = None;
            let stop = AtomicBool::new(false);
            let snapshot = crate::discovery::acquire_for_worker(
                Acquisition {
                    policy: &policy,
                    home: &root,
                    device_id: &anchor.device_id,
                    sequence: 42,
                    cache: &mut cache,
                    stop: &stop,
                    observer: &mut observer,
                },
                &mut |_| panic!("fallback accessed disabled guest credentials"),
            )
            .unwrap()
            .unwrap();
            assert!(!snapshot.complete);
            assert!(snapshot.facts.is_empty());
            for adapter in ["system-collector", "network"] {
                assert!(snapshot.coverage.iter().any(|c| c.adapter == adapter
                    && c.status == milvago_discovery_engine::CoverageStatus::Unavailable
                    && !c.complete));
            }
            milvago_discovery_engine::validate_snapshot(&snapshot).unwrap();
            return;
        }
        if matches!(role.as_str(), "warm" | "measure") {
            assert_eq!(unsafe { libc::geteuid() }, 1000);
            let (first, count) = if role == "warm" {
                (100, 16)
            } else {
                (1000, 128)
            };
            policy["configuration"]["host"] = false.into();
            for index in 0..count {
                policy["revision"] = (first + index).into();
                policy["configuration"]["network"] = (index % 2 == 0).into();
                let response = operation(&policy, false, 0).unwrap();
                assert_eq!(
                    response.status,
                    if index % 2 == 0 {
                        "waiting"
                    } else {
                        "disabled"
                    }
                );
                assert!(response.snapshot.is_none());
            }
            return;
        }
        if role == "outsider" {
            assert_eq!(unsafe { libc::geteuid() }, 1001);
            assert!(operation(&policy, true, 1).is_err());
            return;
        }
        assert_eq!(unsafe { libc::geteuid() }, 1000);
        assert!(Directory::open(&root.join("state")).is_err());
        assert_eq!(operation(&policy, false, 0).unwrap().status, "waiting");
        let collected = operation(&policy, true, 1).unwrap();
        assert_eq!(collected.status, "collected");
        let snapshot = collected.snapshot.as_ref().unwrap();
        assert_eq!(snapshot.sequence, 1);
        assert!(
            snapshot
                .facts
                .iter()
                .any(|f| f.source == milvago_discovery_engine::Source::HostProcess)
        );
        let waiting = operation(&policy, true, 2).unwrap();
        assert_eq!(waiting.status, "waiting");
        assert!(waiting.snapshot.is_none());
        let mut wrong = policy.clone();
        wrong["device_id"] = "22222222-2222-4222-8222-222222222222".into();
        assert_eq!(operation(&wrong, true, 3).unwrap().status, "unavailable");
        let withdrawn = request(
            &runtime,
            &Request {
                version: 1,
                collect: false,
                sequence: 0,
                authorization: Envelope {
                    payload: String::new(),
                    signature: String::new(),
                },
            },
        )
        .unwrap();
        assert_eq!(withdrawn.status, "withdrawn");
        policy["revision"] = 8.into();
        policy["configuration"]["host"] = false.into();
        assert_eq!(operation(&policy, false, 0).unwrap().status, "disabled");
        policy["revision"] = 7.into();
        assert_eq!(operation(&policy, false, 0).unwrap().status, "unavailable");
        policy["revision"] = 9.into();
        policy["configuration"]["host"] = true.into();
        policy["runs"] = serde_json::json!(["33333333-3333-4333-8333-333333333333"]);
        assert_eq!(operation(&policy, true, 4).unwrap().status, "collected");
    }
    #[test]
    #[ignore = "Required isolated root with SETUID/SETGID; never runs on an endpoint"]
    fn root_service_authenticates_real_peers_collects_and_cleans_up() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let home = tempfile::Builder::new()
            .prefix("milvago-discovery-rpc-")
            .tempdir_in("/run")
            .unwrap();
        fs::set_permissions(home.path(), fs::Permissions::from_mode(0o755)).unwrap();
        for (name, mode) in [("config", 0o700), ("state", 0o700), ("runtime", 0o755)] {
            fs::create_dir(home.path().join(name)).unwrap();
            fs::set_permissions(home.path().join(name), fs::Permissions::from_mode(mode)).unwrap();
        }
        let (anchor, _, _) = rpc_fixture();
        fs::create_dir(home.path().join("imports")).unwrap();
        fs::set_permissions(
            home.path().join("imports"),
            fs::Permissions::from_mode(0o1733),
        )
        .unwrap();
        Directory::open(&home.path().join("config"))
            .unwrap()
            .write("anchor.json", &serde_json::to_vec(&anchor).unwrap())
            .unwrap();
        // The build scratch may be 0700 and /run may be noexec. Resolve only the
        // current test ELF through a held descriptor; do not relax directory ACLs.
        // File::open sets CLOEXEC, so this descriptor closes after execve opens it.
        use std::os::fd::AsRawFd;
        let executable = fs::File::open(std::env::current_exe().unwrap()).unwrap();
        let child_executable = format!("/proc/self/fd/{}", executable.as_raw_fd());
        let child = |role: &str, uid| {
            let mut command = Command::new(&child_executable);
            command
                .args([
                    "--exact",
                    "discovery_privileged::service::tests::isolated_rpc_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", home.path())
                .env("MILVAGO_DISCOVERY_RPC_ROOT", home.path())
                .env("MILVAGO_DISCOVERY_RPC_ROLE", role)
                .uid(uid)
                .gid(1000)
                .stdin(Stdio::piped());
            Process(command.spawn().unwrap())
        };
        let mut server = child("server", 0);
        let deadline = Instant::now() + Duration::from_secs(5);
        let socket = home.path().join("runtime/collector.sock");
        while !socket.exists() {
            assert!(
                server.0.try_wait().unwrap().is_none(),
                "system collector exited before listening"
            );
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        let mut client = child("client", 1000);
        completed(&mut client);
        let ledger = fs::read(home.path().join("state/authority.json")).unwrap();
        let mut outsider = child("outsider", 1001);
        completed(&mut outsider);
        assert_eq!(
            fs::read(home.path().join("state/authority.json")).unwrap(),
            ledger
        );
        let mut fallback = child("fallback", 1000);
        completed(&mut fallback);
        let mut imported = child("seed-import", 1000);
        completed(&mut imported);
        let mut warm = child("warm", 1000);
        completed(&mut warm);
        let resources = || {
            let process = PathBuf::from(format!("/proc/{}", server.0.id()));
            let status = fs::read_to_string(process.join("status")).unwrap();
            let kilobytes = |name: &str| {
                status
                    .lines()
                    .find_map(|line| line.strip_prefix(name))
                    .unwrap()
                    .split_whitespace()
                    .next()
                    .unwrap()
                    .parse::<u64>()
                    .unwrap()
            };
            (
                kilobytes("VmRSS:"),
                kilobytes("VmHWM:"),
                fs::read_dir(process.join("fd")).unwrap().count(),
                fs::read_dir(process.join("task")).unwrap().count(),
            )
        };
        let before = resources();
        let mut measure = child("measure", 1000);
        completed(&mut measure);
        let after = resources();
        println!(
            "System collector short resource check: RSS {} -> {} KiB, peak {} KiB, FDs {} -> {}, tasks {} -> {}; 128 signed changes, 64 observer lifecycles",
            before.0, after.0, after.1, before.2, after.2, before.3, after.3
        );
        assert!(
            after.0 <= before.0 + 8 * 1024,
            "unexpected retained RSS growth"
        );
        assert!(
            after.1 <= 128 * 1024,
            "collector exceeded its memory budget"
        );
        assert_eq!(after.2, before.2, "collector retained file descriptors");
        assert_eq!(after.3, before.3, "collector retained observer tasks");
        server.0.stdin.as_mut().unwrap().write_all(b"x").unwrap();
        completed(&mut server);
        assert!(!socket.exists());
        // An unreadable/corrupt failure latch is never silently reset on restart.
        Directory::open(&home.path().join("state"))
            .unwrap()
            .write("guest-failures.json", b"{broken")
            .unwrap();
        assert!(
            run(
                &home.path().join("config"),
                &home.path().join("state"),
                &home.path().join("runtime"),
                &AtomicBool::new(false)
            )
            .is_err()
        );
        assert!(!socket.exists());
        Directory::open(&home.path().join("state"))
            .unwrap()
            .write("guest-failures.json", b"[]")
            .unwrap();
        let mut revoked_server = child("server-revocation", 0);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !socket.exists() {
            assert!(revoked_server.0.try_wait().unwrap().is_none());
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        let mut arm = child("arm-revocation", 1000);
        completed(&mut arm);
        let mut changed = anchor;
        changed.device_id = "44444444-4444-4444-8444-444444444444".into();
        Directory::open(&home.path().join("config"))
            .unwrap()
            .write("anchor.json", &serde_json::to_vec(&changed).unwrap())
            .unwrap();
        completed(&mut revoked_server);
        assert!(
            !socket.exists(),
            "revoked collector left its socket available"
        );
        assert!(connect(&socket).is_err());
    }
    #[test]
    fn a_full_accept_queue_does_not_block_connect() {
        use std::os::fd::AsRawFd;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("collector.sock");
        let listener = UnixListener::bind(&path).unwrap();
        assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 1) }, 0);
        let mut clients = Vec::new();
        for _ in 0..8 {
            match connect(&path) {
                Ok(client) => clients.push(client),
                Err(_) => break,
            }
        }
        assert!(!clients.is_empty());
        assert!(clients.len() < 8);
    }
    #[test]
    fn trickled_frames_have_one_deadline_and_blocked_writes_are_bounded() {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let value = serde_json::json!({"version":1,"revision":7,"catalog_revision":1,"status":"waiting","retry_after":30,"snapshot":null});
        let bytes = serde_json::to_vec(&value).unwrap();
        sender.write_all(MAGIC).unwrap();
        sender
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .unwrap();
        let writer = std::thread::spawn(move || {
            for byte in bytes {
                if sender.write_all(&[byte]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        });
        assert!(receive::<Response>(&mut receiver, RESPONSE_MAX).is_err());
        drop(receiver);
        writer.join().unwrap();

        let (mut sender, _receiver) = UnixStream::pair().unwrap();
        sender
            .set_write_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        assert!(send(&mut sender, &"x".repeat(1024 * 1024), RESPONSE_MAX).is_err());
    }
    #[test]
    fn frames_reject_cross_protocol_requests_invalid_types_and_oversized_allocations() {
        for (magic, length) in [
            (*b"WRONG001", 1),
            (*MAGIC, 0),
            (*MAGIC, (REQUEST_MAX + 1) as u32),
        ] {
            let (mut sender, mut receiver) = UnixStream::pair().unwrap();
            receiver
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            sender.write_all(&magic).unwrap();
            sender.write_all(&length.to_be_bytes()).unwrap();
            assert!(receive::<Request>(&mut receiver, REQUEST_MAX).is_err());
        }
        for value in [
            serde_json::json!({"version":1,"collect":true,"sequence":1,"authorization":{"image":"data:image/png"}}),
            serde_json::json!({"version":1,"collect":"image","sequence":1,"authorization":{}}),
        ] {
            let (mut sender, mut receiver) = UnixStream::pair().unwrap();
            send(&mut sender, &value, REQUEST_MAX).unwrap();
            assert!(receive::<Request>(&mut receiver, REQUEST_MAX).is_err());
        }
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        send(
            &mut sender,
            &Response {
                version: 1,
                revision: 7,
                catalog_revision: 1,
                status: "waiting".into(),
                retry_after: 30,
                snapshot: None,
            },
            RESPONSE_MAX,
        )
        .unwrap();
        let response: Response = receive(&mut receiver, RESPONSE_MAX).unwrap();
        assert_eq!(response.status, "waiting");
        assert_eq!(response.retry_after, 30);
        assert!(response.snapshot.is_none());
    }
}

pub fn run(configuration: &Path, home: &Path, runtime: &Path, stop: &AtomicBool) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("system discovery collector requires its dedicated system service".into());
    }
    let config = Directory::open(configuration)?;
    let state = Directory::open(home)?;
    let runtime_directory = Directory::open(runtime)?;
    let anchor_bytes = config.read("anchor.json", 16384)?;
    let anchor: Anchor = serde_json::from_slice(&anchor_bytes)?;
    let ledger = match state.read_optional("authority.json", 128 * 1024)? {
        Some(bytes) => serde_json::from_slice(&bytes)?,
        None => Ledger::default(),
    };
    let authority = Authority::new(anchor, ledger)?;
    let mut cache = match state.read_optional("acquisition.json", 128 * 1024)? {
        Some(bytes) => {
            let saved: AcquisitionState = serde_json::from_slice(&bytes)?;
            if saved.binding != authority.ledger.binding {
                return Err("system discovery acquisition binding changed".into());
            }
            saved.cache
        }
        None => Cache::default(),
    };
    if !cache.pending.is_empty()
        || cache.guest_failures.len() > 32
        || cache.guest_failures.iter().any(|s| s.len() > 512)
    {
        return Err("invalid system discovery acquisition state".into());
    }
    if let Some(bytes) = state.read_optional("guest-failures.json", 32768)? {
        let failures: Vec<String> = serde_json::from_slice(&bytes)?;
        if failures.len() > 32 || failures.iter().any(|s| s.len() > 512) {
            return Err("invalid system discovery guest state".into());
        }
        cache.guest_failures = failures;
    }
    let path = runtime.join("collector.sock");
    if let Ok(existing) = fs::symlink_metadata(&path) {
        if !existing.file_type().is_socket() || existing.uid() != 0 || existing.mode() & 0o007 != 0
        {
            return Err("unsafe system discovery socket".into());
        }
        return Err("system discovery socket already exists".into());
    }
    let listener = UnixListener::bind(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o660))?;
    let metadata = fs::symlink_metadata(&path)?;
    let _socket = Socket {
        path,
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    listener.set_nonblocking(true)?;
    let mut collector = Collector {
        configuration: config,
        anchor_bytes,
        authority,
        state,
        home: home.into(),
        cache,
        observer: None,
        active: None,
    };
    let mut checked = Instant::now();
    while !stop.load(Ordering::Acquire) {
        if checked.elapsed() >= Duration::from_secs(1) {
            collector.check_anchor()?;
            runtime_directory.current()?;
            checked = Instant::now();
        }
        collector.refresh_interfaces(stop);
        match listener.accept() {
            Ok((mut stream, _)) => {
                if peer_uid(&stream).ok() != Some(collector.authority.anchor.agent_uid) {
                    continue;
                }
                stream.set_read_timeout(Some(Duration::from_secs(2)))?;
                stream.set_write_timeout(Some(Duration::from_secs(5)))?;
                let outcome = receive::<Request>(&mut stream, REQUEST_MAX)
                    .and_then(|request| collector.handle(&mut stream, request, stop));
                if outcome.is_err() {
                    collector.observer = None;
                    collector.active = None;
                    let _ = send(
                        &mut stream,
                        &Response {
                            version: 1,
                            revision: 0,
                            catalog_revision: 0,
                            status: "unavailable".into(),
                            retry_after: 0,
                            snapshot: None,
                        },
                        RESPONSE_MAX,
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50))
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => (),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}
