//! Signed opt-in discovery, isolated from browser capture and conversation collection.
use crate::{Envelope, Result, State, Store};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use milvago_discovery_collector as collector;
use milvago_discovery_engine::{Catalog, CoverageStatus, Engine, Report, report};
use serde::{Deserialize, Serialize};
use std::{
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

const QUEUE_BYTES: usize = 8 * 1024 * 1024;
// Covers every early return as well as the normal evaluation path. Transport
// libraries may keep their own buffers; raw fact values never enter the queue.
pub(crate) struct Collected(milvago_discovery_engine::Snapshot);
impl std::ops::Deref for Collected {
    type Target = milvago_discovery_engine::Snapshot;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for Collected {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for Collected {
    fn drop(&mut self) {
        for fact in &mut self.0.facts {
            for values in fact.fields.values_mut() {
                for value in values {
                    zeroize::Zeroize::zeroize(value);
                }
            }
        }
    }
}
static READY: AtomicBool = AtomicBool::new(false);
pub fn ready() -> bool {
    READY.load(Ordering::Acquire)
}

#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Cache {
    pub settings_revision: u64,
    pub catalog_revision: u64,
    pub sequence: u64,
    pub last_collected: Option<DateTime<Utc>>,
    pub pending: Vec<Report>,
    pub http_cursor: usize,
    pub vm_http_cursor: usize,
    pub report_retry_after: Option<DateTime<Utc>>,
    pub completed_runs: Vec<String>,
    pub guest_failures: Vec<String>,
    pub docker_cursor: collector::docker::Cursor,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub host: bool,
    pub containers: bool,
    pub virtual_machines: bool,
    pub guest_read: bool,
    pub guest_execute: bool,
    pub http: bool,
    pub network: bool,
    pub interval_seconds: u64,
}
impl Configuration {
    fn active(&self) -> bool {
        self.host || self.containers || self.virtual_machines || self.network
    }
    fn valid(&self) -> bool {
        (60..=3600).contains(&self.interval_seconds)
            && (!self.guest_execute || self.guest_read)
            && (!self.guest_read || self.virtual_machines)
            && (!self.http || self.host || self.containers || self.virtual_machines)
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub kind: String,
    pub version: u32,
    pub device_id: String,
    pub revision: u64,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub configuration: Configuration,
    pub catalog: Catalog,
    pub runs: Vec<String>,
    #[serde(skip)]
    identity_binding: String,
    #[serde(skip)]
    authorization: Option<Envelope>,
}

pub fn verify(envelope: &Envelope, state: &State, now: DateTime<Utc>) -> Result<Policy> {
    if envelope.payload.len() > 256 * 1024 || envelope.signature.len() > 128 {
        return Err("discovery policy exceeds its limit".into());
    }
    let public: [u8; 32] = STANDARD
        .decode(&state.public_key)?
        .try_into()
        .map_err(|_| "invalid discovery trust key")?;
    let bytes = STANDARD.decode(&envelope.payload)?;
    let signature = STANDARD.decode(&envelope.signature)?;
    VerifyingKey::from_bytes(&public)?
        .verify_strict(&bytes, &Signature::from_slice(&signature)?)?;
    let mut policy: Policy = serde_json::from_slice(&bytes)?;
    if policy.kind != "discovery_policy"
        || policy.version != 1
        || policy.device_id != state.device_id
        || policy.revision < state.discovery.settings_revision
        || policy.catalog.revision < state.discovery.catalog_revision
        || policy.issued_at > now + chrono::Duration::seconds(60)
        || policy.expires_at <= now
        || policy.expires_at <= policy.issued_at
        || policy.expires_at - policy.issued_at > chrono::Duration::minutes(10)
        || !policy.configuration.valid()
        || policy.runs.len() > 1
        || policy
            .runs
            .iter()
            .any(|r| uuid::Uuid::parse_str(r).is_err())
    {
        return Err("discovery authorization rejected".into());
    }
    Engine::compile(&policy.catalog).map_err(|_| "discovery catalog rejected")?;
    policy.identity_binding = policy_binding(state);
    policy.authorization = Some(envelope.clone());
    Ok(policy)
}

#[cfg(target_os = "linux")]
fn system_request(
    policy: &Policy,
    sequence: Option<u64>,
) -> Result<crate::discovery_privileged::service::Response> {
    crate::discovery_privileged::service::request(
        Path::new("/run/milvago-discovery"),
        &crate::discovery_privileged::service::Request {
            version: 1,
            collect: sequence.is_some(),
            sequence: sequence.unwrap_or(0),
            authorization: policy
                .authorization
                .clone()
                .ok_or("missing signed discovery authorization")?,
        },
    )
}

#[cfg(windows)]
fn system_request(
    policy: &Policy,
    sequence: Option<u64>,
) -> Result<crate::discovery_system_protocol::Response> {
    crate::discovery_windows_system::request(
        crate::discovery_windows_system::edition(),
        &crate::discovery_system_protocol::Request {
            version: 1,
            collect: sequence.is_some(),
            sequence: sequence.unwrap_or(0),
            authorization: policy
                .authorization
                .clone()
                .ok_or("missing signed discovery authorization")?,
        },
    )
}

#[cfg(windows)]
fn withdraw_system() {
    let _ = crate::discovery_windows_system::request(
        crate::discovery_windows_system::edition(),
        &crate::discovery_system_protocol::Request {
            version: 1,
            collect: false,
            sequence: 0,
            authorization: Envelope {
                payload: String::new(),
                signature: String::new(),
            },
        },
    );
}

#[cfg(any(windows, target_os = "linux"))]
fn system_snapshot(
    policy: &Policy,
    sequence: u64,
    response: &mut crate::discovery_system_protocol::Response,
) -> Result<Option<Collected>> {
    if response.version != 1
        || response.revision != policy.revision
        || response.catalog_revision != policy.catalog.revision
    {
        return Err("system discovery authorization differs".into());
    }
    if response.status == "waiting" && response.snapshot.is_none() {
        return Ok(None);
    }
    if response.status != "collected" {
        return Err("system discovery collector unavailable".into());
    }
    let snapshot = Collected(
        response
            .snapshot
            .take()
            .ok_or("missing system discovery snapshot")?,
    );
    milvago_discovery_engine::validate_snapshot(&snapshot)?;
    if snapshot.scope != "endpoint"
        || snapshot.sequence != sequence
        || snapshot.observed_at > Utc::now().timestamp().saturating_add(60)
        || Utc::now().timestamp().saturating_sub(snapshot.observed_at) > 60
    {
        return Err("stale system discovery snapshot".into());
    }
    use milvago_discovery_engine::Source;
    let configuration = &policy.configuration;
    if snapshot.facts.iter().any(|fact| !match fact.source {
        Source::Installation | Source::HostProcess => configuration.host,
        Source::ContainerProcess | Source::ContainerMetadata => configuration.containers,
        Source::GuestProcess => {
            configuration.virtual_machines
                && configuration.guest_read
                && configuration.guest_execute
        }
        Source::Http => configuration.http,
        Source::HostFlow | Source::HostDnsQuery => configuration.network,
        Source::VmFlow => configuration.network && configuration.virtual_machines,
        Source::RuntimeFlow | Source::ContainerFlow => {
            configuration.network && configuration.containers
        }
    }) {
        return Err("system discovery source is not authorized".into());
    }
    Ok(Some(snapshot))
}

#[cfg(target_os = "linux")]
fn withdraw_system() {
    if unsafe { libc::geteuid() } != 0 {
        let _ = crate::discovery_privileged::service::request(
            Path::new("/run/milvago-discovery"),
            &crate::discovery_privileged::service::Request {
                version: 1,
                collect: false,
                sequence: 0,
                authorization: Envelope {
                    payload: String::new(),
                    signature: String::new(),
                },
            },
        );
    }
}

#[cfg(any(windows, target_os = "linux"))]
fn uses_system_collector() -> bool {
    #[cfg(target_os = "linux")]
    {
        unsafe { libc::geteuid() != 0 }
    }
    #[cfg(windows)]
    {
        true
    }
}

fn policy_binding(state: &State) -> String {
    collector::identity(
        "discovery-authorization",
        &[
            &state.device_id,
            &state.server_url,
            &state.public_key,
            &state.credential,
            &state.authorization_generation.to_string(),
        ],
    )
}

fn same(current: &State, previous: &State) -> bool {
    current.device_id == previous.device_id
        && current.credential == previous.credential
        && current.server_url == previous.server_url
        && current.public_key == previous.public_key
        && current.authorization_generation == previous.authorization_generation
}

fn identity(state: State) -> State {
    State {
        server_url: state.server_url,
        public_key: state.public_key,
        device_id: state.device_id,
        credential: state.credential,
        authorization_generation: state.authorization_generation,
        discovery: Cache {
            settings_revision: state.discovery.settings_revision,
            catalog_revision: state.discovery.catalog_revision,
            ..Default::default()
        },
        ..Default::default()
    }
}

pub fn spawn(home: PathBuf, stop: Arc<AtomicBool>) -> Result<std::thread::JoinHandle<()>> {
    Ok(std::thread::Builder::new()
        .name("milvago-discovery".into())
        .spawn(move || {
            struct ReadyGuard;
            impl Drop for ReadyGuard {
                fn drop(&mut self) {
                    READY.store(false, Ordering::Release);
                }
            }
            let _ready = ReadyGuard;
            #[cfg(windows)]
            {
                withdraw_system();
                crate::discovery_network::cleanup_windows_session();
            }
            READY.store(true, Ordering::Release);
            let mut policy: Option<Policy> = None;
            let mut refreshed: Option<Instant> = None;
            let mut deferred = false;
            let mut observer = None;
            let mut system_active = false;
            while !stop.load(Ordering::Acquire) {
                let refresh =
                    refreshed.is_none_or(|last| last.elapsed() >= Duration::from_secs(60));
                if refresh {
                    refreshed = Some(Instant::now());
                }
                let outcome = pass(
                    &home,
                    &stop,
                    &mut policy,
                    refresh,
                    &mut observer,
                    &mut system_active,
                );
                if outcome.is_err()
                    || policy
                        .as_ref()
                        .is_none_or(|p| !p.configuration.network || p.expires_at <= Utc::now())
                {
                    observer = None;
                    #[cfg(any(windows, target_os = "linux"))]
                    if outcome.is_err()
                        || policy.as_ref().is_none_or(|p| p.expires_at <= Utc::now())
                    {
                        withdraw_system();
                    }
                }
                if outcome.is_err() && !deferred {
                    crate::log::info("AI discovery deferred; visibility may be incomplete");
                }
                if outcome.is_ok() && deferred {
                    crate::log::info("AI discovery synchronized");
                }
                deferred = outcome.is_err();
                for _ in 0..5 {
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
        })?)
}

pub(crate) struct Acquisition<'a> {
    pub policy: &'a Policy,
    pub home: &'a Path,
    pub device_id: &'a str,
    pub sequence: u64,
    pub cache: &'a mut Cache,
    pub stop: &'a AtomicBool,
    pub observer: &'a mut Option<crate::discovery_network::Observer>,
}

pub(crate) fn acquire_for_worker(
    context: Acquisition<'_>,
    persist_guest_failures: &mut dyn FnMut(&[String]) -> Result<()>,
) -> Result<Option<Collected>> {
    #[cfg(target_os = "linux")]
    let system_failed = if unsafe { libc::geteuid() } != 0 {
        match system_request(context.policy, Some(context.sequence)).and_then(|mut response| {
            system_snapshot(context.policy, context.sequence, &mut response)
        }) {
            Ok(snapshot) => return Ok(snapshot),
            Err(_) => true,
        }
    } else {
        false
    };
    #[cfg(windows)]
    let system_failed = match system_request(context.policy, Some(context.sequence))
        .and_then(|mut response| system_snapshot(context.policy, context.sequence, &mut response))
    {
        Ok(snapshot) => return Ok(snapshot),
        Err(_) => true,
    };
    #[cfg(not(any(windows, target_os = "linux")))]
    let system_failed = false;
    let mut snapshot = acquire(context, persist_guest_failures)?;
    if system_failed {
        collector::coverage(
            &mut snapshot,
            "system-collector",
            CoverageStatus::Unavailable,
            false,
        );
        snapshot.complete = false;
    }
    Ok(Some(snapshot))
}

// Shared by the ordinary worker and the isolated system collector. Its inputs
// select only fixed adapters; no catalogue or IPC field selects a program.
pub(crate) fn acquire(
    context: Acquisition<'_>,
    persist_guest_failures: &mut dyn FnMut(&[String]) -> Result<()>,
) -> Result<Collected> {
    let Acquisition {
        policy,
        home,
        device_id,
        sequence,
        cache,
        stop,
        observer,
    } = context;
    if stop.load(Ordering::Acquire) || policy.expires_at <= Utc::now() {
        return Err("discovery collection cancelled".into());
    }
    let mut snapshot = Collected(collector::empty(
        "endpoint",
        sequence,
        Utc::now().timestamp(),
    ));
    snapshot.entities.push(milvago_discovery_engine::Entity {
        display: None,
        id: collector::identity("host", &["endpoint"]),
        kind: milvago_discovery_engine::EntityKind::Host,
    });
    let mut targets = vec![];
    let mut allowed = vec![];
    let mut vm_probes = vec![];
    // Per-source quotas leave time for later sources; the parent also bounds
    // their combined wall time, including gaps between adapters.
    let available = (policy.expires_at - Utc::now())
        .to_std()
        .map_err(|_| "discovery authorization expired")?;
    let scan_budget = collector::Budget::new(available.min(Duration::from_secs(30)), stop);
    if policy.configuration.host {
        let budget = scan_budget.child(Duration::from_secs(3));
        for listener in collector::host::collect(&mut snapshot, &budget) {
            if !listener.address.ip().is_unspecified() && !allowed.contains(&listener.address.ip())
            {
                allowed.push(listener.address.ip());
            }
            let ip = if listener.address.ip().is_unspecified() {
                if listener.address.is_ipv4() {
                    IpAddr::V4(Ipv4Addr::LOCALHOST)
                } else {
                    IpAddr::V6(Ipv6Addr::LOCALHOST)
                }
            } else {
                listener.address.ip()
            };
            targets.push(collector::http::Target {
                address: SocketAddr::new(ip, listener.address.port()),
                origin: listener.owner,
                published: false,
            });
        }
        #[cfg(windows)]
        {
            let budget = scan_budget.child(Duration::from_secs(2));
            collector::system::process_entries(
                &mut snapshot,
                &crate::discovery_system::NativeReader,
                &budget,
            );
        }
        let budget = scan_budget.child(Duration::from_secs(1));
        collector::installation::collect(&mut snapshot, &budget);
    } else {
        collector::coverage(&mut snapshot, "host", CoverageStatus::Disabled, false);
        collector::coverage(
            &mut snapshot,
            "installed-packages",
            CoverageStatus::Disabled,
            false,
        );
    }
    if policy.configuration.containers {
        let budget = scan_budget.child(Duration::from_secs(5));
        let mut engines = collector::docker::local_engines();
        crate::discovery_runtime_channels::extend(&mut snapshot, home, device_id, &mut engines);
        for port in collector::docker::collect_with_cursor(
            &mut snapshot,
            &engines,
            &budget,
            &mut cache.docker_cursor,
        ) {
            let ip = if port.address.ip().is_unspecified() {
                if port.address.is_ipv4() {
                    IpAddr::V4(Ipv4Addr::LOCALHOST)
                } else {
                    IpAddr::V6(Ipv6Addr::LOCALHOST)
                }
            } else {
                port.address.ip()
            };
            targets.push(collector::http::Target {
                address: SocketAddr::new(ip, port.address.port()),
                origin: Some(port.entity_id),
                published: true,
            });
        }
        let budget = scan_budget.child(Duration::from_secs(2));
        for listener in collector::containerd::collect(&mut snapshot, &budget) {
            let ip = if listener.address.ip().is_unspecified() {
                if listener.address.is_ipv4() {
                    IpAddr::V4(Ipv4Addr::LOCALHOST)
                } else {
                    IpAddr::V6(Ipv6Addr::LOCALHOST)
                }
            } else {
                listener.address.ip()
            };
            if !allowed.contains(&ip) {
                allowed.push(ip);
            }
            targets.push(collector::http::Target {
                address: SocketAddr::new(ip, listener.address.port()),
                origin: listener.owner,
                published: false,
            });
        }
    } else {
        collector::coverage(&mut snapshot, "containers", CoverageStatus::Disabled, false);
    }
    // Unsupported channels remain visible; they must never manufacture an empty successful inventory.
    let mut running_guests = std::collections::BTreeSet::new();
    if policy.configuration.virtual_machines {
        let budget = scan_budget.child(Duration::from_secs(4));
        let machines = collector::system::virtual_machines(
            &mut snapshot,
            &crate::discovery_system::NativeReader,
            &budget,
        );
        running_guests.extend(machines.iter().map(|machine| machine.entity.clone()));
        if policy.configuration.http {
            let mut guests: Vec<_> = machines
                .iter()
                .filter(|m| matches!(m.hypervisor, collector::vm::Hypervisor::Libvirt))
                .cloned()
                .collect();
            guests.sort_by(|a, b| a.uuid.cmp(&b.uuid));
            if !guests.is_empty() {
                let length = guests.len();
                guests.rotate_left(cache.vm_http_cursor % length);
                cache.vm_http_cursor = cache.vm_http_cursor.wrapping_add(16.min(length));
            }
            vm_probes = collector::vm_http::collect(
                &mut snapshot,
                &guests,
                &crate::discovery_system::NativeReader,
                &policy.catalog.http_ports,
                &scan_budget.child(Duration::from_secs(3)),
            );
            for probe in &vm_probes {
                if !allowed.contains(&probe.target.address.ip()) {
                    allowed.push(probe.target.address.ip());
                }
                targets.push(probe.target.clone());
            }
        }
        if policy.configuration.network {
            if let Some(observer) = observer.as_ref() {
                observer.machines(machines);
                observer.refresh_interfaces(&crate::discovery_system::NativeReader, &budget);
            }
        }
    }
    if policy.configuration.guest_read {
        let budget = scan_budget.child(Duration::from_secs(5));
        crate::discovery_guests::collect(
            &mut snapshot,
            home,
            device_id,
            collector::guest::Access {
                read: policy.configuration.guest_read,
                execute: policy.configuration.guest_execute,
            },
            &mut cache.guest_failures,
            &budget,
            &running_guests,
        );
        // Persist failed access attempts before cancellation/evaluation can
        // discard this scan; repeated runs must not lock guest accounts.
        persist_guest_failures(&cache.guest_failures)?;
    }
    if policy.configuration.network {
        snapshot.observed_at = Utc::now().timestamp();
        if let Some(observer) = observer.as_ref() {
            observer.drain(&mut snapshot);
        } else {
            collector::coverage(&mut snapshot, "network", CoverageStatus::Unavailable, false);
        }
    } else {
        collector::coverage(&mut snapshot, "network", CoverageStatus::Disabled, false);
    }
    if policy.configuration.http {
        targets = endpoint_targets(&mut snapshot, targets);
        if !targets.is_empty() {
            let length = targets.len();
            targets.rotate_left(cache.http_cursor % length);
        }
        let budget = scan_budget.child(Duration::from_secs(5));
        let (consumed, connections) = collector::http::collect_paths_with_connections(
            &mut snapshot,
            &targets,
            &allowed,
            &policy.catalog.http_paths,
            &budget,
        );
        collector::vm_http::attribute(&mut snapshot, &vm_probes, &connections, &scan_budget);
        cache.http_cursor = cache.http_cursor.wrapping_add(consumed.max(1));
    } else {
        collector::coverage(&mut snapshot, "http", CoverageStatus::Disabled, false);
    }
    snapshot.observed_at = Utc::now().timestamp();
    snapshot.complete = snapshot
        .coverage
        .iter()
        .filter(|c| c.status != CoverageStatus::Disabled)
        .all(|c| c.complete);
    if stop.load(Ordering::Acquire) || policy.expires_at <= Utc::now() {
        return Err("discovery collection cancelled".into());
    }
    Ok(snapshot)
}

fn pass(
    home: &Path,
    stop: &AtomicBool,
    cached: &mut Option<Policy>,
    refresh: bool,
    observer: &mut Option<crate::discovery_network::Observer>,
    system_active: &mut bool,
) -> Result<()> {
    let initial = {
        let store = Store::open(home)?;
        let mut state = store.load()?;
        if expire_pending(&mut state.discovery, Utc::now().timestamp()) {
            store.save(&state)?;
        }
        identity(state)
    };
    if initial.credential.is_empty() {
        *system_active = false;
        *observer = None;
        *cached = None;
        #[cfg(any(windows, target_os = "linux"))]
        withdraw_system();
        return Ok(());
    }
    if cached.as_ref().is_none_or(|p| {
        p.identity_binding != policy_binding(&initial)
            || !p.configuration.network
            || p.expires_at <= Utc::now()
    }) {
        *observer = None;
    }
    if refresh {
        let response = crate::client()?
            .get(crate::api_url(&initial, "/v1/discovery/policy")?)
            .bearer_auth(&initial.credential)
            .timeout(Duration::from_secs(3))
            .send()?;
        if matches!(response.status().as_u16(), 401 | 403 | 404 | 405) {
            *cached = None;
            let store = Store::open(home)?;
            let mut current = store.load()?;
            if same(&current, &initial) {
                current.discovery.pending.clear();
                store.save(&current)?;
            }
            return Ok(());
        }
        let response = response.error_for_status()?;
        let mut bytes = vec![];
        response.take(256 * 1024 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > 256 * 1024 {
            *cached = None;
            return Err("discovery response exceeds its limit".into());
        }
        let envelope: Envelope = serde_json::from_slice(&bytes)?;
        let policy = match verify(&envelope, &initial, Utc::now()) {
            Ok(p) => p,
            Err(error) => {
                *cached = None;
                return Err(error);
            }
        };
        let store = Store::open(home)?;
        let mut current = store.load()?;
        if !same(&current, &initial) {
            *cached = None;
            return Err("discovery identity changed".into());
        }
        if policy.revision != current.discovery.settings_revision
            || policy.catalog.revision != current.discovery.catalog_revision
            || !policy.configuration.active()
        {
            current.discovery.pending.clear();
            current.discovery.last_collected = None;
            current.discovery.report_retry_after = None;
        }
        current.discovery.settings_revision = policy.revision;
        current.discovery.catalog_revision = policy.catalog.revision;
        store.save(&current)?;
        *cached = Some(policy);
        drop(store);
        #[cfg(target_os = "linux")]
        if uses_system_collector() {
            // Refresh also conveys signed source revocations. The helper verifies
            // the envelope independently against its administrator-owned anchor.
            if let Some(policy) = cached.as_ref() {
                let _ = system_request(policy, None);
            }
        }
        #[cfg(windows)]
        {
            // Close the fallback observer before the root component acquires its
            // metadata session. Older installations retain ordinary discovery.
            *observer = None;
            *system_active = cached.as_ref().is_some_and(|policy| {
                system_request(policy, None).is_ok_and(|response| {
                    response.revision == policy.revision
                        && response.catalog_revision == policy.catalog.revision
                        && matches!(response.status.as_str(), "waiting" | "disabled")
                })
            });
        }
    }
    if cached
        .as_ref()
        .is_some_and(|p| p.identity_binding != policy_binding(&initial))
    {
        *cached = None;
        let store = Store::open(home)?;
        let mut current = store.load()?;
        current.discovery.pending.clear();
        store.save(&current)?;
    }
    let Some(policy) = cached
        .as_ref()
        .filter(|p| p.expires_at > Utc::now() && p.configuration.active())
    else {
        if cached.as_ref().is_some_and(|p| p.expires_at <= Utc::now()) {
            *cached = None;
        }
        return Ok(());
    };
    let mut current = { Store::open(home)?.load()? };
    if !same(&current, &initial)
        || current.discovery.settings_revision != policy.revision
        || current.discovery.catalog_revision != policy.catalog.revision
    {
        return Err("discovery identity changed".into());
    }
    let local = {
        #[cfg(target_os = "linux")]
        {
            (unsafe { libc::geteuid() }) == 0
        }
        #[cfg(not(target_os = "linux"))]
        {
            !*system_active
        }
    };
    if local && policy.configuration.network {
        if !observer.as_ref().is_some_and(|o| {
            o.authorize(
                &policy.catalog,
                policy.revision,
                policy.expires_at.timestamp(),
            )
        }) {
            *observer = None;
            *observer = Some(crate::discovery_network::Observer::start(
                &policy.catalog,
                policy.revision,
                policy.expires_at.timestamp(),
            )?);
        }
    } else {
        *observer = None;
    }
    if policy.configuration.virtual_machines && policy.configuration.network {
        if let Some(observer) = observer.as_ref() {
            observer.refresh_interfaces(
                &crate::discovery_system::NativeReader,
                &collector::Budget::new(Duration::from_secs(2), stop),
            );
        }
    }
    if current.discovery.pending.len() > 256
        || crate::shadow::serialized_size(&current.discovery.pending)? > QUEUE_BYTES
    {
        return Err("discovery queue exceeds its limit".into());
    }
    if !delivery_ready(&current.discovery, Utc::now()) {
        return Ok(());
    }
    let has_run = policy
        .runs
        .iter()
        .any(|run| !current.discovery.completed_runs.contains(run));
    let due = current.discovery.last_collected.is_none_or(|last| {
        Utc::now() < last
            || Utc::now().signed_duration_since(last).num_seconds()
                >= policy.configuration.interval_seconds as i64
    });
    if current.discovery.pending.is_empty() && (due || has_run) && !stop.load(Ordering::Acquire) {
        let sequence = current
            .discovery
            .sequence
            .checked_add(1)
            .ok_or("discovery sequence exhausted")?
            .max(Utc::now().timestamp_millis().max(1) as u64);
        if sequence > i64::MAX as u64 {
            return Err("discovery sequence exhausted".into());
        }
        {
            let store = Store::open(home)?;
            let mut checked = store.load()?;
            if !same(&checked, &initial) {
                return Err("discovery identity changed".into());
            }
            checked.discovery.sequence = sequence;
            store.save(&checked)?;
        }
        let mut persist_guest_failures = |failures: &[String]| -> Result<()> {
            let store = Store::open(home)?;
            let mut checked = store.load()?;
            if !same(&checked, &initial) {
                return Err("discovery identity changed".into());
            }
            checked.discovery.guest_failures = failures.to_vec();
            store.save(&checked)
        };
        let Some(mut snapshot) = acquire_for_worker(
            Acquisition {
                policy,
                home,
                device_id: &initial.device_id,
                sequence,
                cache: &mut current.discovery,
                stop,
                observer,
            },
            &mut persist_guest_failures,
        )?
        else {
            return Ok(());
        };
        let deadline = Instant::now() + Duration::from_secs(2);
        let evaluation = Engine::compile(&policy.catalog)?.evaluate_with_cancel(&snapshot, || {
            stop.load(Ordering::Acquire) || Instant::now() >= deadline
        });
        for fact in &mut snapshot.facts {
            for values in fact.fields.values_mut() {
                for value in values {
                    zeroize::Zeroize::zeroize(value);
                }
            }
        }
        let result = match evaluation {
            Ok(result) => result,
            Err(_) => {
                snapshot.entities.clear();
                snapshot.facts.clear();
                snapshot.relations.clear();
                snapshot.complete = false;
                collector::coverage(
                    &mut snapshot,
                    "detection-engine",
                    CoverageStatus::Saturated,
                    false,
                );
                milvago_discovery_engine::Evaluation {
                    identifications: vec![],
                    communications: vec![],
                    queries: vec![],
                    evaluated_facts: 0,
                    unknown_conditions: 0,
                    saturated: false,
                }
            }
        };
        let mut pages = delivery_pages(
            &mut snapshot,
            &result,
            policy.catalog.revision,
            policy.revision,
        )?;
        for page in &mut pages {
            page.run_id = policy
                .runs
                .iter()
                .find(|run| !current.discovery.completed_runs.contains(run))
                .cloned();
            report::validate(page, &policy.catalog)?;
            if crate::shadow::serialized_size(page)? > 128 * 1024 {
                return Err("discovery report exceeds its limit".into());
            }
        }
        if crate::shadow::serialized_size(&pages)? > QUEUE_BYTES {
            return Err("discovery queue is full".into());
        }
        let store = Store::open(home)?;
        let mut checked = store.load()?;
        if !same(&checked, &initial) || checked.discovery.settings_revision != policy.revision {
            return Err("discovery authorization changed".into());
        }
        checked.discovery.pending = pages;
        checked.discovery.last_collected = Some(Utc::now());
        checked.discovery.http_cursor = current.discovery.http_cursor;
        checked.discovery.vm_http_cursor = current.discovery.vm_http_cursor;
        checked.discovery.guest_failures = current.discovery.guest_failures;
        checked.discovery.docker_cursor = current.discovery.docker_cursor;
        store.save(&checked)?;
    }
    for _ in 0..16 {
        if stop.load(Ordering::Acquire) || policy.expires_at <= Utc::now() {
            break;
        }
        let state = { Store::open(home)?.load()? };
        if !same(&state, &initial) {
            return Err("discovery identity changed".into());
        }
        let Some(page) = state.discovery.pending.first() else {
            break;
        };
        let response = crate::client()?
            .post(crate::api_url(&state, "/v1/discovery/reports")?)
            .bearer_auth(&state.credential)
            .json(page)
            .timeout(Duration::from_secs(3))
            .send()?;
        if matches!(response.status().as_u16(), 400 | 401 | 403 | 409 | 413) {
            let status = response.status().as_u16();
            let mut bytes = vec![];
            response.take(2049).read_to_end(&mut bytes)?;
            let capacity = status == 409
                && bytes.len() <= 2048
                && serde_json::from_slice::<serde_json::Value>(&bytes)
                    .ok()
                    .is_some_and(|value| {
                        value.get("error").and_then(serde_json::Value::as_str)
                            == Some("discovery_capacity")
                    });
            let store = Store::open(home)?;
            let mut checked = store.load()?;
            if same(&checked, &state) {
                if capacity {
                    defer_capacity(&mut checked.discovery, Utc::now());
                } else {
                    checked.discovery.pending.clear();
                    checked.discovery.last_collected = None;
                    checked.discovery.report_retry_after = None;
                }
                store.save(&checked)?;
            }
            if !capacity {
                *cached = None;
            }
            return Err("discovery report rejected".into());
        }
        response.error_for_status()?;
        let store = Store::open(home)?;
        let mut checked = store.load()?;
        if same(&checked, &state)
            && checked
                .discovery
                .pending
                .first()
                .is_some_and(|p| p.sequence == page.sequence && p.page == page.page)
        {
            checked.discovery.pending.remove(0);
            checked.discovery.report_retry_after = None;
            if checked.discovery.pending.is_empty() {
                if let Some(run) = &page.run_id {
                    if !checked.discovery.completed_runs.contains(run) {
                        checked.discovery.completed_runs.push(run.clone());
                        if checked.discovery.completed_runs.len() > 16 {
                            checked.discovery.completed_runs.remove(0);
                        }
                    }
                }
            }
            store.save(&checked)?;
        }
    }
    Ok(())
}

fn expire_pending(cache: &mut Cache, now: i64) -> bool {
    if cache.pending.iter().any(|page| {
        page.observed_at > now.saturating_add(60)
            || now.saturating_sub(page.observed_at) > 48 * 60 * 60
    }) {
        cache.pending.clear();
        cache.last_collected = None;
        cache.report_retry_after = None;
        return true;
    }
    false
}

fn defer_capacity(cache: &mut Cache, now: DateTime<Utc>) {
    cache.report_retry_after = Some(now + chrono::Duration::seconds(60));
}
fn delivery_ready(cache: &Cache, now: DateTime<Utc>) -> bool {
    cache
        .report_retry_after
        .is_none_or(|until| until <= now || until.signed_duration_since(now).num_seconds() > 60)
}

fn delivery_pages(
    snapshot: &mut milvago_discovery_engine::Snapshot,
    result: &milvago_discovery_engine::Evaluation,
    catalog: u64,
    settings: u64,
) -> Result<Vec<Report>> {
    let pages = report::pages(snapshot, result, catalog, settings).and_then(|pages| {
        let size = crate::shadow::serialized_size(&pages)
            .map_err(|_| "Cannot size discovery report".to_string())?;
        if size.saturating_add(pages.len() * 128) > QUEUE_BYTES {
            return Err("Discovery delivery capacity reached".into());
        }
        Ok(pages)
    });
    match pages {
        Ok(pages) => Ok(pages),
        Err(_) => {
            // A single oversized observation or malformed source must not produce
            // a retry loop which continues to advertise old, apparently healthy visibility.
            snapshot.entities.clear();
            snapshot.facts.clear();
            snapshot.relations.clear();
            snapshot.coverage.clear();
            snapshot.complete = false;
            collector::coverage(
                snapshot,
                "report-delivery",
                CoverageStatus::Saturated,
                false,
            );
            report::pages(
                snapshot,
                &milvago_discovery_engine::Evaluation {
                    identifications: vec![],
                    communications: vec![],
                    queries: vec![],
                    evaluated_facts: 0,
                    unknown_conditions: 0,
                    saturated: false,
                },
                catalog,
                settings,
            )
            .map_err(Into::into)
        }
    }
}

fn endpoint_targets(
    snapshot: &mut milvago_discovery_engine::Snapshot,
    targets: Vec<collector::http::Target>,
) -> Vec<collector::http::Target> {
    use std::collections::{BTreeMap, BTreeSet};
    let mut groups: BTreeMap<SocketAddr, Vec<collector::http::Target>> = BTreeMap::new();
    for target in targets {
        groups.entry(target.address).or_default().push(target);
    }
    let mut ambiguous = false;
    let output = groups
        .into_iter()
        .map(|(address, group)| {
            let published: BTreeSet<_> = group
                .iter()
                .filter(|t| t.published)
                .filter_map(|t| t.origin.clone())
                .collect();
            let owners: BTreeSet<_> = group.iter().filter_map(|t| t.origin.clone()).collect();
            let (origin, published) = if published.len() == 1 {
                (published.into_iter().next(), true)
            } else if published.len() > 1 {
                ambiguous = true;
                (None, false)
            } else if owners.len() <= 1 {
                (owners.into_iter().next(), false)
            } else {
                ambiguous = true;
                (None, false)
            };
            collector::http::Target {
                address,
                origin,
                published,
            }
        })
        .collect();
    if ambiguous {
        collector::coverage(
            snapshot,
            "endpoint-attribution",
            CoverageStatus::Partial,
            false,
        );
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    fn fixture() -> (State, serde_json::Value, SigningKey) {
        let key = SigningKey::from_bytes(&[37; 32]);
        let state = State {
            device_id: "fixture-device".into(),
            public_key: STANDARD.encode(key.verifying_key().to_bytes()),
            ..Default::default()
        };
        let now = Utc::now();
        let catalog: Catalog =
            serde_json::from_slice(include_bytes!("../discovery-engine/catalog/factory.json"))
                .unwrap();
        let value = serde_json::json!({"kind":"discovery_policy","version":1,"device_id":"fixture-device","revision":7,"issued_at":now,"expires_at":now+chrono::Duration::minutes(10),"configuration":{"host":true,"containers":false,"virtual_machines":false,"guest_read":false,"guest_execute":false,"http":false,"network":false,"interval_seconds":300},"catalog":catalog,"runs":[]});
        (state, value, key)
    }
    fn envelope(value: &serde_json::Value, key: &SigningKey) -> Envelope {
        let bytes = serde_json::to_vec(value).unwrap();
        Envelope {
            payload: STANDARD.encode(&bytes),
            signature: STANDARD.encode(key.sign(&bytes).to_bytes()),
        }
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn system_responses_require_current_sequence_catalog_and_every_source_consent() {
        use crate::discovery_privileged::service::Response;
        use milvago_discovery_engine::{Entity, EntityKind, Source};
        let (state, value, key) = fixture();
        let mut policy = verify(&envelope(&value, &key), &state, Utc::now()).unwrap();
        let response = |source, kind| {
            let mut snapshot = collector::empty("endpoint", 42, Utc::now().timestamp());
            snapshot.entities.push(Entity {
                id: "entity".into(),
                kind,
                display: None,
            });
            collector::fact(&mut snapshot, "entity", source, Default::default());
            Response {
                version: 1,
                revision: 7,
                catalog_revision: policy.catalog.revision,
                status: "collected".into(),
                retry_after: 0,
                snapshot: Some(snapshot),
            }
        };
        for (source, kind) in [
            (Source::Installation, EntityKind::Host),
            (Source::HostProcess, EntityKind::Process),
            (Source::GuestProcess, EntityKind::Process),
            (Source::ContainerProcess, EntityKind::Process),
            (Source::ContainerMetadata, EntityKind::Container),
            (Source::Http, EntityKind::Endpoint),
            (Source::HostFlow, EntityKind::Host),
            (Source::VmFlow, EntityKind::Vm),
            (Source::RuntimeFlow, EntityKind::Runtime),
            (Source::ContainerFlow, EntityKind::Container),
        ] {
            let mut supplied = response(source, kind);
            let expected = matches!(source, Source::HostProcess | Source::Installation);
            assert_eq!(
                system_snapshot(&policy, 42, &mut supplied).is_ok(),
                expected,
                "{source:?}"
            );
            assert!(supplied.snapshot.is_none());
        }
        for invalid in 0..6 {
            let mut supplied = response(Source::HostProcess, EntityKind::Process);
            match invalid {
                0 => supplied.revision += 1,
                1 => supplied.catalog_revision += 1,
                2 => supplied.snapshot.as_mut().unwrap().sequence += 1,
                3 => supplied.snapshot.as_mut().unwrap().scope = "other".into(),
                4 => supplied.snapshot.as_mut().unwrap().observed_at -= 61,
                _ => supplied.status = "unavailable".into(),
            }
            assert!(system_snapshot(&policy, 42, &mut supplied).is_err());
        }
        let mut waiting = Response {
            version: 1,
            revision: 7,
            catalog_revision: policy.catalog.revision,
            status: "waiting".into(),
            retry_after: 30,
            snapshot: None,
        };
        assert!(
            system_snapshot(&policy, 42, &mut waiting)
                .unwrap()
                .is_none()
        );
        policy.configuration.host = false;
        // All source switches are now off; a privileged sender cannot override them.
        let mut supplied = response(Source::HostProcess, EntityKind::Process);
        assert!(system_snapshot(&policy, 42, &mut supplied).is_err());
    }
    #[test]
    fn shared_acquisition_honors_disabled_sources_expiry_and_cancellation() {
        let (state, mut value, key) = fixture();
        value["configuration"]["host"] = false.into();
        let mut policy = verify(&envelope(&value, &key), &state, Utc::now()).unwrap();
        let home = tempfile::tempdir().unwrap();
        let mut cache = Cache::default();
        let mut observer = None;
        let stop = AtomicBool::new(false);
        let mut persist = |_: &[String]| -> Result<()> {
            panic!("disabled guest source attempted to access credentials")
        };
        let snapshot = acquire(
            Acquisition {
                policy: &policy,
                home: home.path(),
                device_id: &state.device_id,
                sequence: 1,
                cache: &mut cache,
                stop: &stop,
                observer: &mut observer,
            },
            &mut persist,
        )
        .unwrap();
        assert!(snapshot.facts.is_empty());
        assert!(snapshot.relations.is_empty());
        assert!(
            snapshot
                .coverage
                .iter()
                .all(|c| c.status == CoverageStatus::Disabled)
        );
        drop(snapshot);
        stop.store(true, Ordering::Release);
        assert!(
            acquire(
                Acquisition {
                    policy: &policy,
                    home: home.path(),
                    device_id: &state.device_id,
                    sequence: 2,
                    cache: &mut cache,
                    stop: &stop,
                    observer: &mut observer
                },
                &mut persist
            )
            .is_err()
        );
        stop.store(false, Ordering::Release);
        policy.expires_at = Utc::now() - chrono::Duration::seconds(1);
        assert!(
            acquire(
                Acquisition {
                    policy: &policy,
                    home: home.path(),
                    device_id: &state.device_id,
                    sequence: 3,
                    cache: &mut cache,
                    stop: &stop,
                    observer: &mut observer
                },
                &mut persist
            )
            .is_err()
        );
    }
    #[test]
    fn signed_discovery_policy_binds_device_expiry_and_revision() {
        let (mut state, value, key) = fixture();
        let signed = envelope(&value, &key);
        let verified = verify(&signed, &state, Utc::now()).unwrap();
        assert!(verified.configuration.host);
        assert_eq!(verified.revision, 7);
        state.device_id = "other-device".into();
        assert!(verify(&signed, &state, Utc::now()).is_err());
        state.device_id = "fixture-device".into();
        state.discovery.settings_revision = 8;
        assert!(verify(&signed, &state, Utc::now()).is_err());
        state.discovery.settings_revision = 0;
        state.discovery.catalog_revision = 2;
        assert!(verify(&signed, &state, Utc::now()).is_err());
        state.discovery.catalog_revision = 0;
        assert!(verify(&signed, &state, Utc::now() + chrono::Duration::minutes(11)).is_err());
        let mut bad = value.clone();
        bad["configuration"]["guest_execute"] = true.into();
        assert!(verify(&envelope(&bad, &key), &state, Utc::now()).is_err());
        let wrong = SigningKey::from_bytes(&[38; 32]);
        assert!(verify(&envelope(&value, &wrong), &state, Utc::now()).is_err());
    }
    #[test]
    fn signed_policy_rejects_unknown_fields_images_and_future_schema() {
        let (state, value, key) = fixture();
        for (field, data) in [
            ("version", serde_json::json!(99)),
            ("configuration", serde_json::json!("data:image/png")),
            ("exec", serde_json::json!("arbitrary-script")),
        ] {
            let mut bad = value.clone();
            bad[field] = data;
            assert!(verify(&envelope(&bad, &key), &state, Utc::now()).is_err());
        }
    }
    #[test]
    fn synchronization_identity_checks_include_revocation_generation() {
        let (state, _, _) = fixture();
        let mut other = State {
            device_id: state.device_id.clone(),
            public_key: state.public_key.clone(),
            ..Default::default()
        };
        assert!(same(&state, &other));
        other.authorization_generation = 1;
        assert!(!same(&state, &other));
        other.authorization_generation = 0;
        other.credential = "other-credential".into();
        assert!(!same(&state, &other));
    }

    #[test]
    fn cached_authorization_binds_every_enrollment_identity_component() {
        let (state, value, key) = fixture();
        let policy = verify(&envelope(&value, &key), &state, Utc::now()).unwrap();
        assert_eq!(policy.identity_binding, policy_binding(&state));
        for field in ["device", "server", "trust", "credential", "generation"] {
            let (mut changed, _, _) = fixture();
            changed.public_key = state.public_key.clone();
            match field {
                "device" => changed.device_id = "different".into(),
                "server" => changed.server_url = "https://other.example.test".into(),
                "trust" => changed.public_key = "different".into(),
                "credential" => changed.credential = "different".into(),
                _ => changed.authorization_generation = 1,
            }
            assert_ne!(
                policy.identity_binding,
                policy_binding(&changed),
                "reused {field}"
            );
        }
    }

    #[test]
    fn endpoint_candidates_use_proven_publishing_and_do_not_guess_ambiguous_owners() {
        let target = |owner: &str, published: bool| collector::http::Target {
            address: "127.0.0.1:32145".parse().unwrap(),
            origin: Some(owner.into()),
            published,
        };
        let mut snapshot = collector::empty("endpoint", 1, 100);
        let rows = endpoint_targets(
            &mut snapshot,
            vec![target("proxy", false), target("container", true)],
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].origin.as_deref(), Some("container"));
        assert!(rows[0].published);
        let rows = endpoint_targets(
            &mut snapshot,
            vec![target("one", false), target("two", false)],
        );
        assert!(rows[0].origin.is_none());
        assert_eq!(snapshot.coverage[0].status, CoverageStatus::Partial);
        let rows = endpoint_targets(
            &mut snapshot,
            vec![target("container-one", true), target("container-two", true)],
        );
        assert!(rows[0].origin.is_none());
    }

    #[test]
    fn encrypted_pending_batch_expires_atomically_at_server_retention_boundary() {
        let snapshot = collector::empty("endpoint", 1, 100);
        let result = milvago_discovery_engine::Evaluation {
            identifications: vec![],
            communications: vec![],
            queries: vec![],
            evaluated_facts: 0,
            unknown_conditions: 0,
            saturated: false,
        };
        let mut cache = Cache {
            pending: report::pages(&snapshot, &result, 1, 1).unwrap(),
            last_collected: Some(Utc::now()),
            ..Default::default()
        };
        assert!(!expire_pending(&mut cache, 100 + 48 * 3600));
        assert!(!cache.pending.is_empty());
        assert!(expire_pending(&mut cache, 101 + 48 * 3600));
        assert!(cache.pending.is_empty());
        assert!(cache.last_collected.is_none());
        cache.pending = report::pages(&snapshot, &result, 1, 1).unwrap();
        assert!(expire_pending(&mut cache, 0));
    }

    #[test]
    fn capacity_backoff_keeps_unacknowledged_pages_and_is_bounded_after_clock_changes() {
        let now = Utc::now();
        let snapshot = collector::empty("endpoint", 1, now.timestamp());
        let result = milvago_discovery_engine::Evaluation {
            identifications: vec![],
            communications: vec![],
            queries: vec![],
            evaluated_facts: 0,
            unknown_conditions: 0,
            saturated: false,
        };
        let mut cache = Cache {
            pending: report::pages(&snapshot, &result, 1, 1).unwrap(),
            ..Default::default()
        };
        defer_capacity(&mut cache, now);
        assert_eq!(cache.pending.len(), 1);
        assert!(!delivery_ready(&cache, now));
        assert!(!delivery_ready(&cache, now + chrono::Duration::seconds(59)));
        assert!(delivery_ready(&cache, now + chrono::Duration::seconds(60)));
        assert!(delivery_ready(&cache, now - chrono::Duration::minutes(5)));
        assert!(expire_pending(&mut cache, now.timestamp() + 48 * 3600 + 1));
        assert!(cache.report_retry_after.is_none());
    }

    #[test]
    fn oversized_delivery_publishes_a_visibility_gap_instead_of_retrying_forever() {
        let mut snapshot = collector::empty("endpoint", 1, 100);
        snapshot.entities.push(milvago_discovery_engine::Entity {
            display: None,
            id: "process/one".into(),
            kind: milvago_discovery_engine::EntityKind::Endpoint,
        });
        for number in 0..300 {
            let id = format!("host/{number}");
            snapshot.entities.push(milvago_discovery_engine::Entity {
                display: None,
                id: id.clone(),
                kind: milvago_discovery_engine::EntityKind::Host,
            });
            snapshot.relations.push(milvago_discovery_engine::Relation {
                from: id,
                to: "process/one".into(),
                kind: milvago_discovery_engine::RelationKind::ObservedOrigin,
                source: "fixture".into(),
            });
        }
        collector::fact(
            &mut snapshot,
            "process/one",
            milvago_discovery_engine::Source::Http,
            std::collections::BTreeMap::from([(
                milvago_discovery_engine::Field::HttpBody,
                vec!["Ollama is running".into()],
            )]),
        );
        let catalog: Catalog =
            serde_json::from_slice(include_bytes!("../discovery-engine/catalog/factory.json"))
                .unwrap();
        let result = Engine::compile(&catalog)
            .unwrap()
            .evaluate(&snapshot)
            .unwrap();
        let pages = delivery_pages(&mut snapshot, &result, 1, 1).unwrap();
        assert_eq!(pages.len(), 1);
        assert!(pages[0].result.identifications.is_empty());
        assert_eq!(pages[0].coverage[0].status, CoverageStatus::Saturated);
        assert!(!pages[0].complete);
        report::validate(&pages[0], &catalog).unwrap();
    }
}
