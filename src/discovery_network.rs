//! Continuous, consent-bound observation of visible TLS destination metadata.
//! No packet or application payload is retained in the queue or agent state.
use milvago_discovery_collector::{
    self as collector,
    network::{Visibility, Witness},
};
use milvago_discovery_engine::{Catalog, CoverageStatus, Snapshot};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Clone)]
struct Authorization {
    epoch: u64,
    catalog_revision: u64,
    expires: i64,
    deadline: Instant,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    hosts: Arc<BTreeSet<String>>,
}
#[cfg(any(windows, test))]
#[path = "discovery_network_windows.rs"]
mod windows;

#[cfg(windows)]
pub(crate) fn cleanup_windows_session() {
    // Recovery is independent from policy activation: a previous service may
    // have crashed before a later administrator disabled discovery.
    let _ = windows::cleanup_stale();
}

struct State {
    #[cfg(any(windows, test))]
    dns: windows::DnsState,
    authorization: Authorization,
    observations: BTreeMap<(Origin, String, u16), i64>,
    status: CoverageStatus,
    saturated: bool,
    vm_status: CoverageStatus,
    machines: Vec<collector::system::Machine>,
    next_mapping_refresh: Instant,
    mapping_cursor: usize,
    #[cfg(target_os = "linux")]
    bindings: BTreeMap<i32, linux::Binding>,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
enum Origin {
    Host,
    Vm(String),
}
pub struct Observer {
    state: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}
fn now() -> i64 {
    chrono::Utc::now().timestamp()
}
impl Observer {
    pub fn start(catalog: &Catalog, epoch: u64, expires: i64) -> std::io::Result<Self> {
        let authorization = Authorization {
            epoch,
            catalog_revision: catalog.revision,
            expires,
            deadline: Instant::now()
                + Duration::from_secs(expires.saturating_sub(now()).clamp(0, 600) as u64),
            hosts: Arc::new(
                catalog
                    .providers
                    .iter()
                    .flat_map(|p| p.hosts.iter().cloned())
                    .collect(),
            ),
        };
        let state = Arc::new(Mutex::new(State {
            #[cfg(any(windows, test))]
            dns: windows::DnsState::default(),
            authorization,
            observations: BTreeMap::new(),
            status: CoverageStatus::Unavailable,
            saturated: false,
            vm_status: CoverageStatus::Unavailable,
            machines: vec![],
            next_mapping_refresh: Instant::now(),
            mapping_cursor: 0,
            #[cfg(target_os = "linux")]
            bindings: BTreeMap::new(),
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let shared = Arc::clone(&state);
        let stopped = Arc::clone(&stop);
        let thread = thread::Builder::new()
            .name("milvago-discovery-network".into())
            .spawn(move || observe(shared, stopped))?;
        Ok(Self {
            state,
            stop,
            thread: Some(thread),
        })
    }
    pub fn authorize(&self, catalog: &Catalog, epoch: u64, expires: i64) -> bool {
        if self
            .thread
            .as_ref()
            .is_none_or(thread::JoinHandle::is_finished)
        {
            return false;
        }
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        let hosts: BTreeSet<_> = catalog
            .providers
            .iter()
            .flat_map(|p| p.hosts.iter().cloned())
            .collect();
        if state.authorization.epoch != epoch
            || state.authorization.catalog_revision != catalog.revision
            || *state.authorization.hosts != hosts
            || expires > now()
                && (state.authorization.expires <= now()
                    || Instant::now() >= state.authorization.deadline)
        {
            // Revoke before the caller replaces the observer. A callback already
            // in flight must not extend collection under the previous catalogue.
            state.authorization.expires = now();
            state.authorization.deadline = Instant::now();
            state.observations.clear();
            #[cfg(any(windows, test))]
            {
                state.dns = windows::DnsState::default();
            }
            return false;
        }
        if state.authorization.expires != expires {
            state.authorization.deadline = Instant::now()
                + Duration::from_secs(expires.saturating_sub(now()).clamp(0, 600) as u64);
            state.authorization.expires = expires;
        }
        true
    }
    pub fn machines(&self, machines: Vec<collector::system::Machine>) {
        if let Ok(mut state) = self.state.lock() {
            state.machines = machines
                .into_iter()
                .filter(|m| matches!(m.hypervisor, collector::vm::Hypervisor::Libvirt))
                .take(100)
                .collect();
            state.next_mapping_refresh = Instant::now();
            #[cfg(target_os = "linux")]
            {
                let ids: BTreeSet<_> = state.machines.iter().map(|m| m.entity.clone()).collect();
                state
                    .bindings
                    .retain(|_, binding| ids.contains(&binding.interface.entity));
            }
        }
    }
    pub fn refresh_interfaces(
        &self,
        reader: &impl collector::system::Reader,
        budget: &collector::Budget<'_>,
    ) {
        let (machines, epoch) = {
            let Ok(mut state) = self.state.lock() else {
                return;
            };
            if Instant::now() < state.next_mapping_refresh
                || state.authorization.expires <= now()
                || Instant::now() >= state.authorization.deadline
            {
                return;
            }
            state.next_mapping_refresh = Instant::now() + Duration::from_secs(30);
            let mut machines = state.machines.clone();
            if !machines.is_empty() {
                let length = machines.len();
                machines.rotate_left(state.mapping_cursor % length);
                state.mapping_cursor = state.mapping_cursor.wrapping_add(16.min(length));
            }
            machines.truncate(16);
            (machines, state.authorization.epoch)
        };
        let interfaces = collector::vm_network::collect(&machines, reader, budget);
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if epoch != state.authorization.epoch
            || state.authorization.expires <= now()
            || Instant::now() >= state.authorization.deadline
        {
            return;
        }
        #[cfg(target_os = "linux")]
        {
            let ids: BTreeSet<_> = machines.iter().map(|m| &m.entity).collect();
            state
                .bindings
                .retain(|_, binding| !ids.contains(&binding.interface.entity) && binding.current());
            state.vm_status = CoverageStatus::Unavailable;
            if let Ok(interfaces) = interfaces {
                for interface in interfaces.into_iter().take(128) {
                    if let Some(binding) = linux::Binding::open(interface) {
                        let index = binding.index;
                        if state.bindings.len() >= 128 && !state.bindings.contains_key(&index) {
                            break;
                        }
                        if state.bindings.insert(index, binding).is_some() {
                            state.bindings.clear();
                            return;
                        }
                    }
                }
                if !state.bindings.is_empty() {
                    state.vm_status = CoverageStatus::Partial;
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = interfaces;
            state.vm_status = CoverageStatus::Unavailable;
        }
    }
    pub fn drain(&self, snapshot: &mut Snapshot) {
        let Ok(mut state) = self.state.lock() else {
            collector::coverage(snapshot, "network", CoverageStatus::Unavailable, false);
            return;
        };
        let status = if state.saturated {
            CoverageStatus::Saturated
        } else {
            state.status
        };
        let observations = std::mem::take(&mut state.observations);
        state.saturated = false;
        if state.authorization.expires <= now() || Instant::now() >= state.authorization.deadline {
            #[cfg(windows)]
            {
                state.dns = windows::DnsState::default();
                collector::coverage(snapshot, "windows-dns", CoverageStatus::Denied, false);
            }
            collector::coverage(snapshot, "network", CoverageStatus::Denied, false);
            return;
        }
        let host = collector::identity("host", &[&snapshot.scope]);
        let mut field_budget = collector::FieldBudget::new(snapshot);
        #[cfg(windows)]
        windows::drain(&mut state, snapshot, &host, &mut field_budget);
        for ((origin, hostname, port), observed_at) in observations {
            let (entity, visibility) = match origin {
                Origin::Host => (host.clone(), Visibility::Host),
                Origin::Vm(entity) => {
                    if !snapshot.entities.iter().any(|e| e.id == entity) {
                        if snapshot.entities.len() >= milvago_discovery_engine::MAX_ENTITIES
                            || snapshot.relations.len() >= milvago_discovery_engine::MAX_ENTITIES
                        {
                            state.saturated = true;
                            continue;
                        }
                        snapshot.entities.push(milvago_discovery_engine::Entity {
                            display: None,
                            id: entity.clone(),
                            kind: milvago_discovery_engine::EntityKind::Vm,
                        });
                        snapshot.relations.push(milvago_discovery_engine::Relation {
                            from: host.clone(),
                            to: entity.clone(),
                            kind: milvago_discovery_engine::RelationKind::Contains,
                            source: "libvirt-live-tap".into(),
                        });
                    }
                    (entity, Visibility::VmBeforeNat)
                }
            };
            if collector::network::add_with_budget(
                snapshot,
                Witness {
                    entity,
                    visibility,
                    remote_host: hostname,
                    port,
                    observed_at,
                    connection_observed: true,
                    hostname_bound_to_connection: true,
                },
                &mut field_budget,
            ) != Ok(true)
            {
                state.saturated = true;
            }
        }
        // ECH, QUIC, fragmentation and origins behind NAT remain unobserved.
        // Available packet access is not complete network/application visibility.
        collector::coverage(
            snapshot,
            "network",
            if state.saturated {
                CoverageStatus::Saturated
            } else {
                status
            },
            false,
        );
        collector::coverage(snapshot, "vm-network-attribution", state.vm_status, false);
    }
}
impl Drop for Observer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(windows)]
fn observe(state: Arc<Mutex<State>>, stop: Arc<AtomicBool>) {
    windows::observe(state, stop);
}

#[cfg(not(any(target_os = "linux", windows)))]
fn observe(state: Arc<Mutex<State>>, stop: Arc<AtomicBool>) {
    let _ = state;
    while !stop.load(Ordering::Acquire) {
        thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(target_os = "linux")]
#[path = "discovery_network_host.rs"]
mod host_witness;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    pub(super) use collector::vm_network::Guard as Binding;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    pub(super) fn origin(
        state: &mut State,
        index: i32,
        packet_type: u8,
        source_mac: &[u8],
    ) -> Option<Origin> {
        if packet_type == libc::PACKET_OUTGOING as u8 {
            // Packet direction alone includes forwarded and NAT traffic.
            return None;
        }
        if ![libc::PACKET_HOST as u8, libc::PACKET_OTHERHOST as u8].contains(&packet_type) {
            return None;
        }
        let binding = state.bindings.get(&index)?;
        if !binding.current() {
            state.bindings.remove(&index);
            state.vm_status = CoverageStatus::Partial;
            return None;
        }
        if source_mac != binding.interface.mac {
            return None;
        }
        Some(Origin::Vm(binding.interface.entity.clone()))
    }
    enum Line {
        Label(&'static str),
        Op(u16, u32),
        Jump(u32, &'static str, &'static str),
        Greater(u32, &'static str, &'static str),
        Goto(&'static str),
    }
    // Classic BPF accepts only an IP/TCP packet beginning with a ClientHello.
    // The kernel truncates it to 2 KiB before it reaches userspace.
    pub(super) fn filter() -> Vec<libc::sock_filter> {
        use Line::*;
        let lines = [
            Op(0x30, 0),
            Op(0x54, 0xf0),
            Jump(0x40, "v4", "version6"),
            Label("version6"),
            Jump(0x60, "v6", "drop"),
            Label("v4"),
            Op(0x30, 9),
            Jump(6, "fragment", "drop"),
            Label("fragment"),
            Op(0x28, 6),
            Op(0x54, 0x3fff),
            Jump(0, "v4offset", "drop"),
            Label("v4offset"),
            Op(0xb1, 0),
            Goto("tcp"),
            Label("v6"),
            Op(0x30, 6),
            Jump(6, "v6offset", "drop"),
            Label("v6offset"),
            Op(0x01, 40),
            Label("tcp"),
            Op(0x50, 12),
            Op(0x54, 0xf0),
            Op(0x74, 2),
            Op(0x0c, 0),
            Op(0x07, 0),
            Op(0x50, 0),
            Jump(22, "handshake", "drop"),
            Label("handshake"),
            Op(0x50, 5),
            Jump(1, "keep", "drop"),
            Label("keep"),
            // Return only the first TLS record, never a coalesced application
            // record which happens to share the same TCP packet.
            Op(0x48, 3),
            Op(0x04, 5),
            Op(0x0c, 0),
            Greater(2048, "cap", "metadata"),
            Label("metadata"),
            Op(0x16, 0),
            Label("cap"),
            Op(0x06, 2048),
            Label("drop"),
            Op(0x06, 0),
        ];
        let mut labels = BTreeMap::new();
        let mut index = 0;
        for line in &lines {
            if let Label(label) = line {
                labels.insert(*label, index);
            } else {
                index += 1;
            }
        }
        let mut output = vec![];
        for line in lines {
            let index = output.len();
            let offset = |name| labels[name] - index - 1;
            let (code, jt, jf, k) = match line {
                Label(_) => continue,
                Op(code, k) => (code, 0, 0, k),
                Jump(k, yes, no) => (0x15, offset(yes) as u8, offset(no) as u8, k),
                Greater(k, yes, no) => (0x25, offset(yes) as u8, offset(no) as u8, k),
                Goto(label) => (0x05, 0, 0, offset(label) as u32),
            };
            output.push(libc::sock_filter { code, jt, jf, k });
        }
        output
    }
    pub(super) fn socket() -> Result<OwnedFd, CoverageStatus> {
        // Protocol zero receives nothing until bind, after the filter is locked.
        let raw = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if raw < 0 {
            return Err(
                if matches!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EACCES | libc::EPERM)
                ) {
                    CoverageStatus::Denied
                } else {
                    CoverageStatus::Unavailable
                },
            );
        }
        let socket = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut code = filter();
        let program = libc::sock_fprog {
            len: code.len() as u16,
            filter: code.as_mut_ptr(),
        };
        let receive: i32 = 65536;
        let locked: i32 = 1;
        for (option, value, size) in [
            (
                libc::SO_RCVBUF,
                (&receive as *const i32).cast::<libc::c_void>(),
                std::mem::size_of_val(&receive),
            ),
            (
                libc::SO_ATTACH_FILTER,
                (&program as *const libc::sock_fprog).cast(),
                std::mem::size_of_val(&program),
            ),
            (
                libc::SO_LOCK_FILTER,
                (&locked as *const i32).cast(),
                std::mem::size_of_val(&locked),
            ),
        ] {
            if unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    option,
                    value,
                    size as libc::socklen_t,
                )
            } != 0
            {
                return Err(CoverageStatus::Unavailable);
            }
        }
        let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        address.sll_family = libc::AF_PACKET as u16;
        address.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        if unsafe {
            libc::bind(
                socket.as_raw_fd(),
                (&address as *const libc::sockaddr_ll).cast(),
                std::mem::size_of_val(&address) as libc::socklen_t,
            )
        } != 0
        {
            return Err(CoverageStatus::Unavailable);
        }
        Ok(socket)
    }
    pub(super) fn run(state: Arc<Mutex<State>>, stop: Arc<AtomicBool>) {
        let mut socket: Option<OwnedFd> = None;
        let mut retry = Instant::now();
        let mut window = Instant::now();
        let mut packets = 0;
        let mut buffer = [0u8; 2048];
        while !stop.load(Ordering::Acquire) {
            let authorization = match state.lock() {
                Ok(mut state) => {
                    if state.authorization.expires <= now()
                        || Instant::now() >= state.authorization.deadline
                    {
                        state.observations.clear();
                        state.bindings.clear();
                        socket = None;
                        state.status = CoverageStatus::Denied;
                    }
                    state.authorization.clone()
                }
                Err(_) => break,
            };
            if authorization.expires <= now() || Instant::now() >= authorization.deadline {
                thread::sleep(Duration::from_millis(50));
                continue;
            }
            if socket.is_none() {
                if Instant::now() < retry {
                    thread::sleep(Duration::from_millis(50));
                    continue;
                }
                match self::socket() {
                    Ok(fd) => {
                        socket = Some(fd);
                        if let Ok(mut state) = state.lock() {
                            state.status = CoverageStatus::Partial;
                        }
                    }
                    Err(status) => {
                        if let Ok(mut state) = state.lock() {
                            state.status = status;
                        }
                        retry = Instant::now() + Duration::from_secs(60);
                        continue;
                    }
                }
            }
            if window.elapsed() >= Duration::from_secs(1) {
                window = Instant::now();
                packets = 0;
                if let Some(fd) = &socket {
                    let mut statistics: libc::tpacket_stats = unsafe { std::mem::zeroed() };
                    let mut length = std::mem::size_of_val(&statistics) as libc::socklen_t;
                    if unsafe {
                        libc::getsockopt(
                            fd.as_raw_fd(),
                            libc::SOL_PACKET,
                            libc::PACKET_STATISTICS,
                            (&mut statistics as *mut libc::tpacket_stats).cast(),
                            &mut length,
                        )
                    } == 0
                        && statistics.tp_drops != 0
                    {
                        if let Ok(mut state) = state.lock() {
                            state.saturated = true;
                        }
                    }
                }
                if let Ok(mut state) = state.lock() {
                    state
                        .bindings
                        .retain(|_, binding| Instant::now() < binding.deadline);
                }
            }
            if packets >= 256 {
                if let Ok(mut state) = state.lock() {
                    state.saturated = true;
                }
                thread::sleep(Duration::from_millis(50));
                continue;
            }
            let Some(fd) = &socket else {
                continue;
            };
            let mut poll = libc::pollfd {
                fd: fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let ready = unsafe { libc::poll(&mut poll, 1, 50) };
            if ready < 0 {
                if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                    socket = None;
                    retry = Instant::now() + Duration::from_secs(1);
                }
                continue;
            }
            if ready == 0 {
                continue;
            }
            if poll.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                socket = None;
                retry = Instant::now() + Duration::from_secs(1);
                if let Ok(mut state) = state.lock() {
                    state.status = CoverageStatus::Unavailable;
                }
                continue;
            }
            let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            let mut length = std::mem::size_of_val(&address) as libc::socklen_t;
            let received = unsafe {
                libc::recvfrom(
                    fd.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    0,
                    (&mut address as *mut libc::sockaddr_ll).cast(),
                    &mut length,
                )
            };
            if received < 0 {
                if !matches!(
                    std::io::Error::last_os_error().kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) {
                    socket = None;
                    retry = Instant::now() + Duration::from_secs(1);
                }
                continue;
            }
            packets += 1;
            let received = received as usize;
            let parsed = collector::tls::ip_client_hello(&buffer[..received]);
            buffer[..received].fill(0);
            if let Ok(Some(hello)) = parsed {
                if authorization.hosts.contains(&hello.hostname) {
                    // A post-NAT source address can belong to the host without
                    // there being a host socket. Require both current witnesses.
                    let host_socket = address.sll_pkttype == libc::PACKET_OUTGOING as u8
                        && super::host_witness::matches(address.sll_ifindex, &hello);
                    let origin = state.lock().ok().and_then(|mut state| {
                        if host_socket && !state.bindings.contains_key(&address.sll_ifindex) {
                            Some(Origin::Host)
                        } else {
                            origin(
                                &mut state,
                                address.sll_ifindex,
                                address.sll_pkttype,
                                &address.sll_addr[..(address.sll_halen as usize).min(8)],
                            )
                        }
                    });
                    let Some(origin) = origin else {
                        continue;
                    };
                    if let Ok(mut state) = state.lock() {
                        if state.authorization.epoch == authorization.epoch
                            && state.authorization.expires > now()
                            && Instant::now() < state.authorization.deadline
                        {
                            let key = (origin, hello.hostname, hello.remote.port());
                            if state.observations.len() < 1024
                                || state.observations.contains_key(&key)
                            {
                                state.observations.insert(key, now());
                            } else {
                                state.saturated = true;
                            }
                        }
                    }
                }
            }
        }
    }
}
#[cfg(target_os = "linux")]
fn observe(state: Arc<Mutex<State>>, stop: Arc<AtomicBool>) {
    linux::run(state, stop)
}

#[cfg(all(test, target_os = "linux"))]
#[path = "discovery_network_ipv6_tests.rs"]
mod ipv6_tests;

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    pub(super) fn hello_record(host: &[u8]) -> Vec<u8> {
        let mut names = vec![0];
        names.extend_from_slice(&(host.len() as u16).to_be_bytes());
        names.extend_from_slice(host);
        let mut extension = vec![];
        extension.extend_from_slice(&(names.len() as u16).to_be_bytes());
        extension.extend(names);
        let mut extensions = vec![0, 0];
        extensions.extend_from_slice(&(extension.len() as u16).to_be_bytes());
        extensions.extend(extension);
        let mut hello = vec![3, 3];
        hello.extend_from_slice(&[0; 32]);
        hello.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0]);
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend(extensions);
        let mut handshake = vec![1, 0, 0, hello.len() as u8];
        handshake.extend(hello);
        let mut record = vec![22, 3, 1];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend(handshake);
        record
    }

    #[cfg(target_os = "linux")]
    fn checksum(bytes: &[u8]) -> u16 {
        let mut sum: u32 = bytes
            .chunks(2)
            .map(|pair| u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]) as u32)
            .sum();
        while sum > 65535 {
            sum = (sum & 65535) + (sum >> 16);
        }
        !(sum as u16)
    }
    #[cfg(target_os = "linux")]
    fn tcp_reply(request: &[u8], flags: u8, sequence: u32, ack: u32, payload: &[u8]) -> Vec<u8> {
        let ip_length = ((request[14] & 15) * 4) as usize;
        let tcp = 14 + ip_length;
        let mut output = vec![0; 14 + 40 + payload.len()];
        output[..6].copy_from_slice(&request[6..12]);
        output[6..12].copy_from_slice(&[0x52, 0x54, 0, 0x12, 0x34, 0x56]);
        output[12..14].copy_from_slice(&[8, 0]);
        output[14] = 0x45;
        output[16..18].copy_from_slice(&((40 + payload.len()) as u16).to_be_bytes());
        output[22] = 64;
        output[23] = 6;
        output[26..30].copy_from_slice(&request[30..34]);
        output[30..34].copy_from_slice(&request[26..30]);
        output[34..36].copy_from_slice(&request[tcp + 2..tcp + 4]);
        output[36..38].copy_from_slice(&request[tcp..tcp + 2]);
        output[38..42].copy_from_slice(&sequence.to_be_bytes());
        output[42..46].copy_from_slice(&ack.to_be_bytes());
        output[46] = 0x50;
        output[47] = flags;
        output[48..50].copy_from_slice(&4096u16.to_be_bytes());
        output[54..].copy_from_slice(payload);
        let mut pseudo = output[26..34].to_vec();
        pseudo.extend_from_slice(&[0, 6]);
        pseudo.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        pseudo.extend_from_slice(&output[34..]);
        output[50..52].copy_from_slice(&checksum(&pseudo).to_be_bytes());
        let ip_checksum = checksum(&output[14..34]);
        output[24..26].copy_from_slice(&ip_checksum.to_be_bytes());
        output
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "Required isolated TAP qualification: --vm-network discovery_network::tests::tap_transport_and_guest_origin -- --ignored --exact"]
    fn tap_transport_and_guest_origin() {
        use std::{
            io::{Read, Write},
            os::{
                fd::{AsRawFd, FromRawFd, OwnedFd},
                unix::fs::OpenOptionsExt,
            },
        };
        struct Fixture;
        impl collector::system::Reader for Fixture {
            fn read(
                &self,
                query: collector::system::Query,
                _: &collector::Budget<'_>,
            ) -> Result<Vec<u8>, &'static str> {
                match query {
                    collector::system::Query::LibvirtInterfaces(_) => Ok(b" Interface Type Source Model MAC\n----------------------------------------\n mvfixture0 network default virtio 52:54:00:12:34:56\n".to_vec()),
                    collector::system::Query::LibvirtInterfaceLink { interface, .. } if interface=="mvfixture0" => Ok(b"mvfixture0 up\n".to_vec()),
                    collector::system::Query::LibvirtAddresses(_) => Ok(b"Name MAC address Protocol Address\n-------------------------------------\nmvfixture0 52:54:00:12:34:56 ipv4 192.168.246.2/24\n".to_vec()),
                    _ => Err("unsupported_fixture"),
                }
            }
        }
        let descriptors = || std::fs::read_dir("/proc/self/fd").unwrap().count();
        let before = descriptors();
        {
            let mut tap = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open("/dev/net/tun")
                .expect("Required isolated TUN device unavailable");
            let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
            for (target, byte) in request.ifr_name.iter_mut().zip(b"mvfixture0") {
                *target = *byte as libc::c_char;
            }
            request.ifr_ifru.ifru_flags = (libc::IFF_TAP | libc::IFF_NO_PI) as libc::c_short;
            assert_eq!(
                unsafe { libc::ioctl(tap.as_raw_fd(), libc::TUNSETIFF, &request) },
                0,
                "Required isolated CAP_NET_ADMIN/TAP unavailable"
            );
            let raw =
                unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
            assert!(raw >= 0);
            let control = unsafe { OwnedFd::from_raw_fd(raw) };
            request.ifr_ifru.ifru_flags = libc::IFF_UP as libc::c_short;
            assert_eq!(
                unsafe { libc::ioctl(control.as_raw_fd(), libc::SIOCSIFFLAGS, &request) },
                0
            );
            let catalog: Catalog =
                serde_json::from_slice(include_bytes!("../discovery-engine/catalog/factory.json"))
                    .unwrap();
            let observer = Observer::start(&catalog, 1, now() + 60).unwrap();
            let stopped = AtomicBool::new(false);
            observer.machines(vec![collector::system::Machine {
                hypervisor: collector::vm::Hypervisor::Libvirt,
                uuid: "11111111-1111-4111-8111-111111111111".into(),
                entity: "vm/fixture".into(),
            }]);
            observer.refresh_interfaces(
                &Fixture,
                &collector::Budget::new(Duration::from_secs(2), &stopped),
            );
            let index = observer
                .state
                .lock()
                .unwrap()
                .bindings
                .keys()
                .copied()
                .next()
                .expect("Live TAP mapping was rejected");
            {
                let mut state = observer.state.lock().unwrap();
                assert!(
                    linux::origin(&mut state, index, libc::PACKET_HOST as u8, &[0; 6]).is_none(),
                    "Foreign source MAC was attributed to this VM"
                );
                assert!(
                    linux::origin(
                        &mut state,
                        index + 1,
                        libc::PACKET_HOST as u8,
                        &[0x52, 0x54, 0, 0x12, 0x34, 0x56]
                    )
                    .is_none()
                );
            }
            let deadline = Instant::now() + Duration::from_secs(2);
            while observer.state.lock().unwrap().status != CoverageStatus::Partial {
                assert!(Instant::now() < deadline);
                thread::sleep(Duration::from_millis(10));
            }
            let record = hello_record(b"api.openai.com");
            let mut packet = vec![0u8; 40];
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&((40 + record.len()) as u16).to_be_bytes());
            packet[8] = 64;
            packet[9] = 6;
            packet[12..16].copy_from_slice(&[192, 0, 2, 2]);
            packet[16..20].copy_from_slice(&[203, 0, 113, 2]);
            packet[20..22].copy_from_slice(&43210u16.to_be_bytes());
            packet[22..24].copy_from_slice(&443u16.to_be_bytes());
            packet[32] = 0x50;
            packet[33] = 0x18;
            packet.extend(record);
            let mut frame: Vec<u8> = std::fs::read_to_string("/sys/class/net/mvfixture0/address")
                .unwrap()
                .trim()
                .split(':')
                .map(|v| u8::from_str_radix(v, 16).unwrap())
                .collect();
            frame.extend_from_slice(&[0x52, 0x54, 0, 0x12, 0x34, 0x56, 8, 0]);
            frame.extend(packet);
            tap.write_all(&frame).unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            while observer.state.lock().unwrap().observations.is_empty() {
                assert!(Instant::now() < deadline, "Live TAP ingress not observed");
                thread::sleep(Duration::from_millis(10));
            }
            let mut snapshot = collector::empty("endpoint", 1, now());
            snapshot.entities.push(milvago_discovery_engine::Entity {
                display: None,
                id: collector::identity("host", &["endpoint"]),
                kind: milvago_discovery_engine::EntityKind::Host,
            });
            observer.drain(&mut snapshot);
            assert_eq!(snapshot.facts.len(), 1);
            assert_eq!(
                snapshot.facts[0].source,
                milvago_discovery_engine::Source::VmFlow
            );
            assert_eq!(snapshot.facts[0].entity_id, "vm/fixture");
            let result = milvago_discovery_engine::Engine::compile(&catalog)
                .unwrap()
                .evaluate(&snapshot)
                .unwrap();
            assert!(result.identifications.is_empty());
            assert_eq!(result.communications[0].provider, "openai");
            // A guest-side ARP/TCP fixture exercises host HTTP and neighbor
            // resolution through the isolated TAP, without a guest agent.
            let mut host_address: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            host_address.sin_family = libc::AF_INET as u16;
            host_address.sin_addr.s_addr = u32::from_ne_bytes([192, 168, 246, 1]);
            unsafe {
                std::ptr::write(
                    (&mut request.ifr_ifru.ifru_addr as *mut libc::sockaddr)
                        .cast::<libc::sockaddr_in>(),
                    host_address,
                );
            }
            assert_eq!(
                unsafe { libc::ioctl(control.as_raw_fd(), libc::SIOCSIFADDR, &request) },
                0
            );
            host_address.sin_addr.s_addr = u32::from_ne_bytes([255, 255, 255, 0]);
            unsafe {
                std::ptr::write(
                    (&mut request.ifr_ifru.ifru_addr as *mut libc::sockaddr)
                        .cast::<libc::sockaddr_in>(),
                    host_address,
                );
            }
            assert_eq!(
                unsafe { libc::ioctl(control.as_raw_fd(), libc::SIOCSIFNETMASK, &request) },
                0
            );
            let mut guest = tap.try_clone().unwrap();
            let server = thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(5);
                let mut buffer = [0; 4096];
                while Instant::now() < deadline {
                    let count = match guest.read(&mut buffer) {
                        Ok(count) => count,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(1));
                            continue;
                        }
                        Err(error) => panic!("TAP guest read failed: {error}"),
                    };
                    let frame = &buffer[..count];
                    if count < 42 {
                        continue;
                    }
                    if frame[12..14] == [8, 6]
                        && frame[20..22] == [0, 1]
                        && frame[38..42] == [192, 168, 246, 2]
                    {
                        let mut response = frame[..42].to_vec();
                        response[..6].copy_from_slice(&frame[6..12]);
                        response[6..12].copy_from_slice(&[0x52, 0x54, 0, 0x12, 0x34, 0x56]);
                        response[20..22].copy_from_slice(&[0, 2]);
                        response[22..28].copy_from_slice(&[0x52, 0x54, 0, 0x12, 0x34, 0x56]);
                        response[28..32].copy_from_slice(&[192, 168, 246, 2]);
                        response[32..38].copy_from_slice(&frame[22..28]);
                        response[38..42].copy_from_slice(&frame[28..32]);
                        guest.write_all(&response).unwrap();
                        continue;
                    }
                    if frame[12..14] != [8, 0] || frame[23] != 6 {
                        continue;
                    }
                    let tcp = 14 + ((frame[14] & 15) * 4) as usize;
                    if count < tcp + 20 || frame[tcp + 2..tcp + 4] != 32145u16.to_be_bytes() {
                        continue;
                    }
                    let sequence = u32::from_be_bytes(frame[tcp + 4..tcp + 8].try_into().unwrap());
                    if frame[tcp + 13] & 2 != 0 {
                        guest
                            .write_all(&tcp_reply(frame, 0x12, 1000, sequence.wrapping_add(1), &[]))
                            .unwrap();
                        continue;
                    }
                    let start = tcp + ((frame[tcp + 12] >> 4) * 4) as usize;
                    if count > start && frame[start..].starts_with(b"GET / HTTP/1.1") {
                        guest.write_all(&tcp_reply(frame,0x19,1001,sequence.wrapping_add((count-start) as u32),b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\nConnection: close\r\n\r\nOllama is running")).unwrap();
                        return;
                    }
                }
                panic!("The isolated guest did not receive an HTTP probe");
            });
            let machines = vec![collector::system::Machine {
                hypervisor: collector::vm::Hypervisor::Libvirt,
                uuid: "11111111-1111-4111-8111-111111111111".into(),
                entity: "vm/fixture".into(),
            }];
            let budget = collector::Budget::new(Duration::from_secs(4), &stopped);
            let probes =
                collector::vm_http::collect(&mut snapshot, &machines, &Fixture, &[32145], &budget);
            assert_eq!(probes.len(), 1);
            let targets: Vec<_> = probes.iter().map(|p| p.target.clone()).collect();
            let (_, connections) = collector::http::collect_with_connections(
                &mut snapshot,
                &targets,
                &["192.168.246.2".parse().unwrap()],
                &budget,
            );
            server.join().unwrap();
            collector::vm_http::attribute(&mut snapshot, &probes, &[], &budget);
            assert!(
                !snapshot
                    .relations
                    .iter()
                    .any(|r| r.kind == milvago_discovery_engine::RelationKind::ObservedOrigin),
                "DHCP and ARP alone manufactured a VM response origin"
            );
            assert_eq!(
                connections.len(),
                1,
                "HTTP transport did not expose its actual TCP tuple"
            );
            collector::vm_http::attribute(&mut snapshot, &probes, &connections, &budget);
            assert!(
                snapshot.relations.iter().any(|r| r.from == "vm/fixture"
                    && r.kind == milvago_discovery_engine::RelationKind::ObservedOrigin),
                "Real HTTP response was not tied to its exact TCP tuple on the live TAP"
            );
            let result = milvago_discovery_engine::Engine::compile(&catalog)
                .unwrap()
                .evaluate(&snapshot)
                .unwrap();
            assert_eq!(result.identifications.len(), 1);
            assert_eq!(result.identifications[0].application_id, "ollama");
            drop(probes);
            drop(tap);
            let mut state = observer.state.lock().unwrap();
            assert!(
                linux::origin(
                    &mut state,
                    index,
                    libc::PACKET_HOST as u8,
                    &[0x52, 0x54, 0, 0x12, 0x34, 0x56]
                )
                .is_none(),
                "Removed/reused interface retained a VM origin"
            );
            assert!(state.bindings.is_empty());
        }
        assert_eq!(
            descriptors(),
            before,
            "TAP mapping/capture retained file descriptors"
        );
    }
    #[test]
    fn authorization_expires_and_epoch_changes_cannot_reuse_queued_metadata() {
        let catalog: Catalog =
            serde_json::from_slice(include_bytes!("../discovery-engine/catalog/factory.json"))
                .unwrap();
        let observer = Observer::start(&catalog, 1, now() - 1).unwrap();
        assert!(!observer.authorize(&catalog, 2, now() + 60));
        assert!(
            !observer.authorize(&catalog, 1, now() + 60),
            "expired collection must restart before renewal"
        );
        let mut snapshot = collector::empty("endpoint", 1, now());
        observer.drain(&mut snapshot);
        assert!(snapshot.facts.is_empty());
        assert_eq!(snapshot.coverage[0].status, CoverageStatus::Denied);
        let start = Instant::now();
        drop(observer);
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn catalogue_changes_revoke_the_previous_network_observer_before_renewal() {
        let catalog: Catalog =
            serde_json::from_slice(include_bytes!("../discovery-engine/catalog/factory.json"))
                .unwrap();
        for change_revision in [false, true] {
            let observer = Observer::start(&catalog, 1, now() + 60).unwrap();
            assert!(observer.authorize(&catalog, 1, now() + 120));
            observer
                .state
                .lock()
                .unwrap()
                .observations
                .insert((Origin::Host, "api.openai.com".into(), 443), now());
            let mut changed = catalog.clone();
            if change_revision {
                changed.revision += 1;
            } else {
                changed.providers.clear();
            }
            assert!(!observer.authorize(&changed, 1, now() + 180));
            let state = observer.state.lock().unwrap();
            assert!(state.authorization.expires <= now());
            assert!(state.authorization.deadline <= Instant::now());
            assert!(state.observations.is_empty());
            drop(state);
            let mut snapshot = collector::empty("endpoint", 1, now());
            observer.drain(&mut snapshot);
            assert!(snapshot.facts.is_empty());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "Required isolated capture qualification: --capture discovery_network::tests::kernel_filter_and_socket_lifetime -- --ignored --exact"]
    fn kernel_filter_and_socket_lifetime() {
        use std::{
            io::{Read, Write},
            net::{TcpListener, TcpStream},
            os::fd::AsRawFd,
        };
        let descriptors = || std::fs::read_dir("/proc/self/fd").unwrap().count();
        let before = descriptors();
        {
            let socket =
                linux::socket().expect("Required CAP_NET_RAW or kernel filter unavailable");
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (mut server, _) = listener.accept().unwrap();
            client.set_nodelay(true).unwrap();
            server
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let host = b"api.openai.com";
            let mut names = vec![0];
            names.extend_from_slice(&(host.len() as u16).to_be_bytes());
            names.extend_from_slice(host);
            let mut extension = vec![];
            extension.extend_from_slice(&(names.len() as u16).to_be_bytes());
            extension.extend(names);
            let mut extensions = vec![0, 0];
            extensions.extend_from_slice(&(extension.len() as u16).to_be_bytes());
            extensions.extend(extension);
            let mut hello = vec![3, 3];
            hello.extend_from_slice(&[0; 32]);
            hello.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0]);
            hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
            hello.extend(extensions);
            let mut handshake = vec![1, 0, 0, hello.len() as u8];
            handshake.extend(hello);
            let mut record = vec![22, 3, 1];
            record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
            record.extend(handshake);
            let mut combined = record.clone();
            combined.extend_from_slice(&[23, 3, 3, 0, 17]);
            combined.extend_from_slice(b"PRIVATE_META_TEST");
            client.write_all(&combined).unwrap();
            let mut received = vec![0; combined.len()];
            server.read_exact(&mut received).unwrap();
            let mut buffer = [0u8; 2048];
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut found = false;
            while Instant::now() < deadline {
                let mut poll = libc::pollfd {
                    fd: socket.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                if unsafe { libc::poll(&mut poll, 1, 50) } <= 0 {
                    if found {
                        break;
                    }
                    continue;
                }
                let count = unsafe {
                    libc::recv(
                        socket.as_raw_fd(),
                        buffer.as_mut_ptr().cast(),
                        buffer.len(),
                        0,
                    )
                };
                if count > 0 {
                    assert!(
                        !buffer[..count as usize]
                            .windows(17)
                            .any(|bytes| bytes == b"PRIVATE_META_TEST"),
                        "Coalesced application data crossed the metadata filter"
                    );
                    if let Ok(Some(hello)) =
                        collector::tls::ip_client_hello(&buffer[..count as usize])
                    {
                        assert_eq!(hello.hostname, "api.openai.com");
                        found = true;
                    }
                }
            }
            assert!(
                found,
                "Kernel filter rejected the real local TCP ClientHello"
            );
            let application = [23, 3, 3, 0, 1, 1];
            client.write_all(&application).unwrap();
            let mut received = [0; 6];
            server.read_exact(&mut received).unwrap();
            let mut poll = libc::pollfd {
                fd: socket.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            assert_eq!(
                unsafe { libc::poll(&mut poll, 1, 100) },
                0,
                "Application record crossed the kernel metadata filter"
            );
            let catalog: Catalog =
                serde_json::from_slice(include_bytes!("../discovery-engine/catalog/factory.json"))
                    .unwrap();
            let observer = Observer::start(&catalog, 8, now() + 60).unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            while observer.state.lock().unwrap().status != CoverageStatus::Partial {
                assert!(Instant::now() < deadline, "Continuous sensor did not start");
                thread::sleep(Duration::from_millis(10));
            }
            client.write_all(&record).unwrap();
            let mut received = vec![0; record.len()];
            server.read_exact(&mut received).unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            while observer.state.lock().unwrap().observations.is_empty() {
                assert!(
                    Instant::now() < deadline,
                    "Continuous sensor lost a local ClientHello"
                );
                thread::sleep(Duration::from_millis(10));
            }
            let mut snapshot = collector::empty("endpoint", 1, now());
            snapshot.entities.push(milvago_discovery_engine::Entity {
                display: None,
                id: collector::identity("host", &["endpoint"]),
                kind: milvago_discovery_engine::EntityKind::Host,
            });
            observer.drain(&mut snapshot);
            assert_eq!(snapshot.facts.len(), 1);
            assert_eq!(
                snapshot.facts[0].source,
                milvago_discovery_engine::Source::HostFlow
            );
            let result = milvago_discovery_engine::Engine::compile(&catalog)
                .unwrap()
                .evaluate(&snapshot)
                .unwrap();
            assert!(result.identifications.is_empty());
            assert_eq!(result.communications[0].provider, "openai");
            assert!(observer.authorize(&catalog, 8, now() - 1));
            let deadline = Instant::now() + Duration::from_secs(2);
            while observer.state.lock().unwrap().status != CoverageStatus::Denied {
                assert!(Instant::now() < deadline, "Expired sensor did not close");
                thread::sleep(Duration::from_millis(10));
            }
            let mut snapshot = collector::empty("endpoint", 2, now());
            observer.drain(&mut snapshot);
            assert!(snapshot.facts.is_empty());
            drop(observer);
        }
        assert_eq!(
            descriptors(),
            before,
            "Packet socket or TCP fixture leaked a descriptor"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn outgoing_packets_without_a_local_socket_witness_have_no_host_origin() {
        let mut state = State {
            dns: windows::DnsState::default(),
            authorization: Authorization {
                epoch: 1,
                catalog_revision: 1,
                expires: now() + 60,
                deadline: Instant::now() + Duration::from_secs(60),
                hosts: Arc::new(BTreeSet::new()),
            },
            observations: BTreeMap::new(),
            status: CoverageStatus::Partial,
            saturated: false,
            vm_status: CoverageStatus::Unavailable,
            machines: vec![],
            next_mapping_refresh: Instant::now(),
            mapping_cursor: 0,
            bindings: BTreeMap::new(),
        };
        for index in [0, 1, 2, 999999] {
            assert!(
                linux::origin(&mut state, index, libc::PACKET_OUTGOING as u8, &[0; 6]).is_none(),
                "forwarded/NAT traffic must not become host use merely because it is outgoing"
            );
        }
    }
}
