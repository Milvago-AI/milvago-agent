//! An isolated TAP guest supplies real IPv6 NDP and TCP, without a guest agent.
use milvago_discovery_collector as collector;
use milvago_discovery_engine::{Catalog, Engine, Entity, EntityKind, RelationKind};
use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv6Addr},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::OpenOptionsExt,
    },
    sync::atomic::AtomicBool,
    thread,
    time::{Duration, Instant},
};

const MAC: [u8; 6] = [0x52, 0x54, 0, 0x12, 0x34, 0x56];
const NAME: &str = "mv6fixture0";
const PORT: u16 = 32145;

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|part| u16::from_be_bytes([part[0], *part.get(1).unwrap_or(&0)]) as u32)
        .sum();
    while sum > 65535 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}

fn packet(request: &[u8], protocol: u8, hops: u8, payload: &[u8]) -> Vec<u8> {
    let mut output = vec![0; 54 + payload.len()];
    output[..6].copy_from_slice(&request[6..12]);
    output[6..12].copy_from_slice(&MAC);
    output[12..14].copy_from_slice(&[0x86, 0xdd]);
    output[14] = 0x60;
    output[18..20].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    output[20] = protocol;
    output[21] = hops;
    output[22..38].copy_from_slice(&"fd42:246::2".parse::<Ipv6Addr>().unwrap().octets());
    output[38..54].copy_from_slice(&request[22..38]);
    output[54..].copy_from_slice(payload);
    let mut pseudo = output[22..54].to_vec();
    pseudo.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, protocol]);
    pseudo.extend_from_slice(payload);
    let field = if protocol == 58 { 56 } else { 70 };
    output[field..field + 2].copy_from_slice(&checksum(&pseudo).to_be_bytes());
    output
}

fn advertisement(request: &[u8]) -> Vec<u8> {
    let mut body = vec![0; 32];
    body[0] = 136;
    body[4] = 0x60;
    body[8..24].copy_from_slice(&"fd42:246::2".parse::<Ipv6Addr>().unwrap().octets());
    body[24..26].copy_from_slice(&[2, 1]);
    body[26..32].copy_from_slice(&MAC);
    packet(request, 58, 255, &body)
}

fn tcp(request: &[u8], flags: u8, sequence: u32, acknowledgement: u32, payload: &[u8]) -> Vec<u8> {
    let mut body = vec![0; 20 + payload.len()];
    body[..2].copy_from_slice(&request[56..58]);
    body[2..4].copy_from_slice(&request[54..56]);
    body[4..8].copy_from_slice(&sequence.to_be_bytes());
    body[8..12].copy_from_slice(&acknowledgement.to_be_bytes());
    body[12] = 0x50;
    body[13] = flags;
    body[14..16].copy_from_slice(&4096u16.to_be_bytes());
    body[20..].copy_from_slice(payload);
    packet(request, 6, 64, &body)
}

fn replace_neighbor(index: i32, address: Ipv6Addr, mac: [u8; 6]) {
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    assert!(raw >= 0);
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as u16;
    let mut request = [0u8; 60];
    request[..4].copy_from_slice(&60u32.to_ne_bytes());
    request[4..6].copy_from_slice(&28u16.to_ne_bytes());
    request[6..8].copy_from_slice(&0x505u16.to_ne_bytes());
    request[8..12].copy_from_slice(&19u32.to_ne_bytes());
    request[16] = libc::AF_INET6 as u8;
    request[20..24].copy_from_slice(&index.to_ne_bytes());
    request[24..26].copy_from_slice(&128u16.to_ne_bytes());
    request[28..30].copy_from_slice(&20u16.to_ne_bytes());
    request[30..32].copy_from_slice(&1u16.to_ne_bytes());
    request[32..48].copy_from_slice(&address.octets());
    request[48..50].copy_from_slice(&10u16.to_ne_bytes());
    request[50..52].copy_from_slice(&2u16.to_ne_bytes());
    request[52..58].copy_from_slice(&mac);
    assert_eq!(
        unsafe {
            libc::sendto(
                fd.as_raw_fd(),
                request.as_ptr().cast(),
                request.len(),
                0,
                (&kernel as *const libc::sockaddr_nl).cast(),
                std::mem::size_of_val(&kernel) as libc::socklen_t,
            )
        },
        request.len() as isize
    );
    let mut poll = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    assert_eq!(unsafe { libc::poll(&mut poll, 1, 500) }, 1);
    let mut response = [0u8; 512];
    let size = unsafe {
        libc::recv(
            fd.as_raw_fd(),
            response.as_mut_ptr().cast(),
            response.len(),
            libc::MSG_DONTWAIT | libc::MSG_TRUNC,
        )
    };
    assert!(size >= 20 && size <= response.len() as isize);
    assert_eq!(u16::from_ne_bytes(response[4..6].try_into().unwrap()), 2);
    assert_eq!(
        i32::from_ne_bytes(response[16..20].try_into().unwrap()),
        0,
        "isolated neighbor update refused"
    );
}

fn inject_provider(tap: &mut std::fs::File) {
    let host_mac = std::fs::read_to_string(format!("/sys/class/net/{NAME}/address"))
        .unwrap()
        .trim()
        .split(':')
        .map(|part| u8::from_str_radix(part, 16).unwrap())
        .collect::<Vec<_>>();
    let mut destination = vec![0u8; 54];
    destination[6..12].copy_from_slice(&host_mac);
    destination[22..38].copy_from_slice(&"2001:db8:ffff::2".parse::<Ipv6Addr>().unwrap().octets());
    let mut hello = vec![0u8; 20];
    hello[..2].copy_from_slice(&43210u16.to_be_bytes());
    hello[2..4].copy_from_slice(&443u16.to_be_bytes());
    hello[12] = 0x50;
    hello[13] = 0x18;
    hello.extend(super::tests::hello_record(b"api.openai.com"));
    // Synthetic ingress in the isolated namespace: no provider is contacted.
    tap.write_all(&packet(&destination, 6, 64, &hello)).unwrap();
}

fn systemd_mode() -> bool {
    if std::env::var_os("MILVAGO_DISCOVERY_SYSTEMD_VM").is_none() {
        return false;
    }
    assert!(cfg!(feature = "systemd-qualification"));
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let id = std::env::var("MILVAGO_SYSTEMD_QA_ID").unwrap();
    assert!(uuid::Uuid::parse_str(&id).is_ok());
    assert_eq!(std::fs::read_to_string("/opt/qa/id").unwrap(), id);
    assert_eq!(
        std::fs::read_to_string("/proc/1/comm").unwrap().trim(),
        "systemd"
    );
    assert_eq!(
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap()
            .trim(),
        "systemd-fixture"
    );
    true
}

fn systemd_roundtrip(tap: &mut std::fs::File) {
    struct Client(std::process::Child);
    impl Drop for Client {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let marker = std::path::Path::new("/opt/qa/vm-source");
    assert!(!marker.join("ready").exists() && !marker.join("collect").exists());
    let mut command = std::process::Command::new("/usr/bin/setpriv");
    command
        .args(["--reuid=1000", "--regid=1000", "--clear-groups"])
        .arg(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "discovery_privileged::service::tests::isolated_rpc_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/tmp")
        .env("MILVAGO_DISCOVERY_RPC_ROOT", "/opt/qa/rpc")
        .env("MILVAGO_DISCOVERY_RPC_ROLE", "systemd-vm")
        .env(
            "MILVAGO_SYSTEMD_QA_ID",
            std::env::var("MILVAGO_SYSTEMD_QA_ID").unwrap(),
        );
    let mut client = Client(command.spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(20);
    for (ready, collect) in [("ready", "collect"), ("ready-flow", "collect-flow")] {
        assert!(!marker.join(collect).exists());
        while !marker.join(ready).exists() {
            assert!(
                client.0.try_wait().unwrap().is_none(),
                "service VM client exited before prime"
            );
            assert!(Instant::now() < deadline, "service VM prime timed out");
            thread::sleep(Duration::from_millis(10));
        }
        inject_provider(tap);
        thread::sleep(Duration::from_millis(150));
        std::fs::write(marker.join(collect), b"1").unwrap();
    }
    loop {
        if let Some(status) = client.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(Instant::now() < deadline, "service VM collection timed out");
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
#[ignore = "Requires isolated Linux NET_ADMIN/NET_RAW and TUN: --vm-network"]
fn tap_http_ipv6_requires_current_interface_tuple_and_neighbor() {
    struct Fixture;
    impl collector::system::Reader for Fixture {
        fn read(
            &self,
            query: collector::system::Query,
            _: &collector::Budget<'_>,
        ) -> Result<Vec<u8>, &'static str> {
            match query {
                collector::system::Query::LibvirtInterfaces(_)=>Ok(format!(" Interface Type Source Model MAC\n----------------------------------------\n {NAME} network default virtio 52:54:00:12:34:56\n").into_bytes()),
                collector::system::Query::LibvirtInterfaceLink { interface,.. } if interface==NAME=>Ok(format!("{NAME} up\n").into_bytes()),
                collector::system::Query::LibvirtAddresses(_)=>Ok(format!("Name MAC address Protocol Address\n-------------------------------------\n{NAME} 52:54:00:12:34:56 ipv6 fd42:246::2/64\n").into_bytes()),
                _=>Err("unsupported_fixture"),
            }
        }
    }
    let systemd = systemd_mode();
    let descriptors = || std::fs::read_dir("/proc/self/fd").unwrap().count();
    let before = descriptors();
    {
        let mut tap = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open("/dev/net/tun")
            .expect("isolated TUN required");
        let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
        for (target, byte) in request.ifr_name.iter_mut().zip(NAME.bytes()) {
            *target = byte as libc::c_char;
        }
        request.ifr_ifru.ifru_flags = (libc::IFF_TAP | libc::IFF_NO_PI) as libc::c_short;
        assert_eq!(
            unsafe { libc::ioctl(tap.as_raw_fd(), libc::TUNSETIFF, &request) },
            0
        );
        let raw = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        assert!(raw >= 0);
        let control = unsafe { OwnedFd::from_raw_fd(raw) };
        request.ifr_ifru.ifru_flags = libc::IFF_UP as libc::c_short;
        assert_eq!(
            unsafe { libc::ioctl(control.as_raw_fd(), libc::SIOCSIFFLAGS, &request) },
            0
        );
        let interface = std::ffi::CString::new(NAME).unwrap();
        let index = unsafe { libc::if_nametoindex(interface.as_ptr()) } as i32;
        assert!(index > 0);
        #[repr(C)]
        struct Address {
            address: libc::in6_addr,
            prefix: u32,
            index: i32,
        }
        let host = Address {
            address: libc::in6_addr {
                s6_addr: "fd42:246::1".parse::<Ipv6Addr>().unwrap().octets(),
            },
            prefix: 64,
            index,
        };
        assert_eq!(
            unsafe { libc::ioctl(control.as_raw_fd(), libc::SIOCSIFADDR, &host) },
            0
        );
        // Let duplicate-address detection finish; this never starts a VM/distro.
        thread::sleep(Duration::from_secs(2));
        let catalog: Catalog =
            serde_json::from_slice(include_bytes!("../discovery-engine/catalog/factory.json"))
                .unwrap();
        if !systemd {
            let observer = super::Observer::start(&catalog, 1, super::now() + 60).unwrap();
            observer.machines(vec![collector::system::Machine {
                hypervisor: collector::vm::Hypervisor::Libvirt,
                uuid: "11111111-1111-4111-8111-111111111111".into(),
                entity: "vm/ipv6-fixture".into(),
            }]);
            let stopped_flow = AtomicBool::new(false);
            observer.refresh_interfaces(
                &Fixture,
                &collector::Budget::new(Duration::from_secs(2), &stopped_flow),
            );
            let ready = Instant::now() + Duration::from_secs(2);
            while observer.state.lock().unwrap().status
                != milvago_discovery_engine::CoverageStatus::Partial
            {
                assert!(
                    Instant::now() < ready,
                    "IPv6 metadata observer did not start"
                );
                thread::sleep(Duration::from_millis(10));
            }
            inject_provider(&mut tap);
            let ready = Instant::now() + Duration::from_secs(2);
            while observer.state.lock().unwrap().observations.is_empty() {
                assert!(
                    Instant::now() < ready,
                    "IPv6 guest ClientHello not observed"
                );
                thread::sleep(Duration::from_millis(10));
            }
            let mut flow = collector::empty("endpoint", 1, super::now());
            flow.entities.push(Entity {
                id: collector::identity("host", &["endpoint"]),
                kind: EntityKind::Host,
                display: None,
            });
            observer.drain(&mut flow);
            assert_eq!(flow.facts.len(), 1);
            assert_eq!(flow.facts[0].entity_id, "vm/ipv6-fixture");
            assert_eq!(
                flow.facts[0].source,
                milvago_discovery_engine::Source::VmFlow
            );
            let only_destination = Engine::compile(&catalog).unwrap().evaluate(&flow).unwrap();
            assert!(only_destination.identifications.is_empty());
            assert_eq!(only_destination.communications.len(), 1);
            assert_eq!(only_destination.communications[0].provider, "openai");
            drop(observer);
        }
        let mut guest = tap.try_clone().unwrap();
        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(if systemd { 25 } else { 8 });
            let mut remaining = if systemd { 2 } else { 1 };
            let mut buffer = [0u8; 4096];
            while Instant::now() < deadline {
                let size = match guest.read(&mut buffer) {
                    Ok(size) => size,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(error) => panic!("isolated TAP read: {error}"),
                };
                let frame = &buffer[..size];
                if size < 54 || frame[12..14] != [0x86, 0xdd] {
                    continue;
                }
                if frame[20] == 58
                    && size >= 78
                    && frame[54] == 135
                    && frame[62..78] == "fd42:246::2".parse::<Ipv6Addr>().unwrap().octets()
                {
                    guest.write_all(&advertisement(frame)).unwrap();
                    continue;
                }
                if frame[20] != 6 || size < 74 || frame[56..58] != PORT.to_be_bytes() {
                    continue;
                }
                let end = 54 + u16::from_be_bytes(frame[18..20].try_into().unwrap()) as usize;
                let end = end.min(size);
                let sequence = u32::from_be_bytes(frame[58..62].try_into().unwrap());
                if frame[67] & 2 != 0 {
                    guest
                        .write_all(&tcp(frame, 0x12, 4000, sequence.wrapping_add(1), &[]))
                        .unwrap();
                    continue;
                }
                let start = 54 + (frame[66] >> 4) as usize * 4;
                if start < end && frame[start..end].starts_with(b"GET / HTTP/1.1") {
                    guest.write_all(&tcp(frame,0x19,4001,sequence.wrapping_add((end-start) as u32),b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\nConnection: close\r\n\r\nOllama is running")).unwrap();
                    remaining -= 1;
                    if remaining == 0 {
                        return;
                    }
                }
            }
            panic!("isolated IPv6 guest did not receive HTTP");
        });
        if systemd {
            systemd_roundtrip(&mut tap);
            server.join().unwrap();
        } else {
            let stopped = AtomicBool::new(false);
            let budget = collector::Budget::new(Duration::from_secs(6), &stopped);
            let mut snapshot = collector::empty("endpoint", 1, super::now());
            snapshot.entities.push(Entity {
                id: "vm/ipv6-fixture".into(),
                kind: EntityKind::Vm,
                display: None,
            });
            let machines = [collector::system::Machine {
                hypervisor: collector::vm::Hypervisor::Libvirt,
                uuid: "11111111-1111-4111-8111-111111111111".into(),
                entity: "vm/ipv6-fixture".into(),
            }];
            let mut groups = vec![];
            for _ in 0..4 {
                let mut candidate_snapshot = collector::empty("endpoint", 1, super::now());
                let probes = collector::vm_http::collect(
                    &mut candidate_snapshot,
                    &machines,
                    &Fixture,
                    &[PORT],
                    &budget,
                );
                if groups.is_empty() {
                    snapshot.coverage.extend(candidate_snapshot.coverage);
                }
                assert_eq!(probes.len(), 1);
                groups.push(probes);
            }
            let targets = groups[0]
                .iter()
                .map(|probe| probe.target.clone())
                .collect::<Vec<_>>();
            let (_, connections) = collector::http::collect_paths_with_connections(
                &mut snapshot,
                &targets,
                &["fd42:246::2".parse::<IpAddr>().unwrap()],
                &["/".into()],
                &budget,
            );
            server.join().unwrap();
            assert_eq!(connections.len(), 1);
            let unassigned = snapshot.clone();
            collector::vm_http::attribute(&mut snapshot, &groups[0], &[], &budget);
            let assigned = |snapshot: &milvago_discovery_engine::Snapshot| {
                snapshot
                    .relations
                    .iter()
                    .any(|relation| relation.kind == RelationKind::ObservedOrigin)
            };
            assert!(!assigned(&snapshot), "lease and NDP alone attributed a VM");
            let mut forged = snapshot.clone();
            let mut wrong = connections.clone();
            let wrong_port = wrong[0].local.port().wrapping_add(1);
            wrong[0].local.set_port(wrong_port);
            collector::vm_http::attribute(&mut forged, &groups[1], &wrong, &budget);
            assert!(!assigned(&forged), "a different TCP tuple attributed a VM");
            let mut expired = unassigned.clone();
            collector::vm_http::attribute(
                &mut expired,
                &groups[0],
                &connections,
                &collector::Budget::new(Duration::ZERO, &stopped),
            );
            assert!(!assigned(&expired), "expired work attributed a VM");
            let cancelled = AtomicBool::new(true);
            collector::vm_http::attribute(
                &mut expired,
                &groups[0],
                &connections,
                &collector::Budget::new(Duration::from_secs(1), &cancelled),
            );
            assert!(!assigned(&expired), "cancelled work attributed a VM");
            collector::vm_http::attribute(&mut snapshot, &groups[0], &connections, &budget);
            assert!(
                assigned(&snapshot),
                "actual IPv6 HTTP/TAP/NDP was not attributed"
            );
            let result = Engine::compile(&catalog)
                .unwrap()
                .evaluate(&snapshot)
                .unwrap();
            assert_eq!(result.identifications.len(), 1);
            assert_eq!(result.identifications[0].application_id, "ollama");
            assert_eq!(
                result.identifications[0].entity_id,
                collector::identity(
                    "endpoint",
                    &["endpoint", "[fd42:246::2]:32145", "vm/ipv6-fixture"]
                ),
                "a reused address must not move historical application evidence to another VM"
            );
            replace_neighbor(
                index,
                "fd42:246::2".parse().unwrap(),
                [0x52, 0x54, 0, 0xaa, 0xbb, 0xcc],
            );
            let mut wrong_neighbor = unassigned.clone();
            collector::vm_http::attribute(&mut wrong_neighbor, &groups[2], &connections, &budget);
            assert!(
                !assigned(&wrong_neighbor),
                "a mismatching NDP MAC attributed a VM"
            );
            replace_neighbor(index, "fd42:246::2".parse().unwrap(), MAC);
            drop(tap);
            let mut removed = unassigned;
            collector::vm_http::attribute(&mut removed, &groups[3], &connections, &budget);
            assert!(
                !assigned(&removed),
                "a removed interface retained its VM attribution"
            );
            drop(groups);
        }
    }
    assert_eq!(
        descriptors(),
        before,
        "IPv6 TAP/NDP/witness descriptors leaked"
    );
}
