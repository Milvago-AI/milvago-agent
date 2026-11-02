//! Bounded VM endpoint candidates. DHCP alone never establishes response origin.
#[cfg(target_os = "linux")]
use crate::system::Query;
use crate::{
    system::{Machine, Reader},
    vm_network::Interface,
    *,
};
#[cfg(target_os = "linux")]
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr};

pub fn addresses(
    bytes: &[u8],
    interfaces: &[Interface],
) -> Result<Vec<(IpAddr, Interface)>, &'static str> {
    if bytes.len() > 64 * 1024 {
        return Err("vm_address_limit");
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "invalid_vm_addresses")?;
    let mut lines = text.lines().filter(|line| !line.trim().is_empty());
    if lines
        .next()
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        != Some(vec!["Name", "MAC", "address", "Protocol", "Address"])
        || !lines
            .next()
            .is_some_and(|line| line.trim().len() >= 5 && line.trim().bytes().all(|b| b == b'-'))
    {
        return Err("invalid_vm_addresses");
    }
    let mut output = vec![];
    for (index, line) in lines.enumerate() {
        if index >= 128 {
            return Err("vm_address_limit");
        }
        let columns: Vec<_> = line.split_whitespace().collect();
        if columns.len() != 4 {
            return Err("invalid_vm_addresses");
        }
        if !matches!(columns[2], "ipv4" | "ipv6") {
            continue;
        }
        let Some((ip, prefix)) = columns[3].split_once('/') else {
            return Err("invalid_vm_addresses");
        };
        let ip: IpAddr = ip.parse().map_err(|_| "invalid_vm_addresses")?;
        let (maximum, admitted) = match (columns[2], ip) {
            ("ipv4", IpAddr::V4(ip)) => (
                32,
                ip.is_private() && !ip.is_loopback() && !ip.is_link_local(),
            ),
            ("ipv6", IpAddr::V6(ip)) => (128, ip.is_unique_local()),
            _ => return Err("invalid_vm_addresses"),
        };
        if prefix.parse::<u8>().ok().is_none_or(|p| p > maximum) {
            return Err("invalid_vm_addresses");
        }
        if !admitted || http::metadata_address(ip) {
            continue;
        }
        let Some(interface) = interfaces
            .iter()
            .find(|i| i.name == columns[0] && crate::vm_network::mac(columns[1]) == Some(i.mac))
        else {
            continue;
        };
        if output.len() >= 16 {
            return Err("vm_address_limit");
        }
        output.push((ip, interface.clone()));
    }
    Ok(output)
}

pub fn arp_matches(bytes: &[u8], ip: Ipv4Addr, device: &str, mac: [u8; 6]) -> bool {
    if bytes.len() > 64 * 1024 {
        return false;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let mut found = false;
    for line in text.lines().skip(1) {
        let columns: Vec<_> = line.split_whitespace().collect();
        if columns.len() != 6 {
            continue;
        }
        if columns[0].parse::<Ipv4Addr>().ok() != Some(ip) {
            continue;
        }
        if found
            || columns[1] != "0x1"
            || u32::from_str_radix(columns[2].trim_start_matches("0x"), 16)
                .ok()
                .is_none_or(|f| f & 2 == 0)
            || crate::vm_network::mac(columns[3]) != Some(mac)
            || columns[5] != device
        {
            return false;
        }
        found = true;
    }
    found
}

pub struct Probe {
    pub target: http::Target,
    #[cfg(target_os = "linux")]
    guard: vm_network::Guard,
    #[cfg(target_os = "linux")]
    witness: Option<crate::vm_http_connection::Witness>,
}

pub fn collect(
    snapshot: &mut Snapshot,
    machines: &[Machine],
    reader: &impl Reader,
    ports: &[u16],
    budget: &Budget<'_>,
) -> Vec<Probe> {
    #[cfg(target_os = "linux")]
    {
        let mut output = vec![];
        let mut checked = 0;
        for machine in machines
            .iter()
            .filter(|m| matches!(m.hypervisor, vm::Hypervisor::Libvirt))
            .take(16)
        {
            if budget.check().is_err() {
                break;
            }
            let collected = (|| {
                let interfaces =
                    vm_network::collect(std::slice::from_ref(machine), reader, budget)?;
                let leases = reader.read(Query::LibvirtAddresses(machine.uuid.clone()), budget)?;
                let addresses = addresses(&leases, &interfaces)?;
                for (ip, interface) in addresses {
                    if native::is_local(ip) {
                        continue;
                    }
                    for port in ports.iter().copied().filter(|p| *p > 0).take(64) {
                        budget.check()?;
                        if output.len() >= 128 {
                            return Err("vm_probe_limit");
                        }
                        let Some(guard) = vm_network::Guard::open(interface.clone()) else {
                            continue;
                        };
                        let address = SocketAddr::new(ip, port);
                        let witness = crate::vm_http_connection::Witness::open(&guard, address);
                        output.push(Probe {
                            witness,
                            target: http::Target {
                                address,
                                origin: None,
                                published: false,
                            },
                            guard,
                        });
                    }
                }
                Ok::<(), &'static str>(())
            })();
            if collected.is_ok() {
                checked += 1;
            }
        }
        // Conflicting current lease assignments are unusable, even if one
        // daemon response happened to arrive first.
        let mut owners: BTreeMap<IpAddr, std::collections::BTreeSet<(String, String, [u8; 6])>> =
            BTreeMap::new();
        for probe in &output {
            owners
                .entry(probe.target.address.ip())
                .or_default()
                .insert((
                    probe.guard.interface.entity.clone(),
                    probe.guard.interface.name.clone(),
                    probe.guard.interface.mac,
                ));
        }
        output.retain(|p| owners[&p.target.address.ip()].len() == 1);
        coverage(
            snapshot,
            "vm-http-candidates",
            if checked > 0 {
                CoverageStatus::Partial
            } else {
                CoverageStatus::Unavailable
            },
            false,
        );
        output
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (machines, reader, ports, budget);
        coverage(
            snapshot,
            "vm-http-candidates",
            CoverageStatus::Unavailable,
            false,
        );
        vec![]
    }
}

#[cfg(any(target_os = "linux", test))]
fn scope_endpoint(
    snapshot: &mut Snapshot,
    old: &str,
    vm: &str,
    address: std::net::SocketAddr,
) -> Option<String> {
    let base = identity("endpoint", &[&snapshot.scope, &address.to_string()]);
    let id = identity("endpoint", &[&snapshot.scope, &address.to_string(), vm]);
    if (old != base && old != id)
        || snapshot
            .entities
            .iter()
            .filter(|entity| entity.id == old)
            .count()
            != 1
        || !snapshot
            .entities
            .iter()
            .any(|entity| entity.id == old && entity.kind == EntityKind::Endpoint)
        || snapshot
            .entities
            .iter()
            .filter(|entity| entity.id == vm && entity.kind == EntityKind::Vm)
            .count()
            != 1
        || (id != old && snapshot.entities.iter().any(|entity| entity.id == id))
    {
        return None;
    }
    // IP reuse must not attach an earlier VM's application history to its successor.
    // Rewrite every graph reference only after the destination has been validated.
    for entity in &mut snapshot.entities {
        if entity.id == old {
            entity.id.clone_from(&id);
        }
    }
    for fact in &mut snapshot.facts {
        if fact.entity_id == old {
            fact.entity_id.clone_from(&id);
        }
    }
    for relation in &mut snapshot.relations {
        if relation.from == old {
            relation.from.clone_from(&id);
        }
        if relation.to == old {
            relation.to.clone_from(&id);
        }
    }
    for coverage in &mut snapshot.coverage {
        if coverage.scope == old {
            coverage.scope.clone_from(&id);
        }
    }
    Some(id)
}

pub fn attribute(
    snapshot: &mut Snapshot,
    probes: &[Probe],
    connections: &[http::Connection],
    budget: &Budget<'_>,
) {
    #[cfg(target_os = "linux")]
    {
        let Ok(remaining) = budget.remaining() else {
            return;
        };
        let deadline = Instant::now() + remaining.min(Duration::from_millis(100));
        let mut neighbors = BTreeMap::new();
        for probe in probes {
            if budget.check().is_err() {
                break;
            }
            let id = identity(
                "endpoint",
                &[&snapshot.scope, &probe.target.address.to_string()],
            );
            if !snapshot
                .entities
                .iter()
                .any(|e| e.id == id && e.kind == EntityKind::Endpoint)
            {
                continue;
            }
            let ip = probe.target.address.ip();
            if native::is_local(ip) || !probe.guard.current() {
                continue;
            }
            let Some(connection) = connections
                .iter()
                .find(|c| c.remote == probe.target.address)
            else {
                continue;
            };
            if !probe
                .witness
                .as_ref()
                .is_some_and(|w| w.confirms(&probe.guard, connection))
            {
                continue;
            }
            let device = std::fs::read_link(
                std::path::Path::new("/sys/class/net")
                    .join(&probe.guard.interface.name)
                    .join("master"),
            )
            .ok()
            .and_then(|p| p.file_name().and_then(|v| v.to_str()).map(str::to_owned))
            .unwrap_or_else(|| probe.guard.interface.name.clone());
            let neighbor = match ip {
                IpAddr::V4(ip) => {
                    host::read_limited(std::path::Path::new("/proc/net/arp"), 64 * 1024).is_ok_and(
                        |table| arp_matches(&table, ip, &device, probe.guard.interface.mac),
                    )
                }
                IpAddr::V6(ip) => {
                    let Some(index) = crate::vm_http_ndp::device_index(&device) else {
                        continue;
                    };
                    let key = (index, ip);
                    if !neighbors.contains_key(&key) {
                        if neighbors.len() >= 16 || Instant::now() >= deadline {
                            continue;
                        }
                        neighbors.insert(key, crate::vm_http_ndp::lookup(ip, index, deadline));
                    }
                    neighbors[&key] == Some(probe.guard.interface.mac)
                        && crate::vm_http_ndp::device_index(&device) == Some(index)
                }
            };
            if !neighbor || !probe.guard.current() || budget.check().is_err() {
                continue;
            }
            if snapshot.relations.len() >= MAX_ENTITIES {
                continue;
            }
            let Some(id) = scope_endpoint(
                snapshot,
                &id,
                &probe.guard.interface.entity,
                probe.target.address,
            ) else {
                continue;
            };
            if !snapshot.relations.iter().any(|r| {
                r.from == probe.guard.interface.entity
                    && r.to == id
                    && r.kind == RelationKind::ObservedOrigin
            }) {
                snapshot.relations.push(Relation {
                    from: probe.guard.interface.entity.clone(),
                    to: id,
                    kind: RelationKind::ObservedOrigin,
                    source: "libvirt-tap-http-connection".into(),
                });
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (snapshot, probes, connections, budget);
    }
}

#[cfg(target_os = "linux")]
mod native {
    use super::*;
    pub(super) fn is_local(ip: IpAddr) -> bool {
        let mut addresses = std::ptr::null_mut();
        if unsafe { libc::getifaddrs(&mut addresses) } != 0 {
            return true;
        }
        struct List(*mut libc::ifaddrs);
        impl Drop for List {
            fn drop(&mut self) {
                unsafe {
                    libc::freeifaddrs(self.0);
                }
            }
        }
        let _guard = List(addresses);
        let mut current = addresses;
        for _ in 0..1024 {
            if current.is_null() {
                return false;
            }
            let row = unsafe { &*current };
            if !row.ifa_addr.is_null() {
                match (ip, unsafe { (*row.ifa_addr).sa_family } as i32) {
                    (IpAddr::V4(ip), libc::AF_INET) => {
                        let address = unsafe { &*(row.ifa_addr as *const libc::sockaddr_in) };
                        if Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()) == ip {
                            return true;
                        }
                    }
                    (IpAddr::V6(ip), libc::AF_INET6) => {
                        let address = unsafe { &*(row.ifa_addr as *const libc::sockaddr_in6) };
                        if address.sin6_addr.s6_addr == ip.octets() {
                            return true;
                        }
                    }
                    _ => (),
                }
            }
            current = row.ifa_next;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn vm_endpoint_identity_keeps_history_separate_and_rewrites_graph_references() {
        let address: std::net::SocketAddr = "[fd42::2]:32145".parse().unwrap();
        let old = identity("endpoint", &["endpoint", &address.to_string()]);
        let make = || {
            let mut snapshot = empty("endpoint", 1, 100);
            for (id, kind) in [
                ("host/one".to_string(), EntityKind::Host),
                ("vm/one".into(), EntityKind::Vm),
                ("vm/two".into(), EntityKind::Vm),
                (old.clone(), EntityKind::Endpoint),
            ] {
                snapshot.entities.push(Entity {
                    id,
                    kind,
                    display: None,
                });
            }
            snapshot.facts.push(Fact {
                id: "fact/one".into(),
                entity_id: old.clone(),
                source: Source::Http,
                observed_at: 100,
                fields: BTreeMap::from([
                    (Field::HttpStatus, vec!["200".into()]),
                    (Field::HttpPath, vec!["/".into()]),
                    (Field::HttpBody, vec!["Ollama is running".into()]),
                ]),
            });
            snapshot.relations.push(Relation {
                from: "host/one".into(),
                to: old.clone(),
                kind: RelationKind::OwnsEndpoint,
                source: "fixture".into(),
            });
            snapshot.coverage.push(Coverage {
                scope: old.clone(),
                adapter: "http".into(),
                status: CoverageStatus::Available,
                checked_at: 100,
                complete: true,
            });
            snapshot
        };
        let mut first = make();
        let mut second = make();
        let one = scope_endpoint(&mut first, &old, "vm/one", address).unwrap();
        let two = scope_endpoint(&mut second, &old, "vm/two", address).unwrap();
        assert_ne!(one, two);
        assert_ne!(one, old);
        for (snapshot, id) in [(&first, &one), (&second, &two)] {
            assert!(snapshot.entities.iter().any(|entity| &entity.id == id));
            assert!(!snapshot.entities.iter().any(|entity| entity.id == old));
            assert_eq!(&snapshot.facts[0].entity_id, id);
            assert_eq!(&snapshot.relations[0].to, id);
            assert_eq!(&snapshot.coverage[0].scope, id);
            let catalog: Catalog = serde_json::from_slice(include_bytes!(
                "../../discovery-engine/catalog/factory.json"
            ))
            .unwrap();
            assert_eq!(
                Engine::compile(&catalog)
                    .unwrap()
                    .evaluate(snapshot)
                    .unwrap()
                    .identifications[0]
                    .entity_id,
                *id
            );
        }
        let before = serde_json::to_vec(&first).unwrap();
        assert_eq!(
            scope_endpoint(&mut first, &one, "vm/one", address),
            Some(one)
        );
        assert_eq!(serde_json::to_vec(&first).unwrap(), before);
        let mut conflict = make();
        conflict.entities.push(Entity {
            id: two,
            kind: EntityKind::Endpoint,
            display: None,
        });
        let before = serde_json::to_vec(&conflict).unwrap();
        assert!(scope_endpoint(&mut conflict, &old, "vm/two", address).is_none());
        assert_eq!(serde_json::to_vec(&conflict).unwrap(), before);
        assert!(scope_endpoint(&mut conflict, &old, "host/one", address).is_none());
        assert_eq!(serde_json::to_vec(&conflict).unwrap(), before);
    }
    #[test]
    fn vm_candidates_require_private_leases_matching_live_interface_and_mac() {
        let interface = Interface {
            entity: "vm/fixture".into(),
            name: "vnet0".into(),
            mac: [0x52, 0x54, 0, 0x12, 0x34, 0x56],
        };
        let header = "Name MAC address Protocol Address\n-------------------------------------\n";
        let parse = |row: &str| {
            addresses(
                format!("{header}{row}").as_bytes(),
                std::slice::from_ref(&interface),
            )
        };
        assert_eq!(
            parse("vnet0 52:54:00:12:34:56 ipv4 192.168.122.10/24")
                .unwrap()
                .len(),
            1
        );
        for row in [
            "vnet1 52:54:00:12:34:56 ipv4 192.168.122.10/24",
            "vnet0 52:54:00:12:34:57 ipv4 192.168.122.10/24",
            "vnet0 52:54:00:12:34:56 ipv4 169.254.169.254/16",
            "vnet0 52:54:00:12:34:56 ipv4 8.8.8.8/32",
        ] {
            assert!(parse(row).unwrap().is_empty());
        }
        assert!(parse("vnet0 52:54:00:12:34:56 ipv4 192.168.122.10/99").is_err());
        assert!(parse("data:image/png").is_err());
    }
    #[test]
    fn vm_ipv6_candidates_require_unique_local_leases_and_valid_prefixes() {
        let interface = Interface {
            entity: "vm/fixture".into(),
            name: "vnet0".into(),
            mac: [0x52, 0x54, 0, 0x12, 0x34, 0x56],
        };
        let parse = |row: &str| {
            addresses(
                format!("Name MAC address Protocol Address\n-------------------------------------\nvnet0 52:54:00:12:34:56 {row}").as_bytes(),
                std::slice::from_ref(&interface),
            )
        };
        assert_eq!(parse("ipv6 fd42::2/64").unwrap().len(), 1);
        for address in [
            "fe80::2/64",
            "::1/128",
            "::ffff:192.168.1.2/128",
            "ff02::1/64",
            "2001:db8::2/64",
            "::/0",
            "fd00:ec2::254/64",
            "fd20:ce::254/64",
        ] {
            assert!(parse(&format!("ipv6 {address}")).unwrap().is_empty());
        }
        for row in [
            "ipv6 fd42::2/129",
            "ipv6 fd42::2/-1",
            "ipv6 fd42::2/image",
            "ipv6 192.168.1.2/24",
            "ipv6 fd42::2%eth0/64",
        ] {
            assert!(parse(row).is_err());
        }
    }

    #[test]
    fn stale_conflicting_or_wrong_interface_neighbors_do_not_prove_endpoint_origin() {
        let ip = "192.168.122.10".parse().unwrap();
        let mac = [0x52, 0x54, 0, 0x12, 0x34, 0x56];
        let header = "IP address HW type Flags HW address Mask Device\n";
        let row = "192.168.122.10 0x1 0x2 52:54:00:12:34:56 * virbr0\n";
        assert!(arp_matches(
            format!("{header}{row}").as_bytes(),
            ip,
            "virbr0",
            mac
        ));
        assert!(!arp_matches(
            format!("{header}{row}{row}").as_bytes(),
            ip,
            "virbr0",
            mac
        ));
        assert!(!arp_matches(
            format!("{header}{row}").as_bytes(),
            ip,
            "other",
            mac
        ));
        assert!(!arp_matches(
            format!("{header}{}", row.replace("0x2", "0x0")).as_bytes(),
            ip,
            "virbr0",
            mac
        ));
        assert!(!arp_matches(
            format!("{header}{}", row.replace("34:56", "34:57")).as_bytes(),
            ip,
            "virbr0",
            mac
        ));
        #[cfg(target_os = "linux")]
        assert!(native::is_local(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }
}
