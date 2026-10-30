//! Hypervisor-owned live interface mappings, never names inferred from a VM process.
use crate::{
    system::{Machine, Query, Reader},
    *,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interface {
    pub entity: String,
    pub name: String,
    pub mac: [u8; 6],
}

pub(crate) fn mac(value: &str) -> Option<[u8; 6]> {
    if value.len() != 17 {
        return None;
    }
    let bytes: Vec<_> = value
        .split(':')
        .map(|part| {
            if part.len() != 2 {
                None
            } else {
                u8::from_str_radix(part, 16).ok()
            }
        })
        .collect::<Option<_>>()?;
    let bytes: [u8; 6] = bytes.try_into().ok()?;
    (bytes != [0; 6] && bytes[0] & 1 == 0).then_some(bytes)
}

pub fn parse(entity: &str, bytes: &[u8]) -> Result<Vec<Interface>, &'static str> {
    if !identifier(entity) || bytes.len() > 64 * 1024 {
        return Err("invalid_vm_interfaces");
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "invalid_vm_interfaces")?;
    let mut lines = text.lines().filter(|line| !line.trim().is_empty());
    if lines
        .next()
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        != Some(vec!["Interface", "Type", "Source", "Model", "MAC"])
        || !lines
            .next()
            .is_some_and(|line| line.trim().len() >= 5 && line.trim().bytes().all(|b| b == b'-'))
    {
        return Err("invalid_vm_interfaces");
    }
    let mut output = vec![];
    let mut names = std::collections::BTreeSet::new();
    for line in lines {
        let columns: Vec<_> = line.split_whitespace().collect();
        if columns.len() != 5 || output.len() >= 32 {
            return Err("invalid_vm_interfaces");
        }
        if columns[0] == "-" {
            continue;
        }
        let name = columns[0];
        if name.len() > 15
            || name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            || matches!(name, "." | "..")
            || !names.insert(name)
        {
            return Err("invalid_vm_interfaces");
        }
        let mac = mac(columns[4]).ok_or("invalid_vm_interfaces")?;
        if !matches!(columns[1], "bridge" | "network") {
            continue;
        }
        output.push(Interface {
            entity: entity.into(),
            name: name.into(),
            mac,
        });
    }
    Ok(output)
}

pub fn collect(
    machines: &[Machine],
    reader: &impl Reader,
    budget: &Budget<'_>,
) -> Result<Vec<Interface>, &'static str> {
    let mut output = vec![];
    for machine in machines
        .iter()
        .filter(|m| matches!(m.hypervisor, vm::Hypervisor::Libvirt))
    {
        budget.check()?;
        // Read live interfaces; --inactive would describe a future configuration.
        let rows = reader.read(Query::LibvirtInterfaces(machine.uuid.clone()), budget)?;
        let rows = parse(&machine.entity, &rows)?;
        for row in &rows {
            // A network/source name can contain escaped or multiline text in
            // domiflist output. Confirm each target independently by passing
            // its strictly validated name to the domain-scoped query.
            let link = reader.read(
                Query::LibvirtInterfaceLink {
                    vm_id: machine.uuid.clone(),
                    interface: row.name.clone(),
                },
                budget,
            )?;
            let link = std::str::from_utf8(&link).map_err(|_| "invalid_vm_interface_link")?;
            if link.trim() != format!("{} up", row.name) {
                return Err("unverified_vm_interface");
            }
        }
        if output.len() + rows.len() > 128 {
            return Err("vm_interface_limit");
        }
        output.extend(rows);
    }
    let mut names = std::collections::BTreeSet::new();
    if output.iter().any(|row| !names.insert(&row.name)) {
        return Err("ambiguous_vm_interface");
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    const HEADER: &str = " Interface   Type     Source   Model    MAC\n-------------------------------------------------------\n";
    #[test]
    fn live_interfaces_reject_ambiguity_paths_and_injected_rows_atomically() {
        let bytes = format!("{HEADER} vnet3 network default virtio 52:54:00:12:34:56\n");
        let rows = parse("vm/fixture", bytes.as_bytes()).unwrap();
        assert_eq!(rows[0].name, "vnet3");
        assert_eq!(rows[0].mac, [0x52, 0x54, 0, 0x12, 0x34, 0x56]);
        for row in [
            "../bad network default virtio 52:54:00:12:34:56",
            "vnet3 network default virtio ff:ff:ff:ff:ff:ff",
            "vnet3 network default virtio 52:54:00:12:34:56\nvnet3 network default virtio 52:54:00:12:34:56",
            "vnet3 network name with newline virtio 52:54:00:12:34:56",
            "vnet3 network default virtio 52:54:00:12:34:56\nImage: data:image/png",
        ] {
            assert!(
                parse("vm/fixture", format!("{HEADER}{row}\n").as_bytes()).is_err(),
                "accepted {row}"
            );
        }
        assert!(parse("vm/fixture", b"[]").is_err());
        assert!(parse("vm/fixture", HEADER.as_bytes()).unwrap().is_empty());
    }
    #[test]
    fn a_forged_table_row_cannot_bind_another_domains_interface() {
        struct Fixture;
        impl Reader for Fixture {
            fn read(&self, query: Query, _: &Budget<'_>) -> Result<Vec<u8>, &'static str> {
                match query {
                    Query::LibvirtInterfaces(_)=>Ok(format!("{HEADER} vnet3 network default virtio 52:54:00:12:34:56\n vnet4 network default virtio 52:54:00:12:34:57\n").into_bytes()),
                    Query::LibvirtInterfaceLink{interface,..} if interface=="vnet3"=>Ok(b"vnet3 up".to_vec()),
                    _=>Err("not_owned_by_domain"),
                }
            }
        }
        let stop = AtomicBool::new(false);
        let budget = Budget::new(Duration::from_secs(1), &stop);
        let machines = [Machine {
            uuid: "11111111-1111-4111-8111-111111111111".into(),
            entity: "vm/fixture".into(),
            hypervisor: vm::Hypervisor::Libvirt,
        }];
        assert_eq!(
            collect(&machines, &Fixture, &budget),
            Err("not_owned_by_domain")
        );
    }
}

#[cfg(target_os = "linux")]
pub use native::Guard;
#[cfg(target_os = "linux")]
mod native {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    pub struct Guard {
        pub interface: Interface,
        directory: std::fs::File,
        pub index: i32,
        address: Vec<u8>,
        pub deadline: Instant,
    }
    impl Guard {
        fn path(name: &str) -> std::path::PathBuf {
            std::path::Path::new("/sys/class/net").join(name)
        }
        fn index(name: &str) -> Option<i32> {
            let name = std::ffi::CString::new(name).ok()?;
            let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
            (index != 0 && index <= i32::MAX as u32).then_some(index as i32)
        }
        pub fn open(interface: Interface) -> Option<Self> {
            if interface.name.is_empty()
                || interface.name.len() > 15
                || !interface
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
                || matches!(interface.name.as_str(), "." | "..")
            {
                return None;
            }
            let path = Self::path(&interface.name);
            let directory = std::fs::File::open(&path).ok()?;
            let metadata = directory.metadata().ok()?;
            let flags = crate::host::read_limited(&path.join("tun_flags"), 32).ok()?;
            let flags = std::str::from_utf8(&flags)
                .ok()?
                .trim()
                .strip_prefix("0x")?;
            if !metadata.is_dir()
                || metadata.uid() != 0
                || u32::from_str_radix(flags, 16).ok()? & 2 == 0
            {
                return None;
            }
            let index = Self::index(&interface.name)?;
            let address = crate::host::read_limited(&path.join("address"), 32).ok()?;
            let binding = Self {
                interface,
                directory,
                index,
                address,
                deadline: Instant::now() + Duration::from_secs(60),
            };
            binding.current().then_some(binding)
        }
        pub fn current(&self) -> bool {
            if Instant::now() >= self.deadline
                || Self::index(&self.interface.name) != Some(self.index)
            {
                return false;
            }
            let path = Self::path(&self.interface.name);
            let Ok(current) = std::fs::metadata(&path) else {
                return false;
            };
            let Ok(original) = self.directory.metadata() else {
                return false;
            };
            current.dev() == original.dev()
                && current.ino() == original.ino()
                && crate::host::read_limited(&path.join("address"), 32)
                    .is_ok_and(|address| address == self.address)
        }
    }
}
