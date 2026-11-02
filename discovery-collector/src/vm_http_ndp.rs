//! Read one kernel neighbor entry; never receive application packets or dump a network.
use std::{
    net::Ipv6Addr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::atomic::{AtomicU32, Ordering},
    time::{Duration, Instant},
};

pub(super) fn device_index(name: &str) -> Option<i32> {
    if name.is_empty()
        || name.len() > 15
        || matches!(name, "." | "..")
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
    {
        return None;
    }
    let name = std::ffi::CString::new(name).ok()?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    (index > 0 && index <= i32::MAX as u32).then_some(index as i32)
}

fn reply(bytes: &[u8], sequence: u32, port: u32, index: i32, ip: Ipv6Addr) -> Option<[u8; 6]> {
    if bytes.len() < 28 || bytes.len() > 4096 || sequence == 0 || port == 0 || index <= 0 {
        return None;
    }
    let length = u32::from_ne_bytes(bytes[..4].try_into().ok()?) as usize;
    if length < 28
        || length > bytes.len()
        || ((length + 3) & !3) != bytes.len()
        || u16::from_ne_bytes(bytes[4..6].try_into().ok()?) != 28
        || u16::from_ne_bytes(bytes[6..8].try_into().ok()?) != 0
        || u32::from_ne_bytes(bytes[8..12].try_into().ok()?) != sequence
        || u32::from_ne_bytes(bytes[12..16].try_into().ok()?) != port
        || bytes[16] != libc::AF_INET6 as u8
        || i32::from_ne_bytes(bytes[20..24].try_into().ok()?) != index
        || ![2u16, 4, 8, 16, 128].contains(&u16::from_ne_bytes(bytes[24..26].try_into().ok()?))
        || bytes[26] & 8 != 0
    {
        return None;
    }
    let mut address = None;
    let mut mac = None;
    let mut offset = 28;
    while offset < length {
        if length - offset < 4 {
            return None;
        }
        let size = u16::from_ne_bytes(bytes[offset..offset + 2].try_into().ok()?) as usize;
        let kind = u16::from_ne_bytes(bytes[offset + 2..offset + 4].try_into().ok()?);
        if size < 4 || size > length - offset {
            return None;
        }
        let payload = &bytes[offset + 4..offset + size];
        match kind {
            1 => {
                if address.is_some() || payload.len() != 16 {
                    return None;
                }
                address = Some(<[u8; 16]>::try_from(payload).ok()?);
            }
            2 => {
                if mac.is_some() || payload.len() != 6 {
                    return None;
                }
                mac = Some(<[u8; 6]>::try_from(payload).ok()?);
            }
            _ => (),
        }
        offset += (size + 3) & !3;
        if offset > length {
            return None;
        }
    }
    let mac = mac?;
    (address? == ip.octets() && mac != [0; 6] && mac[0] & 1 == 0).then_some(mac)
}

pub(super) fn lookup(ip: Ipv6Addr, index: i32, deadline: Instant) -> Option<[u8; 6]> {
    if index <= 0 || Instant::now() >= deadline {
        return None;
    }
    let deadline = deadline.min(Instant::now() + Duration::from_millis(25));
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            libc::NETLINK_ROUTE,
        )
    };
    if raw < 0 {
        return None;
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let receive = 8192i32;
    if unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&receive as *const i32).cast(),
            std::mem::size_of_val(&receive) as libc::socklen_t,
        )
    } != 0
    {
        return None;
    }
    let mut local: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    local.nl_family = libc::AF_NETLINK as u16;
    if unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&local as *const libc::sockaddr_nl).cast(),
            std::mem::size_of_val(&local) as libc::socklen_t,
        )
    } != 0
    {
        return None;
    }
    let mut size = std::mem::size_of_val(&local) as libc::socklen_t;
    if unsafe {
        libc::getsockname(
            fd.as_raw_fd(),
            (&mut local as *mut libc::sockaddr_nl).cast(),
            &mut size,
        )
    } != 0
        || size as usize != std::mem::size_of_val(&local)
        || local.nl_family != libc::AF_NETLINK as u16
        || local.nl_pid == 0
        || local.nl_groups != 0
    {
        return None;
    }
    static SEQUENCE: AtomicU32 = AtomicU32::new(1);
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    if sequence == 0 {
        return None;
    }
    let mut request = [0u8; 48];
    request[..4].copy_from_slice(&48u32.to_ne_bytes());
    request[4..6].copy_from_slice(&30u16.to_ne_bytes());
    request[6..8].copy_from_slice(&1u16.to_ne_bytes());
    request[8..12].copy_from_slice(&sequence.to_ne_bytes());
    request[12..16].copy_from_slice(&local.nl_pid.to_ne_bytes());
    request[16] = libc::AF_INET6 as u8;
    request[20..24].copy_from_slice(&index.to_ne_bytes());
    request[28..30].copy_from_slice(&20u16.to_ne_bytes());
    request[30..32].copy_from_slice(&1u16.to_ne_bytes());
    request[32..48].copy_from_slice(&ip.octets());
    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as u16;
    if unsafe {
        libc::sendto(
            fd.as_raw_fd(),
            request.as_ptr().cast(),
            request.len(),
            0,
            (&kernel as *const libc::sockaddr_nl).cast(),
            std::mem::size_of_val(&kernel) as libc::socklen_t,
        )
    } != request.len() as isize
    {
        return None;
    }
    let remaining = deadline.checked_duration_since(Instant::now())?;
    let mut poll = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    if unsafe { libc::poll(&mut poll, 1, remaining.as_millis().clamp(1, 25) as i32) } != 1
        || poll.revents != libc::POLLIN
        || Instant::now() >= deadline
    {
        return None;
    }
    let mut bytes = [0u8; 4096];
    let mut sender: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of_val(&sender) as libc::socklen_t;
    let count = unsafe {
        libc::recvfrom(
            fd.as_raw_fd(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
            libc::MSG_TRUNC,
            (&mut sender as *mut libc::sockaddr_nl).cast(),
            &mut size,
        )
    };
    if count < 0
        || count as usize > bytes.len()
        || size as usize != std::mem::size_of_val(&sender)
        || sender.nl_family != libc::AF_NETLINK as u16
        || sender.nl_pid != 0
        || sender.nl_groups != 0
    {
        return None;
    }
    reply(&bytes[..count as usize], sequence, local.nl_pid, index, ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    const MAC: [u8; 6] = [0x52, 0x54, 0, 0x12, 0x34, 0x56];
    fn message(ip: Ipv6Addr) -> Vec<u8> {
        let mut bytes = vec![0; 60];
        bytes[..4].copy_from_slice(&60u32.to_ne_bytes());
        bytes[4..6].copy_from_slice(&28u16.to_ne_bytes());
        bytes[8..12].copy_from_slice(&7u32.to_ne_bytes());
        bytes[12..16].copy_from_slice(&42u32.to_ne_bytes());
        bytes[16] = libc::AF_INET6 as u8;
        bytes[20..24].copy_from_slice(&5i32.to_ne_bytes());
        bytes[24..26].copy_from_slice(&2u16.to_ne_bytes());
        bytes[28..30].copy_from_slice(&20u16.to_ne_bytes());
        bytes[30..32].copy_from_slice(&1u16.to_ne_bytes());
        bytes[32..48].copy_from_slice(&ip.octets());
        bytes[48..50].copy_from_slice(&10u16.to_ne_bytes());
        bytes[50..52].copy_from_slice(&2u16.to_ne_bytes());
        bytes[52..58].copy_from_slice(&MAC);
        bytes
    }
    #[test]
    fn ipv6_neighbor_reply_requires_exact_kernel_context_and_complete_attributes() {
        let ip = "fd42::2".parse().unwrap();
        let original = message(ip);
        assert_eq!(reply(&original, 7, 42, 5, ip), Some(MAC));
        for end in 0..original.len() {
            assert!(reply(&original[..end], 7, 42, 5, ip).is_none());
        }
        for index in [0, 4, 6, 8, 12, 16, 20, 28, 30, 32, 48, 50] {
            let mut bytes = original.clone();
            bytes[index] ^= 1;
            assert!(reply(&bytes, 7, 42, 5, ip).is_none(), "offset {index}");
        }
        for state in [2u16, 4, 8, 16, 128] {
            let mut bytes = original.clone();
            bytes[24..26].copy_from_slice(&state.to_ne_bytes());
            assert_eq!(reply(&bytes, 7, 42, 5, ip), Some(MAC));
        }
        for state in [0u16, 1, 32, 64, 3, 130, u16::MAX] {
            let mut bytes = original.clone();
            bytes[24..26].copy_from_slice(&state.to_ne_bytes());
            assert!(reply(&bytes, 7, 42, 5, ip).is_none());
        }
        let mut proxy = original.clone();
        proxy[26] = 8;
        assert!(reply(&proxy, 7, 42, 5, ip).is_none());
        let mut duplicate = original.clone();
        duplicate.extend_from_slice(&original[48..]);
        let size = duplicate.len() as u32;
        duplicate[..4].copy_from_slice(&size.to_ne_bytes());
        assert!(reply(&duplicate, 7, 42, 5, ip).is_none());
        let mut duplicate = original.clone();
        duplicate.extend_from_slice(&original[28..48]);
        let size = duplicate.len() as u32;
        duplicate[..4].copy_from_slice(&size.to_ne_bytes());
        assert!(reply(&duplicate, 7, 42, 5, ip).is_none());
        for mac in [[0; 6], [255; 6]] {
            let mut bytes = original.clone();
            bytes[52..58].copy_from_slice(&mac);
            assert!(reply(&bytes, 7, 42, 5, ip).is_none());
        }
        assert!(reply(b"data:image/png", 7, 42, 5, ip).is_none());
        assert!(reply(&vec![0; 4097], 7, 42, 5, ip).is_none());
        assert!(reply(&original, 0, 42, 5, ip).is_none());
        assert!(reply(&original, 7, 0, 5, ip).is_none());
        assert!(reply(&original, 7, 42, 0, ip).is_none());
    }
    #[test]
    fn ipv6_neighbor_kernel_misses_and_expired_work_do_not_retain_descriptors() {
        let count = || std::fs::read_dir("/proc/self/fd").unwrap().count();
        let before = count();
        let index = device_index("lo").unwrap();
        for _ in 0..64 {
            assert!(
                lookup(
                    "fd42::2".parse().unwrap(),
                    index,
                    Instant::now() + Duration::from_millis(30)
                )
                .is_none()
            );
        }
        assert_eq!(count(), before);
        assert!(lookup("::1".parse().unwrap(), index, Instant::now()).is_none());
        for name in ["", ".", "..", "lo/../x", "image:png", "lo\n"] {
            assert!(device_index(name).is_none());
        }
    }
}
