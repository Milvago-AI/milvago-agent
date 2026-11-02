//! A DHCP/ARP mapping is only a candidate. Confirm the probe's exact TCP tuple
//! on the hypervisor-mapped ingress TAP before claiming a guest response origin.
use crate::{http::Connection, vm_network::Guard};
use std::{
    net::{IpAddr, SocketAddr},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

pub(crate) struct Witness(OwnedFd);

fn filter(remote: SocketAddr) -> Vec<libc::sock_filter> {
    if let IpAddr::V6(ip) = remote.ip() {
        return filter_v6(ip, remote.port());
    }
    let IpAddr::V4(ip) = remote.ip() else {
        return vec![];
    };
    let mut code = vec![];
    let mut checks = vec![];
    let op = |code: &mut Vec<libc::sock_filter>, instruction, k| {
        code.push(libc::sock_filter {
            code: instruction,
            jt: 0,
            jf: 0,
            k,
        })
    };
    let check = |code: &mut Vec<libc::sock_filter>, checks: &mut Vec<usize>, value| {
        checks.push(code.len());
        code.push(libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 0,
            k: value,
        });
    };
    op(&mut code, 0x30, 0);
    op(&mut code, 0x54, 0xf0);
    check(&mut code, &mut checks, 0x40);
    op(&mut code, 0x30, 9);
    check(&mut code, &mut checks, 6);
    op(&mut code, 0x28, 6);
    op(&mut code, 0x54, 0x3fff);
    check(&mut code, &mut checks, 0);
    op(&mut code, 0x20, 12);
    check(&mut code, &mut checks, u32::from(ip));
    op(&mut code, 0xb1, 0);
    op(&mut code, 0x48, 0);
    check(&mut code, &mut checks, remote.port() as u32);
    op(&mut code, 0x50, 13);
    op(&mut code, 0x54, 0x3f);
    check(&mut code, &mut checks, 0x12);
    // Return only the IPv4 header and first twenty TCP bytes. Even TCP Fast
    // Open data or options coalesced with a SYN-ACK cannot expose application data.
    op(&mut code, 0x87, 0);
    op(&mut code, 0x04, 20);
    op(&mut code, 0x16, 0);
    let drop = code.len();
    op(&mut code, 0x06, 0);
    for index in checks {
        code[index].jf = (drop - index - 1) as u8;
    }
    code
}

fn filter_v6(ip: std::net::Ipv6Addr, port: u16) -> Vec<libc::sock_filter> {
    let mut code = vec![];
    let op = |code: &mut Vec<libc::sock_filter>, instruction, k| {
        code.push(libc::sock_filter {
            code: instruction,
            jt: 0,
            jf: 0,
            k,
        });
    };
    // Extension headers and jumbograms are deliberately outside this witness.
    // Validate the declared minimum TCP header before retaining its fixed prefix.
    for (instruction, value) in [
        (0x30, 0),
        (0x54, 0xf0),
        (0x15, 0x60),
        (0x30, 6),
        (0x15, 6),
        (0x28, 4),
        (0x35, 20),
        (0x30, 52),
        (0x54, 0xf0),
        (0x35, 0x50),
        (0x74, 2),
        (0x07, 0),
        (0x28, 4),
        (0x3d, 0),
    ] {
        op(&mut code, instruction, value);
    }
    for (offset, chunk) in ip.octets().chunks_exact(4).enumerate() {
        op(&mut code, 0x20, (8 + offset * 4) as u32);
        op(
            &mut code,
            0x15,
            u32::from_be_bytes(chunk.try_into().unwrap()),
        );
    }
    for (instruction, value) in [
        (0x28, 40),
        (0x15, port as u32),
        (0x30, 53),
        (0x54, 0x3f),
        (0x15, 0x12),
        // Exactly 40 IPv6 bytes and 20 TCP bytes: no options or Fast Open data.
        (0x06, 60),
    ] {
        op(&mut code, instruction, value);
    }
    let drop = code.len();
    op(&mut code, 0x06, 0);
    for (index, instruction) in code[..drop].iter_mut().enumerate() {
        if matches!(instruction.code, 0x15 | 0x35 | 0x3d) {
            instruction.jf = (drop - index - 1) as u8;
        }
    }
    code
}

pub(crate) fn matches(bytes: &[u8], connection: &Connection) -> bool {
    if let (IpAddr::V6(remote), IpAddr::V6(local)) = (connection.remote.ip(), connection.local.ip())
    {
        return bytes.len() >= 60
            && bytes[0] >> 4 == 6
            && bytes[6] == 6
            && bytes[52] >> 4 >= 5
            && u16::from_be_bytes([bytes[4], bytes[5]]) >= (bytes[52] >> 4) as u16 * 4
            && bytes[8..24] == remote.octets()
            && bytes[24..40] == local.octets()
            && u16::from_be_bytes([bytes[40], bytes[41]]) == connection.remote.port()
            && u16::from_be_bytes([bytes[42], bytes[43]]) == connection.local.port()
            && bytes[53] & 0x3f == 0x12;
    }
    let (IpAddr::V4(remote), IpAddr::V4(local)) = (connection.remote.ip(), connection.local.ip())
    else {
        return false;
    };
    if bytes.len() < 40
        || bytes[0] >> 4 != 4
        || bytes[9] != 6
        || u16::from_be_bytes([bytes[6], bytes[7]]) & 0x3fff != 0
    {
        return false;
    }
    let offset = (bytes[0] & 15) as usize * 4;
    offset >= 20
        && bytes.len() >= offset + 20
        && bytes[12..16] == remote.octets()
        && bytes[16..20] == local.octets()
        && u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) == connection.remote.port()
        && u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]) == connection.local.port()
        && bytes[offset + 13] & 0x3f == 0x12
}

impl Witness {
    pub(crate) fn open(guard: &Guard, remote: SocketAddr) -> Option<Self> {
        if !guard.current() {
            return None;
        }
        let witness = Self::socket(guard.index, remote)?;
        guard.current().then_some(witness)
    }

    fn socket(index: i32, remote: SocketAddr) -> Option<Self> {
        if index <= 0 {
            return None;
        }
        let raw = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if raw < 0 {
            return None;
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut code = filter(remote);
        let program = libc::sock_fprog {
            len: code.len() as u16,
            filter: code.as_mut_ptr(),
        };
        let receive = 8192i32;
        let locked = 1i32;
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
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    option,
                    value,
                    size as libc::socklen_t,
                )
            } != 0
            {
                return None;
            }
        }
        let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        address.sll_family = libc::AF_PACKET as u16;
        address.sll_protocol = (if remote.is_ipv4() {
            libc::ETH_P_IP
        } else {
            libc::ETH_P_IPV6
        } as u16)
            .to_be();
        address.sll_ifindex = index;
        if unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&address as *const libc::sockaddr_ll).cast(),
                std::mem::size_of_val(&address) as libc::socklen_t,
            )
        } != 0
        {
            return None;
        }
        Some(Self(fd))
    }

    pub(crate) fn confirms(&self, guard: &Guard, connection: &Connection) -> bool {
        if !guard.current() {
            return false;
        }
        for _ in 0..16 {
            let mut bytes = [0u8; 80];
            let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            let mut length = std::mem::size_of_val(&address) as libc::socklen_t;
            let received = unsafe {
                libc::recvfrom(
                    self.0.as_raw_fd(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                    0,
                    (&mut address as *mut libc::sockaddr_ll).cast(),
                    &mut length,
                )
            };
            if received < 0 {
                return false;
            }
            if length as usize >= std::mem::size_of::<libc::sockaddr_ll>()
                && address.sll_ifindex == guard.index
                && [libc::PACKET_HOST as u8, libc::PACKET_OTHERHOST as u8]
                    .contains(&address.sll_pkttype)
                && address.sll_halen == 6
                && address.sll_addr[..6] == guard.interface.mac
                && matches(&bytes[..received as usize], connection)
                && guard.current()
            {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn an_arp_match_does_not_substitute_for_the_actual_probe_tcp_tuple() {
        let connection = Connection {
            remote: "192.168.122.2:32145".parse().unwrap(),
            local: "192.168.122.1:54321".parse().unwrap(),
        };
        let mut bytes = [0u8; 40];
        bytes[0] = 0x45;
        bytes[9] = 6;
        bytes[12..16].copy_from_slice(&[192, 168, 122, 2]);
        bytes[16..20].copy_from_slice(&[192, 168, 122, 1]);
        bytes[20..22].copy_from_slice(&32145u16.to_be_bytes());
        bytes[22..24].copy_from_slice(&54321u16.to_be_bytes());
        bytes[33] = 0x12;
        assert!(matches(&bytes, &connection));
        for index in [0, 9, 12, 16, 20, 22, 33] {
            let mut wrong = bytes;
            wrong[index] ^= 1;
            assert!(!matches(&wrong, &connection), "index {index}");
        }
        assert!(!matches(&bytes[..39], &connection));
        bytes[6] = 0x20;
        assert!(!matches(&bytes, &connection));
    }

    #[test]
    fn ipv6_witness_requires_the_complete_tuple_and_direct_tcp_header() {
        let connection = Connection {
            remote: "[fd42::2]:32145".parse().unwrap(),
            local: "[fd42::1]:54321".parse().unwrap(),
        };
        let mut bytes = [0u8; 60];
        bytes[0] = 0x60;
        bytes[4..6].copy_from_slice(&20u16.to_be_bytes());
        bytes[6] = 6;
        bytes[8..24].copy_from_slice(&"fd42::2".parse::<std::net::Ipv6Addr>().unwrap().octets());
        bytes[24..40].copy_from_slice(&"fd42::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
        bytes[40..42].copy_from_slice(&32145u16.to_be_bytes());
        bytes[42..44].copy_from_slice(&54321u16.to_be_bytes());
        bytes[52] = 0x50;
        bytes[53] = 0x12;
        assert!(matches(&bytes, &connection));
        for index in [0, 6, 8, 24, 40, 42, 53] {
            let mut wrong = bytes;
            wrong[index] ^= if index == 0 { 0x10 } else { 1 };
            assert!(!matches(&wrong, &connection), "index {index}");
        }
        let mut traffic_class = bytes;
        traffic_class[0] |= 15;
        traffic_class[1..4].fill(255);
        assert!(matches(&traffic_class, &connection));
        for length in [0u16, 19] {
            let mut wrong = bytes;
            wrong[4..6].copy_from_slice(&length.to_be_bytes());
            assert!(!matches(&wrong, &connection));
        }
        for offset in [0x40, 0xf0] {
            let mut wrong = bytes;
            wrong[52] = offset;
            assert!(!matches(&wrong, &connection));
        }
        for next in [0, 43, 44, 50, 51, 60] {
            let mut extension = bytes;
            extension[6] = next;
            assert!(!matches(&extension, &connection));
        }
        assert!(!matches(&bytes[..59], &connection));
    }

    #[test]
    #[ignore = "Required isolated NET_RAW qualification: --vm-network --components -- --include-ignored"]
    fn kernel_admits_only_syn_ack_headers_and_never_the_http_response_payload() {
        use std::{
            io::{Read, Write},
            net::{TcpListener, TcpStream},
            time::Duration,
        };
        for address in ["127.0.0.1:0", "[::1]:0"] {
            let listener = TcpListener::bind(address).unwrap();
            let remote = listener.local_addr().unwrap();
            let index = unsafe { libc::if_nametoindex(c"lo".as_ptr()) } as i32;
            let witness = Witness::socket(index, remote).expect("isolated NET_RAW is required");
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = [0u8; 64];
                let _ = stream.read(&mut request).unwrap();
                stream.write_all(&vec![b'X'; 4096]).unwrap();
            });
            let mut client = TcpStream::connect(remote).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let connection = Connection {
                remote,
                local: client.local_addr().unwrap(),
            };
            client.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
            let mut body = [0u8; 4096];
            client.read_exact(&mut body).unwrap();
            server.join().unwrap();
            let mut admitted = 0;
            loop {
                let mut bytes = [0u8; 4096];
                let size = unsafe {
                    libc::recv(
                        witness.0.as_raw_fd(),
                        bytes.as_mut_ptr().cast(),
                        bytes.len(),
                        0,
                    )
                };
                if size < 0 {
                    assert_eq!(
                        std::io::Error::last_os_error().kind(),
                        std::io::ErrorKind::WouldBlock
                    );
                    break;
                }
                admitted += 1;
                assert_eq!(
                    size,
                    if remote.is_ipv4() { 40 } else { 60 },
                    "kernel copied TCP options or application data"
                );
                assert!(matches(&bytes[..size as usize], &connection));
                assert!(
                    !bytes[..size as usize]
                        .windows(16)
                        .any(|part| part == [b'X'; 16])
                );
                assert!(admitted <= 4, "filter admitted non-handshake traffic");
            }
            assert!(
                admitted >= 1,
                "the actual SYN-ACK did not reach the metadata witness"
            );
        }
    }
}
