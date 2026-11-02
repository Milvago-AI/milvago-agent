//! A forwarded/NAT packet is not evidence of a host-originated TCP connection.
use milvago_discovery_collector::{host, tls::ClientHello};
use std::{ffi::CStr, net::IpAddr};

fn interface_address(index: i32, address: IpAddr) -> bool {
    if index <= 0 {
        return false;
    }
    struct Addresses(*mut libc::ifaddrs);
    impl Drop for Addresses {
        fn drop(&mut self) {
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
    let mut raw = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut raw) } != 0 {
        return false;
    }
    let _addresses = Addresses(raw);
    for _ in 0..4096 {
        let Some(entry) = (unsafe { raw.as_ref() }) else {
            break;
        };
        raw = entry.ifa_next;
        if entry.ifa_name.is_null() || entry.ifa_addr.is_null() {
            continue;
        }
        let name = unsafe { CStr::from_ptr(entry.ifa_name) };
        if name.to_bytes().len() >= libc::IFNAMSIZ
            || unsafe { libc::if_nametoindex(name.as_ptr()) } != index as u32
        {
            continue;
        }
        let family = unsafe { (*entry.ifa_addr).sa_family as i32 };
        let observed = match family {
            libc::AF_INET => {
                let value = unsafe { &*entry.ifa_addr.cast::<libc::sockaddr_in>() };
                IpAddr::V4(value.sin_addr.s_addr.to_ne_bytes().into())
            }
            libc::AF_INET6 => {
                let value = unsafe { &*entry.ifa_addr.cast::<libc::sockaddr_in6>() };
                IpAddr::V6(value.sin6_addr.s6_addr.into())
            }
            _ => continue,
        };
        if observed == address {
            return true;
        }
    }
    false
}

fn socket_table(bytes: &[u8], hello: &ClientHello) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    for line in text.lines().skip(1).take(16384) {
        if line.len() > 1024 {
            return false;
        }
        let fields: Vec<_> = line.split_whitespace().take(11).collect();
        if fields.len() < 10 || fields[3] != "01" {
            continue;
        }
        if host::parse_tcp_endpoint(fields[1]) == Some(hello.local)
            && host::parse_tcp_endpoint(fields[2]) == Some(hello.remote)
            && fields[9].parse::<u64>().is_ok_and(|inode| inode > 0)
        {
            return true;
        }
    }
    false
}

pub(super) fn matches(index: i32, hello: &ClientHello) -> bool {
    if hello.local.port() == 0
        || hello.remote.port() == 0
        || !interface_address(index, hello.local.ip())
    {
        return false;
    }
    // This is the observer's network namespace, not conntrack or a guest table.
    // Forwarded packets remain absent even after NAT rewrites their source.
    let table = if hello.local.is_ipv4() {
        "/proc/self/net/tcp"
    } else {
        "/proc/self/net/tcp6"
    };
    host::read_limited(std::path::Path::new(table), 2 * 1024 * 1024)
        .is_ok_and(|bytes| socket_table(&bytes, hello))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    #[test]
    fn a_real_host_socket_is_required_in_addition_to_the_outgoing_address() {
        for address in ["127.0.0.1:0", "[::1]:0"] {
            let listener = TcpListener::bind(address).unwrap();
            let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (_server, _) = listener.accept().unwrap();
            let index = unsafe { libc::if_nametoindex(c"lo".as_ptr()) } as i32;
            assert!(index > 0);
            let mut hello = ClientHello {
                local: client.local_addr().unwrap(),
                remote: client.peer_addr().unwrap(),
                hostname: "api.openai.com".into(),
            };
            assert!(matches(index, &hello));
            assert!(!matches(999999, &hello));
            // A NAT/forwarded tuple has no socket in the observer's namespace.
            hello.local.set_port(1);
            assert!(!matches(index, &hello));
            hello.local = client.local_addr().unwrap();
            drop(client);
            assert!(!matches(index, &hello));
        }
    }

    #[test]
    fn socket_metadata_requires_an_exact_established_tuple_and_nonzero_inode() {
        let hello = ClientHello {
            local: "127.0.0.1:30000".parse().unwrap(),
            remote: "127.0.0.1:443".parse().unwrap(),
            hostname: "api.openai.com".into(),
        };
        for (state, inode, expected) in [
            ("01", "42", true),
            ("0A", "42", false),
            ("01", "0", false),
            ("01", "image/png", false),
        ] {
            let row = format!("header\n0: 0100007F:7530 0100007F:01BB {state} 0 0 0 0 0 {inode}\n");
            assert_eq!(socket_table(row.as_bytes(), &hello), expected);
        }
        assert!(!socket_table(b"image/png\ninvalid", &hello));
    }
}
