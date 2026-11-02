//! Bounded recognition of visible TLS ClientHello metadata. No TLS keys,
//! application records, HTTP bodies or DNS-to-IP guesses are consumed.
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

#[derive(Debug, PartialEq, Eq)]
pub struct ClientHello {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub hostname: String,
}
struct Cursor<'a> {
    bytes: &'a [u8],
}
impl<'a> Cursor<'a> {
    fn take(&mut self, size: usize) -> Result<&'a [u8], &'static str> {
        if size > self.bytes.len() {
            return Err("truncated_metadata");
        }
        let (head, tail) = self.bytes.split_at(size);
        self.bytes = tail;
        Ok(head)
    }
    fn byte(&mut self) -> Result<u8, &'static str> {
        Ok(self.take(1)?[0])
    }
    fn word(&mut self) -> Result<usize, &'static str> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]) as usize)
    }
}
fn host(value: &[u8]) -> Result<String, &'static str> {
    if value.is_empty() || value.len() > 253 || !value.is_ascii() {
        return Err("invalid_server_name");
    }
    let value = std::str::from_utf8(value)
        .map_err(|_| "invalid_server_name")?
        .strip_suffix('.')
        .unwrap_or(std::str::from_utf8(value).map_err(|_| "invalid_server_name")?);
    if !value.contains('.')
        || value.parse::<IpAddr>().is_ok()
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err("invalid_server_name");
    }
    Ok(value.to_ascii_lowercase())
}

pub fn server_name(record: &[u8]) -> Result<Option<String>, &'static str> {
    if record.len() > 65535 {
        return Err("metadata_limit");
    }
    let mut cursor = Cursor { bytes: record };
    if cursor.byte()? != 22 {
        return Ok(None);
    }
    let version = cursor.take(2)?;
    if version[0] != 3 || version[1] > 4 {
        return Ok(None);
    }
    let size = cursor.word()?;
    if size > 16384 {
        return Err("metadata_limit");
    }
    let mut hello = Cursor {
        bytes: cursor.take(size)?,
    };
    if hello.byte()? != 1 {
        return Ok(None);
    }
    let size = hello.take(3)?;
    let size = ((size[0] as usize) << 16) | ((size[1] as usize) << 8) | size[2] as usize;
    let mut hello = Cursor {
        bytes: hello.take(size)?,
    };
    if hello.take(2)?[0] != 3 {
        return Ok(None);
    }
    hello.take(32)?;
    let session = hello.byte()? as usize;
    if session > 32 {
        return Err("invalid_client_hello");
    }
    hello.take(session)?;
    let ciphers = hello.word()?;
    if ciphers < 2 || ciphers % 2 != 0 {
        return Err("invalid_client_hello");
    }
    hello.take(ciphers)?;
    let compression = hello.byte()? as usize;
    if compression == 0 {
        return Err("invalid_client_hello");
    }
    hello.take(compression)?;
    if hello.bytes.is_empty() {
        return Ok(None);
    }
    let extensions = hello.word()?;
    if extensions != hello.bytes.len() {
        return Err("invalid_extensions");
    }
    let mut extensions = Cursor {
        bytes: hello.take(extensions)?,
    };
    let mut seen = BTreeSet::new();
    let mut name = None;
    let mut ech = false;
    while !extensions.bytes.is_empty() {
        let kind = extensions.word()?;
        let size = extensions.word()?;
        let bytes = extensions.take(size)?;
        if seen.len() >= 128 || !seen.insert(kind) {
            return Err("invalid_extensions");
        }
        if kind == 0xfe0d {
            ech = true;
        }
        if kind != 0 {
            continue;
        }
        let mut names = Cursor { bytes };
        let size = names.word()?;
        if size != names.bytes.len() || size == 0 {
            return Err("invalid_server_name");
        }
        while !names.bytes.is_empty() {
            let kind = names.byte()?;
            let size = names.word()?;
            let value = names.take(size)?;
            if kind != 0 || name.is_some() {
                return Err("invalid_server_name");
            }
            name = Some(host(value)?);
        }
    }
    // An ECH outer name does not establish the actual intended provider.
    Ok(if ech { None } else { name })
}

/// IP datagram from a metadata sensor; TCP reassembly is deliberately outside
/// this parser. Fragmented/truncated/encrypted handshakes remain a visibility gap.
pub fn ip_client_hello(packet: &[u8]) -> Result<Option<ClientHello>, &'static str> {
    if packet.len() > 65535 {
        return Err("metadata_limit");
    }
    let Some(first) = packet.first() else {
        return Err("truncated_metadata");
    };
    let (local, remote, tcp) = match first >> 4 {
        4 => {
            if packet.len() < 20 {
                return Err("truncated_metadata");
            }
            let header = ((first & 15) as usize) * 4;
            let total = u16::from_be_bytes([packet[2], packet[3]]) as usize;
            if header < 20 || total < header || header > packet.len() {
                return Err("invalid_ip_metadata");
            }
            if packet[9] != 6 || u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0 {
                return Ok(None);
            }
            (
                IpAddr::V4(Ipv4Addr::new(
                    packet[12], packet[13], packet[14], packet[15],
                )),
                IpAddr::V4(Ipv4Addr::new(
                    packet[16], packet[17], packet[18], packet[19],
                )),
                &packet[header..total.min(packet.len())],
            )
        }
        6 => {
            if packet.len() < 40 {
                return Err("truncated_metadata");
            }
            let total = 40 + u16::from_be_bytes([packet[4], packet[5]]) as usize;
            if packet[6] != 6 {
                return Ok(None);
            }
            let local = Ipv6Addr::from(
                <[u8; 16]>::try_from(&packet[8..24]).map_err(|_| "invalid_ip_metadata")?,
            );
            let remote = Ipv6Addr::from(
                <[u8; 16]>::try_from(&packet[24..40]).map_err(|_| "invalid_ip_metadata")?,
            );
            (
                IpAddr::V6(local),
                IpAddr::V6(remote),
                &packet[40..total.min(packet.len())],
            )
        }
        _ => return Ok(None),
    };
    if tcp.len() < 20 {
        return Err("truncated_metadata");
    }
    let header = ((tcp[12] >> 4) as usize) * 4;
    if header < 20 || header > tcp.len() {
        return Err("invalid_tcp_metadata");
    }
    if tcp[13] & 0x10 == 0 || tcp[13] & 0x06 != 0 {
        return Ok(None);
    }
    let local = SocketAddr::new(local, u16::from_be_bytes([tcp[0], tcp[1]]));
    let remote = SocketAddr::new(remote, u16::from_be_bytes([tcp[2], tcp[3]]));
    if local.port() == 0 || remote.port() == 0 {
        return Err("invalid_tcp_metadata");
    }
    Ok(server_name(&tcp[header..])?.map(|hostname| ClientHello {
        local,
        remote,
        hostname,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record(host: &[u8], ech: bool) -> Vec<u8> {
        let mut names = vec![0];
        names.extend_from_slice(&(host.len() as u16).to_be_bytes());
        names.extend_from_slice(host);
        let mut extension = vec![];
        extension.extend_from_slice(&(names.len() as u16).to_be_bytes());
        extension.extend(names);
        let mut extensions = vec![0, 0];
        extensions.extend_from_slice(&(extension.len() as u16).to_be_bytes());
        extensions.extend(extension);
        if ech {
            extensions.extend_from_slice(&[0xfe, 0x0d, 0, 0]);
        }
        let mut hello = vec![3, 3];
        hello.extend_from_slice(&[0; 32]);
        hello.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0]);
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend(extensions);
        let mut handshake = vec![
            1,
            0,
            ((hello.len() >> 8) & 255) as u8,
            (hello.len() & 255) as u8,
        ];
        handshake.extend(hello);
        let mut record = vec![22, 3, 1];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend(handshake);
        record
    }
    #[test]
    fn client_hello_extracts_only_visible_exact_hostname() {
        let mut bytes = record(b"API.OPENAI.COM.", false);
        bytes.extend_from_slice(b"PRIVATE_APPLICATION_DATA");
        assert_eq!(server_name(&bytes).unwrap(), Some("api.openai.com".into()));
        assert!(
            server_name(&record(b"api.openai.com", true))
                .unwrap()
                .is_none()
        );
        for host in [
            b"api.openai.com:443".as_slice(),
            b"api.openai.com/path",
            b"127.0.0.1",
            b"-api.openai.com",
            b"api..openai.com",
            b"api.openai.com\0evil",
        ] {
            assert!(server_name(&record(host, false)).is_err());
        }
    }
    #[test]
    fn truncation_and_random_metadata_never_panics() {
        let bytes = record(b"api.openai.com", false);
        for length in 0..bytes.len() {
            assert!(server_name(&bytes[..length]).is_err());
        }
        for position in 0..bytes.len() {
            for value in [0, 1, 127, 255] {
                let mut mutated = bytes.clone();
                mutated[position] = value;
                let _ = server_name(&mutated);
            }
        }
        let mut state = 91u32;
        for length in 0..2048 {
            let mut bytes = vec![0; length];
            for value in &mut bytes {
                state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                *value = (state >> 24) as u8;
            }
            let _ = server_name(&bytes);
            let _ = ip_client_hello(&bytes);
        }
    }
    #[test]
    fn tcp_ipv4_and_ipv6_require_connection_metadata() {
        for ipv6 in [false, true] {
            let header = if ipv6 { 40 } else { 20 };
            let record = record(b"api.openai.com", false);
            let mut packet = vec![0; header + 20];
            packet[0] = if ipv6 { 0x60 } else { 0x45 };
            packet[if ipv6 { 6 } else { 9 }] = 6;
            let length = (packet.len() + record.len() - if ipv6 { 40 } else { 0 }) as u16;
            let offset = if ipv6 { 4 } else { 2 };
            packet[offset..offset + 2].copy_from_slice(&length.to_be_bytes());
            packet[header..header + 4].copy_from_slice(&[0xc0, 0, 1, 0xbb]);
            packet[header + 12] = 0x50;
            packet[header + 13] = 0x18;
            packet.extend(record);
            assert_eq!(
                ip_client_hello(&packet).unwrap().unwrap().hostname,
                "api.openai.com"
            );
            packet[header + 13] = 2;
            assert!(ip_client_hello(&packet).unwrap().is_none());
        }
    }
}
