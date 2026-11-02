//! Read-only distribution of browser packages embedded in this signed release.
//! No remote fetch, upload, mutable package directory or proxy.
use crate::Result;
use rustls::{ServerConnection, StreamOwned};

use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
include!(concat!(env!("OUT_DIR"), "/extension_bundle.rs"));
const REQUEST_LIMIT: usize = 8192;

pub fn info() -> Result<serde_json::Value> {
    if CRX.is_empty() || XPI.is_empty() {
        return Err("this build has no embedded extensions".into());
    }
    Ok(serde_json::json!({
        "edition": EDITION, "version": VERSION, "origin": ORIGIN,
        "firefox_origin": FIREFOX_ORIGIN, "firefox_id": FIREFOX_ID, "firefox_version": FIREFOX_VERSION,
        "firefox_install_url": format!("{FIREFOX_ORIGIN}/ext/{FIREFOX_VERSION}/milvago.xpi"),
        "chromium_id": CHROMIUM_ID, "embedded": true,
        "crx_size": CRX.len(), "crx_sha256": crate::sha256_hex(CRX),
        "xpi_size": XPI.len(), "xpi_sha256": crate::sha256_hex(XPI),
    }))
}

pub struct Server {
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

/// Browsers whose machine policy no longer force-installs this release's extension.
/// Group Policy rewrites whole lists: an organization GPO that owns
/// `ExtensionInstallForcelist` (or Firefox's `ExtensionSettings`) silently removes what
/// the installer wrote, and the browser then uninstalls the extension. Read-only: the
/// fix belongs in the organization's GPO, which the documentation describes.
#[cfg(windows)]
fn missing_policies() -> Vec<&'static str> {
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn RegOpenKeyExW(key: isize, sub: *const u16, options: u32, access: u32, result: *mut isize) -> i32;
        fn RegEnumValueW(key: isize, index: u32, name: *mut u16, name_len: *mut u32, reserved: *mut u32, kind: *mut u32, data: *mut u8, data_len: *mut u32) -> i32;
        fn RegGetValueW(key: isize, sub: *const u16, value: *const u16, flags: u32, kind: *mut u32, data: *mut std::ffi::c_void, size: *mut u32) -> i32;
        fn RegCloseKey(key: isize) -> i32;
    }
    const HKLM: isize = 0x80000002u32 as i32 as isize;
    let wide = |text: &str| -> Vec<u16> { text.encode_utf16().chain(Some(0)).collect() };
    let text = |data: &[u16]| String::from_utf16_lossy(data).replace('\0', "\n");
    let mut missing = Vec::new();
    if CHROMIUM_ID.is_empty() || FIREFOX_ID.is_empty() {
        return missing;
    }
    for vendor in ["Google\\Chrome", "Microsoft\\Edge", "BraveSoftware\\Brave", "Chromium", "Vivaldi", "TheBrowserCompany\\Arc"] {
        let path = wide(&format!(r"SOFTWARE\Policies\{vendor}\ExtensionInstallForcelist"));
        let mut key = 0isize;
        // KEY_READ | KEY_WOW64_64KEY.
        let mut found = false;
        if unsafe { RegOpenKeyExW(HKLM, path.as_ptr(), 0, 0x20119, &mut key) } == 0 {
            for index in 0..1000 {
                let (mut name, mut name_len) = ([0u16; 64], 64u32);
                let mut data = [0u16; 1024];
                let (mut kind, mut data_len) = (0u32, (data.len() * 2) as u32);
                let status = unsafe { RegEnumValueW(key, index, name.as_mut_ptr(), &mut name_len, std::ptr::null_mut(),
                    &mut kind, data.as_mut_ptr().cast(), &mut data_len) };
                if status == 259 { break; } // ERROR_NO_MORE_ITEMS
                if status == 0 && kind == 1 && text(&data[..(data_len as usize / 2).min(data.len())]).starts_with(&format!("{CHROMIUM_ID};")) {
                    found = true;
                    break;
                }
            }
            unsafe { RegCloseKey(key) };
        }
        if !found {
            missing.push(vendor);
        }
    }
    let (sub, value) = (wide(r"SOFTWARE\Policies\Mozilla\Firefox"), wide("ExtensionSettings"));
    let mut data = vec![0u16; 32 * 1024];
    let mut size = (data.len() * 2) as u32;
    // RRF_RT_REG_SZ | RRF_RT_REG_MULTI_SZ | RRF_SUBKEY_WOW6464KEY.
    let read = unsafe { RegGetValueW(HKLM, sub.as_ptr(), value.as_ptr(), 0x0001_0022, std::ptr::null_mut(), data.as_mut_ptr().cast(), &mut size) } == 0;
    if !read || !text(&data[..(size as usize / 2).min(data.len())]).contains(&format!("\"{FIREFOX_ID}\"")) {
        missing.push("Mozilla\\Firefox");
    }
    missing
}

/// Logs each change of the set of browsers that lost their force-install policy. The
/// caller keeps `last` between passes; nothing is logged while the set is unchanged.
pub fn watch_policies(last: &mut Option<Vec<&'static str>>) {
    #[cfg(windows)]
    {
        let missing = missing_policies();
        if last.as_ref() != Some(&missing) {
            if missing.is_empty() {
                if last.is_some() { crate::log::info("browser force-install policies are in place again"); }
            } else {
                crate::log::error(&format!("browser force-install policy missing for {} (a Group Policy may have replaced it); the extension will be removed from those browsers", missing.join(", ")));
            }
            *last = Some(missing);
        }
    }
    #[cfg(not(windows))]
    let _ = last;
}

/// The service's copy: a local user who occupies a port first must not take the whole
/// agent down with it (its IPC, and so every browser's extension, fails closed); the
/// browser verifies what it downloads, so the loss is local extension updates, logged.
pub fn start_for_service(home: &Path, stop: Arc<AtomicBool>) -> Option<Server> {
    crate::extension_tls::directory(home)
        .and_then(|directory| start(&directory, stop))
        .unwrap_or_else(|error| {
            crate::log::error(&format!("local extension server unavailable: {error}"));
            None
        })
}

/// Both ports are bound before IPC readiness. No fallback to a central URL or to
/// an arbitrary free local port if another process has occupied our address.
pub fn start(tls_home: &Path, stop: Arc<AtomicBool>) -> Result<Option<Server>> {
    if CRX.is_empty() && XPI.is_empty() {
        return Ok(None);
    }
    info()?;
    let config = crate::extension_tls::server_config(tls_home)?;
    // network.bind_address: this machine only unless an administrator opened it.
    let address = crate::config::current().listen.address;
    let plain = TcpListener::bind((address, PORT))?;
    let secure = TcpListener::bind((address, FIREFOX_PORT))?;
    plain.set_nonblocking(true)?;
    secure.set_nonblocking(true)?;
    let mut threads = Vec::new();
    // Shared by both listeners: an idle connection holds one worker for at most its
    // 2 s deadline and can no longer block the next browser request.
    let active = Arc::new(AtomicUsize::new(0));
    let sessions: Sessions = Arc::default();
    for (listener, tls) in [(plain, None), (secure, Some(config))] {
        let signal = stop.clone();
        let active = active.clone();
        let sessions = sessions.clone();
        threads.push(thread::spawn(move || {
            while !signal.load(Ordering::Acquire) {
                match listener.accept() {
                    // Loopback always; another peer only inside network.allowed_peers.
                    Ok((stream, peer)) if crate::config::current().listen.admits(peer.ip()) => {
                        if active.fetch_add(1, Ordering::AcqRel) >= WORKER_LIMIT {
                            active.fetch_sub(1, Ordering::AcqRel);
                            continue;
                        }
                        let worker = Worker(active.clone());
                        let tls = tls.clone();
                        let sessions = sessions.clone();
                        // A failed spawn drops the closure: socket closed, slot released.
                        let _ = thread::Builder::new().name("extension-connection".into()).spawn(move || {
                            let _worker = worker;
                            // One session (one uid) cannot hold every slot and keep the other
                            // users' browsers from installing the extension. Attributed here,
                            // off the accept loop.
                            let Some(_share) = Share::take(&sessions, peer_key(&stream)) else { return };
                            // Browser disconnects and invalid/untrusted handshakes are
                            // request failures, not service failures and not log floods.
                            let _ = serve_connection(stream, tls);
                        });
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(50));
                    }
                    // A client that reset before being accepted is its own failure; any
                    // local process could otherwise stop the extension server.
                    Err(error) if matches!(error.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted | io::ErrorKind::Interrupted) => {}
                    Err(error) => {
                        crate::log::error(&format!("local extension listener failed: {error}"));
                        signal.store(true, Ordering::Release);
                        break;
                    }
                }
            }
        }));
    }
    Ok(Some(Server { stop, threads }))
}

const WORKER_LIMIT: usize = 32;
const SESSION_LIMIT: usize = 6;
/// Releases a worker slot when its connection ends, however it ends.
struct Worker(Arc<AtomicUsize>);
impl Drop for Worker {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}
type Sessions = Arc<std::sync::Mutex<std::collections::HashMap<String, usize>>>;
/// One connection charged to its peer's session (or uid) until it ends.
struct Share(Sessions, String);
impl Share {
    fn take(sessions: &Sessions, key: String) -> Option<Self> {
        let mut map = sessions.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let held = map.entry(key.clone()).or_insert(0);
        if *held >= SESSION_LIMIT {
            return None;
        }
        *held += 1;
        drop(map);
        Some(Self(sessions.clone(), key))
    }
}
impl Drop for Share {
    fn drop(&mut self) {
        let mut map = self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(held) = map.get_mut(&self.1) {
            *held -= 1;
            if *held == 0 {
                map.remove(&self.1);
            }
        }
    }
}
/// Who is behind a loopback connection, as the OS records it: the Windows session of
/// the owning process, the Linux uid of the socket. A remote peer admitted by
/// network.allowed_peers is its address; an undetermined one shares one budget.
fn peer_key(stream: &TcpStream) -> String {
    let (Ok(peer), Ok(local)) = (stream.peer_addr(), stream.local_addr()) else { return "unknown".into() };
    if !peer.ip().is_loopback() {
        return peer.ip().to_string();
    }
    loopback_owner(peer, local).unwrap_or_else(|| "unknown".into())
}
#[cfg(windows)]
fn loopback_owner(peer: std::net::SocketAddr, local: std::net::SocketAddr) -> Option<String> {
    #[repr(C)]
    struct Row { state: u32, local_addr: u32, local_port: u32, remote_addr: u32, remote_port: u32, pid: u32 }
    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn GetExtendedTcpTable(table: *mut std::ffi::c_void, size: *mut u32, order: i32, family: u32, class: i32, reserved: u32) -> u32;
    }
    // AF_INET, TCP_TABLE_OWNER_PID_ALL. The table may grow between the size query and the
    // read (ERROR_INSUFFICIENT_BUFFER): retried with margin rather than left unattributed.
    let mut length = 0u32;
    unsafe { GetExtendedTcpTable(std::ptr::null_mut(), &mut length, 0, 2, 5, 0) };
    let mut buffer = Vec::new();
    for _ in 0..3 {
        if length < 4 || length > 16 * 1024 * 1024 {
            return None;
        }
        buffer = vec![0u32; (length as usize).div_ceil(4) + 1024];
        length = u32::try_from(buffer.len() * 4).ok()?;
        match unsafe { GetExtendedTcpTable(buffer.as_mut_ptr().cast(), &mut length, 0, 2, 5, 0) } {
            0 => break,
            122 => { buffer.clear(); continue }
            _ => return None,
        }
    }
    if buffer.is_empty() {
        return None;
    }
    let size = std::mem::size_of::<Row>();
    let count = (buffer[0] as usize).min((length as usize).saturating_sub(4) / size);
    let pid = (0..count).map(|index| unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast::<u8>().add(4 + index * size).cast::<Row>()) })
        .find(|row| row.state == 5 && u16::from_be(row.local_port as u16) == peer.port() && u16::from_be(row.remote_port as u16) == local.port())?
        .pid;
    process_session(pid).map(|session| format!("session:{session}"))
}
/// The session of any process, readable without opening it: NetworkService cannot open
/// another account's process, which ProcessIdToSessionId requires.
#[cfg(all(windows, target_pointer_width = "64"))]
fn process_session(pid: u32) -> Option<u32> {
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtQuerySystemInformation(class: u32, buffer: *mut std::ffi::c_void, length: u32, returned: *mut u32) -> i32;
    }
    let mut buffer = vec![0u64; 1 << 17];
    for _ in 0..4 {
        let mut needed = 0u32;
        let bytes = u32::try_from(buffer.len() * 8).ok()?;
        // SystemProcessInformation.
        let status = unsafe { NtQuerySystemInformation(5, buffer.as_mut_ptr().cast(), bytes, &mut needed) };
        if status == 0 {
            let data = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), bytes as usize) };
            let mut at = 0usize;
            // SYSTEM_PROCESS_INFORMATION (x64): NextEntryOffset at 0, UniqueProcessId at
            // 0x50, SessionId at 0x64.
            while at + 0x68 <= data.len() {
                let next = u32::from_le_bytes(data[at..at + 4].try_into().ok()?) as usize;
                let id = u64::from_le_bytes(data[at + 0x50..at + 0x58].try_into().ok()?);
                if id == u64::from(pid) {
                    return Some(u32::from_le_bytes(data[at + 0x64..at + 0x68].try_into().ok()?));
                }
                if next == 0 {
                    return None;
                }
                at = at.checked_add(next)?;
            }
            return None;
        }
        // STATUS_INFO_LENGTH_MISMATCH: grow once to what the kernel asked for, bounded.
        if status as u32 != 0xC000_0004 || needed as usize > 64 * 1024 * 1024 {
            return None;
        }
        buffer = vec![0u64; (needed as usize).div_ceil(8) + 4096];
    }
    None
}
#[cfg(all(windows, not(target_pointer_width = "64")))]
fn process_session(_pid: u32) -> Option<u32> {
    None
}
#[cfg(unix)]
fn loopback_owner(peer: std::net::SocketAddr, local: std::net::SocketAddr) -> Option<String> {
    let table = if peer.is_ipv4() { "/proc/net/tcp" } else { "/proc/net/tcp6" };
    let source = std::fs::read_to_string(table).ok()?;
    let (from, to) = (format!(":{:04X}", peer.port()), format!(":{:04X}", local.port()));
    source.lines().skip(1).map(|line| line.split_whitespace().collect::<Vec<_>>())
        .find(|f| f.len() > 7 && f[1].ends_with(&from) && f[2].ends_with(&to) && f[3] == "01")
        .map(|f| format!("uid:{}", f[7]))
}
fn serve_connection(stream: TcpStream, tls: Option<Arc<rustls::ServerConfig>>) -> Result<()> {
    let mut socket = DeadlineSocket {
        stream,
        deadline: Instant::now() + Duration::from_secs(2),
    };
    // Accepted sockets inherit nonblocking mode on Windows.
    // This worker uses bounded blocking I/O, not a reactor.
    socket.stream.set_nonblocking(false)?;
    if let Some(config) = tls {
        let mut conn = ServerConnection::new(config)?;
        while conn.is_handshaking() {
            conn.complete_io(&mut socket)?;
        }
        let mut channel = StreamOwned::new(conn, socket);
        respond(&mut channel, true)?;
        channel.conn.send_close_notify();
        channel.flush()?;
    } else {
        respond(&mut socket, false)?;
    }
    Ok(())
}

struct DeadlineSocket {
    stream: TcpStream,
    deadline: Instant,
}
impl DeadlineSocket {
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "local extension deadline"))
    }
}
impl Read for DeadlineSocket {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(bytes)
    }
}
impl Write for DeadlineSocket {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}
trait Channel: Read + Write {
    fn deadline(&mut self, deadline: Instant);
}
impl Channel for DeadlineSocket {
    fn deadline(&mut self, deadline: Instant) {
        self.deadline = deadline;
    }
}
impl Channel for StreamOwned<ServerConnection, DeadlineSocket> {
    fn deadline(&mut self, deadline: Instant) {
        self.sock.deadline = deadline;
    }
}

fn respond(stream: &mut impl Channel, firefox: bool) -> Result<()> {
    stream.deadline(Instant::now() + Duration::from_secs(2));
    let mut request = Vec::with_capacity(1024);
    loop {
        let mut chunk = [0u8; 1024];
        let count = stream.read(&mut chunk)?;
        if count == 0 {
            return Err("incomplete local request".into());
        }
        request.extend_from_slice(&chunk[..count]);
        if request.len() > REQUEST_LIMIT {
            return Err("local request too large".into());
        }
        if request.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let raw = std::str::from_utf8(&request)?;
    let mut lines = raw.split("\r\n");
    let mut first = lines.next().ok_or("missing request line")?.split(' ');
    let method = first.next().unwrap_or("");
    let target = first.next().unwrap_or("");
    let protocol = first.next().unwrap_or("");
    if first.next().is_some() || protocol != "HTTP/1.1" {
        return Err("unsupported local HTTP request".into());
    }
    let mut host = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':').ok_or("invalid header")?;
        if name.eq_ignore_ascii_case("host") && host.replace(value.trim()).is_some() {
            return Err("duplicate host".into());
        }
        if name.eq_ignore_ascii_case("transfer-encoding")
            || (name.eq_ignore_ascii_case("content-length") && value.trim() != "0")
        {
            return Err("local request bodies refused".into());
        }
    }
    let authority = if firefox {
        FIREFOX_ORIGIN.strip_prefix("https://")
    } else {
        ORIGIN.strip_prefix("http://")
    };
    let crx_path = format!("/ext/{VERSION}/milvago.crx");
    let xpi_path = format!("/ext/{FIREFOX_VERSION}/milvago.xpi");
    let manifest = if firefox {
        serde_json::to_string(&serde_json::json!({"addons": {
            (FIREFOX_ID): {"updates": [{"version": FIREFOX_VERSION,
                "update_link": format!("{FIREFOX_ORIGIN}{xpi_path}"),
                "update_hash": format!("sha256:{}", crate::sha256_hex(XPI)),
                "applications":{"gecko":{"strict_min_version":"140.0"}}
            }]}
        }}))?
    } else {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><gupdate xmlns=\"http://www.google.com/update2/response\" protocol=\"2.0\"><app appid=\"{CHROMIUM_ID}\"><updatecheck codebase=\"{ORIGIN}{crx_path}\" version=\"{VERSION}\" /></app></gupdate>"
        )
    };
    let (status, kind, body): (&str, &str, &[u8]) = if host != authority {
        ("403 Forbidden", "text/plain", b"Forbidden")
    } else if !matches!(method, "GET" | "HEAD") {
        (
            "405 Method Not Allowed",
            "text/plain",
            b"Method not allowed",
        )
    } else {
        match target.split('?').next().unwrap_or("") {
            "/ext/update.xml" if !firefox => ("200 OK", "application/xml", manifest.as_bytes()),
            "/ext/updates.json" if firefox => ("200 OK", "application/json", manifest.as_bytes()),
            path if !firefox && path == crx_path => {
                ("200 OK", "application/x-chrome-extension", CRX)
            }
            path if firefox && path == xpi_path => ("200 OK", "application/x-xpinstall", XPI),
            _ => ("404 Not Found", "text/plain", b"Not found"),
        }
    };
    let headers = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.deadline(Instant::now() + Duration::from_secs(5));
    stream.write_all(headers.as_bytes())?;
    if method != "HEAD" {
        stream.write_all(body)?;
    }
    stream.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{CertificateDer, ServerName};
    use rustls::{ClientConfig, ClientConnection, RootCertStore};
    #[test]
    fn a_loopback_peer_is_charged_to_its_session_and_each_session_is_bounded() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        let key = peer_key(&accepted);
        #[cfg(windows)]
        {
            #[link(name = "kernel32")]
            unsafe extern "system" { fn ProcessIdToSessionId(pid: u32, session: *mut u32) -> i32; }
            let mut session = 0u32;
            assert_ne!(unsafe { ProcessIdToSessionId(std::process::id(), &mut session) }, 0);
            assert_eq!(key, format!("session:{session}"));
        }
        #[cfg(unix)]
        assert_eq!(key, format!("uid:{}", unsafe { libc::getuid() }));
        let sessions: Sessions = Arc::default();
        let held: Vec<_> = (0..SESSION_LIMIT).map(|_| Share::take(&sessions, key.clone()).unwrap()).collect();
        assert!(Share::take(&sessions, key.clone()).is_none());
        assert!(Share::take(&sessions, "session:another".into()).is_some());
        drop(held);
        assert!(Share::take(&sessions, key).is_some());
    }
    fn exchange(request: &[u8], trust: bool, hostname: &'static str) -> Result<Vec<u8>> {
        let home = tempfile::tempdir()?;
        crate::extension_tls::prepare(home.path())?;
        let config = crate::extension_tls::server_config(home.path())?;
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let address = listener.local_addr()?;
        listener.set_nonblocking(true)?;
        let worker = thread::spawn(move || -> Result<()> {
            let (stream, _) = loop {
                match listener.accept() {
                    Ok(pair) => break pair,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(error) => return Err(error.into()),
                }
            };
            stream.set_nonblocking(false)?;
            let socket = DeadlineSocket {
                stream,
                deadline: Instant::now() + Duration::from_secs(3),
            };
            let mut channel = StreamOwned::new(ServerConnection::new(config)?, socket);
            respond(&mut channel, true)?;
            channel.conn.send_close_notify();
            channel.flush()?;
            Ok(())
        });
        let mut roots = RootCertStore::empty();
        if trust {
            roots.add(CertificateDer::from(std::fs::read(
                home.path().join("extension-ca.cer"),
            )?))?;
        }
        let config =
            ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
                .with_safe_default_protocol_versions()?
                .with_root_certificates(roots)
                .with_no_client_auth();
        let socket = DeadlineSocket {
            stream: TcpStream::connect(address)?,
            deadline: Instant::now() + Duration::from_secs(3),
        };
        let mut channel = StreamOwned::new(
            ClientConnection::new(Arc::new(config), ServerName::try_from(hostname)?)?,
            socket,
        );
        let result = (|| -> Result<Vec<u8>> {
            channel.write_all(request)?;
            let mut raw = Vec::new();
            channel.read_to_end(&mut raw)?;
            Ok(raw)
        })();
        drop(channel);
        let _ = worker.join().map_err(|_| "TLS worker panicked")?;
        result
    }
    #[test]
    fn firefox_tls_requires_trust_and_matching_hostname() {
        let request_text =
            format!("GET /ext/updates.json HTTP/1.1\r\nHost: 127.0.0.1:{FIREFOX_PORT}\r\n\r\n");
        let request = request_text.as_bytes();
        assert!(exchange(request, false, "127.0.0.1").is_err());
        assert!(exchange(request, true, "unrelated.example.test").is_err());
        let response = exchange(request, true, "127.0.0.1").unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        let raw = std::str::from_utf8(&response).unwrap();
        let body = raw.split_once("\r\n\r\n").unwrap().1;
        let manifest: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(
            manifest["addons"][FIREFOX_ID]["updates"][0]["version"],
            FIREFOX_VERSION
        );
    }
    #[test]
    fn firefox_endpoint_refuses_foreign_hosts_writes_and_filesystem_paths() {
        for (request, status) in [
            (
                &b"GET /ext/updates.json HTTP/1.1\r\nHost: attacker.example.test\r\n\r\n"[..],
                "403",
            ),
            (
                &b"POST /ext/updates.json HTTP/1.1\r\nHost: 127.0.0.1:17651\r\n\r\n"[..],
                "405",
            ),
            (
                &b"GET /../../identity.bin HTTP/1.1\r\nHost: 127.0.0.1:17651\r\n\r\n"[..],
                "404",
            ),
        ] {
            let request = String::from_utf8(request.to_vec())
                .unwrap()
                .replace(":17651", &format!(":{FIREFOX_PORT}"));
            let raw = exchange(request.as_bytes(), true, "127.0.0.1").unwrap();
            assert!(
                String::from_utf8(raw)
                    .unwrap()
                    .starts_with(&format!("HTTP/1.1 {status}"))
            );
        }
    }
}
