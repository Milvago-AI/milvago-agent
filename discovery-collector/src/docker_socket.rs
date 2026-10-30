//! Pin each Unix HTTP response to its actual kernel peer and socket generation.
use crate::{
    Budget, MAX_RESPONSE,
    containerd_process::Peer,
    docker::{Authority, LocalResponse},
};
use std::{
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{
            ffi::OsStrExt,
            fs::{FileTypeExt, MetadataExt},
            net::UnixStream,
        },
    },
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Guard {
    pub(super) peer: Peer,
    socket: PathBuf,
    device: u64,
    inode: u64,
    uid: u32,
}

fn protected_parents(socket: &Path, uid: u32) -> bool {
    socket.ancestors().skip(1).all(|path| {
        std::fs::symlink_metadata(path).is_ok_and(|metadata| {
            // A sticky root-owned /tmp cannot replace another owner's child.
            let sticky_root = metadata.uid() == 0 && metadata.mode() & libc::S_ISVTX != 0;
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && (metadata.uid() == 0 || metadata.uid() == uid)
                && (metadata.mode() & 0o022 == 0 || sticky_root)
        })
    })
}

impl Guard {
    fn read(stream: &UnixStream, socket: &Path, before: &std::fs::Metadata) -> Option<Self> {
        let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
        let mut size = std::mem::size_of_val(&credentials) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut credentials as *mut libc::ucred).cast(),
                &mut size,
            )
        } != 0
            || size as usize != std::mem::size_of_val(&credentials)
            || credentials.pid <= 0
        {
            return None;
        }
        let current = std::fs::symlink_metadata(socket).ok()?;
        if !current.file_type().is_socket()
            || current.uid() != credentials.uid
            || current.mode() & 0o002 != 0
            || current.dev() != before.dev()
            || current.ino() != before.ino()
            || !protected_parents(socket, credentials.uid)
        {
            return None;
        }
        Some(Self {
            peer: Peer::read(credentials.pid as u32, credentials.uid)?,
            socket: socket.into(),
            device: current.dev(),
            inode: current.ino(),
            uid: credentials.uid,
        })
    }
    pub(super) fn root_trusted(&self) -> bool {
        self.uid == 0 && self.current()
    }
    pub(super) fn current(&self) -> bool {
        self.peer.current()
            && protected_parents(&self.socket, self.uid)
            && std::fs::symlink_metadata(&self.socket).is_ok_and(|metadata| {
                metadata.file_type().is_socket()
                    && metadata.uid() == self.uid
                    && metadata.dev() == self.device
                    && metadata.ino() == self.inode
                    && metadata.mode() & 0o002 == 0
            })
    }
}

fn connect(socket: &Path, budget: &Budget<'_>) -> Result<UnixStream, &'static str> {
    budget.check()?;
    let bytes = socket.as_os_str().as_bytes();
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.is_empty() || bytes.contains(&0) || bytes.len() >= address.sun_path.len() {
        return Err("engine_transport");
    }
    address.sun_family = libc::AF_UNIX as _;
    for (target, byte) in address.sun_path.iter_mut().zip(bytes) {
        *target = *byte as _;
    }
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if raw < 0 {
        return Err("engine_transport");
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let size =
        (std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1) as libc::socklen_t;
    if unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            size,
        )
    } != 0
    {
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINPROGRESS) {
            return Err("engine_transport");
        }
        loop {
            budget.check()?;
            let mut poll = libc::pollfd {
                fd: fd.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            };
            let result = unsafe { libc::poll(&mut poll, 1, 25) };
            if result < 0
                && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
            {
                return Err("engine_transport");
            }
            if result > 0 {
                break;
            }
        }
        let mut error = 0i32;
        let mut size = std::mem::size_of_val(&error) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&mut error as *mut i32).cast(),
                &mut size,
            )
        } != 0
            || error != 0
        {
            return Err("engine_transport");
        }
    }
    let stream = UnixStream::from(fd);
    stream
        .set_nonblocking(false)
        .map_err(|_| "engine_transport")?;
    Ok(stream)
}

pub(super) fn request(
    socket: &Path,
    path: &str,
    budget: &Budget<'_>,
) -> Result<LocalResponse, &'static str> {
    if path.len() > 512
        || !path.starts_with('/')
        || !path.is_ascii()
        || path.bytes().any(|byte| byte <= 0x20 || byte == 0x7f)
    {
        return Err("invalid_engine_path");
    }
    let metadata = std::fs::symlink_metadata(socket).map_err(|_| "engine_transport")?;
    if !metadata.file_type().is_socket() {
        return Err("engine_transport");
    }
    let mut stream = connect(socket, budget)?;
    let guard = Guard::read(&stream, socket, &metadata);
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n"
    );
    let mut written = 0;
    while written < request.len() {
        stream
            .set_write_timeout(Some(budget.remaining()?.min(Duration::from_millis(50))))
            .map_err(|_| "engine_transport")?;
        match stream.write(&request.as_bytes()[written..]) {
            Ok(0) => return Err("engine_transport"),
            Ok(count) => written += count,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                ()
            }
            Err(_) => return Err("engine_transport"),
        }
    }
    let mut bytes = vec![];
    let mut buffer = [0u8; 8192];
    loop {
        stream
            .set_read_timeout(Some(budget.remaining()?.min(Duration::from_millis(50))))
            .map_err(|_| "engine_transport")?;
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                if bytes.len() + count > MAX_RESPONSE + 16384 {
                    return Err("response_limit");
                }
                bytes.extend_from_slice(&buffer[..count]);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                ()
            }
            Err(_) => return Err("engine_transport"),
        }
    }
    budget.check()?;
    let authority = match guard {
        Some(guard) if guard.current() => Authority::Local(guard),
        _ => Authority::Unverified,
    };
    Ok(LocalResponse {
        body: crate::pipe::parse_response(&bytes)?,
        authority,
    })
}
