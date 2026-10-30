use crate::MAX_RESPONSE;

pub fn parse_response(input: &[u8]) -> Result<Vec<u8>, &'static str> {
    if input.len() > MAX_RESPONSE + 16_384 {
        return Err("response_limit");
    }
    let end = input
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("invalid_engine_http")?;
    if end > 16_384 {
        return Err("response_limit");
    }
    let header = std::str::from_utf8(&input[..end]).map_err(|_| "invalid_engine_http")?;
    let mut lines = header.split("\r\n");
    let status = lines
        .next()
        .ok_or("invalid_engine_http")?
        .split_whitespace()
        .collect::<Vec<_>>();
    if status.len() < 2 || !matches!(status[0], "HTTP/1.0" | "HTTP/1.1") || status[1] != "200" {
        return Err("engine_denied");
    }
    let mut length = None;
    let mut chunked = false;
    for line in lines {
        let (key, value) = line.split_once(':').ok_or("invalid_engine_http")?;
        if key.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err("ambiguous_engine_http");
            }
            length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| "invalid_engine_http")?,
            );
        }
        if key.eq_ignore_ascii_case("transfer-encoding") {
            if chunked || !value.trim().eq_ignore_ascii_case("chunked") {
                return Err("ambiguous_engine_http");
            }
            chunked = true;
        }
        if key.eq_ignore_ascii_case("content-encoding")
            && !value.trim().eq_ignore_ascii_case("identity")
        {
            return Err("unsupported_engine_encoding");
        }
    }
    let body = &input[end + 4..];
    if chunked {
        if length.is_some() {
            return Err("ambiguous_engine_http");
        }
        let mut cursor = 0;
        let mut output = vec![];
        for _ in 0..16_384 {
            let end = body[cursor..]
                .windows(2)
                .position(|w| w == b"\r\n")
                .ok_or("invalid_engine_chunk")?
                + cursor;
            let size = std::str::from_utf8(&body[cursor..end])
                .ok()
                .and_then(|v| usize::from_str_radix(v.split(';').next().unwrap_or(""), 16).ok())
                .ok_or("invalid_engine_chunk")?;
            cursor = end + 2;
            if size == 0 {
                if body.get(cursor..cursor + 2) != Some(b"\r\n") {
                    return Err("unsupported_engine_trailer");
                }
                return Ok(output);
            }
            if size > MAX_RESPONSE - output.len()
                || cursor
                    .checked_add(size + 2)
                    .is_none_or(|end| end > body.len())
            {
                return Err("response_limit");
            }
            output.extend_from_slice(&body[cursor..cursor + size]);
            cursor += size;
            if &body[cursor..cursor + 2] != b"\r\n" {
                return Err("invalid_engine_chunk");
            }
            cursor += 2;
        }
        Err("engine_chunk_limit")
    } else {
        if length.is_some_and(|n| n != body.len()) || body.len() > MAX_RESPONSE {
            return Err("response_limit");
        }
        Ok(body.to_vec())
    }
}

#[cfg(windows)]
pub fn http(
    path: &std::path::Path,
    route: &str,
    budget: &crate::Budget<'_>,
) -> Result<Vec<u8>, &'static str> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, ERROR_BROKEN_PIPE, ERROR_IO_PENDING, GetLastError, HANDLE,
            INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
        },
        Storage::FileSystem::{
            CreateFileW, FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
            FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, ReadFile, SECURITY_IDENTIFICATION,
            SECURITY_SQOS_PRESENT, WriteFile,
        },
        System::{
            IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
            Threading::{CreateEventW, WaitForSingleObject},
        },
    };
    struct Handle(HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    fn transfer(
        handle: HANDLE,
        buffer: &mut [u8],
        write: bool,
        budget: &crate::Budget<'_>,
    ) -> Result<usize, &'static str> {
        let event = Handle(unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) });
        if event.0.is_null() {
            return Err("pipe_event");
        }
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        overlapped.hEvent = event.0;
        let mut bytes = 0;
        let success = unsafe {
            if write {
                WriteFile(
                    handle,
                    buffer.as_ptr(),
                    buffer.len() as u32,
                    &mut bytes,
                    &mut overlapped,
                )
            } else {
                ReadFile(
                    handle,
                    buffer.as_mut_ptr(),
                    buffer.len() as u32,
                    &mut bytes,
                    &mut overlapped,
                )
            }
        };
        if success != 0 {
            return Ok(bytes as usize);
        }
        let error = unsafe { GetLastError() };
        if error == ERROR_BROKEN_PIPE && !write {
            return Ok(0);
        };
        if error != ERROR_IO_PENDING {
            return Err("pipe_io");
        }
        let timeout = budget
            .remaining()
            .map(|d| d.as_millis().min(u32::MAX as u128) as u32)
            .unwrap_or(0);
        if unsafe { WaitForSingleObject(event.0, timeout) } != WAIT_OBJECT_0 {
            // Cancellation must finish before either the OVERLAPPED or its buffer is dropped.
            unsafe {
                CancelIoEx(handle, &overlapped);
                GetOverlappedResult(handle, &overlapped, &mut bytes, 1);
            }
            return Err("pipe_timeout");
        }
        if unsafe { GetOverlappedResult(handle, &overlapped, &mut bytes, 0) } == 0 {
            if unsafe { GetLastError() } == ERROR_BROKEN_PIPE && !write {
                return Ok(0);
            };
            return Err("pipe_io");
        }
        Ok(bytes as usize)
    }
    let text = path.to_str().ok_or("invalid_pipe")?;
    if !admitted_pipe(text) {
        return Err("invalid_pipe");
    }
    budget.check()?;
    if !admitted_route(route) {
        return Err("invalid_engine_route");
    }
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            std::ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err("engine_unavailable");
    };
    let handle = Handle(raw);
    let mut request=format!("GET {route} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nConnection: close\r\n\r\n").into_bytes();
    let mut offset = 0;
    while offset < request.len() {
        let size = transfer(handle.0, &mut request[offset..], true, budget)?;
        if size == 0 {
            return Err("pipe_io");
        };
        offset += size;
    }
    let mut response = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let size = transfer(handle.0, &mut buffer, false, budget)?;
        if size == 0 {
            break;
        };
        if response.len() + size > MAX_RESPONSE + 16_384 {
            return Err("response_limit");
        };
        response.extend_from_slice(&buffer[..size]);
    }
    parse_response(&response)
}

#[cfg(any(windows, test))]
fn admitted_pipe(path: &str) -> bool {
    matches!(
        path,
        r"\\.\pipe\docker_engine"
            | r"\\.\pipe\dockerDesktopLinuxEngine"
            | r"\\.\pipe\podman-machine-default"
    )
}

#[cfg(any(windows, test))]
fn admitted_route(route: &str) -> bool {
    if matches!(route, "/info" | "/containers/json?all=1") {
        return true;
    }
    route
        .strip_prefix("/containers/")
        .and_then(|tail| tail.strip_suffix("/top?ps_args=-eo%20pid,lstart,args"))
        .is_some_and(|id| {
            (12..=128).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_hexdigit())
        })
}

#[cfg(test)]
mod tests {
    #[test]
    fn local_engine_pipes_include_podman_without_accepting_remote_or_arbitrary_pipes() {
        for path in [
            r"\\.\pipe\docker_engine",
            r"\\.\pipe\dockerDesktopLinuxEngine",
            r"\\.\pipe\podman-machine-default",
        ] {
            assert!(super::admitted_pipe(path));
        }
        for path in [
            r"\\remote\pipe\docker_engine",
            r"\\.\pipe\unknown",
            r"\\.\pipe\podman-machine-default\other",
            r"C:\private.json",
        ] {
            assert!(!super::admitted_pipe(path));
        }
    }
    #[cfg(windows)]
    #[test]
    #[ignore = "requires an isolated Windows VM without a Docker engine"]
    fn native_engine_pipe_limits_impersonation_and_cancels_pending_reads() {
        use std::{
            io::{Read, Write},
            os::windows::io::FromRawHandle,
            sync::atomic::AtomicBool,
            time::{Duration, Instant},
        };
        use windows_sys::Win32::{
            Foundation::{CloseHandle, ERROR_PIPE_CONNECTED, GetLastError, INVALID_HANDLE_VALUE},
            Security::{GetTokenInformation, RevertToSelf, TOKEN_QUERY, TokenImpersonationLevel},
            Storage::FileSystem::{
                FILE_FLAG_FIRST_PIPE_INSTANCE, FlushFileBuffers, PIPE_ACCESS_DUPLEX,
            },
            System::{
                Pipes::{
                    ConnectNamedPipe, CreateNamedPipeW, ImpersonateNamedPipeClient,
                    PIPE_REJECT_REMOTE_CLIENTS,
                },
                Threading::{GetCurrentThread, OpenThreadToken},
            },
        };
        let path = std::path::Path::new(r"\\.\pipe\docker_engine");
        let wide: Vec<_> = r"\\.\pipe\docker_engine"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        for reply in [
            Some(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n[]".as_slice()),
            Some(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n[]".as_slice()),
            None,
        ] {
            let raw = unsafe {
                CreateNamedPipeW(
                    wide.as_ptr(),
                    PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                    PIPE_REJECT_REMOTE_CLIENTS,
                    1,
                    8192,
                    8192,
                    1000,
                    std::ptr::null(),
                )
            };
            assert_ne!(
                raw, INVALID_HANDLE_VALUE,
                "never attach this test to an existing engine"
            );
            let raw = raw as usize;
            let server = std::thread::spawn(move || {
                let raw = raw as windows_sys::Win32::Foundation::HANDLE;
                let mut file = unsafe { std::fs::File::from_raw_handle(raw) };
                assert!(
                    unsafe { ConnectNamedPipe(raw, std::ptr::null_mut()) } != 0
                        || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED
                );
                let mut request = vec![];
                let mut byte = [0];
                while !request.ends_with(b"\r\n\r\n") {
                    assert!(request.len() < 1024);
                    file.read_exact(&mut byte).unwrap();
                    request.push(byte[0]);
                }
                assert_eq!(request, b"GET /info HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nConnection: close\r\n\r\n");
                assert_ne!(unsafe { ImpersonateNamedPipeClient(raw) }, 0);
                let mut token = std::ptr::null_mut();
                let opened =
                    unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) };
                let mut level = -1i32;
                let mut size = 0;
                let queried = if opened != 0 {
                    unsafe {
                        GetTokenInformation(
                            token,
                            TokenImpersonationLevel,
                            (&mut level as *mut i32).cast(),
                            4,
                            &mut size,
                        )
                    }
                } else {
                    0
                };
                let reverted = unsafe { RevertToSelf() };
                if !token.is_null() {
                    unsafe {
                        CloseHandle(token);
                    }
                }
                assert_ne!(reverted, 0);
                assert_ne!(queried, 0);
                assert_eq!(
                    level, 1,
                    "the engine receives identification, never impersonation authority"
                );
                if let Some(reply) = reply {
                    file.write_all(reply).unwrap();
                    assert_ne!(unsafe { FlushFileBuffers(raw) }, 0);
                } else {
                    std::thread::sleep(Duration::from_millis(250));
                }
            });
            let stop = AtomicBool::new(false);
            let budget = crate::Budget::new(
                if reply.is_some() {
                    Duration::from_secs(2)
                } else {
                    Duration::from_millis(100)
                },
                &stop,
            );
            let started = Instant::now();
            let result = super::http(path, "/info", &budget);
            if let Some(reply) = reply {
                if reply.windows(17).any(|w| w == b"Content-Length: 2") {
                    assert_eq!(result.unwrap(), b"[]");
                } else {
                    assert!(result.is_err());
                }
            } else {
                assert_eq!(result.unwrap_err(), "pipe_timeout");
                assert!(started.elapsed() < Duration::from_secs(1));
            }
            server.join().unwrap();
        }
    }
    #[test]
    fn engine_pipe_allows_only_fixed_metadata_requests() {
        for route in [
            "/info",
            "/containers/json?all=1",
            "/containers/0123456789abcdef/top?ps_args=-eo%20pid,lstart,args",
        ] {
            assert!(super::admitted_route(route));
        }
        for route in [
            "/containers/create",
            "/info\r\nX-Injected: value",
            "/containers/../../info/top?ps_args=-eo%20pid,lstart,args",
            "/containers/0123456789abcdef/top?ps_args=--arbitrary",
            "/containers/short/top?ps_args=-eo%20pid,lstart,args",
        ] {
            assert!(!super::admitted_route(route));
        }
    }
    #[test]
    fn engine_http_content_length_chunking_and_smuggling() {
        assert_eq!(
            super::parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n[]").unwrap(),
            b"[]"
        );
        assert_eq!(
            super::parse_response(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n[]\r\n0\r\n\r\n"
            )
            .unwrap(),
            b"[]"
        );
        for bytes in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n[]".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n[]",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFF\r\n[]",
            b"HTTP/1.1 403 Denied\r\n\r\n[]",
        ] {
            assert!(super::parse_response(bytes).is_err());
        }
    }
}
