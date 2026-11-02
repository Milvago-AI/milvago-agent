//! WSL 2.6.3 private IDL adapter. All calls execute in a non-elevated owner process.
use super::{Identity, Request, exit_status::ExitStatus, supported_abi};
use milvago_discovery_collector::{Budget, MAX_RESPONSE};
use std::{
    ffi::{CString, c_void},
    os::windows::io::AsRawHandle,
    path::PathBuf,
    time::Duration,
};
use windows_sys::{
    Win32::{
        Foundation::CloseHandle,
        Security::{GetTokenInformation, TokenElevation, TokenUser},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    },
    core::GUID,
};

type Result<T> = std::result::Result<T, &'static str>;
#[link(name = "ole32")]
unsafe extern "system" {
    fn CoInitializeEx(reserved: *mut c_void, flags: u32) -> i32;
    fn CoUninitialize();
    fn CoCreateInstance(
        class: *const GUID,
        outer: *mut c_void,
        context: u32,
        iid: *const GUID,
        result: *mut *mut c_void,
    ) -> i32;
    fn CoTaskMemFree(memory: *mut c_void);
    fn CoSetProxyBlanket(
        proxy: *mut c_void,
        authentication: u32,
        authorization: u32,
        principal: *const u16,
        authentication_level: u32,
        impersonation_level: u32,
        identity: *mut c_void,
        capabilities: u32,
    ) -> i32;
}
#[link(name = "advapi32")]
unsafe extern "system" {
    fn ConvertSidToStringSidW(sid: *mut c_void, text: *mut *mut u16) -> i32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn LocalFree(memory: *mut c_void) -> *mut c_void;
}
#[link(name = "version")]
unsafe extern "system" {
    fn GetFileVersionInfoSizeW(path: *const u16, unused: *mut u32) -> u32;
    fn GetFileVersionInfoW(path: *const u16, unused: u32, size: u32, buffer: *mut c_void) -> i32;
    fn VerQueryValueW(
        buffer: *const c_void,
        sub: *const u16,
        result: *mut *mut c_void,
        size: *mut u32,
    ) -> i32;
}
#[link(name = "ws2_32")]
unsafe extern "system" {
    fn ioctlsocket(socket: usize, command: i32, value: *mut u32) -> i32;
    fn recv(socket: usize, data: *mut u8, size: i32, flags: i32) -> i32;
    fn send(socket: usize, data: *const u8, size: i32, flags: i32) -> i32;
    fn closesocket(socket: usize) -> i32;
    fn WSAGetLastError() -> i32;
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

pub(super) fn owner() -> Result<String> {
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), 8, &mut token) } == 0 {
        return Err("access_denied");
    }
    struct Token(*mut c_void);
    impl Drop for Token {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    let token = Token(token);
    let mut elevated = 0u32;
    let mut length = 0;
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            (&mut elevated as *mut u32).cast(),
            4,
            &mut length,
        )
    } == 0
        || elevated != 0
    {
        return Err("access_denied");
    }
    let value = token_identity(token.0)?;
    Identity::parse(&format!("{value}/11111111-1111-4111-8111-111111111111"))?;
    Ok(value)
}

pub(super) fn token_identity(token: *mut c_void) -> Result<String> {
    let mut length = 0;
    let mut data = [0u64; 512];
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            data.as_mut_ptr().cast(),
            4096,
            &mut length,
        )
    } == 0
        || length < 8
        || length > 4096
    {
        return Err("access_denied");
    }
    let sid = unsafe { *(data.as_ptr().cast::<*mut c_void>()) };
    let mut text = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 || text.is_null() {
        return Err("access_denied");
    }
    let result = (|| {
        let mut count = 0;
        while count <= 80 && unsafe { *text.add(count) } != 0 {
            count += 1;
        }
        if count > 80 {
            return Err("access_denied");
        }
        let value = String::from_utf16(unsafe { std::slice::from_raw_parts(text, count) })
            .map_err(|_| "access_denied")?;
        Ok(value)
    })();
    unsafe {
        LocalFree(text.cast());
    }
    result
}

fn abi_guard() -> Result<(crate::cache_windows::Directory, std::fs::File)> {
    let directory =
        PathBuf::from(std::env::var_os("ProgramFiles").ok_or("unavailable")?).join("WSL");
    let directory =
        crate::cache_windows::Directory::installed(&directory).map_err(|_| "access_denied")?;
    let file = directory
        .hold_file(std::ffi::OsStr::new("wslservice.exe"))
        .map_err(|_| "unavailable")?;
    let path = PathBuf::from(std::env::var_os("ProgramFiles").ok_or("unavailable")?)
        .join("WSL/wslservice.exe");
    let path = wide(path.to_str().ok_or("unavailable")?);
    let mut ignored = 0;
    let size = unsafe { GetFileVersionInfoSizeW(path.as_ptr(), &mut ignored) };
    if size == 0 || size > 1024 * 1024 {
        return Err("unavailable");
    }
    let mut data = vec![0u32; (size as usize).div_ceil(4)];
    if unsafe { GetFileVersionInfoW(path.as_ptr(), 0, size, data.as_mut_ptr().cast()) } == 0 {
        return Err("unavailable");
    }
    let mut info = std::ptr::null_mut();
    let mut length = 0;
    if unsafe {
        VerQueryValueW(
            data.as_ptr().cast(),
            wide("\\").as_ptr(),
            &mut info,
            &mut length,
        )
    } == 0
        || info.is_null()
        || length < 52
    {
        return Err("unavailable");
    }
    let start = data.as_ptr() as usize;
    let address = info as usize;
    if address < start
        || address
            .checked_add(52)
            .is_none_or(|end| end > start + data.len() * 4)
    {
        return Err("unavailable");
    }
    let words = unsafe { std::ptr::read_unaligned(info.cast::<[u32; 13]>()) };
    let version = [
        (words[2] >> 16) as u16,
        words[2] as u16,
        (words[3] >> 16) as u16,
        words[3] as u16,
    ];
    if words[0] != 0xfeef04bd || !supported_abi(version) {
        return Err("unavailable");
    }
    Ok((directory, file))
}

#[repr(C)]
#[derive(Default)]
struct ErrorInfo {
    flags: u32,
    context: u64,
    message: *mut u16,
    warnings: *mut u16,
    pipe: u32,
}
impl Drop for ErrorInfo {
    fn drop(&mut self) {
        unsafe {
            CoTaskMemFree(self.message.cast());
            CoTaskMemFree(self.warnings.cast());
            if self.pipe != 0 {
                CloseHandle(self.pipe as usize as *mut c_void);
            }
        }
    }
}
#[repr(C)]
struct Distribution {
    id: GUID,
    state: u32,
    version: u32,
    flags: u32,
    name: [u16; 257],
}
struct Com {
    object: *mut c_void,
}
impl Drop for Com {
    fn drop(&mut self) {
        unsafe {
            let release: unsafe extern "system" fn(*mut c_void) -> u32 =
                std::mem::transmute(self.method(2));
            release(self.object);
            CoUninitialize();
        }
    }
}
impl Com {
    unsafe fn method(&self, index: usize) -> *const c_void {
        unsafe {
            let table = *(self.object.cast::<*const *const c_void>());
            *table.add(index)
        }
    }
    fn open() -> Result<Self> {
        owner()?;
        if unsafe { CoInitializeEx(std::ptr::null_mut(), 0) } < 0 {
            return Err("unavailable");
        }
        let mut object = std::ptr::null_mut();
        let status = unsafe {
            CoCreateInstance(
                &GUID::from_u128(0xa9b7a1b9_0671_405c_95f1_e0612cb4ce7e),
                std::ptr::null_mut(),
                4,
                &GUID::from_u128(0x38541bdc_f54f_4ceb_85d0_37f0f3d2617e),
                &mut object,
            )
        };
        if status < 0 || object.is_null() {
            unsafe {
                CoUninitialize();
            }
            return Err("unavailable");
        }
        let com = Self { object };
        // WSL impersonates this non-elevated process to open its owner's registry.
        // COM's default IDENTIFY token cannot authorize that access. Bind only this
        // proxy, with packet privacy and no delegation or thread-token cloaking.
        let status = unsafe {
            CoSetProxyBlanket(
                com.object,
                10,
                0,
                std::ptr::null(),
                6,
                3,
                std::ptr::null_mut(),
                0,
            )
        };
        if status < 0 {
            return Err("unavailable");
        }
        Ok(com)
    }
    fn distributions(&self) -> Result<Vec<(String, bool, u32, String)>> {
        let mut count = 0;
        let mut rows = std::ptr::null_mut();
        let mut error = ErrorInfo::default();
        let call: unsafe extern "system" fn(
            *mut c_void,
            *mut u32,
            *mut *mut Distribution,
            *mut ErrorInfo,
        ) -> i32 = unsafe { std::mem::transmute(self.method(15)) };
        let status = unsafe { call(self.object, &mut count, &mut rows, &mut error) };
        #[cfg(all(test, feature = "windows-qualification"))]
        eprintln!(
            "MILVAGO_WSL_ENUM_STATUS={:08X};count={count}",
            status as u32
        );
        struct Rows(*mut Distribution);
        impl Drop for Rows {
            fn drop(&mut self) {
                unsafe {
                    CoTaskMemFree(self.0.cast());
                }
            }
        }
        let rows = Rows(rows);
        if status < 0 || count > 100 || count > 0 && rows.0.is_null() {
            return Err("unavailable");
        }
        let mut out = vec![];
        let mut seen = std::collections::BTreeSet::new();
        for index in 0..count as usize {
            let row = unsafe { &*rows.0.add(index) };
            let id =
                uuid::Uuid::from_fields(row.id.data1, row.id.data2, row.id.data3, &row.id.data4)
                    .to_string();
            if !seen.insert(id.clone()) {
                return Err("invalid_guest_response");
            }
            let length = row
                .name
                .iter()
                .position(|c| *c == 0)
                .ok_or("invalid_guest_response")?;
            let name =
                String::from_utf16(&row.name[..length]).map_err(|_| "invalid_guest_response")?;
            if name.is_empty()
                || name.len() > 160
                || name.chars().any(char::is_control)
                || ![1, 2].contains(&row.version)
            {
                return Err("invalid_guest_response");
            }
            out.push((id, row.state == 2, row.version, name));
        }
        Ok(out)
    }
    fn processes(&self, id: &str, budget: &Budget<'_>) -> Result<Vec<u8>> {
        self.execute_fixed(id, budget, include_str!("../discovery_guest_linux.py"))
    }

    fn execute_fixed(
        &self,
        id: &str,
        budget: &Budget<'_>,
        script: &'static str,
    ) -> Result<Vec<u8>> {
        self.execute_program(id, budget, script, Some("root"), &[])
    }

    fn execute_program(
        &self,
        id: &str,
        budget: &Budget<'_>,
        script: &'static str,
        user: Option<&str>,
        input: &[u8],
    ) -> Result<Vec<u8>> {
        if script.len() > 96 * 1024 || script.contains('\0') || input.len() > 24 * 1024 {
            return Err("request_limit");
        }
        budget.check()?;
        let guid = uuid::Uuid::parse_str(id).map_err(|_| "invalid_wsl_identity")?;
        let (a, b, c, d) = guid.as_fields();
        let guid = GUID {
            data1: a,
            data2: b,
            data3: c,
            data4: *d,
        };
        // NUL descriptors are real client handles, never console pseudohandles.
        let null = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("NUL")
            .map_err(|_| "unavailable")?;
        let handle = u32::try_from(null.as_raw_handle() as usize).map_err(|_| "unavailable")?;
        #[repr(C)]
        struct StdHandle {
            handle: u32,
            kind: u32,
        }
        #[repr(C)]
        struct StdHandles {
            input: StdHandle,
            output: StdHandle,
            error: StdHandle,
        }
        let handles = StdHandles {
            input: StdHandle { handle, kind: 1 },
            output: StdHandle { handle, kind: 2 },
            error: StdHandle { handle, kind: 2 },
        };
        let script = format!("{}\n{script}", include_str!("process_lifetime.py"));
        let arguments = ["/usr/bin/python3", "-I", "-S", "-c", script.as_str()]
            .map(|value| CString::new(value).expect("fixed script contains no NUL"));
        let pointers: Vec<_> = arguments.iter().map(|s| s.as_ptr()).collect();
        // A NULL username selects the distribution's configured Linux account.
        let user = user.map(wide);
        let env = [0u16; 2];
        let mut distribution = GUID::from_u128(0);
        let mut instance = GUID::from_u128(0);
        let mut output = Output([std::ptr::null_mut(); 7]);
        let mut error = ErrorInfo::default();
        type Launch = unsafe extern "system" fn(
            *mut c_void,
            *const GUID,
            *const i8,
            u32,
            *const *const i8,
            *const u16,
            *const u16,
            *const u16,
            u32,
            *const u16,
            i16,
            i16,
            u32,
            *const StdHandles,
            u32,
            *mut GUID,
            *mut GUID,
            *mut *mut c_void,
            *mut *mut c_void,
            *mut *mut c_void,
            *mut *mut c_void,
            *mut *mut c_void,
            *mut *mut c_void,
            *mut *mut c_void,
            *mut ErrorInfo,
        ) -> i32;
        let call: Launch = unsafe { std::mem::transmute(self.method(16)) };
        let [process, server, input_channel, stdout, stderr, control, interop] = &mut output.0;
        // OPEN_EXISTING is checked under the service instance lock. No CLI fallback.
        let status = unsafe {
            call(
                self.object,
                &guid,
                arguments[0].as_ptr(),
                pointers.len() as u32,
                pointers.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                env.as_ptr(),
                2,
                user.as_ref().map_or(std::ptr::null(), |name| name.as_ptr()),
                0,
                0,
                0,
                &handles,
                2,
                &mut distribution,
                &mut instance,
                process,
                server,
                input_channel,
                stdout,
                stderr,
                control,
                interop,
                &mut error,
            )
        };
        if status < 0 {
            return Err("guest_query_failed");
        }
        if distribution.data1 != guid.data1
            || distribution.data2 != guid.data2
            || distribution.data3 != guid.data3
            || distribution.data4 != guid.data4
            || output.0[2..]
                .iter()
                .any(|value| value.is_null() || *value as usize == usize::MAX)
        {
            return Err("invalid_guest_response");
        }
        receive_process_with_input(&mut output, budget, input)
    }
}

#[cfg(test)]
fn receive_process(output: &mut Output, budget: &Budget<'_>) -> Result<Vec<u8>> {
    receive_process_with_input(output, budget, &[])
}

fn receive_process_with_input(
    output: &mut Output,
    budget: &Budget<'_>,
    input: &[u8],
) -> Result<Vec<u8>> {
    if input.len() > 24 * 1024 {
        return Err("request_limit");
    }
    // Keep control open until acknowledgement. Every error path drops it and
    // cancels the relay. Input is private data, never part of the command line.
    for index in [2, 3, 4, 6] {
        let mut nonblocking = 1;
        if unsafe {
            ioctlsocket(
                output.0[index] as usize,
                0x8004667eu32 as i32,
                &mut nonblocking,
            )
        } != 0
        {
            return Err("unavailable");
        }
    }
    let mut bytes = vec![];
    let mut stderr_bytes = 0usize;
    let mut exit = ExitStatus::default();
    let mut acknowledged = false;
    let mut closed = [false; 3];
    let mut buffer = [0u8; 8192];
    let mut input_sent = 0;
    loop {
        budget.check()?;
        let mut progressed = false;
        if !output.0[2].is_null() {
            if input_sent < input.len() {
                let part = &input[input_sent..input.len().min(input_sent + 8192)];
                let count =
                    unsafe { send(output.0[2] as usize, part.as_ptr(), part.len() as i32, 0) };
                if count <= 0 {
                    if count == 0 || unsafe { WSAGetLastError() } != 10035 {
                        return Err("guest_channel_failed");
                    }
                } else {
                    input_sent += count as usize;
                    progressed = true;
                }
            }
            if input_sent == input.len() {
                unsafe {
                    closesocket(output.0[2] as usize);
                }
                output.0[2] = std::ptr::null_mut();
                progressed = true;
            }
        }
        // Drain both output streams while waiting for exit status. A guest that
        // fills stderr must not deadlock a valid stdout snapshot indefinitely.
        for (channel, index) in [3, 4, 6].into_iter().enumerate() {
            if closed[channel] || channel == 2 && acknowledged {
                continue;
            }
            let count = unsafe {
                recv(
                    output.0[index] as usize,
                    buffer.as_mut_ptr(),
                    buffer.len() as i32,
                    0,
                )
            };
            if count < 0 {
                if unsafe { WSAGetLastError() } != 10035 {
                    return Err("guest_channel_failed");
                }
                continue;
            }
            progressed = true;
            if count == 0 {
                closed[channel] = true;
                if channel == 2 && !acknowledged {
                    return Err("missing_guest_exit_status");
                }
                continue;
            }
            let part = &buffer[..count as usize];
            match channel {
                0 => {
                    if bytes.len() + part.len() > MAX_RESPONSE {
                        return Err("response_limit");
                    }
                    bytes.extend_from_slice(part);
                }
                1 => {
                    stderr_bytes += part.len();
                    if stderr_bytes > 65536 {
                        return Err("response_limit");
                    }
                }
                _ => {
                    if exit.push(part)? {
                        let ack = exit.acknowledgement()?;
                        let mut sent = 0;
                        while sent < ack.len() {
                            budget.check()?;
                            let count = unsafe {
                                send(
                                    output.0[6] as usize,
                                    ack[sent..].as_ptr(),
                                    (ack.len() - sent) as i32,
                                    0,
                                )
                            };
                            if count <= 0 {
                                if count == 0 || unsafe { WSAGetLastError() } != 10035 {
                                    return Err("guest_channel_failed");
                                }
                                std::thread::sleep(Duration::from_millis(10));
                            } else {
                                sent += count as usize;
                            }
                        }
                        acknowledged = true;
                        exit.success()?;
                    }
                }
            }
            buffer[..count as usize].fill(0);
        }
        if closed[0] && closed[1] && acknowledged {
            if input_sent != input.len() {
                return Err("guest_input_incomplete");
            }
            return Ok(bytes);
        }
        if !progressed {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
struct Output([*mut c_void; 7]);
impl Drop for Output {
    fn drop(&mut self) {
        for (index, handle) in self.0.iter().enumerate() {
            if !handle.is_null() {
                unsafe {
                    if index < 2 {
                        CloseHandle(*handle);
                    } else {
                        closesocket(*handle as usize);
                    }
                }
            }
        }
    }
}

pub(super) fn query(request: Request, budget: &Budget<'_>) -> Result<Vec<u8>> {
    const NATIVE_LIFETIME_QUALIFIED: bool = true;
    if !NATIVE_LIFETIME_QUALIFIED {
        return Err("unavailable");
    }
    request.validate()?;
    budget.check()?;
    // Never activate per-user COM registrations in a SYSTEM/elevated process.
    let owner = owner()?;
    if let Request::Processes { owner_sid, .. } = &request {
        if owner_sid != &owner {
            return Err("access_denied");
        }
    }
    let _lease = abi_guard()?;
    // Initialize Winsock before receiving transferred hvsockets.
    let _winsock = std::net::UdpSocket::bind("127.0.0.1:0").map_err(|_| "unavailable")?;
    let com = Com::open()?;
    budget.check()?;
    let rows = com.distributions()?;
    budget.check()?;
    match request {
        Request::Inventory {} => {
            let rows:Vec<_>=rows.into_iter().map(|(id,running,_,name)|serde_json::json!({"uuid":format!("{owner}/{id}"),"running":running,"tools_available":running,"display_name":name})).collect();
            serde_json::to_vec(&rows).map_err(|_| "invalid_guest_response")
        }
        Request::Processes {
            distribution_id, ..
        } => {
            if !rows.iter().any(|(id, running, version, _)| {
                id == &distribution_id && *running && *version == 2
            }) {
                return Err("unavailable");
            }
            com.processes(&distribution_id, budget)
        }
    }
}

pub(super) fn observe(
    identity: &str,
    program: &'static str,
    input: &[u8],
    budget: &Budget<'_>,
) -> Result<Vec<u8>> {
    let identity = super::Identity::parse(identity)?;
    budget.check()?;
    if owner()? != identity.owner {
        return Err("access_denied");
    }
    let _lease = abi_guard()?;
    let _winsock = std::net::UdpSocket::bind("127.0.0.1:0").map_err(|_| "unavailable")?;
    let com = Com::open()?;
    budget.check()?;
    if !com
        .distributions()?
        .iter()
        .any(|(id, running, version, _)| id == &identity.distribution && *running && *version == 2)
    {
        return Err("unavailable");
    }
    com.execute_program(&identity.distribution, budget, program, None, input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        os::windows::io::IntoRawSocket,
        sync::atomic::AtomicBool,
    };

    fn channels() -> (Output, Vec<TcpStream>) {
        let mut output = Output([std::ptr::null_mut(); 7]);
        let mut peers = vec![];
        for index in 2..7 {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (peer, _) = listener.accept().unwrap();
            peer.set_nodelay(true).unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            peer.set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            output.0[index] = stream.into_raw_socket() as usize as *mut c_void;
            peers.push(peer);
        }
        (output, peers)
    }

    fn exit(code: i32) -> Vec<u8> {
        [9u32, 16, 1, code as u32]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect()
    }

    #[test]
    fn process_channels_drain_stderr_and_acknowledge_fragmented_exit() {
        let (mut output, mut peers) = channels();
        let mut interop = peers.pop().unwrap();
        let control = peers.pop().unwrap();
        let mut stderr = peers.pop().unwrap();
        let mut stdout = peers.pop().unwrap();
        let writer = std::thread::spawn(move || {
            stdout.write_all(b"{\"complete\":true}").unwrap();
            drop(stdout);
            stderr.write_all(&[b'x'; 65536]).unwrap();
            drop(stderr);
            for byte in exit(0) {
                interop.write_all(&[byte]).unwrap();
            }
            let mut ack = [0; 16];
            interop.read_exact(&mut ack).unwrap();
            assert_eq!(ack.as_slice(), exit(0));
            drop(control);
        });
        let stop = AtomicBool::new(false);
        let budget = Budget::new(Duration::from_secs(3), &stop);
        assert_eq!(
            receive_process(&mut output, &budget).unwrap(),
            b"{\"complete\":true}"
        );
        writer.join().unwrap();
    }

    #[test]
    fn process_channels_refuse_failed_missing_or_foreign_exit() {
        for frame in [exit(127), vec![], vec![0; 16]] {
            let (mut output, mut peers) = channels();
            let mut interop = peers.pop().unwrap();
            let _control = peers.pop().unwrap();
            let stderr = peers.pop().unwrap();
            let mut stdout = peers.pop().unwrap();
            stdout.write_all(b"{\"complete\":true}").unwrap();
            drop(stdout);
            drop(stderr);
            interop.write_all(&frame).unwrap();
            interop.shutdown(std::net::Shutdown::Write).unwrap();
            let stop = AtomicBool::new(false);
            let budget = Budget::new(Duration::from_secs(2), &stop);
            assert!(receive_process(&mut output, &budget).is_err());
        }
    }

    #[test]
    fn cancelled_process_channels_close_control_without_waiting_for_guest_output() {
        let (mut output, mut peers) = channels();
        let _interop = peers.pop().unwrap();
        let mut control = peers.pop().unwrap();
        let stop = AtomicBool::new(true);
        let budget = Budget::new(Duration::from_secs(2), &stop);
        assert!(receive_process(&mut output, &budget).is_err());
        drop(output);
        assert_eq!(control.read(&mut [0; 1]).unwrap(), 0);
    }

    #[test]
    fn silent_process_channels_expire_and_release_control() {
        let (mut output, mut peers) = channels();
        let _interop = peers.pop().unwrap();
        let mut control = peers.pop().unwrap();
        let stop = AtomicBool::new(false);
        let budget = Budget::new(Duration::from_millis(20), &stop);
        assert!(receive_process(&mut output, &budget).is_err());
        drop(output);
        assert_eq!(control.read(&mut [0; 1]).unwrap(), 0);
    }

    #[test]
    fn process_channels_bound_each_output_stream_before_publication() {
        for (channel, limit) in [(3, MAX_RESPONSE), (4, 65536)] {
            let (mut output, mut peers) = channels();
            let mut stream = peers.remove(channel - 2);
            let writer = std::thread::spawn(move || stream.write_all(&vec![b'x'; limit + 1]));
            let stop = AtomicBool::new(false);
            let budget = Budget::new(Duration::from_secs(3), &stop);
            assert_eq!(receive_process(&mut output, &budget), Err("response_limit"));
            drop(output);
            // A refusal may close the socket before the writer's final syscall.
            let _ = writer.join().unwrap();
        }
    }

    #[test]
    fn private_input_is_complete_before_eof_and_never_appears_in_output_implicitly() {
        let (mut output, mut peers) = channels();
        let mut interop = peers.pop().unwrap();
        let _control = peers.pop().unwrap();
        let stderr = peers.pop().unwrap();
        let mut stdout = peers.pop().unwrap();
        let mut stdin = peers.pop().unwrap();
        let input = vec![b'q'; 24 * 1024];
        let writer = std::thread::spawn(move || {
            let mut received = vec![];
            stdin.read_to_end(&mut received).unwrap();
            assert_eq!(received, vec![b'q'; 24 * 1024]);
            stdout.write_all(b"synthetic acknowledgement").unwrap();
            drop(stdout);
            drop(stderr);
            interop.write_all(&exit(0)).unwrap();
            let mut ack = [0u8; 16];
            interop.read_exact(&mut ack).unwrap();
            assert_eq!(ack.as_slice(), exit(0));
        });
        let stop = AtomicBool::new(false);
        let budget = Budget::new(Duration::from_secs(3), &stop);
        assert_eq!(
            receive_process_with_input(&mut output, &budget, &input).unwrap(),
            b"synthetic acknowledgement"
        );
        writer.join().unwrap();
    }

    #[test]
    fn oversized_private_input_is_refused_before_publication() {
        let (mut output, _peers) = channels();
        let stop = AtomicBool::new(false);
        let budget = Budget::new(Duration::from_secs(1), &stop);
        assert_eq!(
            receive_process_with_input(&mut output, &budget, &vec![0; 24 * 1024 + 1]),
            Err("request_limit")
        );
    }
}

#[cfg(all(test, feature = "windows-qualification"))]
#[path = "native_qualification.rs"]
mod qualification;
