//! Separate SYSTEM process; mutable agent state is never an authorization source.
use super::*;
use crate::{
    cache_windows::Directory,
    discovery::{Acquisition, Collected},
    ipc,
};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

pub use crate::discovery_system_protocol::{Request, Response};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    binding: String,
    ledger: Ledger,
    cache: Cache,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GuestFailures {
    binding: String,
    failures: Vec<String>,
}
struct Collector {
    directory: Directory,
    _lock: std::fs::File,
    anchor_bytes: Vec<u8>,
    home: PathBuf,
    authority: Authority,
    cache: Cache,
    observer: Option<crate::discovery_network::Observer>,
    active: Option<(DateTime<Utc>, Instant)>,
}
fn require_system() -> Result<()> {
    use windows_sys::Win32::{
        Foundation::CloseHandle,
        Security::{
            GetTokenInformation, IsWellKnownSid, TOKEN_QUERY, TOKEN_USER, TokenUser,
            WinLocalSystemSid,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err("system discovery identity unavailable".into());
    }
    struct Token(windows_sys::Win32::Foundation::HANDLE);
    impl Drop for Token {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    let token = Token(token);
    let mut bytes = [0usize; 512];
    let mut length = 0;
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            bytes.as_mut_ptr().cast(),
            std::mem::size_of_val(&bytes) as u32,
            &mut length,
        )
    } == 0
        || length < std::mem::size_of::<TOKEN_USER>() as u32
        || length as usize > std::mem::size_of_val(&bytes)
        || unsafe {
            IsWellKnownSid(
                (*(bytes.as_ptr().cast::<TOKEN_USER>())).User.Sid,
                WinLocalSystemSid,
            )
        } == 0
    {
        return Err("the dedicated SYSTEM discovery service is required".into());
    }
    Ok(())
}

fn require_installer() -> Result<()> {
    if require_system().is_ok() {
        return Ok(());
    }
    use windows_sys::Win32::{
        Foundation::CloseHandle,
        Security::{
            CheckTokenMembership, CreateWellKnownSid, GetTokenInformation, TOKEN_QUERY,
            TokenElevation, WinBuiltinAdministratorsSid,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(
            "an elevated administrator is required to install the discovery binding".into(),
        );
    }
    let (mut elevation, mut length) = (0u32, 0u32);
    let queried = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut u32).cast(),
            4,
            &mut length,
        )
    };
    unsafe {
        CloseHandle(token);
    }
    let mut sid = [0u32; 17];
    let mut size = std::mem::size_of_val(&sid) as u32;
    let mut member = 0;
    if queried == 0
        || length != 4
        || elevation == 0
        || unsafe {
            CreateWellKnownSid(
                WinBuiltinAdministratorsSid,
                std::ptr::null_mut(),
                sid.as_mut_ptr().cast(),
                &mut size,
            )
        } == 0
        || unsafe {
            CheckTokenMembership(std::ptr::null_mut(), sid.as_mut_ptr().cast(), &mut member)
        } == 0
        || member == 0
    {
        return Err(
            "an elevated administrator is required to install the discovery binding".into(),
        );
    }
    Ok(())
}
fn root(edition: &str) -> Result<PathBuf> {
    if !["community", "commercial"].contains(&edition) {
        return Err("invalid discovery edition".into());
    }
    Ok(
        PathBuf::from(std::env::var_os("ProgramData").ok_or("machine data root absent")?)
            .join("MilvagoDiscovery")
            .join(edition),
    )
}
pub(crate) fn channel(edition: &str) -> String {
    format!("discovery-system-{edition}")
}
impl Collector {
    fn open(home: &Path, edition: &str) -> Result<Self> {
        let directory = Directory::open(home, true)?;
        let lock = directory.lock()?;
        let anchor_bytes = directory.read("anchor.json", 16384)?;
        let anchor: Anchor = serde_json::from_slice(&anchor_bytes)?;
        if anchor.edition != edition
            || anchor.agent_service_sid != crate::cache_peer::service_sid(edition)?
        {
            return Err("Windows discovery agent binding mismatch".into());
        }
        let binding = anchor.binding()?;
        let mut saved = if directory.contains("state.bin")? {
            let saved: Saved =
                serde_json::from_slice(&directory.read("state.bin", 2 * 1024 * 1024)?)?;
            if saved.binding != binding {
                return Err("Windows discovery state binding changed".into());
            }
            saved
        } else {
            Saved {
                binding,
                ledger: Ledger::default(),
                cache: Cache::default(),
            }
        };
        if directory.contains("guest-failures.json")? {
            let failures: GuestFailures =
                serde_json::from_slice(&directory.read("guest-failures.json", 32768)?)?;
            if failures.binding != saved.binding
                || failures.failures.len() > 32
                || failures.failures.iter().any(|v| v.len() > 256)
            {
                return Err("Windows guest failure journal rejected".into());
            }
            saved.cache.guest_failures = failures.failures;
        }
        if saved.cache.pending.len() > 0
            || saved.cache.completed_runs.len() > 256
            || saved.cache.guest_failures.len() > 32
        {
            return Err("Windows discovery cache exceeds limit".into());
        }
        let authority = Authority::new(anchor, saved.ledger)?;
        Ok(Self {
            directory,
            _lock: lock,
            anchor_bytes,
            home: home.into(),
            authority,
            cache: saved.cache,
            observer: None,
            active: None,
        })
    }
    fn check_anchor(&self) -> Result<()> {
        if self.directory.read("anchor.json", 16384)? != self.anchor_bytes {
            return Err("Windows discovery anchor changed".into());
        }
        Ok(())
    }
    fn save(directory: &Directory, ledger: &Ledger, cache: &Cache) -> Result<()> {
        #[derive(Serialize)]
        struct Snapshot<'a> {
            binding: &'a str,
            ledger: &'a Ledger,
            cache: &'a Cache,
        }
        let bytes = serde_json::to_vec(&Snapshot {
            binding: &ledger.binding,
            ledger,
            cache,
        })?;
        if bytes.len() > 2 * 1024 * 1024 {
            return Err("Windows discovery cache exceeds limit".into());
        }
        directory.write("state.bin", &bytes)
    }
    fn observation(&mut self, policy: &Policy, deadline: Instant) -> Result<()> {
        if policy.configuration.network {
            if !self.observer.as_ref().is_some_and(|o| {
                o.authorize(
                    &policy.catalog,
                    policy.revision,
                    policy.expires_at.timestamp(),
                )
            }) {
                self.observer = None;
                self.observer = Some(crate::discovery_network::Observer::start(
                    &policy.catalog,
                    policy.revision,
                    policy.expires_at.timestamp(),
                )?);
            }
        } else {
            self.observer = None;
        }
        self.active = Some((policy.expires_at, deadline));
        Ok(())
    }
    fn handle(&mut self, peer: Peer, request: Request, stop: &AtomicBool) -> Result<Value> {
        self.check_anchor()?;
        if request.version != 1
            || request.sequence > i64::MAX as u64
            || request.collect && request.sequence == 0
        {
            return Err("invalid Windows discovery request".into());
        }
        if !request.collect
            && request.sequence == 0
            && request.authorization.payload.is_empty()
            && request.authorization.signature.is_empty()
        {
            if peer.service_sid != self.authority.anchor.agent_service_sid {
                return Err("Windows discovery peer rejected".into());
            }
            self.observer = None;
            self.active = None;
            return Ok(
                json!({"version":1,"revision":0,"catalog_revision":0,"status":"withdrawn","retry_after":0,"snapshot":null}),
            );
        }
        let directory = &self.directory;
        let cache = &self.cache;
        let decision = self.authority.authorize(
            &peer,
            &request.authorization,
            request.collect,
            Utc::now(),
            Instant::now(),
            |ledger| Self::save(directory, ledger, cache),
        )?;
        let (policy, status, retry, snapshot): (Policy, &str, u64, Option<Collected>) =
            match decision {
                Decision::Disabled { policy } => {
                    self.observer = None;
                    self.active = None;
                    (policy, "disabled", 0, None)
                }
                Decision::Wait {
                    policy,
                    retry_after,
                } => {
                    let validity = (policy.expires_at - Utc::now())
                        .to_std()
                        .unwrap_or_default()
                        .min(Duration::from_secs(600));
                    self.observation(&policy, Instant::now() + validity)?;
                    (
                        policy,
                        "waiting",
                        retry_after.as_secs() + u64::from(retry_after.subsec_nanos() > 0),
                        None,
                    )
                }
                Decision::Collect { policy, deadline } => {
                    if request.sequence <= self.cache.sequence {
                        return Err("stale Windows discovery sequence".into());
                    }
                    self.cache.sequence = request.sequence;
                    Self::save(&self.directory, &self.authority.ledger, &self.cache)?;
                    self.observation(&policy, deadline)?;
                    let directory = &self.directory;
                    let binding = &self.authority.ledger.binding;
                    let mut persist = |values: &[String]| {
                        if values.len() > 32 || values.iter().any(|v| v.len() > 256) {
                            return Err("Windows guest failure journal exceeds limit".into());
                        }
                        // Persist an authentication refusal before querying any
                        // further guest, including when the scan later fails.
                        directory.write(
                            "guest-failures.json",
                            &serde_json::to_vec(&GuestFailures {
                                binding: binding.clone(),
                                failures: values.to_vec(),
                            })?,
                        )
                    };
                    let snapshot = crate::discovery::acquire(
                        Acquisition {
                            policy: &policy,
                            home: &self.home,
                            device_id: &self.authority.anchor.device_id,
                            sequence: request.sequence,
                            cache: &mut self.cache,
                            stop,
                            observer: &mut self.observer,
                        },
                        &mut persist,
                    )?;
                    Self::save(&self.directory, &self.authority.ledger, &self.cache)?;
                    self.check_anchor()?;
                    if policy.expires_at <= Utc::now() || Instant::now() >= deadline {
                        self.observer = None;
                        self.active = None;
                        return Err("Windows discovery authorization expired".into());
                    }
                    (policy, "collected", 0, Some(snapshot))
                }
            };
        #[derive(Serialize)]
        struct Reply<'a> {
            version: u32,
            revision: u64,
            catalog_revision: u64,
            status: &'a str,
            retry_after: u64,
            snapshot: Option<&'a milvago_discovery_engine::Snapshot>,
        }
        let reply = Reply {
            version: 1,
            revision: policy.revision,
            catalog_revision: policy.catalog.revision,
            status,
            retry_after: retry,
            snapshot: snapshot.as_deref(),
        };
        if crate::shadow::serialized_size(&reply)? > 8 * 1024 * 1024 {
            return Err("Windows discovery response exceeds limit".into());
        }
        Ok(serde_json::to_value(reply)?)
    }
    fn maintain(&mut self) {
        if self
            .active
            .is_some_and(|(expiry, deadline)| expiry <= Utc::now() || Instant::now() >= deadline)
            || self.check_anchor().is_err()
        {
            self.observer = None;
            self.active = None;
        }
    }
}

pub(crate) fn request(edition: &str, request: &Request) -> Result<Response> {
    let value = ipc::exchange_timeout(
        &channel(edition),
        ipc::Access::DiscoveryAgent,
        &serde_json::to_value(request)?,
        Duration::from_secs(if request.collect { 35 } else { 5 }),
    )?;
    let response: Response = serde_json::from_value(value)?;
    if response.version != 1 {
        return Err("unsupported Windows discovery protocol".into());
    }
    Ok(response)
}
pub(super) fn run(edition: &str, stop: Arc<AtomicBool>) -> Result<()> {
    require_system()?;
    crate::discovery_network::cleanup_windows_session();
    let home = root(edition)?;
    let collector = Arc::new(Mutex::new(Collector::open(&home, edition)?));
    let watcher = collector.clone();
    let watcher_stop = stop.clone();
    let watcher = thread::spawn(move || {
        while !watcher_stop.load(Ordering::Acquire) {
            watcher.lock().unwrap_or_else(|p| p.into_inner()).maintain();
            thread::sleep(Duration::from_millis(200));
        }
        let mut collector = watcher.lock().unwrap_or_else(|p| p.into_inner());
        collector.observer = None;
        collector.active = None;
    });
    let handler_stop = stop.clone();
    let handler: Arc<ipc::Handler> = Arc::new(move |_, mut value| {
        let peer = Peer {
            service_sid: value["caller"]["service_sid"]
                .as_str()
                .ok_or("verified discovery peer absent")?
                .into(),
        };
        value
            .as_object_mut()
            .ok_or("discovery object required")?
            .remove("caller");
        let request: Request = serde_json::from_value(value)?;
        collector
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .handle(peer, request, &handler_stop)
    });
    let result = ipc::serve(
        &home,
        &channel(edition),
        ipc::Access::DiscoveryAgent,
        stop.clone(),
        handler,
    );
    stop.store(true, Ordering::Release);
    let _ = watcher.join();
    result
}

pub(super) fn initialize(edition: &str, bytes: &[u8]) -> Result<()> {
    require_installer()?;
    if bytes.len() > 16384 {
        return Err("Windows discovery anchor exceeds limit".into());
    }
    let anchor =
        super::administrator_anchor(bytes, edition, &crate::cache_peer::service_sid(edition)?)?;
    if anchor.edition != edition
        || anchor.agent_service_sid != crate::cache_peer::service_sid(edition)?
    {
        return Err("Windows discovery agent binding mismatch".into());
    }
    let binding = anchor.binding()?;
    let directory = Directory::open(&root(edition)?, true)?;
    let _lock = directory.lock()?;
    if directory.contains("anchor.json")? {
        let current: Anchor = serde_json::from_slice(&directory.read("anchor.json", 16384)?)?;
        if current.binding()? != binding {
            return Err(
                "Windows discovery anchor replacement requires explicit reprovisioning".into(),
            );
        }
        return Ok(());
    }
    if directory.contains("state.bin")? {
        return Err("Windows discovery anchor absent but ledger exists".into());
    }
    directory.write("anchor.json", &serde_json::to_vec(&anchor)?)
}

pub(super) fn initialize_staged(edition: &str) -> Result<()> {
    use std::io::Read;
    require_installer()?;
    let directory = Directory::open(&root(edition)?, true)?;
    let file = directory.hold_file(std::ffi::OsStr::new("binding.json"))?;
    let mut bytes = Vec::new();
    file.take(16385).read_to_end(&mut bytes)?;
    initialize(edition, &bytes)
}

#[cfg(all(test, feature = "windows-qualification"))]
mod qualification {
    use super::*;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::{
        Foundation::CloseHandle,
        Security::{
            GetTokenInformation, IsWellKnownSid, TOKEN_QUERY, TOKEN_USER, TokenUser,
            WinLocalSystemSid, WinNetworkServiceSid,
        },
        Storage::FileSystem::GetDriveTypeW,
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    #[test]
    #[ignore = "requires the owned offline Windows qualification VM, both SYSTEM and NetworkService passes"]
    fn native_installer_and_run_reject_an_unprivileged_service_token() {
        let identity =
            std::env::var("MILVAGO_DISCOVERY_WINDOWS_QA_ID").expect("owned QA media required");
        assert_eq!(
            uuid::Uuid::parse_str(&identity).unwrap().to_string(),
            identity
        );
        let executable = std::env::current_exe().unwrap();
        assert!(matches!(
            executable.file_name().and_then(|s| s.to_str()),
            Some("agent.exe" | "enterprise-agent.exe")
        ));
        let path = executable.to_str().unwrap();
        assert!(path.is_ascii() && path.as_bytes().get(1) == Some(&b':'));
        let root = PathBuf::from(format!("{}:\\", &path[..1]));
        let wide: Vec<_> = root.as_os_str().encode_wide().chain(Some(0)).collect();
        assert_eq!(
            unsafe { GetDriveTypeW(wide.as_ptr()) },
            5,
            "immutable QA disc required"
        );
        let marker = root.join(format!("{identity}.txt"));
        assert_eq!(std::fs::metadata(&marker).unwrap().len(), 36);
        assert_eq!(std::fs::read(marker).unwrap(), identity.as_bytes());

        let mut token = std::ptr::null_mut();
        assert_ne!(
            unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) },
            0
        );
        let mut data = [0usize; 512];
        let mut size = 0;
        let read = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                data.as_mut_ptr().cast(),
                std::mem::size_of_val(&data) as u32,
                &mut size,
            )
        };
        unsafe {
            CloseHandle(token);
        }
        assert_ne!(read, 0);
        assert!(
            (std::mem::size_of::<TOKEN_USER>()..=std::mem::size_of_val(&data))
                .contains(&(size as usize))
        );
        let sid = unsafe { (*(data.as_ptr().cast::<TOKEN_USER>())).User.Sid };
        let system = unsafe { IsWellKnownSid(sid, WinLocalSystemSid) } != 0;
        let network = unsafe { IsWellKnownSid(sid, WinNetworkServiceSid) } != 0;
        assert!(
            system ^ network,
            "only the two declared service principals belong in this recipe"
        );
        assert_eq!(require_installer().is_ok(), system);
        let error = initialize(super::super::edition(), b"{}")
            .unwrap_err()
            .to_string();
        if network {
            assert!(
                error.contains("elevated administrator"),
                "unprivileged initialization reached parsing or persistence"
            );
            let stopped = Arc::new(AtomicBool::new(true));
            assert_eq!(
                run(super::super::edition(), stopped)
                    .unwrap_err()
                    .to_string(),
                "the dedicated SYSTEM discovery service is required"
            );
        } else {
            assert!(
                !error.contains("elevated administrator"),
                "SYSTEM could not reach binding validation"
            );
        }
    }
}
