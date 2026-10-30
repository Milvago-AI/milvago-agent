//! DNS request metadata only. No packet socket, DNS answers or ETL files.
use super::*;

const SESSION_NAME: &str = "MilvagoDiscoveryDNS";
const METADATA_REALTIME_MODE: u32 = 0x1000_0100;
const STOP_ON_HYBRID: u32 = 0x0040_0000;
const PERSIST_ON_HYBRID: u32 = 0x0080_0000;

fn metadata_mode(mode: u32) -> bool {
    // ETW reports its default hybrid-shutdown policy even when no flag was
    // supplied at creation. Neither policy permits file or buffering modes.
    [
        METADATA_REALTIME_MODE,
        METADATA_REALTIME_MODE | STOP_ON_HYBRID,
        METADATA_REALTIME_MODE | PERSIST_ON_HYBRID,
    ]
    .contains(&mode)
}

struct SessionIdentity<'a> {
    name: &'a str,
    signature_matches: bool,
    metadata_only: bool,
}

fn recover_existing(
    identity: Option<SessionIdentity<'_>>,
    stop: impl FnOnce() -> Result<(), CoverageStatus>,
) -> Result<(), CoverageStatus> {
    let Some(identity) = identity else {
        return Ok(());
    };
    if !identity.name.eq_ignore_ascii_case(SESSION_NAME)
        || !identity.signature_matches
        || !identity.metadata_only
    {
        return Err(CoverageStatus::Denied);
    }
    stop()
}

#[derive(Default)]
pub(super) struct DnsState {
    queries: BTreeMap<String, i64>,
    status: Option<CoverageStatus>,
    saturated: bool,
    window: Option<Instant>,
    received: u16,
}

fn request_event(id: u16, version: u8) -> bool {
    id == 3006 && version == 0
}

fn event_time(timestamp: i64, received: i64) -> Option<i64> {
    // ProcessTrace converts QPC timestamps to FILETIME without RAW_TIMESTAMP.
    let seconds = (timestamp / 10_000_000).checked_sub(11_644_473_600)?;
    (seconds >= 0 && seconds <= received && received.saturating_sub(seconds) <= 3600)
        .then_some(seconds)
}

fn query_name(data: &[u8]) -> Option<String> {
    if data.len() > 8192 || data.len() % 2 != 0 {
        return None;
    }
    let mut name = String::with_capacity(64);
    for pair in data.chunks_exact(2).take(255) {
        let c = u16::from_le_bytes([pair[0], pair[1]]);
        if c == 0 {
            let host = name.strip_suffix('.').unwrap_or(&name).to_ascii_lowercase();
            return (!host.is_empty()
                && host.len() <= 253
                && host.split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && !label.starts_with('-')
                        && !label.ends_with('-')
                }))
            .then_some(host);
        }
        if c > 127 || !(c as u8).is_ascii_alphanumeric() && c != b'-' as u16 && c != b'.' as u16 {
            return None;
        }
        name.push(c as u8 as char);
    }
    None
}

fn accept(state: &mut State, stop: bool, data: &[u8], time: i64) {
    if stop
        || state.authorization.expires <= now()
        || Instant::now() >= state.authorization.deadline
    {
        state.dns.queries.clear();
        return;
    }
    let dns = &mut state.dns;
    let instant = Instant::now();
    if dns
        .window
        .is_none_or(|start| instant.duration_since(start) >= Duration::from_secs(1))
    {
        dns.window = Some(instant);
        dns.received = 0;
    }
    if dns.received >= 256 {
        dns.saturated = true;
        return;
    }
    dns.received += 1;
    let Some(host) = query_name(data) else {
        return;
    };
    if !state.authorization.hosts.contains(&host) {
        return;
    }
    if dns.queries.len() >= 1024 && !dns.queries.contains_key(&host) {
        dns.saturated = true;
        return;
    }
    dns.queries.insert(host, time);
}

pub(super) fn drain(
    state: &mut State,
    snapshot: &mut Snapshot,
    host: &str,
    budget: &mut collector::FieldBudget,
) {
    use milvago_discovery_engine::{EntityKind, Field, Source};
    let queries = std::mem::take(&mut state.dns.queries);
    let mut saturated = std::mem::take(&mut state.dns.saturated);
    for (hostname, time) in queries {
        if time < 0
            || time > snapshot.observed_at
            || snapshot.observed_at.saturating_sub(time) > 3600
        {
            continue;
        }
        if !snapshot
            .entities
            .iter()
            .any(|entity| entity.id == host && entity.kind == EntityKind::Host)
        {
            continue;
        }
        if budget.insert(
            snapshot,
            host,
            Source::HostDnsQuery,
            BTreeMap::from([(Field::RemoteHost, vec![hostname])]),
        ) {
            if let Some(fact) = snapshot.facts.last_mut() {
                fact.observed_at = time;
            }
        } else {
            saturated = true;
        }
    }
    collector::coverage(
        snapshot,
        "windows-dns",
        if saturated {
            CoverageStatus::Saturated
        } else {
            state.dns.status.unwrap_or(CoverageStatus::Unavailable)
        },
        false,
    );
}

#[cfg(windows)]
mod native {
    use super::*;
    use windows_sys::{
        Win32::{
            Foundation::{
                CloseHandle, ERROR_ACCESS_DENIED, ERROR_SUCCESS, ERROR_WMI_INSTANCE_NOT_FOUND,
                HANDLE, WAIT_ABANDONED, WAIT_OBJECT_0,
            },
            System::{
                Diagnostics::Etw::*,
                Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject},
            },
        },
        core::GUID,
    };
    const PROVIDER: GUID = GUID::from_u128(0x1c95126e_7eea_49a9_a3fe_a378b03ddb4d);
    const SESSION_GUID: GUID = GUID::from_u128(0xe6be26a6_b2a4_4fca_9776_679f3dc74e12);
    const NATIVE_LIFETIME_QUALIFIED: bool = true;
    const _: () = {
        assert!(
            METADATA_REALTIME_MODE
                == EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING
        );
        assert!(STOP_ON_HYBRID == EVENT_TRACE_STOP_ON_HYBRID_SHUTDOWN);
        assert!(PERSIST_ON_HYBRID == EVENT_TRACE_PERSIST_ON_HYBRID_SHUTDOWN);
    };

    fn same_guid(left: &GUID, right: &GUID) -> bool {
        left.data1 == right.data1
            && left.data2 == right.data2
            && left.data3 == right.data3
            && left.data4 == right.data4
    }

    struct Controller(HANDLE);
    impl Controller {
        fn acquire() -> Result<Self, CoverageStatus> {
            // A kernel mutex is released even when its owning process crashes.
            // Another live controller is never displaced, including across editions.
            let handle = unsafe {
                CreateMutexW(
                    std::ptr::null(),
                    0,
                    windows_sys::core::w!("Global\\MilvagoDiscoveryDNSController"),
                )
            };
            if handle.is_null() {
                return Err(CoverageStatus::Denied);
            }
            match unsafe { WaitForSingleObject(handle, 0) } {
                WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(Self(handle)),
                _ => {
                    unsafe {
                        CloseHandle(handle);
                    }
                    Err(CoverageStatus::Unavailable)
                }
            }
        }
    }
    impl Drop for Controller {
        fn drop(&mut self) {
            unsafe {
                ReleaseMutex(self.0);
                CloseHandle(self.0);
            }
        }
    }

    #[repr(C)]
    struct Properties {
        value: EVENT_TRACE_PROPERTIES,
        name: [u16; 1024],
        file: [u16; 1024],
    }
    impl Properties {
        fn new(name: &[u16]) -> Self {
            let mut properties = Self {
                value: EVENT_TRACE_PROPERTIES::default(),
                name: [0; 1024],
                file: [0; 1024],
            };
            properties.name[..name.len()].copy_from_slice(name);
            properties.value.Wnode.BufferSize = std::mem::size_of::<Self>() as u32;
            properties.value.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            properties.value.Wnode.ClientContext = 1;
            properties.value.BufferSize = 16;
            properties.value.MinimumBuffers = 2;
            properties.value.MaximumBuffers = 4;
            properties.value.FlushTimer = 1;
            properties.value.LogFileMode = METADATA_REALTIME_MODE | STOP_ON_HYBRID;
            properties.value.LoggerNameOffset = std::mem::offset_of!(Self, name) as u32;
            properties
        }
        fn for_query(name: &[u16]) -> Self {
            let mut properties = Self::new(name);
            properties.value.LogFileNameOffset = std::mem::offset_of!(Self, file) as u32;
            properties
        }
        fn metadata_only(&self) -> bool {
            self.value.LoggerNameOffset == std::mem::offset_of!(Self, name) as u32
                && (self.value.LogFileNameOffset == 0
                    || self.value.LogFileNameOffset == std::mem::offset_of!(Self, file) as u32)
                && self.file[0] == 0
                && metadata_mode(self.value.LogFileMode)
        }
        fn prepare_stop(&mut self) {
            // QUERY returns an output filename slot even when the name is empty.
            // A subsequent control operation must not interpret it as an update.
            self.value.LogFileNameOffset = 0;
            self.value.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        }
    }
    struct Session {
        handle: CONTROLTRACE_HANDLE,
        properties: Properties,
    }
    impl Drop for Session {
        fn drop(&mut self) {
            // Only the handle returned by our successful StartTrace is stopped.
            self.properties.prepare_stop();
            unsafe {
                ControlTraceW(
                    self.handle,
                    std::ptr::null(),
                    &mut self.properties.value,
                    EVENT_TRACE_CONTROL_STOP,
                );
            }
        }
    }
    struct Context {
        state: Arc<Mutex<State>>,
        stop: Arc<AtomicBool>,
    }

    unsafe extern "system" fn event(record: *mut EVENT_RECORD) {
        // ETW owns the record and its user data for this callback only.
        let _ = std::panic::catch_unwind(|| unsafe {
            let Some(record) = record.as_ref() else {
                return;
            };
            let header = &record.EventHeader;
            #[cfg(all(test, feature = "windows-qualification"))]
            if same_guid(&header.ProviderId, &PROVIDER) {
                qualification::received(header.EventDescriptor.Id);
            }
            if !same_guid(&header.ProviderId, &PROVIDER)
                || !request_event(header.EventDescriptor.Id, header.EventDescriptor.Version)
                || record.UserData.is_null()
                || record.UserDataLength > 8192
            {
                return;
            }
            let Some(context) = (record.UserContext as *const Context).as_ref() else {
                return;
            };
            let Ok(mut state) = context.state.try_lock() else {
                return;
            };
            let Some(time) = event_time(header.TimeStamp, now()) else {
                return;
            };
            let data = std::slice::from_raw_parts(
                record.UserData as *const u8,
                record.UserDataLength as usize,
            );
            accept(&mut state, context.stop.load(Ordering::Acquire), data, time);
        });
    }

    unsafe extern "system" fn buffer(logfile: *mut EVENT_TRACE_LOGFILEW) -> u32 {
        std::panic::catch_unwind(|| unsafe {
            let Some(logfile) = logfile.as_ref() else {
                return 0;
            };
            let Some(context) = (logfile.Context as *const Context).as_ref() else {
                return 0;
            };
            if logfile.EventsLost > 0 {
                if let Ok(mut state) = context.state.try_lock() {
                    state.dns.saturated = true;
                }
            }
            u32::from(active(&context.state, &context.stop))
        })
        .unwrap_or(0)
    }

    fn active(state: &Arc<Mutex<State>>, stop: &AtomicBool) -> bool {
        !stop.load(Ordering::Acquire)
            && state.lock().is_ok_and(|state| {
                state.authorization.expires > now() && Instant::now() < state.authorization.deadline
            })
    }
    fn status(state: &Arc<Mutex<State>>, value: CoverageStatus) {
        if let Ok(mut state) = state.lock() {
            state.dns.status = Some(value);
        }
    }

    fn recover_session() -> Result<(), CoverageStatus> {
        let name: Vec<u16> = SESSION_NAME.encode_utf16().chain(Some(0)).collect();
        let mut previous = Properties::for_query(&name);
        let existing = unsafe {
            ControlTraceW(
                CONTROLTRACE_HANDLE::default(),
                name.as_ptr(),
                &mut previous.value,
                EVENT_TRACE_CONTROL_QUERY,
            )
        };
        if existing == ERROR_SUCCESS {
            let length = previous
                .name
                .iter()
                .position(|character| *character == 0)
                .unwrap_or(previous.name.len());
            let previous_name = String::from_utf16(&previous.name[..length]).unwrap_or_default();
            let identity = SessionIdentity {
                name: &previous_name,
                signature_matches: same_guid(&previous.value.Wnode.Guid, &SESSION_GUID),
                metadata_only: previous.metadata_only(),
            };
            if let Err(error) = recover_existing(Some(identity), || {
                previous.prepare_stop();
                let result = unsafe {
                    ControlTraceW(
                        CONTROLTRACE_HANDLE::default(),
                        name.as_ptr(),
                        &mut previous.value,
                        EVENT_TRACE_CONTROL_STOP,
                    )
                };
                if result == ERROR_SUCCESS {
                    Ok(())
                } else {
                    Err(CoverageStatus::Unavailable)
                }
            }) {
                return Err(error);
            }
        } else if existing != ERROR_WMI_INSTANCE_NOT_FOUND {
            return Err(if existing == ERROR_ACCESS_DENIED {
                CoverageStatus::Denied
            } else {
                CoverageStatus::Unavailable
            });
        }
        Ok(())
    }

    pub(crate) fn cleanup_stale() -> Result<(), CoverageStatus> {
        let _controller = Controller::acquire()?;
        recover_session()
    }

    pub(crate) fn observe(state: Arc<Mutex<State>>, stop: Arc<AtomicBool>) {
        // Cross-process ETW sessions outlive a crashed controller. Keep native
        // collection closed until owned-session recovery and crash cleanup are
        // implemented and qualified; Drop alone is not a lifetime guarantee.
        if !NATIVE_LIFETIME_QUALIFIED {
            status(&state, CoverageStatus::Unavailable);
            return;
        }
        observe_inner(state, stop);
    }

    fn observe_inner(state: Arc<Mutex<State>>, stop: Arc<AtomicBool>) {
        if !active(&state, &stop) {
            return;
        }
        let _controller = match Controller::acquire() {
            Ok(controller) => controller,
            Err(error) => {
                status(&state, error);
                return;
            }
        };
        if let Err(error) = recover_session() {
            status(&state, error);
            return;
        }
        let mut name: Vec<u16> = SESSION_NAME.encode_utf16().chain(Some(0)).collect();
        let mut properties = Properties::new(&name);
        properties.value.Wnode.Guid = SESSION_GUID;
        let mut handle = CONTROLTRACE_HANDLE::default();
        let result = unsafe { StartTraceW(&mut handle, name.as_ptr(), &mut properties.value) };
        if result != ERROR_SUCCESS {
            status(
                &state,
                if result == ERROR_ACCESS_DENIED {
                    CoverageStatus::Denied
                } else {
                    CoverageStatus::Unavailable
                },
            );
            return;
        }
        let session = Session { handle, properties };
        let mut ids = EVENT_FILTER_EVENT_ID {
            FilterIn: true,
            Reserved: 0,
            Count: 1,
            Events: [3006],
        };
        let mut descriptor = EVENT_FILTER_DESCRIPTOR {
            Ptr: &mut ids as *mut _ as u64,
            Size: std::mem::size_of_val(&ids) as u32,
            Type: EVENT_FILTER_TYPE_EVENT_ID,
        };
        let parameters = ENABLE_TRACE_PARAMETERS {
            Version: ENABLE_TRACE_PARAMETERS_VERSION_2,
            FilterDescCount: 1,
            EnableFilterDesc: &mut descriptor,
            ..Default::default()
        };
        // No unfiltered fallback. Response event 3008 must never reach this consumer.
        let result = unsafe {
            EnableTraceEx2(
                handle,
                &PROVIDER,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                5,
                0,
                0,
                1000,
                &parameters,
            )
        };
        if result != ERROR_SUCCESS {
            status(
                &state,
                if result == ERROR_ACCESS_DENIED {
                    CoverageStatus::Denied
                } else {
                    CoverageStatus::Unavailable
                },
            );
            return;
        }
        let context = Box::new(Context {
            state: Arc::clone(&state),
            stop: Arc::clone(&stop),
        });
        let mut logfile = EVENT_TRACE_LOGFILEW::default();
        logfile.LoggerName = name.as_mut_ptr();
        logfile.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(event);
        logfile.BufferCallback = Some(buffer);
        logfile.Context = (&*context as *const Context).cast_mut().cast();
        let consumer = unsafe { OpenTraceW(&mut logfile) };
        if consumer.Value == u64::MAX {
            status(&state, CoverageStatus::Unavailable);
            return;
        }
        let worker = thread::Builder::new()
            .name("milvago-discovery-dns".into())
            .spawn(move || {
                // Keep the callback context and session name alive through the final callback.
                let result =
                    unsafe { ProcessTrace(&consumer, 1, std::ptr::null(), std::ptr::null()) };
                drop(context);
                drop(name);
                result
            });
        let Ok(worker) = worker else {
            unsafe {
                CloseTrace(consumer);
            }
            status(&state, CoverageStatus::Unavailable);
            return;
        };
        status(&state, CoverageStatus::Partial);
        while active(&state, &stop) && !worker.is_finished() {
            thread::sleep(Duration::from_millis(50));
        }
        drop(session);
        unsafe {
            CloseTrace(consumer);
        }
        let _ = worker.join();
        status(
            &state,
            if active(&state, &stop) {
                CoverageStatus::Unavailable
            } else {
                CoverageStatus::Denied
            },
        );
    }
    #[cfg(all(test, feature = "windows-qualification"))]
    include!("discovery_network_windows_tests.rs");
}

#[cfg(windows)]
pub(super) use native::{cleanup_stale, observe};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn normalized_metadata_modes_never_allow_files_or_unknown_flags() {
        for mode in [
            METADATA_REALTIME_MODE,
            METADATA_REALTIME_MODE | STOP_ON_HYBRID,
            METADATA_REALTIME_MODE | PERSIST_ON_HYBRID,
        ] {
            assert!(metadata_mode(mode));
        }
        assert!(!metadata_mode(
            METADATA_REALTIME_MODE | STOP_ON_HYBRID | PERSIST_ON_HYBRID
        ));
        for bit in 0..32 {
            let extra = 1u32 << bit;
            if extra & (METADATA_REALTIME_MODE | STOP_ON_HYBRID | PERSIST_ON_HYBRID) == 0 {
                assert!(!metadata_mode(METADATA_REALTIME_MODE | extra));
            }
        }
        for mode in [0, 1, 2, 4, u32::MAX, METADATA_REALTIME_MODE & !0x100] {
            assert!(!metadata_mode(mode));
        }
    }
    #[test]
    fn session_recovery_refuses_foreign_names_identity_or_log_modes_and_propagates_failure() {
        let stops = std::cell::Cell::new(0);
        for (name, signature_matches, metadata_only) in [
            ("OtherTrace", true, true),
            ("MilvagoDiscoveryDNS-extra", true, true),
            (SESSION_NAME, false, true),
            (SESSION_NAME, true, false),
        ] {
            let result = recover_existing(
                Some(SessionIdentity {
                    name,
                    signature_matches,
                    metadata_only,
                }),
                || {
                    stops.set(stops.get() + 1);
                    Ok(())
                },
            );
            assert_eq!(result, Err(CoverageStatus::Denied));
        }
        assert!(
            recover_existing(None, || {
                stops.set(stops.get() + 1);
                Ok(())
            })
            .is_ok()
        );
        assert_eq!(stops.get(), 0);
        let result = recover_existing(
            Some(SessionIdentity {
                name: SESSION_NAME,
                signature_matches: true,
                metadata_only: true,
            }),
            || {
                stops.set(stops.get() + 1);
                Err(CoverageStatus::Unavailable)
            },
        );
        assert_eq!(result, Err(CoverageStatus::Unavailable));
        assert_eq!(stops.get(), 1);
        assert!(
            recover_existing(
                Some(SessionIdentity {
                    name: "milvagodiscoverydns",
                    signature_matches: true,
                    metadata_only: true
                }),
                || {
                    stops.set(stops.get() + 1);
                    Ok(())
                }
            )
            .is_ok()
        );
        assert_eq!(stops.get(), 2);
    }
    fn bytes(name: &str) -> Vec<u8> {
        name.encode_utf16()
            .chain(Some(0))
            .flat_map(u16::to_le_bytes)
            .collect()
    }
    pub(super) fn state() -> State {
        State {
            dns: DnsState::default(),
            authorization: Authorization {
                epoch: 1,
                catalog_revision: 1,
                expires: now() + 60,
                deadline: Instant::now() + Duration::from_secs(60),
                hosts: Arc::new(BTreeSet::from(["api.openai.com".into()])),
            },
            observations: BTreeMap::new(),
            status: CoverageStatus::Unavailable,
            saturated: false,
            vm_status: CoverageStatus::Unavailable,
            machines: vec![],
            next_mapping_refresh: Instant::now(),
            mapping_cursor: 0,
            #[cfg(target_os = "linux")]
            bindings: BTreeMap::new(),
        }
    }
    #[test]
    fn dns_event_gate_rejects_response_and_unknown_schema_and_stale_timestamps() {
        assert!(request_event(3006, 0));
        for (id, version) in [(3008, 0), (3006, 1), (0, 0), (1000, 0), (u16::MAX, u8::MAX)] {
            assert!(!request_event(id, version));
        }
        let received = 1_000_000;
        let stamp = |time| (11_644_473_600 + time) * 10_000_000;
        assert_eq!(event_time(stamp(received), received), Some(received));
        assert_eq!(
            event_time(stamp(received - 3600), received),
            Some(received - 3600)
        );
        for value in [
            0,
            i64::MIN,
            i64::MAX,
            stamp(received + 1),
            stamp(received - 3601),
        ] {
            assert_eq!(event_time(value, received), None);
        }
    }
    #[test]
    fn finished_network_listener_cannot_be_reauthorized_without_restart() {
        let thread = thread::spawn(|| {});
        let deadline = Instant::now() + Duration::from_secs(2);
        while !thread.is_finished() {
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
        let observer = Observer {
            state: Arc::new(Mutex::new(state())),
            stop: Arc::new(AtomicBool::new(false)),
            thread: Some(thread),
        };
        let catalog: Catalog =
            serde_json::from_slice(include_bytes!("../discovery-engine/catalog/factory.json"))
                .unwrap();
        assert!(!observer.authorize(&catalog, 1, now() + 60));
    }
    #[test]
    fn dns_metadata_is_catalogue_limited_rate_bounded_and_revocable() {
        let mut state = state();
        let time = now();
        for name in [
            "unknown.test",
            "api.openai.com.evil.test",
            "PRIVATE_FIXTURE",
            "data:image/png",
        ] {
            accept(&mut state, false, &bytes(name), time);
        }
        assert!(state.dns.queries.is_empty());
        accept(&mut state, false, &bytes("API.OPENAI.COM."), time);
        assert_eq!(
            state.dns.queries,
            BTreeMap::from([("api.openai.com".into(), time)])
        );
        assert!(state.observations.is_empty());
        for _ in 0..10_000 {
            accept(&mut state, false, &bytes("api.openai.com"), time);
        }
        assert!(state.dns.saturated);
        assert_eq!(state.dns.received, 256);
        assert_eq!(state.dns.queries.len(), 1);
        accept(&mut state, true, &bytes("api.openai.com"), time);
        assert!(state.dns.queries.is_empty());
        state.dns.window = None;
        accept(&mut state, false, &bytes("api.openai.com"), time);
        assert_eq!(state.dns.queries.len(), 1);
        state.authorization.expires = time;
        accept(&mut state, false, &bytes("api.openai.com"), time);
        assert!(state.dns.queries.is_empty());
        state.authorization.expires = time + 60;
        state.authorization.deadline = Instant::now();
        accept(&mut state, false, &bytes("api.openai.com"), time);
        assert!(state.dns.queries.is_empty());
    }
    #[test]
    fn dns_metadata_drains_as_host_query_only_and_forgets_raw_names() {
        let mut state = state();
        let time = now();
        accept(&mut state, false, &bytes("api.openai.com"), time);
        state.dns.status = Some(CoverageStatus::Partial);
        let mut snapshot = collector::empty("endpoint", 1, time);
        let host = collector::identity("host", &[&snapshot.scope]);
        snapshot.entities.push(milvago_discovery_engine::Entity {
            display: None,
            id: host.clone(),
            kind: milvago_discovery_engine::EntityKind::Host,
        });
        let mut budget = collector::FieldBudget::new(&snapshot);
        drain(&mut state, &mut snapshot, &host, &mut budget);
        assert_eq!(snapshot.facts.len(), 1);
        assert_eq!(
            snapshot.facts[0].source,
            milvago_discovery_engine::Source::HostDnsQuery
        );
        assert_eq!(snapshot.coverage[0].adapter, "windows-dns");
        assert!(!snapshot.coverage[0].complete);
        assert!(state.dns.queries.is_empty());
        let catalog =
            serde_json::from_slice(include_bytes!("../discovery-engine/catalog/factory.json"))
                .unwrap();
        let output = milvago_discovery_engine::Engine::compile(&catalog)
            .unwrap()
            .evaluate(&snapshot)
            .unwrap();
        assert_eq!(output.queries.len(), 1);
        assert!(output.communications.is_empty());
        assert!(output.identifications.is_empty());
        let pages = milvago_discovery_engine::report::pages(&snapshot, &output, 1, 1).unwrap();
        assert!(
            !serde_json::to_string(&pages)
                .unwrap()
                .contains("api.openai.com")
        );
    }
    #[test]
    fn dns_metadata_parser_rejects_hostile_names_and_does_not_read_following_fields() {
        let mut data = bytes("API.OPENAI.COM.");
        data.extend(bytes("PRIVATE_SERVER_LIST"));
        assert_eq!(query_name(&data).as_deref(), Some("api.openai.com"));
        for name in [
            "",
            "api.openai.com/secret",
            "api.openai.com:443",
            "api.openai.com\n",
            "é.test",
            "a..b",
            "-a.b",
            "a-.b",
            "data:image/png",
        ] {
            assert!(query_name(&bytes(name)).is_none(), "{name:?}");
        }
        for data in [
            vec![1],
            vec![65; 8194],
            vec![65, 0, 66, 0],
            bytes(&"a".repeat(254)),
            bytes(&format!("{}.test", "a".repeat(64))),
        ] {
            assert!(query_name(&data).is_none());
        }
    }
}
