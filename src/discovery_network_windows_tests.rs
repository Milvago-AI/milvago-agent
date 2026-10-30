/// Opt-in native tests run only from the owned offline Windows qualification DVD.
mod qualification {
    use super::*;
    static RECEIVED_IDS: Mutex<BTreeMap<u16, u32>> = Mutex::new(BTreeMap::new());
    pub(super) fn received(id: u16) {
        *RECEIVED_IDS.lock().unwrap().entry(id).or_default() += 1;
    }
    use std::{
        fs,
        path::PathBuf,
        process::{Child, Command, Stdio},
    };
    use windows_sys::Win32::{
        NetworkManagement::Dns::{DNS_QUERY_NO_WIRE_QUERY, DnsFree, DnsFreeRecordList, DnsQuery_W},
        Storage::FileSystem::GetDriveTypeW,
        System::Threading::{GetCurrentProcess, GetProcessHandleCount},
    };

    fn guard() -> String {
        let id =
            std::env::var("MILVAGO_DISCOVERY_WINDOWS_QA_ID").expect("owned VM identity required");
        assert_eq!(uuid::Uuid::parse_str(&id).unwrap().to_string(), id);
        let executable = std::env::current_exe().unwrap();
        let root = executable.parent().unwrap();
        let mut wide: Vec<u16> = root.as_os_str().to_string_lossy().encode_utf16().collect();
        wide.push(0);
        assert_eq!(
            unsafe { GetDriveTypeW(wide.as_ptr()) },
            5,
            "qualification executable must reside on an optical drive"
        );
        let marker = root.join(format!("{id}.txt"));
        assert!(fs::metadata(&marker).unwrap().len() < 128);
        assert_eq!(fs::read_to_string(marker).unwrap(), id);
        assert!(PathBuf::from("C:/MilvagoQA").is_dir());
        id
    }

    fn query_session() -> Option<Properties> {
        let name: Vec<u16> = SESSION_NAME.encode_utf16().chain(Some(0)).collect();
        let mut properties = Properties::for_query(&name);
        let result = unsafe {
            ControlTraceW(
                CONTROLTRACE_HANDLE::default(),
                name.as_ptr(),
                &mut properties.value,
                EVENT_TRACE_CONTROL_QUERY,
            )
        };
        if result == ERROR_WMI_INSTANCE_NOT_FOUND {
            return None;
        }
        assert_eq!(result, ERROR_SUCCESS, "query own session");
        Some(properties)
    }

    struct Cleanup;
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = cleanup_stale();
        }
    }
    struct Listener {
        state: Arc<Mutex<State>>,
        stop: Arc<AtomicBool>,
        worker: Option<thread::JoinHandle<()>>,
    }
    impl Listener {
        fn start(lifetime: Duration) -> Self {
            let mut state = super::super::tests::state();
            state.authorization.deadline = Instant::now() + lifetime;
            let state = Arc::new(Mutex::new(state));
            let stop = Arc::new(AtomicBool::new(false));
            let shared = Arc::clone(&state);
            let stopped = Arc::clone(&stop);
            let worker = thread::spawn(move || observe_inner(shared, stopped));
            Self {
                state,
                stop,
                worker: Some(worker),
            }
        }
        fn ready(&self) {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if self.state.lock().unwrap().dns.status == Some(CoverageStatus::Partial) {
                    return;
                }
                assert!(
                    !self.worker.as_ref().unwrap().is_finished(),
                    "native DNS listener failed: {:?}",
                    self.state.lock().unwrap().dns.status
                );
                assert!(Instant::now() < deadline, "native DNS startup deadline");
                thread::sleep(Duration::from_millis(10));
            }
        }
    }
    impl Drop for Listener {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            if let Some(worker) = self.worker.take() {
                worker.join().unwrap();
            }
        }
    }
    fn dns_query(name: &str) {
        let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let mut records = std::ptr::null_mut();
        // Cache-only API calls still exercise the real provider without sending DNS.
        unsafe {
            DnsQuery_W(
                name.as_ptr(),
                1,
                DNS_QUERY_NO_WIRE_QUERY,
                std::ptr::null_mut(),
                &mut records,
                std::ptr::null_mut(),
            );
            if !records.is_null() {
                DnsFree(records.cast(), DnsFreeRecordList);
            }
        }
    }
    fn handles() -> u32 {
        let mut count = 0;
        assert_ne!(
            unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut count) },
            0
        );
        count
    }

    #[test]
    fn queried_metadata_requires_known_offsets_and_an_empty_file_name() {
        let name: Vec<u16> = SESSION_NAME.encode_utf16().chain(Some(0)).collect();
        let mut properties = Properties::for_query(&name);
        assert!(properties.metadata_only());
        for offset in [1, 2, u32::MAX, std::mem::size_of::<Properties>() as u32] {
            properties.value.LogFileNameOffset = offset;
            assert!(!properties.metadata_only());
        }
        properties.value.LogFileNameOffset = std::mem::offset_of!(Properties, file) as u32;
        properties.file[0] = b'x' as u16;
        assert!(!properties.metadata_only());
        properties.value.LogFileNameOffset = 0;
        assert!(!properties.metadata_only());
        properties.file[0] = 0;
        assert!(properties.metadata_only());
        properties.value.LoggerNameOffset = 0;
        assert!(!properties.metadata_only());
    }

    #[test]
    #[ignore = "Owned offline Windows VM DVD and windows-qualification feature required"]
    fn native_dns_request_metadata_is_filtered_and_revoked() {
        guard();
        RECEIVED_IDS.lock().unwrap().clear();
        cleanup_stale().unwrap();
        assert!(query_session().is_none());
        let _cleanup = Cleanup;
        let listener = Listener::start(Duration::from_secs(15));
        listener.ready();
        let properties = query_session().unwrap();
        assert!(same_guid(&properties.value.Wnode.Guid, &SESSION_GUID));
        assert!(properties.metadata_only());
        assert_eq!(
            properties.value.LogFileMode,
            METADATA_REALTIME_MODE | STOP_ON_HYBRID
        );
        dns_query("not-a-provider.invalid");
        dns_query("api.openai.com");
        let deadline = Instant::now() + Duration::from_secs(4);
        while !listener
            .state
            .lock()
            .unwrap()
            .dns
            .queries
            .contains_key("api.openai.com")
        {
            assert!(
                Instant::now() < deadline,
                "actual DNS request event missing"
            );
            // Provider enablement and delivery are asynchronous. Keep driving
            // real cache-only requests within the same bounded deadline.
            dns_query("api.openai.com");
            thread::sleep(Duration::from_millis(20));
        }
        let mut state = listener.state.lock().unwrap();
        assert_eq!(state.dns.queries.len(), 1);
        assert!(state.observations.is_empty());
        assert_eq!(
            RECEIVED_IDS
                .lock()
                .unwrap()
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            vec![3006],
            "non-request events crossed the kernel filter"
        );
        let mut snapshot = collector::empty("endpoint", 1, now());
        let host = collector::identity("host", &[&snapshot.scope]);
        snapshot.entities.push(milvago_discovery_engine::Entity {
            id: host.clone(),
            kind: milvago_discovery_engine::EntityKind::Host,
            display: None,
        });
        let mut budget = collector::FieldBudget::new(&snapshot);
        drain(&mut state, &mut snapshot, &host, &mut budget);
        drop(state);
        let catalog =
            serde_json::from_slice(include_bytes!("../discovery-engine/catalog/factory.json"))
                .unwrap();
        let result = milvago_discovery_engine::Engine::compile(&catalog)
            .unwrap()
            .evaluate(&snapshot)
            .unwrap();
        assert_eq!(result.queries.len(), 1);
        assert!(result.communications.is_empty() && result.identifications.is_empty());
        drop(listener);
        assert!(
            query_session().is_none(),
            "revocation left an active ETW session"
        );
    }

    #[test]
    #[ignore = "Owned offline Windows VM DVD and windows-qualification feature required"]
    fn native_dns_public_observer_respects_gate_and_revocation() {
        guard();
        cleanup_stale().unwrap();
        let _cleanup = Cleanup;
        let catalog =
            serde_json::from_slice(include_bytes!("../discovery-engine/catalog/factory.json"))
                .unwrap();
        let observer = Observer::start(&catalog, 1, now() + 30).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        if NATIVE_LIFETIME_QUALIFIED {
            while observer.state.lock().unwrap().dns.status != Some(CoverageStatus::Partial) {
                assert!(
                    !observer.thread.as_ref().unwrap().is_finished(),
                    "public observer failed to activate"
                );
                assert!(Instant::now() < deadline);
                thread::sleep(Duration::from_millis(10));
            }
            dns_query("api.openai.com");
            let deadline = Instant::now() + Duration::from_secs(4);
            while observer.state.lock().unwrap().dns.queries.is_empty() {
                assert!(
                    Instant::now() < deadline,
                    "public observer missed DNS query"
                );
                dns_query("api.openai.com");
                thread::sleep(Duration::from_millis(20));
            }
            let _ = observer.authorize(&catalog, 1, now() - 1);
            let mut snapshot = collector::empty("endpoint", 1, now());
            observer.drain(&mut snapshot);
            assert!(
                snapshot.facts.is_empty(),
                "revoked public observer exported metadata"
            );
        } else {
            while !observer.thread.as_ref().unwrap().is_finished() {
                assert!(Instant::now() < deadline);
                thread::sleep(Duration::from_millis(10));
            }
            assert_eq!(
                observer.state.lock().unwrap().dns.status,
                Some(CoverageStatus::Unavailable)
            );
        }
        drop(observer);
        assert!(query_session().is_none());
    }

    #[test]
    #[ignore = "Owned offline Windows VM DVD and windows-qualification feature required"]
    fn native_dns_kernel_event_filter_blocks_response_before_callback() {
        guard();
        cleanup_stale().unwrap();
        RECEIVED_IDS.lock().unwrap().clear();
        let _cleanup = Cleanup;
        let listener = Listener::start(Duration::from_secs(10));
        listener.ready();
        struct Provider(REGHANDLE);
        impl Drop for Provider {
            fn drop(&mut self) {
                unsafe {
                    EventUnregister(self.0);
                }
            }
        }
        let mut registration = 0;
        assert_eq!(
            unsafe { EventRegister(&PROVIDER, None, std::ptr::null(), &mut registration) },
            ERROR_SUCCESS
        );
        let provider = Provider(registration);
        let positive = EVENT_DESCRIPTOR {
            Id: 3006,
            Level: 4,
            ..Default::default()
        };
        let enabled_deadline = Instant::now() + Duration::from_secs(3);
        while !unsafe { EventEnabled(provider.0, &positive) } {
            assert!(
                Instant::now() < enabled_deadline,
                "fixture provider was not enabled"
            );
            thread::sleep(Duration::from_millis(10));
        }
        // Only fixed synthetic data is emitted in the disconnected QA VM.
        for (id, name) in [(3008, "PRIVATE_RESPONSE_FIXTURE"), (3006, "api.openai.com")] {
            let payload: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
            let descriptor = EVENT_DESCRIPTOR {
                Id: id,
                Level: 4,
                ..Default::default()
            };
            let data = EVENT_DATA_DESCRIPTOR {
                Ptr: payload.as_ptr() as u64,
                Size: (payload.len() * 2) as u32,
                ..Default::default()
            };
            assert_eq!(
                unsafe { EventWrite(provider.0, &descriptor, 1, &data) },
                ERROR_SUCCESS
            );
        }
        let deadline = Instant::now() + Duration::from_secs(4);
        while !listener
            .state
            .lock()
            .unwrap()
            .dns
            .queries
            .contains_key("api.openai.com")
        {
            assert!(
                Instant::now() < deadline,
                "positive request fixture not delivered"
            );
            thread::sleep(Duration::from_millis(20));
        }
        drop(provider);
        drop(listener);
        assert_eq!(
            RECEIVED_IDS
                .lock()
                .unwrap()
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            vec![3006],
            "response reached callback before parser rejection"
        );
        assert!(query_session().is_none());
    }

    #[test]
    #[ignore = "Owned offline Windows VM DVD and windows-qualification feature required"]
    fn native_dns_expiry_and_repeated_stop_do_not_retain_handles() {
        guard();
        cleanup_stale().unwrap();
        let _cleanup = Cleanup;
        let warmed = Listener::start(Duration::from_secs(10));
        warmed.ready();
        drop(warmed);
        let before = handles();
        for _ in 0..8 {
            let listener = Listener::start(Duration::from_secs(10));
            listener.ready();
            drop(listener);
            assert!(query_session().is_none());
        }
        let listener = Listener::start(Duration::from_secs(1));
        listener.ready();
        let deadline = Instant::now() + Duration::from_secs(4);
        while !listener.worker.as_ref().unwrap().is_finished() {
            assert!(
                Instant::now() < deadline,
                "expired ETW authorization remained active"
            );
            thread::sleep(Duration::from_millis(10));
        }
        drop(listener);
        assert!(query_session().is_none());
        assert_eq!(handles(), before, "ETW lifecycle retained handles");
    }

    #[test]
    #[ignore = "Owned offline Windows VM DVD and windows-qualification feature required"]
    fn native_dns_live_and_foreign_sessions_are_not_displaced() {
        guard();
        cleanup_stale().unwrap();
        let _cleanup = Cleanup;
        let listener = Listener::start(Duration::from_secs(10));
        listener.ready();
        let second = Listener::start(Duration::from_secs(10));
        let deadline = Instant::now() + Duration::from_secs(3);
        while !second.worker.as_ref().unwrap().is_finished() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            second.state.lock().unwrap().dns.status,
            Some(CoverageStatus::Unavailable)
        );
        drop(second);
        assert!(query_session().is_some());
        drop(listener);
        let name: Vec<u16> = SESSION_NAME.encode_utf16().chain(Some(0)).collect();
        let mut properties = Properties::new(&name);
        let foreign = GUID::from_u128(0x11111111_1111_4111_8111_111111111111);
        properties.value.Wnode.Guid = foreign;
        let mut handle = CONTROLTRACE_HANDLE::default();
        assert_eq!(
            unsafe { StartTraceW(&mut handle, name.as_ptr(), &mut properties.value) },
            ERROR_SUCCESS
        );
        let foreign_session = Session { handle, properties };
        assert_eq!(cleanup_stale(), Err(CoverageStatus::Denied));
        assert!(same_guid(
            &query_session().unwrap().value.Wnode.Guid,
            &foreign
        ));
        drop(foreign_session);
        assert!(query_session().is_none());
    }

    struct Process(Child);
    impl Drop for Process {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    #[test]
    #[ignore = "Native DNS subprocess helper; never run directly"]
    fn isolated_dns_child() {
        guard();
        assert_eq!(
            std::env::var("MILVAGO_DISCOVERY_DNS_ROLE").unwrap(),
            "orphan"
        );
        let listener = Listener::start(Duration::from_secs(30));
        listener.ready();
        fs::write("C:/MilvagoQA/dns-child-ready", b"1").unwrap();
        thread::sleep(Duration::from_secs(30));
        drop(listener);
    }

    #[test]
    #[ignore = "Owned offline Windows VM DVD and windows-qualification feature required"]
    fn native_dns_crash_is_recovered_even_when_next_worker_has_no_policy() {
        let id = guard();
        cleanup_stale().unwrap();
        let _cleanup = Cleanup;
        for activate in [true, false] {
            let marker = PathBuf::from("C:/MilvagoQA/dns-child-ready");
            if marker.exists() {
                fs::remove_file(&marker).unwrap();
            }
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "discovery_network::windows::native::qualification::isolated_dns_child",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env_clear()
                .env("SystemRoot", "C:/Windows")
                .env("WINDIR", "C:/Windows")
                .env("PATH", "C:/Windows/System32")
                .env("TEMP", "C:/MilvagoQA")
                .env("TMP", "C:/MilvagoQA")
                .env("MILVAGO_DISCOVERY_WINDOWS_QA_ID", &id)
                .env("MILVAGO_DISCOVERY_DNS_ROLE", "orphan")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let mut child = Process(command.spawn().unwrap());
            let deadline = Instant::now() + Duration::from_secs(5);
            while !marker.exists() {
                assert!(
                    child.0.try_wait().unwrap().is_none(),
                    "DNS child exited before ready"
                );
                assert!(Instant::now() < deadline, "DNS child startup deadline");
                thread::sleep(Duration::from_millis(10));
            }
            child.0.kill().unwrap();
            child.0.wait().unwrap();
            assert!(
                query_session().is_some(),
                "fixture did not reproduce an orphan ETW session"
            );
            if activate {
                let listener = Listener::start(Duration::from_secs(10));
                listener.ready();
                drop(listener);
            } else {
                // Exercise the actual worker entry with discovery stopped and no
                // provisioned identity, rather than calling cleanup directly.
                let stopped = Arc::new(AtomicBool::new(true));
                crate::discovery::spawn(PathBuf::from("C:/MilvagoQA/disabled"), stopped)
                    .unwrap()
                    .join()
                    .unwrap();
            }
            assert!(
                query_session().is_none(),
                "restart left the crashed observer's session active"
            );
        }
    }
}
