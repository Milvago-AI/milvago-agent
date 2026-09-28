use milvago_browser_agent::native::native_message;
use milvago_browser_agent::{
    Provision, Result, Store, enroll, flush, frame, ipc, refresh, watch, write_frame,
};
use serde_json::{Value, json};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use std::{fs, io, path::PathBuf};

const SERVICE_NAME: &str = "Milvago Agent Logger Community";
const CHANNEL: &str = "browser";

// Safe browser operations served over IPC to the relay shim.
fn handler() -> Arc<ipc::Handler> {
    Arc::new(|home: &Path, request: Value| {
        if request["op"] == "health" {
            milvago_browser_agent::health::local(home, "community", env!("CARGO_PKG_VERSION"))
        } else { native_message(home, request) }
    })
}

// One synchronization pass of the persistent watch loop.
fn watch_pass(home: &Path) -> Result<()> {
    milvago_browser_agent::bootstrap::resume(
        home,
        "community",
        &[
            "browser.navigation",
            "browser.conversation",
            "local.inspection",
        ],
    )?;
    milvago_browser_agent::shadow::refresh_home(home, chrono::Duration::seconds(30))?;
    let state = { Store::open(home)?.load()? };
    watch::deferred("heartbeat", milvago_browser_agent::shadow::heartbeat(&state));
    milvago_browser_agent::shadow::flush_home(home, false, chrono::Duration::zero())?;
    watch::deferred(
        "detection catalog refresh",
        milvago_browser_agent::detection::refresh_home(home),
    );
    watch::deferred(
        "detection health delivery",
        milvago_browser_agent::detection::flush_health_home(home),
    );
    Ok(())
}

// Persistent loop: retry delivery every five seconds and apply signed
// updates. Returns when `stop` is set (service shutdown).
fn run_watch(home: &Path, stop: &Arc<AtomicBool>) {
    let mut update_at: Option<Instant> = None;
    let mut policies = None;
    let mut status = watch::Status::default();
    while !stop.load(Ordering::Acquire) {
        status = watch::observe(home, status, watch_pass(home));
        #[cfg(windows)]
        watch::deferred(
            "browser cache preparation",
            milvago_browser_agent::cache_service::prepare_home(home, "community"),
        );
        if update_at.is_none_or(|last| last.elapsed() >= Duration::from_secs(60)) {
            update_at = Some(Instant::now());
            milvago_browser_agent::extension_update::watch_policies(&mut policies);
            if milvago_browser_agent::update::launch(home, "community", env!("CARGO_PKG_VERSION"))
                .unwrap_or_else(|error| {
                    milvago_browser_agent::log::info(&format!("signed update deferred; retrying in 60 seconds: {error}"));
                    false
                })
            {
                // Updater staged a new binary; exit so the service manager restarts us.
                milvago_browser_agent::log::info("signed update staged, restarting to apply it");
                std::process::exit(75);
            }
        }
        for _ in 0..5 {
            if stop.load(Ordering::Acquire) {
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }
}

// The service body: the IPC endpoint (for the browser relay) plus the watch loop.
fn run_service(home: &Path, stop: Arc<AtomicBool>) -> Result<()> {
    milvago_browser_agent::log::open(home);
    milvago_browser_agent::log::info(&format!(
        "agent service started, version {}",
        env!("CARGO_PKG_VERSION")
    ));
    let _extension_server = milvago_browser_agent::extension_update::start_for_service(home, stop.clone());
    let ipc_home = home.to_path_buf();
    let ipc_channel = CHANNEL.to_string();
    // Only development test binaries may isolate their pipe from installed
    // services. Neither this variable name nor the override is in release code.
    #[cfg(debug_assertions)]
    let ipc_channel = std::env::var("MILVAGO_TEST_CHANNEL").ok()
        .filter(|value| !value.is_empty() && value.len() <= 64
            && value.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'))
        .unwrap_or(ipc_channel);
    let ipc_stop = stop.clone();
    let ipc_handler = handler();
    let ipc_thread = std::thread::spawn(move || {
        // Losing the endpoint is not cosmetic: the browser extension fails closed
        // without it, so the failure must not be swallowed the way it was.
        let result = ipc::serve(&ipc_home, &ipc_channel, ipc::Access::Browser, ipc_stop.clone(), ipc_handler);
        if let Err(error) = &result {
            milvago_browser_agent::log::error(&format!(
                "browser IPC endpoint unavailable: {error}"
            ));
            ipc_stop.store(true, Ordering::Release);
        }
        result
    });
    run_watch(home, &stop);
    milvago_browser_agent::log::info("agent service stopped");
    ipc_thread.join().map_err(|_| "IPC service thread failed")?
}

#[cfg(windows)]
mod service {
    use super::*;
    use std::ffi::OsString;
    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };
    define_windows_service!(entry, main);
    fn main(_: Vec<OsString>) {
        let stop = Arc::new(AtomicBool::new(false));
        let signal = stop.clone();
        let Ok(status) = service_control_handler::register(SERVICE_NAME, move |event| match event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                signal.store(true, Ordering::Release);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }) else {
            return;
        };
        let report = |state, code| {
            status.set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: state,
                controls_accepted: if state == ServiceState::Running {
                    ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
                } else {
                    ServiceControlAccept::empty()
                },
                exit_code: ServiceExitCode::Win32(code),
                checkpoint: 0,
                wait_hint: Duration::from_secs(10),
                process_id: None,
            })
        };
        let _ = report(ServiceState::Running, 0);
        let result = match std::env::args_os().nth(2) {
            Some(dir) => run_service(&PathBuf::from(dir), stop),
            None => {
                let _ = report(ServiceState::Stopped, 1);
                return;
            }
        };
        let _ = report(ServiceState::Stopped, if result.is_ok() { 0 } else { 1 });
    }
    pub fn start() -> Result<()> {
        service_dispatcher::start(SERVICE_NAME, entry)?;
        Ok(())
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // The browser launches this binary as the native-messaging host in the user
    // session; relay to the machine service instead of touching state directly.
    if milvago_browser_agent::native::browser_caller(&args) {
        return ipc::relay(CHANNEL);
    }
    if args.first().is_some_and(|s| s == "--version") {
        println!("Milvago Agent Logger Community {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let op = args.first().map(String::as_str).unwrap_or("help");
    #[cfg(windows)]
    if op == "validate-msi" || op == "validate-json" {
        let path = Path::new(args.get(1).ok_or("package required")?);
        let bytes = if op == "validate-msi" {
            milvago_browser_agent::bootstrap::msi_provision(path)?
        } else {
            let file = std::fs::File::open(path)?;
            use std::io::Read;
            let mut bytes = Vec::new();
            file.take(16385).read_to_end(&mut bytes)?;
            if bytes.len() > 16384 { return Err("provisioning file too large".into()); }
            bytes
        };
        milvago_browser_agent::bootstrap::validate_organization_package(&bytes, "community")?;
        return Ok(());
    }
    if matches!(op, "extension-tls" | "extension-serve") {
        let directory = Path::new(args.get(1).ok_or("TLS directory required")?);
        if op == "extension-tls" {
            println!("{}", milvago_browser_agent::extension_tls::prepare(directory)?);
        } else {
            let stop = Arc::new(AtomicBool::new(false));
            let _server = milvago_browser_agent::extension_update::start(directory, stop.clone())?
                .ok_or("embedded extensions required")?;
            println!("{}", milvago_browser_agent::extension_update::info()?);
            while !stop.load(Ordering::Acquire) { std::thread::sleep(Duration::from_secs(1)); }
        }
        return Ok(());
    }
    if op == "extension-info" {
        println!("{}", milvago_browser_agent::extension_update::info()?);
        return Ok(());
    }
    // What the installer writes into config\milvago.toml on a first installation, so
    // the documented defaults come from the agent that applies them. An argument
    // names a certificate the installer staged, relative to the configuration
    // directory.
    if op == "default-configuration" {
        print!(
            "{}",
            milvago_browser_agent::config::default_document(args.get(1).map(String::as_str))?
        );
        return Ok(());
    }
    if op == "health" {
        println!("{}", milvago_browser_agent::health::wait(CHANNEL, ipc::Access::Browser, "community", env!("CARGO_PKG_VERSION"))?);
        return Ok(());
    }
    if op == "help" {
        println!(
            "milvago-browser-agent service <state-dir>\nmilvago-browser-agent watch <state-dir>\nmilvago-browser-agent enroll <state-dir> <provision.json> <hostname>\nmilvago-browser-agent sync <state-dir>\nmilvago-browser-agent status <state-dir>"
        );
        return Ok(());
    }
    if op == "service" {
        let home = PathBuf::from(args.get(1).ok_or("state directory required")?);
        #[cfg(windows)]
        {
            let _ = &home;
            return service::start();
        }
        #[cfg(not(windows))]
        {
            return run_service(&home, Arc::new(AtomicBool::new(false)));
        }
    }
    let home = PathBuf::from(args.get(1).ok_or("state directory required")?);
    // A one-shot command must honour the administrator's `[tls]` settings exactly
    // like the running service; the log stays quiet here, only the configuration is
    // registered.
    milvago_browser_agent::config::open(&home);
    if op == "installation-info" {
        println!(
            "{}",
            json!({"server_url": milvago_browser_agent::bootstrap::installation_server(&home)?})
        );
        return Ok(());
    }
    match op {
        "bootstrap" | "bootstrap-msi" => {
            let file = PathBuf::from(args.get(2).ok_or("installer configuration required")?);
            let bytes = if op == "bootstrap-msi" {
                #[cfg(windows)]
                {
                    milvago_browser_agent::bootstrap::msi_provision(&file)?
                }
                #[cfg(not(windows))]
                {
                    return Err("MSI requires Windows".into());
                }
            } else {
                if fs::metadata(&file)?.len() > 16384 {
                    return Err("installer configuration too large".into());
                }
                fs::read(file)?
            };
            milvago_browser_agent::bootstrap::stage(
                &home,
                &bytes,
                args.get(3).ok_or("hostname required")?,
                "community",
                milvago_browser_agent::bootstrap::replace_foreign_flag(&args, 4)?,
            )?;
            if milvago_browser_agent::bootstrap::resume(
                &home,
                "community",
                &[
                    "browser.navigation",
                    "browser.conversation",
                    "local.inspection",
                ],
            )
            .is_err()
            {
                eprintln!("Milvago registration pending; the background agent will retry.");
            }
        }
        "enroll" | "enroll-v2" => {
            let file = PathBuf::from(args.get(2).ok_or("provisioning file required")?);
            if fs::metadata(&file)?.len() > 16384 {
                return Err("provisioning file too large".into());
            }
            let provision: Provision = serde_json::from_slice(&fs::read(&file)?)?;
            let host = args.get(3).ok_or("explicit hostname required")?;
            let store = Store::open(&home)?;
            if op == "enroll-v2" {
                milvago_browser_agent::shadow::enroll(
                    &store,
                    &provision,
                    host,
                    "browser",
                    &[
                        "browser.navigation",
                        "browser.conversation",
                        "local.inspection",
                    ],
                )?;
            } else {
                enroll(&store, &provision, host)?;
            }
            println!("Enrolled. Administrator approval is required before collection.");
        }
        "sync" => {
            let store = Store::open(&home)?;
            let mut state = store.load()?;
            let updated = refresh(&mut state);
            store.save(&state)?;
            updated?;
            let _ = milvago_browser_agent::shadow::heartbeat(&state);
            let count = flush(&mut state)?;
            store.save(&state)?;
            println!("Policy verified; {count} events acknowledged.");
        }
        "watch" => {
            // Foreground combined loop (dev/manual). The service op is preferred
            // in production; this keeps a runnable path for testing the IPC.
            run_service(&home, Arc::new(AtomicBool::new(false)))?;
        }
        "sync-v2" => {
            let store = Store::open(&home)?;
            let mut state = store.load()?;
            let policy = milvago_browser_agent::shadow::refresh(&mut state);
            store.save(&state)?;
            policy?;
            let count = milvago_browser_agent::shadow::flush(&mut state);
            store.save(&state)?;
            println!("Signed policy v2 verified; {} events acknowledged.", count?);
        }
        "associate" => println!("{}", native_message(&home, json!({"op":"associate"}))?),
        "status" => println!("{}", native_message(&home, json!({"op":"status"}))?),
        "native" => {
            let mut input = io::stdin().lock();
            let mut output = io::stdout().lock();
            while let Some(mut request) = frame(&mut input)? {
                // Identity is the IPC server's to state, never a frame's.
                if let Some(object) = request.as_object_mut() { object.remove("caller"); }
                let answer = match native_message(&home, request) {
                    Ok(v) => v,
                    Err(_) => json!({"ok":false,"error":"operation_refused"}),
                };
                write_frame(&mut output, &answer)?;
            }
        }
        _ => return Err("unknown command".into()),
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("Milvago: {error}");
        std::process::exit(1);
    }
}
