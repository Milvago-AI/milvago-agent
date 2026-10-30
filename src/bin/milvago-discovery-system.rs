//! Dedicated system collector. It never starts the browser bridge.
#[cfg(target_os = "linux")]
fn main() {
    use milvago_browser_agent::discovery_privileged::{enrollment, service};
    use std::{
        io::Read,
        path::Path,
        sync::atomic::{AtomicBool, Ordering},
    };
    static STOP: AtomicBool = AtomicBool::new(false);
    extern "C" fn stop(_: libc::c_int) {
        STOP.store(true, Ordering::Release);
    }
    let result = (|| -> milvago_browser_agent::Result<()> {
        if unsafe { libc::geteuid() } != 0 {
            return Err("the dedicated system service or administrator is required".into());
        }
        let configuration = Path::new("/etc/milvago-discovery");
        let home = Path::new("/var/lib/milvago-discovery");
        let runtime = Path::new("/run/milvago-discovery");
        let arguments: Vec<_> = std::env::args_os().skip(1).collect();
        if arguments.len() != 1 {
            return Err("expected run, bootstrap or install-anchor".into());
        }
        if arguments[0] == "bootstrap" {
            milvago_browser_agent::config::open(home);
            return enrollment::resume(configuration, home);
        }
        if arguments[0] == "install-anchor" {
            // Only an administrator supplies this root-owned binding. Never
            // promote a device identity from the browser's writable state.
            let mut bytes = Vec::new();
            std::io::stdin().take(16385).read_to_end(&mut bytes)?;
            if bytes.len() > 16384 {
                return Err("system discovery anchor exceeds its budget".into());
            }
            return enrollment::install_binding(configuration, home, &bytes);
        }
        if arguments[0] != "run" {
            return Err("expected run, bootstrap or install-anchor".into());
        }
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = stop as *const () as usize;
            libc::sigemptyset(&mut action.sa_mask);
            if libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut()) != 0
                || libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut()) != 0
            {
                return Err("system discovery shutdown handler unavailable".into());
            }
        }
        service::run(configuration, home, runtime, &STOP)
    })();
    if let Err(error) = result {
        eprintln!("System discovery: {error}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
mod windows {
    use milvago_browser_agent::{Result, discovery_windows_system as discovery};
    use std::{
        ffi::OsString,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };
    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };
    define_windows_service!(entry, service_main);
    fn service_main(_: Vec<OsString>) {
        // StartService arguments are untrusted. Only the installer-controlled
        // process command line selects this fixed service entry point.
        if std::env::args_os().skip(1).collect::<Vec<_>>() != [OsString::from("service")] {
            return;
        }
        let Ok(name) = discovery::service_name(discovery::edition()) else {
            return;
        };
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let Ok(status) = service_control_handler::register(name, move |event| match event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                stopping.store(true, Ordering::Release);
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
                controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
                exit_code: ServiceExitCode::Win32(code),
                checkpoint: 0,
                wait_hint: Duration::from_secs(40),
                process_id: None,
            })
        };
        if report(ServiceState::Running, 0).is_err() {
            return;
        }
        let result = discovery::run(stop);
        let _ = report(ServiceState::Stopped, u32::from(result.is_err()));
    }
    pub fn main() -> Result<()> {
        let args: Vec<_> = std::env::args_os().skip(1).collect();
        if args == [OsString::from("--capabilities")] {
            println!(
                "{}",
                serde_json::json!({"version":env!("CARGO_PKG_VERSION"),"edition":discovery::edition(),"service":discovery::service_name(discovery::edition())?,"discovery_protocol":1,"additional_driver":false})
            );
            return Ok(());
        }
        if args == [OsString::from("discovery-wsl-probe")] {
            return milvago_browser_agent::discovery_wsl::probe();
        }
        if args == [OsString::from("discovery-vmware-probe")] {
            return milvago_browser_agent::discovery_vmware::probe();
        }
        if args == [OsString::from("service")] {
            return Ok(service_dispatcher::start(
                discovery::service_name(discovery::edition())?,
                entry,
            )?);
        }
        if args == [OsString::from("install-anchor")] {
            use std::io::Read;
            let mut bytes = zeroize::Zeroizing::new(Vec::new());
            std::io::stdin().take(16385).read_to_end(&mut bytes)?;
            return discovery::initialize(&bytes);
        }
        if args == [OsString::from("install-staged-anchor")] {
            return discovery::initialize_staged();
        }
        Err("expected service, install-anchor or install-staged-anchor".into())
    }
}

#[cfg(windows)]
fn main() {
    if let Err(error) = windows::main() {
        eprintln!("System discovery: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
fn main() {
    eprintln!("The dedicated system discovery collector requires Windows or Linux.");
    std::process::exit(1);
}
