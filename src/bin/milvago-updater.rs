//! Update applier. Two shapes:
//!
//! * `apply` — the historic helper, spawned by the agent for a per-user installation.
//! * `service` — the privileged applier registered as a LocalSystem service for a
//!   per-machine installation. Starting it authorizes no installation: only the
//!   authenticated service channel may schedule update work. The separate browser
//!   channel inspects requests and keeps event custody under SYSTEM.
use milvago_browser_agent::update;
use std::path::{Path, PathBuf};

/// Re-derives the installed version and applies whatever the server authorizes.
/// The version is never taken from an argument: `update::verify` only rejects a
/// release older than the installed one, so an understated baseline would turn a
/// downgrade into an apparent upgrade.
fn apply_now(home: &Path, target: &Path, edition: &str, privileged: bool) -> update::Applied {
    let current = match update::installed_version(target) {
        Ok(version) => version,
        Err(_) => return update::Applied::Failed,
    };
    match update::apply(home, target, edition, &current, privileged) {
        Ok(outcome) => outcome,
        Err(_) => update::Applied::Failed,
    }
}

#[cfg(windows)]
mod service {
    use super::*;
    use std::ffi::OsString;
    use std::time::Duration;
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

    // The service control manager hands us whatever argument vector the caller of
    // StartService supplied, and SERVICE_START does not constrain its contents. We
    // therefore ignore it entirely and read our own command line, which comes only
    // from the binPath the installer wrote as SYSTEM.
    fn main(_: Vec<OsString>) {
        let args: Vec<String> = std::env::args().skip(2).collect();
        let (Some(home), Some(target), Some(edition)) =
            (args.first(), args.get(1), args.get(2))
        else {
            return;
        };
        let name = milvago_browser_agent::update::applier_service(edition);
        let requested_stop=std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let service_stop=requested_stop.clone();
        let Ok(status) = service_control_handler::register(&name, move |event| match event {
            ServiceControl::Stop=>{service_stop.store(true,std::sync::atomic::Ordering::Release);ServiceControlHandlerResult::NoError},
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            // An administrative stop is deferred until active MSI work finishes.
            // The browser has SERVICE_START only and cannot request this control.
            _ => ServiceControlHandlerResult::NotImplemented,
        }) else {
            return;
        };
        let report = |state, code| {
            status.set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: state,
                controls_accepted: ServiceControlAccept::STOP,
                exit_code: ServiceExitCode::Win32(code),
                checkpoint: 0,
                wait_hint: Duration::from_secs(900),
                process_id: None,
            })
        };
        let _ = report(ServiceState::Running, 0);
        let outcome = milvago_browser_agent::update_host::run(
            &PathBuf::from(home), &PathBuf::from(target), edition, requested_stop,
        );
        let _ = report(ServiceState::Stopped, u32::from(outcome.is_err()));
    }
    pub fn start(name: &str) -> windows_service::Result<()> {
        service_dispatcher::start(name, entry)
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.as_slice()==["--capabilities"] {
        println!("{}",milvago_browser_agent::browser_broker::capabilities());return;
    }
    let verb = args.first().map(String::as_str).unwrap_or("");
    let ok = match verb {
        // Historic per-user helper: the agent spawns it and supplies the baseline.
        "apply" if args.len() == 5 => update::apply(
            Path::new(&args[1]),
            Path::new(&args[2]),
            &args[3],
            &args[4],
            false,
        )
        .is_ok_and(|outcome| matches!(outcome, update::Applied::Installed | update::Applied::NoUpdate | update::Applied::RebootRequired)),
        // Privileged applier, run as a service by the service control manager.
        #[cfg(windows)]
        "service" if args.len() == 4 => {
            service::start(&update::applier_service(&args[3])).is_ok()
        }
        // Linux root applier, run by its systemd unit on the agent's request.
        #[cfg(unix)]
        "apply-root" if args.len() == 5 => update::apply_root(
            Path::new(&args[1]),
            Path::new(&args[2]),
            &args[3],
            &args[4],
        )
        .is_ok_and(|outcome| outcome.is_success()),
        #[cfg(windows)]
        "prepare-cache-msi" if args.len() == 3 => milvago_browser_agent::cache_service::initialize_msi(&args[1], Path::new(&args[2])).is_ok(),
        #[cfg(windows)]
        "prepare-cache-file" if args.len() == 3 => milvago_browser_agent::cache_service::initialize_file(&args[1], Path::new(&args[2])).is_ok(),
        // Same work as the service body, for diagnosis from an elevated prompt.
        "apply-now" if args.len() == 4 => {
            apply_now(Path::new(&args[1]), Path::new(&args[2]), &args[3], true)
                .is_success()
        }
        _ => {
            eprintln!(
                "usage: milvago-updater apply <state> <executable> <edition> <current-version>\n       milvago-updater apply-now <state> <executable> <edition>\n       milvago-updater service <state> <executable> <edition>"
            );
            false
        }
    };
    if !ok {
        eprintln!("Milvago update not applied; inspect campaign and local installation status.");
        std::process::exit(1);
    }
}
