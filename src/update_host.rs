//! Update service. Starting SCM never schedules an installation.
//! IPC admission and MSI execution run on separate threads.
//!
//! Windows: the service runs from boot and never stops for idleness (decision of
//! 2026-09-24). Its pipe names are then held from boot rather than freed after a minute,
//! when any user could create them first and keep updates and the offline cache from
//! ever being served. After an installation rewrites its binPath (binaries are
//! versioned), it exits with an error once idle so that SCM recovery restarts it on the
//! new binary.
use crate::{Result, ipc, update};
use serde_json::{Value, json};
use std::{path::Path, sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}}, time::{Duration, Instant}};

fn update_request(request: &Value) -> bool {
    request.as_object().is_some_and(|object| {
        object.keys().all(|key| matches!(key.as_str(), "protocol" | "op" | "caller"))
            && request["protocol"] == 1 && request["op"] == "update_apply"
    })
}
struct Lifecycle { busy: bool, last_request: Instant, stopping: bool, failed: bool }

/// Paths and edition come exclusively from the installer's SCM command line.
pub fn run(home: &Path, target: &Path, edition: &str, requested_stop:Arc<AtomicBool>) -> Result<()> {
    if !matches!(edition, "community" | "commercial") { return Err("invalid service edition".into()); }
    let stop = Arc::new(AtomicBool::new(false));
    let lifecycle = Arc::new(Mutex::new(Lifecycle { busy: false, last_request: Instant::now(), stopping: false, failed: false }));
    #[cfg(windows)]
    let authority = Arc::new(Mutex::new(crate::cache_service::Authority::open(edition).ok()));
    #[cfg(windows)]
    let prepare_authority = authority.clone();
    #[cfg(windows)]
    let cache_admission = Arc::new(crate::cache_replay::Admission::default());
    #[cfg(windows)]
    let prepare_admission = cache_admission.clone();
    #[cfg(windows)]
    let cache_ownership = Arc::new(crate::cache_replay::Ownership::default());
    #[cfg(windows)]
    let prepare_ownership = cache_ownership.clone();
    let work_home = home.to_path_buf();
    let work_target = target.to_path_buf();
    let work_edition = edition.to_owned();
    let work_lifecycle = lifecycle.clone();
    let handler: Arc<ipc::Handler> = Arc::new(move |_: &Path, request: Value| {
        #[cfg(windows)]
        if request["op"] == "cache_prepare" {
            if request.as_object().is_none_or(|object| object.keys().any(|key| !matches!(key.as_str(),
                "protocol" | "op" | "origin" | "organization_anchor" | "authorization_generation" | "policy" | "catalog" | "caller"))) {
                return Err("cache source request refused".into());
            }
            { let mut lifecycle = work_lifecycle.lock().map_err(|_| "update lifecycle unavailable")?;
                if lifecycle.stopping { return Err("update service stopping".into()); }
                lifecycle.last_request = Instant::now(); }
            let deadline = Instant::now() + Duration::from_secs(6);
            let boot = crate::cache_windows::boot(&work_edition, true)?;
            return crate::cache_service::run_replayed(&prepare_authority, &prepare_admission, &prepare_ownership,
                &work_edition, "trusted-agent", false,
                crate::cache_service::Operation::Prepare { request, boot }, deadline);
        }
        if !update_request(&request) { return Ok(json!({"ok":false,"protocol":1,"error":"operation_refused"})); }
        let mut state = work_lifecycle.lock().map_err(|_| "update lifecycle unavailable")?;
        if state.stopping { return Err("update service is stopping".into()); }
        state.last_request = Instant::now();
        if !state.busy {
            state.busy = true;
            let (home, target, edition, lifecycle) = (
                work_home.clone(), work_target.clone(), work_edition.clone(), work_lifecycle.clone());
            if std::thread::Builder::new().name("milvago-update-work".into()).spawn(move || {
                // update::apply owns durable results and actual health verification.
                let result = std::panic::catch_unwind(|| update::installed_version(&target).and_then(|current|
                    update::apply(&home, &target, &edition, &current, true)));
                let failed = !matches!(result, Ok(Ok(outcome)) if !matches!(outcome, update::Applied::Failed | update::Applied::TimedOut));
                if let Ok(mut state) = lifecycle.lock() { state.last_request = Instant::now(); state.busy = false; state.failed = failed; }
            }).is_err() { state.busy = false; return Err("update worker unavailable".into()); }
        }
        Ok(json!({"ok":true,"protocol":1,"scheduled":true}))
    });
    let server_stop = stop.clone();
    let server_home = home.to_path_buf();
    let channel = update::applier_channel(edition);
    #[cfg(windows)]
    let service_access = ipc::Access::UpdateAgent;
    #[cfg(not(windows))]
    let service_access = ipc::Access::Service;
    let server = std::thread::spawn(move || ipc::serve(
        &server_home, &channel, service_access, server_stop, handler));
    #[cfg(windows)]
    let cache_server = {
        let cache_home = home.to_path_buf(); let cache_stop = stop.clone();
        let cache_lifecycle = lifecycle.clone(); let cache_authority = authority.clone();
        let cache_admission = cache_admission.clone();
        let cache_ownership = cache_ownership.clone();
        let cache_channel = crate::cache_service::channel(edition);
        let cache_edition = edition.to_owned();
        let handler: Arc<ipc::Handler> = Arc::new(move |_, request| {
            { let mut lifecycle = cache_lifecycle.lock().map_err(|_| "cache lifecycle unavailable")?;
                if lifecycle.stopping { return Err("cache service stopping".into()); }
                lifecycle.last_request = Instant::now(); }
            let deadline = Instant::now() + Duration::from_secs(6);
            let parsed = crate::browser_broker::parse(&request)?;
            let principal = parsed.principal.clone();
            let boot = crate::cache_windows::boot(&cache_edition, true)?;
            crate::cache_service::run_replayed(&cache_authority, &cache_admission, &cache_ownership, &cache_edition,
                &principal, false, crate::cache_service::Operation::Browser { parsed, boot, deadline }, deadline)
        });
        std::thread::spawn(move || ipc::serve(&cache_home, &cache_channel, ipc::Access::CacheBrowser, cache_stop, handler))
    };
    #[cfg(windows)]
    let mut last_maintenance: Option<Instant> = None;
    #[cfg(windows)]
    let mut maintenance_worker: Option<std::thread::JoinHandle<()>> = None;
    #[cfg(windows)]
    let launched = own_command(edition);
    #[cfg(windows)]
    let mut last_command_check = Instant::now();
    #[cfg(windows)]
    let mut replaced = false;
    loop {
        #[cfg(windows)]
        if last_maintenance.is_none_or(|last| last.elapsed() >= Duration::from_millis(100)) {
            if maintenance_worker.as_ref().is_some_and(|worker| worker.is_finished()) {
                if let Some(worker) = maintenance_worker.take() { let _ = worker.join(); }
            }
            if maintenance_worker.is_none() {
                let authority = authority.clone();
                let admission = cache_admission.clone();
                let ownership = cache_ownership.clone();
                let edition = edition.to_owned();
                maintenance_worker = std::thread::Builder::new().name("milvago-cache-work".into()).spawn(move || {
                    let deadline = Instant::now() + Duration::from_secs(6);
                    if let Ok(boot) = crate::cache_windows::boot(&edition, true) {
                        let _ = crate::cache_service::run_replayed(&authority, &admission, &ownership, &edition,
                            "maintenance", true, crate::cache_service::Operation::Maintenance { boot, owner:None }, deadline);
                    }
                }).ok();
            }
            last_maintenance = Some(Instant::now());
        }
        let mut state = lifecycle.lock().map_err(|_| "update lifecycle unavailable")?;
        // Serialize idle shutdown with admission of acknowledged work.
        #[cfg(windows)]
        let (grace_active, cache_pending) = authority.try_lock().map_or((true, true), |a|
            a.as_ref().map_or((false, false), |a| (a.active(), a.maintenance_pending())));
        #[cfg(not(windows))]
        let grace_active = false;
        #[cfg(not(windows))]
        let cache_pending = false;
        #[cfg(windows)]
        let idle = {
            let _ = (grace_active, cache_pending);
            if launched.is_some() && last_command_check.elapsed() >= Duration::from_secs(60) {
                last_command_check = Instant::now();
                replaced = own_command(edition).is_some_and(|now| Some(now) != launched);
            }
            server.is_finished() || replaced
        };
        #[cfg(not(windows))]
        let idle = !grace_active && !cache_pending
            && (server.is_finished() || state.last_request.elapsed() >= Duration::from_secs(60));
        if !state.busy && (requested_stop.load(Ordering::Acquire) || idle) {
            state.stopping = true; break;
        }
        drop(state);
        std::thread::sleep(Duration::from_millis(100));
    }
    stop.store(true, Ordering::Release);
    let result = server.join().map_err(|_| "update IPC worker failed")?;
    #[cfg(windows)]
    if let Some(worker) = maintenance_worker.take() { let _ = worker.join(); }
    #[cfg(windows)]
    cache_server.join().map_err(|_| "cache IPC worker failed")??;
    result?;
    #[cfg(windows)]
    if replaced && !requested_stop.load(Ordering::Acquire) { return Err("update service binary replaced; restarting".into()); }
    // A requested stop ends cleanly even after a failed attempt: an error exit would
    // have SCM recovery restart a service being stopped or removed.
    if lifecycle.lock().map_err(|_| "update lifecycle unavailable")?.failed && !requested_stop.load(Ordering::Acquire) { return Err("update work failed".into()); }
    Ok(())
}
/// The binPath SCM would start this service with now, as SYSTEM reads it.
#[cfg(windows)]
fn own_command(edition: &str) -> Option<std::path::PathBuf> {
    use windows_service::{service::ServiceAccess, service_manager::{ServiceManager, ServiceManagerAccess}};
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).ok()?;
    let config = manager.open_service(update::applier_service(edition), ServiceAccess::QUERY_CONFIG).ok()?.query_config().ok()?;
    // The whole binPath as SCM stores it: executable and arguments.
    Some(config.executable_path)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn installation_requires_explicit_bounded_versioned_request() {
        assert!(update_request(&json!({"protocol":1,"op":"update_apply"})));
        for request in [json!({}), json!({"protocol":2,"op":"update_apply"}),
            json!({"protocol":1,"op":"cache_grant"}),
            json!({"protocol":1,"op":"update_apply","path":"C:/unexpected/package.msi"}),
            json!({"protocol":1,"op":"update_apply","url":"https://example.test"}),
            json!({"protocol":1,"op":"update_apply","command":"install"})] {
            assert!(!update_request(&request));
        }
    }
}
