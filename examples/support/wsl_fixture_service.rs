//! Actual SCM adapter shared by opt-in offline fixtures only.
use std::{ffi::OsString, time::Duration};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};
const NAME: &str = "Milvago WSL offline QA";
define_windows_service!(entry, run);
pub fn start(id: &OsString, owner: Option<&OsString>) -> milvago_browser_agent::Result<()> {
    let text = id.to_str().ok_or("invalid fixture identity")?;
    let parsed = uuid::Uuid::parse_str(text)?;
    if parsed.is_nil() || parsed.to_string() != text {
        return Err("invalid fixture identity".into());
    }
    // This fixture's main has not started any application threads yet.
    unsafe {
        std::env::set_var("MILVAGO_DISCOVERY_WINDOWS_QA_ID", text);
        if let Some(owner) = owner {
            std::env::set_var("MILVAGO_QA_HANDOFF_OWNER", owner);
        } else {
            std::env::remove_var("MILVAGO_QA_HANDOFF_OWNER");
        }
    }
    service_dispatcher::start(NAME, entry)?;
    Ok(())
}
fn bounded_job() -> milvago_browser_agent::Result<()> {
    use windows_sys::Win32::{
        Foundation::CloseHandle,
        System::{JobObjects::*, Threading::GetCurrentProcess},
    };
    let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if job.is_null() {
        return Err("fixture job unavailable".into());
    }
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_JOB_MEMORY
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        // Windows jobs cannot contain processes from different sessions.
        // The fixed cross-session helper is suspended until its own bounded
        // job is assigned, and that job dies when this process exits.
        | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK;
    limits.BasicLimitInformation.ActiveProcessLimit = 16;
    limits.JobMemoryLimit = 256 * 1024 * 1024;
    if unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &limits as *const _ as *const _,
            std::mem::size_of_val(&limits) as u32,
        )
    } == 0
        || unsafe { AssignProcessToJobObject(job, GetCurrentProcess()) } == 0
    {
        unsafe { CloseHandle(job) };
        return Err("fixture job unavailable".into());
    }
    // Retain the unnamed, non-inheritable job until process exit. A wall timeout
    // exits the process, closing this handle and terminating its descendants.
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_secs(120));
        std::process::exit(124);
    });
    Ok(())
}
fn run(_: Vec<OsString>) {
    let Ok(status) = service_control_handler::register(NAME, |event| match event {
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    }) else {
        return;
    };
    let report = |state, code| {
        status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(code),
            checkpoint: 0,
            wait_hint: Duration::from_secs(120),
            process_id: None,
        })
    };
    if report(ServiceState::Running, 0).is_err() {
        return;
    }
    let result = (|| -> milvago_browser_agent::Result<()> {
        bounded_job()?;
        let handoff = std::env::var("MILVAGO_QA_HANDOFF_OWNER").ok();
        if let Some(owner) = handoff.as_ref() {
            milvago_browser_agent::discovery_wsl::qualify_system_handoff(owner)?;
        } else {
            super::qualify_transport()?;
        }
        // Successful qualification has verified the protected installed path,
        // its immutable marker, the SYSTEM token and actual Session 0.
        let output = std::env::current_exe()?.with_extension("scm.json");
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)?;
        file.write_all(&serde_json::to_vec(&serde_json::json!({"service":true,"session":0,"system":true,"observer":handoff.is_none(),"handoff":handoff.is_some()}))?)?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(error) = &result {
        let _ = (|| -> milvago_browser_agent::Result<()> {
            let image = std::env::current_exe()?;
            let parent = image.parent().ok_or("fixture path unavailable")?;
            let directory = milvago_browser_agent::cache_windows::Directory::installed(parent)?;
            let _image =
                directory.hold_file(image.file_name().ok_or("fixture image unavailable")?)?;
            let bytes = serde_json::to_vec(
                &serde_json::json!({"error":error.to_string().chars().take(256).collect::<String>()}),
            )?;
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(image.with_extension("scm-error.json"))?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            Ok(())
        })();
    }
    let _ = report(ServiceState::Stopped, if result.is_ok() { 0 } else { 1 });
}
