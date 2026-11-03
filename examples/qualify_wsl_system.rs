//! Owned offline fixture entry point, not an installer or an agent release.
#[cfg(windows)]
fn main() {
    use std::ffi::OsString;
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let result = if args == [OsString::from("discovery-wsl-probe")] {
        milvago_browser_agent::discovery_wsl::probe()
    } else if args == [OsString::from("discovery-observer-probe")] {
        match milvago_browser_agent::discovery_wsl::qualify_handoff_probe() {
            Ok(true) => Ok(()),
            Ok(false) => milvago_browser_agent::discovery_wsl::observer_probe(
                "import json,os,sys\nb=sys.stdin.buffer.read(24577)\nassert b==b'q'*24576\nprint(json.dumps({'uid':os.getuid(),'bytes':len(b)}))\n",
            ),
            Err(error) => Err(error),
        }
    } else if args.len() == 2 && args[0] == OsString::from("--service") {
        scm::start(&args[1], None)
    } else if args.len() == 2 && args[0] == OsString::from("--service-desktop") {
        // Only the owned fixture command line can select this qualification.
        unsafe { std::env::set_var("MILVAGO_QA_DESKTOP", "1"); }
        scm::start(&args[1], None)
    } else if args.len() == 2 && args[0] == OsString::from("--service-desktop-vmware") {
        unsafe { std::env::set_var("MILVAGO_QA_DESKTOP", "vmware"); }
        scm::start(&args[1], None)
    } else if args.len() == 3 && args[0] == OsString::from("--service-handoff") {
        scm::start(&args[1], Some(&args[2]))
    } else if args.is_empty() {
        milvago_browser_agent::discovery_wsl::qualify_system_transport()
    } else {
        Err("unexpected fixture argument".into())
    };
    if let Err(error) = result {
        eprintln!("WSL_SYSTEM_FIXTURE_ERROR={error}");
        let code = if args == [OsString::from("discovery-wsl-probe")] {
            match error.to_string().as_str() {
                "unavailable" => 41,
                "query_failed" => 42,
                "desktop_profile_unavailable" => 43,
                "access_denied" => 44,
                "timeout" => 45,
                "cancelled" => 46,
                "query_stdout" => 47,
                "response_limit" => 48,
                "invalid_inventory" | "invalid_inventory_owner" | "invalid_vm_identity" | "vm_limit" => 49,
                "invalid_owner" => 50,
                _ => 1,
            }
        } else { 1 };
        std::process::exit(code);
    }
}

#[cfg(windows)]
#[path = "support/wsl_fixture_service.rs"]
mod scm;

#[cfg(windows)]
fn qualify_transport() -> milvago_browser_agent::Result<()> {
    if matches!(std::env::var("MILVAGO_QA_DESKTOP").as_deref(), Ok("1" | "vmware")) {
        return milvago_browser_agent::discovery_wsl::qualify_desktop_inventory();
    }
    milvago_browser_agent::discovery_wsl::qualify_system_transport()
}

#[cfg(not(windows))]
fn main() {
    eprintln!("This opt-in fixture requires the owned offline Windows VM.");
    std::process::exit(2);
}
