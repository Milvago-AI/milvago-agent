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
    } else if args.len() == 3 && args[0] == OsString::from("--service-handoff") {
        scm::start(&args[1], Some(&args[2]))
    } else if args.is_empty() {
        milvago_browser_agent::discovery_wsl::qualify_system_transport()
    } else {
        Err("unexpected fixture argument".into())
    };
    if let Err(error) = result {
        eprintln!("WSL_SYSTEM_FIXTURE_ERROR={error}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
#[path = "support/wsl_fixture_service.rs"]
mod scm;

#[cfg(windows)]
fn qualify_transport() -> milvago_browser_agent::Result<()> {
    milvago_browser_agent::discovery_wsl::qualify_system_transport()
}

#[cfg(not(windows))]
fn main() {
    eprintln!("This opt-in fixture requires the owned offline Windows VM.");
    std::process::exit(2);
}
