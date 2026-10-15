//! `milvago-installer`: the MSI's custom actions.
//!
//! ```text
//! milvago-installer health community
//! milvago-installer configure install <edition> <package> <fresh> <ca-file> <proxy> <system-store> <self-update>
//! milvago-installer configure remove <edition>
//! milvago-installer transaction <prepare|restore|commit> <edition> <product-code> <chromium-id> <firefox-id>
//! ```
//!
//! Stored in the MSI Binary table, so Windows Installer extracts and runs it as SYSTEM
//! even when the product's own files are already removed (rollback, uninstall). Its
//! arguments are build-time constants and the MSI's own properties; nothing a caller
//! types becomes code. A failure writes its fixed phrase and the installer's own detail
//! (a path, a Win32 code; never a child process's output) to the Application log (event
//! 1001, as the PowerShell actions did), and the full detail to standard error.
#[cfg(windows)]
mod browser;
#[cfg(windows)]
mod configure;
#[cfg(windows)]
mod health;
// ponytail: some helpers only get callers with the configuration port (B5).
#[cfg(windows)]
#[allow(dead_code)]
mod paths;
#[cfg(windows)]
mod reg;
#[cfg(windows)]
#[allow(dead_code)]
mod services;
#[cfg(windows)]
mod tasks;
#[cfg(windows)]
mod transaction;
#[cfg(windows)]
mod win;

#[cfg(windows)]
enum Request<'a> {
    Health,
    Install(configure::Install<'a>),
    Remove,
    Transaction(transaction::Operation, &'a str, &'a str, &'a str),
}

#[cfg(windows)]
fn usage() -> ! {
    eprintln!("usage: milvago-installer health <edition> | configure install <edition> <package> <fresh> <ca-file> <proxy> <system-store> <self-update> | configure remove <edition> | transaction <prepare|restore|commit> <edition> <product> <chromium-id> <firefox-id>");
    std::process::exit(2);
}

#[cfg(windows)]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let (label, edition, request): (&str, &str, Request) = match args.as_slice() {
        ["health", edition] => ("health", *edition, Request::Health),
        ["configure", "install", edition, package, fresh, ca, proxy, store, update] => ("install", *edition, Request::Install(configure::Install {
            package, fresh: *fresh == "1", ca_file: ca, proxy, system_store: store, self_update: update,
        })),
        ["configure", "remove", edition] => ("remove", *edition, Request::Remove),
        ["transaction", step @ ("prepare" | "restore" | "commit"), edition, product, chromium, firefox] => {
            let operation = match *step {
                "prepare" => transaction::Operation::Prepare,
                "restore" => transaction::Operation::Restore,
                _ => transaction::Operation::Commit,
            };
            (*step, *edition, Request::Transaction(operation, *product, *chromium, *firefox))
        }
        _ => usage(),
    };
    if !matches!(edition, "community" | "commercial") {
        usage();
    }
    // Built per edition: an Enterprise action cannot run from the Community package.
    if edition == "commercial" {
        eprintln!("this installer was built for the other edition");
        std::process::exit(2);
    }
    let outcome = match request {
        Request::Transaction(operation, product, chromium, firefox) => transaction::run_operation(operation, edition, product, chromium, firefox),
        other => configure::refuse_community_over_enterprise(edition).and_then(|()| match other {
            Request::Health => health::run(edition),
            Request::Install(options) => configure::layout(edition).and_then(|l| configure::install(&l, &options)),
            Request::Remove => configure::layout(edition).and_then(|l| configure::remove(&l)),
            Request::Transaction(..) => unreachable!(),
        }),
    };
    match outcome {
        Ok(message) => println!("{message}"),
        Err(failure) => {
            // Windows Installer keeps no custom-action output, so the event is the only
            // diagnostic an administrator gets. Our own details are paths and Win32 codes;
            // a child process's output stays out (the Application log is world-readable).
            win::register_event_source();
            win::event(1001, true, &format!("Installer action failed: {label}/{edition}; step={}; detail={}. No process output or provisioning recorded.", failure.step, public_detail(failure.step, &failure.detail)));
            eprintln!("{}: {}", failure.step, failure.detail);
            std::process::exit(1);
        }
    }
}

/// What of a failure's detail reaches the world-readable Application log: `win::run`
/// reports a child's refusal as `exit <code>: <stderr> <stdout>`, of which only the code
/// is kept.
#[cfg(windows)]
fn public_detail<'a>(step: &str, detail: &'a str) -> &'a str {
    // The agent's health command prints only local readiness causes (which link, which
    // service state), never provisioning: kept, so a failed health check is diagnosable.
    if step == "Local operational health" {
        return detail;
    }
    if detail.starts_with("exit ") { detail.split(':').next().unwrap_or_default() } else { detail }
}

#[cfg(all(windows, test))]
mod tests {
    #[test]
    fn a_child_process_output_never_reaches_the_event_log() {
        assert_eq!(super::public_detail("Installer configuration", "exit Some(1): bootstrap_token rejected {\"server\":\"x\"}"), "exit Some(1)");
        assert_eq!(super::public_detail("Installer configuration", "exit None: "), "exit None");
        // The installer's own details stay: they are what makes a failure diagnosable.
        let own = r"C:\ProgramData\Milvago\Browser (Win32 error 3)";
        assert_eq!(super::public_detail("Private directory could not be created", own), own);
        assert_eq!(super::public_detail("Installer configuration", ""), "");
        // The health check's cause names the failing link: kept.
        let health = "exit Some(1): agent: local broker unavailable";
        assert_eq!(super::public_detail("Local operational health", health), health);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("milvago-installer runs only inside the Windows MSI");
    std::process::exit(2);
}
