//! Reporting for the persistent watch loop.
//!
//! The loop runs unattended for hours, so it must not repeat itself once per
//! minute: it reports only transitions — the first failed pass, a **change of
//! cause** while the state stays the same, the moment the cached authorization
//! lapses, and the return to normal — and states a cause the person reading it can
//! act on.

use crate::{Result, Store, shadow};
use std::path::Path;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Health {
    #[default]
    Synchronized,
    /// A pass failed while a valid cached authorization remains.
    Deferred,
    /// A pass failed and no valid authorization remains: the AI surface is sealed.
    Blocked,
}

/// What the loop last reported. The cause is carried alongside the health because a
/// machine that stays blocked for a different reason is new information: reporting
/// only the health change hid, for instance, a refused connection turning into a
/// rejected certificate or an expired authorization.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Status {
    pub health: Health,
    pub cause: Option<&'static str>,
}

/// Why a connection never produced an answer, read from the lower-cased error chain.
///
/// Neither reqwest nor hyper exposes a typed transport reason, and rustls' own error
/// is buried several sources down, so the chain is matched textually. That is a
/// heuristic: it names what it recognises and falls back to the general case, and it
/// is separate from [`cause`] so the recognition itself can be tested without asking
/// the operating system to produce each failure on demand.
fn transport(chain: &str) -> &'static str {
    if chain.contains("certificate") || chain.contains("unknownissuer") {
        return "the Milvago server certificate was not accepted; check the private certificate authority in the agent configuration";
    }
    if chain.contains("dns")
        || chain.contains("failed to lookup")
        || chain.contains("name or service not known")
    {
        return "the Milvago server name could not be resolved";
    }
    if chain.contains("refused") {
        return "the connection to the Milvago server was refused";
    }
    if chain.contains("timed out") || chain.contains("timeout") {
        return "the Milvago server did not answer in time";
    }
    "the Milvago server is unreachable; check the network connection"
}

/// A coarse explanation of a failed pass, with the remedy when there is one.
/// Transport detail, URLs and credentials never reach the console.
pub fn cause(error: &(dyn std::error::Error + Send + Sync + 'static)) -> &'static str {
    const UNAUTHORIZED: &str =
        "this device is no longer authorized; ask your administrator to approve it";
    if let Some(http) = error.downcast_ref::<reqwest::Error>() {
        if http.is_timeout() {
            return "the Milvago server did not answer in time";
        }
        if let Some(status) = http.status().map(|status| status.as_u16()) {
            return match status {
                401 | 403 => UNAUTHORIZED,
                _ => "the Milvago server reported an error; it may be updating",
            };
        }
        let mut chain = String::new();
        let mut step: Option<&(dyn std::error::Error + 'static)> = Some(http);
        while let Some(current) = step {
            chain.push_str(&current.to_string().to_ascii_lowercase());
            chain.push(' ');
            step = current.source();
        }
        return transport(&chain);
    }
    let text = error.to_string();
    if text.contains("authorization refused") {
        UNAUTHORIZED
    } else if text.contains("tls.ca_file") || text.contains("tls.allow_private_ca") {
        "the configured HTTPS trust could not be applied; check the agent configuration"
    } else if text.contains("state is full") || text.contains("queue") {
        "the local delivery queue is saturated; events wait until delivery resumes"
    } else if text.contains("policy") {
        "the signed policy was rejected; ask your administrator to check the server"
    } else {
        "the agent could not complete its local checks"
    }
}

/// Record a best-effort step that failed. These steps must not fail the pass — a
/// deferred heartbeat or an absent collector is expected, and turning them into pass
/// failures would seal the AI surface for a cosmetic reason — but discarding their
/// error left no trace at all when something real went wrong.
pub fn deferred<T>(step: &str, outcome: Result<T>) {
    if let Err(error) = outcome {
        crate::log::debug(&format!("{step} deferred: {}", cause(&*error)));
    }
}

/// Fold one pass outcome into the reported status, writing a line only when the
/// health or the cause changes. Returns the new status, to be carried into the next
/// pass.
pub fn observe(home: &Path, previous: Status, outcome: Result<()>) -> Status {
    let error = match outcome {
        Ok(()) => {
            if previous.health != Health::Synchronized {
                eprintln!("Milvago synchronization restored.");
                crate::log::info("synchronization restored");
            }
            crate::log::debug("synchronization pass succeeded");
            return Status::default();
        }
        Err(error) => error,
    };
    let cached = Store::open(home)
        .and_then(|store| store.load())
        .ok()
        .is_some_and(|state| shadow::cached(&state).is_ok());
    let health = if cached { Health::Deferred } else { Health::Blocked };
    let reason = cause(&*error);
    let current = Status { health, cause: Some(reason) };
    if current == previous {
        return current;
    }
    let detail = if cached {
        "; signed cached policy remains applied, encrypted delivery will retry"
    } else {
        "; no authorized cached policy, AI access stays blocked"
    };
    let message = format!("synchronization failed: {reason}{detail}");
    crate::log::error(&message);
    eprintln!("Milvago {message}");
    current
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boxed(message: &str) -> Box<dyn std::error::Error + Send + Sync> {
        message.into()
    }

    #[test]
    fn cause_maps_local_errors_without_leaking_detail() {
        assert!(cause(&*boxed("installation authorization refused")).contains("administrator"));
        assert!(cause(&*boxed("policy authorization expired or invalid")).contains("policy"));
        assert!(cause(&*boxed("state is full")).contains("queue is saturated"));
        assert!(
            cause(&*boxed("tls.ca_file could not be read")).contains("HTTPS trust"),
            "a misconfigured authority must be distinguishable from a network fault"
        );
        assert_eq!(
            cause(&*boxed("state key missing; refusing data loss")),
            "the agent could not complete its local checks"
        );
    }

    #[test]
    fn transport_separates_the_reasons_a_connection_produced_no_answer() {
        assert!(
            transport("invalid peer certificate: unknownissuer").contains("certificate authority"),
            "an unknown authority must point at the trust configuration"
        );
        assert!(
            transport("dns error: failed to lookup address information")
                .contains("could not be resolved")
        );
        assert_eq!(
            transport("tcp connect error: connection refused (os error 10061)"),
            "the connection to the Milvago server was refused"
        );
        assert_eq!(
            transport("operation timed out"),
            "the Milvago server did not answer in time"
        );
        assert_eq!(
            transport("channel closed"),
            "the Milvago server is unreachable; check the network connection"
        );
    }

    #[test]
    fn a_loopback_port_with_nothing_behind_it_is_never_blamed_on_a_certificate() {
        // Whether the operating system answers with a refusal or lets the attempt
        // time out is its decision, and differs between machines; what must hold is
        // that a transport fault is never reported as a trust problem.
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap();
        for url in [
            format!("http://127.0.0.1:{port}/"),
            format!("https://127.0.0.1:{port}/"),
        ] {
            let error = client
                .get(&url)
                .send()
                .expect_err("nothing is listening on that port");
            let reason = cause(&error);
            assert!(!reason.contains("certificate"), "{url}: {reason}");
            assert!(!reason.contains("authorized"), "{url}: {reason}");
        }
    }

    #[test]
    fn repeated_failures_report_once_and_a_change_of_cause_reports_again() {
        let _serial = crate::log::TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir().unwrap();
        // A state directory under a temporary root, so the sibling log directory is
        // unique to this test rather than shared through the system temporary one.
        let home = root.path().join("state");
        std::fs::create_dir_all(&home).unwrap();
        crate::config::invalidate();
        crate::log::open(&home);
        let written = || {
            std::fs::read_to_string(crate::log::directory(&home).join("agent.log"))
                .unwrap_or_default()
        };

        // No enrollment: nothing is cached, so the surface is sealed.
        let first = observe(&home, Status::default(), Err(boxed("offline")));
        assert_eq!(first.health, Health::Blocked);
        let after_first = written().matches("synchronization failed").count();
        assert_eq!(after_first, 1);

        // The same cause again says nothing new.
        assert_eq!(observe(&home, first, Err(boxed("offline"))), first);
        assert_eq!(written().matches("synchronization failed").count(), 1);

        // A different cause at the same health is new information.
        let second = observe(&home, first, Err(boxed("installation authorization refused")));
        assert_eq!(second.health, Health::Blocked);
        assert_ne!(second.cause, first.cause);
        assert_eq!(written().matches("synchronization failed").count(), 2);

        assert_eq!(observe(&home, second, Ok(())).health, Health::Synchronized);
    }
}
