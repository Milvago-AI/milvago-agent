//! Last-resort reporting when the operator log itself cannot be written.
//!
//! `log.rs` is where an administrator looks first, which is exactly why its own
//! failures cannot be reported there: a full disk, a missing directory or a revoked
//! permission would silence the agent without leaving a trace. Those failures go to
//! the Windows Application event log instead, under the `Milvago` source the
//! installer already registers.
//!
//! Rate limited on purpose. A disk that stays full fails on every pass, and a service
//! that logs once every five seconds for a week would bury every other event on the
//! machine. One event per cooldown window is enough to notice; the condition is
//! permanent anyway.
//!
//! The same rule as the log file applies here: no prompt or response text, no file
//! names, no tokens, credentials or policy content.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long one reported failure suppresses the next.
const COOLDOWN: Duration = Duration::from_secs(300);
/// Installer actions use 1001-1004; the running agent starts at 2001.
#[cfg(windows)]
const EVENT_ID: u32 = 2001;
/// The event source the installer registers in the Application log.
#[cfg(windows)]
const SOURCE: &str = "Milvago";

static LAST: Mutex<Option<Instant>> = Mutex::new(None);

/// Whether a report is due, updating the window when it is. Split out from `report`
/// so the rate limit can be tested without touching the machine's event log.
fn due(last: &mut Option<Instant>, now: Instant) -> bool {
    if last.is_some_and(|at| now.duration_since(at) < COOLDOWN) {
        return false;
    }
    *last = Some(now);
    true
}

/// Report one diagnostic failure, at most once per cooldown window.
pub fn report(message: &str) {
    let Ok(mut last) = LAST.lock() else { return };
    if !due(&mut last, Instant::now()) {
        return;
    }
    drop(last);
    // A control character would let one event masquerade as several lines.
    let sanitized: String = message
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(800)
        .collect();
    emit(&sanitized);
}

#[cfg(windows)]
fn emit(message: &str) {
    use windows_sys::Win32::System::EventLog::{
        DeregisterEventSource, EVENTLOG_ERROR_TYPE, RegisterEventSourceW, ReportEventW,
    };
    let source: Vec<u16> = SOURCE.encode_utf16().chain(Some(0)).collect();
    // Null server name: the local machine. A source the installer never registered
    // still lands in the Application log, with a generic description.
    let handle = unsafe { RegisterEventSourceW(std::ptr::null(), source.as_ptr()) };
    if handle.is_null() {
        return;
    }
    let text: Vec<u16> = message.encode_utf16().chain(Some(0)).collect();
    let strings = [text.as_ptr()];
    unsafe {
        ReportEventW(
            handle,
            EVENTLOG_ERROR_TYPE,
            0,
            EVENT_ID,
            std::ptr::null_mut(),
            1,
            0,
            strings.as_ptr(),
            std::ptr::null(),
        );
        DeregisterEventSource(handle);
    }
}

#[cfg(not(windows))]
fn emit(message: &str) {
    // No machine-wide event log to fall back on; a service manager captures stderr.
    eprintln!("Milvago diagnostic unavailable: {message}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_failure_is_reported_and_the_next_ones_wait_for_the_window() {
        let mut last = None;
        let start = Instant::now();
        assert!(due(&mut last, start), "the first failure must be reported");
        assert!(!due(&mut last, start + Duration::from_secs(1)));
        assert!(!due(&mut last, start + COOLDOWN - Duration::from_millis(1)));
        assert!(due(&mut last, start + COOLDOWN));
        // The window restarts from the report that was actually emitted.
        assert!(!due(&mut last, start + COOLDOWN + Duration::from_secs(1)));
    }

    #[test]
    fn reporting_never_panics_even_without_a_registered_source() {
        report("synthetic diagnostic failure");
    }
}
