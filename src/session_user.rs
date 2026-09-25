//! Interactive OS user of the machine, as seen by the service (session 0).
//! Best effort and informational only: an empty string means "not
//! determined". The value never carries authority; the server bounds it too.

/// User name of the active interactive session, sanitized (no control
/// characters, trimmed, at most 128 bytes), or an empty string.
pub fn current() -> String {
    sanitize(&raw_user().unwrap_or_default())
}

/// Mirror of the server rule so a report is never refused for its shape. Shared with
/// the IPC layer, which stamps the account behind each browser connection the same way.
pub(crate) fn sanitize(value: &str) -> String {
    let cleaned: String = value.chars().filter(|c| !c.is_control()).collect();
    let trimmed = cleaned.trim();
    let mut end = trimmed.len().min(128);
    while !trimmed.is_char_boundary(end) {
        end -= 1;
    }
    trimmed[..end].to_string()
}

// Windows Terminal Services: the first session in the active state, then its
// user name. Works from a service account (default WinStation DACL grants
// NETWORK SERVICE query rights); any failure yields None rather than a guess.
#[cfg(windows)]
fn raw_user() -> Option<String> {
    use windows_sys::Win32::System::RemoteDesktop::{
        WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW, WTSActive, WTSEnumerateSessionsW,
        WTSFreeMemory, WTSQuerySessionInformationW, WTSUserName,
    };
    let mut sessions: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
    let mut count: u32 = 0;
    let listed = unsafe {
        WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut sessions, &mut count)
    };
    if listed == 0 || sessions.is_null() {
        return None;
    }
    let active = unsafe { std::slice::from_raw_parts(sessions, count as usize) }
        .iter()
        .find(|session| session.State == WTSActive)
        .map(|session| session.SessionId);
    unsafe { WTSFreeMemory(sessions as *mut _) };
    let id = active?;
    let mut buffer: windows_sys::core::PWSTR = std::ptr::null_mut();
    let mut bytes: u32 = 0;
    let queried = unsafe {
        WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, id, WTSUserName, &mut buffer, &mut bytes)
    };
    if queried == 0 || buffer.is_null() {
        return None;
    }
    let wide = unsafe { std::slice::from_raw_parts(buffer, bytes as usize / 2) };
    let end = wide.iter().position(|&unit| unit == 0).unwrap_or(wide.len());
    let name = String::from_utf16_lossy(&wide[..end]);
    unsafe { WTSFreeMemory(buffer as *mut _) };
    Some(name)
}

// systemd-logind: the active session of the physical seat, then its user.
// Headless hosts (no seat0 session) or a missing loginctl yield None.
#[cfg(not(windows))]
fn raw_user() -> Option<String> {
    let session = loginctl(&["show-seat", "seat0", "-p", "ActiveSession", "--value"])?;
    if session.is_empty()
        || !session
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    loginctl(&["show-session", &session, "-p", "Name", "--value"])
}

#[cfg(not(windows))]
fn loginctl(args: &[&str]) -> Option<String> {
    // Absolute: the root daemon never resolves a tool through PATH.
    let output = std::process::Command::new("/usr/bin/loginctl").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::{current, sanitize};

    #[test]
    fn sanitize_strips_controls_trims_and_bounds_length() {
        assert_eq!(sanitize("  user\u{1b}[31m\tname\r\n "), "user[31mname");
        assert_eq!(sanitize(" \t\n"), "");
        let long = "é".repeat(100); // 200 bytes
        let bounded = sanitize(&long);
        assert!(bounded.len() <= 128);
        assert_eq!(bounded.chars().count(), 64);
        assert!(bounded.chars().all(|c| c == 'é'));
    }

    #[test]
    fn current_never_panics_and_is_bounded() {
        let value = current();
        assert!(value.len() <= 128);
        assert!(!value.chars().any(char::is_control));
        assert_eq!(value, value.trim());
    }
}
