//! Operator-facing log file.
//!
//! The agents run as services: they have no console, and until now a failure left no
//! trace anywhere an administrator could read. This writes a plain text file,
//! `logs\agent.log`, beside the state directory rather than inside it — the state is
//! encrypted and belongs to the agent, the log belongs to whoever has to diagnose it.
//! Verbosity, size and retention come from `config\milvago.toml`, re-read within a
//! few seconds so a change takes effect without restarting the service.
//!
//! **What never goes in here.** No prompt or response text, no file names, no tokens,
//! credentials or deployment keys, no policy content. The file is diagnostic: what the
//! agent did, when, and whether it worked. It inherits the log directory's access
//! control, so it is readable by administrators and by the service account, and by
//! nobody else — but that is a second line of defence, not a licence to write secrets.
//!
//! **A log that cannot be written says so.** Every create, write and rotation failure
//! used to be discarded, so a full disk or a revoked permission silenced the agent
//! without a word. They now go to the Windows event log instead — see
//! [`crate::eventlog`].

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// How much the agent writes. `Off` disables the file entirely.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub enum Level {
    Off,
    Error,
    Warn,
    #[default]
    Info,
    Debug,
}

impl Level {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" | "none" | "silent" => Some(Level::Off),
            "error" => Some(Level::Error),
            "warn" | "warning" => Some(Level::Warn),
            "info" => Some(Level::Info),
            "debug" | "verbose" | "trace" => Some(Level::Debug),
            _ => None,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Level::Off => "OFF",
            Level::Error => "ERROR",
            Level::Warn => "WARN",
            Level::Info => "INFO",
            Level::Debug => "DEBUG",
        }
    }
}

/// The current log file, and the archives it rotates into.
const FILE: &str = "agent.log";
/// Where releases before this one wrote, inside the state directory.
const FORMER_FILE: &str = "milvago.txt";

struct Sink {
    state: PathBuf,
    /// Where lines actually go: the log directory, or the state directory when that
    /// could not be created — diagnostics must not vanish mid-upgrade.
    directory: PathBuf,
    reported_problem: Option<&'static str>,
}

static SINK: Mutex<Option<Sink>> = Mutex::new(None);
#[cfg(test)]
pub(crate) static TEST_LOCK: Mutex<()> = Mutex::new(());

/// The operator log directory. See [`crate::config::beside`] for where it sits.
pub fn directory(state: &Path) -> PathBuf {
    crate::config::beside(state, "logs")
}

/// One line in the file releases before this one wrote, so an administrator still
/// watching it is told where the log went. Written once: the old file is never
/// appended to again, so the notice stays last.
fn forward(state: &Path, directory: &Path) {
    const NOTICE: &str = "the agent log has moved to the logs directory beside this one";
    let former = state.join(FORMER_FILE);
    if state == directory || !former.exists() {
        return;
    }
    // Only the tail matters, and the old file can be megabytes.
    if let Ok(mut file) = std::fs::File::open(&former) {
        use std::io::{Read, Seek, SeekFrom};
        let mut tail = String::new();
        let length = file.metadata().map(|meta| meta.len()).unwrap_or(0);
        let from = length.saturating_sub(512);
        if file.seek(SeekFrom::Start(from)).is_ok()
            && file.read_to_string(&mut tail).is_ok()
            && tail.contains(NOTICE)
        {
            return;
        }
    }
    if let Ok(mut file) = std::fs::OpenOptions::new().append(true).open(&former) {
        let _ = writeln!(file, "{} INFO  {}", chrono::Utc::now().to_rfc3339(), NOTICE);
    }
}

/// Where this agent's lines go, creating the directory if the installer has not yet.
fn destination(state: &Path) -> PathBuf {
    let directory = directory(state);
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    // Created before any installer ACL exists: owner only, whatever the umask.
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    match builder.create(&directory) {
        Ok(()) => {
            forward(state, &directory);
            directory
        }
        Err(error) => {
            crate::eventlog::report(&format!(
                "the agent log directory is unavailable, writing beside the state instead: {error}"
            ));
            state.to_path_buf()
        }
    }
}

/// Point the log at an agent's state directory. Called once, when a service starts.
pub fn open(state: &Path) {
    crate::config::open(state);
    let directory = destination(state);
    if let Ok(mut sink) = SINK.lock() {
        *sink = Some(Sink {
            state: state.to_path_buf(),
            directory,
            reported_problem: None,
        });
    }
}

fn archive(path: &Path, index: u32) -> PathBuf {
    path.with_file_name(format!("agent.{index}.log"))
}

/// Keep the current file under `max_bytes` by shifting it into `agent.1.log`, and
/// keep at most `retained` archives, so the log cannot grow without bound on a
/// machine that has been running for months.
fn rotate(path: &Path, max_bytes: u64, retained: u32) {
    if !std::fs::metadata(path).is_ok_and(|meta| meta.len() >= max_bytes) {
        return;
    }
    let failed = |error: std::io::Error| {
        crate::eventlog::report(&format!("the agent log could not be rotated: {error}"));
    };
    if retained == 0 {
        if let Err(error) = std::fs::remove_file(path) {
            failed(error);
        }
        return;
    }
    // Dropping what already fell out of the window is not itself a failure.
    let _ = std::fs::remove_file(archive(path, retained));
    for index in (1..retained).rev() {
        let from = archive(path, index);
        if from.exists() {
            if let Err(error) = std::fs::rename(&from, archive(path, index + 1)) {
                failed(error);
            }
        }
    }
    if let Err(error) = std::fs::rename(path, archive(path, 1)) {
        failed(error);
    }
}

/// A control character in a message would let one line masquerade as several.
fn line(level: Level, message: &str) -> String {
    let sanitized: String = message
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(2000)
        .collect();
    let mut line = String::new();
    let _ = writeln!(
        line,
        "{} {:<5} {}",
        chrono::Utc::now().to_rfc3339(),
        level.label(),
        sanitized
    );
    line
}

/// Write one line. Anything at or below the configured level is kept.
pub fn write(level: Level, message: &str) {
    // Two phases, and the split is deliberate. config::for_state takes a SECOND mutex
    // and, once per TTL, reads and parses the configuration file from disk; running
    // that under the process-wide logging mutex made every single line pay for it and
    // serialized every thread behind it. Learn the path, drop the lock, read the
    // configuration outside.
    let state = {
        let Ok(guard) = SINK.lock() else { return };
        let Some(sink) = guard.as_ref() else { return };
        sink.state.clone()
    };
    let config = crate::config::for_state(&state);
    if config.level == Level::Off {
        return;
    }
    // Phase two. The once-only problem report and the write itself stay under the lock:
    // that is what keeps the file in timestamp order and stops two writers interleaving
    // a line. Moving the I/O out as well would buy little and cost both guarantees, so
    // it is deliberately not done here.
    let Ok(mut guard) = SINK.lock() else { return };
    let Some(sink) = guard.as_mut() else { return };
    let mut pending = String::new();
    // A configuration the agent could not use is itself worth one line, once.
    if config.problem != sink.reported_problem {
        sink.reported_problem = config.problem;
        if let Some(problem) = config.problem {
            pending.push_str(&line(
                Level::Error,
                &format!("the configuration file was not applied: {problem}"),
            ));
        }
    }
    if level <= config.level {
        pending.push_str(&line(level, message));
    }
    if pending.is_empty() {
        return;
    }
    let path = sink.directory.join(FILE);
    rotate(&path, config.max_file_bytes, config.retained_files);
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    // Never world-readable, whatever umask the agent was started with.
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o640);
    match options.open(&path) {
        Ok(mut file) => {
            if let Err(error) = file.write_all(pending.as_bytes()) {
                crate::eventlog::report(&format!("the agent log could not be written: {error}"));
            }
        }
        Err(error) => {
            crate::eventlog::report(&format!("the agent log could not be opened: {error}"));
        }
    }
}

pub fn error(message: &str) {
    write(Level::Error, message);
}
pub fn warn(message: &str) {
    write(Level::Warn, message);
}
pub fn info(message: &str) {
    write(Level::Info, message);
}
pub fn debug(message: &str) {
    write(Level::Debug, message);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A state directory under a temporary root, so the sibling `config` and `logs`
    /// directories are unique per test rather than shared through the system
    /// temporary directory.
    pub(crate) fn home(root: &Path) -> PathBuf {
        let state = root.join("state");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::create_dir_all(root.join("config")).unwrap();
        state
    }
    fn with_level(state: &Path, value: &str) {
        std::fs::write(
            crate::config::directory(state).join("milvago.toml"),
            format!("[logging]\nlevel = \"{value}\"\nmax_file_mb = 10\nretained_files = 5\n"),
        )
        .unwrap();
        crate::config::invalidate();
    }
    fn contents(state: &Path) -> String {
        std::fs::read_to_string(directory(state).join(FILE)).unwrap_or_default()
    }

    /// The sink is process-wide, so the cases share one test rather than racing.
    #[test]
    fn verbosity_is_read_from_the_configuration_and_bounds_what_is_written() {
        let _serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir().unwrap();
        let state = home(root.path());
        with_level(&state, "warn");
        open(&state);
        error("a failure");
        warn("a warning");
        info("routine");
        debug("detail");
        let written = contents(&state);
        assert!(written.contains("a failure") && written.contains("a warning"));
        assert!(!written.contains("routine") && !written.contains("detail"));

        // A level change is picked up without restarting, once the cache expires.
        with_level(&state, "debug");
        debug("now visible");
        assert!(contents(&state).contains("now visible"));

        // Off means off.
        with_level(&state, "off");
        error("must not appear");
        assert!(!contents(&state).contains("must not appear"));
    }

    #[test]
    fn a_missing_configuration_is_never_created_by_the_agent() {
        let _serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir().unwrap();
        let state = home(root.path());
        crate::config::invalidate();
        open(&state);
        info("routine");
        // The service account may only read the configuration directory: a default
        // written here would fail on a real installation and mask the boundary.
        assert!(
            !crate::config::directory(&state).join("milvago.toml").exists()
        );
        assert!(contents(&state).contains("routine"), "the default level is info");
    }

    #[test]
    fn a_control_character_cannot_forge_a_second_line() {
        let _serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir().unwrap();
        let state = home(root.path());
        with_level(&state, "info");
        open(&state);
        info("first\n2026-01-01T00:00:00Z INFO  forged");
        let written = contents(&state);
        assert_eq!(written.lines().count(), 1, "{written}");
    }

    #[test]
    fn a_configuration_that_could_not_be_applied_is_reported_once() {
        let _serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir().unwrap();
        let state = home(root.path());
        std::fs::write(
            crate::config::directory(&state).join("milvago.toml"),
            "[logging]\nlevel = \"info\"\nmax_file_mb = 10\nretained_files = 5\nunknown = 1\n",
        )
        .unwrap();
        crate::config::invalidate();
        open(&state);
        info("first");
        info("second");
        let written = contents(&state);
        assert_eq!(
            written.matches("the configuration file was not applied").count(),
            1,
            "{written}"
        );
        assert!(written.contains("first") && written.contains("second"));
    }

    #[test]
    fn rotation_honours_the_configured_size_and_keeps_the_requested_archives() {
        let root = tempfile::tempdir().unwrap();
        let logs = root.path().join("logs");
        std::fs::create_dir_all(&logs).unwrap();
        let path = logs.join(FILE);
        for generation in 1..=4u32 {
            std::fs::write(&path, format!("generation {generation}")).unwrap();
            rotate(&path, 1, 2);
            assert!(!path.exists(), "the current file must have been shifted away");
        }
        // Two archives kept: the two most recent generations, newest first.
        assert_eq!(
            std::fs::read_to_string(archive(&path, 1)).unwrap(),
            "generation 4"
        );
        assert_eq!(
            std::fs::read_to_string(archive(&path, 2)).unwrap(),
            "generation 3"
        );
        assert!(!archive(&path, 3).exists(), "the window must be bounded");

        // Below the threshold nothing moves.
        std::fs::write(&path, "small").unwrap();
        rotate(&path, 4096, 2);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "small");

        // No archives requested: the file is simply dropped.
        rotate(&path, 1, 0);
        assert!(!path.exists());
    }

    #[test]
    fn an_unusable_log_directory_falls_back_to_the_state_directory() {
        let root = tempfile::tempdir().unwrap();
        let state = home(root.path());
        // A file where the directory should be: creation cannot succeed.
        std::fs::write(root.path().join("logs"), b"occupied").unwrap();
        assert_eq!(destination(&state), state);
    }

    #[test]
    fn the_former_log_file_is_told_once_where_the_log_went() {
        let root = tempfile::tempdir().unwrap();
        let state = home(root.path());
        std::fs::write(state.join(FORMER_FILE), b"2026-01-01T00:00:00Z INFO  old line\n").unwrap();
        let logs = directory(&state);
        std::fs::create_dir_all(&logs).unwrap();
        forward(&state, &logs);
        forward(&state, &logs);
        let former = std::fs::read_to_string(state.join(FORMER_FILE)).unwrap();
        assert_eq!(former.matches("has moved").count(), 1, "{former}");
    }
}
