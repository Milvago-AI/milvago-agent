//! Administrator-facing configuration: `config\milvago.toml`.
//!
//! It sits beside the encrypted state, never inside it. The installer gives the
//! directory to Administrators and SYSTEM, and grants the service account read
//! access only - which is the point. The agent can write its own state; it must not
//! be able to choose which certificate authorities it trusts.
//!
//! ```toml
//! [queue]
//! max_events = 10000
//! max_size_mb = 8
//!
//! [logging]
//! level = "info"           # off | error | warn | info | debug
//! max_file_mb = 10
//! retained_files = 5
//!
//! [tls]
//! allow_private_ca = false
//! ca_file = ""             # relative to config\, e.g. "certs/ca.pem"
//! system_store = false     # also trust the operating system's root store
//!
//! [network]
//! proxy = ""               # e.g. "http://proxy.example.internal:3128"
//! ```
//!
//! **`allow_private_ca` never disables verification.** It adds one trust anchor to
//! this agent's own HTTP client; the server name and the certificate validity are
//! still checked, the Windows certificate store is untouched, and the browser's trust
//! is untouched. A declared authority that cannot be read is an error that blocks the
//! call - never a silent fall back to an unverified connection.
//!
//! **`system_store` is opt-in** for the same reason: it widens trust to every authority
//! the machine's administrators installed (a TLS-inspection CA deployed by GPO, for
//! instance), which only an administrator may decide. **`proxy`** names one explicit
//! HTTP(S) proxy; empty means direct connections, never the environment's variables.
//! A declared proxy that is invalid blocks the call rather than going direct.
//!
//! The agent only ever reads this file. It is created by the installer, so a missing
//! or broken file resolves to the documented defaults rather than to a write attempt
//! the service account would not be allowed to make.

use crate::Result;
use serde::Deserialize;
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Maximum supported admission budget; the store keeps independent read headroom.
pub(crate) const MAX_QUEUE_SIZE_MB: usize = 128;

/// Certificate files are a handful of PEM blocks. Anything larger is a mistake or an
/// attempt to make the agent read something it should not.
const MAX_CA_BYTES: u64 = 256 * 1024;
/// How long a parsed file is trusted before it is read again. Same window the log
/// level has always used, so an edit takes effect without restarting the service.
const TTL: Duration = Duration::from_secs(5);

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Document {
    #[serde(default)]
    queue: QueueSection,
    #[serde(default)]
    logging: LoggingSection,
    #[serde(default)]
    tls: TlsSection,
    #[serde(default)]
    network: NetworkSection,
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct NetworkSection {
    proxy: String,
    bind_address: String,
    allowed_peers: Vec<String>,
}
impl Default for NetworkSection {
    fn default() -> Self {
        Self { proxy: String::new(), bind_address: "127.0.0.1".into(), allowed_peers: Vec::new() }
    }
}

/// An IPv4 or IPv6 CIDR range, such as `172.16.0.0/12` or `0.0.0.0/0`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    network: std::net::IpAddr,
    prefix: u8,
}
impl Cidr {
    pub fn parse(text: &str) -> Option<Self> {
        let (address, prefix) = text.trim().split_once('/')?;
        let network: std::net::IpAddr = address.parse().ok()?;
        let prefix: u8 = prefix.parse().ok()?;
        (prefix <= if network.is_ipv4() { 32 } else { 128 }).then_some(Self { network, prefix })
    }
    pub fn contains(&self, ip: std::net::IpAddr) -> bool {
        use std::net::IpAddr::{V4, V6};
        // An IPv4 peer seen through an IPv6 socket is compared as IPv4.
        let ip = match ip { V6(v6) => v6.to_ipv4_mapped().map_or(ip, V4), v4 => v4 };
        match (self.network, ip) {
            (V4(network), V4(ip)) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(self.prefix)).unwrap_or(0);
                u32::from(network) & mask == u32::from(ip) & mask
            }
            (V6(network), V6(ip)) => {
                let mask = u128::MAX.checked_shl(128 - u32::from(self.prefix)).unwrap_or(0);
                u128::from(network) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

/// Where the agent's own listeners accept connections: this machine only, unless an
/// administrator opens them. Loopback is always accepted; any other peer only when a
/// listed range contains it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listen {
    pub address: std::net::Ipv4Addr,
    pub peers: Vec<Cidr>,
}
impl Default for Listen {
    fn default() -> Self {
        Self { address: std::net::Ipv4Addr::LOCALHOST, peers: Vec::new() }
    }
}
impl Listen {
    pub fn admits(&self, peer: std::net::IpAddr) -> bool {
        peer.is_loopback() || (!self.address.is_loopback() && self.peers.iter().any(|range| range.contains(peer)))
    }
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct QueueSection {
    max_events: usize,
    max_size_mb: usize,
}
impl Default for QueueSection {
    fn default() -> Self {
        Self { max_events: crate::QUEUE_LIMIT, max_size_mb: 8 }
    }
}

/// Admission limits only: reducing them never invalidates already durable events.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueueLimits {
    pub max_events: usize,
    pub max_bytes: usize,
}
impl Default for QueueLimits {
    fn default() -> Self {
        Self { max_events: crate::QUEUE_LIMIT, max_bytes: crate::shadow::QUEUE_BYTES_LIMIT }
    }
}
impl QueueLimits {
    pub fn check(&self, state: &crate::State, events: usize, bytes: usize) -> Result<()> {
        if state.queue.len().saturating_add(state.shadow_queue.len()).saturating_add(events) > self.max_events {
            return Err("offline queue full; event not accepted".into());
        }
        if crate::shadow::queue_bytes(state)?.saturating_add(bytes) > self.max_bytes {
            return Err("offline queue byte limit reached".into());
        }
        Ok(())
    }
    pub fn collector_share(self) -> Self {
        Self { max_events: self.max_events / 2, max_bytes: self.max_bytes / 2 }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoggingSection {
    level: String,
    max_file_mb: u64,
    retained_files: u32,
}
impl Default for LoggingSection {
    fn default() -> Self {
        Self { level: "info".into(), max_file_mb: 10, retained_files: 5 }
    }
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct TlsSection {
    #[serde(default)]
    allow_private_ca: bool,
    #[serde(default)]
    ca_file: String,
    #[serde(default)]
    system_store: bool,
}

/// The settings in force, as the agent understands them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub queue: QueueLimits,
    pub level: crate::log::Level,
    pub max_file_bytes: u64,
    pub retained_files: u32,
    /// `None` when no private authority is configured, `Some(Ok(path))` when one is
    /// usable, `Some(Err(reason))` when one is declared but cannot be used.
    pub private_ca: Option<std::result::Result<PathBuf, &'static str>>,
    /// Trust the operating system's root store in addition to the public roots.
    pub system_store: bool,
    /// Same shape as `private_ca`: `None` means direct connections.
    pub proxy: Option<std::result::Result<reqwest::Url, &'static str>>,
    pub listen: Listen,
    /// What is wrong with the file, if anything, for the operator to read. It never
    /// names a path: the log file is diagnostic, not a place to publish layout.
    pub problem: Option<&'static str>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            queue: QueueLimits::default(),
            level: crate::log::Level::Info,
            max_file_bytes: 10 * 1024 * 1024,
            retained_files: 5,
            private_ca: None,
            system_store: false,
            proxy: None,
            listen: Listen::default(),
            problem: None,
        }
    }
}

impl Config {
    fn with(problem: &'static str) -> Self {
        Self { problem: Some(problem), ..Self::default() }
    }
}

/// Where the administrator's directories sit relative to the state directory.
///
/// A Windows service is pointed at `...\Milvago\<edition>\state`, and `config` and
/// `logs` are its siblings, each with its own access control. A packaged Linux
/// install points the agent straight at `/var/lib/milvago-<edition>`, which has no
/// such sibling to speak of, so there they are children of it instead.
pub(crate) fn beside(state: &Path, name: &str) -> PathBuf {
    if state.file_name().is_some_and(|last| last == "state") {
        if let Some(parent) = state.parent() {
            return parent.join(name);
        }
    }
    state.join(name)
}

/// The administrator's configuration directory.
///
/// A packaged Linux install keeps it in `/etc/<name>`, root's: under
/// `/var/lib/<name>` the agent account owns the state and could choose its own
/// certificate authorities or open its listener to the network.
pub fn directory(state: &Path) -> PathBuf {
    #[cfg(unix)]
    if state.parent() == Some(Path::new("/var/lib")) {
        if let Some(name) = state.file_name() {
            return Path::new("/etc").join(name);
        }
    }
    beside(state, "config")
}

/// The file the installer writes on a first installation, with `private_ca` naming
/// the certificate it staged, if any. Generated here rather than by the installer so
/// the documented defaults and the values the agent actually applies cannot drift
/// apart.
pub fn default_document(private_ca: Option<&str>) -> Result<String> {
    let reference = match private_ca {
        None => String::new(),
        Some(value) => {
            if value.is_empty()
                || value.len() > 120
                || value.contains("..")
                || value.starts_with('/')
                || !value
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"._-/".contains(&c))
            {
                return Err("a staged certificate must be named by a plain relative path".into());
            }
            value.to_owned()
        }
    };
    Ok(format!(
        "# Milvago agent configuration. Edited by administrators; the service can only read it.\n\
         # Applies within a few seconds, no restart needed.\n\
         \n\
         [queue]\n\
         # Main offline event queue only, not total agent memory or disk usage.\n\
         # max_events: 1..100000; max_size_mb: 1..128 MiB.\n\
         max_events = 10000\n\
         max_size_mb = 8\n\
         \n\
         [logging]\n\
         # off | error | warn | info | debug. The log is agent.log in the logs directory\n\
         # beside this one. It never contains prompt text, response text, file names,\n\
         # tokens, credentials or policy content.\n\
         level = \"info\"\n\
         # max_file_mb: 1..100 MiB; retained_files: 0..20 archives plus the current file.\n\
         max_file_mb = 10\n\
         retained_files = 5\n\
         \n\
         [tls]\n\
         # HTTPS verification is always on. This only adds one certificate authority to\n\
         # the agent's own HTTP client: the server name and the certificate validity are\n\
         # still checked, and neither the Windows certificate store nor the browser is\n\
         # affected. A declared authority that cannot be read is an error that blocks the\n\
         # call; it never falls back to an unverified connection.\n\
         allow_private_ca = {}\n\
         ca_file = \"{reference}\"\n\
         # Also trust the root store of the operating system (for instance a TLS-inspection\n\
         # authority your organization deploys by policy). Off unless you decide it.\n\
         system_store = false\n\
         \n\
         [network]\n\
         # One explicit HTTP(S) proxy, \"http://host:port\", without credentials. Empty means\n\
         # direct connections; environment proxy variables are never used.\n\
         proxy = \"\"\n\
         # Where the agent's own listeners accept connections: the local extension server\n\
         # and, on Enterprise, the native telemetry receiver. 127.0.0.1 keeps them on this\n\
         # machine, which is all a local browser or tool needs. Keep it.\n\
         # WARNING: 0.0.0.0 exposes them to the network. Only peers inside allowed_peers are\n\
         # then accepted (for example [\"172.16.0.0/12\"] for local containers or WSL), a\n\
         # firewall rule must still be opened, and \"0.0.0.0/0\" accepts any machine that can\n\
         # reach this one. The model filter never follows this setting.\n\
         bind_address = \"127.0.0.1\"\n\
         allowed_peers = []\n",
        private_ca.is_some()
    ))
}

/// An explicit proxy: http or https, a host, no credentials, nothing after the port.
/// Credentials in a configuration file would be readable by the service account.
fn resolve_proxy(value: &str) -> Option<std::result::Result<reqwest::Url, &'static str>> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let Ok(url) = reqwest::Url::parse(value) else {
        return Some(Err("network.proxy is not a valid URL"));
    };
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none_or(str::is_empty)
        || !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Some(Err("network.proxy must be http(s)://host:port, without credentials"));
    }
    Some(Ok(url))
}

/// Resolve `tls.ca_file` and prove it is a plain file inside the configuration
/// directory. A relative path is the whole contract: an absolute path, a parent
/// traversal, a symbolic link or a junction would let whoever can write the value
/// point the agent somewhere it is not meant to read.
fn resolve_ca(directory: &Path, value: &str) -> std::result::Result<PathBuf, &'static str> {
    let value = value.trim();
    if value.is_empty() {
        return Err("tls.allow_private_ca is set but tls.ca_file is empty");
    }
    let relative = Path::new(value);
    if relative.is_absolute()
        || !relative.components().all(|part| matches!(part, Component::Normal(_)))
    {
        return Err("tls.ca_file must be a relative path inside the configuration directory");
    }
    let path = directory.join(relative);
    let meta = std::fs::symlink_metadata(&path).map_err(|_| "tls.ca_file could not be read")?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err("tls.ca_file must be a regular file");
    }
    if meta.len() > MAX_CA_BYTES {
        return Err("tls.ca_file is too large to be a certificate");
    }
    // The components were all plain names, but a junction anywhere above the file
    // would still redirect it. Compare the resolved paths, not the written ones.
    let root = std::fs::canonicalize(directory).map_err(|_| "tls.ca_file could not be read")?;
    let full = std::fs::canonicalize(&path).map_err(|_| "tls.ca_file could not be read")?;
    if !full.starts_with(&root) {
        return Err("tls.ca_file must stay inside the configuration directory");
    }
    Ok(full)
}

/// The verbosity an older installation left in `state\milvago.conf`. Read so an
/// upgrade keeps the level its administrator chose; it never carried a TLS section
/// and must never be treated as one.
fn legacy_level(state: &Path) -> Option<crate::log::Level> {
    // The applier reads this too, in a directory the agent account writes: no link,
    // FIFO or device, and a bounded size.
    let text = String::from_utf8(crate::read_regular(&state.join("milvago.conf"), 64 * 1024).ok()?).ok()?;
    text.lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
        .find_map(|line| {
            let (key, value) = line.split_once('=')?;
            key.trim()
                .eq_ignore_ascii_case("log_level")
                .then(|| crate::log::Level::parse(value))?
        })
}

/// Read and validate the file. Never fails and never writes: a file that cannot be
/// read or understood yields the documented defaults plus the reason, so a damaged
/// configuration can lower verbosity but can never loosen TLS.
pub fn load(state: &Path) -> Config {
    let directory = directory(state);
    let text = match std::fs::read_to_string(directory.join("milvago.toml")) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let level = legacy_level(state).unwrap_or_default();
            return Config { level, ..Config::default() };
        }
        Err(_) => return Config::with("the configuration file could not be read"),
    };
    let Ok(document) = toml::from_str::<Document>(&text) else {
        return Config::with("the configuration file is not valid TOML, or names an unknown setting");
    };
    let Some(level) = crate::log::Level::parse(&document.logging.level) else {
        return Config::with("logging.level must be off, error, warn, info or debug");
    };
    if !(1..=100).contains(&document.logging.max_file_mb) {
        return Config::with("logging.max_file_mb must be between 1 and 100");
    }
    if document.logging.retained_files > 20 {
        return Config::with("logging.retained_files must be 20 or fewer");
    }
    if !(1..=100_000).contains(&document.queue.max_events) {
        return Config::with("queue.max_events must be between 1 and 100000");
    }
    if !(1..=MAX_QUEUE_SIZE_MB).contains(&document.queue.max_size_mb) {
        return Config::with("queue.max_size_mb must be between 1 and 128");
    }
    // Anything unexpected keeps the listeners on this machine: an error never opens them.
    let address = match document.network.bind_address.trim() {
        "127.0.0.1" => std::net::Ipv4Addr::LOCALHOST,
        "0.0.0.0" => std::net::Ipv4Addr::UNSPECIFIED,
        _ => return Config::with("network.bind_address must be 127.0.0.1 or 0.0.0.0"),
    };
    if document.network.allowed_peers.len() > 50 {
        return Config::with("network.allowed_peers accepts at most 50 ranges");
    }
    let Some(peers) = document.network.allowed_peers.iter().map(|range| Cidr::parse(range)).collect::<Option<Vec<_>>>() else {
        return Config::with("network.allowed_peers must be CIDR ranges, such as 172.16.0.0/12");
    };
    Config {
        queue: QueueLimits {
            max_events: document.queue.max_events,
            max_bytes: document.queue.max_size_mb * 1024 * 1024,
        },
        level,
        max_file_bytes: document.logging.max_file_mb * 1024 * 1024,
        retained_files: document.logging.retained_files,
        private_ca: document
            .tls
            .allow_private_ca
            .then(|| resolve_ca(&directory, &document.tls.ca_file)),
        system_store: document.tls.system_store,
        proxy: resolve_proxy(&document.network.proxy),
        listen: Listen { address, peers },
        problem: None,
    }
}

struct Cached {
    state: PathBuf,
    config: Config,
    checked: Instant,
}

static STATE: Mutex<Option<PathBuf>> = Mutex::new(None);
static CACHE: Mutex<Option<Cached>> = Mutex::new(None);

/// Point the configuration at an agent's state directory. Called once when a service
/// starts, and once per command-line invocation that names one, so a one-shot
/// `sync` honours `[tls]` exactly like the running service.
pub fn open(state: &Path) {
    if let Ok(mut guard) = STATE.lock() {
        *guard = Some(state.to_path_buf());
    }
    if let Ok(mut guard) = CACHE.lock() {
        *guard = None;
    }
}

/// The settings for one state directory, re-read at most once per TTL.
pub fn for_state(state: &Path) -> Config {
    let Ok(mut guard) = CACHE.lock() else { return load(state) };
    let fresh = guard
        .as_ref()
        .is_some_and(|cached| cached.state == state && cached.checked.elapsed() < TTL);
    if !fresh {
        *guard = Some(Cached {
            state: state.to_path_buf(),
            config: load(state),
            checked: Instant::now(),
        });
    }
    guard.as_ref().map_or_else(Config::default, |cached| cached.config.clone())
}

/// The settings for the directory `open` registered, or the documented defaults when
/// nothing has been registered - a test, or a command that names no state directory.
pub fn current() -> Config {
    let Some(state) = STATE.lock().ok().and_then(|guard| guard.clone()) else {
        return Config::default();
    };
    for_state(&state)
}

/// Force the next read to hit the file. Tests only; the TTL covers production.
#[cfg(test)]
pub(crate) fn invalidate() {
    if let Ok(mut guard) = CACHE.lock() {
        *guard = None;
    }
}

/// Apply the configured HTTPS trust to the one client every network call goes
/// through. The public roots stay in place; a private authority is added to them.
/// Nothing here ever accepts an invalid certificate or an unmatched host name.
pub fn apply_tls(
    builder: reqwest::blocking::ClientBuilder,
) -> Result<reqwest::blocking::ClientBuilder> {
    let config = current();
    // The feature loads the system roots by default; only the administrator turns them on.
    let builder = builder.tls_built_in_native_certs(config.system_store);
    let builder = match config.proxy {
        None => builder.no_proxy(),
        Some(proxy) => builder.proxy(reqwest::Proxy::all(proxy?)?),
    };
    let Some(configured) = config.private_ca else { return Ok(builder) };
    let path = configured?;
    let pem = std::fs::read(path).map_err(|_| "tls.ca_file could not be read")?;
    let certificates = reqwest::Certificate::from_pem_bundle(&pem)
        .map_err(|_| "tls.ca_file is not a valid PEM certificate")?;
    if certificates.is_empty() {
        return Err("tls.ca_file contains no certificate".into());
    }
    let mut builder = builder;
    for certificate in certificates {
        builder = builder.add_root_certificate(certificate);
    }
    Ok(builder)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::Level;
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, TcpListener};

    /// A state directory under a temporary root, so `parent()` is unique per test.
    fn home(root: &Path) -> PathBuf {
        let state = root.join("state");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::create_dir_all(root.join("config").join("certs")).unwrap();
        state
    }
    fn write_config(state: &Path, body: &str) {
        std::fs::write(directory(state).join("milvago.toml"), body).unwrap();
    }

    #[test]
    fn an_absent_file_yields_the_documented_defaults_and_writes_nothing() {
        let root = tempfile::tempdir().unwrap();
        let state = home(root.path());
        let configuration = load(&state);
        assert_eq!(configuration, Config::default());
        assert_eq!(configuration.level, Level::Info);
        assert_eq!(configuration.max_file_bytes, 10 * 1024 * 1024);
        assert!(configuration.private_ca.is_none());
        assert!(!directory(&state).join("milvago.toml").exists());
    }

    #[test]
    fn the_documented_schema_is_read_in_full() {
        let root = tempfile::tempdir().unwrap();
        let state = home(root.path());
        write_config(
            &state,
            "[logging]\nlevel = \"debug\"\nmax_file_mb = 3\nretained_files = 2\n\n[tls]\nallow_private_ca = false\nca_file = \"\"\n",
        );
        let configuration = load(&state);
        assert_eq!(configuration.level, Level::Debug);
        assert_eq!(configuration.max_file_bytes, 3 * 1024 * 1024);
        assert_eq!(configuration.retained_files, 2);
        assert!(configuration.private_ca.is_none());
        assert!(configuration.problem.is_none());
    }

    #[test]
    fn an_unknown_setting_or_an_impossible_value_is_refused_without_loosening_anything() {
        let root = tempfile::tempdir().unwrap();
        let state = home(root.path());
        for body in [
            "[logging]\nlevel = \"info\"\nmax_file_mb = 10\nretained_files = 5\nverbose = true\n",
            "[logging]\nlevel = \"chatty\"\nmax_file_mb = 10\nretained_files = 5\n",
            "[logging]\nlevel = \"info\"\nmax_file_mb = 0\nretained_files = 5\n",
            "[logging]\nlevel = \"info\"\nmax_file_mb = 4096\nretained_files = 5\n",
            "[logging]\nlevel = \"info\"\nmax_file_mb = 10\nretained_files = 99\n",
            "[tls]\nallow_private_ca = true\nca_file = \"certs/ca.pem\"\nwhatever = 1\n",
            "this is not TOML at all",
        ] {
            write_config(&state, body);
            let configuration = load(&state);
            assert!(configuration.problem.is_some(), "{body}");
            assert!(configuration.private_ca.is_none(), "{body}");
            assert_eq!(configuration.level, Level::Info, "{body}");
        }
    }

    #[test]
    fn listeners_stay_local_unless_opened_and_then_admit_only_listed_peers() {
        let root = tempfile::tempdir().unwrap();
        let state = home(root.path());
        let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        // The generated file and a missing section both mean this machine only.
        write_config(&state, &default_document(None).unwrap());
        let local = load(&state).listen;
        assert_eq!(local, Listen::default());
        assert!(local.admits(ip("127.0.0.1")) && local.admits(ip("::1")) && !local.admits(ip("203.0.113.5")));
        // Peers listed while still bound locally change nothing.
        write_config(&state, "[network]\nallowed_peers = [\"0.0.0.0/0\"]\n");
        assert!(!load(&state).listen.admits(ip("203.0.113.5")));
        // Opened without peers: nobody but this machine.
        write_config(&state, "[network]\nbind_address = \"0.0.0.0\"\n");
        let open = load(&state).listen;
        assert_eq!(open.address, std::net::Ipv4Addr::UNSPECIFIED);
        assert!(open.admits(ip("127.0.0.1")) && !open.admits(ip("198.51.100.2")));
        write_config(&state, "[network]\nbind_address = \"0.0.0.0\"\nallowed_peers = [\"198.51.100.0/24\", \"2001:db8:1::/48\"]\n");
        let ranged = load(&state).listen;
        assert!(ranged.admits(ip("198.51.100.2")) && ranged.admits(ip("::ffff:198.51.100.255")) && ranged.admits(ip("2001:db8:1::5")));
        assert!(!ranged.admits(ip("198.51.101.1")) && !ranged.admits(ip("192.0.2.1")) && !ranged.admits(ip("2001:db8:2::1")));
        write_config(&state, "[network]\nbind_address = \"0.0.0.0\"\nallowed_peers = [\"0.0.0.0/0\"]\n");
        assert!(load(&state).listen.admits(ip("203.0.113.9")) && !load(&state).listen.admits(ip("2001:db8::1")));
        // Anything else keeps them local, with the reason.
        for body in ["[network]\nbind_address = \"203.0.113.5\"\n", "[network]\nbind_address = \"0.0.0.0\"\nallowed_peers = [\"198.51.100.0/33\"]\n",
            "[network]\nbind_address = \"0.0.0.0\"\nallowed_peers = [\"everyone\"]\n", "[network]\nbind_address = \"::\"\n"] {
            write_config(&state, body);
            let configuration = load(&state);
            assert!(configuration.problem.is_some(), "{body}");
            assert_eq!(configuration.listen, Listen::default(), "{body}");
        }
    }

    #[test]
    fn a_proxy_and_the_system_store_are_explicit_and_validated() {
        let _serial = crate::log::TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir().unwrap();
        let state = home(root.path());
        // The generated file parses to the defaults: direct, public roots only.
        write_config(&state, &default_document(None).unwrap());
        let configuration = load(&state);
        assert!(configuration.problem.is_none());
        assert!(configuration.proxy.is_none() && !configuration.system_store);
        write_config(&state, "[tls]\nsystem_store = true\n[network]\nproxy = \"http://proxy.synthetic.test:3128\"\n");
        let configuration = load(&state);
        assert!(configuration.system_store);
        assert_eq!(configuration.proxy.unwrap().unwrap().as_str(), "http://proxy.synthetic.test:3128/");
        for value in ["http://user:secret@proxy.synthetic.test:3128", "socks5://proxy.synthetic.test:1080",
            "file:///etc/passwd", "http://proxy.synthetic.test:3128/path", "http://proxy.synthetic.test:3128?x=1", "not a url"] {
            write_config(&state, &format!("[network]\nproxy = \"{value}\"\n"));
            assert!(matches!(load(&state).proxy, Some(Err(_))), "{value} must be refused");
            open(&state);
            assert!(apply_tls(reqwest::blocking::Client::builder()).is_err(), "{value} must block, never go direct");
        }
    }

    #[test]
    fn an_older_installations_verbosity_survives_but_never_becomes_a_trust_setting() {
        let root = tempfile::tempdir().unwrap();
        let state = home(root.path());
        std::fs::write(
            state.join("milvago.conf"),
            "# older installation\nlog_level = debug\n",
        )
        .unwrap();
        let configuration = load(&state);
        assert_eq!(configuration.level, Level::Debug);
        assert!(configuration.private_ca.is_none());
        assert!(configuration.problem.is_none());
    }

    #[test]
    fn a_declared_authority_outside_the_configuration_directory_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let state = home(root.path());
        let outside = root.path().join("elsewhere.pem");
        std::fs::write(&outside, b"-----BEGIN CERTIFICATE-----\n").unwrap();
        std::fs::write(
            directory(&state).join("certs").join("ca.pem"),
            b"-----BEGIN CERTIFICATE-----\n",
        )
        .unwrap();
        for value in [
            outside.to_string_lossy().replace('\\', "/"),
            "../state/milvago.conf".into(),
            "certs/../../state/milvago.conf".into(),
            "certs/absent.pem".into(),
            "certs".into(),
        ] {
            write_config(
                &state,
                &format!("[tls]\nallow_private_ca = true\nca_file = \"{value}\"\n"),
            );
            assert!(
                matches!(load(&state).private_ca, Some(Err(_))),
                "{value} must be refused"
            );
        }
        // An authority that is declared but not named is refused too.
        write_config(&state, "[tls]\nallow_private_ca = true\nca_file = \"\"\n");
        assert!(matches!(load(&state).private_ca, Some(Err(_))));
        // The same file is accepted once it is named relative to the directory.
        write_config(
            &state,
            "[tls]\nallow_private_ca = true\nca_file = \"certs/ca.pem\"\n",
        );
        assert!(matches!(load(&state).private_ca, Some(Ok(_))));
    }

    #[test]
    fn an_oversized_certificate_file_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let state = home(root.path());
        std::fs::write(
            directory(&state).join("certs").join("ca.pem"),
            vec![b'x'; (MAX_CA_BYTES + 1) as usize],
        )
        .unwrap();
        write_config(
            &state,
            "[tls]\nallow_private_ca = true\nca_file = \"certs/ca.pem\"\n",
        );
        assert!(matches!(load(&state).private_ca, Some(Err(_))));
    }

    #[test]
    fn a_certificate_is_only_trusted_when_the_administrator_asked_for_it() {
        let root = tempfile::tempdir().unwrap();
        let state = home(root.path());
        std::fs::write(
            directory(&state).join("certs").join("ca.pem"),
            b"-----BEGIN CERTIFICATE-----\n",
        )
        .unwrap();
        write_config(
            &state,
            "[tls]\nallow_private_ca = false\nca_file = \"certs/ca.pem\"\n",
        );
        assert!(load(&state).private_ca.is_none(), "the file must be ignored");
    }

    /// The installer writes exactly what `default_document` produces, so what the
    /// operator finds on disk and what the agent applies are proved to be the same
    /// thing rather than two texts kept in step by hand.
    #[test]
    fn the_file_the_installer_writes_is_read_back_as_the_documented_defaults() {
        let root = tempfile::tempdir().unwrap();
        let state = home(root.path());
        write_config(&state, &default_document(None).unwrap());
        assert_eq!(load(&state), Config::default());

        // With a certificate staged, the same generated file trusts exactly that one.
        let certificate = directory(&state).join("certs").join("ca.pem");
        std::fs::write(&certificate, b"-----BEGIN CERTIFICATE-----\n").unwrap();
        write_config(&state, &default_document(Some("certs/ca.pem")).unwrap());
        assert_eq!(
            load(&state).private_ca,
            Some(Ok(certificate.canonicalize().unwrap()))
        );

        // A reference that is not a plain relative name never reaches the file.
        for value in ["", "../ca.pem", "certs/../../x.pem", "/etc/ca.pem", "C:\\ca.pem", "certs/ca pem", "certs/ca\".pem"] {
            assert!(default_document(Some(value)).is_err(), "{value}");
        }
    }

    /// Verification can never be switched off, so nothing in this module may reach
    /// for the escape hatches reqwest offers.
    #[test]
    fn the_trust_code_never_accepts_an_invalid_certificate() {
        let source = include_str!("config.rs");
        // Split so this very assertion is not what the search finds.
        assert!(!source.contains(concat!("danger_accept", "_invalid_certs")));
        assert!(!source.contains(concat!("danger_accept", "_invalid_hostnames")));
    }

    // ---- proofs against a real TLS server -------------------------------------

    /// `rcgen` is built without its PEM feature here, and the agent only ever reads
    /// PEM, so the test wraps the DER itself.
    fn pem(der: &[u8]) -> String {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let body = STANDARD.encode(der);
        let mut text = String::from("-----BEGIN CERTIFICATE-----\n");
        for chunk in body.as_bytes().chunks(64) {
            text.push_str(std::str::from_utf8(chunk).unwrap());
            text.push('\n');
        }
        text.push_str("-----END CERTIFICATE-----\n");
        text
    }

    struct Authority {
        ca_pem: String,
        chain: Vec<rustls::pki_types::CertificateDer<'static>>,
        key: rustls::pki_types::PrivatePkcs8KeyDer<'static>,
    }

    /// A throwaway private authority signing one leaf, so the four cases below are
    /// proved against a server that really performs a TLS handshake.
    fn authority(names: Vec<String>, valid: bool) -> Authority {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
        use time::{Duration, OffsetDateTime};
        let now = OffsetDateTime::now_utc();
        let mut root = CertificateParams::default();
        root.distinguished_name.push(DnType::CommonName, "Milvago test authority");
        root.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        root.not_before = now - Duration::days(1);
        root.not_after = now + Duration::days(30);
        let root_key = KeyPair::generate().unwrap();
        let root_certificate = root.self_signed(&root_key).unwrap();
        let ca_pem = pem(root_certificate.der());
        let issuer = Issuer::new(root, root_key);
        let mut leaf = CertificateParams::new(names).unwrap();
        leaf.distinguished_name.push(DnType::CommonName, "Milvago test server");
        if valid {
            leaf.not_before = now - Duration::days(1);
            leaf.not_after = now + Duration::days(30);
        } else {
            leaf.not_before = now - Duration::days(30);
            leaf.not_after = now - Duration::days(1);
        }
        let leaf_key = KeyPair::generate().unwrap();
        let certificate = leaf.signed_by(&leaf_key, &issuer).unwrap();
        Authority {
            ca_pem,
            chain: vec![
                certificate.der().clone(),
                root_certificate.der().clone(),
            ],
            key: rustls::pki_types::PrivatePkcs8KeyDer::from(leaf_key.serialize_der()),
        }
    }

    /// Serve exactly one HTTPS request and return the port it listened on.
    fn serve(authority: &Authority) -> u16 {
        let config = std::sync::Arc::new(
            rustls::ServerConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(authority.chain.clone(), authority.key.clone_key().into())
            .unwrap(),
        );
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let Ok((socket, _)) = listener.accept() else { return };
            let Ok(connection) = rustls::ServerConnection::new(config) else { return };
            let mut channel = rustls::StreamOwned::new(connection, socket);
            let mut buffer = [0u8; 1024];
            // A failed handshake is one of the expected outcomes here.
            if channel.read(&mut buffer).is_err() {
                return;
            }
            let _ = channel.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
            let _ = channel.flush();
        });
        port
    }

    fn get(port: u16) -> Result<u16> {
        let client = apply_tls(
            reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(5))
                .redirect(reqwest::redirect::Policy::none()),
        )?
        .build()?;
        Ok(client.get(format!("https://127.0.0.1:{port}/")).send()?.status().as_u16())
    }

    fn trust(state: &Path, authority: &Authority) {
        std::fs::write(
            directory(state).join("certs").join("ca.pem"),
            authority.ca_pem.as_bytes(),
        )
        .unwrap();
        write_config(
            state,
            "[tls]\nallow_private_ca = true\nca_file = \"certs/ca.pem\"\n",
        );
    }

    #[test]
    fn a_private_authority_is_trusted_only_when_configured_and_only_when_it_matches() {
        let _serial = crate::log::TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir().unwrap();
        let state = home(root.path());
        open(&state);

        // 1. No configuration: the private authority is unknown, the call fails.
        let good = authority(vec!["127.0.0.1".into()], true);
        let port = serve(&good);
        invalidate();
        assert!(get(port).is_err(), "an unknown authority must not be trusted");

        // 2. The same authority, declared: the call succeeds.
        trust(&state, &good);
        let port = serve(&good);
        invalidate();
        assert_eq!(get(port).unwrap(), 200);

        // 3. Trusted authority, wrong name: still refused.
        let mismatched = authority(vec!["milvago.invalid".into()], true);
        std::fs::write(
            directory(&state).join("certs").join("ca.pem"),
            mismatched.ca_pem.as_bytes(),
        )
        .unwrap();
        let port = serve(&mismatched);
        invalidate();
        assert!(get(port).is_err(), "the server name must still be verified");

        // 4. Trusted authority, expired certificate: still refused.
        let expired = authority(vec!["127.0.0.1".into()], false);
        std::fs::write(
            directory(&state).join("certs").join("ca.pem"),
            expired.ca_pem.as_bytes(),
        )
        .unwrap();
        let port = serve(&expired);
        invalidate();
        assert!(get(port).is_err(), "an expired certificate must still be refused");

        // 5. A file that is not a certificate is refused, not ignored.
        std::fs::write(
            directory(&state).join("certs").join("ca.pem"),
            b"not a certificate at all\n",
        )
        .unwrap();
        invalidate();
        assert!(apply_tls(reqwest::blocking::Client::builder()).is_err());

        // 6. A declared authority that cannot be read blocks the call outright,
        //    rather than quietly falling back to an unverified connection.
        std::fs::remove_file(directory(&state).join("certs").join("ca.pem")).unwrap();
        invalidate();
        assert!(get(port).is_err());
        assert!(apply_tls(reqwest::blocking::Client::builder()).is_err());

        open(root.path());
    }
}
