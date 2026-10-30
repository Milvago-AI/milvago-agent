//! Administrator-provisioned local Docker-compatible API channels.
use milvago_discovery_collector::{self as collector, docker::LocalEngine};
use milvago_discovery_engine::{CoverageStatus, Snapshot};
use serde::Deserialize;
use std::{collections::BTreeSet, io::Read, path::Path};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    version: u32,
    device_id: String,
    channels: Vec<String>,
}

fn configuration(
    bytes: &[u8],
    device: &str,
    windows: bool,
) -> Result<Vec<LocalEngine>, &'static str> {
    if bytes.len() > 16_384 {
        return Err("configuration_limit");
    }
    let config: Configuration =
        serde_json::from_slice(bytes).map_err(|_| "invalid_configuration")?;
    if config.version != 1
        || device.is_empty()
        || config.device_id != device
        || config.channels.len() > 32
    {
        return Err("invalid_configuration");
    }
    let mut seen = BTreeSet::new();
    let mut engines = vec![];
    for path in config.channels {
        let normalized = if windows {
            let leaf = path.strip_prefix(r"\\.\pipe\").ok_or("invalid_channel")?;
            if leaf.is_empty()
                || leaf.len() > 200
                || leaf.starts_with('.')
                || !leaf
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                || leaf.contains("..")
            {
                return Err("invalid_channel");
            }
            path.to_ascii_lowercase()
        } else {
            if !path.starts_with('/')
                || path.len() > 103
                || path.ends_with('/')
                || path.chars().any(char::is_control)
                || path
                    .split('/')
                    .skip(1)
                    .any(|part| part.is_empty() || matches!(part, "." | ".."))
            {
                return Err("invalid_channel");
            }
            path
        };
        if !seen.insert(normalized.clone()) {
            return Err("duplicate_channel");
        }
        engines.push(LocalEngine {
            scope: collector::identity("runtime-scope", &[&normalized]),
            socket: normalized.into(),
        });
    }
    Ok(engines)
}

pub(crate) fn extend(
    snapshot: &mut Snapshot,
    home: &Path,
    device: &str,
    engines: &mut Vec<LocalEngine>,
) {
    let path = home.join("config/discovery-runtime-channels.json");
    let result = (|| {
        if !path.try_exists().map_err(|_| "access_denied")? {
            return Ok(None);
        }
        // Reuse the guest configuration's protected ancestor/file checks. No
        // catalogue, browser or IPC payload can select a local channel path.
        let file = crate::discovery_guests::protected_file(&path, 16_384)?;
        let mut bytes = vec![];
        file.take(16_385)
            .read_to_end(&mut bytes)
            .map_err(|_| "access_denied")?;
        configuration(&bytes, device, cfg!(windows)).map(Some)
    })();
    let status = match result {
        Ok(None) => CoverageStatus::Disabled,
        Ok(Some(configured)) => {
            for candidate in configured {
                let exists = engines.iter().any(|engine| {
                    if cfg!(windows) {
                        engine
                            .socket
                            .to_str()
                            .zip(candidate.socket.to_str())
                            .is_some_and(|(left, right)| left.eq_ignore_ascii_case(right))
                    } else {
                        engine.socket == candidate.socket
                    }
                });
                if !exists {
                    engines.push(candidate);
                }
            }
            CoverageStatus::Available
        }
        Err(_) => CoverageStatus::Denied,
    };
    // Configuration access says nothing about daemon access or completeness.
    collector::coverage(snapshot, "runtime-channels", status, false);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(channels: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(
            &serde_json::json!({"version":1,"device_id":"fixture-device","channels":channels}),
        )
        .unwrap()
    }

    #[test]
    fn local_channels_reject_remote_paths_and_untrusted_values() {
        for windows in [false, true] {
            for channels in [
                serde_json::json!(["tcp://127.0.0.1:2375"]),
                serde_json::json!(["https://example.invalid"]),
                serde_json::json!(["data:image/png;base64,AAAA"]),
                serde_json::json!([42]),
                serde_json::json!([""]),
                serde_json::json!(["/run/../secret.sock"]),
                serde_json::json!([r"\\remote\pipe\podman"]),
                serde_json::json!([r"\\.\pipe\podman\nested"]),
                serde_json::json!([r"\\.\pipe\..\other"]),
                serde_json::json!(["/run/api\n.sock"]),
                serde_json::json!(["/run//api.sock"]),
            ] {
                assert!(configuration(&bytes(channels), "fixture-device", windows).is_err());
            }
        }
        for (windows, channel) in [
            (false, "/run/custom/podman.sock"),
            (true, r"\\.\pipe\Podman-custom"),
        ] {
            let raw = bytes(serde_json::json!([channel]));
            let configured = configuration(&raw, "fixture-device", windows).unwrap();
            assert_eq!(configured.len(), 1);
            assert!(!configured[0].scope.contains("custom"));
            assert!(configuration(&raw, "other-device", windows).is_err());
            assert!(
                configuration(
                    &bytes(serde_json::json!([channel, channel])),
                    "fixture-device",
                    windows
                )
                .is_err()
            );
            assert!(
                configuration(
                    &bytes(serde_json::json!(vec![channel; 33])),
                    "fixture-device",
                    windows
                )
                .is_err()
            );
        }
        assert!(
            configuration(
                &bytes(serde_json::json!([
                    r"\\.\pipe\Podman-custom",
                    r"\\.\pipe\podman-CUSTOM"
                ])),
                "fixture-device",
                true
            )
            .is_err()
        );
        for raw in [
            vec![b' '; 16_385],
            b"{}".to_vec(),
            br#"{"version":1,"device_id":"fixture-device","channels":[],"command":"anything"}"#
                .to_vec(),
        ] {
            assert!(configuration(&raw, "fixture-device", false).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn configured_custom_socket_identifies_execution_without_exporting_local_path() {
        use std::{
            io::Write,
            os::unix::{fs::PermissionsExt, net::UnixListener},
            sync::atomic::AtomicBool,
            time::{Duration, Instant},
        };
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir(home.path().join("config")).unwrap();
        let socket = home.path().join("private-custom.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            for index in 0..3 {
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error)
                            if error.kind() == std::io::ErrorKind::WouldBlock
                                && Instant::now() < deadline =>
                        {
                            std::thread::sleep(Duration::from_millis(2))
                        }
                        Err(error) => panic!("fixture accept: {error}"),
                    }
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let mut header = vec![];
                while !header.ends_with(b"\r\n\r\n") {
                    assert!(header.len() < 8192);
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    header.push(byte[0]);
                }
                let line = std::str::from_utf8(&header)
                    .unwrap()
                    .lines()
                    .next()
                    .unwrap();
                let body = match index {
                    0 => { assert!(line.starts_with("GET /info ")); serde_json::json!({"ID":"fixture-engine"}) },
                    1 => { assert!(line.starts_with("GET /containers/json?all=1 ")); serde_json::json!([{"Id":"0123456789abcdef","Names":["/fixture"],"Image":"alpine:fixture","State":"running","Ports":[]}]) },
                    _ => { assert!(line.starts_with("GET /containers/0123456789abcdef/top?ps_args=")); serde_json::json!({"Titles":["PID","STARTED","COMMAND"],"Processes":[["1","fixture-start","/usr/bin/openclaw PRIVATE_FIXTURE"]]}) },
                }.to_string();
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        });
        let path = home.path().join("config/discovery-runtime-channels.json");
        std::fs::write(&path, bytes(serde_json::json!([socket.to_str().unwrap()]))).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut snapshot = collector::empty("endpoint", 1, 100);
        let mut engines = vec![];
        extend(&mut snapshot, home.path(), "fixture-device", &mut engines);
        let stop = AtomicBool::new(false);
        assert!(
            collector::docker::collect(
                &mut snapshot,
                &engines,
                &collector::Budget::new(Duration::from_secs(3), &stop)
            )
            .is_empty()
        );
        server.join().unwrap();
        let catalog =
            serde_json::from_slice(include_bytes!("../discovery-engine/catalog/factory.json"))
                .unwrap();
        let result = milvago_discovery_engine::Engine::compile(&catalog)
            .unwrap()
            .evaluate(&snapshot)
            .unwrap();
        assert!(
            result
                .identifications
                .iter()
                .any(|item| item.application_id == "openclaw"
                    && item.state == milvago_discovery_engine::State::Executed)
        );
        let report = serde_json::to_string(&snapshot).unwrap();
        assert!(!report.contains("private-custom.sock"));
        assert!(!report.contains("PRIVATE_FIXTURE"));
        assert!(!report.contains(home.path().to_str().unwrap()));
    }

    #[cfg(unix)]
    #[test]
    fn runtime_channel_configuration_requires_protected_files_and_bound_device() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir(home.path().join("config")).unwrap();
        let path = home.path().join("config/discovery-runtime-channels.json");
        let mut engines = vec![];
        let mut snapshot = collector::empty("endpoint", 1, 100);
        extend(&mut snapshot, home.path(), "fixture-device", &mut engines);
        assert_eq!(
            snapshot.coverage.last().unwrap().status,
            CoverageStatus::Disabled
        );
        std::fs::write(&path, bytes(serde_json::json!(["/run/custom/podman.sock"]))).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        extend(&mut snapshot, home.path(), "fixture-device", &mut engines);
        assert_eq!(engines.len(), 1);
        #[cfg(target_os = "linux")]
        let own_descriptors = || {
            // Other tests open and close unrelated sockets concurrently. Only
            // descriptors belonging to this fixture can establish its leak.
            std::fs::read_dir("/proc/self/fd")
                .unwrap()
                .filter_map(Result::ok)
                .filter_map(|entry| std::fs::read_link(entry.path()).ok())
                .filter(|target| target.starts_with(home.path()))
                .count()
        };
        #[cfg(target_os = "linux")]
        let descriptors = own_descriptors();
        for _ in 0..64 {
            extend(&mut snapshot, home.path(), "fixture-device", &mut engines);
            assert_eq!(
                engines.len(),
                1,
                "same path must not add duplicate requests"
            );
        }
        #[cfg(target_os = "linux")]
        assert_eq!(own_descriptors(), descriptors);
        std::fs::write(
            &path,
            bytes(serde_json::json!(["/run/new.sock", "tcp://127.0.0.1:2375"])),
        )
        .unwrap();
        extend(&mut snapshot, home.path(), "fixture-device", &mut engines);
        assert_eq!(
            engines.len(),
            1,
            "invalid configuration must not partially add channels"
        );
        assert_eq!(
            snapshot.coverage.last().unwrap().status,
            CoverageStatus::Denied
        );
        std::fs::write(&path, bytes(serde_json::json!(["/run/custom/podman.sock"]))).unwrap();
        engines.clear();
        extend(&mut snapshot, home.path(), "wrong-device", &mut engines);
        assert!(engines.is_empty());
        assert_eq!(
            snapshot.coverage.last().unwrap().status,
            CoverageStatus::Denied
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        extend(&mut snapshot, home.path(), "fixture-device", &mut engines);
        assert!(engines.is_empty());
        std::fs::remove_file(&path).unwrap();
        let target = home.path().join("private.json");
        std::fs::write(
            &target,
            bytes(serde_json::json!(["/run/custom/podman.sock"])),
        )
        .unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, &path).unwrap();
        extend(&mut snapshot, home.path(), "fixture-device", &mut engines);
        assert!(engines.is_empty());
        assert_eq!(
            snapshot.coverage.last().unwrap().status,
            CoverageStatus::Denied
        );
        assert!(
            !serde_json::to_string(&snapshot)
                .unwrap()
                .contains("podman.sock")
        );
    }
}
