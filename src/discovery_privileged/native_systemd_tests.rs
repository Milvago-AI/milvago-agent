//! Opt-in qualification on an owned offline VM acting as a Linux endpoint.
use super::*;
use std::{
    io::{BufRead, BufReader},
    os::unix::fs::PermissionsExt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

fn guard() -> String {
    let expected = std::env::var("MILVAGO_SYSTEMD_QA_ID").expect("owned VM identifier required");
    assert!(uuid::Uuid::parse_str(&expected).is_ok());
    assert_eq!(fs::read_to_string("/opt/qa/id").unwrap(), expected);
    assert_eq!(
        fs::read_to_string("/proc/1/comm").unwrap().trim(),
        "systemd"
    );
    assert_eq!(
        fs::read_to_string("/etc/hostname").unwrap().trim(),
        "systemd-fixture"
    );
    expected
}

fn unit_start() -> bool {
    Command::new("/usr/bin/systemctl")
        .args(["start", "milvago-discovery-enroll.service"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .status()
        .unwrap()
        .success()
}

fn bounded_line(reader: &mut impl BufRead, line: &mut String) {
    line.clear();
    let bytes = std::io::Read::by_ref(reader)
        .take(8193)
        .read_line(line)
        .unwrap();
    assert!(bytes > 0 && bytes <= 8192 && line.ends_with("\r\n"));
}

#[test]
#[ignore = "Requires an owned offline systemd VM and real bridge artifacts"]
fn native_systemd_bootstrap() {
    let identifier = guard();
    let role = std::env::var("MILVAGO_DISCOVERY_BOOTSTRAP_ROLE").unwrap();
    if role == "verify" {
        assert_eq!(unsafe { libc::geteuid() }, 1000);
        assert_eq!(unsafe { libc::getegid() }, 1000);
        let home = Path::new(std::env::var_os("HOME").as_deref().unwrap()).to_owned();
        assert!(matches!(
            home.to_str(),
            Some("/var/lib/milvago-browser" | "/var/lib/milvago-commercial")
        ));
        let expected: u64 = std::env::var("MILVAGO_DISCOVERY_EXPECTED_SEQUENCE")
            .unwrap()
            .parse()
            .unwrap();
        assert!(matches!(expected, 0 | 17));
        let store = Store::open(&home).unwrap();
        let mut state = store.load().unwrap();
        assert!(state.device_id == "11111111-1111-4111-8111-111111111111");
        assert!(state.credential == URL_SAFE_NO_PAD.encode([92; 32]));
        assert!(state.server_url == std::env::var("MILVAGO_DISCOVERY_BOOTSTRAP_ORIGIN").unwrap());
        assert_eq!(state.discovery.sequence, expected);
        state.discovery.sequence = 17;
        store.save(&state).unwrap();
        let info = fs::metadata(home.join("state.bin")).unwrap();
        assert!(info.len() <= 16 * 1024 * 1024);
        let encrypted = fs::read(home.join("state.bin")).unwrap();
        assert!(
            !encrypted
                .windows(state.credential.len())
                .any(|bytes| bytes == state.credential.as_bytes())
        );
        assert_eq!(info.uid(), 1000);
        assert_eq!(info.mode() & 0o077, 0);
        assert!(Directory::open(Path::new("/etc/milvago-discovery")).is_err());
        return;
    }
    assert_eq!(role, "controller");
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let edition = std::env::var("MILVAGO_DISCOVERY_BOOTSTRAP_EDITION").unwrap();
    assert!(matches!(edition.as_str(), "community" | "commercial"));
    let installation = Installation {
        version: 1,
        edition: edition.clone(),
        agent_uid: 1000,
        agent_gid: 1000,
        enroll: true,
        portable: false,
    };
    let (binary, bridge_home) = installation.bridge();
    let config = Directory::open(Path::new("/etc/milvago-discovery")).unwrap();
    assert!(
        config
            .read_optional("anchor.json", 16384)
            .unwrap()
            .is_none()
    );
    assert!(!Path::new("/var/lib/milvago-discovery/registration").exists());
    assert!(!bridge_home.join("state.bin").exists());
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let key = STANDARD.encode(
        ed25519_dalek::SigningKey::from_bytes(&[44; 32])
            .verifying_key()
            .as_bytes(),
    );
    let provision = crate::bootstrap::InstallerProvision {
        server_url: origin.clone(),
        policy_public_key: key.clone(),
        update_public_key: key.clone(),
        bootstrap_token: URL_SAFE_NO_PAD.encode([94; 32]),
        profile_id: uuid::Uuid::parse_str(&identifier).unwrap(),
        edition,
        platform: "linux".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
    };
    let use_installer =
        std::env::var("MILVAGO_DISCOVERY_BOOTSTRAP_INSTALLER").as_deref() == Ok("1");
    let provision_path = format!("/opt/qa/provision-{}.json", installation.edition);
    if use_installer {
        Directory::open(Path::new("/opt/qa"))
            .unwrap()
            .write(
                &format!("provision-{}.json", installation.edition),
                &serde_json::to_vec(&provision).unwrap(),
            )
            .unwrap();
        assert!(
            config
                .read_optional("installation.json", 4096)
                .unwrap()
                .is_none()
        );
    } else {
        config
            .write(
                "installation.json",
                &serde_json::to_vec(&installation).unwrap(),
            )
            .unwrap();
        config
            .write("provision.json", &serde_json::to_vec(&provision).unwrap())
            .unwrap();
    }
    let stopped = Arc::new(AtomicBool::new(false));
    let stop = stopped.clone();
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut requests = 0;
        while !stop.load(Ordering::Acquire) && Instant::now() < deadline {
            let (mut stream, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(error) => panic!("fixture listener: {error}"),
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut reader = BufReader::new(&mut stream);
            let mut line = String::new();
            bounded_line(&mut reader, &mut line);
            assert_eq!(line, "POST /v2/install HTTP/1.1\r\n");
            let mut length = 0;
            let mut headers = 0;
            for _ in 0..64 {
                bounded_line(&mut reader, &mut line);
                headers += line.len();
                assert!(headers <= 8192);
                if line == "\r\n" {
                    break;
                }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse::<usize>().unwrap();
                }
            }
            assert!((1..16384).contains(&length));
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            drop(reader);
            let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert!(request["installation_id"].as_str().is_some());
            let reply = serde_json::to_vec(&serde_json::json!({"device_id":"11111111-1111-4111-8111-111111111111","credential":URL_SAFE_NO_PAD.encode([92;32])})).unwrap();
            write!(stream,"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",reply.len()).unwrap();
            stream.write_all(&reply).unwrap();
            requests += 1;
        }
        requests
    });
    fs::set_permissions(binary, fs::Permissions::from_mode(0o777)).unwrap();
    if use_installer {
        let status = Command::new("/usr/bin/python3")
            .arg(format!(
                "/opt/qa/payload-{}/install-discovery.py",
                installation.edition
            ))
            .arg(&provision_path)
            .arg(&installation.edition)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("HOME", "/root")
            .status()
            .unwrap();
        assert!(status.success(), "real component installer failed");
        let installed: Installation =
            serde_json::from_slice(&config.read("installation.json", 4096).unwrap()).unwrap();
        assert!(
            installed.enroll
                && installed.agent_uid == 1000
                && installed.agent_gid == 1000
                && installed.edition == installation.edition
        );
    }
    assert!(
        !unit_start(),
        "enrollment accepted a writable bridge executable"
    );
    assert!(
        config
            .read_optional("anchor.json", 16384)
            .unwrap()
            .is_none()
    );
    assert!(!bridge_home.join("state.bin").exists());
    fs::set_permissions(binary, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        unit_start(),
        "enrollment did not recover after the bridge was protected"
    );
    let verify = |sequence: &str| {
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "discovery_privileged::enrollment::native_systemd_tests::native_systemd_bootstrap",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", bridge_home)
            .env("MILVAGO_SYSTEMD_QA_ID", &identifier)
            .env("MILVAGO_DISCOVERY_BOOTSTRAP_ROLE", "verify")
            .env("MILVAGO_DISCOVERY_BOOTSTRAP_ORIGIN", &origin)
            .env("MILVAGO_DISCOVERY_EXPECTED_SEQUENCE", sequence)
            .uid(1000)
            .gid(1000)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "unprivileged bridge identity verification failed"
        );
    };
    verify("0");
    let anchor: Anchor =
        serde_json::from_slice(&config.read("anchor.json", 16384).unwrap()).unwrap();
    assert!(
        anchor.device_id == "11111111-1111-4111-8111-111111111111"
            && anchor.server_url == origin
            && anchor.public_key == key
            && anchor.agent_uid == 1000
    );
    assert!(unit_start(), "idempotent enrollment failed");
    verify("17");
    stopped.store(true, Ordering::Release);
    assert_eq!(
        server.join().unwrap(),
        1,
        "enrollment issued another device on retry"
    );
}
