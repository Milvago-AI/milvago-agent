use chrono::Utc;
use milvago_browser_agent::update::{Release, install};

#[test]
fn installs_a_real_binary_and_checks_its_reported_version() {
    let bytes = std::fs::read(env!("CARGO_BIN_EXE_milvago-browser-agent")).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let target = directory
        .path()
        .join(if cfg!(windows) { "agent.exe" } else { "agent" });
    std::fs::write(&target, b"synthetic previous executable").unwrap();
    let hash = milvago_browser_agent::sha256_hex(&bytes);
    let release = Release {
        format: "binary".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        edition: "community".into(),
        platform: std::env::consts::OS.into(),
        protocol: 2,
        sha256: hash.clone(),
        size: bytes.len() as u64,
        expires_at: Utc::now() + chrono::Duration::hours(1),
        artifact: format!("/v2/update/artifact/{hash}"),
        rollback_from: vec![],
    };
    assert!(install(&target, &release, &bytes).unwrap());
    let output = std::process::Command::new(&target)
        .arg("--version")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains(env!("CARGO_PKG_VERSION"))
    );
    assert!(std::fs::read_dir(directory.path()).unwrap().any(|entry| {
        entry
            .unwrap()
            .path()
            .extension()
            .is_some_and(|s| s == "backup")
    }));
}
