use std::{
    process::{Command, Stdio},
    thread,
    time::Duration,
};

#[test]
fn watcher_survives_startup_without_enrollment() {
    let directory = tempfile::tempdir().unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_milvago-browser-agent"));
    command
        .arg("watch")
        .arg(directory.path())
        .env("MILVAGO_TEST_CHANNEL", format!("test-watch-{}", uuid::Uuid::new_v4()))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let mut child = command.spawn().unwrap();
    thread::sleep(Duration::from_secs(2));
    let status = child.try_wait().unwrap();
    if status.is_none() {
        child.kill().unwrap();
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        status.is_none(),
        "watcher exited during startup: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
