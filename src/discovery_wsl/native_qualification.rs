//! Runs only against synthetic distributions inside an explicitly owned offline VM.
use super::*;
use std::{collections::BTreeSet, sync::atomic::AtomicBool, time::Instant};
use windows_sys::Win32::{
    Storage::FileSystem::GetDriveTypeW, System::Threading::GetProcessHandleCount,
};

fn fixture() {
    let id = std::env::var("MILVAGO_DISCOVERY_WINDOWS_QA_ID").unwrap();
    assert_eq!(uuid::Uuid::parse_str(&id).unwrap().to_string(), id);
    let executable = std::env::current_exe().unwrap();
    assert!(matches!(
        executable.file_name().unwrap().to_str().unwrap(),
        "agent.exe" | "enterprise-agent.exe"
    ));
    let root = executable.parent().unwrap();
    assert_eq!(
        unsafe { GetDriveTypeW(wide(root.to_str().unwrap()).as_ptr()) },
        5
    );
    let marker = root.join(format!("{id}.txt"));
    assert_eq!(std::fs::metadata(&marker).unwrap().len(), 36);
    assert_eq!(std::fs::read_to_string(marker).unwrap(), id);
    owner().expect("non-elevated fixture owner required");
    let _lease = abi_guard().expect("the exact qualified service ABI must be installed");
}

fn handles() -> u32 {
    let mut value = 0;
    assert_ne!(
        unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut value) },
        0
    );
    value
}

fn python_processes(com: &Com, id: &str) -> usize {
    let stop = AtomicBool::new(false);
    let budget = Budget::new(Duration::from_secs(5), &stop);
    let bytes = com
        .processes(id, &budget)
        .expect("synthetic process inventory");
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["complete"], true);
    value["processes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| {
            row["executable"]
                .as_str()
                .is_some_and(|name| name.starts_with("python"))
        })
        .count()
}

fn assert_no_orphan(com: &Com, id: &str, baseline: usize) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let count = python_processes(com, id);
        if count <= baseline {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "closing the control channel left a Linux process alive"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
#[ignore = "requires the owned offline WSL2 fixture and its DVD identity"]
fn native_wsl_existing_distribution_lifetime_is_bounded() {
    fixture();
    let _winsock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let com = Com::open().unwrap();
    let rows = com.distributions().unwrap();
    let names: BTreeSet<_> = rows.iter().map(|row| row.3.as_str()).collect();
    assert_eq!(
        names,
        BTreeSet::from(["milvago-qa-running", "milvago-qa-stopped"])
    );
    let running = rows
        .iter()
        .find(|row| row.3 == "milvago-qa-running")
        .unwrap();
    let stopped = rows
        .iter()
        .find(|row| row.3 == "milvago-qa-stopped")
        .unwrap();
    assert!(running.1 && running.2 == 2 && !stopped.1 && stopped.2 == 2);
    let stop = AtomicBool::new(false);
    let budget = Budget::new(Duration::from_secs(5), &stop);
    assert!(com.processes(&stopped.0, &budget).is_err());
    assert!(
        !com.distributions()
            .unwrap()
            .iter()
            .find(|row| row.0 == stopped.0)
            .unwrap()
            .1
    );
    let baseline = python_processes(&com, &running.0);

    const OBSERVER: &str = "import json,os,pwd,sys\nb=sys.stdin.buffer.read(24577)\nassert len(b)==24576 and b==b'q'*24576\nprint(json.dumps({'uid':os.getuid(),'home':pwd.getpwuid(os.getuid()).pw_dir,'bytes':len(b)}))\n";
    let observed = com
        .execute_program(&running.0, &budget, OBSERVER, None, &vec![b'q'; 24 * 1024])
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&observed).unwrap(),
        serde_json::json!({"uid":1000,"home":"/home/qa","bytes":24576})
    );
    assert_no_orphan(&com, &running.0, baseline);

    // The alarm is a fixture backstop; the assertions require earlier cancellation.
    const SLEEP: &str = "import signal,time\nsignal.alarm(10)\ntime.sleep(9)\n";
    let budget = Budget::new(Duration::from_millis(100), &stop);
    let started = Instant::now();
    assert!(com.execute_fixed(&running.0, &budget, SLEEP).is_err());
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_no_orphan(&com, &running.0, baseline);

    let cancelled = AtomicBool::new(true);
    let budget = Budget::new(Duration::from_secs(5), &cancelled);
    assert!(com.execute_fixed(&running.0, &budget, SLEEP).is_err());
    assert_no_orphan(&com, &running.0, baseline);

    let budget = Budget::new(Duration::from_secs(3), &stop);
    let oversized = com.execute_fixed(&running.0, &budget, "print('x' * (2*1024*1024+1))");
    assert!(
        matches!(oversized, Err("response_limit")),
        "oversized guest output was not refused"
    );
    let budget = Budget::new(Duration::from_secs(3), &stop);
    assert!(
        com.execute_fixed(&running.0, &budget, "raise SystemExit(23)")
            .is_err()
    );
    assert_no_orphan(&com, &running.0, baseline);

    let before = handles();
    for _ in 0..16 {
        assert_eq!(python_processes(&com, &running.0), baseline);
    }
    let after = handles();
    assert!(
        after <= before + 4,
        "WSL process handles grew from {before} to {after}"
    );
    assert!(
        !com.distributions()
            .unwrap()
            .iter()
            .find(|row| row.0 == stopped.0)
            .unwrap()
            .1
    );
    println!(
        "MILVAGO_WSL_NATIVE=existing-only,stopped-preserved,timeout,cancel,exit,output-bound,handles"
    );
}
