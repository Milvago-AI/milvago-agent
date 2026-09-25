use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{Duration as ChronoDuration, Utc};
use ed25519_dalek::{Signer, SigningKey};
use milvago_browser_agent::{Envelope, State, Store, native::native_message, shadow};
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex, atomic::{AtomicBool, AtomicUsize, Ordering}},
    thread,
    time::{Duration, Instant},
};

fn envelope(issued: chrono::DateTime<Utc>) -> (Envelope, String) {
    let key = SigningKey::from_bytes(&[61; 32]);
    let payload = serde_json::to_vec(&json!({
        "version":3,"revision":7,"issued_at":issued,
        "expires_at":issued+ChronoDuration::minutes(15),"capabilities":[],
        "config":{
            "collection":{"enabled":true,"store_content":true},
            "services":[{"id":"chatgpt","domains":["chatgpt.com"],"enabled":true,"mode":"observe"}],
            "protection":{"keywords":["synthetic-denied"],"exact":"block","unicode":"off","fuzzy":"off"},
            "privacy":{"enabled":false}
        }
    })).unwrap();
    (Envelope { payload:STANDARD.encode(&payload), signature:STANDARD.encode(key.sign(&payload).to_bytes()) },
     STANDARD.encode(key.verifying_key().as_bytes()))
}

struct Agent(Child);
impl Drop for Agent {
    fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); }
}

#[test]
fn expired_local_cache_is_verified_but_expired_network_policy_is_refused() {
    let issued=Utc::now()-ChronoDuration::hours(2);
    let (signed,key)=envelope(issued);
    assert!(shadow::verify(&signed,&key,7,issued).is_ok());
    assert!(shadow::verify(&signed,&key,7,Utc::now()).is_err());
    let mut state=State{public_key:key,shadow_policy:Some(signed),shadow_revision:7,..State::default()};
    assert_eq!(shadow::cached(&state).unwrap().revision,7);
    state.shadow_revision=8;
    assert!(shadow::cached(&state).is_err());
    state.shadow_revision=7;
    state.shadow_policy.as_mut().unwrap().payload=STANDARD.encode(b"{}");
    assert!(shadow::cached(&state).is_err());
    state.shadow_policy=None;
    assert!(shadow::cached(&state).is_err());
}

#[test]
fn running_agent_retains_encrypted_events_offline_and_recovers_without_restart() {
    let listener=TcpListener::bind("127.0.0.1:0").unwrap();
    let address=listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let online=Arc::new(AtomicBool::new(false));
    let stop=Arc::new(AtomicBool::new(false));
    let policy_calls=Arc::new(AtomicUsize::new(0));
    let accepted:Arc<Mutex<Vec<Value>>>=Arc::default();
    let (server_online,server_stop,calls,received)=(online.clone(),stop.clone(),policy_calls.clone(),accepted.clone());
    let server=thread::spawn(move || {
        while !server_stop.load(Ordering::Acquire) {
            let (mut socket,_)=match listener.accept() {
                Ok(pair)=>pair,
                Err(e) if e.kind()==std::io::ErrorKind::WouldBlock=>{thread::sleep(Duration::from_millis(10));continue;},
                Err(e)=>panic!("test server accept failed: {e}"),
            };
            socket.set_nonblocking(false).unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut reader=BufReader::new(socket.try_clone().unwrap());
            let mut line=String::new();
            reader.read_line(&mut line).unwrap();
            let route=line.split_whitespace().nth(1).unwrap().to_owned();
            let mut length=0;
            loop {
                line.clear();reader.read_line(&mut line).unwrap();
                if line=="\r\n" {break;}
                if let Some((key,value))=line.split_once(':') {
                    if key.eq_ignore_ascii_case("content-length"){length=value.trim().parse().unwrap();}
                }
            }
            assert!(length<=128*1024);
            let mut body=vec![0;length];reader.read_exact(&mut body).unwrap();
            if route=="/v3/policy"{calls.fetch_add(1,Ordering::AcqRel);}
            let (status,answer)=if !server_online.load(Ordering::Acquire) {
                ("503 Service Unavailable",json!({"error":"offline"}))
            } else if route=="/v3/policy" {
                ("200 OK",serde_json::to_value(envelope(Utc::now()).0).unwrap())
            } else if route=="/v2/events" {
                let request:Value=serde_json::from_slice(&body).unwrap();
                let events=request["events"].as_array().unwrap();
                assert!(!events.is_empty());
                received.lock().unwrap().extend(events.iter().cloned());
                ("200 OK",json!({"accepted_ids":events.iter().map(|e|e["id"].clone()).collect::<Vec<_>>()}))
            } else if route=="/v3/detection-catalog" {
                ("404 Not Found",json!({}))
            } else {("200 OK",json!({}))};
            let bytes=serde_json::to_vec(&answer).unwrap();
            write!(socket,"HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",bytes.len()).unwrap();
            socket.write_all(&bytes).unwrap();
        }
    });
    let directory=tempfile::tempdir().unwrap();
    let home=directory.path();
    let issued=Utc::now()-ChronoDuration::hours(2);
    let (signed,key)=envelope(issued);
    assert!(shadow::verify(&signed,&key,7,issued).is_ok(),"fixture was valid before disconnection");
    let state=State{server_url:format!("http://{address}"),credential:"synthetic-offline-credential".into(),
        device_id:uuid::Uuid::new_v4().to_string(),public_key:key,shadow_revision:7,
        shadow_policy:Some(signed),..State::default()};
    Store::open(home).unwrap().save(&state).unwrap();
    let began=Instant::now();
    let policy=native_message(home,json!({"op":"policy_v3"})).unwrap();
    assert_eq!(policy["online"],false);
    assert!(chrono::DateTime::parse_from_rfc3339(policy["policy"]["expires_at"].as_str().unwrap()).unwrap()>Utc::now());
    assert!(chrono::DateTime::parse_from_rfc3339(policy["policy"]["signed_expires_at"].as_str().unwrap()).unwrap()<Utc::now());
    let inspection=native_message(home,json!({"op":"inspect","provider":"chatgpt.com","text":"synthetic-denied","upload":false})).unwrap();
    assert_eq!(inspection["action"],"block","offline policy must actually be enforced");
    let receipt=native_message(home,json!({"op":"event_v2","event":{
        "kind":"prompt","provider":"chatgpt.com","source":"browser","tool":"chrome","action":"observed",
        "characters":22,"labels":[],"prompt":"synthetic-offline-body","policy_revision":7
    }})).unwrap();
    assert!(began.elapsed()<Duration::from_secs(2),"IPC path waited for the network");
    assert_eq!(policy_calls.load(Ordering::Acquire),0,"IPC path performed a policy request");
    assert_eq!(receipt["ok"],true);
    let restored=Store::open(home).unwrap().load().unwrap();
    assert_eq!(restored.shadow_queue.len(),1);
    assert_eq!(restored.shadow_queue[0].prompt.as_deref(),Some("synthetic-offline-body"));
    let raw=std::fs::read(home.join("state.bin")).unwrap();
    assert!(!raw.windows(b"synthetic-offline-body".len()).any(|w|w==b"synthetic-offline-body"));
    let mut command=Command::new(env!("CARGO_BIN_EXE_milvago-browser-agent"));
    command.arg("watch").arg(home).env("MILVAGO_TEST_CHANNEL",format!("offline-{}",uuid::Uuid::new_v4()))
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    #[cfg(windows)] {use std::os::windows::process::CommandExt;command.creation_flags(0x08000000);}
    let mut agent=Agent(command.spawn().unwrap());
    let pid=agent.0.id();
    let deadline=Instant::now()+Duration::from_secs(12);
    while policy_calls.load(Ordering::Acquire)==0 {
        assert!(agent.0.try_wait().unwrap().is_none(),"agent exited during outage");
        assert!(Instant::now()<deadline,"watcher never attempted synchronization");
        thread::sleep(Duration::from_millis(50));
    }
    thread::sleep(Duration::from_millis(200));
    let pending=Store::open(home).unwrap().load().unwrap();
    assert_eq!(pending.shadow_queue.len(),1);
    assert_eq!(pending.shadow_queue[0].prompt.as_deref(),Some("synthetic-offline-body"));
    online.store(true,Ordering::Release);
    let deadline=Instant::now()+Duration::from_secs(50);
    loop {
        assert!(agent.0.try_wait().unwrap().is_none(),"recovery required a process restart");
        let recovered=Store::open(home).unwrap().load().unwrap();
        if recovered.shadow_online&&recovered.shadow_queue.is_empty(){break;}
        assert!(Instant::now()<deadline,"watcher did not recover automatically");
        thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(agent.0.id(),pid);
    thread::sleep(Duration::from_secs(6));
    assert!(agent.0.try_wait().unwrap().is_none());
    let rows=accepted.lock().unwrap();
    assert_eq!(rows.len(),1,"the queued event must be delivered exactly once");
    assert_eq!(rows[0]["id"],receipt["id"]);
    assert_eq!(rows[0]["prompt"],"synthetic-offline-body");
    drop(rows);
    drop(agent);
    stop.store(true,Ordering::Release);
    server.join().unwrap();
}
