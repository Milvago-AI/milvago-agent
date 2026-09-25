//! An organization MSI is an explicit reinstallation request, not a revocation bypass.
use crate::{Result, State, Store};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use std::{io::Read, path::Path};
use uuid::Uuid;

#[derive(Deserialize)]
struct Envelope { payload: String, signature: String }
#[derive(Deserialize)]
struct Confirmation { purpose: String, device_id: String, nonce: String, status: String }

pub(crate) fn resume(home: &Path, edition: &str) -> Result<()> {
    let state = { Store::open(home)?.load()? };
    let Some(pending) = state.pending_reinstallation.clone() else { return Ok(()); };
    if state.credential.is_empty() { return Err("reinstallation identity missing".into()); }
    pending.validate_local(edition)?;
    if pending.provision.server_url != state.server_url || pending.provision.policy_public_key != state.public_key {
        return Err("reinstallation origin mismatch".into());
    }
    Uuid::parse_str(&state.device_id)?;
    let nonce = Uuid::new_v4().to_string();
    // No Store lock is held during the bounded network request.
    let response = crate::client()?.post(crate::trusted_url(&state.server_url)?.join("/v2/install/reinstallation")?)
        .bearer_auth(&pending.provision.bootstrap_token)
        .json(&serde_json::json!({"device_id":state.device_id,"credential":state.credential,"nonce":nonce}))
        .send()?.error_for_status()?;
    let mut bytes = Vec::new();
    response.take(16385).read_to_end(&mut bytes)?;
    if bytes.len() > 16384 { return Err("reinstallation response exceeds limit".into()); }
    let envelope: Envelope = serde_json::from_slice(&bytes)?;
    let payload = STANDARD.decode(envelope.payload)?;
    let signature = ed25519_dalek::Signature::from_slice(&STANDARD.decode(envelope.signature)?)?;
    let key: [u8; 32] = STANDARD.decode(&state.public_key)?.try_into().map_err(|_| "invalid reinstallation key")?;
    ed25519_dalek::VerifyingKey::from_bytes(&key)?.verify_strict(&payload, &signature)?;
    let reply: Confirmation = serde_json::from_slice(&payload)?;
    if reply.purpose != "milvago/reinstallation/v1" || reply.device_id != state.device_id || reply.nonce != nonce
        || !matches!(reply.status.as_str(), "present" | "revoked" | "deleted") {
        return Err("reinstallation confirmation rejected".into());
    }
    let store = Store::open(home)?;
    let mut current = store.load()?;
    if current.device_id != state.device_id || current.credential != state.credential
        || current.server_url != state.server_url || current.public_key != state.public_key
        || !current.pending_reinstallation.as_ref().is_some_and(|p|
            p.installation_id == pending.installation_id
            && p.provision.bootstrap_token == pending.provision.bootstrap_token
            && p.provision.profile_id == pending.provision.profile_id) {
        return Err("reinstallation superseded".into());
    }
    if reply.status == "deleted" {
        // Preserve the latest encrypted state, including events queued during the
        // request. Persistence precedes identity replacement; a failure loses nothing.
        store.archive_identity()?;
        current = State { pending_installation: Some(pending), ..State::default() };
        crate::log::info("deleted device confirmed; encrypted identity archived, re-enrollment pending");
    } else {
        // Approved/pending devices keep their identity. Revocation is terminal,
        // not permission to manufacture another device.
        current.pending_reinstallation = None;
        if reply.status == "revoked" {
            crate::log::info("reinstallation refused for revoked device; identity retained");
        }
    }
    store.save(&current)
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::{self, InstallerProvision};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::Signer;
    use std::{fs, io::{BufRead, BufReader, Write}, net::TcpListener, thread, time::{Duration, Instant}};

    fn prepared(origin: String) -> (tempfile::TempDir, State) {
        let dir = tempfile::tempdir().unwrap();
        let key = STANDARD.encode(ed25519_dalek::SigningKey::from_bytes(&[91;32]).verifying_key().as_bytes());
        let mut state = State::default();
        state.server_url = origin.clone();
        state.public_key = key.clone();
        state.device_id = Uuid::new_v4().to_string();
        state.credential = URL_SAFE_NO_PAD.encode([92;32]);
        state.extension_data = serde_json::json!({"preserved":"synthetic-cached-data"});
        { Store::open(dir.path()).unwrap().save(&state).unwrap(); }
        let p = InstallerProvision { server_url:origin, policy_public_key:key.clone(), update_public_key:key,
            bootstrap_token:URL_SAFE_NO_PAD.encode([93;32]), profile_id:Uuid::new_v4(),
            edition:"community".into(), platform:std::env::consts::OS.into(),
            version:env!("CARGO_PKG_VERSION").into(), expires_at:chrono::Utc::now()+chrono::Duration::days(1) };
        bootstrap::stage(dir.path(), &serde_json::to_vec(&p).unwrap(), "synthetic-device", "community", false).unwrap();
        (dir,state)
    }

    fn signed_server(status: &'static str, corrupt: &'static str) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}",listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let worker = thread::spawn(move || {
            let deadline = Instant::now()+Duration::from_secs(10);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream,_)) => break stream,
                    Err(e) if e.kind()==std::io::ErrorKind::WouldBlock && Instant::now()<deadline =>
                        thread::sleep(Duration::from_millis(5)),
                    Err(e) => panic!("mock did not receive a request: {e}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut reader=BufReader::new(&mut stream);
            let mut line=String::new();
            reader.read_line(&mut line).unwrap();
            assert!(line.starts_with("POST /v2/install/reinstallation HTTP/1.1"));
            let mut length=None;
            loop {
                line.clear(); assert!(reader.read_line(&mut line).unwrap()>0);
                if line=="\r\n" {break;}
                if let Some(v)=line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length=Some(v.trim().parse::<usize>().unwrap());
                }
            }
            let mut body=vec![0;length.expect("request body required")];
            reader.read_exact(&mut body).unwrap(); drop(reader);
            let request:serde_json::Value=serde_json::from_slice(&body).unwrap();
            assert_eq!(request["credential"],URL_SAFE_NO_PAD.encode([92;32]));
            let payload=serde_json::to_vec(&serde_json::json!({
                "purpose":"milvago/reinstallation/v1", "device_id":request["device_id"],
                "nonce":if corrupt=="nonce" { serde_json::json!(Uuid::new_v4().to_string()) } else {request["nonce"].clone()},
                "status":status
            })).unwrap();
            let signing=ed25519_dalek::SigningKey::from_bytes(&[if corrupt=="key" {94}else{91};32]);
            let response=serde_json::to_vec(&serde_json::json!({"payload":STANDARD.encode(&payload),
                "signature":STANDARD.encode(signing.sign(&payload).to_bytes())})).unwrap();
            write!(stream,"HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",response.len()).unwrap();
            stream.write_all(&response).unwrap();
        });
        (origin,worker)
    }

    #[test]
    fn signed_deleted_confirmation_archives_before_staging_new_identity() {
        let (origin,worker)=signed_server("deleted","");
        let (dir,old)=prepared(origin);
        let before=fs::read(dir.path().join("state.bin")).unwrap();
        resume(dir.path(),"community").unwrap(); worker.join().unwrap();
        let current=Store::open(dir.path()).unwrap().load().unwrap();
        assert!(current.credential.is_empty());
        assert!(current.pending_installation.is_some());
        assert!(current.pending_reinstallation.is_none());
        assert!(current.queue.is_empty() && current.shadow_queue.is_empty());
        assert_ne!(current.extension_data,old.extension_data);
        let archives:Vec<_>=fs::read_dir(dir.path()).unwrap().map(|e|e.unwrap().path())
            .filter(|p|p.file_name().unwrap().to_string_lossy().starts_with("retired-identity-")).collect();
        assert_eq!(archives.len(),1);
        assert_eq!(fs::read(&archives[0]).unwrap(),before);
        assert!(!String::from_utf8_lossy(&before).contains("synthetic-cached-data"));
    }

    #[test]
    fn present_and_revoked_devices_never_get_new_identities() {
        for status in ["present","revoked"] {
            let (origin,worker)=signed_server(status,"");
            let (dir,old)=prepared(origin);
            resume(dir.path(),"community").unwrap(); worker.join().unwrap();
            let current=Store::open(dir.path()).unwrap().load().unwrap();
            assert_eq!(current.device_id,old.device_id);
            assert_eq!(current.credential,old.credential);
            assert_eq!(current.extension_data,old.extension_data);
            assert!(current.pending_reinstallation.is_none());
            assert!(current.pending_installation.is_none());
        }
    }

    #[test]
    fn forged_replayed_and_unknown_confirmations_cannot_reset_identity() {
        for (status,corrupt) in [("deleted","key"),("deleted","nonce"),("unknown","")] {
            let (origin,worker)=signed_server(status,corrupt);
            let (dir,old)=prepared(origin);
            assert!(resume(dir.path(),"community").is_err()); worker.join().unwrap();
            let current=Store::open(dir.path()).unwrap().load().unwrap();
            assert_eq!(current.device_id,old.device_id);
            assert_eq!(current.credential,old.credential);
            assert!(current.pending_reinstallation.is_some());
            assert!(current.pending_installation.is_none());
        }
    }

    #[test]
    fn offline_reinstallation_preserves_identity_and_does_not_block_normal_sync() {
        let listener=TcpListener::bind("127.0.0.1:0").unwrap();
        let origin=format!("http://{}",listener.local_addr().unwrap()); drop(listener);
        let (dir,old)=prepared(origin);
        bootstrap::resume(dir.path(),"community",&[]).unwrap();
        let current=Store::open(dir.path()).unwrap().load().unwrap();
        assert_eq!(current.credential,old.credential);
        assert_eq!(current.extension_data,old.extension_data);
        assert!(current.pending_reinstallation.is_some());
    }

    #[test]
    fn generic_upgrade_does_not_request_reinstallation() {
        let dir=tempfile::tempdir().unwrap();
        let mut state=State::default(); state.credential=URL_SAFE_NO_PAD.encode([95;32]);
        { Store::open(dir.path()).unwrap().save(&state).unwrap(); }
        bootstrap::stage(dir.path(),b"{}","synthetic-device","community",false).unwrap();
        assert!(Store::open(dir.path()).unwrap().load().unwrap().pending_reinstallation.is_none());
    }
}
