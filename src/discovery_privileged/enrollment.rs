//! Root-owned registration supplies the binding; bridge-writable state is never
//! used to select the privileged collector's device or trust key.
use super::{Anchor, Authority, Ledger, files::Directory};
use crate::{Result, State, Store};
use base64::{Engine as _, engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}};
use serde::{Deserialize, Serialize};
use std::{fs, io::{Read, Write}, os::{fd::AsRawFd, unix::{fs::{MetadataExt, OpenOptionsExt}, process::CommandExt}}, path::Path,
    process::{Command, Stdio}, time::{Duration, Instant}};
use zeroize::Zeroize;

#[cfg(all(test, feature = "systemd-qualification"))]
#[path = "native_systemd_tests.rs"]
mod native_systemd_tests;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Installation {
    pub version: u32,
    pub edition: String,
    pub agent_uid: u32,
    pub agent_gid: u32,
    pub enroll: bool,
    #[serde(default)]
    pub portable: bool,
}
impl Installation {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 || !matches!(self.edition.as_str(), "community" | "commercial")
            || matches!(self.agent_uid, 0 | u32::MAX) || matches!(self.agent_gid, 0 | u32::MAX) {
            return Err("invalid system discovery installation".into());
        }
        Ok(())
    }
    fn bridge(&self) -> (&'static Path, &'static Path) {
        if self.edition == "community" && self.portable {
            (Path::new("/opt/milvago-browser/milvago-browser-agent"),Path::new("/var/lib/milvago-browser"))
        } else if self.edition == "community" {
            (Path::new("/opt/milvago-community/milvago-browser-agent"),Path::new("/var/lib/milvago-browser"))
        } else {
            (Path::new("/opt/milvago-commercial/milvago-commercial-bridge"),Path::new("/var/lib/milvago-commercial"))
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Seed {
    version: u32,
    edition: String,
    server_url: String,
    public_key: String,
    update_public_key: String,
    device_id: String,
    credential: String,
}
impl Drop for Seed {
    fn drop(&mut self) { self.credential.zeroize(); }
}
impl Seed {
    fn validate(&self, edition: &str) -> Result<()> {
        if self.version != 1 || self.edition != edition || !matches!(edition,"community"|"commercial")
            || self.server_url.len() > 2048 || uuid::Uuid::parse_str(&self.device_id).is_err()
            || URL_SAFE_NO_PAD.decode(&self.credential).map_or(true,|v|v.len()!=32) {
            return Err("invalid system discovery enrollment seed".into());
        }
        crate::trusted_url(&self.server_url)?;
        for key in [&self.public_key,&self.update_public_key] {
            let key: [u8;32] = STANDARD.decode(key)?.try_into().map_err(|_|"invalid enrollment trust key")?;
            ed25519_dalek::VerifyingKey::from_bytes(&key)?;
        }
        Ok(())
    }
}

pub fn import(home: &Path, edition: &str, reader: &mut impl Read) -> Result<()> {
    // This runs under the bridge account. Even a redirected destination grants
    // no root filesystem access; the privileged process never opens this store.
    if unsafe { libc::geteuid() } == 0 { return Err("import requires the unprivileged bridge account".into()); }
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    reader.take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 { return Err("enrollment seed exceeds its budget".into()); }
    let seed: Seed = serde_json::from_slice(&bytes)?;
    seed.validate(edition)?;
    let store = Store::open(home)?;
    let mut state = store.load()?;
    if state.device_id == seed.device_id && state.credential == seed.credential
        && state.server_url == seed.server_url && state.public_key == seed.public_key {
        return Ok(());
    }
    if !state.credential.is_empty() { store.archive_identity()?; }
    state = State { server_url:seed.server_url.clone(), public_key:seed.public_key.clone(),
        update_public_key:Some(seed.update_public_key.clone()), device_id:seed.device_id.clone(),
        credential:seed.credential.clone(), ..Default::default() };
    store.save(&state)
}

fn transfer(installation: &Installation, seed: &Seed) -> Result<()> {
    installation.validate()?;
    seed.validate(&installation.edition)?;
    let (binary,home) = installation.bridge();
    Directory::open(binary.parent().ok_or("missing bridge directory")?)?;
    let file = fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC).open(binary)?;
    let info = file.metadata()?;
    if !info.is_file() || info.uid() != 0 || info.nlink() != 1 || info.mode() & 0o6022 != 0 || info.mode() & 0o100 == 0 {
        return Err("bridge executable is not protected".into());
    }
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(seed)?);
    if bytes.len() > 4096 { return Err("enrollment seed exceeds its budget".into()); }
    let mut child = Command::new(format!("/proc/self/fd/{}",file.as_raw_fd()))
        .args(["import-discovery-enrollment"]).arg(home).env_clear()
        .env("PATH","/usr/bin:/bin").env("HOME",home).uid(installation.agent_uid).gid(installation.agent_gid)
        .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn()?;
    let outcome = (|| -> Result<()> {
        child.stdin.take().ok_or("enrollment pipe unavailable")?.write_all(&bytes)?;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait()? {
                return if status.success() { Ok(()) } else { Err("bridge enrollment import refused".into()) };
            }
            if Instant::now() >= deadline { return Err("bridge enrollment import timed out".into()); }
            std::thread::sleep(Duration::from_millis(10));
        }
    })();
    if outcome.is_err() { let _ = child.kill(); let _ = child.wait(); }
    outcome
}

pub fn resume(configuration: &Path, home: &Path) -> Result<()> {
    resume_with(configuration,home,transfer)
}
pub fn install_binding(configuration: &Path, home: &Path, bytes: &[u8]) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 || bytes.len() > 16384 { return Err("invalid administrator binding request".into()); }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Binding { version:u32, device_id:String, server_url:String, public_key:String, #[serde(default)] agent_uid:Option<u32> }
    let binding:Binding=serde_json::from_slice(bytes)?;
    let config=Directory::open(configuration)?;
    let installation:Installation=serde_json::from_slice(&config.read("installation.json",4096)?)?;
    installation.validate()?;
    if installation.enroll {return Err("this installation uses protected automatic enrollment".into());}
    let provision:crate::bootstrap::InstallerProvision=serde_json::from_slice(&config.read("provision.json",16384)?)?;
    if binding.server_url!=provision.server_url || binding.public_key!=provision.policy_public_key
        || binding.agent_uid.is_some_and(|uid|uid!=installation.agent_uid) {
        return Err("binding differs from the protected local installation".into());
    }
    let anchor=Anchor {version:binding.version,agent_uid:installation.agent_uid,device_id:uuid::Uuid::parse_str(&binding.device_id)?.to_string(),
        server_url:binding.server_url,public_key:binding.public_key};
    let ledger=match Directory::open(home)?.read_optional("authority.json",128*1024)? {
        Some(bytes)=>serde_json::from_slice(&bytes)?,None=>Ledger::default(),
    };
    Authority::new(anchor.clone(),ledger)?;
    config.write("anchor.json",&serde_json::to_vec(&anchor)?)
}
fn resume_with(configuration: &Path, home: &Path, deliver: impl FnOnce(&Installation,&Seed)->Result<()>) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 { return Err("system enrollment requires root".into()); }
    let config = Directory::open(configuration)?;
    let state_directory = Directory::open(home)?;
    let installation: Installation = serde_json::from_slice(&config.read("installation.json",4096)?)?;
    installation.validate()?;
    let bytes = zeroize::Zeroizing::new(config.read("provision.json",16384)?);
    let provision: crate::bootstrap::InstallerProvision = serde_json::from_slice(&bytes)?;
    if !installation.enroll {
        let anchor: Anchor = serde_json::from_slice(&config.read("anchor.json",16384)?)?;
        if anchor.agent_uid != installation.agent_uid || anchor.server_url != provision.server_url
            || anchor.public_key != provision.policy_public_key || provision.edition != installation.edition {
            return Err("existing installation binding does not match the protected profile".into());
        }
        let ledger = match state_directory.read_optional("authority.json",128*1024)? {
            Some(bytes)=>serde_json::from_slice(&bytes)?,None=>Ledger::default(),
        };
        Authority::new(anchor,ledger)?;
        return Ok(());
    }
    let registration = home.join("registration");
    Directory::create(&registration,0o700)?;
    let state = Store::open(&registration)?.load()?;
    if state.credential.is_empty() {
        let hostname = fs::read_to_string("/proc/sys/kernel/hostname")?;
        crate::bootstrap::stage(&registration,&bytes,hostname.trim(),&installation.edition,false)?;
    } else if state.server_url != provision.server_url || state.public_key != provision.policy_public_key || provision.edition != installation.edition {
        return Err("system enrollment organization changed; explicit reprovisioning is required".into());
    }
    crate::bootstrap::resume(&registration,&installation.edition,&["browser.navigation","browser.conversation","local.inspection","discovery-v1"])?;
    let state = Store::open(&registration)?.load()?;
    if state.credential.is_empty() { return Err("system enrollment is pending".into()); }
    let anchor = Anchor { version:1,agent_uid:installation.agent_uid,server_url:state.server_url.clone(),
        public_key:state.public_key.clone(),device_id:state.device_id.clone() };
    let ledger = match state_directory.read_optional("authority.json",128*1024)? {
        Some(bytes)=>serde_json::from_slice(&bytes)?,None=>Ledger::default(),
    };
    Authority::new(anchor.clone(),ledger)?;
    if let Some(previous) = config.read_optional("anchor.json",16384)? {
        let previous: Anchor = serde_json::from_slice(&previous)?;
        if previous.device_id != anchor.device_id || previous.public_key != anchor.public_key || previous.server_url != anchor.server_url || previous.agent_uid != anchor.agent_uid {
            return Err("system enrollment binding changed; explicit reprovisioning is required".into());
        }
    }
    let seed = Seed { version:1,edition:installation.edition.clone(),server_url:state.server_url.clone(),
        public_key:state.public_key.clone(),update_public_key:state.update_public_key.clone().ok_or("missing root release key")?,
        device_id:state.device_id.clone(),credential:state.credential.clone() };
    deliver(&installation,&seed)?;
    config.write("anchor.json",&serde_json::to_vec(&anchor)?)?;
    Ok(())
}

#[cfg(test)]
pub(crate) fn exercise_import(home: &Path) {
    assert_ne!(unsafe { libc::geteuid() },0);
    let key = STANDARD.encode(ed25519_dalek::SigningKey::from_bytes(&[91;32]).verifying_key().as_bytes());
    let mut seed = Seed { version:1,edition:"community".into(),server_url:"https://server.example.test".into(),
        public_key:key.clone(),update_public_key:key,device_id:"11111111-1111-4111-8111-111111111111".into(),
        credential:URL_SAFE_NO_PAD.encode([92;32]) };
    for invalid in [br#"{"version":1,"credential":{"image":"png"}}"#.as_slice(), b"[]", &vec![b'x';4097]] {
        assert!(import(home,"community",&mut &invalid[..]).is_err());
        assert!(!home.exists());
    }
    let serialized = serde_json::to_vec(&seed).unwrap();
    import(home,"community",&mut &serialized[..]).unwrap();
    {
        let store = Store::open(home).unwrap();
        let mut state = store.load().unwrap();
        assert_eq!(state.device_id,seed.device_id);
        assert_eq!(state.credential,seed.credential);
        state.discovery.sequence = 17;
        store.save(&state).unwrap();
    }
    import(home,"community",&mut &serialized[..]).unwrap();
    assert_eq!(Store::open(home).unwrap().load().unwrap().discovery.sequence,17);
    seed.credential = URL_SAFE_NO_PAD.encode([93;32]);
    import(home,"community",&mut &serde_json::to_vec(&seed).unwrap()[..]).unwrap();
    let state = Store::open(home).unwrap().load().unwrap();
    assert_eq!(state.discovery.sequence,0);
    assert_eq!(state.credential,seed.credential);
    assert!(!fs::read(home.join("state.bin")).unwrap().windows(seed.credential.len()).any(|s|s==seed.credential.as_bytes()));
    drop(state);
    fs::remove_dir_all(home).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn installation_and_seed_types_do_not_grant_privileges() {
        let mut installation = Installation { version:1,edition:"community".into(),agent_uid:1000,agent_gid:1000,enroll:true,portable:false };
        assert!(installation.validate().is_ok());
        installation.agent_uid=0;
        assert!(installation.validate().is_err());
        installation.agent_uid=1000; installation.agent_gid=0;
        assert!(installation.validate().is_err());
        for invalid in [br#"{"version":1,"edition":"community","agent_uid":"image","agent_gid":1000,"enroll":true}"#.as_slice(),br#"{"shell":"anything"}"#] {
            assert!(serde_json::from_slice::<Installation>(invalid).is_err());
        }
    }
    #[test]
    #[ignore="Required isolated root enrollment qualification"]
    fn protected_registration_retries_delivery_and_never_adopts_bridge_state() {
        use std::io::{BufRead,BufReader};
        assert_eq!(unsafe { libc::geteuid() },0);
        let root = tempfile::Builder::new().prefix("milvago-root-enrollment-").tempdir_in("/run").unwrap();
        let configuration = root.path().join("config");
        let home = root.path().join("state");
        let config = Directory::create(&configuration,0o700).unwrap();
        Directory::create(&home,0o700).unwrap();
        let installation = Installation { version:1,edition:"community".into(),agent_uid:1000,agent_gid:1000,enroll:true,portable:false };
        config.write("installation.json",&serde_json::to_vec(&installation).unwrap()).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}",listener.local_addr().unwrap());
        let key = STANDARD.encode(ed25519_dalek::SigningKey::from_bytes(&[91;32]).verifying_key().as_bytes());
        let provision = crate::bootstrap::InstallerProvision { server_url:origin.clone(), policy_public_key:key.clone(),update_public_key:key,
            bootstrap_token:URL_SAFE_NO_PAD.encode([94;32]),profile_id:uuid::Uuid::new_v4(),edition:"community".into(),platform:"linux".into(),
            version:env!("CARGO_PKG_VERSION").into(),expires_at:chrono::Utc::now()+chrono::Duration::hours(1) };
        config.write("provision.json",&serde_json::to_vec(&provision).unwrap()).unwrap();
        let worker = std::thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            let deadline = Instant::now()+Duration::from_secs(5);
            let mut stream = loop { match listener.accept() {
                Ok((stream,_))=>break stream,Err(e) if e.kind()==std::io::ErrorKind::WouldBlock=>{
                    assert!(Instant::now()<deadline);std::thread::sleep(Duration::from_millis(10));
                },Err(e)=>panic!("fixture listener failed: {e}"),
            }};
            stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut reader = BufReader::new(&mut stream);
            let mut line = String::new(); reader.read_line(&mut line).unwrap();
            assert!(line.starts_with("POST /v2/install HTTP/1.1"));
            let mut length=0;
            for _ in 0..64 {
                line.clear();reader.read_line(&mut line).unwrap();
                if line=="\r\n" {break;}
                if let Some(value)=line.to_ascii_lowercase().strip_prefix("content-length:") {length=value.trim().parse::<usize>().unwrap();}
            }
            assert!((1..16384).contains(&length));
            let mut body=vec![0;length];reader.read_exact(&mut body).unwrap();drop(reader);
            let request:serde_json::Value=serde_json::from_slice(&body).unwrap();
            assert!(request["installation_id"].as_str().is_some());
            let reply=serde_json::to_vec(&serde_json::json!({"device_id":"11111111-1111-4111-8111-111111111111","credential":URL_SAFE_NO_PAD.encode([92;32])})).unwrap();
            write!(stream,"HTTP/1.1 201 Created\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",reply.len()).unwrap();stream.write_all(&reply).unwrap();
        });
        assert!(resume_with(&configuration,&home,|_,seed|{assert_eq!(seed.device_id,"11111111-1111-4111-8111-111111111111");Err("fixture delivery failed".into())}).is_err());
        worker.join().unwrap();
        assert!(config.read_optional("anchor.json",16384).unwrap().is_none());
        resume_with(&configuration,&home,|_,seed|{assert_eq!(seed.server_url,origin);Ok(())}).unwrap();
        let anchor:Anchor=serde_json::from_slice(&config.read("anchor.json",16384).unwrap()).unwrap();
        assert_eq!(anchor.device_id,"11111111-1111-4111-8111-111111111111");
        assert!(import(&root.path().join("bridge"),"community",&mut &b"{}"[..]).is_err());
        assert!(!root.path().join("bridge").exists());
        let mut wrong=installation;wrong.enroll=false;
        config.write("installation.json",&serde_json::to_vec(&wrong).unwrap()).unwrap();
        resume_with(&configuration,&home,|_,_|panic!("manual binding must not transfer a new identity")).unwrap();
        let mut anchor=anchor;anchor.agent_uid+=1;
        config.write("anchor.json",&serde_json::to_vec(&anchor).unwrap()).unwrap();
        assert!(resume_with(&configuration,&home,|_,_|Ok(())).is_err());
        let binding=serde_json::json!({"version":1,"device_id":"11111111-1111-4111-8111-111111111111","server_url":provision.server_url,"public_key":provision.policy_public_key});
        install_binding(&configuration,&home,&serde_json::to_vec(&binding).unwrap()).unwrap();
        let fixed:Anchor=serde_json::from_slice(&config.read("anchor.json",16384).unwrap()).unwrap();
        assert_eq!(fixed.agent_uid,1000);
        let mut wrong=binding;wrong["agent_uid"]=0.into();
        assert!(install_binding(&configuration,&home,&serde_json::to_vec(&wrong).unwrap()).is_err());
    }
}
