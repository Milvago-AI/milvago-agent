use super::*;
use crate::{browser_broker::{self as broker, PendingHealth}, detection, shadow};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{Duration, Utc};
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{cell::{Cell, RefCell}, fs, fs::OpenOptions, os::windows::fs::OpenOptionsExt};

fn signed<T: Serialize>(key: &SigningKey, value: &T) -> Envelope {
    let bytes = serde_json::to_vec(value).unwrap();
    Envelope {
        payload: STANDARD.encode(&bytes),
        signature: STANDARD.encode(key.sign(&bytes).to_bytes()),
    }
}

fn live_policy(key: &SigningKey, revision: u64) -> Envelope {
    let now = Utc::now();
    signed(key, &json!({
        "version":3,"revision":revision,"issued_at":now,"expires_at":now+Duration::minutes(10),
        "capabilities":[],"config":{
            "collection":{"enabled":true,"store_content":true,"store_file_names":true},
            "services":[{"id":"chatgpt","domains":["chatgpt.com"],"enabled":true,"mode":"observe"}],
            "privacy":{"enabled":true,"review":false,"types":["email","ip"],
                "custom_rules":[{"enabled":true,"label":"NUMERO","pattern":"ID-[0-9]+","case_insensitive":false}]},
            "protection":{"block_uploads":false,"exact":"block","unicode":"off","fuzzy":"off","keywords":["synthetic-denied"]}
        }
    }))
}

fn live_catalog(key: &SigningKey) -> Envelope {
    let now = Utc::now();
    let content = detection::Content {
        providers: vec![detection::Provider {
            id: "chatgpt".into(), label: "Synthetic provider".into(), domains: vec!["chatgpt.com".into()],
            aliases: vec![], conversation_path: String::new(), conversation_segment: 0, conversation_paths: vec![],
            dom: detection::Dom { editor:String::new(), send:String::new(), response:String::new() },
            network: vec![], qualified_at: now.to_rfc3339(), asset_hosts: vec![],
        }],
        native_tools: vec![],
        heuristics: detection::Heuristics { keys: vec![], mime_types: vec![] },
        known_platforms: vec![],
    };
    let raw = serde_json::to_vec(&content).unwrap();
    signed(key, &detection::Header {
        kind:"detection_catalog".into(), schema:1, revision:1, issued_at:now,
        expires_at:now+Duration::minutes(10),
        min_engine:detection::Engines { extension:detection::ENGINE_VERSION.into(), bridge:detection::ENGINE_VERSION.into() },
        content_hash:format!("{:x}",Sha256::digest(&raw)), content:STANDARD.encode(raw),
    })
}

fn memory_authority() -> (Authority, Value, shadow::ShadowPolicy, String) {
    let authority_key = SigningKey::from_bytes(&[73; 32]);
    let keys = Keys::generate();
    let pin = Pin {
        installation:uuid::Uuid::new_v4().to_string(), edition:crate::extension_update::EDITION.into(),
        origin:"https://example.test".into(),
        organization_anchor:STANDARD.encode(authority_key.verifying_key().as_bytes()), signing_key:keys.public(),
    };
    let mut journal = Journal::new(pin).unwrap();
    let policy_envelope = live_policy(&authority_key, 1);
    let catalog_envelope = live_catalog(&authority_key);
    cache::prepare(&mut journal, &keys, &policy_envelope, &catalog_envelope).unwrap();
    let policy = shadow::verify(&policy_envelope, &journal.pin.organization_anchor, 1, Utc::now()).unwrap();
    let boot = uuid::Uuid::new_v4().to_string();
    journal.recovered(&boot, 100).unwrap();
    let response = json!({
        "ok":true,"online":false,"policy":crate::native::browser_policy(&policy),
        "cache_policy_hash":cache::envelope_hash(&policy_envelope).unwrap(),
        "cache_authorization_generation":7,
        "cache_policy_content_hash":journal.policy_content_hash,
        "cache_catalog_content_hash":journal.catalog_content_hash,
        "cache_catalog_revision":journal.catalog_revision,
    });
    let stored = Stored { journal, keys, queue:Default::default() };
    (Authority { stored, storage:Storage::Memory, storage_failed:false }, response, policy, boot)
}

fn wrapped(request: Value) -> crate::browser_broker::Parsed {
    broker::parse(&json!({"protocol":broker::PROTOCOL,"op":"browser_request",
        "caller":{"user":"synthetic-user","sid":"S-1-5-21-1-2-3-1001"},
        "body":STANDARD.encode(serde_json::to_vec(&request).unwrap())})).unwrap()
}

fn request(op: &str) -> crate::browser_broker::Parsed {
    let mut request = json!({"protocol":broker::PROTOCOL,"op":op,
        "challenge":STANDARD.encode([11u8;32]),"tool":"chrome"});
    if matches!(op, "browser_inspect" | "browser_submit") {
        request["provider"]=json!("chatgpt.com"); request["text"]=json!("synthetic body");
        request["upload"]=json!(false);
    }
    if op == "browser_submit" {
        request["delivery_id"]=json!(uuid::Uuid::new_v4().to_string());
        request["event"]=json!({"tool":"chrome"});
    }
    wrapped(request)
}

fn event_request(delivery: uuid::Uuid) -> crate::browser_broker::Parsed {
    wrapped(json!({"protocol":broker::PROTOCOL,"op":"browser_event",
        "challenge":STANDARD.encode([12u8;32]),"tool":"chrome","delivery_id":delivery,
        "event":{"kind":"prompt","provider":"chatgpt.com","source":"browser","tool":"chrome",
            "action":"observed","characters":14,"labels":[],"prompt":"synthetic body"}}))
}
fn prepared_event(policy: &shadow::ShadowPolicy, response: &Value, request: &Value) -> Value {
    let input = request["event"].clone();
    let mut event = shadow::browser_event(
        policy,
        response["cache_catalog_revision"].as_u64().unwrap(),
        input.clone(),
    ).unwrap();
    event.id = uuid::Uuid::nil();
    event.user = None;
    json!({"ok":true,"event":event,"provenance":{
        "policy_revision":policy.revision,
        "policy_content_hash":response["cache_policy_content_hash"],
        "authorization_generation":response["cache_authorization_generation"],
        "catalog_revision":response["cache_catalog_revision"],
        "input_hash":cache::hash(&serde_json::to_vec(&input).unwrap())
    }})
}

fn fixture() -> Stored {
    let keys = Keys::generate();
    let mut journal = Journal::new(Pin {
        installation: uuid::Uuid::new_v4().to_string(), edition: crate::extension_update::EDITION.into(),
        origin: "https://example.test".into(), organization_anchor: keys.public(), signing_key: keys.public(),
    }).unwrap();
    journal.generation=81; journal.policy_revision=17; journal.catalog_revision=2;
    let mut queue = crate::browser_broker::Queue::default();
    queue.sequence=2;
    queue.health=(1..=2).map(|sequence|PendingHealth { sequence, generation:81,
        tool:"chrome".into(), batch:json!({"id":uuid::Uuid::new_v4().to_string()}), principal:String::new() }).collect();
    Stored { journal, keys, queue }
}
fn epoch(s:&Stored)->windows::Epoch {
    let j=&s.journal;
    serde_json::from_value(json!({"installation":j.pin.installation,"generation":j.generation,
        "cache_hash":j.cache_hash,"policy_revision":j.policy_revision,"catalog_revision":j.catalog_revision,
        "boot":j.boot,"deadline":j.deadline,"armed":j.armed,"last_tick":j.last_tick,
        "queue_hash":cache::hash(&serde_json::to_vec(&s.queue).unwrap())})).unwrap()
}
fn encrypted(s:&Stored)->Vec<u8> {
    let mut plain=serde_json::to_vec(s).unwrap();
    let bytes=crate::os_wrap(&plain,true).unwrap();plain.zeroize();bytes
}
// Real files, DPAPI and Windows sharing errors. Epoch uses the actual schema and
// validator in a test file; these tests do not qualify protected HKLM or SCM.
fn commit(root:&Path,s:&Stored)->Result<()> {
    commit_snapshot(&encrypted(s), |name,bytes|crate::atomic_private(&root.join(name),bytes),
        ||crate::atomic_private(&root.join("epoch.json"),&serde_json::to_vec(&epoch(s))?))
}
fn recover(root:&Path,pin:&Pin)->Result<(Stored,Option<Vec<u8>>)> {
    let e=serde_json::from_slice(&fs::read(root.join("epoch.json"))?)?;
    committed_snapshot(pin,&e,|name|Ok(fs::read(root.join(name))?),||Ok(fs::read_dir(root)?
        .filter_map(|entry|{let name=entry.ok()?.file_name().to_str()?.to_owned();
            name.ends_with(".tmp").then_some(name)}).collect()))
}
fn sharing_violation(error:&(dyn std::error::Error+Send+Sync+'static)) {
    // MoveFileEx may report ACCESS_DENIED for a handle lacking delete sharing.
    // Each test proves that releasing this exact handle permits replacement.
    assert!(matches!(error.downcast_ref::<std::io::Error>().and_then(|e|e.raw_os_error()),Some(5|32)));
}
#[test]
fn failed_replace_keeps_committed_receipt_removal_recoverable() {
    let dir=tempfile::tempdir().unwrap();let root=dir.path();let mut s=fixture();commit(root,&s).unwrap();
    let old=fs::read(root.join("state.bin")).unwrap();
    let lock=OpenOptions::new().read(true).share_mode(1).open(root.join("state.bin")).unwrap();
    s.queue.health.remove(0); // Only after a durable agent receipt.
    sharing_violation(commit(root,&s).unwrap_err().as_ref());
    assert_eq!(fs::read(root.join("state.bin")).unwrap(),old);
    let(restored,pending)=recover(root,&s.journal.pin).unwrap();
    assert_eq!(restored.queue.health.len(),1);assert_eq!(restored.queue.health[0].sequence,2);
    assert!(pending.is_some());drop(lock);
    crate::atomic_private(&root.join("state.bin"),&pending.unwrap()).unwrap();
    let(restored,pending)=recover(root,&s.journal.pin).unwrap();
    assert_eq!(restored.queue.health.len(),1);assert!(pending.is_none());
}
#[test]
fn failed_staging_does_not_advance_the_epoch() {
    let dir=tempfile::tempdir().unwrap();let root=dir.path();let mut s=fixture();commit(root,&s).unwrap();
    let before=fs::read(root.join("epoch.json")).unwrap();
    let lock=OpenOptions::new().read(true).share_mode(1).open(root.join("pending.bin")).unwrap();
    s.queue.health.remove(0);sharing_violation(commit(root,&s).unwrap_err().as_ref());
    assert_eq!(fs::read(root.join("epoch.json")).unwrap(),before);
    assert_eq!(recover(root,&s.journal.pin).unwrap().0.queue.health.len(),2);
    drop(lock);commit(root,&s).unwrap();
    assert_eq!(recover(root,&s.journal.pin).unwrap().0.queue.health.len(),1);
}
#[test]
fn uncommitted_staging_cannot_override_the_current_epoch() {
    let dir=tempfile::tempdir().unwrap();let root=dir.path();let mut s=fixture();commit(root,&s).unwrap();
    s.queue.health.remove(0);
    assert!(commit_snapshot(&encrypted(&s),|name,bytes|crate::atomic_private(&root.join(name),bytes),
        ||Err("injected epoch failure".into())).is_err());
    let(restored,pending)=recover(root,&s.journal.pin).unwrap();
    assert_eq!(restored.queue.health.len(),2);assert!(pending.is_none());
    fs::remove_file(root.join("state.bin")).unwrap();assert!(recover(root,&s.journal.pin).is_err());
}
#[test]
fn legacy_rename_failure_recovers_only_the_exact_epoch() {
    let dir=tempfile::tempdir().unwrap();let root=dir.path();let mut s=fixture();commit(root,&s).unwrap();
    fs::remove_file(root.join("pending.bin")).unwrap();
    let lock=OpenOptions::new().read(true).share_mode(1).open(root.join("state.bin")).unwrap();
    s.queue.health.remove(0);
    // Exact old order: epoch advances, then the rename fails. atomic_private now removes
    // its temporary on failure; up to 0.5.16 it left it, as written here by hand.
    crate::atomic_private(&root.join("epoch.json"),&serde_json::to_vec(&epoch(&s)).unwrap()).unwrap();
    sharing_violation(crate::atomic_private(&root.join("state.bin"),&encrypted(&s)).unwrap_err().as_ref());
    assert!(fs::read_dir(root).unwrap().flatten().all(|entry| !entry.file_name().to_string_lossy().ends_with(".tmp")), "a failed write left its temporary");
    fs::write(root.join(format!("state.{}.tmp",uuid::Uuid::new_v4())),encrypted(&s)).unwrap();
    let(restored,temporary)=recover(root,&s.journal.pin).unwrap();
    assert_eq!(restored.queue.health.len(),1);assert_eq!(restored.queue.health[0].sequence,2);
    assert!(temporary.is_some());drop(lock);
    crate::atomic_private(&root.join("state.bin"),&temporary.unwrap()).unwrap();
    assert!(recover(root,&s.journal.pin).unwrap().1.is_none());
}
#[test]
fn mismatched_queue_pin_key_and_generation_are_never_recovered() {
    let mut s=fixture();let pin=s.journal.pin.clone();let e=epoch(&s);
    let mut original=serde_json::to_vec(&s).unwrap();
    for field in ["queue","pin","key","generation"] {
        s=serde_json::from_slice(&original).unwrap();
        match field { "queue"=>{s.queue.health.remove(0);},
            "pin"=>s.journal.pin.installation=uuid::Uuid::new_v4().to_string(),
            "key"=>s.keys=Keys::generate(),"generation"=>s.journal.generation+=1,_=>unreachable!() }
        assert!(decode_snapshot(&encrypted(&s),&pin,&e).is_err(),"accepted {field}");
    }
    original.zeroize();
}
#[test]
fn recovery_preserves_persisted_grace_and_revocation() {
    let mut s=fixture();s.journal.boot=uuid::Uuid::new_v4().to_string();
    s.journal.deadline=Some(300_000);s.journal.last_tick=240_000;s.journal.armed=false;
    let e=epoch(&s);s.journal.deadline=None;s.journal.last_tick=0;s.journal.armed=true;
    s.journal.boot=uuid::Uuid::new_v4().to_string();
    let restored=decode_snapshot(&encrypted(&s),&s.journal.pin,&e).unwrap();
    assert_eq!(restored.journal.deadline,Some(300_000));assert_eq!(restored.journal.last_tick,240_000);
    assert!(!restored.journal.armed);assert_ne!(restored.journal.boot,s.journal.boot);
}

#[test]
fn reachable_offline_agent_keeps_every_browser_operation_connected_past_grace() {
    let (mut authority, response, policy, boot) = memory_authority();
    authority.stored.journal.deadline = Some(300_100);
    let delivered = RefCell::new(Vec::new());
    let mut exchange = |request: &Value| -> Result<Value> {
        match request["op"].as_str().unwrap_or("") {
            "policy_v3" => Ok(response.clone()),
            "broker_inspect" => Ok(json!({"ok":true,"policy_content_hash":response["cache_policy_content_hash"],
                "inspection":{"ok":true,"action":"observe","text":request["text"],"labels":[]}})),
            "broker_prepare_event" => Ok(prepared_event(&policy, &response, request)),
            "inspect" => crate::native::inspect_authorized_request(&policy, request),
            "catalog" => Ok(json!({"ok":true,"catalog":{"providers":[],"heuristics":{}},"revision":1})),
            "broker_event" => {
                let id = request.get("event").map(|event| event["id"].clone())
                    .unwrap_or_else(|| request["batch"]["id"].clone());
                delivered.borrow_mut().push(id.clone());
                Ok(json!({"ok":true,"durable":true,"id":id}))
            }
            other => Err(format!("unexpected operation {other}").into()),
        }
    };
    for op in ["browser_policy", "browser_catalog", "browser_inspect", "browser_submit"] {
        let (mode, reply) = authority.answer_with(&request(op), &mut exchange, &boot, 400_101).unwrap();
        assert_eq!(mode, "connected", "{op}");
        assert_ne!(reply["ok"], false, "{op}: {reply}");
        if op == "browser_policy" { assert_eq!(reply["online"], false); }
    }
    assert!(authority.stored.journal.armed);
    assert_eq!(authority.stored.journal.deadline, None);
    assert_eq!(delivered.borrow().len(), 0, "interactive requests never drain custody");
    assert_eq!(authority.stored.queue.len(), 1);
    assert!(authority.drain_one_with(&mut exchange).unwrap());
    assert_eq!(delivered.borrow().len(), 1);
    assert_eq!(authority.stored.queue.len(), 0);
}

#[test]
fn stale_system_copy_does_not_block_live_custody_or_duplicate_recovery() {
    let (mut authority, mut response, _policy, boot) = memory_authority();
    response["cache_policy_content_hash"] = json!("f".repeat(64));
    let delivery = uuid::Uuid::new_v4();
    let parsed = event_request(delivery);
    let allow_delivery = Cell::new(false);
    let delivered = RefCell::new(Vec::new());
    let mut exchange = |request: &Value| -> Result<Value> {
        match request["op"].as_str().unwrap_or("") {
            "policy_v3" => Ok(response.clone()),
            "broker_prepare_event" => Ok(prepared_event(&_policy, &response, request)),
            "broker_cache_source" => Err("synthetic resynchronization failure".into()),
            "broker_event" if !allow_delivery.get() => Err("synthetic agent queue failure".into()),
            "broker_event" => {
                let id = request["event"]["id"].clone();
                delivered.borrow_mut().push(id.clone());
                Ok(json!({"ok":true,"durable":true,"id":id}))
            }
            other => Err(format!("unexpected operation {other}").into()),
        }
    };
    let (mode, first) = authority.answer_with(&parsed, &mut exchange, &boot, 500).unwrap();
    assert_eq!(mode, "connected");
    assert_eq!(first["durable"], true);
    assert_eq!(authority.stored.queue.len(), 1);
    assert!(!authority.stored.journal.armed, "stale SYSTEM cache must not grant later grace");

    allow_delivery.set(true);
    authority.answer_with(&request("browser_policy"), &mut exchange, &boot, 600).unwrap();
    assert_eq!(authority.stored.queue.len(), 1, "interactive policy lookup never drains");
    assert!(authority.drain_one_with(&mut exchange).unwrap());
    assert_eq!(authority.stored.queue.len(), 0);
    assert_eq!(delivered.borrow().len(), 1);
    let (_, replay) = authority.answer_with(&parsed, &mut exchange, &boot, 700).unwrap();
    assert_eq!(replay["id"], first["id"]);
    assert_eq!(delivered.borrow().len(), 1, "stable delivery receipt prevents a duplicate");
}

#[test]
fn connected_preparation_masks_before_system_custody_and_rejects_stale_provenance() {
    let (mut authority, response, policy, boot) = memory_authority();
    let delivery = uuid::Uuid::new_v4();
    let parsed = wrapped(json!({"protocol":broker::PROTOCOL,"op":"browser_event",
        "challenge":STANDARD.encode([12u8;32]),"tool":"chrome","delivery_id":delivery,
        "event":{"kind":"prompt","provider":"chatgpt.com","source":"browser","tool":"chrome",
            "action":"observed","characters":70,"labels":[],
            "prompt":"a@example.invalid b@example.invalid a@example.invalid 192.0.2.1 ID-42"}}));
    let mut exchange = |request: &Value| -> Result<Value> {
        match request["op"].as_str().unwrap_or("") {
            "policy_v3" => Ok(response.clone()),
            "broker_prepare_event" => Ok(prepared_event(&policy, &response, request)),
            other => Err(format!("unexpected operation {other}").into()),
        }
    };
    let (_, reply) = authority.answer_with(&parsed, &mut exchange, &boot, 500).unwrap();
    assert_eq!(reply["durable"], true);
    let stored = authority.stored.queue.pending[0].event.prompt.as_deref().unwrap();
    for secret in ["a@example.invalid", "b@example.invalid", "192.0.2.1", "ID-42"] {
        assert!(!stored.contains(secret), "SYSTEM custody retained {secret}");
    }
    assert!(stored.contains("[EMAIL"));
    assert!(stored.contains("[IP]"));
    assert!(stored.contains("[NUMERO]"));

    let (mut forged, response, policy, boot) = memory_authority();
    let mut tampered = |request: &Value| -> Result<Value> {
        match request["op"].as_str().unwrap_or("") {
            "policy_v3" => Ok(response.clone()),
            "broker_prepare_event" => {
                let mut answer = prepared_event(&policy, &response, request);
                answer["event"]["id"] = json!(uuid::Uuid::new_v4());
                Ok(answer)
            }
            _ => Err("unexpected operation".into()),
        }
    };
    assert!(forged.answer_with(&parsed, &mut tampered, &boot, 550).is_err());
    assert_eq!(forged.stored.queue.len(), 0);

    let (mut stale, response, policy, boot) = memory_authority();
    let mut changed = |request: &Value| -> Result<Value> {
        match request["op"].as_str().unwrap_or("") {
            "policy_v3" => Ok(response.clone()),
            "broker_prepare_event" => {
                let mut answer = prepared_event(&policy, &response, request);
                answer["provenance"]["authorization_generation"] = json!(8);
                Ok(answer)
            }
            _ => Err("unexpected operation".into()),
        }
    };
    assert!(stale.answer_with(&parsed, &mut changed, &boot, 600).is_err());
    assert_eq!(stale.stored.queue.len(), 0);
}

#[test]
fn unreachable_agent_gets_one_monotone_grace_and_never_renews_it() {
    let (mut authority, _response, _policy, boot) = memory_authority();
    let parsed = request("browser_policy");
    let mut unavailable = |_request: &Value| -> Result<Value> { Err("agent unavailable".into()) };
    let (mode, _) = authority.answer_with(&parsed, &mut unavailable, &boot, 1_000).unwrap();
    assert_eq!(mode, "grace");
    let deadline = authority.stored.journal.deadline;
    let (mode, _) = authority.answer_with(&parsed, &mut unavailable, &boot, 300_999).unwrap();
    assert_eq!(mode, "grace");
    assert_eq!(authority.stored.journal.deadline, deadline);
    assert!(authority.answer_with(&parsed, &mut unavailable, &boot, 301_000).is_err());
    assert_eq!(authority.stored.journal.deadline, deadline);
    assert!(!authority.stored.journal.armed);
    assert!(authority.answer_with(&parsed, &mut unavailable, &boot, 301_001).is_err());
    assert_eq!(authority.stored.journal.deadline, deadline);
}

#[test]
fn explicit_or_cryptographically_invalid_agent_state_still_blocks() {
    let (mut refused, _response, _policy, boot) = memory_authority();
    let mut deny = |_request: &Value| -> Result<Value> { Ok(json!({"ok":false,"error":"operation_refused"})) };
    let (mode, reply) = refused.answer_with(&request("browser_policy"), &mut deny, &boot, 200).unwrap();
    assert_eq!(mode, "blocked");
    assert_eq!(reply["error"], "agent_refused");
    assert!(refused.stored.journal.cache.is_none());

    let (mut invalid, mut response, _policy, boot) = memory_authority();
    let key = SigningKey::from_bytes(&[73; 32]);
    let mut bad_policy = live_policy(&key, 1);
    bad_policy.signature = STANDARD.encode([0u8; 64]);
    response["cache_policy_hash"] = json!(cache::envelope_hash(&bad_policy).unwrap());
    response["cache_policy_content_hash"] = json!("0".repeat(64));
    let source = json!({"ok":true,"protocol":cache::PROTOCOL,"op":"cache_prepare",
        "origin":invalid.stored.journal.pin.origin,
        "organization_anchor":invalid.stored.journal.pin.organization_anchor,
        "authorization_generation":7,"policy":bad_policy,"catalog":live_catalog(&key)});
    let mut forged = |request: &Value| -> Result<Value> {
        match request["op"].as_str().unwrap_or("") {
            "policy_v3" => Ok(response.clone()),
            "broker_cache_source" => Ok(source.clone()),
            _ => Err("unexpected operation".into()),
        }
    };
    let (mode, _) = invalid.answer_with(&request("browser_policy"), &mut forged, &boot, 300).unwrap();
    assert_eq!(mode, "connected", "a stale SYSTEM copy cannot downgrade a live agent");
    assert!(!invalid.stored.journal.armed);
    assert!(matches!(invalid.sync_cache(&response, &mut forged, &boot, 301), CacheSync::Refused));
    let _ = invalid.refuse_agent().unwrap();
    assert!(invalid.stored.journal.cache.is_none(), "bad signature invalidates offline authority");
}
#[test]
fn corrupt_snapshot_without_committed_copy_is_refused() {
    let dir=tempfile::tempdir().unwrap();let root=dir.path();let s=fixture();commit(root,&s).unwrap();
    fs::write(root.join("state.bin"),b"corrupt").unwrap();fs::write(root.join("pending.bin"),b"corrupt").unwrap();
    assert!(recover(root,&s.journal.pin).is_err());assert_eq!(fs::read(root.join("state.bin")).unwrap(),b"corrupt");
}
