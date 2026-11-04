use super::*;
use crate::{browser_broker::{self as broker, PendingHealth}, detection, shadow};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{Duration, Utc};
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;

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
            network: vec![], qualified_at: "2000-01-01T00:00:00Z".into(), asset_hosts: vec![],
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
        content_hash:crate::sha256_hex(&raw), content:STANDARD.encode(raw),
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
    (Authority { stored, storage:Storage::Memory, storage_failed:false, masked:Vec::new(), replay:Default::default() }, response, policy, boot)
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
        let (mode, reply) = authority.answer_direct_with(&request(op), &mut exchange, &boot, 400_101).unwrap();
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
    let (mode, first) = authority.answer_direct_with(&parsed, &mut exchange, &boot, 500).unwrap();
    assert_eq!(mode, "connected");
    assert_eq!(first["durable"], true);
    assert_eq!(authority.stored.queue.len(), 1);
    assert!(!authority.stored.journal.armed, "stale SYSTEM cache must not grant later grace");

    allow_delivery.set(true);
    authority.answer_direct_with(&request("browser_policy"), &mut exchange, &boot, 600).unwrap();
    assert_eq!(authority.stored.queue.len(), 1, "interactive policy lookup never drains");
    assert!(authority.drain_one_with(&mut exchange).unwrap());
    assert_eq!(authority.stored.queue.len(), 0);
    assert_eq!(delivered.borrow().len(), 1);
    let (_, replay) = authority.answer_direct_with(&parsed, &mut exchange, &boot, 700).unwrap();
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
    let (_, reply) = authority.answer_direct_with(&parsed, &mut exchange, &boot, 500).unwrap();
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
    assert!(forged.answer_direct_with(&parsed, &mut tampered, &boot, 550).is_err());
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
    assert!(stale.answer_direct_with(&parsed, &mut changed, &boot, 600).is_err());
    assert_eq!(stale.stored.queue.len(), 0);
}

#[test]
fn unreachable_agent_gets_one_monotone_grace_and_never_renews_it() {
    let (mut authority, _response, _policy, boot) = memory_authority();
    let parsed = request("browser_policy");
    let mut unavailable = |_request: &Value| -> Result<Value> { Err("agent unavailable".into()) };
    let (mode, _) = authority.answer_direct_with(&parsed, &mut unavailable, &boot, 1_000).unwrap();
    assert_eq!(mode, "grace");
    let deadline = authority.stored.journal.deadline;
    let (mode, _) = authority.answer_direct_with(&parsed, &mut unavailable, &boot, 300_999).unwrap();
    assert_eq!(mode, "grace");
    assert_eq!(authority.stored.journal.deadline, deadline);
    assert!(authority.answer_direct_with(&parsed, &mut unavailable, &boot, 301_000).is_err());
    assert_eq!(authority.stored.journal.deadline, deadline);
    assert!(!authority.stored.journal.armed);
    assert!(authority.answer_direct_with(&parsed, &mut unavailable, &boot, 301_001).is_err());
    assert_eq!(authority.stored.journal.deadline, deadline);
}

#[test]
fn explicit_or_cryptographically_invalid_agent_state_still_blocks() {
    let (mut refused, _response, _policy, boot) = memory_authority();
    let mut deny = |_request: &Value| -> Result<Value> { Ok(json!({"ok":false,"error":"operation_refused"})) };
    let (mode, reply) = refused.answer_direct_with(&request("browser_policy"), &mut deny, &boot, 200).unwrap();
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
    let (mode, _) = invalid.answer_direct_with(&request("browser_policy"), &mut forged, &boot, 300).unwrap();
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

fn draft(op: &str, text: &str, sid: &str) -> crate::browser_broker::Parsed {
    let mut request = json!({"protocol":broker::PROTOCOL,"op":op,"challenge":STANDARD.encode([13u8;32]),
        "tool":"chrome","provider":"chatgpt.com","text":text,"upload":false});
    if op == "browser_submit" {
        request["delivery_id"]=json!(uuid::Uuid::new_v4().to_string());
        request["event"]=json!({"tool":"chrome"});
    }
    broker::parse(&json!({"protocol":broker::PROTOCOL,"op":"browser_request",
        "caller":{"user":"synthetic-user","sid":sid},
        "body":STANDARD.encode(serde_json::to_vec(&request).unwrap())})).unwrap()
}

/// Inspects a draft carrying a custom-rule match, then submits `sent` from `sid`;
/// returns the masked text and the queued event, serialized.
fn masked_send(sent: Option<&str>, sid: &str) -> (String, String) {
    let (mut authority, response, policy, boot) = memory_authority();
    let mut exchange = |request: &Value| -> Result<Value> {
        match request["op"].as_str().unwrap_or("") {
            "policy_v3" => Ok(response.clone()),
            "inspect" => crate::native::inspect_authorized_request(&policy, request),
            "broker_inspect" => Ok(json!({"ok":true,"policy_content_hash":response["cache_policy_content_hash"],
                "inspection":crate::native::inspect_authorized_request(&policy, request)?})),
            "broker_prepare_event" => Ok(prepared_event(&policy, &response, request)),
            other => Err(format!("unexpected operation {other}").into()),
        }
    };
    let owner = "S-1-5-21-1-2-3-1001";
    let (_, inspected) = authority.answer_direct_with(&draft("browser_inspect", "reference ID-4242 synthetic", owner), &mut exchange, &boot, 400).unwrap();
    let masked = inspected["text"].as_str().unwrap().to_string();
    assert_ne!(masked, "reference ID-4242 synthetic", "the draft is masked: {inspected}");
    assert_eq!(inspected["labels"], json!(["custom"]));
    let sent = sent.unwrap_or(&masked);
    let (_, reply) = authority.answer_direct_with(&draft("browser_submit", sent, sid), &mut exchange, &boot, 401).unwrap();
    assert_eq!(reply["recorded"], true, "{reply}");
    assert_eq!(authority.stored.queue.pending.len(), 1);
    (masked, serde_json::to_string(&authority.stored.queue.pending[0].event).unwrap())
}

#[test]
fn masked_send_keeps_the_labels_of_the_unmasked_draft() {
    let (masked, event) = masked_send(None, "S-1-5-21-1-2-3-1001");
    let event: Value = serde_json::from_str(&event).unwrap();
    assert_eq!(event["labels"], json!(["custom"]));
    assert_eq!(event["prompt"], json!(masked));
    assert!(!event.to_string().contains("ID-4242"), "unmasked text never reaches the event: {event}");
}

#[test]
fn another_draft_or_account_cannot_borrow_masked_labels() {
    let (_, other_draft) = masked_send(Some("unrelated synthetic body"), "S-1-5-21-1-2-3-1001");
    assert!(other_draft.contains("\"labels\":[]"), "{other_draft}");
    // Same masked text, other OS account: the inspection was not its own.
    let (_, other_account) = masked_send(None, "S-1-5-21-1-2-3-1002");
    assert!(other_account.contains("\"labels\":[]"), "{other_account}");
}

/// Inspects `pasted` (a paste reviewed apart), then submits whatever `send` builds from its
/// masked text, from `sid`; returns the queued event's labels.
fn paste_then_send(pasted: &str, send: impl Fn(&str) -> String, sid: &str) -> Value {
    let (mut authority, response, policy, boot) = memory_authority();
    let mut exchange = |request: &Value| -> Result<Value> {
        match request["op"].as_str().unwrap_or("") {
            "policy_v3" => Ok(response.clone()),
            "inspect" => crate::native::inspect_authorized_request(&policy, request),
            "broker_inspect" => Ok(json!({"ok":true,"policy_content_hash":response["cache_policy_content_hash"],
                "inspection":crate::native::inspect_authorized_request(&policy, request)?})),
            "broker_prepare_event" => Ok(prepared_event(&policy, &response, request)),
            other => Err(format!("unexpected operation {other}").into()),
        }
    };
    let (_, inspected) = authority.answer_direct_with(&draft("browser_inspect", pasted, "S-1-5-21-1-2-3-1001"), &mut exchange, &boot, 400).unwrap();
    let masked = inspected["text"].as_str().unwrap().to_string();
    assert!(!masked.contains("ID-4242"), "{inspected}");
    let (_, reply) = authority.answer_direct_with(&draft("browser_submit", &send(&masked), sid), &mut exchange, &boot, 401).unwrap();
    assert_eq!(reply["recorded"], true, "{reply}");
    let event = serde_json::to_value(&authority.stored.queue.pending[0].event).unwrap();
    assert!(!event.to_string().contains("ID-4242"), "{event}");
    // Single-use: the same draft sent again borrows nothing.
    let (_, again) = authority.answer_direct_with(&draft("browser_submit", &send(&masked), sid), &mut exchange, &boot, 402).unwrap();
    assert_eq!(again["labels"], json!([]), "{again}");
    event["labels"].clone()
}

// Real campaign 0.7.10: a masked paste of three lines, laid out by the editor with a doubled break
// between paragraphs, was recorded with `labels=[]`.
#[test]
fn a_masked_paste_lends_its_labels_to_the_draft_that_carries_it() {
    const PASTE: &str = "Ligne un ID-4242\nLigne deux synthetique\nReponds juste OK.";
    let owner = "S-1-5-21-1-2-3-1001";
    assert_eq!(paste_then_send(PASTE, |m| m.replace('\n', "\n\n"), owner), json!(["custom"]));
    assert_eq!(paste_then_send(PASTE, |m| format!("Question avant\n{}\n  \nApres", m.replace('\n', "\n\n")), owner), json!(["custom"]));
    assert_eq!(paste_then_send(PASTE, |m| m.replace(' ', "\u{a0}  "), owner), json!(["custom"]), "blanks collapsed");
}

#[test]
fn a_partial_or_foreign_paste_lends_no_labels() {
    const PASTE: &str = "Ligne un ID-4242\nLigne deux synthetique\nReponds juste OK.";
    let owner = "S-1-5-21-1-2-3-1001";
    assert_eq!(paste_then_send(PASTE, |m| m.lines().take(2).collect::<Vec<_>>().join("\n"), owner), json!([]), "a line missing");
    assert_eq!(paste_then_send(PASTE, |m| m.replace("Ligne un", "Ligne une"), owner), json!([]), "a line changed");
    assert_eq!(paste_then_send(PASTE, |m| m.replace('\n', " "), owner), json!([]), "lines merged into one");
    assert_eq!(paste_then_send(PASTE, |m| m.to_string(), "S-1-5-21-1-2-3-1002"), json!([]), "another OS account");
    assert_eq!(paste_then_send(PASTE, |_| "unrelated synthetic body".into(), owner), json!([]));
}

fn memory_dlp_authority() -> (Authority,Value,shadow::ShadowPolicy,String) {
    let (mut authority,_,mut policy,boot)=memory_authority();
    policy.version=4;
    policy.config["collection"]=json!({"enabled":false,"store_content":false,"store_file_names":false});
    policy.config["dlp_legacy_disabled"]=json!(true);
    policy.config["dlp_fingerprint"]=json!("a".repeat(64));
    policy.config["dlp_context"]=json!({"device_id":"dc93a18c-a541-40e4-a39b-46892967fc54","organization_id":"5ea5b3f3-17ad-4084-b092-28a019f9e1f3","group_id":"none"});
    policy.config["dlp"]=json!({"schema_version":1,"domain":"endpoint","inspection":true,"native_inspection":false,"journal":true,"detectors":[],"rules":[{
        "id":"replacement","revision":1,"name":"Frozen replacement","mode":"active","priority":1,"condition":{"op":"contains","field":"prompt","value":"Tomate","ignore_case":false,"whole_word":false},"scope":{"op":"true"},"consequence":{"action":"replace","value":"Tomate","replacement":"Carotte","ignore_case":false,"whole_word":false},"review":true,"message":""
    }]});
    // This is a different signed policy, not a renewal of the original bytes.
    policy.revision+=1;
    policy.issued_at+=Duration::milliseconds(1);
    policy.expires_at+=Duration::milliseconds(1);
    let key=SigningKey::from_bytes(&[73;32]);let envelope=signed(&key,&policy);
    cache::prepare(&mut authority.stored.journal,&authority.stored.keys,&envelope,&live_catalog(&key)).unwrap();
    let journal=&authority.stored.journal;
    let response=json!({"ok":true,"online":true,"policy":crate::native::browser_policy(&policy),"cache_policy_hash":cache::envelope_hash(&envelope).unwrap(),"cache_authorization_generation":7,"cache_policy_content_hash":journal.policy_content_hash,"cache_catalog_content_hash":journal.catalog_content_hash,"cache_catalog_revision":journal.catalog_revision});
    (authority,response,policy,boot)
}
fn dlp_exchange(response:&Value,policy:&shadow::ShadowPolicy,request:&Value)->Result<Value> {
    match request["op"].as_str().unwrap_or("") {
        "policy_v3"=>Ok(response.clone()),
        "inspect"=>crate::native::inspect_authorized_request(policy,request),
        "broker_inspect"=>Ok(json!({"ok":true,"policy_content_hash":response["cache_policy_content_hash"],"inspection":crate::native::inspect_authorized_request(policy,request)?})),
        other=>Err(format!("unexpected fixture operation {other}").into()),
    }
}

#[test]
fn dlp_replacement_without_legacy_labels_keeps_single_use_custody_and_network_completion() {
    let (mut authority,response,policy,boot)=memory_dlp_authority();
    let mut exchange=|request:&Value|dlp_exchange(&response,&policy,request);
    let owner="S-1-5-21-1-2-3-1001";
    let (_,inspected)=authority.answer_direct_with(&draft("browser_inspect","Tomate",owner),&mut exchange,&boot,400).unwrap();
    assert_eq!(inspected["text"],"Carotte");assert_eq!(inspected["labels"],json!([]));assert!(inspected["dlp_receipt"].is_string());
    let submit=draft("browser_submit","Carotte",owner);
    let (_,sent)=authority.answer_direct_with(&submit,&mut exchange,&boot,401).unwrap();
    assert_eq!(sent["recording_required"],true);assert_eq!(sent["durable"],true);
    let event=&authority.stored.queue.pending[0].event;
    assert!(event.prompt.is_none());let trace=event.dlp.as_ref().unwrap();assert_eq!(trace.action,"transform");assert_eq!(trace.delivery,"prepared");assert_eq!(trace.decisions[0].rule_name,"Frozen replacement");
    assert!(!serde_json::to_string(event).unwrap().contains("Tomate"));
    let (_,again)=authority.answer_direct_with(&draft("browser_submit","Carotte",owner),&mut exchange,&boot,402).unwrap();
    assert_eq!(again["recording_required"],false);assert_eq!(authority.stored.queue.pending.len(),1);
    let complete=wrapped(json!({"protocol":broker::PROTOCOL,"op":"browser_complete","challenge":STANDARD.encode([11u8;32]),"tool":"chrome","delivery_id":submit.request.delivery_id,"completion":{"model":"fixture-model"}}));
    let (_,done)=authority.answer_direct_with(&complete,&mut exchange,&boot,403).unwrap();assert_eq!(done["applied"],true);
    assert_eq!(authority.stored.queue.pending[0].event.dlp.as_ref().unwrap().delivery,"observed");
}

#[test]
fn dlp_cancel_receipt_is_bound_to_the_account_and_cannot_be_replayed() {
    let (mut authority,response,policy,boot)=memory_dlp_authority();let mut exchange=|request:&Value|dlp_exchange(&response,&policy,request);
    let (_,inspected)=authority.answer_direct_with(&draft("browser_inspect","Tomate","S-1-5-21-1-2-3-1001"),&mut exchange,&boot,400).unwrap();
    let cancel=wrapped(json!({"protocol":broker::PROTOCOL,"op":"browser_cancelled","challenge":STANDARD.encode([11u8;32]),"tool":"chrome","delivery_id":inspected["dlp_receipt"]}));
    let mut foreign=cancel.clone();foreign.principal="S-1-5-21-1-2-3-1002".into();
    assert_eq!(authority.answer_direct_with(&foreign,&mut exchange,&boot,401).unwrap().1["applied"],false);
    assert_eq!(authority.answer_direct_with(&cancel,&mut exchange,&boot,402).unwrap().1["applied"],true);
    assert_eq!(authority.answer_direct_with(&cancel,&mut exchange,&boot,403).unwrap().1["applied"],false);
    assert_eq!(authority.stored.queue.pending.len(),1);
    let event=&authority.stored.queue.pending[0].event;assert!(event.prompt.is_none());assert_eq!(event.dlp.as_ref().unwrap().delivery,"cancelled");assert_eq!(event.dlp.as_ref().unwrap().decisions[0].outcome,"cancelled");
}

#[test]
fn dlp_response_inspection_never_creates_a_prompt_receipt_or_attempt() {
    let (mut authority,response,policy,boot)=memory_dlp_authority();let mut exchange=|request:&Value|dlp_exchange(&response,&policy,request);
    let mut observation=draft("browser_inspect","Tomate","S-1-5-21-1-2-3-1001");observation.request.observation=Some(true);
    let (_,reply)=authority.answer_direct_with(&observation,&mut exchange,&boot,400).unwrap();assert_eq!(reply["text"],"Carotte");
    assert!(reply["dlp_receipt"].is_null());assert!(authority.masked.is_empty());assert!(authority.stored.queue.pending.is_empty());
}

#[test]
fn generated_numbered_masks_are_reused_only_with_exact_privileged_custody() {
 for journal in [false,true] {
    let (mut authority,mut response,mut policy,boot)=memory_dlp_authority();
    policy.config["dlp"]["journal"]=json!(journal);
    policy.config["dlp"]["detectors"]=json!([{"id":"digits","name":"Digits","definition":{"kind":"regex","pattern":"[0-9]+","ignore_case":false}}]);
    policy.config["dlp"]["rules"][0]["condition"]=json!({"op":"matches","field":"prompt","detector":"digits","minimum":1});
    policy.config["dlp"]["rules"][0]["consequence"]=json!({"action":"mask","detector":"digits","label":"NUMBER"});
    response["policy"]=crate::native::browser_policy(&policy);
    let mut exchange=|request:&Value|dlp_exchange(&response,&policy,request);
    let owner="S-1-5-21-1-2-3-1001";
    let (_,checked)=authority.answer_direct_with(&draft("browser_inspect","12 34",owner),&mut exchange,&boot,400).unwrap();
    assert_eq!(checked["text"],"[NUMBER1] [NUMBER2]");
    let (_,sent)=authority.answer_direct_with(&draft("browser_submit","[NUMBER1] [NUMBER2]",owner),&mut exchange,&boot,401).unwrap();
    assert_eq!(sent["action"],"observe");assert_eq!(sent["text"],"[NUMBER1] [NUMBER2]");
    let (_,foreign)=authority.answer_direct_with(&draft("browser_submit","[NUMBER1] [NUMBER2]","S-1-5-21-1-2-3-1002"),&mut exchange,&boot,402).unwrap();
    assert_ne!(foreign["text"],"[NUMBER1] [NUMBER2]");
 }
}

#[test]
fn dlp_confirmation_is_required_single_use_context_bound_and_independent_of_journaling(){
 for journal in [false,true] {
 let (mut authority,mut response,mut policy,boot)=memory_dlp_authority();
 policy.config["dlp"]["journal"]=json!(journal);
 policy.config["dlp"]["rules"][0]["consequence"]=json!({"action":"warn"});
 policy.config["dlp"]["rules"][0]["review"]=json!(false);
 policy.config["dlp"]["rules"][0]["message"]=json!("Confirm before sending.");
 response["policy"]=crate::native::browser_policy(&policy);
 let mut exchange=|request:&Value|dlp_exchange(&response,&policy,request);
 let owner="S-1-5-21-1-2-3-1001";
 let (_,checked)=authority.answer_direct_with(&draft("browser_inspect","Tomate",owner),&mut exchange,&boot,400).unwrap();
 assert_eq!(checked["confirmation"],true);assert_eq!(checked["text"],"Tomate");
 let receipt=checked["dlp_receipt"].as_str().unwrap();
 let submit=draft("browser_submit","Tomate",owner);
 assert_eq!(authority.answer_direct_with(&submit,&mut exchange,&boot,401).unwrap().1["action"],"review");
 let confirm=wrapped(json!({"protocol":broker::PROTOCOL,"op":"browser_confirm","challenge":STANDARD.encode([11u8;32]),"tool":"chrome","delivery_id":receipt}));
 let mut foreign=confirm.clone();foreign.principal="S-1-5-21-1-2-3-1002".into();
 assert_eq!(authority.answer_direct_with(&foreign,&mut exchange,&boot,402).unwrap().1["applied"],false);
 assert_eq!(authority.answer_direct_with(&confirm,&mut exchange,&boot,403).unwrap().1["applied"],true);
 assert_eq!(authority.answer_direct_with(&confirm,&mut exchange,&boot,404).unwrap().1["applied"],false);
 let mut approved=submit.clone();approved.request.approval_id=Some(receipt.into());
 let (_,sent)=authority.answer_direct_with(&approved,&mut exchange,&boot,405).unwrap();assert_eq!(sent["action"],"observe");
 assert_eq!(authority.answer_direct_with(&approved,&mut exchange,&boot,406).unwrap().1["action"],"review");
 assert_eq!(authority.stored.queue.pending.len(),if journal{1}else{0});
 if journal{let trace=authority.stored.queue.pending[0].event.dlp.as_ref().unwrap();assert_eq!(trace.action,"observe");assert_eq!(trace.decisions[0].consequence,"warn");}
 }
}

#[test]
fn dlp_confirmation_requires_the_current_projected_fingerprint_and_browser() {
 let (mut authority,mut response,mut policy,boot)=memory_dlp_authority();
 policy.config["dlp"]["rules"][0]["consequence"]=json!({"action":"warn"});
 policy.config["dlp"]["rules"][0]["review"]=json!(false);
 policy.config["dlp"]["rules"][0]["message"]=json!("Confirm before sending.");
 response["policy"]=crate::native::browser_policy(&policy);
 let owner="S-1-5-21-1-2-3-1001";
 let (_,checked)=authority.answer_direct_with(&draft("browser_inspect","Tomate",owner),&mut |r|dlp_exchange(&response,&policy,r),&boot,400).unwrap();
 let receipt=checked["dlp_receipt"].as_str().unwrap();
 let confirm=wrapped(json!({"protocol":broker::PROTOCOL,"op":"browser_confirm","challenge":STANDARD.encode([11u8;32]),"tool":"chrome","delivery_id":receipt}));
 let mut foreign=confirm.clone();foreign.request.tool="edge".into();
 assert_eq!(authority.answer_direct_with(&foreign,&mut |r|dlp_exchange(&response,&policy,r),&boot,401).unwrap().1["applied"],false);
 let original=response["policy"]["config"]["dlp_control"]["fingerprint"].clone();
 for fingerprint in [Value::Null,json!("b".repeat(64))] {
  response["policy"]["config"]["dlp_control"]["fingerprint"]=fingerprint;
  assert_eq!(authority.answer_direct_with(&confirm,&mut |r|dlp_exchange(&response,&policy,r),&boot,402).unwrap().1["applied"],false);
 }
 response["policy"]["config"]["dlp_control"]["fingerprint"]=original;
 assert_eq!(authority.answer_direct_with(&confirm,&mut |r|dlp_exchange(&response,&policy,r),&boot,403).unwrap().1["applied"],true);
 assert_eq!(authority.answer_direct_with(&confirm,&mut |r|dlp_exchange(&response,&policy,r),&boot,404).unwrap().1["applied"],false);
}
#[test]
fn cached_authorized_inspection_cannot_recover_a_later_observed_outage() {
    use std::sync::{Arc, Mutex, mpsc}; use std::thread;
    let (target, response, policy, boot) = memory_authority();
    let slot = Arc::new(Mutex::new(Some(target))); let worker_slot = slot.clone();
    let worker_boot = boot.clone(); let parsed = request("browser_inspect");
    let (started, observed) = mpsc::channel(); let (release, wait) = mpsc::channel();
    let worker = thread::spawn(move || crate::cache_replay::drive(&worker_slot,
        &super::authority_replay::Operation::Browser { parsed, boot:worker_boot, deadline:Instant::now()+std::time::Duration::from_secs(5) },
        Instant::now()+std::time::Duration::from_secs(5), || unreachable!(), |request, _| {
            if request["op"] == "policy_v3" { return crate::cache_replay::Reply::Value(response.clone()); }
            assert_eq!(request["op"], "inspect");
            started.send(()).unwrap(); wait.recv().unwrap();
            crate::cache_replay::Reply::Value(crate::native::inspect_authorized_request(&policy,request).unwrap())
        }));
    observed.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
    crate::cache_replay::drive(&slot,
        &super::authority_replay::Operation::Browser { parsed:request("browser_policy"), boot, deadline:Instant::now()+std::time::Duration::from_secs(5) },
        Instant::now()+std::time::Duration::from_secs(5), || unreachable!(), |_, _| crate::cache_replay::Reply::Unreachable).unwrap();
    let outage_deadline = slot.lock().unwrap().as_ref().unwrap().stored.journal.deadline;
    assert!(outage_deadline.is_some());
    release.send(()).unwrap(); assert!(worker.join().unwrap().is_err());
    assert_eq!(slot.lock().unwrap().as_ref().unwrap().stored.journal.deadline, outage_deadline);
}

#[test]
fn every_local_event_preparation_branch_suspends_outside_authority() {
    use std::sync::{Arc, Mutex, mpsc}; use std::thread;
    let owner = "S-1-5-21-1-2-3-1001";
    // Offline event, offline submit, connected trace submit, blocked inspection,
    // and cancelled receipt all reach the same real out-of-lock local work path.
    for case in 0..5 {
        let (mut target, mut response, mut policy, boot) = if case < 2 { memory_authority() } else { memory_dlp_authority() };
        if case == 3 {
            policy.config["dlp"]["rules"][0]["consequence"] = json!({"action":"block"});
            // A block has no interactive transformation to review.
            policy.config["dlp"]["rules"][0]["review"] = json!(false);
            policy.revision += 1; policy.issued_at += Duration::milliseconds(1); policy.expires_at += Duration::milliseconds(1);
            let key = SigningKey::from_bytes(&[73;32]); let envelope = signed(&key,&policy);
            cache::prepare(&mut target.stored.journal,&target.stored.keys,&envelope,&live_catalog(&key)).unwrap();
            response["policy"] = crate::native::browser_policy(&policy);
            response["cache_policy_hash"] = json!(cache::envelope_hash(&envelope).unwrap());
            response["cache_policy_content_hash"] = json!(target.stored.journal.policy_content_hash);
        }
        let mut receipt = None;
        if matches!(case, 2 | 4) {
            let mut exchange = |request:&Value| dlp_exchange(&response,&policy,request);
            let (_, inspected) = target.answer_direct_with(&draft("browser_inspect","Tomate",owner), &mut exchange, &boot, 400).unwrap();
            receipt = inspected["dlp_receipt"].as_str().map(str::to_owned);
            assert!(receipt.is_some());
        }
        let parsed = match case {
            0 => event_request(uuid::Uuid::new_v4()),
            1 => draft("browser_submit","synthetic plain",owner),
            2 => draft("browser_submit","Carotte",owner),
            3 => draft("browser_inspect","Tomate",owner),
            _ => wrapped(json!({"protocol":broker::PROTOCOL,"op":"browser_cancelled",
                "challenge":STANDARD.encode([11u8;32]),"tool":"chrome","delivery_id":receipt.unwrap()})),
        };
        let slot = Arc::new(Mutex::new(Some(target))); let worker_slot = slot.clone();
        let (started, observed) = mpsc::channel(); let (release, wait) = mpsc::channel();
        let worker = thread::spawn(move || crate::cache_replay::drive(&worker_slot,
            &super::authority_replay::Operation::Browser { parsed, boot, deadline:Instant::now()+std::time::Duration::from_secs(5) },
            Instant::now()+std::time::Duration::from_secs(5), || unreachable!(), |request, _| {
                if request["op"] == "cache_local_event" {
                    started.send(()).unwrap(); wait.recv().unwrap();
                }
                if let Some(result) = crate::cache_replay_authority::local_work(request) {
                    return crate::cache_replay::Reply::Value(result.unwrap());
                }
                if request["op"] == "policy_v3" && case < 2 { return crate::cache_replay::Reply::Unreachable; }
                crate::cache_replay::Reply::Value(dlp_exchange(&response,&policy,request).unwrap())
            }));
        observed.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
        { let locked = slot.try_lock().expect("local event preparation held the Authority mutex");
          assert!(locked.as_ref().unwrap().stored.queue.pending.is_empty()); }
        release.send(()).unwrap(); worker.join().unwrap().unwrap();
        assert_eq!(slot.lock().unwrap().as_ref().unwrap().stored.queue.pending.len(), 1, "branch {case} lost custody");
    }
}

fn replay_signed_body(reply:&Value)->Value{
    serde_json::from_slice(&STANDARD.decode(reply["signed"]["payload"].as_str().unwrap()).unwrap()).unwrap()
}

#[test]
fn unattributed_legacy_completion_is_refused_before_any_remote_forwarding(){
    use std::sync::{Arc,Mutex};
    let(mut target,response,policy,boot)=memory_authority();let delivery=uuid::Uuid::new_v4();
    let id=target.stored.queue.admit(&target.stored.journal,&policy,&event_request(delivery)).unwrap();
    target.stored.queue.pending[0].principal.clear();
    let slot=Mutex::new(Some(target));let ownership=Arc::new(crate::cache_replay::Ownership::default());
    let parsed=wrapped(json!({"protocol":broker::PROTOCOL,"op":"browser_complete","challenge":STANDARD.encode([11u8;32]),
        "tool":"chrome","delivery_id":delivery,"completion":{"model":"synthetic-legacy-model"}}));
    let deadline=Instant::now()+std::time::Duration::from_secs(5);
    let reply=super::authority_replay::run_gated(&slot,&ownership,super::authority_replay::Operation::Browser{parsed,boot,deadline},deadline,
        ||unreachable!(),|request,_|{assert_eq!(request["op"],"policy_v3");crate::cache_replay::Reply::Value(response.clone())}).unwrap();
    assert_eq!(replay_signed_body(&reply)["reply"]["applied"],false);
    let locked=slot.lock().unwrap();let row=&locked.as_ref().unwrap().stored.queue.pending[0];
    assert_eq!(row.event.id,id);assert!(row.event.model.is_none());
}

#[test]
fn owned_handoff_reconciles_ack_without_rearming_and_exposes_real_receiver_refusal(){
    use std::sync::{Arc,Mutex,mpsc};use std::thread;
    for refuse in [false,true]{
        let(mut target,_,policy,boot)=memory_authority();let delivery=uuid::Uuid::new_v4();
        let a=event_request(delivery);let id=target.stored.queue.admit(&target.stored.journal,&policy,&a).unwrap();
        let mut b=event_request(uuid::Uuid::new_v4());b.principal="S-1-5-21-1-2-3-1002".into();
        target.stored.queue.admit(&target.stored.journal,&policy,&b).unwrap();
        let home=tempfile::tempdir().unwrap();let remote=home.path().to_path_buf();
        let signing=SigningKey::from_bytes(&[73;32]);
        let state=crate::State{public_key:STANDARD.encode(signing.verifying_key().as_bytes()),shadow_revision:1,
            shadow_policy:Some(live_policy(&signing,1)),detection:crate::detection::Cache{
                revision:target.stored.journal.catalog_revision,content_hash:target.stored.journal.catalog_content_hash.clone(),..Default::default()},..Default::default()};
        {let store=crate::Store::open(&remote).unwrap();store.save(&state).unwrap();}
        let slot=Arc::new(Mutex::new(Some(target)));let ownership=Arc::new(crate::cache_replay::Ownership::default());
        let worker_slot=slot.clone();let worker_ownership=ownership.clone();let worker_remote=remote.clone();let worker_boot=boot.clone();
        let(ack_ready,ack_seen)=mpsc::channel();let(release_ack,wait_ack)=mpsc::channel();
        let maintenance=thread::spawn(move||{
            let deadline=Instant::now()+std::time::Duration::from_secs(15);
            super::authority_replay::run_gated(&worker_slot,&worker_ownership,
                super::authority_replay::Operation::Maintenance{boot:worker_boot,owner:None},deadline,||unreachable!(),|request,_|{
                    let mut packet=request.clone();packet["caller"]=json!({"system":true});
                    let reply=crate::native::native_message(&worker_remote,packet).unwrap();
                    if request["op"]=="broker_event"{assert_eq!(reply["durable"],true);ack_ready.send(()).unwrap();wait_ack.recv().unwrap();}
                    crate::cache_replay::Reply::Value(reply)
                })
        });
        ack_seen.recv_timeout(std::time::Duration::from_secs(3)).unwrap();
        let completion_slot=slot.clone();let completion_ownership=ownership.clone();let completion_remote=remote.clone();let completion_boot=boot.clone();
        let(probe_ready,probe_seen)=mpsc::channel();let(release_probe,wait_probe)=mpsc::channel();let(completed,completion_result)=mpsc::channel();
        let completion=thread::spawn(move||{
            let parsed=wrapped(json!({"protocol":broker::PROTOCOL,"op":"browser_complete","challenge":STANDARD.encode([11u8;32]),
                "tool":"chrome","delivery_id":delivery,"completion":{"decision_reason":"control_unavailable","platform_id":"chatgpt"}}));
            let deadline=Instant::now()+std::time::Duration::from_secs(15);
            let result=super::authority_replay::run_gated(&completion_slot,&completion_ownership,
                super::authority_replay::Operation::Browser{parsed,boot:completion_boot,deadline},deadline,||unreachable!(),|request,_|{
                    if request["op"]=="policy_v3"{probe_ready.send(()).unwrap();wait_probe.recv().unwrap();}
                    let mut packet=request.clone();packet["caller"]=json!({"system":true});
                    crate::cache_replay::Reply::Value(crate::native::native_message(&completion_remote,packet).unwrap())
                });completed.send(result).unwrap();
        });
        assert!(ownership.wait_for_waiter(&a.principal,Instant::now()+std::time::Duration::from_secs(3)));
        assert!(completion_result.try_recv().is_err());
        {let locked=slot.try_lock().unwrap();assert_eq!(locked.as_ref().unwrap().stored.queue.pending[0].event.action,"observed");}
        let mut other=request("browser_policy");other.principal=b.principal.clone();let deadline=Instant::now()+std::time::Duration::from_secs(5);
        let b_reply=super::authority_replay::run_gated(&slot,&ownership,super::authority_replay::Operation::Browser{parsed:other,boot,deadline},deadline,
            ||unreachable!(),|_,_|if refuse{crate::cache_replay::Reply::Value(json!({"ok":false}))}else{crate::cache_replay::Reply::Unreachable}).unwrap();
        assert_eq!(replay_signed_body(&b_reply)["mode"],if refuse{"blocked"}else{"grace"});
        let before={let locked=slot.lock().unwrap();let journal=&locked.as_ref().unwrap().stored.journal;(journal.generation,journal.deadline,journal.armed,journal.cache.is_some())};
        // Model an accepted server flush using the fixture's actual durable store,
        // without any network. The real broker_complete receiver must say false.
        {let store=crate::Store::open(&remote).unwrap();let mut state=store.load().unwrap();assert!(state.shadow_queue.iter().any(|event|event.id==id));state.shadow_queue.clear();store.save(&state).unwrap();}
        release_ack.send(()).unwrap();maintenance.join().unwrap().unwrap();
        probe_seen.recv_timeout(std::time::Duration::from_secs(3)).unwrap();
        {let locked=slot.lock().unwrap();let target=locked.as_ref().unwrap();let journal=&target.stored.journal;
            assert_eq!((journal.generation,journal.deadline,journal.armed,journal.cache.is_some()),before);
            assert_eq!(target.stored.queue.pending.len(),1);assert_eq!(target.stored.queue.pending[0].principal,b.principal);
            if refuse{assert!(target.stored.queue.pending[0].event.prompt.is_none());}}
        release_probe.send(()).unwrap();let reply=completion_result.recv_timeout(std::time::Duration::from_secs(5)).unwrap().unwrap();completion.join().unwrap();
        assert_eq!(replay_signed_body(&reply)["reply"]["applied"],false);
        {let store=crate::Store::open(&remote).unwrap();let state=store.load().unwrap();assert!(state.shadow_completions.is_empty());}
    }
}

#[test]
fn maintenance_with_empty_snapshot_never_transfers_a_new_unowned_row(){
    use std::sync::{Arc,Mutex,mpsc};use std::thread;
    let(target,response,policy,boot)=memory_authority();let slot=Arc::new(Mutex::new(Some(target)));
    let ownership=Arc::new(crate::cache_replay::Ownership::default());let worker_slot=slot.clone();let worker_ownership=ownership.clone();
    let(started,seen)=mpsc::channel();let(release,wait)=mpsc::channel();
    let worker=thread::spawn(move||super::authority_replay::run_gated(&worker_slot,&worker_ownership,
        super::authority_replay::Operation::Maintenance{boot,owner:None},Instant::now()+std::time::Duration::from_secs(5),||unreachable!(),|request,_|{
            assert_eq!(request["op"],"policy_v3");started.send(()).unwrap();wait.recv().unwrap();crate::cache_replay::Reply::Value(response.clone())
        }));
    seen.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
    let id={let mut locked=slot.lock().unwrap();let target=locked.as_mut().unwrap();
        let id=target.stored.queue.admit(&target.stored.journal,&policy,&event_request(uuid::Uuid::new_v4())).unwrap();target.save().unwrap();id};
    release.send(()).unwrap();worker.join().unwrap().unwrap();
    let locked=slot.lock().unwrap();let target=locked.as_ref().unwrap();assert_eq!(target.stored.queue.pending.len(),1);assert_eq!(target.stored.queue.pending[0].event.id,id);
}

#[test]
fn failed_marker_persistence_prevents_every_handoff_call(){
    use std::sync::{Arc,Mutex};use std::cell::Cell;
    let(mut target,response,policy,boot)=memory_authority();
    target.stored.queue.admit(&target.stored.journal,&policy,&event_request(uuid::Uuid::new_v4())).unwrap();
    target.storage=Storage::FaultedMemory;
    let slot=Mutex::new(Some(target));let ownership=Arc::new(crate::cache_replay::Ownership::default());let handoffs=Cell::new(0);
    let result=super::authority_replay::run_gated(&slot,&ownership,super::authority_replay::Operation::Maintenance{boot,owner:None},
        Instant::now()+std::time::Duration::from_secs(5),||unreachable!(),|request,_|{
            if request["op"]=="broker_event"{handoffs.set(handoffs.get()+1);}
            assert_eq!(request["op"],"policy_v3");crate::cache_replay::Reply::Value(response.clone())
        });
    assert!(result.is_err());assert_eq!(handoffs.get(),0);
    let locked=slot.lock().unwrap();let target=locked.as_ref().unwrap();assert!(target.stored.queue.pending[0].transfer_started);assert!(target.storage_failed);
}

#[test]
fn lost_ack_restart_never_promises_local_or_premature_remote_completion(){
    use std::sync::{Arc,Mutex};
    for accepted in [false,true]{
        let(mut target,_,policy,boot)=memory_authority();let delivery=uuid::Uuid::new_v4();
        let id=target.stored.queue.admit(&target.stored.journal,&policy,&event_request(delivery)).unwrap();
        let home=tempfile::tempdir().unwrap();let remote=home.path().to_path_buf();let key=SigningKey::from_bytes(&[73;32]);
        let state=crate::State{public_key:STANDARD.encode(key.verifying_key().as_bytes()),shadow_revision:1,shadow_policy:Some(live_policy(&key,1)),
            detection:crate::detection::Cache{revision:target.stored.journal.catalog_revision,content_hash:target.stored.journal.catalog_content_hash.clone(),..Default::default()},..Default::default()};
        {let store=crate::Store::open(&remote).unwrap();store.save(&state).unwrap();}
        let before_offer=encrypted(&target.stored);
        let slot=Mutex::new(Some(target));let ownership=Arc::new(crate::cache_replay::Ownership::default());
        let result=super::authority_replay::run_gated(&slot,&ownership,super::authority_replay::Operation::Maintenance{boot:boot.clone(),owner:None},
            Instant::now()+std::time::Duration::from_secs(5),||unreachable!(),|request,_|{
                if request["op"]=="broker_event"{
                    assert!(slot.try_lock().unwrap().as_ref().unwrap().stored.queue.pending[0].transfer_started);
                    if accepted{let mut packet=request.clone();packet["caller"]=json!({"system":true});let reply=crate::native::native_message(&remote,packet).unwrap();assert_eq!(reply["durable"],true);}
                    return crate::cache_replay::Reply::Unreachable;
                }
                assert_eq!(request["op"],"policy_v3");let mut packet=request.clone();packet["caller"]=json!({"system":true});
                crate::cache_replay::Reply::Value(crate::native::native_message(&remote,packet).unwrap())
            });
        assert!(result.is_err());
        {let mut locked=slot.lock().unwrap();let previous=locked.take().unwrap();assert!(previous.stored.queue.pending[0].transfer_started);
            let committed=epoch(&previous.stored);let pin=previous.stored.journal.pin.clone();let bytes=encrypted(&previous.stored);
            assert!(decode_snapshot(&before_offer,&pin,&committed).is_err(),"an older snapshot lost the durable marker");
            let restored=decode_snapshot(&bytes,&pin,&committed).unwrap();assert!(restored.queue.pending[0].transfer_started);
            *locked=Some(Authority{stored:restored,storage:Storage::Memory,storage_failed:false,masked:Vec::new(),replay:Default::default()});}
        if accepted{let store=crate::Store::open(&remote).unwrap();let mut state=store.load().unwrap();assert!(state.shadow_queue.iter().any(|event|event.id==id));state.shadow_queue.clear();store.save(&state).unwrap();}
        for fields in [json!({"decision_reason":"control_unavailable","platform_id":"chatgpt"}),json!({"model":"synthetic-completion"})]{
            let parsed=wrapped(json!({"protocol":broker::PROTOCOL,"op":"browser_complete","challenge":STANDARD.encode([11u8;32]),"tool":"chrome","delivery_id":delivery,"completion":fields}));
            let deadline=Instant::now()+std::time::Duration::from_secs(5);
            let reply=super::authority_replay::run_gated(&slot,&ownership,super::authority_replay::Operation::Browser{parsed,boot:boot.clone(),deadline},deadline,
                ||unreachable!(),|request,_|{assert_eq!(request["op"],"policy_v3","a marked completion was forwarded prematurely");
                    let mut packet=request.clone();packet["caller"]=json!({"system":true});crate::cache_replay::Reply::Value(crate::native::native_message(&remote,packet).unwrap())}).unwrap();
            assert_eq!(replay_signed_body(&reply)["reply"]["applied"],false);
        }
        {let locked=slot.lock().unwrap();let row=&locked.as_ref().unwrap().stored.queue.pending[0];assert!(row.transfer_started);assert!(row.event.model.is_none());assert_eq!(row.event.action,"observed");}
        {let store=crate::Store::open(&remote).unwrap();assert!(store.load().unwrap().shadow_completions.is_empty());}
        super::authority_replay::run_gated(&slot,&ownership,super::authority_replay::Operation::Maintenance{boot,owner:None},
            Instant::now()+std::time::Duration::from_secs(5),||unreachable!(),|request,_|{
                let mut packet=request.clone();packet["caller"]=json!({"system":true});crate::cache_replay::Reply::Value(crate::native::native_message(&remote,packet).unwrap())}).unwrap();
        assert!(slot.lock().unwrap().as_ref().unwrap().stored.queue.pending.is_empty());
    }
}

#[test]
fn inherited_false_rows_are_sealed_before_exposing_completion_and_failure_blocks_open(){
    let(mut target,_,policy,_)=memory_authority();target.stored.queue.admit(&target.stored.journal,&policy,&event_request(uuid::Uuid::new_v4())).unwrap();
    assert!(!target.stored.queue.pending[0].transfer_started);target.seal_inherited_transfers().unwrap();assert!(target.stored.queue.pending[0].transfer_started);
    target.storage=Storage::FaultedMemory;target.seal_inherited_transfers().unwrap();assert!(!target.storage_failed,"already sealed reload attempted another save");
    let(mut failed,_,policy,_)=memory_authority();failed.stored.queue.admit(&failed.stored.journal,&policy,&event_request(uuid::Uuid::new_v4())).unwrap();
    failed.storage=Storage::FaultedMemory;assert!(failed.seal_inherited_transfers().is_err());assert!(failed.stored.queue.pending[0].transfer_started);assert!(failed.storage_failed);
}

#[test]
fn full_valid_data_budget_can_persist_marker_and_drain_without_metadata_headroom(){
    use std::sync::{Arc,Mutex};
    let(mut target,response,policy,boot)=memory_authority();
    for index in 0..128{
        let mut parsed=event_request(uuid::Uuid::new_v4());parsed.principal=format!("S-1-5-21-{}",1001+index/32);
        target.stored.queue.admit(&target.stored.journal,&policy,&parsed).unwrap();
    }
    for row in &mut target.stored.queue.pending{row.event.prompt=Some(String::new());row.event.characters=65536;}
    let spare=broker::MAX_BYTES-shadow::serialized_size(&target.stored.queue).unwrap();let part=spare/128;let rest=spare%128;
    assert!(part+1<=65536);
    for(index,row)in target.stored.queue.pending.iter_mut().enumerate(){let length=part+usize::from(index<rest);row.event.prompt=Some("x".repeat(length));row.event.characters=length.try_into().unwrap();}
    assert_eq!(shadow::serialized_size(&target.stored.queue).unwrap(),broker::MAX_BYTES);target.stored.queue.validate().unwrap();
    let id=target.stored.queue.pending[0].event.id;let slot=Mutex::new(Some(target));let ownership=Arc::new(crate::cache_replay::Ownership::default());
    super::authority_replay::run_gated(&slot,&ownership,super::authority_replay::Operation::Maintenance{boot,owner:None},
        Instant::now()+std::time::Duration::from_secs(10),||unreachable!(),|request,_|{
            if request["op"]=="broker_event"{let locked=slot.try_lock().unwrap();let target=locked.as_ref().unwrap();
                assert!(target.stored.queue.pending[0].transfer_started);assert_eq!(shadow::serialized_size(&target.stored.queue).unwrap(),broker::MAX_BYTES+24);
                return crate::cache_replay::Reply::Value(json!({"ok":true,"durable":true,"id":id}));}
            assert_eq!(request["op"],"policy_v3");crate::cache_replay::Reply::Value(response.clone())
        }).unwrap();
    assert_eq!(slot.lock().unwrap().as_ref().unwrap().stored.queue.pending.len(),127);
}

#[test]
fn local_pending_quota_refusal_never_forwards_before_handoff_and_absent_row_still_forwards(){
    use std::sync::{Arc,Mutex};use std::cell::Cell;
    let(mut target,_,policy,boot)=memory_authority();let delivery=uuid::Uuid::new_v4();
    // Keep each prompt within the receiver limit while saturating total custody.
    for index in 0..256{
        let mut parsed=event_request(if index==0{delivery}else{uuid::Uuid::new_v4()});
        parsed.principal=format!("S-1-5-21-1-2-3-{}",1001+index/64);
        target.stored.queue.admit(&target.stored.journal,&policy,&parsed).unwrap();
    }
    for row in &mut target.stored.queue.pending{row.event.prompt=Some(String::new());row.event.characters=32768;}
    let spare=broker::MAX_BYTES-shadow::serialized_size(&target.stored.queue).unwrap();let part=spare/256;let rest=spare%256;assert!(part+1<=32768);
    for(index,row)in target.stored.queue.pending.iter_mut().enumerate(){let length=part+usize::from(index<rest);row.event.prompt=Some("x".repeat(length));row.event.characters=length.try_into().unwrap();}
    assert_eq!(shadow::serialized_size(&target.stored.queue).unwrap(),broker::MAX_BYTES);target.stored.queue.validate().unwrap();
    let id=target.stored.queue.pending[0].event.id;assert!(!target.stored.queue.pending[0].transfer_started);
    let fields=json!({"model":"synthetic-quota-growth"});
    let mut refused=target.stored.queue.clone();assert!(!refused.complete(&shadow::ShadowCompletion::parse_for(id,&fields).unwrap()));
    let before=cache::hash(&serde_json::to_vec(&target.stored.queue).unwrap());
    assert_eq!(cache::hash(&serde_json::to_vec(&refused).unwrap()),before);
    let home=tempfile::tempdir().unwrap();let key=SigningKey::from_bytes(&[73;32]);
    let state=crate::State{public_key:STANDARD.encode(key.verifying_key().as_bytes()),shadow_revision:1,shadow_policy:Some(live_policy(&key,1)),
        detection:crate::detection::Cache{revision:target.stored.journal.catalog_revision,content_hash:target.stored.journal.catalog_content_hash.clone(),..Default::default()},..Default::default()};
    {let store=crate::Store::open(home.path()).unwrap();store.save(&state).unwrap();}
    let slot=Mutex::new(Some(target));let ownership=Arc::new(crate::cache_replay::Ownership::default());
    let complete=|fields:Value|wrapped(json!({"protocol":broker::PROTOCOL,"op":"browser_complete","challenge":STANDARD.encode([11u8;32]),"tool":"chrome","delivery_id":delivery,"completion":fields}));
    let forwardings=Cell::new(0);
    let no_forward=|request:&Value,_:Instant|{
        if request["op"]=="broker_complete"{forwardings.set(forwardings.get()+1);}
        assert_eq!(request["op"],"policy_v3","a completion was forwarded before its event left local custody");
        let mut packet=request.clone();packet["caller"]=json!({"system":true});
        crate::cache_replay::Reply::Value(crate::native::native_message(home.path(),packet).unwrap())
    };
    let parsed=complete(fields.clone());let deadline=Instant::now()+std::time::Duration::from_secs(10);
    let reply=super::authority_replay::run_gated(&slot,&ownership,super::authority_replay::Operation::Browser{parsed:parsed.clone(),boot:boot.clone(),deadline},deadline,
        ||unreachable!(),&no_forward).unwrap();
    assert_eq!(replay_signed_body(&reply)["reply"]["applied"],false);assert_eq!(forwardings.get(),0);
    {let locked=slot.lock().unwrap();let target=locked.as_ref().unwrap();assert_eq!(cache::hash(&serde_json::to_vec(&target.stored.queue).unwrap()),before);
        assert_eq!(target.stored.queue.completed(&target.stored.journal,&parsed).unwrap(),Some(id));assert!(!target.stored.queue.pending[0].transfer_started);}
    {let store=crate::Store::open(home.path()).unwrap();let state=store.load().unwrap();assert!(state.shadow_queue.is_empty());assert!(state.shadow_completions.is_empty());}
    // Capacity recovery permits a truthful local retry, still without forwarding.
    {let mut locked=slot.lock().unwrap();let target=locked.as_mut().unwrap();target.stored.queue.pending.retain(|pending|pending.event.id==id);target.save().unwrap();}
    let deadline=Instant::now()+std::time::Duration::from_secs(10);
    let reply=super::authority_replay::run_gated(&slot,&ownership,super::authority_replay::Operation::Browser{parsed,boot:boot.clone(),deadline},deadline,
        ||unreachable!(),&no_forward).unwrap();
    assert_eq!(replay_signed_body(&reply)["reply"]["applied"],true);assert_eq!(forwardings.get(),0);
    // Model completed custody transfer using the real native receiver, then remove
    // the local pending row while preserving its receipt. Remote fallback is valid.
    {let mut locked=slot.lock().unwrap();let target=locked.as_mut().unwrap();let pending=&target.stored.queue.pending[0];
        let packet=json!({"op":"broker_event","caller":{"system":true},"installation":target.stored.journal.pin.installation,
            "sequence":pending.sequence,"event":pending.event,"quota_principal":pending.principal});
        let ack=crate::native::native_message(home.path(),packet).unwrap();assert_eq!(ack["durable"],true);assert_eq!(ack["id"],json!(id));
        {let store=crate::Store::open(home.path()).unwrap();let state=store.load().unwrap();assert!(state.shadow_queue.iter().any(|event|event.id==id),"handoff must retain the valid event before remote completion");}
        target.stored.queue.pending.clear();target.save().unwrap();}
    let parsed=complete(json!({"body_bytes":42}));let deadline=Instant::now()+std::time::Duration::from_secs(10);
    let reply=super::authority_replay::run_gated(&slot,&ownership,super::authority_replay::Operation::Browser{parsed,boot,deadline},deadline,
        ||unreachable!(),|request,_|{if request["op"]=="broker_complete"{forwardings.set(forwardings.get()+1);}
            let mut packet=request.clone();packet["caller"]=json!({"system":true});crate::cache_replay::Reply::Value(crate::native::native_message(home.path(),packet).unwrap())}).unwrap();
    assert_eq!(replay_signed_body(&reply)["reply"]["applied"],true);assert_eq!(forwardings.get(),1);
    {let store=crate::Store::open(home.path()).unwrap();let state=store.load().unwrap();assert_eq!(state.shadow_queue.iter().find(|event|event.id==id).unwrap().body_bytes,Some(42));}
}
