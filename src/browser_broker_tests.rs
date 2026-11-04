// Intended to be included as `#[cfg(test)] mod browser_broker_tests;` by the
// endpoint crate.  It deliberately exercises the real sealed cache and signed
// protocol values; it does not mock cryptography or queue accounting.
use crate::{Envelope, State, browser_broker as broker, browser_cache as cache, detection, shadow};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{Duration, Utc};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

use serde::Serialize;
use serde_json::{Value, json};


fn authority() -> SigningKey {
    let mut seed = [0u8; 32];
    crate::fill_random(&mut seed);
    SigningKey::from_bytes(&seed)
}

fn signed<T: Serialize>(key: &SigningKey, value: &T) -> Envelope {
    use ed25519_dalek::Signer;
    let bytes = serde_json::to_vec(value).unwrap();
    Envelope {
        payload: STANDARD.encode(&bytes),
        signature: STANDARD.encode(key.sign(&bytes).to_bytes()),
    }
}

fn policy(key: &SigningKey) -> Envelope {
    let now = Utc::now();
    signed(
        key,
        &json!({
            "version": 3, "revision": 1, "issued_at": now, "expires_at": now + Duration::minutes(10),
            "capabilities": [],
            "config": {
                "collection": {"enabled": true, "store_content": true, "store_file_names": true},
                "services": [{"domains": ["chatgpt.com"], "enabled": true, "mode": "observe"}],
                "privacy": {"enabled": false}, "protection": {}
            }
        }),
    )
}

fn catalog(key: &SigningKey) -> Envelope {
    let now = Utc::now();
    let content = detection::Content {
        providers: vec![detection::Provider {
            id: "chatgpt".into(),
            label: "Test provider".into(),
            domains: vec!["chatgpt.com".into()],
            aliases: vec![],
            conversation_path: String::new(),
            conversation_segment: 0,
            conversation_paths: vec![],
            dom: detection::Dom {
                editor: String::new(),
                send: String::new(),
                response: String::new(),
            },
            network: vec![],
            qualified_at: now.to_rfc3339(),
            asset_hosts: vec![],
        }],
        native_tools: vec![],
        heuristics: detection::Heuristics {
            keys: vec![],
            mime_types: vec![],
        },
        known_platforms: vec![],
    };
    let raw = serde_json::to_vec(&content).unwrap();
    let header = detection::Header {
        kind: "detection_catalog".into(),
        schema: 1,
        revision: 1,
        issued_at: now,
        expires_at: now + Duration::minutes(10),
        min_engine: detection::Engines {
            extension: detection::ENGINE_VERSION.into(),
            bridge: detection::ENGINE_VERSION.into(),
        },
        content_hash: crate::sha256_hex(&raw),
        content: STANDARD.encode(raw),
    };
    signed(key, &header)
}

fn prepared() -> (cache::Journal, cache::Keys, Envelope, SigningKey) {
    let policy_key = authority();
    let keys = cache::Keys::generate();
    let pin = cache::Pin {
        installation: uuid::Uuid::new_v4().to_string(),
        edition: "community".into(),
        origin: "https://example.test".into(),
        organization_anchor: STANDARD.encode(policy_key.verifying_key().as_bytes()),
        signing_key: keys.public(),
    };
    let mut journal = cache::Journal::new(pin).unwrap();
    let policy = policy(&policy_key);
    cache::prepare(&mut journal, &keys, &policy, &catalog(&policy_key)).unwrap();
    (journal, keys, policy, policy_key)
}

fn wrapped(request: Value) -> Value {
    json!({"protocol": broker::PROTOCOL, "op": "browser_request", "caller": {"user": "unit-user","sid":"S-1-5-21-1-2-3-1001"},
        "body": STANDARD.encode(serde_json::to_vec(&request).unwrap())})
}

fn event_request(delivery_id: uuid::Uuid, characters: u32) -> Value {
    wrapped(json!({"protocol":broker::PROTOCOL,"op":"browser_event",
        "challenge":STANDARD.encode([7u8;32]),"tool":"chrome","delivery_id":delivery_id.to_string(),
        "event":{"kind":"prompt","provider":"chatgpt.com","source":"browser","tool":"chrome",
            "action":"observed","characters":characters,"labels":[],"prompt":"synthetic local text"}}))
}

#[test]
fn encrypted_cache_rejects_signature_nonce_pin_and_generation_tampering() {
    let (journal, keys, mut policy, authority) = prepared();
    assert_eq!(
        cache::open(&journal, &keys).unwrap()["metadata"]["generation"],
        1
    );

    policy.signature = STANDARD.encode([0u8; 64]);
    assert!(cache::prepare(&mut journal.clone(), &keys, &policy, &catalog(&authority)).is_err());

    let mut nonce = journal.clone();
    nonce.cache.as_mut().unwrap().nonce = STANDARD.encode([0u8; 12]);
    nonce.cache_hash = cache::hash(&serde_json::to_vec(nonce.cache.as_ref().unwrap()).unwrap());
    assert!(
        cache::open(&nonce, &keys).is_err(),
        "tampered nonce must reach and fail AES authentication"
    );
    let mut pin = journal.clone();
    pin.pin.origin = "https://other.test".into();
    assert!(cache::open(&pin, &keys).is_err());
    let mut generation = journal.clone();
    generation.generation += 1;
    assert!(cache::open(&generation, &keys).is_err());
}

#[test]
fn request_wrapper_rejects_unknown_fields_and_service_operations() {
    let request = json!({"protocol":broker::PROTOCOL,"op":"browser_catalog","challenge":STANDARD.encode([3u8;32]),"tool":"chrome"});
    let mut unknown = wrapped(request.clone());
    unknown["unexpected"] = json!(true);
    assert!(broker::parse(&unknown).is_err());
    let mut service = request;
    service["op"] = json!("cache_prepare");
    assert!(broker::parse(&wrapped(service)).is_err());
}

#[test]
fn signed_reply_binds_body_hash_and_challenge_without_key_material() {
    let (journal, keys, _, _) = prepared();
    let request = json!({"protocol":broker::PROTOCOL,"op":"browser_catalog","challenge":STANDARD.encode([9u8;32]),"tool":"chrome"});
    let parsed = broker::parse(&wrapped(request)).unwrap();
    let reply = broker::signed(
        &journal,
        &keys,
        &parsed,
        "connected",
        0,
        json!({"catalog":"minimal"}),
    )
    .unwrap();
    let envelope: Envelope = serde_json::from_value(reply["signed"].clone()).unwrap();
    let bytes = STANDARD.decode(&envelope.payload).unwrap();
    let public: [u8; 32] = STANDARD
        .decode(&journal.pin.signing_key)
        .unwrap()
        .try_into()
        .unwrap();
    VerifyingKey::from_bytes(&public)
        .unwrap()
        .verify_strict(
            &bytes,
            &Signature::from_slice(&STANDARD.decode(&envelope.signature).unwrap()).unwrap(),
        )
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["challenge"], parsed.request.challenge);
    assert_eq!(body["request_hash"], parsed.hash);
    assert_eq!(body["generation"], journal.generation);
    let wire = serde_json::to_string(&reply).unwrap();
    assert!(!wire.contains("\"encryption\"") && !wire.contains("\"private\""));
}

#[test]
fn queue_retains_before_serialization_and_rejects_id_collision() {
    let (journal, _, policy_envelope, authority) = prepared();
    let policy = shadow::verify(
        &policy_envelope,
        &STANDARD.encode(authority.verifying_key().as_bytes()),
        1,
        Utc::now(),
    )
    .unwrap();
    let delivery = uuid::Uuid::new_v4();
    let parsed = broker::parse(&event_request(delivery, 21)).unwrap();
    let mut queue = broker::Queue::default();
    let first = queue.admit(&journal, &policy, &parsed).unwrap();
    assert_eq!(queue.admit(&journal, &policy, &parsed).unwrap(), first);
    assert_eq!(queue.pending.len(), 1);
    assert!(
        queue
            .admit(
                &journal,
                &policy,
                &broker::parse(&event_request(delivery, 22)).unwrap()
            )
            .is_err()
    );

    let mut no_content = policy.clone();
    no_content.config["collection"]["store_content"] = json!(false);
    no_content.config["collection"]["store_file_names"] = json!(false);
    let mut retained = broker::Queue::default();
    retained
        .admit(
            &journal,
            &no_content,
            &broker::parse(&event_request(uuid::Uuid::new_v4(), 23)).unwrap(),
        )
        .unwrap();
    assert!(
        retained.pending[0].event.prompt.is_none() && retained.pending[0].event.files.is_empty()
    );
    assert!(
        serde_json::to_vec(&retained)
            .unwrap()
            .windows(b"synthetic local text".len())
            .all(|w| w != b"synthetic local text")
    );
}

#[test]
fn queue_constructs_count_and_byte_saturation_before_admission() {
    let (journal, _, policy_envelope, authority) = prepared();
    let policy = shadow::verify(
        &policy_envelope,
        &STANDARD.encode(authority.verifying_key().as_bytes()),
        1,
        Utc::now(),
    )
    .unwrap();
    let mut queue = broker::Queue::default();
    // One account is refused at its share; the others are still admitted.
    for _ in 0..broker::PRINCIPAL_EVENTS {
        let parsed = broker::parse(&event_for_principal("S-1-5-21-1", uuid::Uuid::new_v4(), 1)).unwrap();
        queue.admit(&journal, &policy, &parsed).unwrap();
    }
    assert!(queue.admit(&journal, &policy, &broker::parse(&event_for_principal("S-1-5-21-1", uuid::Uuid::new_v4(), 1)).unwrap()).is_err());
    for index in broker::PRINCIPAL_EVENTS..broker::MAX_EVENTS {
        let sid = format!("S-1-5-21-{}", 2 + index / broker::PRINCIPAL_EVENTS);
        let parsed = broker::parse(&event_for_principal(&sid, uuid::Uuid::new_v4(), 1)).unwrap();
        queue.admit(&journal, &policy, &parsed).unwrap();
    }
    assert_eq!(queue.pending.len(), broker::MAX_EVENTS);
    assert!(
        queue
            .admit(
                &journal,
                &policy,
                &broker::parse(&event_request(uuid::Uuid::new_v4(), 1)).unwrap()
            )
            .is_err()
    );

    let mut oversized = queue.clone();
    oversized.pending[0].event.prompt = Some("x".repeat(broker::MAX_BYTES));
    assert!(
        oversized.validate().is_err(),
        "serialized 8 MiB state must be refused"
    );
}

#[test]
fn native_receive_reloads_encrypted_receipt_and_deduplicates_retry() {
    let (journal, _, policy_envelope, authority) = prepared();
    let policy_key = STANDARD.encode(authority.verifying_key().as_bytes());
    let policy = shadow::verify(&policy_envelope, &policy_key, 1, Utc::now()).unwrap();
    let mut broker_queue = broker::Queue::default();
    let parsed = broker::parse(&event_request(uuid::Uuid::new_v4(), 3)).unwrap();
    broker_queue.admit(&journal, &policy, &parsed).unwrap();
    let event = broker_queue.pending[0].event.clone();
    let installation = uuid::Uuid::new_v4().to_string();
    let mut state = State {
        public_key: policy_key,
        shadow_policy: Some(policy_envelope),
        shadow_revision: 1,
        detection: detection::Cache {
            revision: journal.catalog_revision,
            ..Default::default()
        },
        ..State::default()
    };
    let request =
        json!({"caller":{"system":true},"installation":installation,"sequence":1,"event":event});
    assert_eq!(
        broker::receive(&mut state, &request).0.unwrap()["durable"],
        true
    );
    assert_eq!(state.shadow_queue.len(), 1);
    let home = tempfile::tempdir().unwrap();
    {
        let store = crate::Store::open(home.path()).unwrap();
        store.save(&state).unwrap();
    }
    state = crate::Store::open(home.path()).unwrap().load().unwrap();
    assert_eq!(state.browser_broker_receipt.as_ref().unwrap().sequence, 1);
    assert_eq!(
        broker::receive(&mut state, &request).0.unwrap()["durable"],
        true
    );
    assert_eq!(
        state.shadow_queue.len(),
        1,
        "durable acknowledgement must make retry idempotent"
    );
    let mut collision = request;
    collision["event"]["id"] = json!(uuid::Uuid::new_v4());
    assert!(broker::receive(&mut state, &collision).0.is_err());
}

// Concatenate this file after browser_broker_tests.rs inside the same test module.

fn wrapped_for_principal(request: Value, sid: &str) -> Value {
    json!({"protocol": broker::PROTOCOL, "op": "browser_request",
        "caller": {"user": "same-user", "sid": sid},
        "body": STANDARD.encode(serde_json::to_vec(&request).unwrap())})
}

fn event_for_principal(sid: &str, delivery: uuid::Uuid, characters: u32) -> Value {
    wrapped_for_principal(
        json!({"protocol":broker::PROTOCOL,"op":"browser_event",
        "challenge":STANDARD.encode([4u8;32]),"tool":"chrome","delivery_id":delivery.to_string(),
        "event":{"kind":"prompt","provider":"chatgpt.com","source":"browser","tool":"chrome",
            "action":"observed","characters":characters,"labels":[],"prompt":"synthetic local text"}}),
        sid,
    )
}

#[test]
fn principal_sid_separates_ids_and_stable_id_survives_receipt_eviction() {
    let (journal, _, policy_envelope, authority) = prepared();
    let policy = shadow::verify(
        &policy_envelope,
        &STANDARD.encode(authority.verifying_key().as_bytes()),
        1,
        Utc::now(),
    )
    .unwrap();
    let delivery = uuid::Uuid::new_v4();
    let first = broker::parse(&event_for_principal("S-1-5-21-101", delivery, 1)).unwrap();
    let same_user_other_sid =
        broker::parse(&event_for_principal("S-1-5-21-202", delivery, 1)).unwrap();
    let mut queue = broker::Queue::default();
    let first_id = queue.admit(&journal, &policy, &first).unwrap();
    assert_ne!(
        first_id,
        queue
            .admit(&journal, &policy, &same_user_other_sid)
            .unwrap()
    );
    queue.pending.clear();

    // Every admission is real, but delivery is drained after its durable receipt.
    for _ in 0..=broker::MAX_EVENTS {
        let parsed = broker::parse(&event_for_principal(
            "S-1-5-21-303",
            uuid::Uuid::new_v4(),
            1,
        ))
        .unwrap();
        queue.admit(&journal, &policy, &parsed).unwrap();
        queue.pending.clear();
    }
    assert_eq!(queue.admit(&journal, &policy, &first).unwrap(), first_id);
}

// Any signed-in user reaches the SYSTEM queue. Delivering in a loop spends only that
// account's share of the receipt ring: another account's receipt, and with it the
// duplicate refusal on its retry, survives.
#[test]
fn one_account_delivering_in_a_loop_cannot_evict_another_accounts_receipt() {
    let (journal, _, policy_envelope, authority) = prepared();
    let policy = shadow::verify(&policy_envelope, &STANDARD.encode(authority.verifying_key().as_bytes()), 1, Utc::now()).unwrap();
    let victim = broker::parse(&event_for_principal("S-1-5-21-501", uuid::Uuid::new_v4(), 1)).unwrap();
    let mut queue = broker::Queue::default();
    let victim_id = queue.admit(&journal, &policy, &victim).unwrap();
    queue.pending.clear();
    for _ in 0..=broker::MAX_EVENTS {
        let flood = broker::parse(&event_for_principal("S-1-5-21-666", uuid::Uuid::new_v4(), 1)).unwrap();
        queue.admit(&journal, &policy, &flood).unwrap();
        queue.pending.clear();
    }
    assert_eq!(queue.completed(&journal, &victim).unwrap(), Some(victim_id), "victim receipt evicted");
    queue.validate().unwrap();
}

#[test]
fn health_admission_shares_event_budget_and_restricts_candidates() {
    let (journal, _, policy_envelope, authority) = prepared();
    let mut policy = shadow::verify(
        &policy_envelope,
        &STANDARD.encode(authority.verifying_key().as_bytes()),
        1,
        Utc::now(),
    )
    .unwrap();
    policy.config["discovery"] = json!({"enabled":true,"ignored_domains":[]});
    let now = Utc::now();
    let batch = json!({"id":uuid::Uuid::new_v4(),"tool":"chrome","extension_version":"1.0.0",
        "catalog_revision":journal.catalog_revision,"catalog_state":"ok","window_start":now-chrono::Duration::minutes(1),"window_end":now,
        "providers":[{"provider":"chatgpt","navigations":1,"prompts_network":0,"prompts_dom":0,"responses_dom":0,"candidates":1}],
        "candidates":[{"domain":"candidate.test","count":1,"signals":["json_keys"]}]});
    let health = wrapped_for_principal(
        json!({"protocol":broker::PROTOCOL,"op":"browser_health",
        "challenge":STANDARD.encode([5u8;32]),"tool":"chrome","batch":batch}),
        "S-1-5-21-404",
    );
    let mut queue = broker::Queue::default();
    queue
        .admit_health(&journal, &policy, &broker::parse(&health).unwrap())
        .unwrap();
    assert_eq!(queue.len(), 1);

    for index in 1..broker::MAX_EVENTS {
        let sid = format!("S-1-5-21-{}", 404 + index / broker::PRINCIPAL_EVENTS);
        let parsed = broker::parse(&event_for_principal(
            &sid,
            uuid::Uuid::new_v4(),
            1,
        ))
        .unwrap();
        queue.admit(&journal, &policy, &parsed).unwrap();
    }
    assert_eq!(queue.len(), broker::MAX_EVENTS);
    assert!(
        queue
            .admit(
                &journal,
                &policy,
                &broker::parse(&event_for_principal(
                    "S-1-5-21-404",
                    uuid::Uuid::new_v4(),
                    1
                ))
                .unwrap()
            )
            .is_err()
    );

    policy.config["discovery"]["ignored_domains"] = json!(["candidate.test"]);
    queue.restrict(Some(&policy), journal.generation);
    assert_eq!(queue.health[0].batch["candidates"], json!([]));
    queue.health[0].batch["candidates"] =
        json!([{"domain":"candidate.test","count":1,"signals":["json_keys"]}]);
    assert_eq!(
        queue.health[0].batch["candidates"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    policy.config["discovery"]["ignored_domains"] = json!([]);
    policy.config["discovery"]["enabled"] = json!(false);
    queue.restrict(Some(&policy), journal.generation);
    assert_eq!(queue.health[0].batch["candidates"], json!([]));
}

#[test]
fn aged_content_is_purged_and_native_receive_keeps_original_revision() {
    let (journal, _, policy_envelope, authority) = prepared();
    let mut policy = shadow::verify(
        &policy_envelope,
        &STANDARD.encode(authority.verifying_key().as_bytes()),
        1,
        Utc::now(),
    )
    .unwrap();
    policy.config["collection"]["content_retention_days"] = json!(1);
    let parsed = broker::parse(&event_for_principal(
        "S-1-5-21-505",
        uuid::Uuid::new_v4(),
        9,
    ))
    .unwrap();
    let mut queue = broker::Queue::default();
    queue.admit(&journal, &policy, &parsed).unwrap();
    queue.pending[0].event.files.push("sample.txt".into());
    queue.pending[0].event.occurred_at = Utc::now() - chrono::Duration::days(2);
    queue.restrict(Some(&policy), journal.generation);
    assert!(queue.pending[0].event.prompt.is_none() && queue.pending[0].event.files.is_empty());

    let mut event = queue.pending[0].event.clone();
    event.policy_revision = 0;
    let policy_key = STANDARD.encode(authority.verifying_key().as_bytes());
    let mut state = State {
        public_key: policy_key,
        shadow_policy: Some(policy_envelope),
        shadow_revision: 1,
        detection: detection::Cache {
            revision: journal.catalog_revision,
            ..Default::default()
        },
        ..State::default()
    };
    let request = json!({"caller":{"system":true},"installation":uuid::Uuid::new_v4().to_string(),"sequence":1,"event":event});
    broker::receive(&mut state, &request).0.unwrap();
    assert_eq!(state.shadow_queue.len(), 1);
    assert_eq!(state.shadow_queue[0].policy_revision, 0);
    assert!(state.shadow_queue[0].prompt.is_none() && state.shadow_queue[0].files.is_empty());
}

#[cfg(feature = "model-control")]
#[test]
fn authorized_enterprise_inspection_uses_lease_after_signed_expiry_without_mutation() {
    let (journal, _, policy_envelope, authority) = prepared();
    let mut policy = shadow::verify(
        &policy_envelope,
        &STANDARD.encode(authority.verifying_key().as_bytes()),
        1,
        Utc::now(),
    )
    .unwrap();
    policy.expires_at = Utc::now() - chrono::Duration::minutes(50);
    policy.config["model_access"] = json!([{"platform_id":"chatgpt","channel":"browser","mode":"allowlist","models":["model-alpha"]}]);
    let original_expiry = policy.expires_at;
    let request = |model| {
        json!({"provider":"chatgpt.com","text":"ordinary text","upload":false,
        "check_model":true,"platform_id":"chatgpt","model":model})
    };
    assert_ne!(
        crate::native::inspect_authorized_request(&policy, &request("model-alpha")).unwrap()["action"],
        "block"
    );
    assert_eq!(
        crate::native::inspect_authorized_request(&policy, &request("model-beta")).unwrap()["action"],
        "block"
    );
    assert_eq!(policy.expires_at, original_expiry);
    let _ = journal;
}

#[cfg(not(feature = "model-control"))]
#[test]
fn community_inspection_refuses_model_question() {
    let (_, _, policy_envelope, authority) = prepared();
    let policy = shadow::verify(
        &policy_envelope,
        &STANDARD.encode(authority.verifying_key().as_bytes()),
        1,
        Utc::now(),
    )
    .unwrap();
    let request = json!({"provider":"chatgpt.com","text":"ordinary text","upload":false,
        "check_model":true,"platform_id":"chatgpt","model":"model-alpha"});
    assert!(crate::native::inspect_authorized_request(&policy, &request).is_err());
}

#[test]
fn health_retry_reapplies_current_discovery_consent_before_ack() {
    let (_, _, envelope, authority) = prepared();
    let key = STANDARD.encode(authority.verifying_key().as_bytes());
    let mut p: Value =
        serde_json::from_slice(&STANDARD.decode(&envelope.payload).unwrap()).unwrap();
    p["config"]["discovery"] = json!({"enabled":true,"ignored_domains":[]});
    let mut state = State {
        server_url: "https://example.test".into(),
        public_key: key,
        shadow_policy: Some(signed(&authority, &p)),
        shadow_revision: 1,
        ..State::default()
    };
    let now = Utc::now();
    let id = uuid::Uuid::new_v4();
    let batch = json!({"id":id,"tool":"chrome","extension_version":"0.5.6","catalog_revision":1,"catalog_state":"ok",
        "window_start":now-Duration::minutes(1),"window_end":now,
        "providers":[{"provider":"chatgpt","navigations":1,"prompts_network":0,"prompts_dom":0,"responses_dom":0,"candidates":1}],
        "candidates":[{"domain":"candidate.test","count":1,"signals":["json_keys"]}]});
    let request = json!({"caller":{"system":true},"installation":uuid::Uuid::new_v4(),"sequence":1,"tool":"chrome","batch":batch});
    assert_eq!(
        broker::receive(&mut state, &request).0.unwrap()["durable"],
        true
    );
    assert_eq!(state.detection.health.len(), 1);
    assert_eq!(
        state.detection.health[0]["candidates"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    p["revision"] = json!(2);
    p["config"]["discovery"]["enabled"] = json!(false);
    state.shadow_policy = Some(signed(&authority, &p));
    state.shadow_revision = 2;
    assert_eq!(
        broker::receive(&mut state, &request).0.unwrap()["durable"],
        true
    );
    assert_eq!(
        state.detection.health.len(),
        1,
        "lost acknowledgement must not duplicate health"
    );
    assert_eq!(
        state.detection.health[0]["candidates"],
        json!([]),
        "current prohibition applies even to receipt retry"
    );
}

fn receipt_request(delivery: uuid::Uuid) -> Value {
    json!({"protocol":broker::PROTOCOL,"op":"browser_receipt","challenge":STANDARD.encode([11u8;32]),"tool":"chrome","delivery_id":delivery})
}

#[test]
fn browser_receipt_rejects_content_privilege_and_submit_without_inspection() {
    let request = receipt_request(uuid::Uuid::new_v4());
    assert!(broker::parse(&wrapped(request.clone())).is_ok());
    for key in [
        "text",
        "event",
        "provider",
        "upload",
        "check_model",
        "platform_id",
        "model",
        "batch",
        "url",
        "hash",
        "path",
    ] {
        for value in [Value::Null, json!("forbidden")] {
            let mut bad = request.clone();
            bad[key] = value;
            assert!(
                broker::parse(&wrapped(bad)).is_err(),
                "unexpected receipt field {key}"
            );
        }
    }
    for op in ["install", "cache_prepare", "broker_event", "broker_prepare_event", "browser_submit"] {
        let mut bad = request.clone();
        bad["op"] = json!(op);
        assert!(
            broker::parse(&wrapped(bad)).is_err(),
            "receipt cannot authorize {op}"
        );
    }
    for id in [Value::Null, json!("not-a-uuid")] {
        let mut bad = request.clone();
        bad["delivery_id"] = id;
        assert!(broker::parse(&wrapped(bad)).is_err());
    }
}

#[test]
fn browser_receipt_is_read_only_bound_and_survives_pending_removal() {
    let (journal, keys, envelope, authority) = prepared();
    let policy = shadow::verify(
        &envelope,
        &STANDARD.encode(authority.verifying_key().as_bytes()),
        1,
        Utc::now(),
    )
    .unwrap();
    let delivery = uuid::Uuid::new_v4();
    let lookup = broker::parse(&wrapped(receipt_request(delivery))).unwrap();
    let mut queue = broker::Queue::default();
    assert_eq!(
        queue.receipt(&journal, &lookup).unwrap(),
        json!({"ok":true,"durable":false,"delivery_id":delivery})
    );
    let event = broker::parse(&event_request(delivery, 21)).unwrap();
    let id = queue.admit(&journal, &policy, &event).unwrap();
    assert_eq!(queue.pending.len(), 1);
    queue.pending.remove(0); // Same removal as a durable agent acknowledgement.
    let queue: broker::Queue =
        serde_json::from_slice(&serde_json::to_vec(&queue).unwrap()).unwrap();
    let before = serde_json::to_vec(&queue).unwrap();
    let reply = queue.receipt(&journal, &lookup).unwrap();
    assert_eq!(
        reply,
        json!({"ok":true,"durable":true,"id":id,"delivery_id":delivery})
    );
    let mut foreign = lookup.clone();
    foreign.principal = "S-1-5-21-1-2-3-1002".into();
    assert_eq!(queue.receipt(&journal, &foreign).unwrap()["durable"], false);
    let mut other_install = journal.clone();
    other_install.pin.installation = uuid::Uuid::new_v4().to_string();
    assert_eq!(
        queue.receipt(&other_install, &lookup).unwrap()["durable"],
        false
    );
    let unknown = broker::parse(&wrapped(receipt_request(uuid::Uuid::new_v4()))).unwrap();
    assert_eq!(queue.receipt(&journal, &unknown).unwrap()["durable"], false);
    assert_eq!(serde_json::to_vec(&queue).unwrap(), before);
    assert!(queue.receipt(&journal, &event).is_err());
    let signed = broker::signed(&journal, &keys, &lookup, "connected", 0, reply.clone()).unwrap();
    let signed: Envelope = serde_json::from_value(signed["signed"].clone()).unwrap();
    let bytes = STANDARD.decode(signed.payload).unwrap();
    let public: [u8; 32] = STANDARD
        .decode(&journal.pin.signing_key)
        .unwrap()
        .try_into()
        .unwrap();
    VerifyingKey::from_bytes(&public)
        .unwrap()
        .verify_strict(
            &bytes,
            &Signature::from_slice(&STANDARD.decode(signed.signature).unwrap()).unwrap(),
        )
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["reply"], reply);
    assert_eq!(body["request_hash"], lookup.hash);
    assert_eq!(body["challenge"], lookup.request.challenge);
    assert!(body["reply"].get("action").is_none());
    assert!(body["reply"].get("text").is_none());
}

#[test]
fn browser_receipt_metadata_content_race_cannot_duplicate_custody() {
    let (journal, _, envelope, authority) = prepared();
    let policy = shadow::verify(
        &envelope,
        &STANDARD.encode(authority.verifying_key().as_bytes()),
        1,
        Utc::now(),
    )
    .unwrap();
    for metadata_first in [false, true] {
        let delivery = uuid::Uuid::new_v4();
        let content = broker::parse(&event_request(delivery, 21)).unwrap();
        let mut metadata = content.clone();
        metadata
            .request
            .event
            .as_mut()
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove("prompt");
        let lookup = broker::parse(&wrapped(receipt_request(delivery))).unwrap();
        let mut queue = broker::Queue::default();
        assert_eq!(queue.receipt(&journal, &lookup).unwrap()["durable"], false);
        let (first, second) = if metadata_first {
            (&metadata, &content)
        } else {
            (&content, &metadata)
        };
        let id = queue.admit(&journal, &policy, first).unwrap();
        assert!(queue.admit(&journal, &policy, second).is_err());
        assert_eq!(queue.pending.len(), 1);
        assert_eq!(queue.sequence, 1);
        assert_eq!(
            queue.receipt(&journal, &lookup).unwrap()["id"],
            id.to_string()
        );
    }
}
#[test]
fn browser_expected_authority_is_optional_but_strict_when_present() {
    let (journal, _, _, _) = prepared();
    let mut request = receipt_request(uuid::Uuid::new_v4());
    assert!(
        broker::parse(&wrapped(request.clone()))
            .unwrap()
            .check_authority(&journal)
            .is_ok()
    );
    request["expected_authority"] = json!(broker::authority_hash(&journal.pin).unwrap());
    assert!(
        broker::parse(&wrapped(request.clone()))
            .unwrap()
            .check_authority(&journal)
            .is_ok()
    );
    for invalid in [
        Value::Null,
        json!(7),
        json!(""),
        json!("a".repeat(63)),
        json!("A".repeat(64)),
        json!("g".repeat(64)),
    ] {
        request["expected_authority"] = invalid;
        assert!(broker::parse(&wrapped(request.clone())).is_err());
    }
}

#[test]
fn browser_expected_authority_rechecks_mutated_pin_before_custody() {
    let (journal, _, envelope, authority) = prepared();
    let policy = shadow::verify(
        &envelope,
        &STANDARD.encode(authority.verifying_key().as_bytes()),
        1,
        Utc::now(),
    )
    .unwrap();
    let delivery = uuid::Uuid::new_v4();
    let mut event = broker::parse(&event_request(delivery, 21)).unwrap();
    event.request.expected_authority = Some(broker::authority_hash(&journal.pin).unwrap());
    let mut request = receipt_request(delivery);
    request["expected_authority"] = json!(event.request.expected_authority);
    let lookup = broker::parse(&wrapped(request)).unwrap();
    let mut same = journal.clone();
    same.generation += 1;
    assert!(
        lookup.check_authority(&same).is_ok(),
        "generation does not change organization authority"
    );
    for field in [
        "installation",
        "edition",
        "origin",
        "organization_anchor",
        "signing_key",
    ] {
        let mut changed = journal.clone();
        match field {
            "installation" => changed.pin.installation = uuid::Uuid::new_v4().to_string(),
            "edition" => changed.pin.edition = "commercial".into(),
            "origin" => changed.pin.origin = "https://other.test".into(),
            "organization_anchor" => changed.pin.organization_anchor = STANDARD.encode([22u8; 32]),
            "signing_key" => changed.pin.signing_key = STANDARD.encode([23u8; 32]),
            _ => unreachable!(),
        }
        assert!(event.check_authority(&changed).is_err(), "{field}");
        let mut queue = broker::Queue::default();
        let before = serde_json::to_vec(&queue).unwrap();
        assert!(queue.admit(&changed, &policy, &event).is_err(), "{field}");
        assert!(queue.receipt(&changed, &lookup).is_err(), "{field}");
        let mut health = event.clone();
        health.request.op = "browser_health".into();
        assert!(
            queue.admit_health(&changed, &policy, &health).is_err(),
            "{field}"
        );
        assert_eq!(
            serde_json::to_vec(&queue).unwrap(),
            before,
            "no custody mutation for {field}"
        );
    }
}

fn completion_request(delivery_id: uuid::Uuid, completion: Value, sid: &str) -> Value {
    wrapped_for_principal(
        json!({"protocol":broker::PROTOCOL,"op":"browser_complete",
        "challenge":STANDARD.encode([9u8;32]),"tool":"chrome","delivery_id":delivery_id.to_string(),
        "completion":completion}),
        sid,
    )
}

/// A prompt is recorded before it is sent, so what the request itself said arrives
/// afterwards. It must reach the event it names and nothing else: fill what is empty,
/// never revise what is written, never designate another account's send, and never
/// turn into a second event.
#[test]
fn a_completion_fills_its_own_event_and_never_another_account_s() {
    let (journal, _, policy_envelope, authority) = prepared();
    let policy = shadow::verify(
        &policy_envelope,
        &STANDARD.encode(authority.verifying_key().as_bytes()),
        1,
        Utc::now(),
    )
    .unwrap();
    let mut queue = broker::Queue::default();
    let delivery = uuid::Uuid::new_v4();
    let submitted = broker::parse(&event_for_principal("S-1-5-21-501", delivery, 4)).unwrap();
    let id = queue.admit(&journal, &policy, &submitted).unwrap();
    queue.pending[0].event.detector = Some("dom".into());
    queue.pending[0].event.model = Some("recorded-model".into());

    let named = broker::parse(&completion_request(
        delivery,
        json!({"model":"observed-model","effort":"high","conversation_id":"observed-conversation","body_bytes":4096,"session":"signed_out"}),
        "S-1-5-21-501",
    ))
    .unwrap();
    let mut completion = shadow::ShadowCompletion::parse_for(
        uuid::Uuid::nil(),
        named.request.completion.as_ref().unwrap(),
    )
    .unwrap();
    completion.id = queue.completed(&journal, &named).unwrap().unwrap();
    assert_eq!(completion.id, id, "the completion named another event");
    assert!(queue.complete(&completion));
    let event = &queue.pending[0].event;
    assert_eq!(event.model.as_deref(), Some("recorded-model"));
    assert_eq!(event.conversation_id.as_deref(), Some("observed-conversation"));
    assert_eq!(event.effort.as_deref(), Some("high"));
    assert_eq!(event.body_bytes, Some(4096));
    assert_eq!(event.session.as_deref(), Some("signed_out"));
    assert_eq!(event.detector.as_deref(), Some("both"));
    assert_eq!(queue.pending.len(), 1, "a completion created an event");
    // The account state is a closed vocabulary: anything else refuses the completion.
    assert!(shadow::ShadowCompletion::parse_for(uuid::Uuid::nil(), &json!({"session":"anonymous"})).is_err());

    // The delivery key binds the calling account: the same delivery identity from
    // another principal designates nothing at all.
    let foreign = broker::parse(&completion_request(
        delivery,
        json!({"conversation_id":"stolen-conversation"}),
        "S-1-5-21-502",
    ))
    .unwrap();
    assert!(queue.completed(&journal, &foreign).unwrap().is_none());
    let unknown = broker::parse(&completion_request(
        uuid::Uuid::new_v4(),
        json!({"conversation_id":"never-sent"}),
        "S-1-5-21-501",
    ))
    .unwrap();
    assert!(queue.completed(&journal, &unknown).unwrap().is_none());

    // Nothing but an observation is readable from a completion, and an identity is
    // stamped by the agent rather than accepted from the browser.
    for refused in [
        json!({}),
        json!({"model":" leading-space"}),
        json!({"model":""}),
        json!({"characters":99}),
        json!({"prompt":"synthetic text"}),
        json!({"id":"11111111-1111-4111-8111-111111111111","model":"m"}),
    ] {
        assert!(
            shadow::ShadowCompletion::parse_for(uuid::Uuid::nil(), &refused).is_err(),
            "accepted {refused}"
        );
    }
    // A completion carries no event, no text and no decision.
    for smuggled in [
        json!({"event":{"kind":"prompt"}}),
        json!({"text":"synthetic text"}),
        json!({"provider":"chatgpt.com"}),
    ] {
        let mut request =
            json!({"protocol":broker::PROTOCOL,"op":"browser_complete","challenge":STANDARD.encode([9u8;32]),
            "tool":"chrome","delivery_id":delivery.to_string(),"completion":{"model":"m"}});
        for (key, value) in smuggled.as_object().unwrap() {
            request[key] = value.clone();
        }
        assert!(
            broker::parse(&wrapped_for_principal(request, "S-1-5-21-501")).is_err(),
            "accepted {smuggled}"
        );
    }
}

/// Where the event is, the completion goes. One the agent already holds is completed
/// in its own queue; one it has never seen is kept for the server, without ever
/// creating an event.
#[test]
fn the_agent_completes_a_queued_event_in_place_and_queues_the_rest() {
    let mut state = State::default();
    let id = uuid::Uuid::new_v4();
    state.shadow_queue.push(
        serde_json::from_value(json!({"id":id,"kind":"prompt","occurred_at":Utc::now(),
        "provider":"chatgpt.com","source":"browser","tool":"chrome","action":"observed",
        "characters":4,"labels":[],"policy_revision":1,"detector":"dom",
        "conversation_id":"recorded-conversation"}))
        .unwrap(),
    );
    let completion = shadow::ShadowCompletion::parse_for(
        id,
        &json!({"model":"observed-model","conversation_id":"observed-conversation"}),
    )
    .unwrap();
    shadow::complete(&mut state, completion).unwrap();
    assert!(state.shadow_completions.is_empty(), "queued what was at hand");
    let event = &state.shadow_queue[0];
    assert_eq!(event.model.as_deref(), Some("observed-model"));
    assert_eq!(
        event.conversation_id.as_deref(),
        Some("recorded-conversation"),
        "a completion revised a written value"
    );
    assert_eq!(event.detector.as_deref(), Some("both"));

    let delivered = uuid::Uuid::new_v4();
    shadow::complete(
        &mut state,
        shadow::ShadowCompletion::parse_for(delivered, &json!({"model":"first-answer"})).unwrap(),
    )
    .unwrap();
    shadow::complete(
        &mut state,
        shadow::ShadowCompletion::parse_for(
            delivered,
            &json!({"model":"second-answer","effort":"high"}),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(state.shadow_queue.len(), 1, "a completion created an event");
    assert_eq!(state.shadow_completions.len(), 1);
    assert_eq!(
        state.shadow_completions[0].model.as_deref(),
        Some("first-answer")
    );
    assert_eq!(state.shadow_completions[0].effort.as_deref(), Some("high"));
}

#[test]
fn health_past_its_share_evicts_only_the_same_accounts_oldest_batch() {
    let (journal, _, policy_envelope, authority) = prepared();
    let policy = shadow::verify(&policy_envelope, &STANDARD.encode(authority.verifying_key().as_bytes()), 1, Utc::now()).unwrap();
    let health = |sid: &str| {
        let now = Utc::now();
        let batch = json!({"id":uuid::Uuid::new_v4(),"tool":"chrome","extension_version":"1.0.0",
            "catalog_revision":journal.catalog_revision,"catalog_state":"ok","window_start":now-chrono::Duration::minutes(1),"window_end":now,
            "providers":[{"provider":"chatgpt","navigations":1,"prompts_network":0,"prompts_dom":0,"responses_dom":0,"candidates":0}],"candidates":[]});
        broker::parse(&wrapped_for_principal(json!({"protocol":broker::PROTOCOL,"op":"browser_health",
            "challenge":STANDARD.encode([5u8;32]),"tool":"chrome","batch":batch}), sid)).unwrap()
    };
    let mut queue = broker::Queue::default();
    queue.admit_health(&journal, &policy, &health("S-1-5-21-900")).unwrap();
    let other = queue.health[0].batch["id"].clone();
    for _ in 0..broker::PRINCIPAL_HEALTH + 5 {
        queue.admit_health(&journal, &policy, &health("S-1-5-21-901")).unwrap();
    }
    assert_eq!(queue.health.len(), broker::PRINCIPAL_HEALTH + 1);
    assert_eq!(queue.health[0].batch["id"], other, "another account's batch was evicted");
    queue.validate().unwrap();
}

#[test]
fn a_completion_that_would_overflow_the_queue_is_not_placed() {
    let (journal, _, policy_envelope, authority) = prepared();
    let policy = shadow::verify(&policy_envelope, &STANDARD.encode(authority.verifying_key().as_bytes()), 1, Utc::now()).unwrap();
    let mut queue = broker::Queue::default();
    let parsed = broker::parse(&event_for_principal("S-1-5-21-902", uuid::Uuid::new_v4(), 1)).unwrap();
    let id = queue.admit(&journal, &policy, &parsed).unwrap();
    let size = shadow::serialized_size(&queue).unwrap();
    let prompt = queue.pending[0].event.prompt.clone().unwrap_or_default();
    queue.pending[0].event.prompt = Some(format!("{prompt}{}", "x".repeat(broker::MAX_BYTES - size)));
    queue.validate().unwrap();
    let completion = shadow::ShadowCompletion::parse_for(id, &json!({"model":"model-alpha"})).unwrap();
    assert!(!queue.complete(&completion));
    assert!(queue.pending[0].event.model.is_none());
    queue.validate().unwrap();
}

/// A send the network guard sealed after its DOM record is one blocked event: the seal
/// completes that record where it still waits. Placed nowhere else, it says so, and the
/// browser records the refusal on its own.
#[test]
fn a_sealed_send_turns_its_waiting_record_blocked_and_nothing_else() {
    let (journal, _, policy_envelope, authority) = prepared();
    let policy = shadow::verify(&policy_envelope, &STANDARD.encode(authority.verifying_key().as_bytes()), 1, Utc::now()).unwrap();
    let mut queue = broker::Queue::default();
    let delivery = uuid::Uuid::new_v4();
    let id = queue.admit(&journal, &policy, &broker::parse(&event_for_principal("S-1-5-21-601", delivery, 4)).unwrap()).unwrap();
    let seal = json!({"decision_reason":"control_unavailable","platform_id":"chatgpt"});
    // Another account cannot name this send.
    assert!(queue.completed(&journal, &broker::parse(&completion_request(delivery, seal.clone(), "S-1-5-21-602")).unwrap()).unwrap().is_none());
    let completion = shadow::ShadowCompletion::parse_for(id, &seal).unwrap();
    let before = (queue.pending[0].event.prompt.clone(), queue.pending[0].event.characters);
    assert!(queue.complete(&completion));
    let event = &queue.pending[0].event;
    assert_eq!((event.action.as_str(), event.decision_reason.as_deref(), event.platform_id.as_deref()), ("blocked", Some("control_unavailable"), Some("chatgpt")));
    assert_eq!((event.prompt.clone(), event.characters), before, "no text and no count change");
    // A record of another platform keeps its action.
    let mut other = queue.pending[0].event.clone();
    (other.action, other.decision_reason, other.platform_id, other.provider) = ("observed".into(), None, None, "claude.ai".into());
    completion.apply(&mut other);
    assert_eq!(other.action, "observed");
    // Already at the server: not placed, and said so.
    let mut state = State::default();
    let mut gone = completion;
    gone.id = uuid::Uuid::new_v4();
    assert!(!shadow::complete(&mut state, gone).unwrap());
    assert!(state.shadow_completions.is_empty());
    for bad in [
        json!({"decision_reason":"model_denied","platform_id":"chatgpt"}),
        json!({"decision_reason":"control_unavailable"}),
        json!({"decision_reason":"control_unavailable","platform_id":"unknown-platform"}),
        json!({"platform_id":"chatgpt","model":"model-alpha"}),
    ] {
        assert!(shadow::ShadowCompletion::parse_for(uuid::Uuid::nil(), &bad).is_err(), "{bad}");
    }
}

#[test]
fn repeated_custody_transfers_keep_the_downstream_account_share() {
    let (journal, _, policy_envelope, authority) = prepared();
    let policy_key = STANDARD.encode(authority.verifying_key().as_bytes());
    let policy = shadow::verify(&policy_envelope,&policy_key,1,Utc::now()).unwrap();
    let mut queue=broker::Queue::default();
    let parsed=broker::parse(&event_request(uuid::Uuid::new_v4(),3)).unwrap();
    queue.admit(&journal,&policy,&parsed).unwrap();
    let event=queue.pending[0].event.clone();
    let installation=uuid::Uuid::new_v4().to_string();
    let mut state=State {public_key:policy_key,shadow_policy:Some(policy_envelope),shadow_revision:1,
        detection:detection::Cache {revision:journal.catalog_revision,..Default::default()},..State::default()};
    let share=250.min((crate::config::current().queue.max_events/2).max(1));
    for sequence in 1..=share {
        let mut event=event.clone();event.id=uuid::Uuid::new_v4();
        let request=json!({"caller":{"system":true},"installation":installation,"sequence":sequence,
            "quota_principal":"S-1-5-21-1000","event":event});
        assert_eq!(broker::receive(&mut state,&request).0.unwrap()["durable"],true);
    }
    let mut refused=event.clone();refused.id=uuid::Uuid::new_v4();
    let mut request=json!({"caller":{"system":true},"installation":installation,"sequence":share+1,
        "quota_principal":"S-1-5-21-1000","event":refused});
    assert!(broker::receive(&mut state,&request).0.is_err());
    assert_eq!(state.browser_broker_receipt.as_ref().unwrap().sequence,share as u64);
    assert_eq!(state.shadow_queue.len(),share);
    request["quota_principal"]=json!("S-1-5-21-1001");
    assert_eq!(broker::receive(&mut state,&request).0.unwrap()["durable"],true);
    assert_eq!(state.shadow_queue.len(),share+1);
    assert_eq!(state.browser_queue_owners.len(),share+1);
}
fn replay_live_response(journal: &cache::Journal, envelope: &Envelope, policy: &shadow::ShadowPolicy) -> Value {
    json!({"ok":true,"policy":crate::native::browser_policy(policy),
        "cache_policy_hash":cache::envelope_hash(envelope).unwrap(),"cache_authorization_generation":7,
        "cache_policy_content_hash":journal.policy_content_hash,
        "cache_catalog_content_hash":journal.catalog_content_hash,"cache_catalog_revision":journal.catalog_revision})
}

#[test]
fn production_observation_orders_probe_results_and_does_not_extend_an_outage() {
    use crate::cache_replay_authority::{Observation, classify};
    let (mut journal, keys, envelope, authority) = prepared();
    let policy = shadow::verify(&envelope, &STANDARD.encode(authority.verifying_key().as_bytes()), 1, Utc::now()).unwrap();
    let response = replay_live_response(&journal, &envelope, &policy);
    let boot = uuid::Uuid::new_v4().to_string(); journal.recovered(&boot, 100).unwrap();
    let mut queue = broker::Queue::default(); let mut observation = Observation::default();
    let authorized = observation.ticket().unwrap();
    observation.observe(&mut journal, &keys, &mut queue, classify(Some(response.clone())), authorized, Some(&boot), 200).unwrap();
    let captured_authorized_epoch = observation.epoch();
    let outage = observation.ticket().unwrap();
    assert!(observation.observe(&mut journal, &keys, &mut queue, classify(None), outage, Some(&boot), 300).unwrap().save);
    assert_ne!(observation.epoch(), captured_authorized_epoch, "cached authorized work could otherwise recover a later outage");
    let deadline = journal.deadline;
    let outage_epoch = observation.epoch();
    let next_outage = observation.ticket().unwrap();
    observation.observe(&mut journal, &keys, &mut queue, classify(None), next_outage, Some(&boot), 400).unwrap();
    assert_eq!(journal.deadline, deadline); assert_eq!(observation.epoch(), outage_epoch);
    let recovery = observation.ticket().unwrap();
    observation.observe(&mut journal, &keys, &mut queue, classify(Some(response)), recovery, Some(&boot), 500).unwrap();
    assert_ne!(observation.epoch(), outage_epoch, "an older unreachable transcript must not start a second outage");
}

#[test]
fn production_observation_rejects_delayed_probe_after_newer_success_or_failure() {
    use crate::cache_replay_authority::{Observation, classify};
    for newer_reachable in [true, false] {
        let (mut journal, keys, envelope, authority) = prepared();
        let policy = shadow::verify(&envelope, &STANDARD.encode(authority.verifying_key().as_bytes()), 1, Utc::now()).unwrap();
        let response = replay_live_response(&journal, &envelope, &policy);
        let boot = uuid::Uuid::new_v4().to_string(); journal.recovered(&boot, 100).unwrap();
        let mut queue = broker::Queue::default(); let mut observation = Observation::default();
        let old = observation.ticket().unwrap(); let new = observation.ticket().unwrap();
        let newest = if newer_reachable { Some(response.clone()) } else { None };
        observation.observe(&mut journal, &keys, &mut queue, classify(newest), new, Some(&boot), 200).unwrap();
        let epoch = observation.epoch(); let deadline = journal.deadline;
        let delayed = if newer_reachable { None } else { Some(response) };
        assert!(observation.observe(&mut journal, &keys, &mut queue, classify(delayed), old, Some(&boot), 300).is_err());
        assert_eq!(observation.epoch(), epoch); assert_eq!(journal.deadline, deadline);
    }
}

#[test]
fn production_local_event_preparation_is_identity_free_and_preserves_dlp_custody() {
    let (journal, _, envelope, authority) = prepared();
    let mut policy = shadow::verify(&envelope, &STANDARD.encode(authority.verifying_key().as_bytes()), 1, Utc::now()).unwrap();
    let input = json!({"kind":"prompt","provider":"chatgpt.com","source":"browser","tool":"chrome",
        "action":"observed","characters":20,"labels":[],"prompt":"synthetic local text"});
    let normal = crate::cache_replay_authority::local_work(&json!({"op":"cache_local_event","policy":policy,
        "catalog_revision":journal.catalog_revision,"input":input,"trace":null})).unwrap().unwrap();
    let normal:shadow::ShadowEvent=serde_json::from_value(normal).unwrap();
    assert!(normal.id.is_nil()); assert!(normal.user.is_none()); assert!(normal.prompt.is_some());
    policy.version = 4;
    policy.config["collection"] = json!({"enabled":false,"store_content":false,"store_file_names":false});
    policy.config["dlp"] = json!({"schema_version":1,"domain":"endpoint","inspection":true,"native_inspection":false,"journal":true,"detectors":[],"rules":[]});
    policy.config["dlp_fingerprint"] = json!("a".repeat(64)); policy.config["dlp_legacy_disabled"] = json!(true);
    use shadow::dlp_transport::{Trace, Decision, Mode, Truth};
    for delivery in ["not_sent","cancelled"] {
        let trace = Trace { fingerprint:"a".repeat(64),action:"block".into(),delivery:delivery.into(),
            decisions:vec![Decision {rule_id:"synthetic.rule".into(),rule_revision:1,rule_name:"Synthetic rule".into(),
                mode:Mode::Active,consequence:"block".into(),condition:Truth::True,scope:Truth::True,
                outcome:if delivery=="cancelled" {"cancelled"}else{"blocked"}.into(),occurrences:1}] };
        let prepared = crate::cache_replay_authority::local_work(&json!({"op":"cache_local_event","policy":policy,
            "catalog_revision":journal.catalog_revision,"input":input,"trace":trace})).unwrap().unwrap();
        let event:shadow::ShadowEvent=serde_json::from_value(prepared).unwrap();
        assert!(event.id.is_nil()); assert!(event.user.is_none()); assert!(event.prompt.is_none());
        assert_eq!(event.dlp.as_ref().unwrap().delivery, delivery);
    }
}

#[test]
fn legacy_unattributed_row_cannot_gain_in_place_completion_during_handoff(){
    let(journal,_,envelope,authority)=prepared();let policy=shadow::verify(&envelope,&STANDARD.encode(authority.verifying_key().as_bytes()),1,Utc::now()).unwrap();
    let mut queue=broker::Queue::default();let parsed=broker::parse(&event_request(uuid::Uuid::new_v4(),1)).unwrap();
    let id=queue.admit(&journal,&policy,&parsed).unwrap();let mut value=serde_json::to_value(&queue).unwrap();
    value["pending"][0].as_object_mut().unwrap().remove("principal");
    let mut legacy:broker::Queue=serde_json::from_value(value).unwrap();legacy.validate().unwrap();
    assert!(!legacy.complete(&shadow::ShadowCompletion::parse_for(id,&json!({"model":"synthetic-model"})).unwrap()));
    assert!(legacy.pending[0].event.model.is_none());
}

#[test]
fn real_native_completion_receiver_reports_recoverable_quota_refusal(){
    let(journal,_,envelope,authority)=prepared();let policy=shadow::verify(&envelope,&STANDARD.encode(authority.verifying_key().as_bytes()),1,Utc::now()).unwrap();
    let base=shadow::browser_event(&policy,journal.catalog_revision,json!({"kind":"prompt","provider":"chatgpt.com","source":"browser","tool":"chrome",
        "action":"observed","characters":1,"labels":[],"prompt":"synthetic"})).unwrap();
    let mut state=State::default();let owner="sid:S-1-5-21-1000";
    for _ in 0..250{
        let mut row=base.clone();row.id=uuid::Uuid::new_v4();row.prompt=Some("x".repeat(32*1024));let id=row.id;state.shadow_queue.push(row);
        if crate::browser_queue_quota::claim(&mut state,id,owner.into()).is_err(){crate::browser_queue_quota::rollback(&mut state,id);break;}
    }
    let mut row=base;row.id=uuid::Uuid::new_v4();row.prompt=Some(String::new());let id=row.id;state.shadow_queue.push(row);
    crate::browser_queue_quota::claim(&mut state,id,owner.into()).unwrap();
    let cap=(2*1024*1024).min((crate::config::current().queue.max_bytes/2).max(1));
    let used=shadow::queue_bytes(&state).unwrap();let padding=cap.checked_sub(used+32).unwrap();assert!(padding<32*1024);
    state.shadow_queue.last_mut().unwrap().prompt=Some("x".repeat(padding));crate::browser_queue_quota::check_growth(&state,id).unwrap();
    let home=tempfile::tempdir().unwrap();{let store=crate::Store::open(home.path()).unwrap();store.save(&state).unwrap();}
    let too_large=shadow::ShadowCompletion::parse_for(id,&json!({"model":"m".repeat(200),"effort":"e".repeat(200),"conversation_id":"c".repeat(200)})).unwrap();
    let reply=crate::native::native_message(home.path(),json!({"op":"broker_complete","caller":{"system":true},"completion":too_large})).unwrap();
    assert_eq!(reply["ok"],true);assert_eq!(reply["applied"],false);
    {let store=crate::Store::open(home.path()).unwrap();let current=store.load().unwrap();assert!(current.shadow_queue.iter().any(|event|event.id==id&&event.model.is_none()));}
    let small=shadow::ShadowCompletion::parse_for(id,&json!({"body_bytes":1})).unwrap();
    let reply=crate::native::native_message(home.path(),json!({"op":"broker_complete","caller":{"system":true},"completion":small})).unwrap();
    assert_eq!(reply["applied"],true);
}

#[test]
fn transfer_marker_roundtrips_refuses_mutation_and_charges_only_present_format_bytes(){
    let(journal,_,envelope,authority)=prepared();let policy=shadow::verify(&envelope,&STANDARD.encode(authority.verifying_key().as_bytes()),1,Utc::now()).unwrap();
    let mut queue=broker::Queue::default();let id=queue.admit(&journal,&policy,&broker::parse(&event_request(uuid::Uuid::new_v4(),1)).unwrap()).unwrap();
    let old=serde_json::to_value(&queue).unwrap();assert!(old["pending"][0].get("transfer_started").is_none());
    queue.pending[0].transfer_started=true;let size=shadow::serialized_size(&queue).unwrap();
    let padding=broker::MAX_BYTES+24-size;queue.pending[0].event.prompt.as_mut().unwrap().push_str(&"x".repeat(padding));
    queue.pending[0].transfer_started=false;assert_eq!(shadow::serialized_size(&queue).unwrap(),broker::MAX_BYTES);queue.validate().unwrap();
    queue.pending[0].transfer_started=true;assert_eq!(shadow::serialized_size(&queue).unwrap(),broker::MAX_BYTES+24);queue.validate().unwrap();
    let bytes=serde_json::to_vec(&queue).unwrap();let mut restored:broker::Queue=serde_json::from_slice(&bytes).unwrap();restored.validate().unwrap();
    assert!(restored.pending[0].transfer_started);
    assert!(!restored.complete(&shadow::ShadowCompletion::parse_for(id,&json!({"model":"synthetic-model"})).unwrap()));
    restored.pending[0].event.prompt.as_mut().unwrap().push('x');assert!(restored.validate().is_err());
    let mut malformed=old.clone();malformed["pending"][0]["transfer_started"]=json!("true");assert!(serde_json::from_value::<broker::Queue>(malformed).is_err());
    let mut oversized=old;let mut row=oversized["pending"][0].clone();row["transfer_started"]=json!(true);oversized["pending"]=json!(vec![row;broker::MAX_EVENTS+1]);
    let oversized:broker::Queue=serde_json::from_value(oversized).unwrap();assert!(oversized.validate().is_err());
}

#[test]
fn offered_retry_allows_only_privacy_narrowing_and_never_metadata_or_identity_changes(){
    let(journal,_,envelope,authority)=prepared();let policy=shadow::verify(&envelope,&STANDARD.encode(authority.verifying_key().as_bytes()),1,Utc::now()).unwrap();
    let original=shadow::browser_event(&policy,journal.catalog_revision,json!({"kind":"prompt","provider":"chatgpt.com","source":"browser","tool":"chrome",
        "action":"observed","characters":1,"labels":[],"prompt":"synthetic"})).unwrap();
    let mut narrow=original.clone();narrow.discard_content();narrow.files.clear();
    assert!(crate::cache_replay_authority::narrow_offered(&original,&serde_json::to_value(narrow).unwrap()).is_ok());
    for field in ["id","model","action"]{
        let mut changed=serde_json::to_value(&original).unwrap();changed[field]=match field{"id"=>json!(uuid::Uuid::new_v4()),"action"=>json!("blocked"),_=>json!("injected-model")};
        assert!(crate::cache_replay_authority::narrow_offered(&original,&changed).is_err());
    }
}

// These tests exercise the actual portable observation/token implementation used
// by the Windows adapter, with real signed journals and the production driver.
struct PortableReplayAuthority {
    journal:cache::Journal, keys:cache::Keys, catalogue:Envelope, queue:broker::Queue,
    observation:crate::cache_replay_authority::Observation,
    boot:String, staged:bool, dirty:bool, saves:usize,
}
enum PortableReplayOperation {
    Policy,
    Replace { envelope:Envelope, catalog:Envelope },
}
impl PortableReplayAuthority {
    fn save(&mut self) -> crate::Result<()> {
        self.dirty=true;
        if !self.staged { self.queue.validate()?; self.saves+=1; self.dirty=false; }
        Ok(())
    }
}
impl crate::cache_replay::Target for PortableReplayAuthority {
    type Operation=PortableReplayOperation; type Output=bool;
    type Snapshot=(cache::Journal,broker::Queue,bool);
    type Token=crate::cache_replay_authority::Token; type Ticket=Option<u64>;
    fn token(&self)->crate::Result<Self::Token>{self.observation.token(&self.journal)}
    fn snapshot(&self)->Self::Snapshot{(self.journal.clone(),self.queue.clone(),self.dirty)}
    fn restore(&mut self,snapshot:Self::Snapshot){self.journal=snapshot.0;self.queue=snapshot.1;self.dirty=snapshot.2;}
    fn staging(&mut self,enabled:bool){self.staged=enabled;}
    fn flush(&mut self)->crate::Result<()>{if self.dirty{self.save()?;}Ok(())}
    fn begin_exchange(&mut self,_operation:&Self::Operation,request:&Value)->crate::Result<Option<u64>>{
        Ok(if request["op"]=="policy_v3"{Some(self.observation.ticket()?)}else{None})
    }
    fn is_refused_reply(&self,request:&Value,reply:&crate::cache_replay::Reply)->bool{
        request["op"]=="policy_v3"&&matches!(reply,crate::cache_replay::Reply::Value(value)if matches!(crate::cache_replay_authority::classify(Some(value.clone())),crate::cache_replay_authority::Input::Refused))
    }
    fn accept_changed_token(&self,expected:&Self::Token,request:&Value,reply:&crate::cache_replay::Reply,ticket:&Option<u64>)->crate::Result<bool>{
        self.observation.accept_changed_token(&self.journal,expected,request,reply,*ticket)
    }
    fn observe(&mut self,_operation:&Self::Operation,request:&Value,reply:&crate::cache_replay::Reply,ticket:Option<u64>)->crate::Result<()>{
        if request["op"]!="policy_v3"{return Ok(());}
        let input=crate::cache_replay_authority::classify(match reply{crate::cache_replay::Reply::Value(value)=>Some(value.clone()),crate::cache_replay::Reply::Unreachable=>None});
        let effect=self.observation.observe(&mut self.journal,&self.keys,&mut self.queue,input,ticket.unwrap(),Some(&self.boot),1000)?;
        if effect.save{self.save()?;}Ok(())
    }
    fn attempt(&mut self,operation:&Self::Operation,transcript:&mut crate::cache_replay::Transcript)->crate::Result<bool>{
        let input=crate::cache_replay_authority::classify(transcript.exchange(&json!({"op":"policy_v3"})).ok());
        match input{
            crate::cache_replay_authority::Input::Refused=>Ok(false),
            crate::cache_replay_authority::Input::Unreachable=>{let result=self.journal.remaining(&self.boot,1000,cache::Presence::Unreachable);self.save()?;result.map(|_|true)},
            crate::cache_replay_authority::Input::Authorized{..}=>{
                if let PortableReplayOperation::Replace{envelope,catalog}=operation{cache::prepare(&mut self.journal,&self.keys,envelope,catalog)?;}
                self.journal.recovered(&self.boot,1000)?;self.save()?;Ok(true)
            }
        }
    }
}
// Capture one exact admitted signed catalogue; its revision-one content contains a timestamp.
fn portable_replay_prepared() -> (cache::Journal, cache::Keys, Envelope, SigningKey, Envelope) {
    let policy_key = authority();
    let keys = cache::Keys::generate();
    let pin = cache::Pin {
        installation: uuid::Uuid::new_v4().to_string(),
        edition: "community".into(),
        origin: "https://example.test".into(),
        organization_anchor: STANDARD.encode(policy_key.verifying_key().as_bytes()),
        signing_key: keys.public(),
    };
    let mut journal = cache::Journal::new(pin).unwrap();
    let policy = policy(&policy_key);
    let catalogue=catalog(&policy_key);
    cache::prepare(&mut journal, &keys, &policy, &catalogue).unwrap();
    assert_eq!(cache::envelope_hash(&catalogue).unwrap(),journal.catalog_hash);
    (journal, keys, policy, policy_key, catalogue)
}

fn portable_replay_fixture()->(PortableReplayAuthority,Value,SigningKey,Envelope){
    let(mut journal,keys,envelope,authority,catalogue)=portable_replay_prepared();
    let policy=shadow::verify(&envelope,&STANDARD.encode(authority.verifying_key().as_bytes()),1,Utc::now()).unwrap();
    let response=replay_live_response(&journal,&envelope,&policy);
    let boot=uuid::Uuid::new_v4().to_string();journal.recovered(&boot,100).unwrap();
    (PortableReplayAuthority{journal,keys,catalogue,queue:broker::Queue::default(),observation:Default::default(),boot,staged:false,dirty:false,saves:0},response,authority,envelope)
}
fn portable_deadline()->std::time::Instant{std::time::Instant::now()+std::time::Duration::from_secs(5)}

#[test]
fn production_portable_driver_reuses_delayed_same_policy_without_cancelling_the_slower_principal(){
    use std::sync::{Arc,Mutex,mpsc};use std::thread;
    let(target,response,_,_)=portable_replay_fixture();let slot=Arc::new(Mutex::new(Some(target)));
    let a_slot=slot.clone();let a_response=response.clone();let(started,seen)=mpsc::channel();let(release,wait)=mpsc::channel();
    let a=thread::spawn(move||crate::cache_replay::drive(&a_slot,&PortableReplayOperation::Policy,portable_deadline(),||unreachable!(),|_,_|{
        started.send(()).unwrap();wait.recv().unwrap();crate::cache_replay::Reply::Value(a_response.clone())
    }));
    seen.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
    assert!(crate::cache_replay::drive(&slot,&PortableReplayOperation::Policy,portable_deadline(),||unreachable!(),|_,_|crate::cache_replay::Reply::Value(response.clone())).unwrap());
    let epoch=slot.lock().unwrap().as_ref().unwrap().observation.epoch();
    release.send(()).unwrap();assert!(a.join().unwrap().unwrap());
    assert_eq!(slot.lock().unwrap().as_ref().unwrap().observation.epoch(),epoch);
}

#[test]
fn production_portable_driver_keeps_delayed_refusal_across_newer_uncertainty(){
    use std::sync::{Arc,Mutex,mpsc};use std::thread;
    let(target,_,_,_)=portable_replay_fixture();let slot=Arc::new(Mutex::new(Some(target)));let a_slot=slot.clone();
    let(started,seen)=mpsc::channel();let(release,wait)=mpsc::channel();
    let a=thread::spawn(move||crate::cache_replay::drive(&a_slot,&PortableReplayOperation::Policy,portable_deadline(),||unreachable!(),|_,_|{
        started.send(()).unwrap();wait.recv().unwrap();crate::cache_replay::Reply::Value(json!({"ok":false}))
    }));
    seen.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
    assert!(crate::cache_replay::drive(&slot,&PortableReplayOperation::Policy,portable_deadline(),||unreachable!(),|_,_|crate::cache_replay::Reply::Unreachable).unwrap());
    assert!(slot.lock().unwrap().as_ref().unwrap().journal.deadline.is_some());
    release.send(()).unwrap();assert!(!a.join().unwrap().unwrap());
    {let guard=slot.lock().unwrap();let current=guard.as_ref().unwrap();assert!(current.journal.cache.is_none());assert!(!current.journal.armed);}
    assert!(crate::cache_replay::drive(&slot,&PortableReplayOperation::Policy,portable_deadline(),||unreachable!(),|_,_|crate::cache_replay::Reply::Unreachable).is_err());
}

#[test]
fn production_portable_driver_newer_positive_and_replacement_protect_against_old_refusal(){
    use std::sync::{Arc,Mutex,mpsc};use std::thread;
    for replace in [false,true]{
        let(target,mut response,key,envelope)=portable_replay_fixture();let catalogue=target.catalogue.clone();let slot=Arc::new(Mutex::new(Some(target)));let a_slot=slot.clone();
        let(started,seen)=mpsc::channel();let(release,wait)=mpsc::channel();
        let a=thread::spawn(move||crate::cache_replay::drive(&a_slot,&PortableReplayOperation::Policy,portable_deadline(),||unreachable!(),|_,_|{
            started.send(()).unwrap();wait.recv().unwrap();crate::cache_replay::Reply::Value(json!({"ok":false}))
        }));
        seen.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
        let operation=if replace{
            let mut policy:shadow::ShadowPolicy=serde_json::from_slice(&STANDARD.decode(envelope.payload).unwrap()).unwrap();
            policy.revision+=1;policy.issued_at+=Duration::milliseconds(1);policy.expires_at+=Duration::milliseconds(1);
            policy.config["collection"]["store_content"]=json!(false);
            let envelope=signed(&key,&policy);
            response["policy"]=crate::native::browser_policy(&policy);
            response["cache_policy_hash"]=json!(cache::envelope_hash(&envelope).unwrap());
            response["cache_policy_content_hash"]=json!(cache::policy_content_hash(&policy).unwrap());
            PortableReplayOperation::Replace{envelope,catalog:catalogue}
        }else{PortableReplayOperation::Policy};
        assert!(crate::cache_replay::drive(&slot,&operation,portable_deadline(),||unreachable!(),|_,_|crate::cache_replay::Reply::Value(response.clone())).unwrap());
        let generation=slot.lock().unwrap().as_ref().unwrap().journal.generation;
        release.send(()).unwrap();assert!(a.join().unwrap().is_err());
        let guard=slot.lock().unwrap();let current=guard.as_ref().unwrap();
        assert!(current.journal.cache.is_some());assert!(current.journal.armed);assert_eq!(current.journal.generation,generation);
        assert_eq!(current.journal.policy_revision,if replace{2}else{1});
    }
}

#[test]
fn production_portable_driver_never_applies_old_refusal_to_another_pin_or_generation(){
    use std::sync::{Arc,Mutex,mpsc};use std::thread;
    for replace_pin in [false,true]{
        let(target,_,_key,envelope)=portable_replay_fixture();let slot=Arc::new(Mutex::new(Some(target)));let a_slot=slot.clone();
        let(started,seen)=mpsc::channel();let(release,wait)=mpsc::channel();
        let a=thread::spawn(move||crate::cache_replay::drive(&a_slot,&PortableReplayOperation::Policy,portable_deadline(),||unreachable!(),|_,_|{
            started.send(()).unwrap();wait.recv().unwrap();crate::cache_replay::Reply::Value(json!({"ok":false}))
        }));
        seen.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
        {
            let mut guard=slot.lock().unwrap();
            if replace_pin{*guard=Some(portable_replay_fixture().0);}
            else{let current=guard.as_mut().unwrap();current.journal.invalidate().unwrap();
                cache::prepare(&mut current.journal,&current.keys,&envelope,&current.catalogue).unwrap();
                current.journal.recovered(&current.boot,1000).unwrap();current.save().unwrap();}
        }
        let generation=slot.lock().unwrap().as_ref().unwrap().journal.generation;
        release.send(()).unwrap();assert!(a.join().unwrap().is_err());
        let guard=slot.lock().unwrap();let current=guard.as_ref().unwrap();
        assert!(current.journal.cache.is_some());assert!(current.journal.armed);assert_eq!(current.journal.generation,generation);
    }
}
