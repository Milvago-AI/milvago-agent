use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use milvago_browser_agent::{config, shadow, Envelope, State, Store};
use serde_json::{json, Value};
use std::{path::Path, time::Duration};

fn configured(home: &Path, events: usize, mib: usize) {
    std::fs::write(config::directory(home).join("milvago.toml"),
        format!("[queue]\nmax_events = {events}\nmax_size_mb = {mib}\n")).unwrap();
}
fn authorized() -> State {
    let key = SigningKey::from_bytes(&[61; 32]);
    let now = Utc::now();
    let value = json!({"version":3,"revision":1,"issued_at":now,
        "expires_at":now+chrono::Duration::minutes(10),"capabilities":[],
        "config":{"collection":{"enabled":true,"store_content":true},
        "services":[{"domains":["chatgpt.com"],"enabled":true,"mode":"observe"}],
        "privacy":{"enabled":false},"protection":{}}});
    let payload = serde_json::to_vec(&value).unwrap();
    State { public_key: STANDARD.encode(key.verifying_key().as_bytes()), shadow_revision:1,
        shadow_policy:Some(Envelope {payload:STANDARD.encode(&payload),
        signature:STANDARD.encode(key.sign(&payload).to_bytes())}), ..State::default() }
}
fn event(text: &str) -> Value {
    json!({"kind":"prompt","provider":"chatgpt.com","source":"browser","tool":"chrome",
        "action":"observed","characters":text.len(),"labels":[],"prompt":text})
}

// One process owns the global configuration. No unit-test fixture can change it.
#[test]
fn queue_configuration_controls_admission_and_preserves_durable_backlog() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    std::fs::create_dir_all(config::directory(&home)).unwrap();
    configured(&home, 2, 1);
    config::open(&home);
    let mut state = authorized();
    let first = shadow::enqueue_browser(&mut state, event("first")).unwrap();
    shadow::enqueue_refusal(&mut state, "claude-code", "blocked", 7, vec![]).unwrap_err(); // Provider absent.
    let second = shadow::enqueue_refusal(&mut state, "codex", "blocked", 7, vec![]).unwrap();
    let before = serde_json::to_vec(&state.shadow_queue).unwrap();
    assert!(shadow::enqueue_browser(&mut state, event("third")).is_err());
    assert!(shadow::enqueue_refusal(&mut state, "codex", "blocked", 7, vec![]).is_err());
    assert_eq!(serde_json::to_vec(&state.shadow_queue).unwrap(), before);
    Store::open(&home).unwrap().save(&state).unwrap();

    configured(&home, 1, 1);
    std::thread::sleep(Duration::from_millis(5100));
    assert_eq!(config::current().queue.max_events, 1);
    state = Store::open(&home).unwrap().load().unwrap();
    assert_eq!(state.shadow_queue.iter().map(|e|e.id).collect::<Vec<_>>(), vec![first, second]);
    assert!(shadow::enqueue_browser(&mut state, event("third")).is_err());
    // Removing acknowledged events restores admission, without reopening configuration.
    state.shadow_queue.clear();
    shadow::enqueue_browser(&mut state, event("after acknowledgement")).unwrap();

    configured(&home, 1000, 1);
    config::open(&home);
    state.shadow_queue.clear();
    let body = "x".repeat(32 * 1024);
    loop {
        let count = state.shadow_queue.len();
        if shadow::enqueue_browser(&mut state, event(&body)).is_err() {
            assert_eq!(state.shadow_queue.len(), count);
            break;
        }
    }
    assert!(state.shadow_queue.len() < 1000);
    assert!(shadow::queue_bytes(&state).unwrap() <= 1024 * 1024);
    assert!(shadow::enqueue_refusal(&mut state, "codex", &body, body.chars().count() as u32, vec![]).is_err());

    // Attribution happens after parsing; its bytes must not turn a refusal into custody.
    let mut probe = authorized();
    shadow::enqueue_browser(&mut probe, event("boundary")).unwrap();
    let incoming_size = shadow::serialized_size(&probe.shadow_queue[0]).unwrap();
    let mut filler = state.shadow_queue[0].clone();
    filler.id = uuid::Uuid::new_v4();
    filler.prompt = Some(String::new());
    filler.characters = 0;
    state.shadow_queue.push(filler);
    let padding = 1024 * 1024 - incoming_size - 64 - shadow::queue_bytes(&state).unwrap();
    assert!(padding < 32 * 1024);
    state.shadow_queue.last_mut().unwrap().prompt = Some("p".repeat(padding));
    let boundary_ids: Vec<_> = state.shadow_queue.iter().map(|e| e.id).collect();
    Store::open(&home).unwrap().save(&state).unwrap();
    let refused = milvago_browser_agent::native::native_message(&home,
        json!({"op":"event_v2","event":event("boundary"),"caller":{"user":"u".repeat(128)}}));
    assert!(refused.is_err(), "OS attribution must fit before acknowledgement");
    let restored = Store::open(&home).unwrap().load().unwrap();
    assert_eq!(restored.shadow_queue.iter().map(|e|e.id).collect::<Vec<_>>(), boundary_ids);
    let mut broker_event = probe.shadow_queue[0].clone();
    broker_event.user = Some("u".repeat(128));
    let (broker_refused, _) = milvago_browser_agent::browser_broker::receive(&mut state,
        &json!({"caller":{"system":true},"installation":uuid::Uuid::new_v4(),
            "sequence":1,"event":broker_event}));
    assert!(broker_refused.is_err());
    assert!(state.browser_broker_receipt.is_none());
    assert_eq!(state.shadow_queue.iter().map(|e|e.id).collect::<Vec<_>>(), boundary_ids);

    // Construct a large backlog, prove admission beyond the old bound, then lower it.
    configured(&home, 1000, 20);
    config::open(&home);
    let seed = state.shadow_queue[0].clone();
    state.shadow_queue = (0..550).map(|_| {
        let mut event = seed.clone();
        event.id = uuid::Uuid::new_v4();
        event
    }).collect();
    assert!(shadow::queue_bytes(&state).unwrap() > 17 * 1024 * 1024);
    shadow::enqueue_browser(&mut state, event(&body)).unwrap();
    let ids: Vec<_> = state.shadow_queue.iter().map(|e|e.id).collect();
    Store::open(&home).unwrap().save(&state).unwrap();
    configured(&home, 1, 1);
    config::open(&home);
    state = Store::open(&home).unwrap().load().unwrap();
    assert_eq!(state.shadow_queue.iter().map(|e|e.id).collect::<Vec<_>>(), ids);
    assert!(shadow::enqueue_browser(&mut state, event("refused")).is_err());
    Store::open(&home).unwrap().save(&state).unwrap();
    let encrypted = std::fs::read(home.join("state.bin")).unwrap();
    assert!(!encrypted.windows(64).any(|chunk|chunk == &body.as_bytes()[..64]));
}

#[test]
fn queue_schema_defaults_bounds_and_malformed_values() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    std::fs::create_dir_all(config::directory(&home)).unwrap();
    let path = config::directory(&home).join("milvago.toml");
    for document in ["", "[queue]", "[queue]\nmax_events = 10000", "[queue]\nmax_size_mb = 8"] {
        std::fs::write(&path, document).unwrap();
        assert_eq!(config::load(&home), config::Config::default());
    }
    for document in ["max_events = 0", "max_events = 100001", "max_events = -1",
        "max_size_mb = 0", "max_size_mb = 129", "max_events = 1.5", "unknown = 2"] {
        std::fs::write(&path, format!("[queue]\n{document}")).unwrap();
        let parsed = config::load(&home);
        assert!(parsed.problem.is_some(), "{document}");
        assert_eq!(parsed.queue, config::QueueLimits::default());
    }
    configured(&home, 100000, 128);
    let parsed = config::load(&home);
    assert!(parsed.problem.is_none());
    assert_eq!(parsed.queue.max_bytes, 128 * 1024 * 1024);
    assert_eq!(parsed.queue.collector_share().max_events, 50000);
}
