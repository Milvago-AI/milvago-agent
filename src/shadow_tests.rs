use crate::{Envelope, State, Store, shadow::*};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;

fn prepared(content: bool) -> State {
    let key = SigningKey::from_bytes(&[29; 32]);
    let now = Utc::now();
    let policy = ShadowPolicy {
        version: 2,
        revision: 1,
        issued_at: now,
        expires_at: now + chrono::Duration::minutes(10),
        capabilities: vec![],
        config: json!({"collection":{"enabled":true,"store_content":content},"services":[{"domains":["chatgpt.com"],"enabled":true,"mode":"observe"}],"protection":{"keywords":["confidential"],"exact":"block","unicode":"block","fuzzy":"block","exceptions":[],"message":"Envoi bloqué"},"privacy":{"enabled":true,"review":true,"types":["email"],"custom_rules":[]}}),
    };
    let bytes = serde_json::to_vec(&policy).unwrap();
    let env = Envelope {
        payload: STANDARD.encode(&bytes),
        signature: STANDARD.encode(key.sign(&bytes).to_bytes()),
    };
    State {
        public_key: STANDARD.encode(key.verifying_key().as_bytes()),
        shadow_policy: Some(env),
        shadow_revision: 1,
        ..State::default()
    }
}
// The policy config as signed, with `blocked_platforms` set to the given value.
fn with_blocked(blocked: serde_json::Value) -> State {
    let key = SigningKey::from_bytes(&[29; 32]);
    let now = Utc::now();
    let policy = ShadowPolicy {
        version: 3, revision: 1, issued_at: now, expires_at: now + chrono::Duration::minutes(10), capabilities: vec![],
        config: json!({"collection":{"enabled":true},"services":[],"blocked_platforms":blocked}),
    };
    let bytes = serde_json::to_vec(&policy).unwrap();
    let env = Envelope { payload: STANDARD.encode(&bytes), signature: STANDARD.encode(key.sign(&bytes).to_bytes()) };
    State { public_key: STANDARD.encode(key.verifying_key().as_bytes()), shadow_policy: Some(env), shadow_revision: 1, ..State::default() }
}
#[test]
fn blocked_platforms_are_held_to_the_catalogue_grammar() {
    assert!(cached(&with_blocked(json!([{"id":"mammouth","domains":["mammouth.ai"]},{"id":"github-copilot","domains":["github.com"],"paths":["/copilot*"]}]))).is_ok());
    for bad in [
        json!("mammouth.ai"),
        json!([{"id":"Mammouth","domains":["mammouth.ai"]}]),
        json!([{"id":"mammouth","domains":[]}]),
        json!([{"id":"mammouth","domains":["not a host"]}]),
        json!([{"id":"mammouth","domains":["mammouth.ai"],"paths":["copilot"]}]),
        json!([{"id":"mammouth","domains":["mammouth.ai"],"regex":".*"}]),
    ] {
        assert!(cached(&with_blocked(bad.clone())).is_err(), "accepted {bad}");
    }
}
#[test]
fn a_presence_record_may_say_the_visit_was_blocked() {
    let mut state = prepared(false);
    let presence = json!({"kind":"navigation","provider":"mammouth.ai","source":"browser","tool":"chrome","action":"blocked","characters":0,"labels":[],"detector":"presence"});
    assert!(enqueue_browser(&mut state, presence).is_ok());
    let redirected = json!({"kind":"navigation","provider":"mammouth.ai","source":"browser","tool":"chrome","action":"redirected","characters":0,"labels":[],"detector":"presence"});
    assert!(enqueue_browser(&mut state, redirected).is_err());
}
fn input() -> serde_json::Value {
    json!({"kind":"prompt","provider":"chatgpt.com","source":"browser","tool":"chrome","action":"observed","characters":12,"labels":[],"prompt":"synthetic local text"})
}
#[test]
fn overlapping_masks_remove_entire_union() {
    let mut p = cached(&prepared(true)).unwrap();
    p.config["privacy"]["custom_rules"] =
        json!([{"enabled":true,"pattern":"abcde"},{"enabled":true,"pattern":"defgh"}]);
    let result = inspect(&p, "abcdefgh tail", "chatgpt.com", false).unwrap();
    assert_eq!(result.text, "[custom] tail");
}
// Product decision of 2026-09-16: the marker carries the rule's label, and each
// additional distinct value receives one more number — the same value keeps its own.
#[test]
fn placeholders_carry_the_rule_label_and_number_distinct_values() {
    let mut p = cached(&prepared(true)).unwrap();
    p.config["privacy"]["types"] = json!(["ip", "email"]);
    p.config["privacy"]["custom_rules"] = json!([{"enabled":true,"label":"NUMERO","pattern":"\\b[0-9]\\b"}]);
    // Documentation addresses (RFC 5737), never a private range.
    let one = inspect(&p, "hôte 192.0.2.1 joignable", "chatgpt.com", false).unwrap();
    assert_eq!(one.text, "hôte [IP] joignable");
    let two = inspect(&p, "de 192.0.2.1 vers 192.0.2.2 puis 192.0.2.1", "chatgpt.com", false).unwrap();
    assert_eq!(two.text, "de [IP1] vers [IP2] puis [IP1]");
    let custom = inspect(&p, "valeurs 1 et 5 puis 1", "chatgpt.com", false).unwrap();
    assert_eq!(custom.text, "valeurs [NUMERO1] et [NUMERO2] puis [NUMERO1]");
    assert!(custom.labels.contains(&"custom".into()), "event labels keep the category identifier");
    let mixed = inspect(&p, "member@example.test et 7", "chatgpt.com", false).unwrap();
    assert_eq!(mixed.text, "[EMAIL] et [NUMERO]");
}
#[test]
fn numeric_checks_reduce_false_positives() {
    let p = cached(&prepared(false)).unwrap();
    let invalid = inspect(&p, "999.999.999.999 4111111111111112", "chatgpt.com", false).unwrap();
    assert!(!invalid.labels.contains(&"ip".into()));
    assert!(!invalid.labels.contains(&"card".into()));
    let valid = inspect(&p, "192.0.2.1 4111111111111111", "chatgpt.com", false).unwrap();
    assert!(valid.labels.contains(&"ip".into()));
    assert!(valid.labels.contains(&"card".into()));
}
#[test]
fn classification_uses_scope_selection() {
    let mut p = cached(&prepared(false)).unwrap();
    p.config["classification"] = json!({"browser":[],"coding":["source_code"]});
    assert!(
        inspect(&p, "fn example() {}", "chatgpt.com", false)
            .unwrap()
            .labels
            .is_empty()
    );
    assert_eq!(
        inspect_scope(&p, "fn example() {}", "chatgpt.com", false, "coding")
            .unwrap()
            .labels,
        vec!["source_code"]
    );
}
#[test]
fn firefox_requires_verified_extension_argument_position() {
    let (expected, other) = if cfg!(feature = "enterprise-extension") {
        ("browser-enterprise@milvago.app", "browser-community@milvago.app")
    } else {
        ("browser-community@milvago.app", "browser-enterprise@milvago.app")
    };
    assert!(crate::native::browser_caller(&[
        "C:/host.json".into(),
        expected.into()
    ]));
    assert!(!crate::native::browser_caller(&[
        "C:/host.json".into(),
        other.into()
    ]));
    assert!(!crate::native::browser_caller(&[
        "C:/host.json".into(),
        "foreign@example.test".into()
    ]));
}
#[test]
fn content_off_strips_body_and_preserves_metadata() {
    let mut s = prepared(false);
    enqueue_browser(&mut s, input()).unwrap();
    assert!(s.shadow_queue[0].prompt.is_none());
    assert_eq!(s.shadow_queue[0].kind, "prompt");
}
#[test]
fn normalization_and_fuzzy_enforcement() {
    let s = prepared(false);
    let p = cached(&s).unwrap();
    for text in [
        "confidential",
        "cоnfidential",
        "confidentiаl",
        "confidentia1",
    ] {
        assert_eq!(
            inspect(&p, text, "chatgpt.com", false).unwrap().action,
            "block"
        );
    }
}
#[test]
fn review_returns_only_masked_text() {
    let p = cached(&prepared(true)).unwrap();
    let r = inspect(&p, "Contact member@example.test", "chatgpt.com", false).unwrap();
    assert_eq!(r.action, "review");
    assert!(!r.text.contains("member@"));
    assert!(r.labels.contains(&"email".into()));
}
#[test]
fn browser_path_rejects_native_source_and_spoofed_identity() {
    let mut s = prepared(true);
    let mut e = input();
    e["source"] = json!("native");
    assert!(enqueue_browser(&mut s, e).is_err());
    let mut e = input();
    e["actor_id"] = json!("someone-else");
    assert!(enqueue_browser(&mut s, e).is_err());
}
#[test]
fn new_policy_disables_unsent_body() {
    let mut s = prepared(true);
    enqueue_browser(&mut s, input()).unwrap();
    assert!(s.shadow_queue[0].prompt.is_some());
    let off = prepared(false);
    s.shadow_policy = off.shadow_policy;
    discard_unpermitted(&mut s);
    assert!(s.shadow_queue[0].prompt.is_none());
}
#[test]
fn expired_permission_strips_unsent_body() {
    let mut s = prepared(true);
    enqueue_browser(&mut s, input()).unwrap();
    s.shadow_policy = None;
    discard_unpermitted(&mut s);
    assert!(s.shadow_queue[0].prompt.is_none());
    assert!(enqueue_browser(&mut s, input()).is_err());
}
#[test]
fn shadow_signature_and_expiration_are_verified() {
    let s = prepared(true);
    let env = s.shadow_policy.as_ref().unwrap();
    assert!(verify(env, &s.public_key, 2, Utc::now()).is_err());
    assert!(
        verify(
            env,
            &s.public_key,
            1,
            Utc::now() + chrono::Duration::hours(1)
        )
        .is_err()
    );
    let mut fake = env.clone();
    fake.payload = STANDARD.encode(b"{}");
    assert!(verify(&fake, &s.public_key, 1, Utc::now()).is_err());
}
#[test]
fn navigation_has_no_conversation_content_or_private_query() {
    assert_eq!(
        normalized_url(
            "https://chatgpt.com/c/private-id?secret=value#fragment",
            "chatgpt.com"
        )
        .unwrap(),
        "https://chatgpt.com/"
    );
    assert!(normalized_url("https://malicious.test/", "chatgpt.com").is_err());
    let mut s = prepared(true);
    let mut e = input();
    e["kind"] = json!("navigation");
    assert!(enqueue_browser(&mut s, e).is_err());
}
#[test]
fn content_queue_is_encrypted_on_disk() {
    let d = tempfile::tempdir().unwrap();
    let st = Store::open(d.path()).unwrap();
    let mut s = prepared(true);
    enqueue_browser(&mut s, input()).unwrap();
    st.save(&s).unwrap();
    let bytes = std::fs::read(d.path().join("state.bin")).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("synthetic local text"));
    assert_eq!(st.load().unwrap().shadow_queue.len(), 1);
}

// Anti-evasion of the keyword protection. The previous normalization carried eight
// hand-written homoglyph substitutions and neither folded diacritics nor neutralized
// separators, so a term typed with two Cyrillic letters, with an added accent, or
// spaced out went straight through.
#[test]
fn keyword_protection_survives_obfuscation() {
    let p = cached(&prepared(false)).unwrap();
    let blocked = |text: &str| {
        let out = inspect(&p, text, "chatgpt.com", false).unwrap();
        out.action == "block" && out.labels.contains(&"keyword".to_string())
    };
    assert!(blocked("ceci est confidential"), "plain term missed");
    // Two Cyrillic homoglyphs at once: one used to be absorbed by the fuzzy tier,
    // two put the word out of edit distance one.
    assert!(blocked("ceci est cоnfidentiаl"), "multiple homoglyphs missed");
    // Diacritics were never folded at all.
    assert!(blocked("ceci est confidentiál"), "diacritic missed");
    // Separator insertion defeated both the substring search and the per-word
    // edit distance, which compared the whole term to single characters.
    assert!(blocked("ceci est c o n f i d e n t i a l"), "spaced term missed");
    assert!(blocked("ceci est c-o-n-f-i-d-e-n-t-i-a-l"), "dashed term missed");
    // Invisible characters, including the bidirectional controls.
    assert!(blocked("ceci est conf\u{200b}ident\u{202e}ial"), "invisible characters missed");
    assert!(!blocked("ceci est parfaitement ordinaire"), "false positive on ordinary text");
}

#[test]
fn keyword_match_reports_the_form_actually_typed() {
    let p = cached(&prepared(false)).unwrap();
    // The excerpt is the source substring, not the configured term: an analyst must
    // see the obfuscated form. It never leaves the device.
    let out = inspect(&p, "ceci est cоnfidentiаl ici", "chatgpt.com", false).unwrap();
    assert_eq!(out.evidence.as_deref(), Some("cоnfidentiаl"));
    let spaced = inspect(&p, "ceci est c o n f i d e n t i a l ici", "chatgpt.com", false).unwrap();
    assert_eq!(spaced.evidence.as_deref(), Some("c o n f i d e n t i a l"));
    let clean = inspect(&p, "rien a signaler", "chatgpt.com", false).unwrap();
    assert_eq!(clean.evidence, None);
}

#[test]
fn a_short_term_is_not_matched_across_removed_separators() {
    let mut p = cached(&prepared(false)).unwrap();
    p.config["protection"]["keywords"] = json!(["abc"]);
    // Removing every separator glues neighbouring words together, so a very short
    // term would match almost any text. Below four characters the compact view is
    // not consulted.
    let out = inspect(&p, "a b c", "chatgpt.com", false).unwrap();
    assert!(!out.labels.contains(&"keyword".to_string()));
}

#[test]
fn source_code_needs_more_than_one_indicator() {
    let mut p = cached(&prepared(false)).unwrap();
    p.config["classification"] = json!({"browser":["source_code"],"coding":[]});
    let labelled = |text: &str| {
        inspect(&p, text, "chatgpt.com", false)
            .unwrap()
            .labels
            .contains(&"source_code".to_string())
    };
    // One substring used to be enough, so any sentence containing "import" was
    // reported as source code.
    assert!(!labelled("Il faut import er ce dossier avant vendredi."));
    assert!(!labelled("Voir https://example.test/fn pour la suite."));
    assert!(labelled("fn example() {}"));
    assert!(labelled("import os\nclass Report:\n    return None"));
}

#[test]
fn one_medical_term_is_not_a_medical_record() {
    let mut p = cached(&prepared(false)).unwrap();
    p.config["classification"] = json!({"browser":["medical"],"coding":[],"medical_terms":["irm","diagnostic","ordonnance"]});
    let labelled = |text: &str| {
        inspect(&p, text, "chatgpt.com", false)
            .unwrap()
            .labels
            .contains(&"medical".to_string())
    };
    assert!(!labelled("J'ai rendez-vous pour une IRM mardi."));
    assert!(labelled("Diagnostic pose apres IRM, ordonnance jointe."));
}

// The command-line hook runs as the user, on a channel every signed-in user can
// write to. It supplies the text and which of the two tools; everything that gives a
// record its meaning is decided by the agent.
#[test]
fn a_refusal_record_takes_nothing_from_its_caller() {
    let mut state = prepared(true);
    let id = enqueue_refusal(&mut state, "codex", "confidential", 12, vec!["keyword".into()]).unwrap();
    let event = state.shadow_queue.last().unwrap();
    assert_eq!(event.id, id);
    assert_eq!(event.source, "native");
    assert_eq!(event.kind, "prompt");
    assert_eq!(event.action, "blocked");
    assert_eq!(event.provider, "chatgpt.com");
    assert_eq!(event.tool, "codex");
    assert_eq!(event.characters, 12);
    assert!(event.files.is_empty());
    assert!(event.user.is_none());
}

// One vocabulary for acceptance and for the liveness map: every browser the agent
// can report as present must be able to deliver an event (Brave could not, silently).
#[test]
fn every_browser_the_agent_reports_can_deliver_events() {
    for tool in BROWSER_TOOLS {
        let mut s = prepared(false);
        let mut e = input();
        e["tool"] = json!(tool);
        enqueue_browser(&mut s, e).unwrap_or_else(|error| panic!("{tool}: {error}"));
        assert_eq!(s.shadow_queue[0].tool, tool);
    }
    let mut s = prepared(false);
    let mut e = input();
    e["tool"] = json!("safari");
    assert!(enqueue_browser(&mut s, e).is_err());
    assert!(s.shadow_queue.is_empty());
}

#[test]
fn a_refusal_record_is_refused_for_an_unknown_tool() {
    let mut state = prepared(false);
    assert!(enqueue_refusal(&mut state, "editor", "text", 4, vec![]).is_err());
    assert!(state.shadow_queue.is_empty());
}

// A browser record belongs to the account behind the connection. The IPC layer
// stamps it under `caller`; the agent sanitizes it like the heartbeat's OS user, an
// undetermined account leaves the record unattributed, and the extension's own word
// — `user` inside the event — is refused as before.
#[test]
fn browser_records_carry_the_calling_account_stamped_by_the_agent() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    store.save(&prepared(false)).unwrap();
    drop(store);
    crate::native::native_message(dir.path(), json!({"op":"event_v2","event":input(),"caller":{"user":"  alice\t "}})).unwrap();
    crate::native::native_message(dir.path(), json!({"op":"event_v2","event":input(),"caller":{"user":""}})).unwrap();
    let mut spoofed = json!({"op":"event_v2","event":input(),"caller":{"user":"bob"}});
    spoofed["event"]["user"] = json!("mallory");
    assert!(crate::native::native_message(dir.path(), spoofed).is_err());
    let state = Store::open(dir.path()).unwrap().load().unwrap();
    assert_eq!(state.shadow_queue.len(), 2);
    assert_eq!(state.shadow_queue[0].user.as_deref(), Some("alice"));
    assert_eq!(state.shadow_queue[1].user, None);
}

// The service the tool talks to has to be one the policy covers.
#[test]
fn a_refusal_record_is_refused_for_a_service_the_policy_does_not_cover() {
    let mut state = prepared(false);
    assert!(enqueue_refusal(&mut state, "claude-code", "text", 4, vec![]).is_err());
    assert!(state.shadow_queue.is_empty());
}

// A presence record names a platform the catalogue does NOT cover, so it is never an
// enabled service and the ordinary service check would refuse it. What replaces that check
// is a fixed shape: the host was reached, and nothing else. Which hosts actually count
// stays the server's decision, against the signed catalogue it holds.
#[test]
fn a_presence_record_may_name_an_uncovered_platform_and_nothing_else() {
    let mut state = prepared(false);
    let presence = |extra: serde_json::Value| {
        let mut event = json!({"kind":"navigation","provider":"aggregator.example.invalid","source":"browser","tool":"chrome","action":"observed","characters":0,"labels":[],"detector":"presence"});
        for (key, value) in extra.as_object().unwrap() {
            event[key] = value.clone();
        }
        event
    };
    let accepted = enqueue_browser(&mut state, presence(json!({}))).unwrap();
    let stored = state.shadow_queue.last().unwrap();
    assert_eq!(stored.id, accepted);
    assert_eq!(stored.provider, "aggregator.example.invalid");
    assert_eq!(stored.detector.as_deref(), Some("presence"));
    assert!(stored.url.is_none() && stored.prompt.is_none());
    // Anything beyond the host is refused here rather than trimmed, so a modified
    // endpoint learns that the shape is wrong instead of having part of it accepted.
    for extra in [
        json!({"url":"https://aggregator.example.invalid/c/secret"}),
        json!({"conversation_id":"secret-conversation"}),
        json!({"characters":42}),
        json!({"prompt":"a prompt"}),
        json!({"model":"some-model"}),
        json!({"files":["payroll.xlsx"]}),
        json!({"labels":["email"]}),
        json!({"kind":"prompt"}),
    ] {
        let mut fresh = prepared(false);
        assert!(
            enqueue_browser(&mut fresh, presence(extra.clone())).is_err(),
            "a presence record carrying {extra} was accepted"
        );
    }
    // And the ordinary path is untouched: an uncovered host without the presence detector
    // is still refused for not being an enabled service.
    let mut ordinary = prepared(false);
    assert!(enqueue_browser(&mut ordinary, json!({"kind":"prompt","provider":"aggregator.example.invalid","source":"browser","tool":"chrome","action":"observed","characters":12,"labels":[]})).is_err());
}

#[test]
fn a_refusal_record_withholds_the_text_unless_the_policy_retains_it() {
    let mut state = prepared(false);
    enqueue_refusal(&mut state, "codex", "confidential", 12, vec![]).unwrap();
    assert!(state.shadow_queue.last().unwrap().prompt.is_none());
    let mut retaining = prepared(true);
    enqueue_refusal(&mut retaining, "codex", "confidential", 12, vec![]).unwrap();
    assert_eq!(retaining.shadow_queue.last().unwrap().prompt.as_deref(), Some("confidential"));
}
