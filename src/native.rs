use crate::{Result, Store, cached_policy, enqueue};
use serde_json::{Value, json};
#[cfg(feature = "model-control")]
#[path = "native_enterprise.rs"]
mod enterprise;

/// Shortest interval between two policy synchronizations triggered by an IPC
/// caller. The watch loop synchronizes every 60 s on its own; this only bounds
/// the repair path taken when no valid cached policy remains.
const RESYNC_COOLDOWN_SECONDS: i64 = 30;

/// OS account of the process behind the connection, stamped on every request by the
/// IPC layer, which overwrites whatever the client sent under `caller`. It is
/// therefore the operating system's word, never the browser's. Empty when the account
/// could not be determined, so a record is then simply left unattributed.
fn caller_user(request: &Value) -> Option<String> {
    let user = crate::session_user::sanitize(request["caller"]["user"].as_str()?);
    (!user.is_empty()).then_some(user)
}
/// Attribute a freshly queued record to the calling account, the way a native
/// record carries the profile it was collected from. Informational only: the
/// verified association remains the authority on identity.
fn attribute(state: &mut crate::State, id: uuid::Uuid, user: Option<String>) -> crate::Result<()> {
    if let Some(event) = state.shadow_queue.iter_mut().find(|event| event.id == id) {
        event.user = user;
    }
    if let Err(error) = crate::config::current().queue.check(state, 0, 0) {
        state.shadow_queue.pop();
        return Err(error);
    }
    Ok(())
}

/// Reduce a verified policy to what the browser extension actually consumes.
///
/// The IPC endpoint is reachable by every signed-in local user, so answering with
/// the whole policy handed each of them the organization's watched keywords, its
/// exceptions, its custom masking expressions and its block message. The extension
/// needs the service list, the collection switches, the model rules, and just
/// enough of the protection block to know that a local decision is required —
/// never the terms themselves. Keyword entries are therefore redacted while their
/// count is preserved, because the extension uses that count to keep network
/// control authoritative.
pub(crate) fn browser_policy(policy: &crate::shadow::ShadowPolicy) -> Value {
    let config = &policy.config;
    let mut out = json!({});
    for key in ["services", "collection", "model_access", "discovery"] {
        if let Some(value) = config.get(key) {
            out[key] = value.clone();
        }
    }
    let protection = &config["protection"];
    let keywords = protection["keywords"].as_array().map_or(0, Vec::len);
    out["protection"] = json!({
        "block_uploads": protection["block_uploads"].as_bool().unwrap_or(false),
        "exact": protection["exact"].clone(),
        "unicode": protection["unicode"].clone(),
        "fuzzy": protection["fuzzy"].clone(),
        "keywords": vec![Value::Null; keywords],
    });
    out["privacy"] = json!({"enabled": config["privacy"]["enabled"].as_bool().unwrap_or(false)});
    json!({
        "version": policy.version,
        "revision": policy.revision,
        "issued_at": policy.issued_at,
        // Local service lease; the server-signed envelope is never altered.
        "expires_at": chrono::Utc::now() + chrono::Duration::seconds(90),
        "signed_expires_at": policy.expires_at,
        "config": out,
    })
}
pub fn native_message(home: &std::path::Path, request: Value) -> Result<Value> {
    let op = request
        .get("op")
        .and_then(Value::as_str)
        .ok_or("missing operation")?;
    require_system_broker(op, &request)?;
    let store = Store::open(home)?;
    let mut state = store.load()?;
    // Any operation carrying a browser identifies a live extension. Recorded before
    // dispatch so a refused operation still proves the extension is running.
    if let Some(tool) = request["tool"].as_str() {
        if crate::shadow::observe_browser(&mut state, tool) {
            store.save(&state)?;
        }
    }
    match op {
        "broker_cache_source" => {
            crate::shadow::cached(&state)?;
            Ok(json!({"ok":true,"protocol":crate::browser_cache::PROTOCOL,"op":"cache_prepare",
                "origin":state.server_url.trim_end_matches('/'),"organization_anchor":state.public_key,
                "authorization_generation":state.authorization_generation,"policy":state.shadow_policy,"catalog":state.detection.envelope}))
        }
        "broker_event" => {
            // Saved only when something actually changed: the extension re-sends until it
            // sees its delivery acknowledged, so the duplicate-sequence path is the
            // common one, and re-encrypting the whole store for it was free work.
            let (reply,changed)=crate::browser_broker::receive(&mut state,&request);
            if changed { store.save(&state)?; }
            reply
        }
        // The privileged cache never persists a browser-supplied event directly.
        // The main agent validates and masks it with the complete signed policy,
        // then returns a provenance-bound, identity-free value for SYSTEM custody.
        "broker_prepare_event" => {
            if request.as_object().is_none_or(|object| object.keys().any(|key|
                !matches!(key.as_str(), "op" | "event" | "caller"))) {
                return Err("prepared event fields refused".into());
            }
            if crate::shadow::discard_unpermitted(&mut state) {
                store.save(&state)?;
            }
            let policy = crate::shadow::cached(&state)?;
            let input = request.get("event").ok_or("prepared event absent")?.clone();
            let input_hash = crate::browser_cache::hash(&serde_json::to_vec(&input)?);
            let mut event = crate::shadow::browser_event(&policy, state.detection.revision, input)?;
            event.id = uuid::Uuid::nil();
            event.user = None;
            Ok(json!({"ok":true,"event":event,"provenance":{
                "policy_revision":policy.revision,
                "policy_content_hash":crate::browser_cache::policy_content_hash(&policy)?,
                "authorization_generation":state.authorization_generation,
                "catalog_revision":state.detection.revision,
                "input_hash":input_hash
            }}))
        }
        // What the request said about an exchange already recorded. Both paths reach
        // the same rule: fill what is empty, never revise, never create an event. The
        // browser path names the event by the identity the agent itself handed back;
        // an identity it does not recognize designates nothing.
        "event_complete" | "broker_complete" => {
            let fields = request.get("completion").ok_or("missing completion")?;
            let completion = if op == "broker_complete" {
                crate::shadow::ShadowCompletion::parse(fields)?
            } else {
                // A delivery identity this account never used designates nothing: the
                // completion is dropped, never guessed and never turned into an event.
                let Some(id) = crate::detection::completed_delivery(&state, &request)? else {
                    return Ok(json!({"ok":true,"applied":false}));
                };
                crate::shadow::ShadowCompletion::parse_for(id, fields)?
            };
            crate::shadow::complete(&mut state, completion)?;
            store.save(&state)?;
            Ok(json!({"ok":true,"applied":true}))
        }
        "catalog" => {
            crate::shadow::cached(&state)?;
            Ok(crate::detection::browser(&state))
        }
        "detector_health" => {
            let batch = request.get("batch").ok_or("missing health batch")?;
            // Same reasoning as broker_event: a duplicate batch id queues nothing.
            if crate::detection::enqueue_health(&mut state,batch,request["tool"].as_str().unwrap_or(""))? {
                store.save(&state)?;
            }
            Ok(json!({"ok":true,"accepted_health_ids":[batch["id"]]}))
        }
        "policy_v2" | "policy_v3" => {
            let policy = crate::shadow::cached(&state)?;
            Ok(json!({"ok":true,"policy":browser_policy(&policy),"online":state.shadow_online,
                "cache_policy_hash": crate::browser_cache::envelope_hash(state.shadow_policy.as_ref().ok_or("cache source absent")?)?,
                "cache_authorization_generation":state.authorization_generation,
                "cache_policy_content_hash":crate::browser_cache::policy_content_hash(&policy)?,
                "cache_catalog_content_hash":state.detection.content_hash,"cache_catalog_revision":state.detection.revision}))
        }
        "inspect" | "broker_inspect" => {
            // Saving only when the queue actually changed: an inspection is the
            // hottest op on this channel and re-encrypting the whole queue on every
            // call, under the store's exclusive lock, is a machine-wide outage any
            // local user can ask for.
            if crate::shadow::discard_unpermitted(&mut state) {
                store.save(&state)?;
            }
            // The engine runs on the loaded copy, not under the exclusive lock.
            drop(store);
            let policy = crate::shadow::cached(&state)?;
            let inspection=inspect_request(&policy, &request)?;
            if op=="broker_inspect"{Ok(json!({"ok":true,"inspection":inspection,"policy_content_hash":crate::browser_cache::policy_content_hash(&policy)?}))}
            else{Ok(inspection)}
        }
        // Pre-send control of the agentic command-line tools is an Enterprise
        // capability, and Community's server refuses a native record outright.
        #[cfg(not(feature = "model-control"))]
        "inspect_cli" => Err("command-line control unavailable in this edition".into()),
        #[cfg(feature = "model-control")]
        "inspect_cli" => enterprise::inspect_cli(home, &request, store, state),
        // Enforcement reports only exist for per-model control.
        #[cfg(not(feature = "model-control"))]
        "enforcement" => Err("model control unavailable in this edition".into()),
        #[cfg(feature = "model-control")]
        "enforcement" => enterprise::enforcement(&request, store, state),
        "event_v2" => {
            let event = request.get("event").ok_or("missing event")?.clone();
            if let Some(id)=crate::detection::delivery_receipt(&state,&request,&event)? {
                return Ok(json!({"ok":true,"id":id,"delivered":0}));
            }
            let queued = crate::shadow::enqueue_browser(&mut state, event.clone()).and_then(|id| {
                attribute(&mut state, id, caller_user(&request))?;
                Ok(id)
            });
            // A refused event changes nothing worth a rewrite of the whole store.
            let id = queued?;
            crate::detection::remember_delivery(&mut state,&request,&event,id)?;
            store.save(&state)?;
            drop(store);
            // A durable local receipt never waits for a server round trip.
            let delivered = 0;
            Ok(json!({"ok":true,"id":id,"delivered":delivered}))
        }
        "associate" => {
            let now = chrono::Utc::now();
            if state.association_attempted_at
                .is_some_and(|last| last <= now && now - last < chrono::Duration::seconds(5)) {
                return Err("association cooldown".into());
            }
            state.association_attempted_at = Some(now);
            store.save(&state)?;
            drop(store);
            let reply = crate::shadow::association(&state)?;
            Ok(json!({"ok":true,"association":reply}))
        }
        "policy" => {
            drop(store);
            let _ = crate::shadow::refresh_legacy_home(home, chrono::Duration::seconds(RESYNC_COOLDOWN_SECONDS));
            let state = { Store::open(home)?.load()? };
            let policy = cached_policy(&state)?;
            Ok(json!({"ok":true,"policy":policy,"online":state.shadow_online}))
        }
        "event" => {
            let provider = request
                .get("provider")
                .and_then(Value::as_str)
                .ok_or("missing provider")?;
            let characters = request
                .get("characters")
                .and_then(Value::as_u64)
                .ok_or("missing character count")?;
            if request
                .as_object()
                .ok_or("object required")?
                .keys()
                .any(|k| !matches!(k.as_str(), "op" | "provider" | "characters"))
            {
                return Err("unexpected event field".into());
            }
            let id = enqueue(&mut state, provider, characters.try_into()?)?;
            store.save(&state)?;
            // Queue durability precedes any network attempt; failures retain events.
            drop(store);
            let delivered = crate::shadow::flush_home(home, true, chrono::Duration::seconds(5)).unwrap_or(0);
            Ok(json!({"ok":true,"id":id,"delivered":delivered}))
        }
        "status" => Ok(
            json!({"ok":true,"enrolled":!state.credential.is_empty(),"queued":state.queue.len()+state.shadow_queue.len(),"edition":"community","scope":"browser","protocol":3}),
        ),
        _ => Err("unsupported browser operation".into()),
    }
}

fn require_system_broker(op: &str, request: &Value) -> Result<()> {
    if matches!(
        op,
        "broker_event"
            | "broker_prepare_event"
            | "broker_cache_source"
            | "broker_inspect"
            | "broker_complete"
    ) && request["caller"]["system"] != true
    {
        return Err("broker operation requires SYSTEM".into());
    }
    Ok(())
}
// Each edition ships its own extension package, so each binary authenticates its own
// caller. Accepting both identities would let the other edition's extension drive
// this bridge, which is exactly what the split is meant to prevent.
#[cfg(not(feature = "enterprise-extension"))]
const EXTENSION_ID: &str = include_str!("../extension-id.txt");
#[cfg(not(feature = "enterprise-extension"))]
const FIREFOX_ID: &str = "browser-community@milvago.app";
#[cfg(feature = "enterprise-extension")]
const EXTENSION_ID: &str = include_str!("../extension-id-enterprise.txt");
#[cfg(feature = "enterprise-extension")]
const FIREFOX_ID: &str = "browser-enterprise@milvago.app";

pub fn browser_caller(args: &[String]) -> bool {
    let id = EXTENSION_ID.trim();
    args.first()
        .is_some_and(|s| s == &format!("chrome-extension://{id}/"))
        || args.get(1).is_some_and(|s| s == FIREFOX_ID)
}

#[cfg(test)]
mod tests {
    use super::{browser_policy, require_system_broker};
    use serde_json::json;

    fn policy(config: serde_json::Value) -> crate::shadow::ShadowPolicy {
        crate::shadow::ShadowPolicy {
            version: 3,
            revision: 7,
            issued_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(15),
            config,
            capabilities: vec!["native".into()],
        }
    }

    #[test]
    fn browser_answer_withholds_detection_secrets() {
        let out = browser_policy(&policy(json!({
            "collection": {"enabled": true, "store_content": false},
            "services": [{"id": "chatgpt", "domains": ["chatgpt.com"], "mode": "observe", "enabled": true}],
            "protection": {
                "block_uploads": true,
                "exact": "block",
                "unicode": "observe",
                "fuzzy": "off",
                "keywords": ["projet-interne", "codename"],
                "exceptions": ["projet-public"],
                "message": "Interdit par votre organisation."
            },
            "privacy": {"enabled": true, "review": false, "types": ["email"], "custom_rules": [{"name": "matricule", "pattern": "[0-9]{9}"}]},
            "classification": {"browser": ["iban"], "coding": [], "medical_terms": ["diagnostic"]}
        })));
        let text = out.to_string();
        for secret in [
            "projet-interne",
            "codename",
            "projet-public",
            "Interdit par votre organisation.",
            "[0-9]{9}",
            "matricule",
            "diagnostic",
            "iban",
        ] {
            assert!(!text.contains(secret), "browser answer leaked {secret}");
        }
        assert!(out["config"].get("classification").is_none());
        assert!(out["config"]["protection"].get("exceptions").is_none());
        assert!(out["config"]["protection"].get("message").is_none());
        assert!(out["config"]["privacy"].get("types").is_none());
        assert!(out["config"]["privacy"].get("custom_rules").is_none());
    }

    #[test]
    fn broker_preparation_is_reserved_to_system() {
        let request = json!({"caller":{"system":false}});
        assert!(require_system_broker("broker_prepare_event", &request).is_err());
        assert!(require_system_broker("broker_event", &request).is_err());
        assert!(require_system_broker("policy_v3", &request).is_ok());
        let system = json!({"caller":{"system":true}});
        assert!(require_system_broker("broker_prepare_event", &system).is_ok());
    }

    #[test]
    fn browser_answer_keeps_what_the_extension_decides_with() {
        let out = browser_policy(&policy(json!({
            "collection": {"enabled": true, "store_content": true},
            "services": [{"id": "claude", "domains": ["claude.ai"], "mode": "block", "enabled": true}],
            "protection": {"block_uploads": true, "exact": "block", "unicode": "observe", "fuzzy": "off", "keywords": ["a", "b", "c"]},
            "privacy": {"enabled": true, "types": [], "custom_rules": []},
            "model_access": [{"platform_id": "claude", "channel": "browser", "mode": "allowlist", "models": ["claude-opus-4"]}]
        })));
        assert_eq!(out["version"], 3);
        assert_eq!(out["revision"], 7);
        assert_eq!(out["config"]["services"][0]["domains"][0], "claude.ai");
        assert_eq!(out["config"]["collection"]["store_content"], true);
        assert_eq!(out["config"]["model_access"][0]["models"][0], "claude-opus-4");
        assert_eq!(out["config"]["protection"]["block_uploads"], true);
        assert_eq!(out["config"]["protection"]["exact"], "block");
        assert_eq!(out["config"]["privacy"]["enabled"], true);
        // The count is what keeps network control authoritative; the terms are not.
        assert_eq!(out["config"]["protection"]["keywords"].as_array().unwrap().len(), 3);
        assert!(out["config"]["protection"]["keywords"]
            .as_array()
            .unwrap()
            .iter()
            .all(serde_json::Value::is_null));
    }

    #[test]
    fn browser_answer_omits_a_model_rule_the_edition_never_carries() {
        let out = browser_policy(&policy(json!({
            "collection": {"enabled": true, "store_content": false},
            "services": [],
            "protection": {"keywords": []},
            "privacy": {"enabled": false}
        })));
        assert!(out["config"].get("model_access").is_none());
    }
}

pub(crate) fn inspect_request(policy: &crate::shadow::ShadowPolicy, request: &Value) -> Result<Value> {
    inspect_request_inner(policy,request,false)
}
pub(crate) fn inspect_authorized_request(policy: &crate::shadow::ShadowPolicy, request: &Value) -> Result<Value> {
    inspect_request_inner(policy,request,true)
}
fn inspect_request_inner(policy: &crate::shadow::ShadowPolicy, request: &Value, _lease_authorized:bool) -> Result<Value> {
            let text = request["text"].as_str().ok_or("missing inspection text")?;
            let provider = request["provider"].as_str().ok_or("missing provider")?;
            #[cfg_attr(not(feature = "model-control"), allow(unused_mut))]
            let mut inspection = crate::shadow::inspect(
                policy,
                text,
                provider,
                request["upload"].as_bool().unwrap_or(false),
            )?;
            // Per-model control is an Enterprise capability: the Community agent
            // contains no model decision, so it refuses to answer the question.
            #[cfg(not(feature = "model-control"))]
            if request["check_model"] == true {
                return Err("model control unavailable in this edition".into());
            }
            #[cfg(feature = "model-control")]
            if request["check_model"] == true {
                enterprise::check_model(policy, request, provider, _lease_authorized, &mut inspection)?;
            }
    Ok(serde_json::to_value(inspection)?)
}
