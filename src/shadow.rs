use crate::{Envelope, Result, State};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::HashSet, io::Read};
use uuid::Uuid;
use zeroize::Zeroize;

const TEXT_LIMIT: usize = 32 * 1024;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RejectedEvent {
    pub id: Uuid,
    pub reason: String,
}

fn quarantine(state: &mut State, ids: &[Uuid], reason: &str) {
    let entries: Vec<_> = ids.iter().map(|id| (*id, reason.to_owned())).collect();
    quarantine_reasons(state, &entries);
}

fn quarantine_reasons(state: &mut State, entries: &[(Uuid, String)]) {
    let queued: HashSet<_> = state.shadow_queue.iter().map(|event| event.id).collect();
    let mut seen = HashSet::new();
    let quarantined: Vec<_> = entries
        .iter()
        .filter(|(id, _)| queued.contains(id) && seen.insert(*id))
        .cloned()
        .collect();
    let quarantined_ids: HashSet<_> = quarantined.iter().map(|(id, _)| *id).collect();
    state.rejected_events.retain(|event| !quarantined_ids.contains(&event.id));
    for (id, reason) in quarantined {
        state.rejected_events.push(RejectedEvent { id, reason });
    }
    state.shadow_queue.retain_mut(|e| {
        if quarantined_ids.contains(&e.id) {
            e.discard_content();
            false
        } else { true }
    });
    let excess = state.rejected_events.len().saturating_sub(100);
    state.rejected_events.drain(..excess);
}

fn clean_metadata(value: &str) -> bool {
    value.len() <= 200 && value.trim() == value && !value.chars().any(char::is_control)
}

/// Intrinsic transport validation only. Clock skew and age are left to the server;
/// a transient local clock change must not discard an offline queue.
fn valid_queued_event(event: &ShadowEvent) -> bool {
    [&event.model, &event.effort, &event.conversation_id, &event.correlation_id]
        .iter().all(|v| v.as_deref().is_none_or(clean_metadata))
        && event.user.as_deref().is_none_or(|u| u.len() <= 128 && u.trim() == u && !u.chars().any(char::is_control))
        && event.policy_revision > 0
        && event.files.len() <= 20
        && (event.files.is_empty() || event.kind == "prompt")
        && event.files.iter().all(|s| !s.is_empty() && s.len() <= 200 && !s.chars().any(char::is_control))
        && event.prompt.as_ref().is_none_or(|s| event.kind == "prompt" && s.len() <= TEXT_LIMIT)
        && event.response.as_ref().is_none_or(|s| event.kind == "response" && s.len() <= TEXT_LIMIT)
}
pub const QUEUE_BYTES_LIMIT: usize = 8 * 1024 * 1024;
const EVENT_BYTES_LIMIT: usize = 96 * 1024;
// Count serialized bytes without allocating another plaintext copy of message bodies.
pub fn serialized_size<T: Serialize + ?Sized>(value: &T) -> Result<usize> {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len());
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, value)?;
    Ok(counter.0)
}
pub fn queue_bytes(state: &State) -> Result<usize> {
    Ok(serialized_size(&state.queue)? + serialized_size(&state.shadow_queue)?)
}
pub fn fit_event(event: &mut ShadowEvent) -> Result<usize> {
    if event.prompt.as_ref().is_some_and(|s| s.len() > TEXT_LIMIT)
        || event
            .response
            .as_ref()
            .is_some_and(|s| s.len() > TEXT_LIMIT)
        || serialized_size(event)? > EVENT_BYTES_LIMIT
    {
        event.discard_content();
    }
    let size = serialized_size(event)?;
    if size > EVENT_BYTES_LIMIT {
        return Err("event metadata exceeds limit".into());
    }
    Ok(size + 1)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowPolicy {
    pub version: u32,
    pub revision: u64,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub config: Value,
    #[serde(default)]
    pub capabilities: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowEvent {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detector: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog_revision: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_bytes: Option<u64>,
    #[serde(default = "characters_known_default")]
    pub characters_known: bool,
    pub id: Uuid,
    pub kind: String,
    pub occurred_at: DateTime<Utc>,
    pub provider: String,
    pub source: String,
    pub tool: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// The reasoning effort the request asked for, stated separately by the provider
    /// and kept separate here: the page only ever shows it fused into a translated
    /// model label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effort: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub action: String,
    pub characters: u32,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<String>,
    /// Names of the files attached to the request. Names only, never contents, and
    /// only while the signed policy asks for them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<String>,
    /// OS account the record belongs to, on a machine where several people sign in:
    /// the profile a native record was collected from, or the account of the browser
    /// process behind the IPC connection for a browser record. Stamped by the agent —
    /// never taken from the extension — and informational: the verified association
    /// stays the only authority on identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    pub policy_revision: u64,
}
fn characters_known_default() -> bool { true }
impl ShadowEvent {
    pub fn discard_content(&mut self) {
        if let Some(mut s) = self.prompt.take() {
            s.zeroize();
        }
        if let Some(mut s) = self.response.take() {
            s.zeroize();
        }
    }
}
pub fn verify(
    envelope: &Envelope,
    key: &str,
    minimum: u64,
    now: DateTime<Utc>,
) -> Result<ShadowPolicy> {
    verify_cached(envelope, key, minimum, now, false)
}

// Only an envelope already admitted to the encrypted local store may outlive
// its refresh deadline. New network documents must still be fresh.
fn verify_cached(
    envelope: &Envelope,
    key: &str,
    minimum: u64,
    now: DateTime<Utc>,
    allow_expired: bool,
) -> Result<ShadowPolicy> {
    if envelope.payload.len() > 128 * 1024 {
        return Err("policy exceeds limit".into());
    }
    let public: [u8; 32] = STANDARD
        .decode(key)?
        .try_into()
        .map_err(|_| "invalid signing key")?;
    let bytes = STANDARD.decode(&envelope.payload)?;
    VerifyingKey::from_bytes(&public)?.verify_strict(
        &bytes,
        &Signature::from_slice(&STANDARD.decode(&envelope.signature)?)?,
    )?;
    let p: ShadowPolicy = serde_json::from_slice(&bytes)?;
    if !matches!(p.version, 2 | 3)
        || p.revision < minimum
        || (!allow_expired && p.expires_at <= now)
        || p.issued_at > now + chrono::Duration::seconds(60)
        || p.expires_at <= p.issued_at
        || p.expires_at - p.issued_at > chrono::Duration::minutes(15)
    {
        return Err("policy authorization expired or invalid".into());
    }
    if !p.config.is_object()
        || !p.config["collection"].is_object()
        || !p.config["services"].is_array()
    {
        return Err("policy configuration missing".into());
    }
    if let Some(discovery)=p.config.get("discovery") {
        if !discovery.as_object().is_some_and(|d|d.len()==2 && d.keys().all(|k|matches!(k.as_str(),"enabled"|"ignored_domains")))
            || !discovery["enabled"].is_boolean()
            || !discovery["ignored_domains"].as_array().is_some_and(|a|a.len()<=128 && a.iter().all(|d|d.as_str().is_some_and(crate::domain_ok))) {
            return Err("invalid discovery policy".into());
        }
    }
    let model_rules = crate::model_access::rules(&p.config)?;
    if p.version < 3 && model_rules.iter().any(|r| r.mode != "off") {
        return Err("model restrictions require policy version 3".into());
    }
    Ok(p)
}
pub fn cached(state: &State) -> Result<ShadowPolicy> {
    verify_cached(
        state
            .shadow_policy
            .as_ref()
            .ok_or("version 2 policy unavailable")?,
        &state.public_key,
        state.shadow_revision,
        Utc::now(),
        true,
    )
}
/// Drop from the queue whatever the current policy no longer permits.
///
/// Returns whether anything changed, so a caller can avoid rewriting the encrypted
/// state when nothing did. That write is not free: it re-encrypts a queue of up to
/// the configured maximum number of events while holding the store's exclusive lock, and an unprivileged
/// caller can ask for it as often as it likes.
pub(crate) fn content_expired(policy:&ShadowPolicy,event:&ShadowEvent)->bool {
    // Older local contracts without this field get the shortest supported
    // retention. Invalid explicit values never authorize additional storage.
    let days=policy.config["collection"]["content_retention_days"].as_i64().unwrap_or(1);
    let now=Utc::now();
    !(1..=30).contains(&days)||event.occurred_at>now+chrono::Duration::seconds(60)
        ||event.occurred_at<=now-chrono::Duration::days(days.clamp(0,30))
}
pub fn discard_unpermitted(state: &mut State) -> bool {
    let mut changed = false;
    let policy = cached(state).ok();
    for e in &mut state.shadow_queue {
        if policy.as_ref().is_none_or(|p| {
            !p.config["collection"]["store_content"]
                .as_bool()
                .unwrap_or(false)
                || !p.config["collection"]["enabled"].as_bool().unwrap_or(false)
                || e.policy_revision != p.revision || content_expired(p,e)
        }) {
            changed |= e.prompt.is_some() || e.response.is_some();
            e.discard_content();
        }
        // File names answer to their own switch, under the same revision check: a
        // policy that turns them off must also drop what is already queued.
        if policy.as_ref().is_none_or(|p| {
            !p.config["collection"]["store_file_names"]
                .as_bool()
                .unwrap_or(false)
                || !p.config["collection"]["enabled"].as_bool().unwrap_or(false)
                || e.policy_revision != p.revision || content_expired(p,e)
        }) {
            changed |= !e.files.is_empty();
            e.files.clear();
        }
        // Repair a previously queued oversized body before it can block every subsequent batch.
        //
        // The repair is a mutation like the two above and has to be reported as one.
        // It was discarded with `let _ =` until 2026-09-21, so a caller that saves only
        // when this returns true -- the `inspect` handler already did -- never persisted
        // the repair, and the same event was repaired again on every later call.
        let carried = e.prompt.is_some() || e.response.is_some();
        let _ = fit_event(e);
        changed |= carried && e.prompt.is_none() && e.response.is_none();
    }
    changed
}
/// Synchronize the signed policy and record the outcome. The recorded outcome is
/// what the IPC policy answer reports, so that path never has to reach the network
/// itself.
/// Execute HTTP without holding the state lock, then merge only policy and queue
/// results into the latest state. Concurrent browser events and connector cursors
/// are never replaced with the old snapshot.
pub fn refresh_home(home: &std::path::Path, cooldown: chrono::Duration) -> Result<ShadowPolicy> {
    network_pass(home, true, false, cooldown)?;
    cached(&crate::Store::open(home)?.load()?)
}

pub fn refresh_legacy_home(home: &std::path::Path, cooldown: chrono::Duration) -> Result<()> {
    network_pass(home, true, true, cooldown).map(|_| ())
}

pub fn flush_home(home: &std::path::Path, legacy: bool, cooldown: chrono::Duration) -> Result<usize> {
    network_pass(home, false, legacy, cooldown)
}

pub(crate) fn revoke_authorization(state: &mut State) {
    state.authorization_generation = state.authorization_generation.saturating_add(1);
    state.shadow_policy = None;
    state.policy = None;
    state.shadow_online = false;
    discard_unpermitted(state);
}

fn same_identity(a: &State, b: &State) -> bool {
    a.credential == b.credential && a.device_id == b.device_id
        && a.server_url == b.server_url && a.public_key == b.public_key
}

fn removed_ids<I>(before: Vec<Uuid>, remaining: I) -> HashSet<Uuid>
where
    I: IntoIterator<Item = Uuid>,
{
    let remaining: HashSet<_> = remaining.into_iter().collect();
    before.into_iter().filter(|id| !remaining.contains(id)).collect()
}

fn network_pass(home: &std::path::Path, policy: bool, legacy: bool, cooldown: chrono::Duration) -> Result<usize> {
    let mut snapshot = {
        let store = crate::Store::open(home)?;
        let mut state = store.load()?;
        let last = if policy { state.shadow_synced_at } else { state.shadow_flushed_at };
        let now = Utc::now();
        // A date ahead of the clock (a clock that jumped forward and back) is no reason to wait.
        if last.is_some_and(|last| last <= now && now - last < cooldown) {
            if policy && !state.shadow_online {
                return Err("synchronization deferred after failed network attempt".into());
            }
            if policy && !legacy { cached(&state)?; }
            if policy && legacy { crate::cached_policy(&state)?; }
            return Ok(0);
        }
        // Reserve the attempt before releasing the lock, including failed calls.
        if policy { state.shadow_synced_at = Some(now); }
        else { state.shadow_flushed_at = Some(now); }
        discard_unpermitted(&mut state);
        store.save(&state)?;
        state
    };
    let policy_attempt = snapshot.shadow_synced_at;
    let generation = snapshot.authorization_generation;
    let before: Vec<_> = snapshot.shadow_queue.iter().map(|e| e.id).collect();
    let before_legacy: Vec<_> = snapshot.queue.iter().map(|e| e.id).collect();
    let before_completions: Vec<_> = snapshot.shadow_completions.iter().map(|c| c.id).collect();
    let outcome = if policy && legacy {
        let result = crate::refresh(&mut snapshot).map(|_| 0);
        snapshot.shadow_online = result.is_ok();
        result
    } else if policy { refresh(&mut snapshot).map(|_| 0) }
        else if legacy { crate::flush(&mut snapshot) }
        else { flush(&mut snapshot) };
    let store = crate::Store::open(home)?;
    let mut current = store.load()?;
    if !same_identity(&current, &snapshot) {
        return Err("installation changed during synchronization".into());
    }
    if snapshot.authorization_generation != generation {
        // Refusal invalidates both protocol generations and every in-flight
        // result that was obtained under the earlier authorization.
        revoke_authorization(&mut current);
    } else if current.authorization_generation == generation
        && current.shadow_synced_at == policy_attempt {
        // A normal successful delivery carries no fresh policy authority.
        // Only a policy fetch (including a 409 repair fetch) may replace it.
        if (!legacy && policy) || snapshot.shadow_synced_at != policy_attempt {
            if snapshot.shadow_revision >= current.shadow_revision {
                current.shadow_revision = snapshot.shadow_revision;
                current.shadow_policy = snapshot.shadow_policy.take();
            }
        }
        if legacy && policy && snapshot.max_revision >= current.max_revision {
            current.max_revision = snapshot.max_revision;
            current.policy = snapshot.policy.take();
        }
        if policy || snapshot.shadow_synced_at != policy_attempt {
            current.shadow_online = snapshot.shadow_online;
            current.shadow_synced_at = snapshot.shadow_synced_at;
        }
    }
    let removed = removed_ids(before, snapshot.shadow_queue.iter().map(|event| event.id));
    let rejected: Vec<_> = snapshot
        .rejected_events
        .iter()
        .filter(|event| removed.contains(&event.id))
        .map(|event| (event.id, event.reason.clone()))
        .collect();
    quarantine_reasons(&mut current, &rejected);
    current.shadow_queue.retain(|e| !removed.contains(&e.id));
    // A completion this pass placed leaves the reloaded queue too; one queued while
    // the pass was running stays, because it was never part of the batch.
    let placed = removed_ids(
        before_completions,
        snapshot.shadow_completions.iter().map(|completion| completion.id),
    );
    current.shadow_completions.retain(|c| !placed.contains(&c.id));
    let removed_legacy = removed_ids(before_legacy, snapshot.queue.iter().map(|event| event.id));
    current.queue.retain(|event| !removed_legacy.contains(&event.id));
    discard_unpermitted(&mut current);
    store.save(&current)?;
    outcome
}

pub fn refresh(state: &mut State) -> Result<ShadowPolicy> {
    let outcome = synchronize(state);
    state.shadow_online = outcome.is_ok();
    state.shadow_synced_at = Some(Utc::now());
    outcome
}
fn synchronize(state: &mut State) -> Result<ShadowPolicy> {
    discard_unpermitted(state);
    let response = crate::client()?
        .get(crate::api_url(state, "/v3/policy")?)
        .bearer_auth(&state.credential)
        .send()?;
    if matches!(response.status().as_u16(), 401 | 403) {
        revoke_authorization(state);
        return Err("installation authorization refused".into());
    }
    let response = response.error_for_status()?;
    let mut bytes = Vec::new();
    response.take(160 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 160 * 1024 {
        return Err("policy response exceeds limit".into());
    }
    let env: Envelope = serde_json::from_slice(&bytes)?;
    let p = verify(&env, &state.public_key, state.shadow_revision, Utc::now())?;
    state.shadow_revision = p.revision;
    state.shadow_policy = Some(env);
    discard_unpermitted(state);
    Ok(p)
}
pub fn enroll(
    store: &crate::Store,
    provision: &crate::Provision,
    hostname: &str,
    kind: &str,
    capabilities: &[&str],
) -> Result<()> {
    let mut state = store.load()?;
    if !state.credential.is_empty() {
        return Err("installation already enrolled".into());
    }
    if hostname.is_empty() || hostname.len() > 128 || !matches!(kind, "browser" | "native") {
        return Err("invalid enrollment".into());
    }
    let origin = crate::trusted_url(&provision.server_url)?;
    let _: [u8; 32] = STANDARD
        .decode(&provision.policy_public_key)?
        .try_into()
        .map_err(|_| "invalid trust anchor")?;
    let reply=crate::client()?.post(origin.join("/v2/enroll")?).json(&json!({"token":provision.token,"hostname":hostname,"platform":std::env::consts::OS,"version":env!("CARGO_PKG_VERSION"),"kind":kind,"capabilities":capabilities})).send()?.error_for_status()?;
    let reply: Value = crate::bounded_json(reply, 64 * 1024)?;
    state.device_id = reply["device_id"]
        .as_str()
        .ok_or("missing device identity")?
        .into();
    state.credential = reply["credential"]
        .as_str()
        .filter(|x| !x.is_empty())
        .ok_or("missing installation credential")?
        .into();
    if let Some(key) = &provision.update_public_key {
        let _: [u8; 32] = STANDARD
            .decode(key)?
            .try_into()
            .map_err(|_| "invalid update trust anchor")?;
    }
    state.update_public_key = provision.update_public_key.clone();
    state.server_url = provision.server_url.clone();
    state.public_key = provision.policy_public_key.clone();
    store.save(&state)
}
pub fn report_enforcement(state: &State, report: &Value) -> Result<()> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Report { revision:u64, platform_id:String, channel:String, status:String, reason:String, mechanism:String }
    let r: Report = serde_json::from_value(report.clone())?;
    let policy = cached(state)?;
    if r.revision != policy.revision || !crate::model_access::valid_platform(&r.platform_id,&r.channel)
        || !matches!(r.status.as_str(),"applied"|"unavailable")
        || r.reason.len()>64 || (!r.reason.is_empty() && (!r.reason.as_bytes()[0].is_ascii_lowercase()
            || !r.reason.bytes().all(|b|b.is_ascii_lowercase()||b.is_ascii_digit()||b"_.-".contains(&b))))
        || !matches!((r.channel.as_str(),r.mechanism.as_str()),("browser","browser-request")|("native","local-proxy")) {
        return Err("invalid enforcement report".into());
    }
    crate::client()?.post(crate::api_url(state,"/v3/enforcement")?)
        .bearer_auth(&state.credential).json(report).send()?.error_for_status()?;
    Ok(())
}
// Informational presence report: the interactive OS user of the machine.
// Best effort by callers (a server without the route must not stop a pass).
/// Browsers whose extension may report. The server bounds the same vocabulary; a
/// value outside it is dropped here rather than sent and refused.
pub const BROWSER_TOOLS: [&str; 5] = ["chrome", "edge", "firefox", "chromium", "brave"];

/// Record that a browser extension just talked to this agent. Liveness only: it
/// says the extension is running, never what it did. Returns whether the state
/// changed enough to be worth persisting — the value is liveness at a few minutes'
/// granularity, and every IPC call would otherwise write the store under its lock.
pub fn observe_browser(state: &mut State, tool: &str) -> bool {
    if !BROWSER_TOOLS.contains(&tool) {
        return false;
    }
    let now = Utc::now();
    if state
        .browsers
        .get(tool)
        .is_some_and(|seen| *seen <= now && now - *seen < chrono::Duration::minutes(5))
    {
        return false;
    }
    state.browsers.insert(tool.to_string(), now);
    true
}

pub fn heartbeat(state: &State) -> Result<()> {
    let user = crate::session_user::current();
    // Only browsers seen within the reporting window travel: an extension removed
    // last month must stop appearing as present.
    let cutoff = Utc::now() - chrono::Duration::hours(24);
    let browsers: Vec<Value> = state
        .browsers
        .iter()
        .filter(|(tool, seen)| **seen > cutoff && BROWSER_TOOLS.contains(&tool.as_str()))
        .map(|(tool, seen)| json!({"tool": tool, "last_seen": seen}))
        .collect();
    let post = |body: &Value| -> Result<reqwest::blocking::Response> {
        Ok(crate::client()?
            .post(crate::api_url(state, "/v2/heartbeat")?)
            .bearer_auth(&state.credential)
            .json(body)
            .send()?)
    };
    let collector_health: Vec<Value> = state.extension_data["health"].as_object()
        .map(|health| health.values().cloned().collect()).unwrap_or_default();
    let mut body = json!({"os_user": user, "browsers": browsers, "version": env!("CARGO_PKG_VERSION")});
    // An empty collector_health still invokes the Enterprise-only server check.
    if !collector_health.is_empty() {
        body["collector_health"] = json!(collector_health);
    }
    let mut response = post(&body)?;
    if response.status() == reqwest::StatusCode::BAD_REQUEST {
        // Strict older servers reject the new version field. Preserve presence
        // on that fallback; never retry transport or authorization failures.
        body.as_object_mut().unwrap().remove("version");
        response = post(&body)?;
        if response.status() == reqwest::StatusCode::BAD_REQUEST {
            response = post(&json!({"os_user": user}))?;
        }
    }
    response.error_for_status()?;
    Ok(())
}

pub fn association(state: &State) -> Result<Value> {
    let response = crate::client()?
        .post(crate::api_url(state, "/v2/identity/start")?)
        .bearer_auth(&state.credential)
        .json(&json!({}))
        .send()?
        .error_for_status()?;
    let value: Value = crate::bounded_json(response, 64 * 1024)?;
    let url = reqwest::Url::parse(
        value["verification_url"]
            .as_str()
            .ok_or("missing association URL")?,
    )?;
    if url.origin() != crate::trusted_url(&state.server_url)?.origin() {
        return Err("association origin mismatch".into());
    }
    Ok(value)
}
pub fn service<'a>(policy: &'a ShadowPolicy, domain: &str) -> Result<&'a Value> {
    if !crate::domain_ok(domain) || domain.len() > 100 {
        return Err("invalid service domain".into());
    }
    policy.config["services"]
        .as_array()
        .ok_or("services missing")?
        .iter()
        .find(|v| {
            v["enabled"].as_bool().unwrap_or(false)
                && v["domains"]
                    .as_array()
                    .is_some_and(|a| a.iter().any(|d| d.as_str() == Some(domain)))
        })
        .ok_or_else(|| "service is not enabled".into())
}
pub fn normalized_url(value: &str, provider: &str) -> Result<String> {
    let url = reqwest::Url::parse(value)?;
    if url.scheme() != "https"
        || url.host_str() != Some(provider)
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err("URL does not match provider".into());
    }
    // Conversation identifiers and user-supplied path segments are not browsing telemetry.
    Ok(format!("https://{provider}/"))
}
pub use milvago_browser_engine::Inspection;
pub fn inspect(
    policy: &ShadowPolicy,
    text: &str,
    provider: &str,
    upload: bool,
) -> Result<Inspection> {
    inspect_scope(policy, text, provider, upload, "browser")
}
pub fn inspect_scope(
    policy: &ShadowPolicy,
    text: &str,
    provider: &str,
    upload: bool,
    scope: &str,
) -> Result<Inspection> {
    let service = service(policy, provider)?;
    milvago_browser_engine::inspect(&milvago_browser_engine::InspectionInput {
        config: policy.config.clone(),
        service: service.clone(),
        text: text.into(),
        provider: provider.into(),
        upload,
        scope: scope.into(),
    })
    .map_err(|error| std::io::Error::other(error).into())
}

/// Agentic command-line tools whose own pre-send extension point can be used to
/// refuse a prompt. Shared with the collector, which registers the hook.
pub const CLI_TOOLS: [&str; 2] = ["claude-code", "codex"];

/// The AI service a command-line tool talks to.
pub fn cli_provider(tool: &str) -> Option<&'static str> {
    match tool {
        "claude-code" => Some("claude.ai"),
        "codex" => Some("chatgpt.com"),
        _ => None,
    }
}

/// Record a prompt a command-line hook refused.
///
/// The hook runs as the user, on a channel every signed-in user can write to, so
/// **nothing about the record comes from the caller** except the text and which of
/// the two tools it was: the source, the kind and the action are fixed here. A local
/// user can therefore add noise to the journal — the same exposure the browser event
/// path already carries — but cannot claim a different source, a different action, or
/// that an enforcement mechanism is active.
/// `characters` counts what the user typed; `text` is what may be kept, masked.
pub fn enqueue_refusal(state: &mut State, tool: &str, text: &str, characters: u32, labels: Vec<String>) -> Result<Uuid> {
    let provider = cli_provider(tool).ok_or("unsupported command-line tool")?;
    let p = cached(state)?;
    if !p.config["collection"]["enabled"].as_bool().unwrap_or(false) {
        return Err("collection is disabled".into());
    }
    service(&p, provider)?;
    let id = Uuid::new_v4();
    let mut event = ShadowEvent {
        id,
        kind: "prompt".into(),
        occurred_at: Utc::now(),
        provider: provider.into(),
        source: "native".into(),
        tool: tool.into(),
        model: None,
        effort: None,
        platform_id: None,
        decision_reason: None,
        conversation_id: None,
        correlation_id: None,
        url: None,
        action: "blocked".into(),
        characters,
        labels: labels.into_iter().take(16).collect(),
        prompt: p.config["collection"]["store_content"]
            .as_bool()
            .unwrap_or(false)
            .then(|| text.to_owned()),
        response: None,
        files: vec![],
        user: None,
        policy_revision: p.revision,
detector:None,catalog_revision:None,input_tokens:None,output_tokens:None,body_bytes:None,characters_known:true,
    };
    let size = fit_event(&mut event)?;
    crate::config::current().queue.check(state, 1, size)?;
    state.shadow_queue.push(event);
    Ok(id)
}
pub(crate) fn browser_event(p: &ShadowPolicy, catalog_revision: u64, mut input: Value) -> Result<ShadowEvent> {
    if !p.config["collection"]["enabled"].as_bool().unwrap_or(false) { return Err("collection is disabled".into()); }
    let object = input.as_object_mut().ok_or("event must be an object")?;
    if object.contains_key("id") || object.contains_key("occurred_at") {
        return Err("event identity is assigned locally".into());
    }
    let id = Uuid::new_v4();
    object.insert("id".into(), json!(id));
    object.insert("occurred_at".into(), json!(Utc::now()));
    object.insert("policy_revision".into(), json!(p.revision));
    let mut event: ShadowEvent = serde_json::from_value(input)?;
    // One vocabulary for acceptance and for liveness: a browser the agent reports as
    // present must not have its events refused (Brave was, silently).
    if event.source != "browser"
        || !BROWSER_TOOLS.contains(&event.tool.as_str())
        || !matches!(event.kind.as_str(), "navigation" | "prompt" | "response")
        || !matches!(event.action.as_str(), "observed" | "blocked" | "redirected")
        || event.characters > 1_000_000
    {
        return Err("browser event rejected".into());
    }
    // A presence record names a platform the catalogue does NOT cover, so it is not an
    // enabled service and service() would refuse it. What it may carry is pinned here
    // instead: the host was reached, and nothing else. Which hosts actually count stays
    // the server's decision, against the signed catalogue it holds -- a record naming
    // anything else is reduced there, not trusted from here.
    if event.detector.as_deref() == Some("presence") {
        if event.kind != "navigation"
            || event.action != "observed"
            || event.characters != 0
            || !crate::domain_ok(&event.provider)
            || event.provider.len() > 253
            || event.url.as_deref().is_some_and(|u| !u.is_empty())
            || event.conversation_id.is_some()
            || event.correlation_id.is_some()
            || event.model.is_some()
            || event.effort.is_some()
            || event.platform_id.is_some()
            || event.decision_reason.is_some()
            || event.prompt.is_some()
            || event.response.is_some()
            || !event.files.is_empty()
            || !event.labels.is_empty()
        {
            return Err("invalid presence record".into());
        }
    } else {
        service(&p, &event.provider)?;
    }
    if event.detector.as_deref().is_some_and(|d| !matches!(d,"dom"|"network"|"both"|"presence"))
        || event.input_tokens.is_some() || event.output_tokens.is_some()
        || event.body_bytes.is_some_and(|n| n>16*1024*1024)
        || (!event.characters_known && event.characters!=0)
        || event.catalog_revision.is_some_and(|r| r>catalog_revision) {
        return Err("invalid browser detector metadata".into());
    }
    // Observing which model answered is inventory, and both editions report it: an
    // administrator has to know what is actually used before deciding anything about
    // it, and refusing the field made every Community record blank. What stays out of
    // Community is the *decision* - `model-rules-community.js` carries no rule code
    // and the server strips `model_access` from its signed policy - not the fact.
    if event.platform_id.as_deref().is_some_and(|platform| crate::model_access::browser_platform(&event.provider) != Some(platform))
        || event.decision_reason.as_deref().is_some_and(|reason| !matches!(reason, "model_denied" | "model_unknown" | "control_unavailable")
            || event.action != "blocked" || event.kind != "prompt" || event.platform_id.is_none()) {
        return Err("invalid model decision metadata".into());
    }
    if [&event.model, &event.effort, &event.conversation_id, &event.correlation_id]
        .iter()
        .any(|s| s.as_ref().is_some_and(|s| !clean_metadata(s)))
        || event.user.is_some()
    {
        return Err("invalid browser event metadata".into());
    }
    if let Some(url) = &event.url {
        event.url = Some(normalized_url(url, &event.provider)?);
    }
    if (event.kind != "prompt" && event.prompt.is_some())
        || (event.kind != "response" && event.response.is_some())
    {
        return Err("content does not match event kind".into());
    }
    // File names travel only while the signed policy asks for them, and only with a
    // request. The page proposes; the policy decides.
    if !event.files.is_empty()
        && (event.kind != "prompt"
            || !p.config["collection"]["store_file_names"]
                .as_bool()
                .unwrap_or(false)
            || event.files.len() > 20
            || event
                .files
                .iter()
                .any(|name| name.is_empty() || name.len() > 200 || name.chars().any(|c| c.is_control())))
    {
        return Err("file names rejected".into());
    }
    // The event-label vocabulary, enforced at this edge. The browser extension enforces
    // the same eleven values in `endpoint/extension/detection-runtime.js`, and the two
    // must stay in step: a label one side emits and the other refuses is an event lost
    // on one path and kept on the other.
    //
    // The server's `classificationTypes` (server/internal/app/shadow_settings.go) is a
    // DIFFERENT list and is deliberately shorter: it maps a label to a sensitivity, and
    // "custom" -- the label of an administrator's own rule -- has no fixed sensitivity,
    // so it belongs here and not there.
    if event.labels.len() > 16
        || event.labels.iter().any(|label| {
            !matches!(
                label.as_str(),
                "email"
                    | "phone"
                    | "iban"
                    | "card"
                    | "social_id"
                    | "ip"
                    | "source_code"
                    | "medical"
                    | "keyword"
                    | "ssn_us"
                    | "custom"
            )
        })
    {
        return Err("event labels rejected".into());
    }
    for value in [&mut event.prompt, &mut event.response] {
        if let Some(text) = value {
            let checked = inspect(&p, text, &event.provider, false)?;
            text.zeroize();
            *text = checked.text;
            event.labels.extend(checked.labels);
        }
    }
    event.labels.sort();
    event.labels.dedup();
    if event.labels.len() > 16 || event.labels.iter().any(|s| s.len() > 40) {
        return Err("event labels rejected".into());
    }
    if !p.config["collection"]["store_content"]
        .as_bool()
        .unwrap_or(false)
    {
        event.discard_content();
    }
    fit_event(&mut event)?;
    Ok(event)
}
pub fn enqueue_browser(state: &mut State, input: Value) -> Result<Uuid> {
    discard_unpermitted(state);
    let p = cached(state)?;
    let mut event = browser_event(&p, state.detection.revision, input)?;
    let size = fit_event(&mut event)?;
    crate::config::current().queue.check(state, 1, size)?;
    let id = event.id;
    state.shadow_queue.push(event);
    Ok(id)
}
/// What an outgoing request said about an exchange that was already made durable.
///
/// A prompt is recorded *before* it is sent, so that nothing leaves the machine
/// without a trace; the conversation identifier, the model and the effort only exist
/// once the request itself is on the wire. They arrive afterwards, as a completion
/// against the event already stored. A completion only ever fills what is still
/// empty: it never revises a value already recorded, and never creates an event.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowCompletion {
    /// Assigned locally, like the event's own identity: the browser names the send it
    /// is completing by its delivery identity, and the agent alone translates that
    /// into the event it recorded.
    #[serde(default)]
    pub id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effort: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_bytes: Option<u64>,
}
/// Completions waiting for the server are few and short-lived: one follows each send,
/// and it leaves on the next pass. The bound only keeps a long outage from growing
/// the file.
const COMPLETION_LIMIT: usize = 512;
impl ShadowCompletion {
    /// Read a completion the browser named by delivery identity: the event identity
    /// is stamped here, never accepted from the caller.
    pub fn parse_for(id: Uuid, value: &Value) -> Result<Self> {
        let mut completion = Self::read(value)?;
        if !completion.id.is_nil() {
            return Err("completion identity refused".into());
        }
        completion.id = id;
        Ok(completion)
    }
    /// Read a completion already bound to an event identity, between the privileged
    /// service and the agent.
    pub fn parse(value: &Value) -> Result<Self> {
        let completion = Self::read(value)?;
        if completion.id.is_nil() {
            return Err("completion identity missing".into());
        }
        Ok(completion)
    }
    /// Unknown fields are refused rather than ignored, so a device cannot smuggle a
    /// column past this: only what a request can legitimately tell us is accepted.
    fn read(value: &Value) -> Result<Self> {
        let completion: Self = serde_json::from_value(value.clone())?;
        if [
            &completion.model,
            &completion.effort,
            &completion.conversation_id,
        ]
        .iter()
        .any(|s| s.as_ref().is_some_and(|s| s.is_empty() || !clean_metadata(s)))
        {
            return Err("invalid completion metadata".into());
        }
        if completion.model.is_none()
            && completion.effort.is_none()
            && completion.conversation_id.is_none()
            && completion.body_bytes.is_none()
        {
            return Err("empty completion".into());
        }
        Ok(completion)
    }
    /// Fill only what is empty, on both queues, exactly as the server does. Keeping
    /// the rule identical in every place a completion lands is what makes a replay
    /// harmless wherever it arrives.
    pub fn apply(&self, event: &mut ShadowEvent) {
        for (target, value) in [
            (&mut event.model, &self.model),
            (&mut event.effort, &self.effort),
            (&mut event.conversation_id, &self.conversation_id),
        ] {
            if target.is_none() {
                target.clone_from(value);
            }
        }
        if event.body_bytes.is_none() {
            event.body_bytes = self.body_bytes;
        }
        // The event was seen on the network after all: the completion is the proof.
        if event.detector.as_deref() == Some("dom") {
            event.detector = Some("both".into());
        }
    }
}
/// Route a completion to wherever its event still is. An event awaiting delivery is
/// completed in place, so nothing extra travels; one already accepted by the server
/// is completed there. An identity that matches neither designates nothing and is
/// dropped — a completion never fabricates an event.
pub fn complete(state: &mut State, completion: ShadowCompletion) -> Result<bool> {
    if let Some(event) = state.shadow_queue.iter_mut().find(|e| e.id == completion.id) {
        completion.apply(event);
        return Ok(true);
    }
    if let Some(queued) = state
        .shadow_completions
        .iter_mut()
        .find(|c| c.id == completion.id)
    {
        // Same rule again: the first answer about an exchange is the one kept.
        for (target, value) in [
            (&mut queued.model, &completion.model),
            (&mut queued.effort, &completion.effort),
            (&mut queued.conversation_id, &completion.conversation_id),
        ] {
            if target.is_none() {
                target.clone_from(value);
            }
        }
        if queued.body_bytes.is_none() {
            queued.body_bytes = completion.body_bytes;
        }
        return Ok(true);
    }
    state.shadow_completions.push(completion);
    let excess = state.shadow_completions.len().saturating_sub(COMPLETION_LIMIT);
    state.shadow_completions.drain(..excess);
    Ok(true)
}
/// Hand queued completions to the server. Every one of them names an event the
/// server has already accepted — `complete` keeps an event still in the queue local —
/// so the order that matters is guaranteed before anything is sent.
fn deliver_completions(state: &mut State) -> Result<()> {
    if state.shadow_completions.is_empty() {
        return Ok(());
    }
    let batch: Vec<_> = state.shadow_completions.iter().take(100).cloned().collect();
    let response = crate::client()?
        .post(crate::api_url(state, "/v2/events/complete")?)
        .bearer_auth(&state.credential)
        .json(&json!({ "completions": batch }))
        .send()?;
    if matches!(response.status().as_u16(), 401 | 403) {
        revoke_authorization(state);
        return Err("installation authorization refused".into());
    }
    if response.status().as_u16() == 400 {
        // A completion the server refuses will never be accepted: drop the batch
        // rather than retry it forever. The events themselves keep what they have.
        let sent: HashSet<_> = batch.iter().map(|c| c.id).collect();
        state.shadow_completions.retain(|c| !sent.contains(&c.id));
        return Err("completion batch rejected".into());
    }
    response.error_for_status()?;
    // Applied or not, the question has been put: an identity the server does not know
    // will not become known later.
    let sent: HashSet<_> = batch.iter().map(|c| c.id).collect();
    state.shadow_completions.retain(|c| !sent.contains(&c.id));
    Ok(())
}
pub fn flush(state: &mut State) -> Result<usize> {
    let events = flush_events(state);
    // Placing a completion is enrichment, never custody: a failure keeps it queued for
    // the next pass and must not report the events themselves as undelivered.
    if let Err(e) = deliver_completions(state) {
        crate::log::warn(&format!("completion delivery deferred: {e}"));
    }
    events
}
fn flush_events(state: &mut State) -> Result<usize> {
    discard_unpermitted(state);
    let invalid: Vec<_> = state.shadow_queue.iter().filter(|e| !valid_queued_event(e)).map(|e| e.id).collect();
    quarantine(state, &invalid, "invalid_metadata");
    if state.shadow_queue.is_empty() {
        return Ok(0);
    }
    let mut batch = Vec::new();
    let mut size = 32;
    for event in state.shadow_queue.iter().take(100) {
        let bytes = serialized_size(event)? + 1;
        if size + bytes > 120 * 1024 {
            break;
        }
        size += bytes;
        batch.push(event.clone());
    }
    if batch.is_empty() {
        return Err("queued event exceeds batch limit".into());
    }
    let response = crate::client()?
        .post(crate::api_url(state, "/v2/events")?)
        .bearer_auth(&state.credential)
        .json(&json!({"events":batch}))
        .send()?;
    if matches!(response.status().as_u16(), 401 | 403) {
        revoke_authorization(state);
        return Err("installation authorization refused".into());
    }
    if response.status().as_u16() == 409 {
        let _ = refresh(state);
        discard_unpermitted(state);
        return Err("content policy changed; refreshed for retry".into());
    }
    if response.status().as_u16() == 400 {
        let mut raw = Vec::new();
        response.take(16385).read_to_end(&mut raw)?;
        if raw.len() <= 16384 {
            #[derive(Deserialize)]
            struct Rejected { error: String, rejected_ids: Vec<Uuid> }
            if let Ok(rejected) = serde_json::from_slice::<Rejected>(&raw) {
                let offered: HashSet<_> = batch.iter().map(|event| event.id).collect();
                if rejected.error == "invalid_event" && !rejected.rejected_ids.is_empty()
                    && rejected.rejected_ids.len() <= batch.len()
                    && rejected.rejected_ids.iter().all(|id| offered.contains(id)) {
                    quarantine(state, &rejected.rejected_ids, "server_invalid_event");
                }
            }
        }
        return Err("event batch rejected; valid events retained".into());
    }
    let response = response.error_for_status()?;
    let mut raw = Vec::new();
    response.take(16385).read_to_end(&mut raw)?;
    if raw.len() > 16384 {
        return Err("acknowledgement too large".into());
    }
    #[derive(Deserialize)]
    struct Ack {
        accepted_ids: Vec<Uuid>,
    }
    let ack: Ack = serde_json::from_slice(&raw)?;
    let offered: HashSet<_> = batch.iter().map(|event| event.id).collect();
    if ack.accepted_ids.iter().any(|id| !offered.contains(id))
    {
        return Err("unknown acknowledgement".into());
    }
    let before = state.shadow_queue.len();
    let accepted: HashSet<_> = ack.accepted_ids.into_iter().collect();
    state.shadow_queue.retain(|event| !accepted.contains(&event.id));
    Ok(before - state.shadow_queue.len())
}

#[cfg(test)]
mod delivery_tests {
    use super::*;
    use crate::{Envelope, Store};
    use ed25519_dalek::{Signer, SigningKey};
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::time::{Duration, Instant};

    fn authorized() -> State {
        let key = SigningKey::from_bytes(&[73; 32]);
        let now = Utc::now();
        let policy = json!({"version":3,"revision":1,"issued_at":now,
            "expires_at":now+chrono::Duration::minutes(10),"capabilities":[],
            "config":{"collection":{"enabled":true,"store_content":true},
                "services":[{"domains":["chatgpt.com"],"enabled":true,"mode":"observe"}],
                "privacy":{"enabled":false},"protection":{}}});
        let bytes = serde_json::to_vec(&policy).unwrap();
        State { credential:"test-credential".into(), device_id:Uuid::new_v4().to_string(),
            public_key:STANDARD.encode(key.verifying_key().as_bytes()), shadow_revision:1,
            shadow_policy:Some(Envelope {payload:STANDARD.encode(&bytes),
                signature:STANDARD.encode(key.sign(&bytes).to_bytes())}), ..State::default() }
    }

    fn event() -> Value {
        json!({"kind":"prompt","provider":"chatgpt.com","source":"browser",
            "tool":"chrome","action":"observed","characters":6,"labels":[],
            "prompt":"sample"})
    }

    #[test]
    fn large_queue_differences_keep_order_and_scale_near_linearly() {
        fn measure(size: usize) -> Duration {
            let before: Vec<_> = (0..size)
                .map(|index| Uuid::from_u128(index as u128 + 1))
                .collect();
            let remaining: Vec<_> = before
                .iter()
                .enumerate()
                .filter(|(index, _)| index % 3 != 0)
                .map(|(_, id)| *id)
                .collect();
            let started = Instant::now();
            let removed = removed_ids(before, remaining);
            let elapsed = started.elapsed();
            assert_eq!(removed.len(), (size + 2) / 3);
            elapsed
        }

        let ten_thousand = measure(10_000);
        let hundred_thousand = measure(100_000);
        eprintln!("queue difference: 10k={ten_thousand:?}, 100k={hundred_thousand:?}");
        assert!(
            hundred_thousand <= ten_thousand * 40 + Duration::from_millis(100),
            "queue difference growth is not compatible with the linear implementation"
        );
    }

    // The server must receive and parse the real request before it can answer.
    // Every wait is bounded so a regression fails instead of hanging the suite.
    fn http(handler: impl Fn(Value) -> (u16, Value) + Send + Sync + 'static)
        -> (String, std::thread::JoinHandle<()>) {
        http_many(1, handler)
    }

    fn http_many(count: usize, handler: impl Fn(Value) -> (u16, Value) + Send + Sync + 'static)
        -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let handler = std::sync::Arc::new(handler);
        let thread = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for _ in 0..count {
            let until = Instant::now() + Duration::from_secs(4);
            let stream = loop {
                if let Ok((stream, _)) = listener.accept() { break stream; }
                assert!(Instant::now() < until, "no HTTP request received");
                std::thread::sleep(Duration::from_millis(5));
            };
            let handler = handler.clone();
            requests.push(std::thread::spawn(move || {
            stream.set_nonblocking(false).unwrap(); // Windows accepted sockets inherit the listener mode.
            stream.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
            let mut reader = BufReader::new(stream);
            let mut length = 0;
            loop {
                let mut line = String::new();
                assert!(reader.read_line(&mut line).unwrap() > 0);
                if line == "\r\n" { break; }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse::<usize>().unwrap();
                }
            }
            assert!(length <= 128 * 1024);
            let mut bytes = vec![0; length];
            reader.read_exact(&mut bytes).unwrap();
            let body = if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap() };
            let (status, answer) = handler(body);
            let raw = serde_json::to_vec(&answer).unwrap();
            let mut stream = reader.into_inner();
            write!(stream, "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", raw.len()).unwrap();
            stream.write_all(&raw).unwrap();
            }));
            }
            for request in requests { request.join().unwrap(); }
        });
        (url, thread)
    }

    #[test]
    fn heartbeat_reports_runtime_and_presence_without_community_collectors() {
        let mut state = authorized();
        state.browsers.insert("chrome".into(), Utc::now());
        state.browsers.insert("firefox".into(), Utc::now() - chrono::Duration::hours(25));
        let (url, server) = http(|body| {
            assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
            assert!(body.get("collector_health").is_none());
            let browsers = body["browsers"].as_array().unwrap();
            assert_eq!(browsers.len(), 1);
            assert_eq!(browsers[0]["tool"], "chrome");
            (200, json!({"ok":true}))
        });
        state.server_url = url;
        heartbeat(&state).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn heartbeat_preserves_presence_when_older_server_rejects_version() {
        let mut state = authorized();
        state.browsers.insert("edge".into(), Utc::now());
        let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = count.clone();
        let (url, server) = http_many(2, move |body| {
            assert_eq!(body["browsers"][0]["tool"], "edge");
            if observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                assert!(body.get("version").is_some());
                (400, json!({"error":"invalid_request"}))
            } else {
                assert!(body.get("version").is_none());
                (200, json!({"ok":true}))
            }
        });
        state.server_url = url;
        heartbeat(&state).unwrap();
        server.join().unwrap();
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[test]
    fn heartbeat_does_not_retry_authentication_or_server_failures() {
        for status in [401, 403, 500] {
            let mut state = authorized();
            let (url, server) = http(move |_| (status, json!({"error":"unavailable"})));
            state.server_url = url;
            let error = heartbeat(&state).unwrap_err();
            assert_eq!(error.downcast_ref::<reqwest::Error>().unwrap().status().unwrap().as_u16(), status);
            server.join().unwrap();
        }
    }

    #[test]
    fn browser_rejects_server_invalid_identifiers_and_user_before_persisting() {
        for field in ["model", "conversation_id", "correlation_id"] {
            for invalid in [" leading", "trailing ", "control\nvalue"] {
                let mut state = authorized();
                let mut input = event();
                input[field] = json!(invalid);
                assert!(enqueue_browser(&mut state, input).is_err());
                assert!(state.shadow_queue.is_empty());
            }
        }
        let mut state = authorized();
        let mut input = event();
        input["user"] = json!("profile-placeholder");
        assert!(enqueue_browser(&mut state, input).is_err());
        assert!(state.shadow_queue.is_empty());
    }

    /// An observed model is inventory and is kept in both editions. Refusing it left
    /// every Community record blank, which is what a real claude.ai exchange showed:
    /// the network observation fired, and the name was dropped on the way in.
    #[test]
    fn an_observed_model_is_kept_and_a_decision_without_a_block_is_still_refused() {
        // Two shapes reach this field: the identifier read from an outgoing request,
        // and the label a site displays for the selected model, which is the only form
        // available before a prompt is sent and does contain spaces.
        for observed in ["claude-fixture-model", "Fixture Model 4.5"] {
            let mut state = authorized();
            let mut input = event();
            input["model"] = json!(observed);
            enqueue_browser(&mut state, input).unwrap();
            assert_eq!(state.shadow_queue[0].model.as_deref(), Some(observed));
        }
        // Reporting a decision stays a different matter from reporting a fact: it is
        // only valid on a blocked prompt that names its platform.
        let mut state = authorized();
        let mut input = event();
        input["decision_reason"] = json!("model_denied");
        assert!(enqueue_browser(&mut state, input).is_err());
        assert!(state.shadow_queue.is_empty());
    }

    #[test]
    fn old_poison_is_isolated_and_following_event_is_actually_delivered() {
        let mut state = authorized();
        let bad = enqueue_browser(&mut state, event()).unwrap();
        state.shadow_queue[0].model = Some(" leading".into());
        let good = enqueue_browser(&mut state, event()).unwrap();
        let (url, server) = http(move |body| {
            assert_eq!(body["events"].as_array().unwrap().len(), 1);
            assert_eq!(body["events"][0]["id"], good.to_string());
            (200, json!({"accepted_ids":[good]}))
        });
        state.server_url = url;
        assert_eq!(flush(&mut state).unwrap(), 1);
        server.join().unwrap();
        assert!(state.shadow_queue.is_empty());
        assert_eq!(state.rejected_events.len(), 1);
        assert_eq!(state.rejected_events[0].id, bad);
        let diagnostic = serde_json::to_string(&state.rejected_events).unwrap();
        assert!(!diagnostic.contains("sample"));
        assert!(!diagnostic.contains("leading"));
    }

    #[test]
    fn only_authenticated_structured_rejected_ids_are_isolated() {
        for mode in 0..3 {
            let mut state = authorized();
            let id = enqueue_browser(&mut state, event()).unwrap();
            let good = enqueue_browser(&mut state, event()).unwrap();
            let (url, server) = http(move |body| {
                assert_eq!(body["events"].as_array().unwrap().len(), 2);
                (400, match mode {
                    0 => json!({"error":"invalid_event","rejected_ids":[id]}),
                    1 => json!({"error":"invalid_event","rejected_ids":[Uuid::new_v4()]}),
                    _ => json!({"error":"invalid_request"}),
                })
            });
            state.server_url = url;
            assert!(flush(&mut state).is_err());
            server.join().unwrap();
            assert!(state.shadow_queue.iter().any(|e| e.id == good));
            assert_eq!(state.shadow_queue.len(), if mode == 0 {1} else {2});
            assert_eq!(state.rejected_events.len(), if mode == 0 {1} else {0});
        }
    }

    #[test]
    fn flush_releases_store_during_http_and_preserves_concurrent_event_and_cursor() {
        use fs2::FileExt;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let mut state = authorized();
        let sent = enqueue_browser(&mut state, event()).unwrap();
        let callback_home = home.clone();
        let (url, server) = http(move |body| {
            assert_eq!(body["events"][0]["id"], sent.to_string());
            let lock = std::fs::OpenOptions::new().read(true).write(true)
                .open(callback_home.join("state.lock")).unwrap();
            lock.try_lock_exclusive().expect("HTTP must not hold Store lock");
            drop(lock);
            let store = Store::open(&callback_home).unwrap();
            let mut state = store.load().unwrap();
            enqueue_browser(&mut state, event()).unwrap();
            state.extension_data = json!({"cursor":42});
            store.save(&state).unwrap();
            (200, json!({"accepted_ids":[sent]}))
        });
        state.server_url = url;
        { Store::open(&home).unwrap().save(&state).unwrap(); }
        assert_eq!(flush_home(&home, false, chrono::Duration::zero()).unwrap(), 1);
        server.join().unwrap();
        let current = Store::open(&home).unwrap().load().unwrap();
        assert_eq!(current.shadow_queue.len(), 1);
        assert_ne!(current.shadow_queue[0].id, sent);
        assert_eq!(current.extension_data["cursor"], 42);
    }

    #[test]
    fn concurrent_stale_success_cannot_restore_revoked_authorization() {
        use std::sync::{Mutex, atomic::{AtomicUsize, Ordering}};
        for (fetch_policy, legacy) in [(false, false), (true, false), (false, true), (true, true)] {
            let dir = tempfile::tempdir().unwrap();
            let mut state = authorized();
            let id = enqueue_browser(&mut state, event()).unwrap();
            let key = SigningKey::from_bytes(&[73; 32]);
            let now = Utc::now();
            let raw = serde_json::to_vec(&json!({"version":1,"revision":1,"issued_at":now,
                "expires_at":now+chrono::Duration::minutes(10),"rules":[],
                "collection":{"prompt_content":false}})).unwrap();
            state.policy = Some(Envelope {payload:STANDARD.encode(&raw),
                signature:STANDARD.encode(key.sign(&raw).to_bytes())});
            state.queue.push(serde_json::from_value(json!({"id":id,"occurred_at":now,
                "provider":"chatgpt.com","source":"browser","action":"observed","characters":6,
                "labels":[]})).unwrap());
            let envelope = serde_json::to_value(if legacy {state.policy.as_ref().unwrap()}
                else {state.shadow_policy.as_ref().unwrap()}).unwrap();
            let (arrived, first_arrived) = std::sync::mpsc::channel();
            let (release, released) = std::sync::mpsc::channel();
            let released = Mutex::new(released);
            let requests = AtomicUsize::new(0);
            let (url, server) = http_many(2, move |body| {
                if requests.fetch_add(1, Ordering::AcqRel) == 0 {
                    arrived.send(()).unwrap();
                    released.lock().unwrap().recv_timeout(Duration::from_secs(3)).unwrap();
                    (200, if fetch_policy {envelope.clone()} else {json!({"accepted_ids":[id]})})
                } else {
                    assert_eq!(body["events"][0]["id"], id.to_string());
                    (401, json!({"error":"device_unauthorized"}))
                }
            });
            state.server_url = url;
            { Store::open(dir.path()).unwrap().save(&state).unwrap(); }
            let home = dir.path().to_path_buf();
            let pending = std::thread::spawn(move || {
                if fetch_policy && legacy { refresh_legacy_home(&home, chrono::Duration::zero()).map(|_| 0) }
                else if fetch_policy { refresh_home(&home, chrono::Duration::zero()).map(|_| 0) }
                else { flush_home(&home, legacy, chrono::Duration::zero()) }
            });
            first_arrived.recv_timeout(Duration::from_secs(3)).unwrap();
            assert!(flush_home(dir.path(), false, chrono::Duration::zero()).is_err());
            {
                let revoked = Store::open(dir.path()).unwrap().load().unwrap();
                assert!(revoked.shadow_policy.is_none());
                assert_eq!(revoked.authorization_generation, 1);
            }
            release.send(()).unwrap();
            let _ = pending.join().unwrap();
            server.join().unwrap();
            let current = Store::open(dir.path()).unwrap().load().unwrap();
            assert!(cached(&current).is_err(), "stale response restored authorization");
            assert!(current.shadow_policy.is_none());
            assert!(current.policy.is_none(), "stale legacy response restored authorization");
            assert_eq!(current.authorization_generation, 1);
        }
    }

    #[test]
    fn association_http_is_unlocked_and_failures_still_arm_cooldown() {
        use fs2::FileExt;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let mut state = authorized();
        let (url, server) = http(move |body| {
            assert_eq!(body, json!({}));
            let lock = std::fs::OpenOptions::new().read(true).write(true)
                .open(home.join("state.lock")).unwrap();
            lock.try_lock_exclusive().expect("association holds the Store lock");
            (503, json!({"error":"unavailable"}))
        });
        state.server_url = url;
        { Store::open(dir.path()).unwrap().save(&state).unwrap(); }
        assert!(crate::native::native_message(dir.path(), json!({"op":"associate"})).is_err());
        server.join().unwrap();
        let error = crate::native::native_message(dir.path(), json!({"op":"associate"})).unwrap_err();
        assert_eq!(error.to_string(), "association cooldown");
        assert!(Store::open(dir.path()).unwrap().load().unwrap().association_attempted_at.is_some());
    }

    #[cfg(feature = "model-control")]
    #[test]
    fn enforcement_attempt_budget_is_per_validated_platform() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = authorized();
        let (url, server) = http(|body| {
            assert_eq!(body["platform_id"], "chatgpt");
            (503, json!({"error":"unavailable"}))
        });
        state.server_url = url;
        { Store::open(dir.path()).unwrap().save(&state).unwrap(); }
        let report = json!({"op":"enforcement","revision":1,"platform_id":"chatgpt",
            "channel":"browser","status":"applied","reason":"","mechanism":"browser-request"});
        assert!(crate::native::native_message(dir.path(), report.clone()).is_err());
        server.join().unwrap();
        assert_eq!(crate::native::native_message(dir.path(), report).unwrap_err().to_string(),
            "enforcement report cooldown");
        let invalid = json!({"op":"enforcement","revision":1,"platform_id":"unbounded-attacker-key",
            "channel":"browser","status":"applied","reason":"","mechanism":"browser-request"});
        assert!(crate::native::native_message(dir.path(), invalid).is_err());
        let state = Store::open(dir.path()).unwrap().load().unwrap();
        assert_eq!(state.enforcement_attempts.len(), 1);
    }

    #[test]
    fn failed_http_keeps_valid_events_and_persists_attempt_cooldown() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = authorized();
        let id = enqueue_browser(&mut state, event()).unwrap();
        let (url, server) = http(move |body| {
            assert_eq!(body["events"][0]["id"], id.to_string());
            (503, json!({"error":"unavailable"}))
        });
        state.server_url = url;
        { Store::open(dir.path()).unwrap().save(&state).unwrap(); }
        assert!(flush_home(dir.path(), false, chrono::Duration::seconds(5)).is_err());
        server.join().unwrap();
        // The listener is now gone; a second HTTP call could not succeed.
        assert_eq!(flush_home(dir.path(), true, chrono::Duration::seconds(5)).unwrap(), 0);
        let current = Store::open(dir.path()).unwrap().load().unwrap();
        assert_eq!(current.shadow_queue[0].id, id);
        assert!(current.shadow_flushed_at.is_some());
        assert!(current.rejected_events.is_empty());
    }
}
