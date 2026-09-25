//! Privileged cache journal. All authorization mutations are serialized and
//! written before a response can authorize a browser operation.
use crate::{
    Envelope, Result,
    browser_cache::{self as cache, Journal, Keys, Pin, Presence},
    cache_windows::{self as windows, Directory},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{fs::File, path::Path, time::{Duration, Instant}};
use zeroize::Zeroize;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    journal: Journal,
    keys: Keys,
    #[serde(default)]
    queue: crate::browser_broker::Queue,
}
pub struct Authority {
    stored: Stored,
    storage: Storage,
    storage_failed: bool,
}
enum Storage {
    Protected {
        directory: Directory,
        _public: Directory,
        _lock: File,
    },
    #[cfg(test)]
    Memory,
}
enum AgentState {
    Authorized {
        response: Value,
        policy: crate::shadow::ShadowPolicy,
    },
    Unreachable,
    Refused,
}
enum CacheSync {
    Current,
    Deferred,
    Refused,
}
pub fn channel(edition: &str) -> String {
    format!("browser-cache-{edition}")
}
fn edition_channel(edition: &str) -> &str {
    if edition == "commercial" {
        "commercial"
    } else {
        "browser"
    }
}
fn exchange_agent(edition: &str, request: &Value, timeout: Duration) -> Result<Value> {
    crate::ipc::exchange_agent(
        edition_channel(edition),
        edition,
        request,
        timeout,
    )
}
fn projected_policy(response: &Value) -> Result<crate::shadow::ShadowPolicy> {
    if response["ok"] != true
        || response["cache_policy_hash"].as_str().is_none()
        || response["cache_authorization_generation"].as_u64().is_none()
        || response["cache_policy_content_hash"].as_str().is_none()
        || response["cache_catalog_content_hash"].as_str().is_none()
        || response["cache_catalog_revision"].as_u64().is_none()
    {
        return Err("agent policy response invalid".into());
    }
    let mut policy = response["policy"]
        .as_object()
        .cloned()
        .ok_or("agent policy absent")?;
    policy.remove("signed_expires_at");
    Ok(serde_json::from_value(Value::Object(policy))?)
}
fn agent_state(response: Result<Value>) -> AgentState {
    match response {
        Err(_) => AgentState::Unreachable,
        Ok(response) if response["ok"] != true => AgentState::Refused,
        Ok(response) => match projected_policy(&response) {
            Ok(policy) => AgentState::Authorized { response, policy },
            Err(_) => AgentState::Refused,
        },
    }
}
fn cache_matches(response: &Value, journal: &Journal) -> bool {
    response["cache_policy_content_hash"] == journal.policy_content_hash
        && response["cache_catalog_content_hash"] == journal.catalog_content_hash
        && response["cache_catalog_revision"] == journal.catalog_revision
}
pub fn public_pin(edition: &str) -> Result<Pin> {
    let root = Directory::open(&windows::root(edition)?, false)?;
    let pin: Pin = serde_json::from_slice(&root.read("anchor.json", 4096)?)?;
    pin.validate()?;
    if pin.edition != edition {
        return Err("cache pin edition mismatch".into());
    }
    Ok(pin)
}
/// Installer-only setup after it established the directory and registry ACLs.
/// Missing files after initialization are refused, including during MSI repair.
pub fn initialize_msi(edition: &str, package: &Path) -> Result<()> {
    let bytes = crate::bootstrap::msi_provision(package)?;
    if serde_json::from_slice::<Value>(&bytes)? == json!({}) {
        // A generic update package carries no organization. The release anchor then
        // comes from the organization package Windows Installer keeps (SYSTEM-owned),
        // never from the agent-writable state.
        if crate::update::read_anchor(edition)?.is_none() {
            if let Some(provision) = previous_organization(edition)? {
                crate::update::write_anchor(edition, &crate::update::ReleaseAnchor {
                    update_public_key: provision.update_public_key.clone(),
                    server_url: provision.server_url.clone(),
                })?;
            }
        }
        if windows::initialized(edition, false)? {
            let pin = public_pin(edition)?;
            return initialize(edition, &pin.origin, &pin.organization_anchor);
        }
        if let Some(provision) = previous_organization(edition)? {
            return initialize(edition, &provision.server_url, &provision.policy_public_key);
        }
        // Upgrading a legacy generic package cannot manufacture an organization
        // anchor. Connected operation remains available; an organization MSI is
        // needed to provision this optional capability.
        eprintln!("Milvago browser cache requires an organization-provisioned MSI.");
        return Ok(());
    }
    let provision: crate::bootstrap::InstallerProvision = serde_json::from_slice(&bytes)?;
    if provision.edition != edition || provision.platform != "windows" {
        return Err("MSI cache identity mismatch".into());
    }
    // The applier's release trust follows the organization MSI the administrator
    // installs, never the agent-writable state. Pinned before the cache, which may
    // legitimately refuse a first installation for another organization.
    crate::update::write_anchor(edition, &crate::update::ReleaseAnchor {
        update_public_key: provision.update_public_key.clone(),
        server_url: provision.server_url.clone(),
    })?;
    initialize(edition, &provision.server_url, &provision.policy_public_key)
}
pub fn initialize(edition: &str, origin: &str, anchor: &str) -> Result<()> {
    let root = windows::root(edition)?;
    let public = Directory::open(&root, false)?;
    let private = Directory::open(&root.join("private"), true)?;
    if windows::initialized(edition, false)? {
        let pin = public_pin(edition)?;
        if pin.origin != origin || pin.organization_anchor != anchor {
            return Err("cache installation identity changed".into());
        }
        // The running updater owns the mutable journal during MSI. Reinstallation
        // verifies only the immutable protected pin and never recreates state,
        // waits on its lock, or resets a lease while that process is alive.
        return Ok(());
    }
    let _lock = private.lock()?;
    if root.join("anchor.json").exists() || root.join("private/state.bin").exists() {
        return Err("orphan cache state refused".into());
    }
    // Set the non-transactional tombstone first. Interrupted initialization must
    // not look like a fresh installation capable of creating a new grace period.
    windows::initialized(edition, true)?;
    let keys = Keys::generate();
    let pin = Pin {
        installation: uuid::Uuid::new_v4().to_string(),
        edition: edition.into(),
        origin: origin.trim_end_matches('/').into(),
        organization_anchor: anchor.into(),
        signing_key: keys.public(),
    };
    let stored = Stored {
        journal: Journal::new(pin.clone())?,
        keys,
        queue: Default::default(),
    };
    persist(&private, &stored)?;
    public.write("anchor.json", &serde_json::to_vec(&pin)?)?;
    Ok(())
}
fn persist(directory: &Directory, stored: &Stored) -> Result<()> {
    stored.queue.validate()?;
    let queue_hash = cache::hash(&serde_json::to_vec(&stored.queue)?);
    let mut bytes = serde_json::to_vec(stored)?;
    let encrypted = crate::os_wrap(&bytes, true);
    bytes.zeroize();
    commit_snapshot(&encrypted?, |name, bytes| directory.write(name, bytes),
        || windows::save_epoch(&stored.journal, queue_hash))
}
// Stage and verify the encrypted state before advancing the non-rollbackable
// epoch. A failed final replacement leaves an exact recoverable committed copy.
fn commit_snapshot(
    encrypted: &[u8],
    mut write: impl FnMut(&str, &[u8]) -> Result<()>,
    commit_epoch: impl FnOnce() -> Result<()>,
) -> Result<()> {
    write("pending.bin", encrypted)?;
    commit_epoch()?;
    write("state.bin", encrypted)
}

fn decode_snapshot(encrypted: &[u8], pin: &Pin, epoch: &windows::Epoch) -> Result<Stored> {
    let mut bytes = crate::os_wrap(encrypted, false)?;
    let parsed = serde_json::from_slice::<Stored>(&bytes);
    bytes.zeroize();
    let mut stored = parsed?;
    if stored.journal.pin != *pin || stored.keys.public() != pin.signing_key {
        return Err("cache identity mismatch".into());
    }
    stored.queue.validate()?;
    epoch.apply(&mut stored.journal, &cache::hash(&serde_json::to_vec(&stored.queue)?))?;
    Ok(stored)
}

fn committed_snapshot(
    pin: &Pin,
    epoch: &windows::Epoch,
    mut read: impl FnMut(&str) -> Result<Vec<u8>>,
    legacy: impl FnOnce() -> Result<Vec<String>>,
) -> Result<(Stored, Option<Vec<u8>>)> {
    for name in ["state.bin", "pending.bin"] {
        if let Ok(bytes) = read(name) {
            if let Ok(stored) = decode_snapshot(&bytes, pin, epoch) {
                return Ok((stored, (name != "state.bin").then_some(bytes)));
            }
        }
    }
    // Up to 0.5.16, a failed atomic rename left a protected state.<UUID>.tmp.
    // Neither its name nor its timestamp grants authority: the current epoch,
    // exact queue hash, installation pin and signing key must all match.
    for name in legacy()? {
        if let Ok(bytes) = read(&name) {
            if let Ok(stored) = decode_snapshot(&bytes, pin, epoch) {
                return Ok((stored, Some(bytes)));
            }
        }
    }
    Err("cache has no state matching authorization journal".into())
}

impl Authority {
    pub fn open(edition: &str) -> Result<Self> {
        if !windows::initialized(edition, false)? {
            return Err("cache not provisioned".into());
        }
        let root = windows::root(edition)?;
        let public = Directory::open(&root, false)?;
        let pin: Pin = serde_json::from_slice(&public.read("anchor.json", 4096)?)?;
        pin.validate()?;
        if pin.edition != edition {
            return Err("cache edition mismatch".into());
        }
        let directory = Directory::open(&root.join("private"), true)?;
        let lock = directory.lock()?;
        let epoch = windows::read_epoch(edition)?;
        let (stored, recovered) = committed_snapshot(&pin, &epoch,
            |name| directory.read(name, 12 * 1024 * 1024),
            || directory.legacy_snapshots())?;
        if let Some(encrypted) = recovered {
            directory.write("state.bin", &encrypted)?;
        }
        Ok(Self {
            stored,
            storage: Storage::Protected {
                directory,
                _public: public,
                _lock: lock,
            },
            storage_failed: false,
        })
    }
    fn save(&mut self) -> Result<()> {
        // Retain the exact intended state on failure, including any learned
        // revocation or delivered receipt. A retry must never restore older state.
        let result = match &self.storage {
            Storage::Protected { directory, .. } => persist(directory, &self.stored),
            #[cfg(test)]
            Storage::Memory => self.stored.queue.validate(),
        };
        self.storage_failed = result.is_err();
        result
    }
    fn probe(&self) -> Result<Value> {
        crate::ipc::exchange_agent(
            edition_channel(&self.stored.journal.pin.edition),
            &self.stored.journal.pin.edition,
            &json!({"op":"policy_v3"}),
            Duration::from_secs(2),
        )
    }
    pub fn active(&self) -> bool {
        let j = &self.stored.journal;
        j.armed && j.deadline.is_some_and(|end| windows::tick() < end)
    }
    pub fn prepare(&mut self, request: &Value) -> Result<Value> {
        if self.storage_failed { self.save()?; }
        if request["protocol"] != cache::PROTOCOL
            || request["op"] != "cache_prepare"
            || request["origin"] != self.stored.journal.pin.origin
            || request["organization_anchor"] != self.stored.journal.pin.organization_anchor
        {
            return Err("cache source identity refused".into());
        }
        let response = self.probe()?;
        if response["ok"] != true {
            self.stored.journal.invalidate()?;
            self.save()?;
            return Err("agent refused cache".into());
        }
        let boot = windows::boot(&self.stored.journal.pin.edition, true)?;
        self.prepare_response(request, &response, &boot, windows::tick())
    }
    fn prepare_response(&mut self, request: &Value, response: &Value, boot: &str, tick: u64) -> Result<Value> {
        if request["protocol"] != cache::PROTOCOL
            || request["op"] != "cache_prepare"
            || request["origin"] != self.stored.journal.pin.origin
            || request["organization_anchor"] != self.stored.journal.pin.organization_anchor
        {
            return Err("cache source identity refused".into());
        }
        let policy: Envelope = serde_json::from_value(request["policy"].clone())?;
        let catalog: Envelope = serde_json::from_value(request["catalog"].clone())?;
        if response["cache_policy_hash"] != cache::envelope_hash(&policy)?
            || response["cache_authorization_generation"] != request["authorization_generation"]
        {
            return Err("cache source changed during admission".into());
        }
        if let Err(error) = cache::prepare(
            &mut self.stored.journal,
            &self.stored.keys,
            &policy,
            &catalog,
        ) {
            self.stored.journal.invalidate()?;
            self.save()?;
            return Err(error);
        }
        let document = cache::open(&self.stored.journal, &self.stored.keys)?;
        let policy: crate::shadow::ShadowPolicy =
            serde_json::from_value(document["policy"].clone())?;
        self.stored
            .queue
            .restrict(Some(&policy), self.stored.journal.generation);
        self.stored.journal.recovered(boot, tick)?;
        self.save()?;
        Ok(
            json!({"ok":true,"protocol":cache::PROTOCOL,"generation":self.stored.journal.generation}),
        )
    }
    pub fn browser(&mut self, request: &Value, deadline: Instant) -> Result<Value> {
        use crate::browser_broker as broker;
        let parsed = broker::parse(request)?;
        if self.storage_failed {
            self.save()?;
        }
        let outcome = self.answer(&parsed, deadline);
        let (mode, reply) = match outcome {
            Ok(answer) => answer,
            Err(_) => ("blocked", json!({"ok":false,"error":"control_unavailable"})),
        };
        let (mode, reply) = if Instant::now() >= deadline {
            ("blocked", json!({"ok":false,"error":"control_timeout"}))
        } else {
            (mode, reply)
        };
        let remaining = if mode == "grace" {
            self.stored
                .journal
                .deadline
                .unwrap_or(0)
                .saturating_sub(windows::tick())
        } else {
            0
        };
        if mode == "grace" && (remaining == 0 || self.storage_failed) {
            return broker::signed(
                &self.stored.journal,
                &self.stored.keys,
                &parsed,
                "blocked",
                0,
                json!({"ok":false,"error":"cache_expired"}),
            );
        }
        broker::signed(
            &self.stored.journal,
            &self.stored.keys,
            &parsed,
            mode,
            remaining,
            reply,
        )
    }
    /// Background-only maintenance. The Update service calls this through
    /// try_lock, so browser requests have priority and each invocation releases
    /// the authority after at most one durable delivery.
    pub fn maintenance(&mut self) -> Result<()> {
        if self.storage_failed {
            self.save()?;
        }
        let edition = self.stored.journal.pin.edition.clone();
        let mut exchange = |request: &Value| exchange_agent(&edition, request, Duration::from_secs(2));
        let state = agent_state(exchange(&json!({"op":"policy_v3"})));
        let AgentState::Authorized { response, policy } = state else {
            if matches!(state, AgentState::Refused) {
                let _ = self.refuse_agent()?;
            }
            return Ok(());
        };
        self.stored
            .queue
            .restrict(Some(&policy), self.stored.journal.generation);
        self.save()?;
        if self.stored.queue.len() != 0 {
            let _ = self.drain_one_with(&mut exchange)?;
            return Ok(());
        }
        let boot = windows::boot(&edition, true)?;
        match self.sync_cache(&response, &mut exchange, &boot, windows::tick()) {
            CacheSync::Current => self.stored.journal.recovered(&boot, windows::tick())?,
            CacheSync::Deferred => {
                self.stored.journal.armed = false;
                self.stored.journal.deadline = None;
            }
            CacheSync::Refused => {
                let _ = self.refuse_agent()?;
                return Ok(());
            }
        }
        self.save()
    }
    pub fn maintenance_pending(&self) -> bool {
        self.storage_failed || self.stored.queue.len() != 0
    }
    fn drain_one_with(&mut self, exchange: &mut impl FnMut(&Value) -> Result<Value>) -> Result<bool> {
        // Maintenance transfers one row per lock acquisition. Every row remains
        // until the main agent's durable receipt has been observed.
            let _custody = match &self.storage {
                Storage::Protected { directory, .. } => Some(
                    directory.delivery_guard(&self.stored.journal.pin.edition)?,
                ),
                #[cfg(test)]
                Storage::Memory => None,
            };
            let event_sequence = self
                .stored
                .queue
                .pending
                .first()
                .map(|p| p.sequence)
                .unwrap_or(u64::MAX);
            let health_sequence = self
                .stored
                .queue
                .health
                .first()
                .map(|p| p.sequence)
                .unwrap_or(u64::MAX);
            if event_sequence == u64::MAX && health_sequence == u64::MAX {
                return Ok(false);
            }
            let health = health_sequence < event_sequence;
            let (packet, id) = if health {
                let pending = &self.stored.queue.health[0];
                (
                    json!({"op":"broker_event","installation":self.stored.journal.pin.installation,"sequence":pending.sequence,
                    "batch":pending.batch,"tool":pending.tool}),
                    pending.batch["id"].clone(),
                )
            } else {
                let pending = &self.stored.queue.pending[0];
                (
                    json!({"op":"broker_event","installation":self.stored.journal.pin.installation,"sequence":pending.sequence,"event":pending.event}),
                    json!(pending.event.id),
                )
            };
            let response = exchange(&packet)?;
            if response["ok"] != true || response["durable"] != true || response["id"] != id {
                return Err("agent durable receipt absent".into());
            }
            if health {
                self.stored.queue.health.remove(0);
            } else {
                self.stored.queue.pending.remove(0);
            }
            self.save()?;
            Ok(true)
    }
    fn prepare_connected_event(
        &self,
        parsed: &crate::browser_broker::Parsed,
        response: &Value,
        exchange: &mut impl FnMut(&Value) -> Result<Value>,
    ) -> Result<crate::shadow::ShadowEvent> {
        let input = parsed.request.event.as_ref().ok_or("browser event absent")?;
        let answer = exchange(&json!({"op":"broker_prepare_event","event":input}))?;
        let provenance = &answer["provenance"];
        if answer["ok"] != true
            || provenance["policy_revision"] != response["policy"]["revision"]
            || provenance["policy_content_hash"] != response["cache_policy_content_hash"]
            || provenance["authorization_generation"] != response["cache_authorization_generation"]
            || provenance["catalog_revision"] != response["cache_catalog_revision"]
            || provenance["input_hash"] != cache::hash(&serde_json::to_vec(input)?)
        {
            return Err("prepared event authority changed".into());
        }
        Ok(serde_json::from_value(answer["event"].clone())?)
    }
    fn refuse_agent(&mut self) -> Result<(&'static str, Value)> {
        self.stored.journal.invalidate()?;
        self.stored
            .queue
            .restrict(None, self.stored.journal.generation);
        self.save()?;
        Ok(("blocked", json!({"ok":false,"error":"agent_refused"})))
    }
    fn sync_cache(
        &mut self,
        response: &Value,
        exchange: &mut impl FnMut(&Value) -> Result<Value>,
        boot: &str,
        tick: u64,
    ) -> CacheSync {
        if cache_matches(response, &self.stored.journal)
            && cache::open(&self.stored.journal, &self.stored.keys).is_ok()
        {
            return CacheSync::Current;
        }
        // Never change the generation while custody from the preceding live
        // policy is pending. Delivery first preserves both content and receipts.
        if self.stored.queue.len() != 0 {
            return CacheSync::Deferred;
        }
        let source = match exchange(&json!({"op":"broker_cache_source"})) {
            Ok(source) if source["ok"] == true => source,
            Ok(_) => return CacheSync::Refused,
            Err(_) => return CacheSync::Deferred,
        };
        match self.prepare_response(&source, response, boot, tick) {
            Ok(_) if cache_matches(response, &self.stored.journal) => CacheSync::Current,
            Ok(_) => CacheSync::Deferred,
            Err(error) if error.to_string() == "cache source changed during admission" => {
                CacheSync::Deferred
            }
            Err(_) => CacheSync::Refused,
        }
    }
    fn answer(&mut self, parsed: &crate::browser_broker::Parsed, deadline: Instant) -> Result<(&'static str, Value)> {
        let edition = self.stored.journal.pin.edition.clone();
        let mut exchange = |request: &Value| {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or("browser operation deadline exceeded")?;
            exchange_agent(&edition, request, remaining.min(Duration::from_secs(2)))
        };
        let boot = windows::boot(&edition, true)?;
        self.answer_with(parsed, &mut exchange, &boot, windows::tick())
    }
    fn answer_with(
        &mut self,
        parsed: &crate::browser_broker::Parsed,
        exchange: &mut impl FnMut(&Value) -> Result<Value>,
        boot: &str,
        tick: u64,
    ) -> Result<(&'static str, Value)> {
        parsed.check_authority(&self.stored.journal)?;
        let mut document = cache::open(&self.stored.journal, &self.stored.keys);
        let state = agent_state(exchange(&json!({"op":"policy_v3","tool":parsed.request.tool})));
        let (mode, response, policy) = if let AgentState::Authorized { response, policy } = state {
            // Restriction and journal are persisted together, once: every request pays
            // one rewrite of the queue, not two.
            self.stored.queue.restrict(
                Some(&policy),
                self.stored.journal.generation,
            );
            if cache_matches(&response, &self.stored.journal)
                && cache::open(&self.stored.journal, &self.stored.keys).is_ok()
            {
                document = cache::open(&self.stored.journal, &self.stored.keys);
                self.stored.journal.recovered(boot, tick)?;
            } else {
                // A stale SYSTEM copy is repaired by maintenance. Connected
                // operation remains live, but this copy cannot arm later grace.
                self.stored.journal.armed = false;
                self.stored.journal.deadline = None;
            }
            self.save()?;
            if self.storage_failed {
                return Err("broker persistence unavailable".into());
            }
            ("connected", Some(response), policy)
        } else if matches!(state, AgentState::Unreachable) {
            if document.is_err() {
                self.stored.journal.invalidate()?;
                self.stored
                    .queue
                    .restrict(None, self.stored.journal.generation);
                self.save()?;
                return Err("cache invalid".into());
            }
            let remaining = self
                .stored
                .journal
                .remaining(boot, tick, Presence::Unreachable);
            self.save()?;
            remaining?;
            let policy: crate::shadow::ShadowPolicy = serde_json::from_value(
                document.as_ref().map_err(|_| "cache invalid")?["policy"].clone(),
            )?;
            ("grace", None, policy)
        } else {
            return self.refuse_agent();
        };
        let connected = response.is_some();
        let mut admission_journal = self.stored.journal.clone();
        if let Some(response) = &response {
            admission_journal.policy_revision = policy.revision;
            admission_journal.catalog_revision = response["cache_catalog_revision"]
                .as_u64()
                .ok_or("agent catalog revision absent")?;
        }
        match parsed.request.op.as_str() {
            "browser_policy" if connected => {
                let r = response.as_ref().ok_or("agent unavailable")?;
                Ok((
                    mode,
                    json!({"ok":true,"policy":r["policy"],"online":r["online"]}),
                ))
            }
            "browser_policy" => {
                Ok((
                    mode,
                    json!({"ok":true,"policy":crate::native::browser_policy(&policy),"online":false}),
                ))
            }
            // Common policy/clock/revocation checks and queue maintenance above
            // still apply. This lookup itself performs no admission or inspection.
            "browser_receipt" => Ok((
                mode,
                self.stored.queue.receipt(&self.stored.journal, parsed)?,
            )),
            // A completion goes where its event still is. One awaiting delivery is
            // completed here, so an outage loses nothing and nothing extra travels;
            // one already handed to the agent is completed there. A delivery identity
            // this account never used designates neither, and is dropped.
            "browser_complete" => {
                let mut completion = crate::shadow::ShadowCompletion::parse_for(
                    uuid::Uuid::nil(),
                    parsed
                        .request
                        .completion
                        .as_ref()
                        .ok_or("completion absent")?,
                )?;
                let Some(id) = self.stored.queue.completed(&self.stored.journal, parsed)? else {
                    return Ok((mode, json!({"ok":true,"applied":false})));
                };
                completion.id = id;
                if self.stored.queue.complete(&completion) {
                    self.save()?;
                    return Ok((mode, json!({"ok":true,"applied":true})));
                }
                // The agent already holds the event. Failing to reach it costs the
                // enrichment, never the event: the completion is simply not placed.
                let answer = exchange(&json!({"op":"broker_complete","completion":completion}));
                Ok((
                    mode,
                    json!({"ok":true,"applied":answer.is_ok_and(|a| a["ok"] == true)}),
                ))
            }
            "browser_submit" => {
                let mut request = parsed.request.inspection();
                let mut reply = if connected {
                    request["op"] = json!("broker_inspect");
                    let answer = exchange(&request)?;
                    if answer["ok"] != true
                        || answer["policy_content_hash"]
                            != response.as_ref().ok_or("agent unavailable")?["cache_policy_content_hash"]
                    {
                        return Err("inspection policy changed".into());
                    }
                    answer["inspection"].clone()
                } else {
                    crate::native::inspect_authorized_request(&policy, &request)?
                };
                // A transformed/reviewed text requires the person to decide again and
                // send a new request. It can never inherit authorization for the old body.
                if reply["ok"] != true
                    || reply["action"] != "observe"
                    || reply["text"] != request["text"]
                {
                    return Ok((mode, reply));
                }
                let required = policy.config["collection"]["enabled"]
                    .as_bool()
                    .unwrap_or(false);
                reply["recording_required"] = json!(required);
                reply["recorded"] = json!(false);
                if required {
                    let mut custody = parsed.clone();
                    let event = custody
                        .request
                        .event
                        .as_mut()
                        .ok_or("submission event absent")?;
                    let object = event.as_object_mut().ok_or("submission event invalid")?;
                    object.insert("kind".into(), json!("prompt"));
                    object.insert("source".into(), json!("browser"));
                    object.insert("provider".into(), request["provider"].clone());
                    object.insert("tool".into(), request["tool"].clone());
                    object.insert("action".into(), json!("observed"));
                    object.insert("labels".into(), reply["labels"].clone());
                    object.insert(
                        "characters".into(),
                        json!(
                            request["text"]
                                .as_str()
                                .ok_or("submission text absent")?
                                .chars()
                                .count()
                        ),
                    );
                    object.insert("prompt".into(), request["text"].clone());
                    object.remove("response");
                    self.stored
                        .queue
                        .restrict(Some(&policy), self.stored.journal.generation);
                    let id = if let Some(response) = &response {
                        let prepared = self.prepare_connected_event(&custody, response, exchange)?;
                        self.stored.queue.admit_prepared(&admission_journal, &custody, prepared)?
                    } else {
                        self.stored.queue.admit(&admission_journal, &policy, &custody)?
                    };
                    self.save()?;
                    reply["id"] = json!(id);
                    reply["delivery_id"] = json!(parsed.request.delivery_id);
                    reply["durable"] = json!(true);
                    reply["recorded"] = json!(true);
                    if self.storage_failed {
                        return Err("submission custody unavailable".into());
                    }
                }
                Ok((mode, reply))
            }
            "browser_inspect" => {
                // Pending prompts only: informational health batches never refuse one.
                if self.stored.queue.pending.len() >= crate::browser_broker::MAX_EVENTS {
                    return Err("browser queue full".into());
                }
                let request = parsed.request.inspection();
                let reply = if connected {
                    exchange(&request)?
                } else {
                    crate::native::inspect_authorized_request(&policy, &request)?
                };
                Ok((mode, reply))
            }
            "browser_catalog" => {
                let mut reply = if connected {
                    exchange(&json!({"op":"catalog","tool":parsed.request.tool}))?
                } else {
                    let document = document.as_ref().map_err(|_| "cache invalid")?;
                    json!({"ok":true,"catalog":document["catalog"],"revision":self.stored.journal.catalog_revision,
                        "expires_at":chrono::Utc::now()+chrono::Duration::minutes(5),"catalog_state":"ok","excluded_domains":document["excluded_domains"]})
                };
                if let Some(catalog) = reply["catalog"].as_object_mut() {
                    catalog.remove("native_tools");
                }
                Ok((mode, reply))
            }
            "browser_health" => {
                self.stored
                    .queue
                    .restrict(Some(&policy), self.stored.journal.generation);
                self.stored
                    .queue
                    .admit_health(&admission_journal, &policy, parsed)?;
                self.save()?;
                if self.storage_failed {
                    return Err("browser custody failed".into());
                }
                Ok((
                    mode,
                    json!({"ok":true,"durable":true,"accepted_health_ids":[parsed.request.batch.as_ref().ok_or("health absent")?["id"]]}),
                ))
            }
            "browser_event" => {
                self.stored
                    .queue
                    .restrict(Some(&policy), self.stored.journal.generation);
                let id = if let Some(response) = &response {
                    let prepared = self.prepare_connected_event(parsed, response, exchange)?;
                    self.stored.queue.admit_prepared(&admission_journal, parsed, prepared)?
                } else {
                    self.stored.queue.admit(&admission_journal, &policy, parsed)?
                };
                self.save()?;
                if self.storage_failed {
                    return Err("browser custody failed".into());
                }
                Ok((
                    mode,
                    json!({"ok":true,"id":id,"delivery_id":parsed.request.delivery_id,"durable":true}),
                ))
            }
            _ => Err("browser operation refused".into()),
        }
    }
}

/// Best-effort preparation does not affect connected operation with old updater.
/// Called on every watch pass, including failures, so revocation cannot depend on
/// browser activity. The service itself verifies the live policy response.
pub fn prepare_home(home: &Path, edition: &str) -> Result<()> {
    let state = { crate::Store::open(home)?.load()? };
    static PREPARED: std::sync::Mutex<Option<(String, String)>> = std::sync::Mutex::new(None);
    let policy_value = state
        .shadow_policy
        .as_ref()
        .and_then(|e| {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(&e.payload)
                .ok()
        })
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .unwrap_or(Value::Null);
    let fingerprint = cache::hash(&serde_json::to_vec(
        &json!({"edition":edition,"origin":state.server_url,
        "anchor":state.public_key,"revision":state.shadow_revision,"generation":state.authorization_generation,
        "config":policy_value["config"],"capabilities":policy_value["capabilities"],
        "catalog_revision":state.detection.revision,"catalog_hash":state.detection.content_hash}),
    )?);
    if PREPARED
        .lock()
        .map_err(|_| "cache preparation unavailable")?
        .as_ref()
        .is_some_and(|p| p.0 == edition && p.1 == fingerprint)
    {
        return Ok(());
    }
    let request = json!({"protocol":cache::PROTOCOL,"op":"cache_prepare","origin":state.server_url.trim_end_matches('/'),
        "organization_anchor":state.public_key,"authorization_generation":state.authorization_generation,
        "policy":state.shadow_policy,"catalog":state.detection.envelope});
    crate::update::wake_applier(edition)?;
    let response = crate::ipc::exchange_timeout(
        &crate::update::applier_channel(edition),
        crate::ipc::Access::UpdateAgent,
        &request,
        Duration::from_secs(3),
    )?;
    if response["ok"] != true {
        return Err("cache preparation unavailable".into());
    }
    *PREPARED
        .lock()
        .map_err(|_| "cache preparation unavailable")? = Some((edition.into(), fingerprint));
    Ok(())
}

#[link(name = "msi")]
unsafe extern "system" {
    fn MsiEnumRelatedProductsW(
        upgrade: *const u16,
        reserved: u32,
        index: u32,
        product: *mut u16,
    ) -> u32;
    fn MsiGetProductInfoW(
        product: *const u16,
        property: *const u16,
        value: *mut u16,
        length: *mut u32,
    ) -> u32;
}
fn previous_organization(edition: &str) -> Result<Option<crate::bootstrap::InstallerProvision>> {
    let upgrade = match edition {
        "community" => "{7B1E2C90-6F4A-4D2B-9E3C-1A2B3C4D5E6F}",
        "commercial" => "{8C2F3DA1-7A5B-4E3C-8F4D-2B3C4D5E6F70}",
        _ => return Err("invalid MSI family".into()),
    };
    let upgrade: Vec<_> = upgrade.encode_utf16().chain(Some(0)).collect();
    let property: Vec<_> = "LocalPackage".encode_utf16().chain(Some(0)).collect();
    let installer =
        std::path::PathBuf::from(std::env::var_os("WINDIR").ok_or("Windows directory absent")?)
            .join("Installer");
    let directory = Directory::installed(&installer)?;
    let mut found: Option<crate::bootstrap::InstallerProvision> = None;
    for index in 0..64 {
        let mut product = [0u16; 39];
        let code =
            unsafe { MsiEnumRelatedProductsW(upgrade.as_ptr(), 0, index, product.as_mut_ptr()) };
        if code == 259 {
            return Ok(found);
        }
        if code != 0 {
            return Err("installed MSI family unavailable".into());
        }
        let mut local = vec![0u16; 32768];
        let mut length = local.len() as u32;
        if unsafe {
            MsiGetProductInfoW(
                product.as_ptr(),
                property.as_ptr(),
                local.as_mut_ptr(),
                &mut length,
            )
        } != 0
        {
            return Err("installed MSI cache unavailable".into());
        }
        let path = std::path::PathBuf::from(String::from_utf16(&local[..length as usize])?);
        if !path.parent().is_some_and(|p| {
            p.as_os_str()
                .to_string_lossy()
                .eq_ignore_ascii_case(&installer.as_os_str().to_string_lossy())
        }) {
            return Err("installed MSI path outside protected cache".into());
        }
        let _file =
            directory.hold_file(path.file_name().ok_or("installed MSI filename absent")?)?;
        let bytes = crate::bootstrap::msi_provision(&path)?;
        if serde_json::from_slice::<Value>(&bytes)? == json!({}) {
            continue;
        }
        let provision: crate::bootstrap::InstallerProvision = serde_json::from_slice(&bytes)?;
        if provision.edition != edition || provision.platform != "windows" {
            return Err("installed MSI identity mismatch".into());
        }
        if found.as_ref().is_some_and(|p| {
            p.server_url != provision.server_url
                || p.policy_public_key != provision.policy_public_key
        }) {
            return Err("ambiguous installed organization anchors".into());
        }
        found = Some(provision);
    }
    Err("installed MSI family exceeds bound".into())
}

#[cfg(test)]
#[path = "cache_service_tests.rs"]
mod recovery_tests;
