//! Bounded browser requests and durable, browser-only event custody.
//! No operation exposes the cache, its encryption key, or arbitrary signing.
use crate::{
    Result,
    browser_cache::{self as cache, Journal, Keys},
    shadow::{ShadowCompletion, ShadowEvent, ShadowPolicy},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const PROTOCOL: u32 = 2;
pub fn capabilities() -> Value {
    json!({"version":env!("CARGO_PKG_VERSION"),"edition":crate::extension_update::EDITION,
    "browser_protocol":PROTOCOL,"model_control":cfg!(feature="model-control")})
}
pub const MAX_EVENTS: usize = 1000;
pub const MAX_BYTES: usize = 8 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wrapper {
    protocol: u32,
    op: String,
    body: String,
    #[serde(default)]
    caller: Value,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub protocol: u32,
    pub op: String,
    pub challenge: String,
    pub tool: String,
    #[serde(default)]
    pub expected_authority: Option<String>,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub upload: Option<bool>,
    #[serde(default)]
    pub check_model: Option<bool>,
    #[serde(default)]
    pub platform_id: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub event: Option<Value>,
    #[serde(default)]
    pub delivery_id: Option<String>,
    #[serde(default)]
    pub batch: Option<Value>,
    #[serde(default)]
    pub completion: Option<Value>,
}
#[derive(Clone)]
pub struct Parsed {
    pub request: Request,
    pub hash: String,
    pub user: String,
    pub principal: String,
}
pub fn parse(value: &Value) -> Result<Parsed> {
    let wrapper: Wrapper = serde_json::from_value(value.clone())?;
    if wrapper.protocol != PROTOCOL
        || wrapper.op != "browser_request"
        || wrapper.body.len() > 512 * 1024
    {
        return Err("browser protocol refused".into());
    }
    let raw = STANDARD.decode(&wrapper.body)?;
    let request: Request = serde_json::from_slice(&raw)?;
    let fields: Value = serde_json::from_slice(&raw)?;
    if fields.get("expected_authority").is_some()
        && request.expected_authority.as_ref().is_none_or(|s| {
            s.len() != 64
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
    {
        return Err("browser expected authority invalid".into());
    }
    if request.protocol != PROTOCOL
        || STANDARD.decode(&request.challenge)?.len() != 32
        || !crate::shadow::BROWSER_TOOLS.contains(&request.tool.as_str())
    {
        return Err("browser request identity refused".into());
    }
    let inspect = matches!(request.op.as_str(), "browser_inspect" | "browser_submit");
    let event = matches!(request.op.as_str(), "browser_event" | "browser_submit");
    let health = request.op == "browser_health";
    let receipt = request.op == "browser_receipt";
    let complete = request.op == "browser_complete";
    if !matches!(
        request.op.as_str(),
        "browser_policy"
            | "browser_inspect"
            | "browser_event"
            | "browser_catalog"
            | "browser_health"
            | "browser_submit"
            | "browser_receipt"
            | "browser_complete"
    ) || (complete != request.completion.is_some())
        || (!inspect
        && (request.provider.is_some()
            || request.text.is_some()
            || request.upload.is_some()
            || request.check_model.is_some()
            || request.model.is_some()
            || request.platform_id.is_some()))
        || ((!event && request.event.is_some())
            || (!event && !receipt && !complete && request.delivery_id.is_some()))
        || (health != request.batch.is_some())
    {
        return Err("browser operation fields refused".into());
    }
    if receipt {
        if fields
            .as_object()
            .ok_or("browser receipt fields refused")?
            .keys()
            .any(|k| {
                !matches!(
                    k.as_str(),
                    "protocol" | "op" | "challenge" | "tool" | "delivery_id" | "expected_authority"
                )
            })
        {
            return Err("browser receipt fields refused".into());
        }
        uuid::Uuid::parse_str(
            request
                .delivery_id
                .as_deref()
                .ok_or("delivery identity missing")?,
        )?;
    }
    if complete {
        // A completion names the send it enriches, and says nothing else: it carries
        // no event, no text and no decision.
        uuid::Uuid::parse_str(
            request
                .delivery_id
                .as_deref()
                .ok_or("delivery identity missing")?,
        )?;
    }
    if inspect {
        if !request.provider.as_deref().is_some_and(crate::domain_ok)
            || request.text.as_ref().is_none_or(|s| s.len() > 32 * 1024)
            || request.upload.is_none()
            || request.model.as_ref().is_some_and(|s| s.len() > 200)
            || request.platform_id.as_ref().is_some_and(|s| s.len() > 80)
        {
            return Err("browser inspection fields refused".into());
        }
        #[cfg(not(feature = "model-control"))]
        if request.check_model == Some(true) || request.model.is_some() {
            return Err("model control unavailable".into());
        }
    }
    if event {
        uuid::Uuid::parse_str(
            request
                .delivery_id
                .as_deref()
                .ok_or("delivery identity missing")?,
        )?;
        if request
            .event
            .as_ref()
            .is_none_or(|e| !e.is_object() || e["tool"] != request.tool)
        {
            return Err("browser event fields refused".into());
        }
    }
    let user = crate::session_user::sanitize(wrapper.caller["user"].as_str().unwrap_or(""));
    if user.is_empty() {
        return Err("browser account unavailable".into());
    }
    let principal = wrapper.caller["sid"]
        .as_str()
        .filter(|s| {
            s.starts_with("S-1-")
                && s.len() <= 184
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || b == b'-' || b == b'S')
        })
        .ok_or("browser principal unavailable")?
        .to_string();
    Ok(Parsed {
        hash: cache::hash(&raw),
        request,
        user,
        principal,
    })
}
pub fn authority_hash(pin: &cache::Pin) -> Result<String> {
    Ok(cache::hash(&serde_json::to_vec(&json!([
        pin.installation,
        pin.edition,
        pin.origin,
        pin.organization_anchor,
        pin.signing_key
    ]))?))
}
impl Parsed {
    pub fn check_authority(&self, journal: &Journal) -> Result<()> {
        if self
            .request
            .expected_authority
            .as_ref()
            .is_some_and(|expected| {
                authority_hash(&journal.pin)
                    .as_ref()
                    .map_or(true, |actual| actual != expected)
            })
        {
            return Err("browser authority changed".into());
        }
        Ok(())
    }
}
impl Request {
    pub fn inspection(&self) -> Value {
        json!({"op":"inspect","tool":self.tool,"provider":self.provider,"text":self.text,"upload":self.upload,
        "check_model":self.check_model.unwrap_or(false),"platform_id":self.platform_id,"model":self.model})
    }
}
pub fn signed(
    journal: &Journal,
    keys: &Keys,
    parsed: &Parsed,
    mode: &str,
    remaining: u64,
    reply: Value,
) -> Result<Value> {
    if !matches!(mode, "connected" | "grace" | "blocked")
        || keys.public() != journal.pin.signing_key
        || (mode == "grace" && (remaining == 0 || remaining > cache::GRACE_MS || !journal.armed))
    {
        return Err("browser response refused".into());
    }
    let envelope=keys.sign(&json!({"kind":"milvago.browser-response.v2","protocol":PROTOCOL,"pin":journal.pin,
        "challenge":parsed.request.challenge,"request_hash":parsed.hash,"generation":journal.generation,
        "mode":mode,"remaining_ms":remaining,"reply":reply}))?;
    Ok(json!({"ok":true,"protocol":PROTOCOL,"signed":envelope}))
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pending {
    pub sequence: u64,
    pub generation: u64,
    pub event: ShadowEvent,
    /// The OS principal that admitted it, for its share of the machine-wide queue.
    #[serde(default)]
    pub principal: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    key: String,
    hash: String,
    id: uuid::Uuid,
    /// The account that earned it, for its share of the ring; empty before 0.5.49.
    #[serde(default)]
    principal: String,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Queue {
    pub sequence: u64,
    pub pending: Vec<Pending>,
    #[serde(default)]
    pub health: Vec<PendingHealth>,
    receipts: Vec<Receipt>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingHealth {
    pub sequence: u64,
    pub generation: u64,
    pub batch: Value,
    pub tool: String,
    #[serde(default)]
    pub principal: String,
}
// One account's share of the SYSTEM queue every account shares: beyond it, only that
// account is refused (events) or loses its own oldest batch (health), never the others.
pub(crate) const PRINCIPAL_EVENTS: usize = 250;
const PRINCIPAL_EVENT_BYTES: usize = 2 * 1024 * 1024;
pub(crate) const PRINCIPAL_HEALTH: usize = 64;
const PRINCIPAL_HEALTH_BYTES: usize = 512 * 1024;
fn stable_id(key: &str) -> uuid::Uuid {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(key.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes)
}
fn delivery_key(journal: &Journal, parsed: &Parsed) -> Result<String> {
    Ok(cache::hash(&serde_json::to_vec(&json!([
        journal.pin.installation,
        parsed.principal,
        parsed.request.delivery_id
    ]))?))
}
fn sequences_overlap(pending: &[Pending], health: &[PendingHealth]) -> bool {
    let (mut event, mut batch) = (0, 0);
    while event < pending.len() && batch < health.len() {
        match pending[event].sequence.cmp(&health[batch].sequence) {
            std::cmp::Ordering::Less => event += 1,
            std::cmp::Ordering::Greater => batch += 1,
            std::cmp::Ordering::Equal => return true,
        }
    }
    false
}
impl Queue {
    /// Custody lookup only. It never admits an event or authorizes a user gesture.
    pub fn receipt(&self, journal: &Journal, parsed: &Parsed) -> Result<Value> {
        parsed.check_authority(journal)?;
        self.validate()?;
        if parsed.request.op != "browser_receipt" {
            return Err("browser receipt operation refused".into());
        }
        let key = delivery_key(journal, parsed)?;
        Ok(match self.receipts.iter().find(|r| r.key == key) {
            Some(receipt) => {
                json!({"ok":true,"durable":true,"id":receipt.id,"delivery_id":parsed.request.delivery_id})
            }
            None => json!({"ok":true,"durable":false,"delivery_id":parsed.request.delivery_id}),
        })
    }
    /// The event identity a delivery was given, for a completion. Custody is not
    /// touched: the receipt that binds a delivery to its payload stays as `admit`
    /// wrote it, so the anti-duplicate rule keeps working unchanged. The key includes
    /// the calling account, so one account cannot name another's delivery.
    pub fn completed(&self, journal: &Journal, parsed: &Parsed) -> Result<Option<uuid::Uuid>> {
        parsed.check_authority(journal)?;
        self.validate()?;
        let key = delivery_key(journal, parsed)?;
        Ok(self.receipts.iter().find(|r| r.key == key).map(|r| r.id))
    }
    /// Complete an event still awaiting delivery, where it stands. Nothing extra
    /// travels, and an outage does not lose what the request said.
    pub fn complete(&mut self, completion: &ShadowCompletion) -> bool {
        let Some(index) = self.pending.iter().position(|p| p.event.id == completion.id) else {
            return false;
        };
        // A completion that would take the queue past its bounds is not placed: kept in
        // memory, it would fail every later save and wedge the queue for all accounts.
        let before = self.pending[index].event.clone();
        completion.apply(&mut self.pending[index].event);
        if self.validate().is_err() {
            self.pending[index].event = before;
            return false;
        }
        true
    }
    pub fn len(&self) -> usize {
        self.pending.len() + self.health.len()
    }
    /// Keep a receipt within its account's share of the ring. The ring is shared by
    /// every account of the machine, and any signed-in user reaches this queue: with a
    /// single global eviction, one account delivering in a loop pushed out everyone
    /// else's receipts, and their retries lost the anti-duplicate guarantee. An account
    /// at its share now gives up its own oldest receipt.
    fn keep_receipt(&mut self, receipt: Receipt) {
        let mut own = self.receipts.iter().enumerate().filter(|(_, r)| r.principal == receipt.principal);
        if let Some((oldest, _)) = own.next() {
            if own.count() + 1 >= PRINCIPAL_EVENTS {
                self.receipts.remove(oldest);
            }
        }
        self.receipts.push(receipt);
        if self.receipts.len() > MAX_EVENTS {
            self.receipts.remove(0);
        }
    }
    pub fn validate(&self) -> Result<()> {
        if self.len() > MAX_EVENTS
            || self.receipts.len() > MAX_EVENTS
            || crate::shadow::serialized_size(self)? > MAX_BYTES
            || self
                .pending
                .iter()
                .any(|p| p.sequence == 0 || p.sequence > self.sequence)
            || self
                .pending
                .windows(2)
                .any(|p| p[0].sequence >= p[1].sequence)
            || self
                .health
                .iter()
                .any(|p| p.sequence == 0 || p.sequence > self.sequence)
            || self
                .health
                .windows(2)
                .any(|p| p[0].sequence >= p[1].sequence)
            || sequences_overlap(&self.pending, &self.health)
        {
            return Err("browser queue invalid".into());
        }
        Ok(())
    }
    pub fn admit(
        &mut self,
        journal: &Journal,
        policy: &ShadowPolicy,
        parsed: &Parsed,
    ) -> Result<uuid::Uuid> {
        parsed.check_authority(journal)?;
        self.validate()?;
        let input = parsed
            .request
            .event
            .as_ref()
            .ok_or("browser event absent")?;
        let event = crate::shadow::browser_event(policy, journal.catalog_revision, input.clone())?;
        self.admit_event(journal, parsed, input, event)
    }
    /// Admit only an event prepared by the privileged main agent. Browser input
    /// remains the receipt/deduplication payload; the prepared value is a separate
    /// type at this boundary and receives its durable identity and OS account here.
    pub fn admit_prepared(
        &mut self,
        journal: &Journal,
        parsed: &Parsed,
        event: ShadowEvent,
    ) -> Result<uuid::Uuid> {
        parsed.check_authority(journal)?;
        self.validate()?;
        let input = parsed.request.event.as_ref().ok_or("browser event absent")?;
        if event.id != uuid::Uuid::nil()
            || event.user.is_some()
            || event.policy_revision != journal.policy_revision
            || event.catalog_revision.is_some_and(|revision| revision > journal.catalog_revision)
            || event.source != "browser"
            || event.tool != parsed.request.tool
        {
            return Err("prepared browser event invalid".into());
        }
        self.admit_event(journal, parsed, input, event)
    }
    fn admit_event(
        &mut self,
        journal: &Journal,
        parsed: &Parsed,
        input: &Value,
        mut event: ShadowEvent,
    ) -> Result<uuid::Uuid> {
        let key = delivery_key(journal, parsed)?;
        let hash = cache::hash(&serde_json::to_vec(input)?);
        if let Some(old) = self.receipts.iter().find(|r| r.key == key) {
            if old.hash != hash {
                return Err("delivery identity collision".into());
            }
            return Ok(old.id);
        }
        if self.len() >= MAX_EVENTS {
            return Err("browser queue full".into());
        }
        let mut own = (0, 0);
        for pending in self.pending.iter().filter(|p| p.principal == parsed.principal) {
            own = (own.0 + 1, own.1 + crate::shadow::serialized_size(&pending.event)?);
        }
        if own.0 >= PRINCIPAL_EVENTS || own.1 >= PRINCIPAL_EVENT_BYTES {
            return Err("browser queue full".into());
        }
        event.user = Some(parsed.user.clone());
        event.id = stable_id(&key);
        let id = event.id;
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or("browser queue sequence exhausted")?;
        let mut next = self.clone();
        next.pending.push(Pending {
            sequence,
            generation: journal.generation,
            event,
            principal: parsed.principal.clone(),
        });
        next.keep_receipt(Receipt { key, hash, id, principal: parsed.principal.clone() });
        next.sequence = sequence;
        next.validate()?;
        *self = next;
        Ok(id)
    }
    pub fn admit_health(
        &mut self,
        journal: &Journal,
        policy: &ShadowPolicy,
        parsed: &Parsed,
    ) -> Result<()> {
        parsed.check_authority(journal)?;
        self.validate()?;
        let batch = parsed.request.batch.as_ref().ok_or("health batch absent")?;
        crate::detection::validate_health(
            policy,
            &journal.pin.origin,
            batch,
            &parsed.request.tool,
        )?;
        let key = cache::hash(&serde_json::to_vec(&json!([
            journal.pin.installation,
            parsed.principal,
            "health",
            batch["id"]
        ]))?);
        let hash = cache::hash(&serde_json::to_vec(batch)?);
        if let Some(old) = self.receipts.iter().find(|r| r.key == key) {
            if old.hash != hash {
                return Err("health identity collision".into());
            }
            return Ok(());
        }
        if self.len() >= MAX_EVENTS {
            return Err("browser queue full".into());
        }
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or("browser queue sequence exhausted")?;
        let id = stable_id(&key);
        let mut batch = batch.clone();
        batch["id"] = json!(id);
        let mut next = self.clone();
        // Health is informational: past its share, an account loses its own oldest batch.
        let incoming = crate::shadow::serialized_size(&batch)?;
        loop {
            let mut own = (0, 0, None);
            for (at, health) in next.health.iter().enumerate().filter(|(_, h)| h.principal == parsed.principal) {
                own = (own.0 + 1, own.1 + crate::shadow::serialized_size(&health.batch)?, own.2.or(Some(at)));
            }
            match own {
                (count, bytes, Some(oldest)) if count >= PRINCIPAL_HEALTH || bytes + incoming > PRINCIPAL_HEALTH_BYTES => {
                    next.health.remove(oldest);
                }
                _ => break,
            }
        }
        if incoming > PRINCIPAL_HEALTH_BYTES {
            return Err("health batch too large".into());
        }
        next.health.push(PendingHealth {
            sequence,
            generation: journal.generation,
            batch,
            tool: parsed.request.tool.clone(),
            principal: parsed.principal.clone(),
        });
        next.keep_receipt(Receipt { key, hash, id, principal: parsed.principal.clone() });
        next.sequence = sequence;
        next.validate()?;
        *self = next;
        Ok(())
    }
    pub fn restrict(&mut self, policy: Option<&ShadowPolicy>, generation: u64) {
        for health in &mut self.health {
            crate::detection::restrict_health(
                &mut health.batch,
                policy.filter(|_| health.generation == generation),
            );
        }
        for pending in &mut self.pending {
            let event = &mut pending.event;
            if policy.is_none_or(|p| {
                pending.generation != generation
                    || !p.config["collection"]["enabled"].as_bool().unwrap_or(false)
                    || !p.config["collection"]["store_content"]
                        .as_bool()
                        .unwrap_or(false)
                    || event.policy_revision != p.revision
                    || crate::shadow::content_expired(p, event)
            }) {
                event.discard_content()
            }
            if policy.is_none_or(|p| {
                pending.generation != generation
                    || !p.config["collection"]["enabled"].as_bool().unwrap_or(false)
                    || !p.config["collection"]["store_file_names"]
                        .as_bool()
                        .unwrap_or(false)
                    || event.policy_revision != p.revision
                    || crate::shadow::content_expired(p, event)
            }) {
                event.files.clear()
            }
        }
    }
}

/// One monotone receipt per installed authority; bounded independently of the
/// legacy receipt ring. A lost acknowledgement never requeues an earlier event.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentReceipt {
    pub installation: String,
    pub sequence: u64,
    pub id: uuid::Uuid,
}
/// Answers the reply and whether the state changed. A tuple rather than
/// `Result<(Value, bool)>` on purpose: the flag has to survive the ERROR paths too.
/// `restrict_health_queue` and `discard_unpermitted` both run before most of the
/// refusals below, so their work must still be persisted even when the call is refused
/// — and the refusals that persist nothing are the common ones, because the extension
/// re-sends until it sees its id acknowledged.
pub fn receive(state: &mut crate::State, request: &Value) -> (Result<Value>, bool) {
    let mut changed = false;
    let reply = receive_into(state, request, &mut changed);
    (reply, changed)
}

fn receive_into(state: &mut crate::State, request: &Value, changed: &mut bool) -> Result<Value> {
    if request["caller"]["system"] != true {
        return Err("browser broker requires SYSTEM".into());
    }
    let installation = request["installation"]
        .as_str()
        .ok_or("broker identity missing")?;
    uuid::Uuid::parse_str(installation)?;
    let sequence = request["sequence"]
        .as_u64()
        .filter(|s| *s > 0)
        .ok_or("broker sequence missing")?;
    if let Some(batch) = request.get("batch") {
        *changed |= crate::detection::restrict_health_queue(state);
        let id = uuid::Uuid::parse_str(batch["id"].as_str().ok_or("health identity absent")?)?;
        if let Some(receipt) = &state.browser_broker_receipt {
            if receipt.installation != installation || sequence < receipt.sequence {
                return Err("old health authority".into());
            }
            if sequence == receipt.sequence {
                if receipt.id != id {
                    return Err("health sequence collision".into());
                }
                return Ok(json!({"ok":true,"durable":true,"id":id}));
            }
        }
        let policy = crate::shadow::cached(state)?;
        let mut batch = batch.clone();
        // Narrows the local copy, not `state`: nothing to report to `changed` here.
        // The success path below sets it unconditionally; the error paths must not,
        // or the caller re-encrypts a store that did not move.
        crate::detection::restrict_health(&mut batch, Some(&policy));
        let start = chrono::DateTime::parse_from_rfc3339(
            batch["window_start"]
                .as_str()
                .ok_or("health window absent")?,
        )?;
        if start >= chrono::Utc::now() - chrono::Duration::days(30) {
            *changed |= crate::detection::enqueue_health(
                state,
                &batch,
                request["tool"].as_str().ok_or("health tool absent")?,
            )?;
        }
        *changed = true;
        state.browser_broker_receipt = Some(AgentReceipt {
            installation: installation.into(),
            sequence,
            id,
        });
        return Ok(json!({"ok":true,"durable":true,"id":id}));
    }
    let mut event: ShadowEvent = serde_json::from_value(request["event"].clone())?;
    *changed |= crate::shadow::discard_unpermitted(state);
    if let Some(receipt) = &state.browser_broker_receipt {
        if receipt.installation != installation {
            return Err("foreign browser broker".into());
        }
        if sequence < receipt.sequence {
            return Err("old browser delivery".into());
        }
        if sequence == receipt.sequence {
            if event.id != receipt.id {
                return Err("browser delivery collision".into());
            }
            return Ok(json!({"ok":true,"durable":true,"id":event.id}));
        }
    }
    let policy = crate::shadow::cached(state)?;
    // Retention is applied before accepting or retrying custody, including when
    // collection was turned off during the outage.
    let collect = policy.config["collection"]["enabled"]
        .as_bool()
        .unwrap_or(false);
    if collect {
        let id = event.id;
        let occurred = event.occurred_at;
        let user = event.user.clone();
        let revision = event.policy_revision;
        if !policy.config["collection"]["store_file_names"]
            .as_bool()
            .unwrap_or(false)
            || event.policy_revision != policy.revision
            || crate::shadow::content_expired(&policy, &event)
        {
            event.files.clear()
        }
        if !policy.config["collection"]["store_content"]
            .as_bool()
            .unwrap_or(false)
            || event.policy_revision != policy.revision
            || crate::shadow::content_expired(&policy, &event)
        {
            event.discard_content()
        }
        let mut input = serde_json::to_value(&event)?;
        let obj = input.as_object_mut().ok_or("invalid broker event")?;
        for key in ["id", "occurred_at", "user"] {
            obj.remove(key);
        }
        *changed = true;
        // An event the current policy refuses for good (its service was disabled since
        // SYSTEM admitted it) is acknowledged and dropped, as when collection is off:
        // refused forever, it would wedge the head of the machine-wide SYSTEM queue.
        if crate::shadow::browser_event(&policy, state.detection.revision, input.clone()).is_err() {
            state.browser_broker_receipt = Some(AgentReceipt { installation: installation.into(), sequence, id });
            return Ok(json!({"ok":true,"durable":true,"id":id}));
        }
        let generated = crate::shadow::enqueue_browser(state, input)?;
        let received = state
            .shadow_queue
            .iter_mut()
            .find(|e| e.id == generated)
            .ok_or("broker event not queued")?;
        received.id = id;
        received.occurred_at = occurred;
        received.user = user;
        received.policy_revision = revision;
        // OS attribution is added after parsing; include it in the admission budget.
        if let Err(error) = crate::config::current().queue.check(state, 0, 0) {
            state.shadow_queue.pop();
            return Err(error);
        }
    }
    *changed = true;
    state.browser_broker_receipt = Some(AgentReceipt {
        installation: installation.into(),
        sequence,
        id: event.id,
    });
    Ok(json!({"ok":true,"durable":true,"id":event.id}))
}
