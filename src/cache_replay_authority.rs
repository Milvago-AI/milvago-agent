//! Portable policy-observation and local preparation used by the Windows cache adapter.
use crate::{Result, browser_cache::{self as cache, Journal, Keys, Presence}, browser_broker::Queue, shadow::ShadowPolicy};
use serde_json::{Value, json};
use crate::cache_replay::Reply;

#[derive(PartialEq, Eq)]
pub struct Token { binding: String, epoch: u64, pin:cache::Pin }
impl Token{pub fn same_pin(&self,journal:&Journal)->bool{self.pin==journal.pin}}

pub(crate) enum Input {
    Authorized { response: Value, policy: ShadowPolicy },
    Unreachable,
    Refused,
}
pub(crate) fn classify(response: Option<Value>) -> Input {
    let Some(response) = response else { return Input::Unreachable; };
    if response["ok"] != true { return Input::Refused; }
    let parsed = (|| -> Result<ShadowPolicy> {
        if response["cache_policy_hash"].as_str().is_none()
            || response["cache_authorization_generation"].as_u64().is_none()
            || response["cache_policy_content_hash"].as_str().is_none()
            || response["cache_catalog_content_hash"].as_str().is_none()
            || response["cache_catalog_revision"].as_u64().is_none() {
            return Err("agent policy response invalid".into());
        }
        let mut policy = response["policy"].as_object().cloned().ok_or("agent policy absent")?;
        policy.remove("signed_expires_at");
        Ok(serde_json::from_value(Value::Object(policy))?)
    })();
    match parsed { Ok(policy) => Input::Authorized { response, policy }, Err(_) => Input::Refused }
}
pub(crate) fn matches(response: &Value, journal: &Journal) -> bool {
    response["cache_policy_content_hash"] == journal.policy_content_hash
        && response["cache_catalog_content_hash"] == journal.catalog_content_hash
        && response["cache_catalog_revision"] == journal.catalog_revision
}

#[derive(Default)]
pub(crate) struct Observation {
    live_stamp: Option<String>,
    live_floor: Option<(u64, u64, u64)>,
    epoch: u64,
    presence: Option<Presence>,
    next_probe: u64,
    last_probe: u64,
    last_positive: u64,
}
pub(crate) struct Effect { pub save: bool, pub clear_masked: bool }
impl Observation {
    #[cfg(test)]
    pub fn epoch(&self) -> u64 { self.epoch }
    pub fn token(&self, journal: &Journal) -> Result<Token> {
        Ok(Token { binding:cache::hash(&serde_json::to_vec(&json!({
            "pin":journal.pin,"generation":journal.generation,"policy_revision":journal.policy_revision,
            "policy_content_hash":journal.policy_content_hash,"policy_hash":journal.policy_hash,
            "catalog_revision":journal.catalog_revision,"catalog_content_hash":journal.catalog_content_hash,
            "cache_hash":journal.cache_hash
        }))?), epoch:self.epoch, pin:journal.pin.clone() })
    }
    pub fn accept_changed_token(&self, journal: &Journal, expected: &Token, request: &Value,
        reply: &Reply, ticket: Option<u64>) -> Result<bool> {
        if request["op"] != "policy_v3" || !expected.same_pin(journal) || expected.binding != self.token(journal)?.binding { return Ok(false); }
        let (Reply::Value(value), Some(ticket)) = (reply, ticket) else { return Ok(false); };
        if !matches!(classify(Some(value.clone())), Input::Refused) { return Ok(false); }
        Ok(self.can_accept_refusal(ticket))
    }
    pub fn can_accept_refusal(&self, ticket: u64) -> bool {
        self.presence == Some(Presence::Refused) || ticket >= self.last_positive
    }
    pub fn ticket(&mut self) -> Result<u64> {
        self.next_probe = self.next_probe.checked_add(1).ok_or("cache probe sequence exhausted")?;
        Ok(self.next_probe)
    }
    fn advance(&mut self) -> Result<()> {
        self.epoch = self.epoch.checked_add(1).ok_or("cache authority epoch exhausted")?; Ok(())
    }
    pub fn observe(&mut self, journal: &mut Journal, keys: &Keys, queue: &mut Queue,
        input: Input, ticket: u64, interactive_boot: Option<&str>, tick: u64) -> Result<Effect> {
        let authorized = if let Input::Authorized { response, policy } = &input {
            Some(authorized_state(response, policy)?)
        } else { None };
        if authorized.as_ref().is_some_and(|(_, (generation, revision, catalog))|
            *revision < journal.policy_revision || *catalog < journal.catalog_revision
            || self.live_floor.is_some_and(|old| *generation < old.0 || *revision < old.1 || *catalog < old.2)) {
            return Err("older live authority response refused".into());
        }
        if ticket <= self.last_probe {
            let compatible = match (&input, &authorized) {
                (Input::Authorized { .. }, Some((stamp, floor))) => self.presence == Some(Presence::Valid)
                    && self.live_stamp.as_ref() == Some(stamp) && self.live_floor.as_ref() == Some(floor),
                (Input::Unreachable, _) => self.presence == Some(Presence::Unreachable) && ticket >= self.last_positive,
                (Input::Refused, _) => self.presence == Some(Presence::Refused),
                _ => false,
            };
            if compatible {
                // Reusing an identical observation does not advance a probe clock,
                // epoch, policy floor or presence, so a faster account cannot cancel
                // a slower account that obtained the same authority.
                return if matches!(input, Input::Unreachable) {
                    unreachable_admission(journal, keys, queue, interactive_boot, tick)
                } else { Ok(Effect { save:false, clear_masked:false }) };
            }
            if !matches!(input, Input::Refused) || !self.can_accept_refusal(ticket) {
                return Err("superseded cache probe response".into());
            }
            // A later IO failure is uncertainty, not positive authorization. Keep
            // the older explicit refusal unless a newer positive result superseded it.
        }
        self.last_probe = self.last_probe.max(ticket);
        match input {
            Input::Unreachable => {
                if self.presence != Some(Presence::Unreachable) { self.advance()?; }
                self.presence = Some(Presence::Unreachable);
                unreachable_admission(journal, keys, queue, interactive_boot, tick)
            }
            Input::Refused => {
                if self.live_stamp.as_deref() != Some("refused") || self.presence != Some(Presence::Refused) { self.advance()?; }
                self.live_stamp = Some("refused".into()); self.presence = Some(Presence::Refused);
                if journal.cache.is_some() || journal.armed { journal.invalidate()?; }
                queue.restrict(None, journal.generation);
                Ok(Effect { save: true, clear_masked: true })
            }
            Input::Authorized { response, policy } => {
                let (stamp, (generation, revision, catalog)) = authorized.ok_or("agent normalized state absent")?;
                if policy.revision < journal.policy_revision || catalog < journal.catalog_revision
                    || self.live_floor.is_some_and(|old| generation < old.0 || policy.revision < old.1 || catalog < old.2) {
                    return Err("older live authority response refused".into());
                }
                let changed = self.live_stamp.as_ref().map_or_else(|| !matches(&response, journal), |old| old != &stamp);
                if changed || self.presence.is_some_and(|presence| presence != Presence::Valid) { self.advance()?; }
                self.presence = Some(Presence::Valid); self.live_stamp = Some(stamp);
                self.live_floor = Some((generation, revision, catalog));
                self.last_positive = self.last_positive.max(ticket);
                if changed {
                    queue.restrict(Some(&policy), journal.generation);
                    if !matches(&response, journal) { journal.armed = false; journal.deadline = None; }
                }
                Ok(Effect { save: changed, clear_masked: changed })
            }
        }
    }
}

fn authorized_state(response: &Value, policy: &ShadowPolicy) -> Result<(String, (u64, u64, u64))> {
    let generation = response["cache_authorization_generation"].as_u64().ok_or("agent generation absent")?;
    let catalog = response["cache_catalog_revision"].as_u64().ok_or("agent catalog revision absent")?;
    let stamp = cache::hash(&serde_json::to_vec(&json!({
        "generation":generation,"revision":policy.revision,"version":policy.version,
        "config":policy.config,"capabilities":policy.capabilities,
        "policy_hash":response["cache_policy_content_hash"],
        "catalog_revision":catalog,"catalog_hash":response["cache_catalog_content_hash"]
    }))?);
    Ok((stamp, (generation, policy.revision, catalog)))
}

fn unreachable_admission(journal: &mut Journal, keys: &Keys, queue: &mut Queue,
    boot: Option<&str>, tick: u64) -> Result<Effect> {
    let mut save=false;
    if let Some(boot) = boot {
        if cache::open(journal, keys).is_err() {
            if journal.cache.is_some()||journal.armed{journal.invalidate()?;queue.restrict(None,journal.generation);save=true;}
        }else if journal.deadline.is_none(){
            let before=(journal.armed,journal.deadline,journal.last_tick);
            let _=journal.remaining(boot,tick,Presence::Unreachable);
            save=before!=(journal.armed,journal.deadline,journal.last_tick);
        }
    }
    Ok(Effect { save, clear_masked:false })
}

/// Private work descriptions are generated by Authority, never accepted over IPC.
pub(crate) fn local_work(request: &Value) -> Option<Result<Value>> {
    let operation = request["op"].as_str()?;
    if !matches!(operation, "cache_local_inspect" | "cache_local_event") { return None; }
    Some((|| {
        let policy: ShadowPolicy = serde_json::from_value(request["policy"].clone())?;
        if operation == "cache_local_inspect" {
            return crate::native::inspect_authorized_request(&policy, &request["request"]);
        }
        let catalog = request["catalog_revision"].as_u64().ok_or("local event catalog absent")?;
        let input = request["input"].clone();
        let mut event = if request["trace"].is_null() { crate::shadow::browser_event(&policy, catalog, input)? }
            else { crate::shadow::dlp_transport::event(&policy, catalog, input, serde_json::from_value(request["trace"].clone())?)? };
        event.id = uuid::Uuid::nil(); event.user = None;
        Ok(serde_json::to_value(event)?)
    })())
}

/// Once offered, only current privacy/retention narrowing may change a row.
pub(crate) fn narrow_offered(current:&crate::shadow::ShadowEvent,value:&Value)->Result<crate::shadow::ShadowEvent>{
    let offered:crate::shadow::ShadowEvent=serde_json::from_value(value.clone())?;
    let mut allowed=current.clone();
    if offered.prompt.is_none(){allowed.prompt=None;}
    if offered.response.is_none(){allowed.response=None;}
    if offered.files.is_empty(){allowed.files.clear();}
    if serde_json::to_value(&allowed)?!=serde_json::to_value(&offered)?{return Err("handoff event changed beyond privacy narrowing".into());}
    Ok(offered)
}
