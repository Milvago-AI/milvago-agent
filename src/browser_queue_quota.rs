//! Internal browser admission ownership. This metadata never leaves the encrypted store.
use crate::{Result, State};
use serde_json::Value;
use std::collections::HashSet;
use uuid::Uuid;

const UNKNOWN: &str = "unknown";
const MAX_EVENTS: usize = 250;
const MAX_BYTES: usize = 2 * 1024 * 1024;

fn sid(value: &str) -> bool {
    let Some(tail) = value.strip_prefix("S-1-") else { return false };
    value.len() <= 184 && !tail.is_empty() && tail.split('-').all(|part|
        !part.is_empty() && (part == "0" || !part.starts_with('0'))
            && part.bytes().all(|byte| byte.is_ascii_digit()) && part.parse::<u64>().is_ok())
}

fn valid(owner: &str) -> bool {
    owner == UNKNOWN || owner.strip_prefix("sid:").is_some_and(sid)
        || owner.strip_prefix("uid:").is_some_and(|uid|
            uid.parse::<u32>().is_ok_and(|value|value.to_string() == uid))
}

/// Only use after the transport overwrote caller with kernel credentials.
pub(crate) fn caller_owner(request: &Value) -> Result<String> {
    if let Some(raw) = request["caller"]["sid"].as_str() {
        if !sid(raw) { return Err("browser principal invalid".into()) }
        return Ok(format!("sid:{raw}"));
    }
    if let Some(uid) = request["caller"]["uid"].as_u64() {
        let uid = u32::try_from(uid).map_err(|_| "browser UID invalid")?;
        return Ok(format!("uid:{uid}"));
    }
    // Older relays and undetermined peers share a conservative bucket. Missing
    // identity never means an unlimited or freshly generated account.
    Ok(UNKNOWN.into())
}

/// Only use after authenticating the privileged broker transport. Older broker
/// versions omitted this field, so their rows remain conservatively unattributed.
pub(crate) fn broker_owner(request: &Value) -> Result<String> {
    match request.get("quota_principal") {
        None => Ok(UNKNOWN.into()),
        Some(value) => {
            let raw = value.as_str().ok_or("browser quota principal invalid")?;
            if raw.is_empty() { return Ok(UNKNOWN.into()) }
            if !sid(raw) { return Err("browser quota principal invalid".into()) }
            Ok(format!("sid:{raw}"))
        }
    }
}

/// Drop stale ownership after ACK/discard, and never elevate malformed legacy state.
pub(crate) fn prune(state: &mut State) -> bool {
    let queued: HashSet<_> = state.shadow_queue.iter()
        .filter(|event|event.source == "browser").map(|event|event.id).collect();
    let before = state.browser_queue_owners.len();
    state.browser_queue_owners.retain(|id,owner|queued.contains(id) && valid(owner));
    before != state.browser_queue_owners.len()
}

fn ownership_bytes(id: Uuid, owner: &str) -> Result<usize> {
    // One object entry plus comma; the global queue check accounts its full object.
    Ok(crate::shadow::serialized_size(&id)?.saturating_add(1)
        .saturating_add(crate::shadow::serialized_size(owner)?).saturating_add(1))
}

fn check_account(state: &State, id: Uuid, owner: &str) -> Result<()> {
    let limits = crate::config::current().queue;
    let count_limit = MAX_EVENTS.min((limits.max_events / 2).max(1));
    let bytes_limit = MAX_BYTES.min((limits.max_bytes / 2).max(1));
    let mut count = 0usize;
    // Conservative array brackets, ownership object braces, and row separators.
    let mut bytes = 4usize;
    for event in state.shadow_queue.iter().filter(|event|event.source == "browser") {
        let charged = if event.id == id { owner }
            else { state.browser_queue_owners.get(&event.id).map(String::as_str).unwrap_or(UNKNOWN) };
        // Legacy/unknown rows count against EVERY account until drained. They
        // cannot be assigned to a principal from their display user field.
        if owner == UNKNOWN || charged == UNKNOWN || charged == owner {
            count = count.saturating_add(1);
            bytes = bytes.saturating_add(crate::shadow::serialized_size(event)?).saturating_add(1)
                .saturating_add(ownership_bytes(event.id, charged)?);
        }
    }
    if count > count_limit || bytes > bytes_limit {
        return Err("browser account queue share full".into());
    }
    Ok(())
}

/// Claim a just-appended, fully attributed browser row, atomically with its quota.
/// On error the caller must roll back that new row before returning or saving.
pub(crate) fn claim(state: &mut State, id: Uuid, owner: String) -> Result<()> {
    prune(state);
    if !valid(&owner) { return Err("browser quota owner invalid".into()) }
    if state.shadow_queue.iter().filter(|event|event.id == id && event.source == "browser").count() != 1 {
        return Err("browser queue identity collision".into());
    }
    if state.browser_queue_owners.contains_key(&id) {
        return Err("browser queue already owned".into());
    }
    check_account(state, id, &owner)?;
    state.browser_queue_owners.insert(id, owner);
    if let Err(error) = crate::config::current().queue.check(state, 0, 0) {
        state.browser_queue_owners.remove(&id);
        return Err(error);
    }
    Ok(())
}

/// Validate only actual growth. A capacity reduction must not invalidate an
/// unchanged durable row; enrichment may never grow it beyond account/global caps.
pub(crate) fn check_growth(state: &State, id: Uuid) -> Result<()> {
    if state.shadow_queue.iter().any(|event|event.id == id && event.source == "browser") {
        let owner = state.browser_queue_owners.get(&id).map(String::as_str).unwrap_or(UNKNOWN);
        check_account(state, id, owner)?;
    }
    crate::config::current().queue.check(state, 0, 0)
}

pub(crate) fn rollback(state: &mut State, id: Uuid) {
    // A collision must never remove the earlier durable row with this identity.
    if let Some(index) = state.shadow_queue.iter().rposition(|event|event.id == id) {
        state.shadow_queue.remove(index);
    }
    prune(state);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn row(user: &str) -> crate::shadow::ShadowEvent {
        serde_json::from_value(json!({"id":Uuid::new_v4(),"occurred_at":chrono::Utc::now(),
            "kind":"prompt","provider":"claude.ai","source":"browser","tool":"chrome",
            "user":user,"action":"observed","characters":1,"labels":[],"files":[],"policy_revision":1})).unwrap()
    }
    fn admit(state: &mut State, owner: &str, user: &str) -> Result<Uuid> {
        let event = row(user); let id = event.id; state.shadow_queue.push(event);
        if let Err(error) = claim(state,id,owner.into()) { rollback(state,id); return Err(error) }
        Ok(id)
    }
    #[test]
    fn transfers_and_direct_events_share_a_durable_kernel_principal_budget() {
        let mut state = State::default();
        let a = caller_owner(&json!({"caller":{"sid":"S-1-5-21-1000"}})).unwrap();
        let broker_a = broker_owner(&json!({"quota_principal":"S-1-5-21-1000"})).unwrap();
        assert_eq!(a,broker_a);
        let share = MAX_EVENTS.min((crate::config::current().queue.max_events/2).max(1));
        for i in 0..share { admit(&mut state,if i%2==0 {&a} else {&broker_a},&format!("renamed-{i}")).unwrap(); }
        assert!(admit(&mut state,&a,"another-display-name").is_err());
        let home = tempfile::tempdir().unwrap();
        { let store=crate::Store::open(home.path()).unwrap(); store.save(&state).unwrap(); }
        let mut state=crate::Store::open(home.path()).unwrap().load().unwrap();
        assert!(admit(&mut state,&a,"after-restart").is_err());
        let b=caller_owner(&json!({"caller":{"sid":"S-1-5-21-1001"}})).unwrap();
        admit(&mut state,&b,"same-display-name").unwrap();
        let removed=state.shadow_queue[0].id;
        state.shadow_queue.remove(0); assert!(prune(&mut state));
        assert!(!state.browser_queue_owners.contains_key(&removed));
        admit(&mut state,&a,"after-ack").unwrap();
        assert_eq!(state.browser_queue_owners.len(),state.shadow_queue.len());
    }
    #[test]
    fn legacy_unknown_and_invalid_owners_cannot_escape_accounting() {
        let mut state=State::default();
        let share=MAX_EVENTS.min((crate::config::current().queue.max_events/2).max(1));
        for _ in 0..share { state.shadow_queue.push(row("untrusted-display-name")); }
        let a=caller_owner(&json!({"caller":{"uid":1000,"user":"rename"}})).unwrap();
        assert_eq!(a,"uid:1000");
        assert!(admit(&mut state,&a,"legacy-name").is_err());
        assert!(broker_owner(&json!({"quota_principal":{"image":"png"}})).is_err());
        assert!(caller_owner(&json!({"caller":{"sid":"forged"}})).is_err());
        assert_eq!(broker_owner(&json!({})).unwrap(),UNKNOWN);
        assert_eq!(caller_owner(&json!({})).unwrap(),UNKNOWN);
    }
    #[test]
    fn byte_refusal_and_identity_collision_do_not_lose_earlier_custody() {
        let mut state=State::default();
        let a="sid:S-1-5-21-1000";
        let mut refused=false;
        for _ in 0..MAX_EVENTS {
            let mut event=row("same-user");event.prompt=Some("x".repeat(32*1024));
            let id=event.id;state.shadow_queue.push(event);
            if claim(&mut state,id,a.into()).is_err() { rollback(&mut state,id);refused=true;break }
        }
        assert!(refused);
        assert!(state.shadow_queue.len()<MAX_EVENTS,"byte quota did not precede count quota");
        let b="sid:S-1-5-21-1001";
        let id=admit(&mut state,b,"same-user").unwrap();
        let previous=state.shadow_queue.last().unwrap().clone();
        state.shadow_queue.push(previous.clone());
        assert!(claim(&mut state,id,a.into()).is_err());rollback(&mut state,id);
        assert_eq!(state.shadow_queue.iter().filter(|event|event.id==id).count(),1);
        assert_eq!(state.browser_queue_owners.get(&id).unwrap(),b);
    }
    #[test]
    fn completion_growth_refuses_the_principal_share_and_preserves_custody() {
        let mut state=State::default();let a="sid:S-1-5-21-1000";
        for _ in 0..MAX_EVENTS {
            let mut event=row("synthetic");event.prompt=Some("x".repeat(32*1024));
            let id=event.id;state.shadow_queue.push(event);
            if claim(&mut state,id,a.into()).is_err() { rollback(&mut state,id);break }
        }
        let mut event=row("synthetic");event.prompt=Some(String::new());
        let id=event.id;state.shadow_queue.push(event);claim(&mut state,id,a.into()).unwrap();
        let cap=MAX_BYTES.min((crate::config::current().queue.max_bytes/2).max(1));
        let used=crate::shadow::queue_bytes(&state).unwrap();
        let padding=cap.checked_sub(used+32).expect("fixture needs room below account byte cap");
        assert!(padding<32*1024);
        state.shadow_queue.last_mut().unwrap().prompt=Some("x".repeat(padding));
        check_growth(&state,id).unwrap();
        let before=serde_json::to_value(&state).unwrap();
        // Both direct event_complete and authenticated broker_complete call this
        // exact downstream function after resolving the trusted event identity.
        let completion=crate::shadow::ShadowCompletion::parse_for(id,&json!({"model":"m".repeat(200),
            "effort":"e".repeat(200),"conversation_id":"c".repeat(200)})).unwrap();
        assert!(!crate::shadow::complete(&mut state,completion).unwrap());
        assert_eq!(serde_json::to_value(&state).unwrap(),before);
        let completion=crate::shadow::ShadowCompletion::parse_for(id,&json!({"body_bytes":1})).unwrap();
        assert!(crate::shadow::complete(&mut state,completion.clone()).unwrap());
        assert!(crate::shadow::complete(&mut state,completion).unwrap(),"unchanged retry must remain idempotent");
        assert_eq!(state.shadow_queue.last().unwrap().body_bytes,Some(1));
    }
    #[test]
    fn completion_growth_cannot_exceed_the_global_queue_budget() {
        let mut state=State::default();
        let id=admit(&mut state,"sid:S-1-5-21-1000","synthetic").unwrap();
        // An inert preexisting legacy row supplies deterministic global occupancy;
        // this fixture exercises local admission only, never network validation.
        state.queue.push(crate::Event {id:Uuid::new_v4(),occurred_at:chrono::Utc::now(),provider:String::new(),
            action:"observed".into(),source:"browser".into(),characters:0,labels:vec![]});
        let used=crate::shadow::queue_bytes(&state).unwrap();
        let padding=crate::config::current().queue.max_bytes.checked_sub(used+32).unwrap();
        state.queue[0].provider="x".repeat(padding);
        let before=state.shadow_queue[0].clone();
        let bytes=crate::shadow::queue_bytes(&state).unwrap();
        let completion=crate::shadow::ShadowCompletion::parse_for(id,&json!({"model":"m".repeat(200)})).unwrap();
        assert!(!crate::shadow::complete(&mut state,completion).unwrap());
        assert_eq!(serde_json::to_value(&state.shadow_queue[0]).unwrap(),serde_json::to_value(&before).unwrap());
        assert_eq!(crate::shadow::queue_bytes(&state).unwrap(),bytes);
        assert_eq!(state.browser_queue_owners.get(&id).unwrap(),"sid:S-1-5-21-1000");
    }
}
