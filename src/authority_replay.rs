//! Adapter kept as a child module of cache_service so private keys never leave Authority.
use super::*;
use crate::cache_replay::{Reply, Target, Transcript};
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub(super) struct ReplayState {
    pub(super) staging: bool,
    pub(super) dirty: bool,
    observation: crate::cache_replay_authority::Observation,
}

pub enum Operation {
    Prepare { request: Value, boot: String },
    Browser { parsed: crate::browser_broker::Parsed, boot: String, deadline: Instant },
    Maintenance { boot: String, owner: Option<RowIdentity> },
}
#[derive(Clone, PartialEq, Eq)]
pub struct RowIdentity { sequence:u64, generation:u64, id:uuid::Uuid, principal:String, health:bool }
pub struct Snapshot {
    journal: Journal,
    queue: crate::browser_broker::Queue,
    masked: Vec<Masked>,
    storage_failed: bool,
    dirty: bool,
}

impl Target for Authority {
    type Operation = Operation;
    type Output = Value;
    type Snapshot = Snapshot;
    type Token = crate::cache_replay_authority::Token;
    type Ticket = Option<u64>;
    fn token(&self) -> Result<Self::Token> {
        // Queue/receipt and grace-clock changes can rebase. Authority changes cannot.
        self.replay.observation.token(&self.stored.journal)
    }
    fn snapshot(&self) -> Snapshot {
        Snapshot { journal: self.stored.journal.clone(), queue: self.stored.queue.clone(),
            masked: self.masked.clone(), storage_failed: self.storage_failed, dirty: self.replay.dirty }
    }
    fn restore(&mut self, snapshot: Snapshot) {
        self.stored.journal = snapshot.journal; self.stored.queue = snapshot.queue;
        self.masked = snapshot.masked; self.storage_failed = snapshot.storage_failed;
        self.replay.dirty = snapshot.dirty;
    }
    fn staging(&mut self, enabled: bool) { self.replay.staging = enabled; }
    fn flush(&mut self) -> Result<()> {
        if self.replay.dirty || self.storage_failed { self.save()?; }
        Ok(())
    }
    fn finish_output(&mut self, operation: &Operation, output: Value) -> Result<Value> {
        let Operation::Browser { parsed, deadline, .. } = operation else { return Ok(output); };
        let mode = output["mode"].as_str().ok_or("browser output mode absent")?;
        let mut reply = output["reply"].clone();
        let mut mode = if Instant::now() >= *deadline {
            reply = json!({"ok":false,"error":"control_timeout"}); "blocked"
        } else { mode };
        let mut remaining = if mode == "grace" {
            self.stored.journal.deadline.unwrap_or(0).saturating_sub(windows::tick())
        } else { 0 };
        if mode == "grace" && (remaining == 0 || self.storage_failed) {
            mode = "blocked"; remaining = 0; reply = json!({"ok":false,"error":"cache_expired"});
        }
        crate::browser_broker::signed(&self.stored.journal, &self.stored.keys, parsed, mode, remaining, reply)
    }
    fn attempt(&mut self, operation: &Operation, transcript: &mut Transcript) -> Result<Value> {
        match operation {
            Operation::Prepare { request, boot } => self.prepare_with(request,
                &mut |request| transcript.exchange(request), boot),
            Operation::Browser { parsed, boot, deadline } => self.browser_with(parsed,
                &mut |request| transcript.exchange(request), boot, *deadline),
            Operation::Maintenance { boot, owner } => {
                self.maintenance_with(&mut |request| transcript.exchange(request), boot, owner.as_ref())?;
                Ok(Value::Null)
            }
        }
    }
    fn begin_exchange(&mut self,operation:&Operation, request: &Value) -> Result<Option<u64>> {
        if request["op"]=="broker_event"{
            let Operation::Maintenance{owner:Some(owner),..}=operation else{return Err("handoff owner absent".into())};
            if self.selected_row()?.as_ref()!=Some(owner)||request["installation"]!=self.stored.journal.pin.installation
                ||request["sequence"]!=owner.sequence{return Err("handoff identity changed".into());}
            if !owner.health{
                if request["quota_principal"]!=owner.principal{return Err("handoff principal changed".into());}
                let row=self.stored.queue.pending.first_mut().ok_or("handoff row absent")?;
                let offered=crate::cache_replay_authority::narrow_offered(&row.event,&request["event"])?;
                let changed=serde_json::to_value(&row.event)?!=serde_json::to_value(&offered)?;
                let persist=!row.transfer_started||changed||self.storage_failed;
                if changed{row.event.discard_content();row.event=offered;}row.transfer_started=true;
                // Runs after preview rollback and before transport. A failed save
                // retains a conservative marker but forbids every external call.
                if persist{self.save()?;}
            }
            return Ok(None);
        }
        if request["op"] != "policy_v3" { return Ok(None); }
        Ok(Some(self.replay.observation.ticket()?))
    }
    fn is_refused_reply(&self,request:&Value,reply:&Reply)->bool{
        request["op"]=="policy_v3"&&matches!(reply,Reply::Value(value)if matches!(crate::cache_replay_authority::classify(Some(value.clone())),crate::cache_replay_authority::Input::Refused))
    }
    fn accept_changed_token(&self, expected: &Self::Token, request: &Value, reply: &Reply,
        ticket: &Option<u64>) -> Result<bool> {
        // Uncertainty does not erase a refusal, but a newer positive admission or
        // another pin/generation must never be invalidated by an older response.
        self.replay.observation.accept_changed_token(&self.stored.journal,expected,request,reply,*ticket)
    }
    fn reconcile_external(&mut self,operation:&Operation,expected:&Self::Token,request:&Value,reply:&Reply)->Result<Option<Value>>{
        let Operation::Maintenance{owner:Some(owner),..}=operation else{return Ok(None)};
        let Reply::Value(answer)=reply else{return Ok(None)};
        if request["op"]!="broker_event"||answer["ok"]!=true||answer["durable"]!=true
            ||answer["id"]!=json!(owner.id)||request["installation"]!=self.stored.journal.pin.installation
            ||request["sequence"]!=owner.sequence||!expected.same_pin(&self.stored.journal)
            ||self.selected_row()?.as_ref()!=Some(owner){return Ok(None);}
        let offered=if owner.health{&request["batch"]["id"]}else{&request["event"]["id"]};
        if *offered!=json!(owner.id){return Ok(None);}
        // This is custody acknowledgement, never an authorization grant. A newer
        // outage/refusal must survive, but cannot make an already handed-off row
        // look locally owned again. Its principal gate excludes new enrichment.
        if owner.health{self.stored.queue.health.remove(0);}else{self.stored.queue.pending.remove(0);}
        self.save()?;Ok(Some(Value::Null))
    }
    fn observe(&mut self, operation: &Operation, request: &Value, reply: &Reply, ticket: Option<u64>) -> Result<()> {
        if request["op"] != "policy_v3" { return Ok(()); }
        let input = crate::cache_replay_authority::classify(match reply {
            Reply::Value(value) => Some(value.clone()), Reply::Unreachable => None,
        });
        let boot = match operation { Operation::Browser { boot, .. } => Some(boot.as_str()), _ => None };
        let effect = self.replay.observation.observe(&mut self.stored.journal, &self.stored.keys,
            &mut self.stored.queue, input, ticket.ok_or("cache probe ticket absent")?, boot, windows::tick())?;
        if effect.clear_masked { self.masked.clear(); }
        if effect.save { self.save()?; }
        Ok(())
    }
}

impl Authority {
    pub(super) fn seal_inherited_transfers(&mut self)->Result<()>{
        if self.stored.queue.pending.iter().any(|row|!row.transfer_started){
            // A reload cannot distinguish an old lost ACK from an unoffered row.
            // Persist uncertainty before exposing any completion interface.
            for row in &mut self.stored.queue.pending{row.transfer_started=true;}
            self.save()?;
        }
        Ok(())
    }
    pub(super) fn selected_row(&self)->Result<Option<RowIdentity>>{
        let event=self.stored.queue.pending.first();let health=self.stored.queue.health.first();
        if health.is_some_and(|row|event.is_none_or(|pending|row.sequence<pending.sequence)){
            let row=health.ok_or("health queue head absent")?;
            let id=uuid::Uuid::parse_str(row.batch["id"].as_str().ok_or("health queue identity absent")?)?;
            Ok(Some(RowIdentity{sequence:row.sequence,generation:row.generation,id,principal:row.principal.clone(),health:true}))
        }else{
            Ok(event.map(|row|RowIdentity{sequence:row.sequence,generation:row.generation,id:row.event.id,principal:row.principal.clone(),health:false}))
        }
    }
}

/// The returned custody lock is nonblocking and stays held across external delivery.
/// Its lifetime covers the transfer and final local ACK commit, rather than a preview.
pub(crate) fn maintenance_guard(edition: &str) -> Result<File> {
    let directory = Directory::open(&windows::root(edition)?.join("private"), true)?;
    directory.delivery_guard(edition)
}

pub(super) use crate::cache_replay_authority::local_work;

pub(crate) fn run(
    slot: &Mutex<Option<Authority>>, admission: &Arc<crate::cache_replay::Admission>,
    ownership:&Arc<crate::cache_replay::Ownership>,
    edition: &str, principal: &str, background: bool, operation: Operation, deadline: Instant,
) -> Result<Value> {
    let _permit = admission.enter(principal, background)?;
    if matches!(&operation,Operation::Browser{parsed,..} if parsed.principal!=principal){return Err("cache caller identity mismatch".into());}
    let _custody = if matches!(&operation, Operation::Maintenance { .. }) { Some(maintenance_guard(edition)?) } else { None };
    run_gated(slot,ownership,operation,deadline,||Authority::open(edition),|request, deadline| {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else { return Reply::Unreachable; };
        if let Some(answer) = local_work(request) {
            return match answer { Ok(value) => Reply::Value(value), Err(_) => Reply::Unreachable };
        }
        match exchange_agent(edition, request, remaining.min(Duration::from_secs(2))) {
            Ok(value) => Reply::Value(value), Err(_) => Reply::Unreachable,
        }
    })
}

pub(super) fn run_gated(
    slot:&Mutex<Option<Authority>>,ownership:&Arc<crate::cache_replay::Ownership>,mut operation:Operation,deadline:Instant,
    mut open:impl FnMut()->Result<Authority>,exchange:impl FnMut(&Value,Instant)->Reply,
)->Result<Value>{
    let principal=match &mut operation{
        Operation::Browser{parsed,..}=>Some(parsed.principal.clone()),
        Operation::Prepare{..}=>None,
        Operation::Maintenance{owner,..}=>{
            let mut locked=slot.lock().map_err(|_|"cache authority unavailable")?;
            if locked.is_none(){*locked=Some(open()?);}
            *owner=locked.as_ref().ok_or("cache authority unavailable")?.selected_row()?;
            owner.as_ref().filter(|row|!row.principal.is_empty()).map(|row|row.principal.clone())
        }
    };
    // This wait is per authenticated principal and always outside Authority. FIFO
    // gives maintenance a turn even if one account continually renews requests.
    let _owner=match principal{Some(principal)=>Some(ownership.enter_until(&principal,deadline)?),None=>None};
    if let Operation::Maintenance{owner,..}=&operation{
        let locked=slot.lock().map_err(|_|"cache authority unavailable")?;
        if locked.as_ref().ok_or("cache authority unavailable")?.selected_row()?.as_ref()!=owner.as_ref(){
            return Err("cache queue head changed before ownership".into());
        }
    }
    crate::cache_replay::drive(slot,&operation,deadline,open,exchange)
}
