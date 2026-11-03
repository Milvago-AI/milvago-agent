//! Shared local-state replay coordinator. Agent IPC never runs with the target locked.
use crate::Result;
use serde_json::Value;
use std::{collections::{HashMap, VecDeque}, sync::{Arc, Condvar, Mutex}, time::Instant};

#[derive(Clone)]
pub enum Reply { Value(Value), Unreachable }
impl Reply {
    pub fn result(&self) -> Result<Value> {
        match self { Self::Value(value) => Ok(value.clone()), Self::Unreachable => Err("agent unavailable".into()) }
    }
}

pub struct Transcript {
    entries: Vec<(Value, Reply)>,
    missing: Option<Value>,
    bytes: usize,
}
impl Transcript {
    fn new() -> Self { Self { entries: Vec::new(), missing: None, bytes: 0 } }
    pub fn exchange(&mut self, request: &Value) -> Result<Value> {
        // Once suspended, no later branch may replace the operation we must perform.
        if self.missing.is_some() { return Err("external work pending".into()); }
        if let Some((_, reply)) = self.entries.iter().find(|(input, _)| input == request) {
            return reply.result();
        }
        self.missing = Some(request.clone());
        Err("external work pending".into())
    }
}

pub trait Target {
    type Operation;
    type Output;
    type Snapshot;
    type Token: Eq;
    type Ticket;
    fn token(&self) -> Result<Self::Token>;
    fn snapshot(&self) -> Self::Snapshot;
    fn restore(&mut self, snapshot: Self::Snapshot);
    fn staging(&mut self, enabled: bool);
    fn attempt(&mut self, operation: &Self::Operation, transcript: &mut Transcript) -> Result<Self::Output>;
    // Flush every staged save before an output is exposed, including a blocked output.
    fn flush(&mut self) -> Result<()>;
    fn begin_exchange(&mut self, operation:&Self::Operation, request: &Value) -> Result<Self::Ticket>;
    fn is_refused_reply(&self,_request:&Value,_reply:&Reply)->bool{false}
    fn accept_changed_token(&self, _expected: &Self::Token, _request: &Value, _reply: &Reply,
        _ticket: &Self::Ticket) -> Result<bool> { Ok(false) }
    fn reconcile_external(&mut self, _operation:&Self::Operation, _expected:&Self::Token,
        _request:&Value, _reply:&Reply)->Result<Option<Self::Output>>{Ok(None)}
    fn finish_output(&mut self, _operation: &Self::Operation, output: Self::Output) -> Result<Self::Output> { Ok(output) }
    // Authoritative refusals/restrictions are persisted independently of request success.
    fn observe(&mut self, operation: &Self::Operation, request: &Value, reply: &Reply, ticket: Self::Ticket) -> Result<()>;
}

pub fn drive<T: Target>(
    slot: &Mutex<Option<T>>, operation: &T::Operation, deadline: Instant,
    open: impl FnMut() -> Result<T>,
    exchange: impl FnMut(&Value, Instant) -> Reply,
) -> Result<T::Output> {
    drive_with_clock(slot, operation, deadline, open, exchange, Instant::now)
}

fn drive_with_clock<T: Target>(
    slot: &Mutex<Option<T>>, operation: &T::Operation, deadline: Instant,
    mut open: impl FnMut() -> Result<T>,
    mut exchange: impl FnMut(&Value, Instant) -> Reply,
    now: impl Fn() -> Instant,
) -> Result<T::Output> {
    let mut transcript = Transcript::new();
    let mut token = None;
    // Existing interactive paths need at most three distinct IPC messages. This
    // bounds transcript bytes and rejects any accidental nondeterministic replay.
    for _ in 0..8 {
        if now() >= deadline { return Err("operation deadline exceeded".into()); }
        let mut locked = slot.lock().map_err(|_| "cache authority unavailable")?;
        if locked.is_none() { *locked = Some(open()?); }
        let target = locked.as_mut().ok_or("cache authority unavailable")?;
        let current = target.token()?;
        if token.as_ref().is_some_and(|expected| expected != &current) {
            return Err("cache authority changed during external work".into());
        }
        token = Some(current);
        let snapshot = target.snapshot();
        target.staging(true);
        transcript.missing = None;
        let attempted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| target.attempt(operation, &mut transcript)));
        target.staging(false);
        let result = match attempted {
            Ok(result) => result,
            Err(panic) => { target.restore(snapshot); std::panic::resume_unwind(panic); }
        };
        if let Some(request) = transcript.missing.take() {
            // Includes swallowed pending errors: browser() signs a blocked answer
            // for errors and maintenance treats an IO error as no work.
            target.restore(snapshot);
            let request_bytes=serde_json::to_vec(&request)?.len();
            let request_total=transcript.bytes.checked_add(request_bytes).ok_or("external transcript overflow")?;
            if request_bytes>2*1024*1024||request_total>8*1024*1024{return Err("external request limit exceeded".into());}
            let ticket = target.begin_exchange(operation,&request)?;
            drop(locked);
            if now() >= deadline { return Err("operation deadline exceeded".into()); }
            let reply = exchange(&request, deadline);
            let reply_bytes = match &reply { Reply::Value(value) => serde_json::to_vec(value)?.len(), Reply::Unreachable => 0 };
            let total=request_total.checked_add(reply_bytes);
            let within_limit=reply_bytes<=2*1024*1024&&total.is_some_and(|bytes|bytes<=8*1024*1024);
            let mut locked = slot.lock().map_err(|_| "cache authority unavailable")?;
            let target = locked.as_mut().ok_or("cache authority unavailable")?;
            let expected = token.as_ref().ok_or("cache authority token absent")?;
            if !within_limit{
                // A bounded transcript cannot retain an oversized reply, but a
                // legitimate refusal still revokes its original current authority.
                if target.is_refused_reply(&request,&reply)
                    &&(expected==&target.token()?||target.accept_changed_token(expected,&request,&reply,&ticket)?){
                    target.observe(operation,&request,&reply,ticket)?;
                }
                return Err("external reply or transcript limit exceeded".into());
            }
            if let Some(output)=target.reconcile_external(operation,expected,&request,&reply)?{
                target.flush()?;
                return target.finish_output(operation,output);
            }
            if expected != &target.token()? && !target.accept_changed_token(expected, &request, &reply, &ticket)? {
                return Err("cache authority changed during external work".into());
            }
            // Do this even if the response consumed the request deadline. A known
            // refusal is not undone by a client timeout or discarded preview.
            target.observe(operation, &request, &reply, ticket)?;
            token = Some(target.token()?);
            transcript.bytes=total.ok_or("external transcript overflow")?;
            transcript.entries.push((request, reply));
            continue;
        }
        // A failed real flush retains the intended state, as Authority::save does;
        // no speculative signed output or durable ACK escapes on that path.
        target.flush()?;
        return result.and_then(|output| target.finish_output(operation, output));
    }
    Err("external operation stage limit exceeded".into())
}

#[derive(Default)]
pub struct Admission(Mutex<HashMap<String, usize>>);
pub struct Permit { admission: Arc<Admission>, principal: String }
impl Admission {
    pub fn enter(self: &Arc<Self>, principal: &str, background: bool) -> Result<Permit> {
        let mut active = self.0.lock().map_err(|_| "cache admission unavailable")?;
        let limit = if background { 1 } else { 2 };
        if active.values().sum::<usize>() >= 16 || active.get(principal).copied().unwrap_or(0) >= limit {
            return Err("cache caller work limit exceeded".into());
        }
        *active.entry(principal.to_owned()).or_default() += 1;
        Ok(Permit { admission: self.clone(), principal: principal.to_owned() })
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        if let Ok(mut active) = self.admission.0.lock() {
            if let Some(count) = active.get_mut(&self.principal) {
                *count -= 1;
                if *count == 0 { active.remove(&self.principal); }
            }
        }
    }
}

#[derive(Default)]
struct OwnerEntry { held:bool, waiting:VecDeque<u64> }
#[derive(Default)]
struct OwnerState { next:u64, entries:HashMap<String,OwnerEntry> }
#[derive(Default)]
pub struct Ownership { state:Mutex<OwnerState>, ready:Condvar }
pub struct OwnerPermit { ownership:Arc<Ownership>, principal:String }
impl Ownership {
    pub fn enter_until(self:&Arc<Self>,principal:&str,deadline:Instant)->Result<OwnerPermit>{
        let mut state=self.state.lock().map_err(|_|"cache ownership unavailable")?;
        if state.entries.values().map(|entry|entry.waiting.len()+usize::from(entry.held)).sum::<usize>()>=16{
            return Err("cache ownership work limit exceeded".into());
        }
        state.next=state.next.checked_add(1).ok_or("cache ownership sequence exhausted")?;
        let ticket=state.next;
        state.entries.entry(principal.to_owned()).or_default().waiting.push_back(ticket);
        self.ready.notify_all();
        loop{
            if Instant::now()>=deadline{
                if let Some(entry)=state.entries.get_mut(principal){entry.waiting.retain(|queued|*queued!=ticket);}
                if state.entries.get(principal).is_some_and(|entry|!entry.held&&entry.waiting.is_empty()){state.entries.remove(principal);}
                self.ready.notify_all();return Err("cache owner operation deadline exceeded".into());
            }
            let entry=state.entries.get_mut(principal).ok_or("cache owner queue unavailable")?;
            if !entry.held&&entry.waiting.front()==Some(&ticket){
                entry.waiting.pop_front();entry.held=true;
                return Ok(OwnerPermit{ownership:self.clone(),principal:principal.to_owned()});
            }
            let remaining=deadline.saturating_duration_since(Instant::now());
            let(waited,_)=self.ready.wait_timeout(state,remaining).map_err(|_|"cache ownership unavailable")?;
            state=waited;
        }
    }
    #[cfg(test)]
    pub(crate) fn wait_for_waiter(&self,principal:&str,deadline:Instant)->bool{
        let Ok(mut state)=self.state.lock() else{return false};
        loop{
            if state.entries.get(principal).is_some_and(|entry|!entry.waiting.is_empty()){return true;}
            let remaining=deadline.saturating_duration_since(Instant::now());if remaining.is_zero(){return false;}
            let Ok((waited,_))=self.ready.wait_timeout(state,remaining) else{return false};state=waited;
        }
    }
}
impl Drop for OwnerPermit{
    fn drop(&mut self){
        if let Ok(mut state)=self.ownership.state.lock(){
            if let Some(entry)=state.entries.get_mut(&self.principal){entry.held=false;}
            if state.entries.get(&self.principal).is_some_and(|entry|entry.waiting.is_empty()){state.entries.remove(&self.principal);}
            self.ownership.ready.notify_all();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::{sync::mpsc, thread, time::Duration};
    #[derive(Clone, Default)]
    struct Data { epoch: u64, queue: Vec<u64>, receipt: bool, persisted: usize }
    struct Fake { data: Data, staged: bool, dirty: bool, fail_save: bool, fail_begin:bool, begins:usize }
    enum Op { Submit, Drain, Revoke, LargeRequest, Transfer }
    impl Fake {
        fn new() -> Self { Self { data: Data { receipt: true, ..Data::default() }, staged: false, dirty: false, fail_save: false,fail_begin:false,begins:0 } }
        fn save(&mut self) -> Result<()> { self.dirty = true; if self.staged { return Ok(()); } self.flush() }
    }
    impl Target for Fake {
        type Operation = Op; type Output = bool; type Snapshot = (Data, bool); type Token = u64;
        type Ticket = ();
        fn token(&self) -> Result<u64> { Ok(self.data.epoch) }
        fn snapshot(&self) -> Self::Snapshot { (self.data.clone(), self.dirty) }
        fn restore(&mut self, snapshot: Self::Snapshot) { self.data = snapshot.0; self.dirty = snapshot.1; }
        fn staging(&mut self, enabled: bool) { self.staged = enabled; }
        fn flush(&mut self) -> Result<()> {
            if self.fail_save { return Err("synthetic persistence failure".into()); }
            if self.dirty { self.data.persisted += 1; self.dirty = false; } Ok(())
        }
        fn begin_exchange(&mut self, _operation:&Op,_request: &Value) -> Result<()> {self.begins+=1;if self.fail_begin{return Err("synthetic pre-exchange save failure".into());}Ok(()) }
        fn is_refused_reply(&self,request:&Value,reply:&Reply)->bool{request["op"]=="policy"&&matches!(reply,Reply::Value(value)if value["ok"]==false)}
        fn observe(&mut self, _operation: &Op, request: &Value, reply: &Reply, _ticket: ()) -> Result<()> {
            if request["op"] == "policy" && matches!(reply, Reply::Value(value) if value["ok"] == false) {
                self.data.epoch += 1; self.data.queue.clear(); self.save()?;
            } Ok(())
        }
        fn attempt(&mut self, op: &Op, rpc: &mut Transcript) -> Result<bool> {
            match op {
                Op::LargeRequest=>{rpc.exchange(&json!({"op":"large","padding":"x".repeat(2*1024*1024)}))?;Ok(true)},
                Op::Transfer=>{rpc.exchange(&json!({"op":"broker_event","id":7}))?;Ok(true)},
                Op::Revoke => { self.data.epoch += 1; self.data.queue.clear(); self.save()?; Ok(false) }
                Op::Submit => {
                    let policy = rpc.exchange(&json!({"op":"policy"}))?;
                    if policy["ok"] != true { return Ok(false); }
                    // A preview must restore consumed approval custody on suspension.
                    let receipt = self.data.receipt; self.data.receipt = false;
                    rpc.exchange(&json!({"op":"inspect","receipt":receipt}))?;
                    if receipt { self.data.queue.push(7); self.save()?; }
                    Ok(receipt)
                }
                Op::Drain => {
                    let Some(id) = self.data.queue.first().copied() else { return Ok(false) };
                    let answer = rpc.exchange(&json!({"op":"ack","id":id}))?;
                    if answer["id"] == id { self.data.queue.remove(0); self.save()?; Ok(true) } else { Ok(false) }
                }
            }
        }
    }
    fn deadline() -> Instant { Instant::now() + Duration::from_secs(3) }
    #[test]
    fn blocked_exchange_releases_lock_and_rebases_queue_without_losing_receipts() {
        let slot = Arc::new(Mutex::new(Some(Fake::new())));
        let worker_slot = slot.clone();
        let (started, observed) = mpsc::channel(); let (release, wait) = mpsc::channel();
        let worker = thread::spawn(move || drive(&worker_slot, &Op::Submit, deadline(), || unreachable!(), |request, _| {
            if request["op"] == "inspect" { started.send(()).unwrap(); wait.recv().unwrap(); }
            Reply::Value(json!({"ok":true}))
        }));
        observed.recv_timeout(Duration::from_secs(1)).unwrap();
        { let mut guard = slot.try_lock().expect("external exchange held Authority"); let target = guard.as_mut().unwrap();
          assert!(target.data.receipt, "suspended preview consumed the approval");
          assert!(target.data.queue.is_empty()); target.data.queue.push(9); target.save().unwrap(); }
        release.send(()).unwrap(); assert!(worker.join().unwrap().unwrap());
        let guard = slot.lock().unwrap(); let target = guard.as_ref().unwrap();
        assert_eq!(target.data.queue, [9, 7]); assert!(!target.data.receipt); assert_eq!(target.data.persisted, 2);
    }
    #[test]
    fn revocation_during_external_work_rejects_old_result() {
        let slot = Arc::new(Mutex::new(Some(Fake::new()))); let worker_slot = slot.clone();
        let (started, observed) = mpsc::channel(); let (release, wait) = mpsc::channel();
        let worker = thread::spawn(move || drive(&worker_slot, &Op::Submit, deadline(), || unreachable!(), |_, _| {
            started.send(()).unwrap(); wait.recv().unwrap(); Reply::Value(json!({"ok":true}))
        }));
        observed.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(!drive(&slot, &Op::Revoke, deadline(), || unreachable!(), |_, _| unreachable!()).unwrap());
        release.send(()).unwrap(); assert!(worker.join().unwrap().is_err());
        assert!(slot.lock().unwrap().as_ref().unwrap().data.queue.is_empty());
    }
    #[test]
    fn ack_for_removed_row_cannot_remove_replacement() {
        let mut target = Fake::new(); target.data.queue = vec![1];
        let slot = Arc::new(Mutex::new(Some(target))); let worker_slot = slot.clone();
        let (started, observed) = mpsc::channel(); let (release, wait) = mpsc::channel();
        let worker = thread::spawn(move || drive(&worker_slot, &Op::Drain, deadline(), || unreachable!(), |request, _| {
            if request["id"] == 1 { started.send(()).unwrap(); wait.recv().unwrap(); }
            Reply::Value(json!({"id":1}))
        }));
        observed.recv_timeout(Duration::from_secs(1)).unwrap();
        slot.lock().unwrap().as_mut().unwrap().data.queue = vec![2];
        release.send(()).unwrap(); assert!(!worker.join().unwrap().unwrap());
        assert_eq!(slot.lock().unwrap().as_ref().unwrap().data.queue, [2]);
    }
    #[test]
    fn persistence_failure_never_returns_speculative_output() {
        let mut target = Fake::new(); target.fail_save = true; let slot = Mutex::new(Some(target));
        assert!(drive(&slot, &Op::Submit, deadline(), || unreachable!(), |_, _| Reply::Value(json!({"ok":true}))).is_err());
        assert_eq!(slot.lock().unwrap().as_ref().unwrap().data.queue, [7]);
    }
    #[test]
    fn caller_cannot_fill_every_external_work_slot() {
        let admission = Arc::new(Admission::default());
        let _a = admission.enter("account-a", false).unwrap(); let _a2 = admission.enter("account-a", false).unwrap();
        assert!(admission.enter("account-a", false).is_err());
        let _b = admission.enter("account-b", false).unwrap();
    }
    #[test]
    fn refusal_survives_expired_request_without_exposing_output() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let mut target = Fake::new(); target.data.queue = vec![1];
        let slot = Mutex::new(Some(target)); let expired = AtomicBool::new(false);
        let start = Instant::now(); let end = start + Duration::from_secs(1);
        let result = drive_with_clock(&slot, &Op::Submit, end, || unreachable!(), |_, _| {
            expired.store(true, Ordering::Release); Reply::Value(json!({"ok":false}))
        }, || if expired.load(Ordering::Acquire) { end } else { start });
        assert!(result.is_err());
        let guard = slot.lock().unwrap(); let target = guard.as_ref().unwrap();
        assert_eq!(target.data.epoch, 1); assert!(target.data.queue.is_empty());
        assert_eq!(target.data.persisted, 1);
    }
    #[test]
    fn owner_wait_is_local_to_principal_and_maintenance_cannot_be_overtaken(){
        let ownership=Arc::new(Ownership::default());let first=ownership.enter_until("account-a",deadline()).unwrap();
        let worker_ownership=ownership.clone();let(acquired,seen)=mpsc::channel();let(release,wait)=mpsc::channel();
        let maintenance=thread::spawn(move||{let _owner=worker_ownership.enter_until("account-a",deadline()).unwrap();acquired.send(()).unwrap();wait.recv().unwrap();});
        assert!(ownership.wait_for_waiter("account-a",deadline()));
        let later_ownership=ownership.clone();let(later,late)=mpsc::channel();
        let browser=thread::spawn(move||{let _owner=later_ownership.enter_until("account-a",deadline()).unwrap();later.send(()).unwrap();});
        let other=ownership.enter_until("account-b",deadline()).unwrap();drop(other);
        drop(first);seen.recv_timeout(Duration::from_secs(1)).unwrap();assert!(late.try_recv().is_err());
        release.send(()).unwrap();maintenance.join().unwrap();late.recv_timeout(Duration::from_secs(1)).unwrap();browser.join().unwrap();
    }
    #[test]
    fn request_limit_precedes_durable_begin_and_external_work(){
        let slot=Mutex::new(Some(Fake::new()));let calls=std::cell::Cell::new(0);
        assert!(drive(&slot,&Op::LargeRequest,deadline(),||unreachable!(),|_,_|{calls.set(calls.get()+1);Reply::Unreachable}).is_err());
        assert_eq!(calls.get(),0);assert_eq!(slot.lock().unwrap().as_ref().unwrap().begins,0);
    }
    #[test]
    fn failed_pre_exchange_commit_forbids_external_work(){
        let mut target=Fake::new();target.fail_begin=true;let slot=Mutex::new(Some(target));let calls=std::cell::Cell::new(0);
        assert!(drive(&slot,&Op::Transfer,deadline(),||unreachable!(),|_,_|{calls.set(calls.get()+1);Reply::Value(json!({"ok":true}))}).is_err());
        assert_eq!(calls.get(),0);assert_eq!(slot.lock().unwrap().as_ref().unwrap().begins,1);
    }
    #[test]
    fn oversized_refusal_is_not_retained_but_still_revokes_current_authority(){
        let mut target=Fake::new();target.data.queue=vec![7];let slot=Mutex::new(Some(target));
        assert!(drive(&slot,&Op::Submit,deadline(),||unreachable!(),|_,_|Reply::Value(json!({"ok":false,"padding":"x".repeat(2*1024*1024)}))).is_err());
        let locked=slot.lock().unwrap();let target=locked.as_ref().unwrap();
        assert_eq!(target.data.epoch,1);assert!(target.data.queue.is_empty());assert_eq!(target.data.persisted,1);
    }
}
