//! Metadata custody: only the privileged inspection path may create attribution.
use super::{ShadowEvent, ShadowPolicy};
use crate::Result;
pub use milvago_browser_engine::dlp::{Decision, Mode, Truth};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trace {
    pub fingerprint: String,
    pub action: String,
    pub delivery: String,
    pub decisions: Vec<Decision>,
}
impl Trace {
    pub fn valid(&self) -> bool {
        self.fingerprint.len()==64 && self.fingerprint.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))
            && matches!(self.action.as_str(),"observe"|"block"|"transform"|"review")
            && matches!(self.delivery.as_str(),"not_sent"|"prepared"|"observed"|"unknown"|"cancelled")
            && !self.decisions.is_empty() && self.decisions.len()<=128
            && self.decisions.iter().all(|d| !d.rule_id.is_empty() && d.rule_id.len()<=100 && d.rule_revision>0
                && !d.rule_name.is_empty() && d.rule_name.len()<=120 && !d.rule_name.chars().any(char::is_control)
                && d.mode!=Mode::Disabled && d.condition!=Truth::False && d.scope!=Truth::False
                && matches!(d.consequence.as_str(),"observe"|"warn"|"block"|"mask"|"replace")
                && matches!(d.outcome.as_str(),"unavailable"|"simulated"|"matched"|"blocked"|"overridden"|"prepared"|"final_blocked"|"observed"|"cancelled"|"observed_after_send")
                && d.occurrences<=2048)
    }
    pub fn inspection(reply: &Value, original: &Value) -> Option<Self> {
        let mut trace=Self {
            fingerprint:reply["dlp_fingerprint"].as_str()?.into(),
            action:reply["action"].as_str()?.into(),
            delivery:if reply["action"]=="block" {"not_sent"} else {"prepared"}.into(),
            decisions:serde_json::from_value(reply["dlp"].clone()).ok()?,
        };
        if trace.action=="observe" && reply["text"]!=*original {trace.action="transform".into();}
        trace.valid().then_some(trace)
    }
    /// Network evidence advances only a decision already held in privileged custody.
    pub fn observed(&mut self) {
        if self.delivery != "prepared" { return; }
        self.delivery = "observed".into();
        for decision in &mut self.decisions {
            if decision.outcome == "prepared" { decision.outcome = "observed".into(); }
        }
    }
    pub fn merge(&mut self, other: Self) {
        if self.fingerprint!=other.fingerprint {return;}
        for decision in other.decisions {
            if !self.decisions.iter().any(|d|d.rule_id==decision.rule_id && d.rule_revision==decision.rule_revision) {
                self.decisions.push(decision);
            }
        }
        if self.action=="observe" {self.action=other.action;}
    }
}

pub fn journal(policy: &ShadowPolicy) -> bool {
    policy.config["dlp"]["journal"].as_bool().or_else(||policy.config["dlp_control"]["journal"].as_bool()).unwrap_or(false)
}

pub fn report(state: &crate::State, request: &Value) -> Result<()> {
    let policy=super::cached(state)?;
    let tool=request["tool"].as_str().filter(|s|super::BROWSER_TOOLS.contains(s)).ok_or("invalid DLP browser")?;
    if policy.version<4 || request["fingerprint"]!=policy.config["dlp_fingerprint"] || request["channel"]!="browser"
        || request["mechanism"]!="browser-request" || request["status"]!="unavailable" {return Err("unqualified DLP coverage report".into());}
    // Loading the engine and sealing a browser transport are separate facts. The
    // private web transports remain unqualified, even with a working local engine.
    for (mechanism,status) in [("browser-engine","applied"),("browser-request","unavailable")] {
        crate::client()?.post(crate::api_url(state,"/v4/dlp/enforcement")?).bearer_auth(&state.credential)
            .json(&json!({"fingerprint":policy.config["dlp_fingerprint"],"tool":tool,"channel":"browser","mechanism":mechanism,"status":status}))
            .send()?.error_for_status()?;
    }
    Ok(())
}

pub fn enqueue_native(state: &mut crate::State,tool:&str,inspection:&milvago_browser_engine::Inspection,characters:u32)->Result<uuid::Uuid> {
    let policy=super::cached(state)?;
    let trace=Trace::inspection(&serde_json::to_value(inspection)?,&json!(inspection.text)).ok_or("DLP attribution unavailable")?;
    if !journal(&policy)||!trace.valid()||policy.config["dlp_fingerprint"]!=trace.fingerprint {return Err("DLP journal refused".into());}
    let provider=super::cli_provider(tool).ok_or("unsupported native DLP tool")?;
    let retained=policy.config["collection"]["enabled"]==true&&policy.config["collection"]["store_content"]==true;
    let mut event:ShadowEvent=serde_json::from_value(json!({"id":uuid::Uuid::new_v4(),"occurred_at":chrono::Utc::now(),"kind":"prompt","provider":provider,"source":"native","tool":tool,"action":if inspection.action=="block"{"blocked"}else{"observed"},"characters":characters,"labels":inspection.labels,"policy_revision":policy.revision}))?;
    event.dlp=Some(trace);
    if retained{event.prompt=Some(inspection.text.clone());}
    let size=super::fit_event(&mut event)?;crate::config::current().queue.check(state,1,size)?;
    let id=event.id;state.shadow_queue.push(event);Ok(id)
}

/// A separate entry point prevents a document-supplied rule id becoming evidence.
pub fn event(policy: &ShadowPolicy, catalog_revision: u64, input: Value, trace: Trace) -> Result<ShadowEvent> {
    if !trace.valid() || !journal(policy) {return Err("DLP journal metadata refused".into());}
    let expected=policy.config["dlp_fingerprint"].as_str().or_else(||policy.config["dlp_control"]["fingerprint"].as_str());
    if expected!=Some(trace.fingerprint.as_str()) {return Err("DLP inspection policy changed".into());}
    let mut narrow=policy.clone();
    if narrow.config["collection"]["enabled"]!=true {
        narrow.config["collection"]=json!({"enabled":true,"store_content":false,"store_file_names":false});
    }
    let mut event=super::browser_event(&narrow,catalog_revision,input)?;
    event.dlp=Some(trace);
    Ok(event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use milvago_browser_engine::dlp::{Policy,Domain};
    use chrono::Utc;
    use base64::{Engine,engine::general_purpose::STANDARD};
    use ed25519_dalek::{Signer,SigningKey};

    fn policy()->ShadowPolicy {
        ShadowPolicy {version:4,revision:8,issued_at:Utc::now(),expires_at:Utc::now()+chrono::Duration::minutes(5),capabilities:vec![],config:json!({
            "services":[{"id":"claude","enabled":true,"mode":"observe","domains":["claude.ai"]}],
            "collection":{"enabled":false,"store_content":false,"store_file_names":false},
            "dlp":Policy{schema_version:1,domain:Domain::Endpoint,inspection:true,native_inspection:false,journal:true,detectors:vec![],rules:vec![]},
            "dlp_legacy_disabled":true,"dlp_fingerprint":"a".repeat(64),
            "dlp_context":{"device_id":"7594a349-2d42-4104-b2e3-4acf54ac1295","organization_id":"ace529a0-7aa4-4585-aaf2-85bc097e5b67","group_id":"none"}
        })}
    }
    fn trace()->Trace {
        Trace {fingerprint:"a".repeat(64),action:"block".into(),delivery:"not_sent".into(),decisions:vec![Decision{rule_id:"fixture.rule".into(),rule_revision:1,rule_name:"Frozen name".into(),mode:Mode::Active,consequence:"block".into(),condition:Truth::True,scope:Truth::True,outcome:"blocked".into(),occurrences:0}]}
    }
    #[test]
    fn journal_does_not_require_retaining_the_prompt() {
        let p=policy();
        let input=json!({"source":"browser","tool":"chrome","provider":"claude.ai","kind":"prompt","action":"blocked","characters":16,"labels":[],"prompt":"synthetic-secret"});
        let record=event(&p,1,input.clone(),trace()).unwrap();
        assert!(record.prompt.is_none());assert_eq!(record.dlp.unwrap().decisions[0].rule_name,"Frozen name");
        let mut forged=input;forged["dlp"]=serde_json::to_value(trace()).unwrap();
        let mut collecting=p.clone();collecting.config["collection"]["enabled"]=json!(true);
        assert!(super::super::browser_event(&collecting,1,forged).is_err());
        let mut foreign=trace();foreign.fingerprint="b".repeat(64);
        assert!(event(&p,1,json!({}),foreign).is_err());
    }
    #[test]
    fn network_observation_advances_only_an_existing_prepared_trace() {
        let mut t=trace(); t.delivery="prepared".into(); t.action="transform".into(); t.decisions[0].outcome="prepared".into();
        t.observed(); assert_eq!(t.delivery,"observed"); assert_eq!(t.decisions[0].outcome,"observed");
        let frozen=serde_json::to_value(&t).unwrap(); t.observed(); assert_eq!(serde_json::to_value(&t).unwrap(),frozen);
        for state in ["not_sent","cancelled","unknown"] {let mut t=trace();t.delivery=state.into();t.observed();assert_eq!(t.delivery,state);assert_eq!(t.decisions[0].outcome,"blocked");}
    }
    #[test]
    fn signed_v4_requires_a_valid_endpoint_engine_configuration() {
        let key=SigningKey::from_bytes(&[73;32]);
        let sign=|policy:&ShadowPolicy|{let raw=serde_json::to_vec(policy).unwrap();crate::Envelope{payload:STANDARD.encode(&raw),signature:STANDARD.encode(key.sign(&raw).to_bytes())}};
        let mut p=policy();let public=STANDARD.encode(key.verifying_key().as_bytes());
        assert!(super::super::verify(&sign(&p),&public,0,Utc::now()).is_ok());
        p.config["dlp"]["schema_version"]=json!(99);
        assert!(super::super::verify(&sign(&p),&public,0,Utc::now()).is_err());
        p=policy();p.version=3;
        assert!(super::super::verify(&sign(&p),&public,0,Utc::now()).is_err());
        p=policy();p.config["dlp"]["domain"]=json!("server");
        assert!(super::super::verify(&sign(&p),&public,0,Utc::now()).is_err());
    }
}
