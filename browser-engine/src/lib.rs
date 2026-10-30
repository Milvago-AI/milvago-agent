pub use milvago_dlp_engine as dlp;
use regex::RegexBuilder;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeSet, VecDeque};
use std::sync::{Mutex, OnceLock};
use unicode_normalization::UnicodeNormalization;

pub const TEXT_LIMIT: usize = 32 * 1024;
#[cfg(target_arch = "wasm32")]
const JSON_LIMIT: usize = 128 * 1024;
pub type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Debug, Deserialize)]
pub struct InspectionInput {
    pub config: Value,
    pub service: Value,
    pub text: String,
    pub provider: String,
    pub upload: bool,
    pub scope: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Inspection {
    pub ok: bool,
    pub action: String,
    pub text: String,
    pub labels: Vec<String>,
    pub reason: String,
    #[serde(default,skip_serializing_if="std::ops::Not::not")]
    pub confirmation: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dlp: Vec<dlp::Decision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dlp_fingerprint: Option<String>,
}

pub fn inspect(input: &InspectionInput) -> Result<Inspection> {
    inspect_with_context(input, std::collections::BTreeMap::new())
}

pub fn inspect_with_context(input: &InspectionInput, mut facts: std::collections::BTreeMap<String,String>) -> Result<Inspection> {
    let Some(raw) = input.config.get("dlp") else { return inspect_legacy(input); };
    let policy: dlp::Policy = serde_json::from_value(raw.clone()).map_err(|_| "invalid DLP policy")?;
    dlp::validate(&policy)?;
    let native=facts.get("channel").is_some_and(|value|value=="native")||input.scope=="coding";
    let mut legacy = input.clone();
    if input.config["dlp_legacy_disabled"] == true {
        legacy.config["protection"]["keywords"] = serde_json::json!([]);
        legacy.config["protection"]["block_uploads"] = serde_json::json!(false);
        legacy.config["privacy"]["enabled"] = serde_json::json!(false);
    }
    if native&&(!policy.inspection||!policy.native_inspection) {
        if input.text.len()>TEXT_LIMIT{return Err("text exceeds local inspection limit".into());}
        legacy.text.clear();legacy.config["protection"]["keywords"]=serde_json::json!([]);
        legacy.config["protection"]["block_uploads"]=serde_json::json!(false);
        legacy.config["privacy"]=serde_json::json!({"enabled":false,"custom_rules":[]});
        legacy.config["classification"]=serde_json::json!({"coding":[],"browser":[],"medical_terms":[]});
        let mut result=inspect_legacy(&legacy)?;result.text=input.text.clone();return Ok(result);
    }
    let mut result = inspect_legacy(&legacy)?;
    if let Some(signed) = input.config["dlp_context"].as_object() {
        for (key,value) in signed { if let Some(value) = value.as_str() { facts.insert(key.clone(),value.into()); } }
    }
    facts.insert("channel".into(), if native { "native" } else { "browser" }.into());
    facts.insert("provider".into(), input.service["id"].as_str().unwrap_or(&input.provider).into());
    let output = dlp::evaluate(&dlp::Input {
        policy:policy.clone(), texts:std::collections::BTreeMap::from([("prompt".into(),vec![input.text.clone()])]),
        facts, upload:Some(input.upload),
    })?;
    if output.action == "block" {
        result.action="block".into();
        result.reason=if output.reason.is_empty(){"This submission is restricted by a DLP rule.".into()}else{output.reason};
        result.decision_reason=Some(if result.reason=="control_unavailable"{"control_unavailable"}else{"dlp"}.into());
        result.text=input.text.clone();
    } else if result.action != "block" && result.action != "redirect" {
        if let Some(text)=output.texts.get("prompt").and_then(|values|values.first()) {
            result.text=text.clone();
            if output.action=="review" { result.action="review".into(); result.confirmation=output.confirmation;result.reason=if output.confirmation{output.reason.clone()}else{"Review the transformed text before sending.".into()}; }
        }
    }
    for decision in &output.decisions {
        if decision.condition != dlp::Truth::True { continue; }
        if decision.rule_id.starts_with("legacy-keyword") { result.labels.push("keyword".into()); }
        if decision.rule_id.starts_with("legacy-custom") { result.labels.push("custom".into()); }
        if let Some(category)=decision.rule_id.strip_prefix("legacy-mask-") { result.labels.push(category.into()); }
    }
    result.labels.sort();result.labels.dedup();
    if policy.journal {
        result.dlp=output.decisions;
        result.dlp_fingerprint=input.config["dlp_fingerprint"].as_str().map(str::to_owned);
    }
    Ok(result)
}

fn inspect_legacy(input: &InspectionInput) -> Result<Inspection> {
    if input.text.len() > TEXT_LIMIT { return Err("text exceeds local inspection limit".into()); }
    if input.provider.len() > 100 || input.scope.len() > 32 { return Err("invalid inspection input".into()); }
    let protection = &input.config["protection"];
    let message = protection["message"].as_str().unwrap_or("La politique de votre organisation empêche cet envoi.");
    let mut out = Inspection { ok: true, action: "observe".into(), text: input.text.clone(), labels: vec![], reason: String::new(), confirmation:false, redirect_url: None, decision_reason: None, evidence: None, dlp: vec![], dlp_fingerprint: None };
    if input.service["mode"] == "block" || (input.upload && protection["block_uploads"].as_bool().unwrap_or(false)) { out.action = "block".into(); out.reason = message.into(); }
    if input.service["mode"] == "redirect" {
        let target = input.service["redirect_url"].as_str().ok_or("missing redirect destination")?;
        let url = url::Url::parse(target).map_err(|_| "redirect destination rejected")?;
        if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() || explicit_port(target) { return Err("redirect destination rejected".into()); }
        // A destination the same policy holds back would only bounce the person again.
        if held(&input.config, url.host_str().unwrap_or_default()) { out.action = "block".into(); out.reason = message.into(); }
        else { out.action = "redirect".into(); out.redirect_url = Some(target.into()); }
    }
    let lower = input.text.to_lowercase();
    let mut labels = BTreeSet::new();
    let keywords = strings(&protection["keywords"]);
    if !keywords.is_empty() {
        let (folded, compact) = skeletons(&input.text);
        let exceptions: Vec<String> = strings(&protection["exceptions"])
            .iter()
            .map(|exception| skeletons(exception).0.text)
            .collect();
        // The server accepts up to 200 keywords: every one of them is read.
        for keyword in keywords.into_iter().take(200) {
            let (key, key_compact) = skeletons(keyword);
            if key.text.is_empty() || exceptions.contains(&key.text) { continue; }
            // Offsets in the lowercased text name the original's bytes only when that very
            // passage lowercases back to the keyword; otherwise no excerpt at all.
            let key_lower = keyword.to_lowercase();
            let tier = if let Some(at) = lower.find(&key_lower) { Some(("exact", input.text.get(at..at + key_lower.len()).filter(|passage| passage.to_lowercase() == key_lower).map(|_| (at, at + key_lower.len())))) }
            else if let Some(at) = folded.text.find(&key.text) { Some(("unicode", folded.source(at, at + key.text.len()))) }
            else if key_compact.text.chars().count() >= 4 && let Some(at) = compact.text.find(&key_compact.text) { Some(("unicode", compact.source(at, at + key_compact.text.len()))) }
            else if protection["fuzzy"] != "off" && folded.text.split(|c: char| !c.is_alphanumeric()).any(|word| distance_one(&key.text, word)) { Some(("fuzzy", None)) }
            else { None };
            if let Some((tier, at)) = tier {
                labels.insert("keyword".into());
                if out.evidence.is_none() { out.evidence = at.and_then(|(from,to)| excerpt(&input.text, from, to)); }
                if protection[tier] == "block" { out.action = "block".into(); out.reason = message.into(); }
            }
        }
    }
        inspect_sensitive(&input.config, &input.text, &input.scope, &lower, &mut out, &mut labels)?;
    out.labels = labels.into_iter().collect();
    Ok(out)
}

// `Url` drops a default port (`:443`) and an empty one: read the authority as written, so
// the engine refuses every port the server refuses.
fn explicit_port(target: &str) -> bool {
    let rest = target.split_once("://").map_or("", |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#', '\\']).next().unwrap_or_default();
    let host = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
    host.rsplit_once(']').map_or(host, |(_, after)| after).contains(':')
}
fn held(config: &Value, host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    config["services"].as_array().into_iter().flatten().filter(|s| s["enabled"].as_bool().unwrap_or(false) && matches!(s["mode"].as_str(), Some("block" | "redirect")))
        .flat_map(|s| strings(&s["domains"])).map(|d| d.trim_end_matches('.').to_ascii_lowercase())
        .any(|d| !d.is_empty() && (host == d || host.ends_with(&format!(".{d}"))))
}
fn strings(v: &Value) -> Vec<&str> { v.as_array().map(|items| items.iter().filter_map(Value::as_str).collect()).unwrap_or_default() }
// Format characters (Unicode Cf), variation selectors and fillers: rendered as nothing,
// kept by NFKC, so they could split a term or a value without changing what is read.
fn invisible(c: char) -> bool { matches!(c, '\u{ad}' | '\u{34f}' | '\u{600}'..='\u{605}' | '\u{61c}' | '\u{6dd}' | '\u{70f}' | '\u{8e2}' | '\u{115f}' | '\u{1160}'
    | '\u{17b4}' | '\u{17b5}' | '\u{180b}'..='\u{180f}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{206f}'
    | '\u{3164}' | '\u{fe00}'..='\u{fe0f}' | '\u{feff}' | '\u{ffa0}' | '\u{fff9}'..='\u{fffb}' | '\u{110bd}' | '\u{110cd}' | '\u{1bca0}'..='\u{1bca3}'
    | '\u{1d173}'..='\u{1d17a}' | '\u{890}' | '\u{891}' | '\u{2065}' | '\u{fff0}'..='\u{fff8}' | '\u{13430}'..='\u{1343f}'
    // The whole tag and variation-selector plane, assigned or not: default ignorable.
    | '\u{e0000}'..='\u{e0fff}') }
#[derive(Default)] struct Skeleton { text: String, spans: Vec<(usize,usize,usize)> }
impl Skeleton {
    fn push(&mut self, c: char, from: usize, to: usize) { self.spans.push((self.text.len(),from,to)); self.text.push(c); }
    fn source(&self, start: usize, end: usize) -> Option<(usize,usize)> { let first=self.spans.partition_point(|s|s.0<start); let last=self.spans.partition_point(|s|s.0<end); (first<last).then(|| (self.spans[first].1, self.spans[last-1].2)) }
}
/// NFKC per character, invisibles, combining marks and the blank Braille cell dropped, case kept: what the sensitive patterns read, so
/// full-width digits or a zero-width space inside a value cannot hide it from them.
fn normalized(text:&str)->Skeleton {
    let mut view=Skeleton::default();
    for (at,source) in text.char_indices() { let end=at+source.len_utf8(); let mut buffer=[0u8;4]; for c in source.encode_utf8(&mut buffer).nfkc().filter(|c|!invisible(*c)&&!unicode_normalization::char::is_combining_mark(*c)&&*c!='\u{2800}') { view.push(c,at,end); } }
    view
}
fn skeletons(text:&str)->(Skeleton,Skeleton) {
    let (mut folded,mut compact)=(Skeleton::default(),Skeleton::default());
    for (at,source) in text.char_indices() { let end=at+source.len_utf8(); let mut buffer=[0u8;4]; let composed:String=source.encode_utf8(&mut buffer).nfkc().collect(); for c in unicode_security::skeleton(&composed).filter(|c|!invisible(*c)&&!unicode_normalization::char::is_combining_mark(*c)).flat_map(char::to_lowercase) { folded.push(c,at,end); if c.is_alphanumeric(){compact.push(c,at,end);} } }
    (folded,compact)
}
fn distance_one(a:&str,b:&str)->bool { let a:Vec<_>=a.chars().collect();let b:Vec<_>=b.chars().collect();if a.len()<4||a.len()>64||b.len()>64||a.len().abs_diff(b.len())>1{return false;}let(mut i,mut j,mut errors)=(0,0,0);while i<a.len()&&j<b.len(){if a[i]==b[j]{i+=1;j+=1;continue;}errors+=1;if errors>1{return false;}if a.len()>=b.len(){i+=1;}if b.len()>=a.len(){j+=1;}}errors+(a.len()-i)+(b.len()-j)<=1 }
fn excerpt(text:&str,from:usize,to:usize)->Option<String>{let(from,to)=(from.min(text.len()),to.min(text.len()));if from>=to||!text.is_char_boundary(from)||!text.is_char_boundary(to){return None;}let matched=&text[from..to];Some(match matched.char_indices().nth(80){None=>matched.into(),Some((cut,_))=>format!("{}…",&matched[..cut])})}

fn safe_regex(pattern:&str,ci:bool)->Result<regex::Regex>{if pattern.len()>200{return Err("custom pattern too long".into());}let re=RegexBuilder::new(pattern).case_insensitive(ci).size_limit(256*1024).dfa_size_limit(512*1024).build().map_err(|e|e.to_string())?;if re.is_match(""){return Err("pattern must not match empty input".into());}Ok(re)}
const FIXED_PATTERNS: [(&str, &str); 7] = [
    ("email", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    // No `\b`: a Unicode word boundary hid a value glued to `é` or `_`. `bounded` holds
    // these two to no ASCII letter or digit on either side instead.
    ("iban", r"[A-Z]{2}[0-9]{2}(?:(?:[ ]{1,2}|\t|\r?\n|[.-])?[A-Z0-9]){11,30}"),
    ("card", r"(?:[0-9]{13,19}|[0-9]{4}(?:[ .-][0-9]{4}){3}|[0-9]{4}[ .-][0-9]{6}[ .-][0-9]{5})"),
    ("phone", r"(?:\+[0-9]{1,3}[ .-]?)?(?:[0-9][ .-]?){8,14}[0-9]"),
    ("social_id", r"\b[12][0-9]{12,14}\b"),
    ("ssn_us", r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b"),
    ("ip", r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
];

/// Each fixed pattern, and the same pattern anchored on a whole candidate.
fn fixed_regexes() -> &'static [(&'static str, regex::Regex, regex::Regex)] {
    static REGEXES: OnceLock<Vec<(&str, regex::Regex, regex::Regex)>> = OnceLock::new();
    REGEXES.get_or_init(|| {
        FIXED_PATTERNS
            .iter()
            .map(|(kind, pattern)| {
                let compile = |p: &str| safe_regex(p, true).expect("fixed sensitive pattern must compile");
                (*kind, compile(pattern), compile(&format!("^(?:{pattern})$")))
            })
            .collect()
    })
}

/// The values of one fixed pattern that pass its check. The patterns are greedy and
/// case-insensitive: an IBAN's pattern also takes the word after it ("… 189 annule"), and a
/// failed check then hid the value itself (real campaign 0.7.3). A failed match is retried
/// shortened at each word end inside it, longest first, then from its next character, so a
/// valid value is never lost to the text around it.
fn checked_matches(kind: &str, pattern: &regex::Regex, whole: &regex::Regex, text: &str) -> Vec<(usize, usize)> {
    let mut found = Vec::new();
    let mut at = 0;
    while at <= text.len() {
        let Some(m) = pattern.find_at(text, at) else { break };
        let start = m.start();
        let word_ends = text[start..m.end()].char_indices().filter(|(i, c)| *i > 0 && !c.is_alphanumeric()).map(|(i, _)| start + i).filter(|end| text[..*end].chars().next_back().is_some_and(char::is_alphanumeric));
        let mut ends: Vec<usize> = std::iter::once(m.end()).chain(word_ends).collect();
        ends[1..].reverse();
        match ends.into_iter().find(|end| *end > start && bounded(kind, text, start, *end) && whole.is_match(&text[start..*end]) && plausible(kind, &text[start..*end])) {
            Some(end) => { found.push((start, end)); at = end; }
            None => at = start + text[start..].chars().next().map_or(1, char::len_utf8),
        }
    }
    found
}

fn bounded(kind: &str, text: &str, start: usize, end: usize) -> bool {
    let alnum = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric());
    !matches!(kind, "iban" | "card") || (!alnum(text[..start].chars().next_back()) && !alnum(text[end..].chars().next()))
}

struct CachedRegex {
    pattern: String,
    case_insensitive: bool,
    regex: regex::Regex,
}

fn custom_regex(pattern: &str, case_insensitive: bool) -> Result<regex::Regex> {
    const CAPACITY: usize = 64;
    static REGEXES: OnceLock<Mutex<VecDeque<CachedRegex>>> = OnceLock::new();
    let mut regexes = REGEXES
        .get_or_init(|| Mutex::new(VecDeque::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(cached) = regexes.iter().find(|cached| {
        cached.pattern == pattern && cached.case_insensitive == case_insensitive
    }) {
        return Ok(cached.regex.clone());
    }
    let regex = safe_regex(pattern, case_insensitive)?;
    if regexes.len() == CAPACITY {
        regexes.pop_front();
    }
    regexes.push_back(CachedRegex {
        pattern: pattern.into(),
        case_insensitive,
        regex: regex.clone(),
    });
    Ok(regex)
}
fn plausible(kind:&str,value:&str)->bool{let compact:String=value.chars().filter(|c|!matches!(c,' '|'-'|'.'|'\t'|'\n'|'\r')).collect();match kind{"ip"=>value.parse::<std::net::Ipv4Addr>().is_ok(),"ssn_us"=>{let p:Vec<_>=value.split('-').collect();p.len()==3&&p[0]!="000"&&p[0]!="666"&&!p[0].starts_with('9')&&p[1]!="00"&&p[2]!="0000"},"card"=>{let d:Vec<_>=compact.chars().filter_map(|c|c.to_digit(10)).collect();if !(13..=19).contains(&d.len())||d.iter().all(|n|*n==d[0]){return false;}d.iter().rev().enumerate().map(|(i,n)|{let n=if i%2==1{n*2}else{*n};if n>9{n-9}else{n}}).sum::<u32>()%10==0},"iban"=>{let value=compact.to_ascii_uppercase();if !(15..=34).contains(&value.len())||!value.is_ascii(){return false;}let mut r=0;for b in value.bytes().skip(4).chain(value.bytes().take(4)){if b.is_ascii_digit(){r=(r*10+u32::from(b-b'0'))%97}else if b.is_ascii_uppercase(){r=(r*100+u32::from(b-b'A'+10))%97}else{return false}}r==1},_=>true}}
fn looks_like_source(text:&str)->bool{const I:[&str;14]=["function ","import ","fn ","def ","class ","return ","const ","public ","#include","=>","->","()","{}","};"];let hits=I.iter().filter(|i|text.contains(**i)).take(3).count();let nested=text.chars().scan(0i32,|d,c|{*d+=match c{'{'|'('| '['=>1,'}'|')'|']'=>-1,_=>0};Some(*d)}).any(|d|d>=2);hits>=3||(hits>=2&&nested)}
fn medical_terms(config:&Value)->Vec<String>{let defined=&config["classification"]["medical_terms"];if defined.is_array(){return strings(defined).into_iter().take(100).map(|s|s.trim().to_lowercase()).filter(|s|!s.is_empty()).collect();}["diagnostic","ordonnance","prescription","medical record","dossier médical"].into_iter().map(str::to_string).collect()}
type SensitiveSpan = (usize, usize, String);

fn merge_sensitive_spans(mut spans: Vec<SensitiveSpan>) -> Vec<SensitiveSpan> {
    spans.sort_by_key(|span| span.0);
    let mut merged: Vec<SensitiveSpan> = Vec::new();
    for (start, end, label) in spans {
        if let Some(previous) = merged.last_mut() {
            if start < previous.1 {
                previous.1 = previous.1.max(end);
                continue;
            }
        }
        merged.push((start, end, label));
    }
    merged
}

fn redact_sensitive_spans(text: &str, spans: Vec<SensitiveSpan>) -> String {
    let merged = merge_sensitive_spans(spans);
    let mut values: std::collections::BTreeMap<&str, Vec<&str>> = std::collections::BTreeMap::new();
    for (start, end, label) in &merged {
        let value = &text[*start..*end];
        let list = values.entry(label.as_str()).or_default();
        if !list.contains(&value) {
            list.push(value);
        }
    }
    let mut result = String::new();
    let mut cursor = 0;
    for (start, end, label) in &merged {
        result.push_str(&text[cursor..*start]);
        let list = &values[label.as_str()];
        if list.len() > 1 {
            let index = list.iter().position(|value| *value == &text[*start..*end]).map_or(1, |index| index + 1);
            result.push_str(&format!("[{label}{index}]"));
        } else {
            result.push_str(&format!("[{label}]"));
        }
        cursor = *end;
    }
    result.push_str(&text[cursor..]);
    result
}

fn inspect_sensitive(config:&Value,text:&str,scope:&str,lower:&str,out:&mut Inspection,labels:&mut BTreeSet<String>)->Result<()>{
 let redact=config["privacy"]["enabled"].as_bool().unwrap_or(false);let types=strings(&config["privacy"]["types"]);let selected=config["classification"][scope].as_array().map(|_|strings(&config["classification"][scope]));let wanted=|kind:&str|types.contains(&kind)||selected.as_ref().is_none_or(|items|items.contains(&kind));let mut spans=Vec::new();
 // The marker carries the rule's LABEL (product decision of 2026-09-16): the
 // predefined category in uppercase (`[IP]`, `[EMAIL]`), the label entered for a
 // custom rule (`[NUMERO]`), `custom` only when it has none. Event
 // labels (`labels`), on the other hand, remain the category identifiers.
 // Patterns read the normalized view; masking covers the original bytes it came from.
 let view=normalized(text);
 for(kind,pattern,whole)in fixed_regexes(){if !wanted(kind){continue}for(start,end)in checked_matches(kind,pattern,whole,&view.text){labels.insert((*kind).into());if redact&&types.contains(kind)&&let Some((from,to))=view.source(start,end){spans.push((from,to,kind.to_uppercase()));}}}
 for custom in config["privacy"]["custom_rules"].as_array().into_iter().flatten().take(50){if !custom["enabled"].as_bool().unwrap_or(false){continue}let placeholder=custom["label"].as_str().map(str::trim).filter(|s|!s.is_empty()).unwrap_or("custom").to_string();for m in custom_regex(custom["pattern"].as_str().ok_or("custom pattern missing")?,custom["case_insensitive"].as_bool().unwrap_or(false))?.find_iter(&view.text).filter(|m|!m.is_empty()){labels.insert("custom".into());if redact&&let Some((from,to))=view.source(m.start(),m.end()){spans.push((from,to,placeholder.clone()));}}}
 if wanted("source_code")&&looks_like_source(text){labels.insert("source_code".into());}if wanted("medical")&&medical_terms(config).iter().filter(|term|lower.contains(term.as_str())).take(2).count()>=2{labels.insert("medical".into());}
 if !spans.is_empty() {
     out.text = redact_sensitive_spans(text, spans);
     if out.action == "observe" && config["privacy"]["review"].as_bool().unwrap_or(false) {
         out.action = "review".into();
         out.reason = "Vérifiez le texte masqué avant l’envoi.".into();
     }
 }
 // A value masked by privacy keeps its label although the usage classification does not list it: the
 // event otherwise said nothing of an e-mail it masked (real campaign 0.7.7: `[EMAIL]` sent, `labels` card and iban).
 if let Some(selected)=config["classification"][scope].as_array(){labels.retain(|label|label=="custom"||label=="keyword"||(redact&&types.contains(&label.as_str()))||selected.iter().any(|v|v.as_str()==Some(label)));}Ok(())
}
#[cfg(target_arch = "wasm32")]
mod wasm {
    use super::*;
    #[unsafe(no_mangle)]
    pub extern "C" fn milvago_engine_alloc(length: usize) -> *mut u8 {
        let mut bytes = Vec::<u8>::with_capacity(length);
        let pointer = bytes.as_mut_ptr();
        std::mem::forget(bytes);
        pointer
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn milvago_engine_inspect_json(pointer: *mut u8, length: usize) -> u64 {
        if length > JSON_LIMIT { return response(error("inspection input exceeds limit")); }
        // The only supported caller is the extension loader, which obtains this
        // allocation from milvago_engine_alloc. It transfers ownership exactly once.
        let input = unsafe { Vec::from_raw_parts(pointer, length, length) };
        let result = String::from_utf8(input)
            .map_err(|_| "inspection input is not UTF-8".to_string())
            .and_then(|input| serde_json::from_str::<InspectionInput>(&input).map_err(|e| e.to_string()))
            .and_then(|input| inspect(&input))
            .and_then(|result| serde_json::to_string(&result).map_err(|e| e.to_string()))
            .unwrap_or_else(|message| error(&message));
        response(result)
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn milvago_engine_free(pointer: *mut u8, length: usize) {
        if !pointer.is_null() {
            unsafe { drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(pointer, length))); }
        }
    }

    fn response(value: String) -> u64 {
        let mut bytes = value.into_bytes().into_boxed_slice();
        let length = bytes.len();
        let pointer = bytes.as_mut_ptr();
        std::mem::forget(bytes);
        ((length as u64) << 32) | pointer as u64
    }
    fn error(message: &str) -> String { serde_json::json!({"ok":false,"error":message}).to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> InspectionInput {
        serde_json::from_value(serde_json::json!({
            "config": {
                "protection": {"keywords": ["confidentiel"], "exact": "block", "unicode": "block", "fuzzy": "off"},
                "privacy": {"enabled": false}
            },
            "service": {"mode": "observe"},
            "text": "c o n f i d e n t i e l",
            "provider": "example.invalid",
            "upload": false,
            "scope": "browser"
        })).unwrap()
    }

    #[test]
    fn unicode_keyword_blocks() {
        let actual = inspect(&input()).unwrap();
        assert_eq!(actual.action, "block");
        assert_eq!(actual.evidence.as_deref(), Some("c o n f i d e n t i e l"));
    }

    #[test]
    fn ssn_is_masked_but_invalid_value_is_not() {
        let mut request = input();
        request.config = serde_json::json!({
            "protection": {},
            "privacy": {"enabled": true, "types": ["ssn_us"], "review": true},
            "classification": {"browser": ["ssn_us"]}
        });
        request.text = "123-45-6789 and 000-45-6789".into();
        let actual = inspect(&request).unwrap();
        assert_eq!(actual.text, "[SSN_US] and 000-45-6789");
        assert_eq!(actual.action, "review");
    }

    #[test]
    fn full_width_digits_and_invisible_characters_do_not_hide_a_value() {
        let mut request = input();
        request.config = serde_json::json!({
            "protection": {},
            "privacy": {"enabled": true, "types": ["ssn_us"], "review": false},
            "classification": {"browser": ["ssn_us"]}
        });
        request.text = "a １２３-４５-６７８９ b 123-4\u{200b}5-67\u{ad}89 c".into();
        let actual = inspect(&request).unwrap();
        assert_eq!(actual.text, "a [SSN_US1] b [SSN_US2] c");
        assert_eq!(actual.labels, vec!["ssn_us".to_string()]);
    }

    #[test]
    fn every_keyword_the_server_accepts_is_read() {
        let mut request = input();
        let keywords: Vec<String> = (0..200).map(|index| format!("term{index:03}")).collect();
        request.config = serde_json::json!({"protection": {"keywords": keywords, "exact": "block", "unicode": "block", "fuzzy": "off"}});
        request.text = "mentions term199 here".into();
        assert_eq!(inspect(&request).unwrap().action, "block");
    }

    #[test]
    fn distinct_values_are_numbered_and_repeated_values_reuse_the_marker() {
        let mut request = input();
        request.config = serde_json::json!({
            "protection": {},
            "privacy": {
                "enabled": true,
                "types": ["ip"],
                "review": true,
                "custom_rules": [{"enabled": true, "label": "NUMERO", "pattern": "\\b[15]\\b", "case_insensitive": false}]
            },
            "classification": {"browser": ["ip"]}
        });
        request.text = "192.0.2.1 et 192.0.2.2 et 192.0.2.1 ; 1 et 5".into();
        let actual = inspect(&request).unwrap();
        assert_eq!(actual.text, "[IP1] et [IP2] et [IP1] ; [NUMERO1] et [NUMERO2]");
        assert_eq!(actual.action, "review");
        assert_eq!(actual.labels, ["custom", "ip"]);
    }

    #[test]
    fn a_zero_width_custom_pattern_marks_nothing() {
        let mut request = input();
        request.config = serde_json::json!({
            "protection": {},
            "privacy": {"enabled": true, "types": [], "custom_rules": [{"enabled": true, "label": "B", "pattern": "\\b", "case_insensitive": false}]}
        });
        request.text = "hello world".into();
        let actual = inspect(&request).unwrap();
        assert_eq!(actual.text, "hello world");
        assert!(actual.labels.is_empty());
    }

    #[test]
    fn an_excerpt_is_never_taken_from_shifted_lowercase_offsets() {
        let mut request = input();
        // 'İ' lowercases to two characters: offsets in the lowercased text no longer
        // name the original's bytes.
        request.config["protection"]["keywords"] = serde_json::json!(["secret"]);
        // Two Kelvin signs shrink by as much: same total length, shifted offsets.
        request.text = "İİİİ secret \u{212A}\u{212A}".into();
        let actual = inspect(&request).unwrap();
        assert_eq!(actual.action, "block");
        assert!(actual.evidence.as_deref().is_none_or(|excerpt| excerpt == "secret"));
    }

    fn masking(types: &[&str], text: &str) -> Inspection {
        let mut request = input();
        request.config = serde_json::json!({
            "protection": {},
            "privacy": {"enabled": true, "types": types, "review": true},
            "classification": {"browser": types}
        });
        request.text = text.into();
        inspect(&request).unwrap()
    }

    // Real campaign 0.7.3: the case-insensitive IBAN pattern swallowed the word after the
    // value, the check digits then failed and the IBAN left in clear.
    #[test]
    fn an_iban_followed_by_a_word_is_masked() {
        for (text, expected) in [
            ("IBAN FR76 3000 6000 0112 3456 7890 189 annule", "IBAN [IBAN] annule"),
            ("IBAN FR76 3000 6000 0112 3456 7890 189 ABCD", "IBAN [IBAN] ABCD"),
            ("(FR76 3000 6000 0112 3456 7890 189).", "([IBAN])."),
            ("iban:fr76 3000 6000 0112 3456 7890 189, merci", "iban:[IBAN], merci"),
            ("FR7630006000 01123456 7890189 ok", "[IBAN] ok"),
            ("FR76\u{a0}3000\u{a0}6000\u{a0}0112\u{a0}3456\u{a0}7890\u{a0}189 ok", "[IBAN] ok"),
            ("FR76 3000 6000 0112 3456 7890 189 DE89 3704 0044 0532 0130 00 fin", "[IBAN1] [IBAN2] fin"),
            ("XX12 FR76 3000 6000 0112 3456 7890 189 fin", "XX12 [IBAN] fin"),
        ] {
            let actual = masking(&["iban"], text);
            assert_eq!(actual.text, expected, "{text}");
            assert_eq!(actual.labels, ["iban"], "{text}");
            assert_eq!(actual.action, "review", "{text}");
        }
    }

    #[test]
    fn a_wrong_iban_is_not_masked_even_when_shortened() {
        for text in ["FR76 3000 6000 0112 3456 7890 188 annule", "FR76 3000 6000 0112 3456 7890 188", "AB12 CDEF GHIJ KLMN OPQR mot"] {
            let actual = masking(&["iban"], text);
            assert_eq!(actual.text, text);
            assert!(actual.labels.is_empty(), "{text}");
        }
    }

    #[test]
    fn a_card_beside_words_is_masked_and_a_wrong_one_is_not() {
        for (text, expected) in [
            ("carte 4111 1111 1111 1111 annule", "carte [CARD] annule"),
            ("carte 4111111111111111.", "carte [CARD]."),
            ("4111-1111-1111-1111 et 5555 5555 5555 4444 fin", "[CARD1] et [CARD2] fin"),
            ("carte 4111 1111 1111 1112 annule", "carte 4111 1111 1111 1112 annule"),
        ] {
            assert_eq!(masking(&["card"], text).text, expected, "{text}");
        }
    }

    // Real campaign 0.7.7: an e-mail masked under privacy lost its label, the classification listing only
    // card and iban. Detection without masking still follows the classification.
    #[test]
    fn a_masked_value_keeps_its_label_outside_the_classification() {
        let mut request = input();
        request.config = serde_json::json!({
            "protection": {},
            "privacy": {"enabled": true, "types": ["email", "card"], "review": true},
            "classification": {"browser": ["iban", "card", "social_id"]}
        });
        request.text = "mail jean.exemple@example.com carte 4111 1111 1111 1111 ip 192.0.2.1".into();
        let actual = inspect(&request).unwrap();
        assert_eq!(actual.text, "mail [EMAIL] carte [CARD] ip 192.0.2.1");
        assert_eq!(actual.labels, ["card", "email"]);
        request.config["privacy"]["enabled"] = serde_json::json!(false);
        assert_eq!(inspect(&request).unwrap().labels, ["card"], "not masked: classification only");
    }

    // Observation mode: a protected word found must leave its label even when the usage
    // classification does not list it, or observing protected words records nothing.
    #[test]
    fn an_observed_keyword_keeps_its_label() {
        let mut request = input();
        request.config = serde_json::json!({
            "protection": {"keywords": ["PRJ-1234"], "exact": "observe", "unicode": "observe", "fuzzy": "off"},
            "privacy": {"enabled": false},
            "classification": {"browser": ["iban"]}
        });
        request.text = "voir PRJ-1234 demain".into();
        let actual = inspect(&request).unwrap();
        assert_eq!(actual.action, "observe");
        assert_eq!(actual.labels, ["keyword"]);
    }

    // Fourth review, M1: a combining mark or a blank Braille cell inside a value split it
    // for the patterns while the reader saw the value whole.
    #[test]
    fn combining_marks_and_braille_blanks_do_not_hide_a_value() {
        for text in ["carte 4\u{301}111 1111 1111 1111 fin", "carte 4111\u{2800}1111\u{2800}1111\u{2800}1111 fin", "carte 4111 1\u{20dd}111 1111 1111 fin"] {
            assert_eq!(masking(&["card"], text).text, "carte [CARD] fin", "{text:?}");
        }
    }

    // Fourth review, M2: other separators a person or a document puts in an IBAN or a card,
    // and a value glued to an accented letter or an underscore.
    #[test]
    fn wider_separators_and_glued_values_are_masked() {
        for (kind, text, expected) in [
            ("iban", "FR76  3000  6000  0112  3456  7890  189 ok", "[IBAN] ok"),
            ("iban", "FR76\t3000\t6000\t0112\t3456\t7890\t189 ok", "[IBAN] ok"),
            ("iban", "FR76\n3000\n6000\n0112\n3456\n7890\n189\nok", "[IBAN]\nok"),
            ("iban", "FR76-3000-6000-0112-3456-7890-189 ok", "[IBAN] ok"),
            ("iban", "FR76.3000.6000.0112.3456.7890.189 ok", "[IBAN] ok"),
            ("iban", "réf_FR7630006000011234567890189 ok", "réf_[IBAN] ok"),
            ("iban", "éFR7630006000011234567890189 ok", "é[IBAN] ok"),
            ("card", "carte 4111.1111.1111.1111 fin", "carte [CARD] fin"),
            ("card", "carte_4111111111111111 fin", "carte_[CARD] fin"),
            ("card", "numéro é4111 1111 1111 1111 fin", "numéro é[CARD] fin"),
        ] {
            assert_eq!(masking(&[kind], text).text, expected, "{text:?}");
        }
    }

    #[test]
    fn wider_separators_bring_no_false_positive() {
        for (kind, text) in [
            ("iban", "FR76.3000.6000.0112.3456.7890.188 ok"),
            ("iban", "FR76\t3000\t6000\t0112\t3456\t7890\t188"),
            ("iban", "version AB12.CDEF.GHIJ.KLMN fin"),
            ("card", "version 2024.1015.0001.0003 fin"),
            ("card", "carte 4111.1111.1111.1112 fin"),
            // A valid card inside a longer run of digits or letters is not a card.
            ("card", "ref 99994111111111111111 fin"),
            ("card", "ref a4111111111111111 fin"),
            ("card", "ref 4111111111111111a fin"),
            ("iban", "codeXFR7630006000011234567890189 fin"),
        ] {
            let actual = masking(&[kind], text);
            assert_eq!(actual.text, text, "{text:?}");
            assert!(actual.labels.is_empty(), "{text:?}");
        }
    }

    fn redirect(config: serde_json::Value, target: &str) -> Result<Inspection> {
        let mut request = input();
        request.config = config;
        request.text = "bonjour".into();
        request.service = serde_json::json!({"mode": "redirect", "redirect_url": target});
        inspect(&request)
    }

    // Fourth review, M5: the server refuses a port in a redirect destination; the engine
    // refuses it too, explicit default port included, and never sends a person to a
    // destination the same policy holds back.
    #[test]
    fn a_redirect_destination_with_a_port_is_refused() {
        let config = serde_json::json!({"protection": {}, "privacy": {"enabled": false}});
        for target in ["https://ai.example.test:8443/", "https://ai.example.test:443/", "https://[2001:db8::1]:443/", "https://ai.example.test:/"] {
            assert!(redirect(config.clone(), target).is_err(), "{target}");
        }
        let fine = redirect(config.clone(), "https://ai.example.test/approved").unwrap();
        assert_eq!(fine.action, "redirect");
        assert_eq!(fine.redirect_url.as_deref(), Some("https://ai.example.test/approved"));
        assert_eq!(redirect(config, "https://[2001:db8::1]/").unwrap().action, "redirect");
    }

    #[test]
    fn a_redirect_to_a_held_destination_blocks_instead() {
        let config = serde_json::json!({"protection": {}, "privacy": {"enabled": false}, "services": [
            {"id": "other", "domains": ["held.example.test"], "enabled": true, "mode": "block"},
            {"id": "off", "domains": ["off.example.test"], "enabled": false, "mode": "block"},
            {"id": "seen", "domains": ["seen.example.test"], "enabled": true, "mode": "observe"}
        ]});
        for target in ["https://held.example.test/", "https://HELD.example.test./x", "https://www.held.example.test/"] {
            let actual = redirect(config.clone(), target).unwrap();
            assert_eq!(actual.action, "block", "{target}");
            assert!(actual.redirect_url.is_none(), "{target}");
        }
        for target in ["https://off.example.test/", "https://seen.example.test/", "https://notheld.example.test/"] {
            assert_eq!(redirect(config.clone(), target).unwrap().action, "redirect", "{target}");
        }
    }

    #[test]
    fn custom_regex_cache_keeps_case_options_distinct() {
        assert!(custom_regex("token", true).unwrap().is_match("TOKEN"));
        assert!(!custom_regex("token", false).unwrap().is_match("TOKEN"));
    }
}
