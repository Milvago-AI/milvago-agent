//! Signed declarative detection data; never a source of policy authority.
use crate::{Envelope, Result, State, Store};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use std::{collections::BTreeSet, io::Read, path::Path};
pub const ENGINE_VERSION: &str = "0.5.0";
#[derive(Default, Serialize, Deserialize)]
pub struct Cache {
    pub revision: u64,
    pub content_hash: String,
    pub envelope: Option<Envelope>,
    pub attempted_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub health: Vec<Value>,
    #[serde(default)]
    pub event_receipts: Vec<Value>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Engines {
    pub extension: String,
    pub bridge: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub kind: String,
    pub schema: u32,
    pub revision: u64,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub min_engine: Engines,
    pub content_hash: String,
    pub content: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dom {
    pub editor: String,
    pub send: String,
    pub response: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    pub method: String,
    pub host: String,
    pub path: String,
    #[serde(default)]
    pub text_path: String,
    /// Candidate paths for the prompt text, tried in order, the first that yields text
    /// winning. One route can carry two body shapes - Le Chat names it
    /// `content[*].text` when a thread opens and `messageInput[*].text` afterwards -
    /// and two rules cannot settle that: they match on method, host and path alone,
    /// and two matches make the observation ambiguous rather than picking one. When
    /// this list is not empty it supersedes `text_path` entirely.
    #[serde(default)]
    pub text_paths: Vec<String>,
    #[serde(default)]
    pub model_path: String,
    /// Where the request states the reasoning effort it asked for. Providers name it
    /// differently (`effort`, `thinking_effort`), so it is a path like the others.
    /// Tolerated before any catalog uses it: `Dom` and `Network` refuse unknown
    /// fields, so a catalog published with a field an older agent does not know is
    /// rejected outright, and `min_engine` does not protect against that - it compares
    /// both of its fields to one frozen constant. Field first, catalog afterwards.
    #[serde(default)]
    pub effort_path: String,
    #[serde(default)]
    pub conversation_path: String,
    /// Where the conversation identifier sits in the request PATH, as a zero-based
    /// segment index, for providers that never put it in the body: claude.ai states it
    /// only as `/api/organizations/<org>/chat_conversations/<uuid>/completion`. The
    /// body path keeps precedence. Declared here before any catalog uses it, for the
    /// reason `effort_path` records above: `Network` refuses unknown fields, so a
    /// catalog carrying a field this agent does not know is rejected whole.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation_url_segment: Option<usize>,
    /// Form fields that carry a whole JSON document of their own. Anonymous/mobile
    /// ChatGPT sends `application/x-www-form-urlencoded` whose `imageAttachments` and
    /// `conversationState` are documents: without naming them, no path can descend
    /// into them. Named rather than guessed - a prompt that happens to be JSON would
    /// otherwise turn into an object and lose its text silently.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub json_fields: Vec<String>,
    /// Where the request states the names of the attached files. The only route where
    /// the composer exposes no file picker to intercept. Never their contents.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub files_path: String,
    /// What the route carries. Absent or "prompt": a send, which observation reads and
    /// which content control holds to the approved text. "file": an upload, which the
    /// file-send block seals and which observation ignores — observing it would produce
    /// a request event of zero characters.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kind: String,
    /// The account state the route itself implies: "signed_out" for a send route only
    /// reachable without an account (anonymous ChatGPT's `/unauth-mweb/`), "signed_in"
    /// for one that requires it. A property of the measured route, never inferred from a
    /// page. Declared before any catalog carries it, for the reason `effort_path`
    /// records above.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub session: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provider {
    pub id: String,
    pub label: String,
    pub domains: Vec<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub conversation_path: String,
    #[serde(default)]
    pub conversation_segment: usize,
    /// Further page paths of a conversation, same segment: signed-out ChatGPT moves to
    /// `/uc/<id>` where a signed-in account uses `/c/<id>`. Declared before any catalog
    /// carries it, for the reason `effort_path` records above.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conversation_paths: Vec<String>,
    pub dom: Dom,
    #[serde(default)]
    pub network: Vec<Network>,
    pub qualified_at: String,
    /// Hosts the provider's page may load under content control besides its own domain
    /// and subdomains: claude.ai serves its interface from `assets-proxy.anthropic.com`,
    /// a different registrable domain. Allowed to be LOADED, never covered — no content
    /// script, no attribution. Measured on the site, never assumed. Declared before any
    /// catalog carries it, for the reason `effort_path` records above: `Provider` refuses
    /// unknown fields, so a catalog naming a host an older agent does not know would be
    /// rejected whole. Omitted when empty so today's catalogs keep their bytes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub asset_hosts: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeTool {
    pub id: String,
    pub platform: String,
    pub qualified_versions: Vec<String>,
    pub parser: String,
    #[serde(default)]
    pub telemetry_text_qualified_versions: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Heuristics {
    pub keys: Vec<String>,
    pub mime_types: Vec<String>,
}
/// An AI platform the catalogue names without covering it: no selector, no network rule,
/// nothing read from the page. The browser service worker reports only that the host was
/// reached.
///
/// It is a section of its own and never merges into `providers`, which is the safety
/// property: nothing here can reach the content-script registration, so naming a platform
/// cannot inject capture into a site this edition carries no qualification for.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnownPlatform {
    pub id: String,
    pub label: String,
    pub domains: Vec<String>,
    /// Path prefixes, for a platform living under a path of a host that is not itself an
    /// AI product. Absent means the whole host counts.
    #[serde(default)]
    pub paths: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Content {
    pub providers: Vec<Provider>,
    #[serde(default)]
    pub native_tools: Vec<NativeTool>,
    pub heuristics: Heuristics,
    /// `skip_serializing_if` matters as much as `default` here: this agent re-serializes
    /// the catalogue on its way to the extension, and emitting `known_platforms: []` for a
    /// catalogue that never named one would hand an older peer a document it refuses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub known_platforms: Vec<KnownPlatform>,
}
pub struct Catalog {
    pub header: Header,
    pub content: Content,
}
fn token(v: &str, max: usize) -> bool {
    !v.is_empty()
        && v.len() <= max
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}
fn version(v: &str) -> Option<Vec<u32>> {
    let n: Vec<_> = v.split('.').map(str::parse::<u32>).collect();
    if n.len() != 3 {
        return None;
    }
    n.into_iter()
        .collect::<std::result::Result<Vec<_>, _>>()
        .ok()
}
pub(crate) fn path(v: &str) -> bool {
    v.is_empty()
        || (v.starts_with('/')
            && v.len() <= 256
            && v.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/_.*-".contains(&b))
            && v.matches('*').count() <= 8)
}
fn json_path(v: &str) -> bool {
    if v.is_empty() {
        return true;
    }
    if v.len() > 256 {
        return false;
    }
    let parts: Vec<_> = v.split('.').collect();
    parts.len() <= 12
        && parts.into_iter().all(|p| {
            // The wildcard suffix must be stripped before the reserved-name check too:
            // "__proto__[*]" is the same prototype-pollution key as "__proto__" once a
            // JSON path is walked with valuesAt()-style array wildcards.
            let base = p.strip_suffix("[*]").unwrap_or(p);
            token(base, 64) && !matches!(base, "__proto__" | "constructor" | "prototype")
        })
}
// Provider ids and heuristic keys share Go's stricter detectionID grammar
// (lowercase-start, then lowercase/digit/dot/underscore/hyphen only) rather than
// the more permissive version-string token() grammar, which also allows uppercase.
pub(crate) fn identifier(v: &str) -> bool {
    let mut bytes = v.bytes();
    match bytes.next() {
        Some(b) if b.is_ascii_lowercase() || b.is_ascii_digit() => {}
        _ => return false,
    }
    v.len() <= 64 && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}
// Ids Go reserves for compiled native-tool parsers: a browser provider must never
// claim one, or the two catalogues (browser providers vs. native tools) collide.
const RESERVED_PROVIDER_IDS: [&str; 4] =
    ["codex", "claude-code", "claude-desktop", "claude-desktop-agent"];
// The closed set of native tools and parsers Go has actually compiled support for.
const NATIVE_TOOL_IDS: [&str; 3] = ["claude-code", "codex", "claude-desktop"];
const NATIVE_TOOL_PARSERS: [&str; 2] = ["otlp-v1", "claude-desktop-v1"];
fn validate_native_tools(c: &Content) -> Result<()> {
    for n in &c.native_tools {
        if !NATIVE_TOOL_IDS.contains(&n.id.as_str())
            || !NATIVE_TOOL_PARSERS.contains(&n.parser.as_str())
            || !matches!(n.platform.as_str(), "windows" | "linux")
            || n.qualified_versions.len() > 128
            || n.telemetry_text_qualified_versions.len() > 128
            || !n
                .qualified_versions
                .iter()
                .chain(&n.telemetry_text_qualified_versions)
                .all(|v| token(v, 64))
            // No raw-text qualification has yet been demonstrated on a real managed
            // tool (mirrors Go's unconditional 409 qualification_required gate).
            || !n.telemetry_text_qualified_versions.is_empty()
        {
            return Err("invalid native qualification".into());
        }
    }
    Ok(())
}

fn validate_known_platforms(c: &Content) -> Result<()> {
    // Known platforms are checked among themselves only. A host named here that is also a
    // covered provider is NOT refused: the editions cover different providers while a
    // published catalogue carries the same bytes to both, so refusing the overlap would
    // make a document valid on one side and impossible on the other. The overlap is
    // settled where the catalogue is consumed — a covered provider silences presence for
    // that host.
    if c.known_platforms.len() > 256 {
        return Err("catalog size invalid".into());
    }
    let mut platform_ids = BTreeSet::new();
    let mut platform_domains = BTreeSet::new();
    for p in &c.known_platforms {
        if !identifier(&p.id)
            || !platform_ids.insert(&p.id)
            || p.label.is_empty()
            || p.label.len() > 100
            || p.label.chars().any(char::is_control)
            || p.domains.is_empty()
            || p.domains.len() > 8
            || p.paths.len() > 8
            || !p.paths.iter().all(|s| path(s) && !s.is_empty())
        {
            return Err("invalid known platform".into());
        }
        for d in &p.domains {
            if !crate::domain_ok(d) || !platform_domains.insert(d) {
                return Err("invalid known platform domain".into());
            }
        }
    }
    Ok(())
}

pub fn validate(c: &Content) -> Result<()> {
    if c.providers.is_empty()
        || c.providers.len() > 128
        || c.native_tools.len() > 32
        || c.heuristics.keys.len() > 16
        || c.heuristics.mime_types.len() > 8
    {
        return Err("catalog size invalid".into());
    }
    let mut ids = BTreeSet::new();
    let mut domains = BTreeSet::new();
    let mut asset_hosts = BTreeSet::new();
    for p in &c.providers {
        if !identifier(&p.id)
            || RESERVED_PROVIDER_IDS.contains(&p.id.as_str())
            || !ids.insert(&p.id)
            || p.label.is_empty()
            || p.label.len() > 100
            || p.label.chars().any(char::is_control)
            || p.domains.is_empty()
            || p.domains.len() + p.aliases.len() > 32
            || !path(&p.conversation_path)
            || p.conversation_paths.len() > 4
            || !p.conversation_paths.iter().all(|s| path(s) && !s.is_empty())
            || p.conversation_segment > 16
            || p.network.len() > 32
            || p.asset_hosts.len() > 8
        {
            return Err("invalid provider".into());
        }
        for d in p.domains.iter().chain(&p.aliases) {
            if !crate::domain_ok(d) || !domains.insert(d) {
                return Err("invalid catalog domain".into());
            }
        }
        // An asset host is a hostname like the others, named once in the whole catalog.
        // It must not be a covered domain or alias of ANY provider — checked after the
        // loop, once every provider has declared its own — or a page could be allowed
        // to call another provider's site and carry data across.
        for h in &p.asset_hosts {
            if !crate::domain_ok(h) || !asset_hosts.insert(h) {
                return Err("invalid asset host".into());
            }
        }
        for s in [&p.dom.editor, &p.dom.send, &p.dom.response] {
            if s.len() > 512 || s.chars().any(char::is_control) || (!s.is_empty() && s.trim() != s)
            {
                return Err("invalid selector".into());
            }
        }
        for n in &p.network {
            if !matches!(n.method.as_str(), "POST" | "PUT")
                || !crate::domain_ok(&n.host)
                // A network rule may only observe a host the provider itself
                // declared as a domain or alias; it must never reach into another
                // provider's traffic or an undeclared third-party host.
                || !(p.domains.contains(&n.host) || p.aliases.contains(&n.host))
                || !path(&n.path)
                || n.path.is_empty()
                || ![&n.text_path, &n.model_path, &n.effort_path, &n.conversation_path]
                    .into_iter()
                    .chain(n.text_paths.iter())
                    .all(|s| json_path(s))
                // Bounded like every other list in the catalog: a rule naming
                // candidate paths without end would let one request be scanned
                // arbitrarily many times. An empty entry is refused rather than
                // skipped: it would shorten the list without saying so.
                || n.text_paths.len() > 4
                || n.text_paths.iter().any(String::is_empty)
                || n.conversation_url_segment.is_some_and(|s| s > 16)
                || !json_path(&n.files_path)
                || !matches!(n.kind.as_str(), "" | "prompt" | "file")
                || !matches!(n.session.as_str(), "" | "signed_in" | "signed_out")
                // A field name, not a path: unwrapping only ever applies at the root of
                // the body, where a form puts its fields. The reserved names are refused
                // here as the engine refuses them.
                || n.json_fields.len() > 4
                || n.json_fields.iter().any(|f| {
                    f.is_empty()
                        || f.len() > 64
                        || !f.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                        || matches!(f.as_str(), "__proto__" | "constructor" | "prototype")
                })
            {
                return Err("invalid network rule".into());
            }
        }
        DateTime::parse_from_rfc3339(&p.qualified_at)?;
    }
    if asset_hosts.iter().any(|h| domains.contains(h)) {
        return Err("asset host is a covered domain".into());
    }
    validate_native_tools(c)?;
    validate_known_platforms(c)?;
    if !c.heuristics.keys.iter().all(|k| identifier(k))
        || !c
            .heuristics
            .mime_types
            .iter()
            .all(|m| matches!(m.as_str(), "text/event-stream" | "application/json"))
    {
        return Err("invalid heuristics".into());
    }
    Ok(())
}
pub fn verify(
    envelope: &Envelope,
    key: &str,
    minimum: u64,
    held_hash: &str,
    now: DateTime<Utc>,
) -> Result<Catalog> {
    if envelope.payload.len() > 1024 * 1024 {
        return Err("catalog envelope exceeds limit".into());
    }
    let bytes = STANDARD.decode(&envelope.payload)?;
    let key: [u8; 32] = STANDARD
        .decode(key)?
        .try_into()
        .map_err(|_| "invalid catalog key")?;
    VerifyingKey::from_bytes(&key)?.verify_strict(
        &bytes,
        &Signature::from_slice(&STANDARD.decode(&envelope.signature)?)?,
    )?;
    let h: Header = serde_json::from_slice(&bytes)?;
    if h.kind != "detection_catalog"
        || h.schema != 1
        || h.revision == 0
        || h.revision < minimum
        || h.expires_at <= now
        || h.issued_at > now + chrono::Duration::seconds(60)
        || h.expires_at <= h.issued_at
        || h.expires_at - h.issued_at > chrono::Duration::days(7)
    {
        return Err("catalog authority invalid or expired".into());
    }
    let engine = version(ENGINE_VERSION).unwrap();
    if ![&h.min_engine.bridge, &h.min_engine.extension]
        .into_iter()
        .all(|v| version(v).is_some_and(|v| v <= engine))
    {
        return Err("catalog requires newer engine".into());
    }
    let raw = STANDARD.decode(&h.content)?;
    let hash = crate::sha256_hex(&raw);
    if raw.len() > 512 * 1024
        || hash != h.content_hash
        || (h.revision == minimum && !held_hash.is_empty() && hash != held_hash)
    {
        return Err("catalog content changed".into());
    }
    let content: Content = serde_json::from_slice(&raw)?;
    validate(&content)?;
    Ok(Catalog { header: h, content })
}
pub fn cached(state: &State) -> Result<Catalog> {
    crate::shadow::cached(state)?;
    verify(
        state.detection.envelope.as_ref().ok_or("catalog missing")?,
        &state.public_key,
        state.detection.revision,
        &state.detection.content_hash,
        Utc::now(),
    )
}
fn same(a: &State, b: &State) -> bool {
    a.device_id == b.device_id
        && a.credential == b.credential
        && a.public_key == b.public_key
        && a.server_url == b.server_url
}
pub fn refresh_home(home: &Path) -> Result<()> {
    let snapshot = {
        let store = Store::open(home)?;
        let mut s = store.load()?;
        crate::shadow::cached(&s)?;
        if s.detection
            .attempted_at
            .is_some_and(|t| t <= Utc::now() && Utc::now() - t < chrono::Duration::seconds(60))
        {
            return Ok(());
        }
        s.detection.attempted_at = Some(Utc::now());
        store.save(&s)?;
        s
    };
    let response = crate::client()?
        .get(crate::api_url(&snapshot, "/v3/detection-catalog")?)
        .bearer_auth(&snapshot.credential)
        .send()?;
    if matches!(response.status().as_u16(), 401 | 403) {
        let store = Store::open(home)?;
        let mut s = store.load()?;
        if same(&snapshot, &s) {
            crate::shadow::revoke_authorization(&mut s);
            s.detection.envelope = None;
            store.save(&s)?
        }
        return Err("catalog authorization refused".into());
    }
    let mut bytes = Vec::new();
    response
        .error_for_status()?
        .take(1400 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 1400 * 1024 {
        return Err("catalog response exceeds limit".into());
    }
    let envelope: Envelope = serde_json::from_slice(&bytes)?;
    let store = Store::open(home)?;
    let mut s = store.load()?;
    if !same(&snapshot, &s) || snapshot.authorization_generation != s.authorization_generation {
        return Err("catalog installation changed".into());
    }
    let c = verify(
        &envelope,
        &s.public_key,
        s.detection.revision,
        &s.detection.content_hash,
        Utc::now(),
    )?;
    s.detection.revision = c.header.revision;
    s.detection.content_hash = c.header.content_hash;
    s.detection.envelope = Some(envelope);
    store.save(&s)
}
pub fn browser(state: &State) -> Value {
    match cached(state) {
        Ok(c) => {
            json!({"ok":true,"catalog":c.content,"revision":c.header.revision,"expires_at":c.header.expires_at,"catalog_state":"ok","excluded_domains":[crate::trusted_url(&state.server_url).ok().and_then(|u|u.host_str().map(str::to_string))]})
        }
        Err(_) => {
            json!({"ok":true,"catalog":null,"revision":0,"catalog_state":if state.detection.revision>0{"stale"}else{"missing"}})
        }
    }
}

pub(crate) fn validate_health(policy:&crate::shadow::ShadowPolicy,origin:&str,batch:&Value,tool:&str)->Result<()>{
    if !crate::shadow::BROWSER_TOOLS.contains(&tool)
        || batch["tool"] != tool
        || serde_json::to_vec(batch)?.len() > 65536
    {
        return Err("invalid health batch".into());
    }
    let obj = batch.as_object().ok_or("invalid health object")?;
    if obj.keys().any(|k| {
        ![
            "id",
            "tool",
            "extension_version",
            "catalog_revision",
            "catalog_state",
            "window_start",
            "window_end",
            "providers",
            "candidates",
        ]
        .contains(&k.as_str())
    }) {
        return Err("unexpected health field".into());
    }
    uuid::Uuid::parse_str(batch["id"].as_str().ok_or("health id missing")?)?;
    if !token(batch["extension_version"].as_str().unwrap_or(""), 32)
        || batch["catalog_revision"].as_u64().is_none()
        || !matches!(
            batch["catalog_state"].as_str(),
            Some("ok" | "missing" | "stale")
        )
    {
        return Err("invalid health metadata".into());
    }
    let start = DateTime::parse_from_rfc3339(
        batch["window_start"]
            .as_str()
            .ok_or("health start missing")?,
    )?;
    let end =
        DateTime::parse_from_rfc3339(batch["window_end"].as_str().ok_or("health end missing")?)?;
    if start > end
        || end - start > chrono::Duration::days(1)
        || end > Utc::now() + chrono::Duration::minutes(1)
        || start < Utc::now() - chrono::Duration::days(30)
    {
        return Err("invalid health window".into());
    }
    let providers = batch["providers"]
        .as_array()
        .ok_or("health counters missing")?;
    let candidates = batch["candidates"]
        .as_array()
        .ok_or("health candidates missing")?;
    if providers.len() > 128 || candidates.len() > 128 {
        return Err("health cardinality exceeded".into());
    }
    for row in providers {
        let o = row.as_object().ok_or("health counter invalid")?;
        if o.len() != 6
            || !token(row["provider"].as_str().unwrap_or(""), 64)
            || ![
                "navigations",
                "prompts_network",
                "prompts_dom",
                "responses_dom",
                "candidates",
            ]
            .into_iter()
            .all(|k| row[k].as_u64().is_some_and(|v| v <= 1_000_000))
        {
            return Err("health counter invalid".into());
        }
    }
    if !candidates.is_empty() && policy.config["discovery"]["enabled"] != true {
        return Err("discovery disabled".into());
    }
    let server = crate::trusted_url(origin)?;
    for row in candidates {
        let o = row.as_object().ok_or("candidate invalid")?;
        let domain = row["domain"].as_str().unwrap_or("");
        if o.len() != 3
            || !crate::domain_ok(domain)
            || server.host_str() == Some(domain)
            || policy.config["discovery"]["ignored_domains"]
                .as_array()
                .is_some_and(|a| a.iter().any(|d| d == domain))
            || !row["count"]
                .as_u64()
                .is_some_and(|n| n > 0 && n <= 1_000_000)
            || !row["signals"].as_array().is_some_and(|s| {
                !s.is_empty()
                    && s.len() <= 2
                    && s.iter()
                        .all(|v| matches!(v.as_str(), Some("json_keys" | "sse")))
            })
        {
            return Err("candidate invalid".into());
        }
    }
    Ok(())
}
/// Answers whether the batch actually changed, so a conditional save upstream can tell
/// a real edit from a no-op pass over an already-restricted queue.
pub(crate) fn restrict_health(batch:&mut Value,policy:Option<&crate::shadow::ShadowPolicy>)->bool{
    if policy.is_none_or(|p|p.config["discovery"]["enabled"]!=true){
        // Absent counts as a change: the key is about to appear.
        let changed=batch["candidates"].as_array().is_none_or(|rows|!rows.is_empty());
        batch["candidates"]=json!([]);
        return changed;
    }
    if let (Some(rows),Some(policy))=(batch["candidates"].as_array_mut(),policy){
        let before=rows.len();
        rows.retain(|row|!policy.config["discovery"]["ignored_domains"].as_array().is_some_and(|a|a.iter().any(|d|d==&row["domain"])));
        return rows.len()!=before;
    }
    false
}
pub(crate) fn restrict_health_queue(state:&mut State)->bool{
    let policy=crate::shadow::cached(state).ok();
    let mut changed=false;
    for batch in &mut state.detection.health{changed|=restrict_health(batch,policy.as_ref());}
    changed
}
/// Queue one health batch. Answers whether the state actually changed, so a caller
/// can skip re-encrypting the whole store for nothing: the extension re-sends a batch
/// until its id comes back in `accepted_health_ids`, so the duplicate path below is the
/// common one, not the exception.
pub fn enqueue_health(state: &mut State, batch: &Value, tool: &str) -> Result<bool> {
    let policy=crate::shadow::cached(state)?;
    validate_health(&policy,&state.server_url,batch,tool)?;
    if state
        .detection
        .health
        .iter()
        .any(|b| b["id"] == batch["id"])
    {
        return Ok(false);
    }
    if state.detection.health.len() >= 64 {
        return Err("health queue full".into());
    }
    state.detection.health.push(batch.clone());
    Ok(true)
}
pub fn flush_health_home(home: &Path) -> Result<()> {
    let state = {let store=Store::open(home)?;let mut state=store.load()?;
        // Re-encrypting the whole store on every flush tick is only worth it when
        // the narrowing actually removed something.
        if restrict_health_queue(&mut state){store.save(&state)?;}state};
    if state.detection.health.is_empty() {
        return Ok(());
    }
    let batches: Vec<_> = state.detection.health.iter().take(8).collect();
    let response = crate::client()?
        .post(crate::api_url(&state, "/v2/heartbeat")?)
        .bearer_auth(&state.credential)
        .json(&json!({"detector_health":batches}))
        .send()?
        .error_for_status()?;
    let reply: Value = crate::bounded_json(response, 64 * 1024)?;
    let accepted = reply["accepted_health_ids"]
        .as_array()
        .ok_or("health acknowledgement missing")?;
    let store = Store::open(home)?;
    let mut current = store.load()?;
    if !same(&state, &current) {
        return Err("health identity changed".into());
    }
    current
        .detection
        .health
        .retain(|b| !accepted.contains(&b["id"]) || !batches.iter().any(|s| s["id"] == b["id"]));
    store.save(&current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    fn signed(content: Content, revision: u64, now: DateTime<Utc>) -> (Envelope, String, Header) {
        let key = SigningKey::from_bytes(&[67; 32]);
        let raw = serde_json::to_vec(&content).unwrap();
        let h = Header {
            kind: "detection_catalog".into(),
            schema: 1,
            revision,
            issued_at: now,
            expires_at: now + chrono::Duration::hours(1),
            min_engine: Engines {
                extension: "0.5.0".into(),
                bridge: "0.5.0".into(),
            },
            content_hash: crate::sha256_hex(&raw),
            content: STANDARD.encode(raw),
        };
        let bytes = serde_json::to_vec(&h).unwrap();
        (
            Envelope {
                payload: STANDARD.encode(&bytes),
                signature: STANDARD.encode(key.sign(&bytes).to_bytes()),
            },
            STANDARD.encode(key.verifying_key().as_bytes()),
            h,
        )
    }
    fn factory() -> Content {
        serde_json::from_str(include_str!("../extension/detection-factory.json")).unwrap()
    }
    #[test]
    fn real_signed_factory_and_authority_failures() {
        let now = Utc::now();
        let (env, key, h) = signed(factory(), 3, now);
        let c = verify(&env, &key, 3, &h.content_hash, now).unwrap();
        assert_eq!(c.content.providers.len(), 9);
        assert!(verify(&env, &key, 4, "", now).is_err());
        assert!(verify(&env, &key, 3, "wrong", now).is_err());
        assert!(
            verify(
                &env,
                &key,
                3,
                &h.content_hash,
                now + chrono::Duration::hours(2)
            )
            .is_err()
        );
        let mut changed = env.clone();
        changed.signature = STANDARD.encode([0; 64]);
        assert!(verify(&changed, &key, 0, "", now).is_err());
        assert!(verify(&env, &STANDARD.encode([1; 32]), 0, "", now).is_err());
    }
    #[test]
    fn same_revision_may_renew_expiry_but_never_change_content() {
        let now = Utc::now();
        let (_, _, old) = signed(factory(), 2, now - chrono::Duration::minutes(5));
        let (env, key, _) = signed(factory(), 2, now);
        assert!(verify(&env, &key, 2, &old.content_hash, now).is_ok());
        let mut modified = factory();
        modified.providers[0].dom.editor = "textarea".into();
        let (env, key, _) = signed(modified, 2, now);
        assert!(verify(&env, &key, 2, &old.content_hash, now).is_err());
    }
    #[test]
    fn declarative_validation_refuses_executable_or_unbounded_shapes() {
        let mut c = factory();
        c.providers[0].network.push(Network {
            method: "POST".into(),
            // Must be one of providers[0] (chatgpt)'s own declared domains/aliases:
            // validate() now requires a network rule's host to belong to its provider.
            host: "chatgpt.com".into(),
            path: "/(a+)+".into(),
            text_path: "input".into(),
            text_paths: vec![],
            model_path: "".into(),
            effort_path: "".into(),
            conversation_path: "".into(),
            conversation_url_segment: None,
            json_fields: vec![],
            files_path: "".into(),
            kind: "".into(),
            session: "".into(),
        });
        // providers[0] now carries its own measured network rule: targeting index 0
        // would mutate THAT ONE instead of the rule added here, and the test would
        // validate something other than what it announces. Target explicitly the one
        // just added.
        let ajoutee = c.providers[0].network.len() - 1;
        assert!(validate(&c).is_err());
        c.providers[0].network[ajoutee].path = "/complete".into();
        c.providers[0].network[ajoutee].text_path = "__proto__.secret".into();
        assert!(validate(&c).is_err());
        c.providers[0].network[ajoutee].text_path = "messages[*].content".into();
        assert!(validate(&c).is_ok());
        // The effort path is validated like any other: a catalog cannot smuggle an
        // executable or prototype-reaching shape through the new field.
        c.providers[0].network[ajoutee].effort_path = "__proto__.secret".into();
        assert!(validate(&c).is_err());
        c.providers[0].network[ajoutee].effort_path = "thinking_effort".into();
        assert!(validate(&c).is_ok());
        // Candidate text paths are validated one by one and bounded, like every other
        // list a published catalog can carry.
        c.providers[0].network[ajoutee].text_paths = vec!["messageInput[*].text".into(), "content[*].text".into()];
        assert!(validate(&c).is_ok());
        c.providers[0].network[ajoutee].text_paths.push("__proto__.secret".into());
        assert!(validate(&c).is_err());
        c.providers[0].network[ajoutee].text_paths = vec!["a".into(), "b".into(), "c".into(), "d".into(), "e".into()];
        assert!(validate(&c).is_err());
        // An empty entry is refused rather than skipped: it would shorten the list
        // without saying so, and the server refuses it at publication too.
        c.providers[0].network[ajoutee].text_paths = vec!["content[*].text".into(), "".into()];
        assert!(validate(&c).is_err());
        c.providers[0].network[ajoutee].text_paths = vec![];
        // The file-name path is a path like the others, and the fields to unwrap are
        // names, bounded and held away from the prototype. Both reach devices only
        // because they are omitted when empty: a rule that carried them to an agent
        // that predates them would be refused whole.
        c.providers[0].network[ajoutee].files_path = "imageAttachments[*].name".into();
        c.providers[0].network[ajoutee].json_fields = vec!["imageAttachments".into(), "conversationState".into()];
        assert!(validate(&c).is_ok());
        c.providers[0].network[ajoutee].files_path = "__proto__.name".into();
        assert!(validate(&c).is_err());
        c.providers[0].network[ajoutee].files_path = "imageAttachments[*].name".into();
        c.providers[0].network[ajoutee].json_fields = vec!["__proto__".into()];
        assert!(validate(&c).is_err());
        c.providers[0].network[ajoutee].json_fields = vec!["image attachments".into()];
        assert!(validate(&c).is_err());
        c.providers[0].network[ajoutee].json_fields = (0..5).map(|i| format!("field{i}")).collect();
        assert!(validate(&c).is_err());
        c.providers[0].network[ajoutee].json_fields = vec![];
        c.providers[0].network[ajoutee].files_path = "".into();
        // A route says what it carries, or says nothing and carries a prompt. Anything
        // else is refused rather than read as one of the two.
        c.providers[0].network[ajoutee].kind = "file".into();
        assert!(validate(&c).is_ok());
        c.providers[0].network[ajoutee].kind = "upload".into();
        assert!(validate(&c).is_err());
        c.providers[0].network[ajoutee].kind = "".into();
        // The account state a route implies is a closed vocabulary, never a free label.
        c.providers[0].network[ajoutee].session = "signed_out".into();
        assert!(validate(&c).is_ok());
        c.providers[0].network[ajoutee].session = "anonymous".into();
        assert!(validate(&c).is_err());
        c.providers[0].network[ajoutee].session = "".into();
        // Further conversation paths are page paths like the first, bounded and never empty.
        c.providers[0].conversation_paths = vec!["/uc/*".into()];
        assert!(validate(&c).is_ok());
        c.providers[0].conversation_paths = vec!["".into()];
        assert!(validate(&c).is_err());
        c.providers[0].conversation_paths = vec!["uc/(a+)+".into()];
        assert!(validate(&c).is_err());
        c.providers[0].conversation_paths = (0..5).map(|i| format!("/p{i}/*")).collect();
        assert!(validate(&c).is_err());
        c.providers[0].conversation_paths = vec![];
        // A positional path is accepted: a provider answering with nested arrays is
        // addressed by index, `0.0.0` reaching the first element of the first element
        // of the first. What the grammar refuses is the bracket syntax `[0]`, not
        // positional access, and `valuesAt` walks it because an array owns "0".
        c.providers[0].network[ajoutee].text_paths = vec!["0.0.0".into()];
        assert!(validate(&c).is_ok());
        c.providers[0].network[ajoutee].text_paths = vec!["0[0]".into()];
        assert!(validate(&c).is_err());
        c.providers[0].network[ajoutee].text_paths = vec![];
        // The URL segment is bounded like every index a published catalog can carry: a
        // rule cannot ask the agent to walk an unbounded path to find an identifier.
        c.providers[0].network[ajoutee].conversation_url_segment = Some(4);
        assert!(validate(&c).is_ok());
        c.providers[0].network[ajoutee].conversation_url_segment = Some(17);
        assert!(validate(&c).is_err());
        c.providers[0].network[ajoutee].conversation_url_segment = None;
        let duplicate = c.providers[1].domains[0].clone();
        c.providers[0].aliases.push(duplicate);
        assert!(validate(&c).is_err());
        c.providers[0].aliases.pop();
        // An asset host is a hostname the page may load, bounded and named once. It is
        // never a covered domain of any provider: that would let one covered page call
        // another provider's site and carry data across. Checked after every provider has
        // declared its domains, so the order of entries cannot hide the collision.
        c.providers[0].asset_hosts = vec!["cdn.example.test".into()];
        assert!(validate(&c).is_ok());
        c.providers[0].asset_hosts = vec![c.providers[1].domains[0].clone()];
        assert!(validate(&c).is_err());
        c.providers[0].asset_hosts = vec!["not a host".into()];
        assert!(validate(&c).is_err());
        c.providers[0].asset_hosts = vec!["cdn.example.test".into(), "cdn.example.test".into()];
        assert!(validate(&c).is_err());
        c.providers[0].asset_hosts = (0..9).map(|i| format!("cdn{i}.example.test")).collect();
        assert!(validate(&c).is_err());
        c.providers[0].asset_hosts = vec![];
        assert!(validate(&c).is_ok());
    }
    #[test]
    fn asset_hosts_are_omitted_when_empty_and_accepted_when_named() {
        // Today's catalogs carry no `asset_hosts`: they must keep their bytes, and a
        // catalog that names one must be read rather than refused as unknown.
        let c = factory();
        let raw = serde_json::to_string(&c).unwrap();
        assert!(!raw.contains("asset_hosts"));
        let mut v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        v["providers"][0]["asset_hosts"] = json!(["cdn.example.test"]);
        let named: Content = serde_json::from_value(v).unwrap();
        assert_eq!(named.providers[0].asset_hosts, vec!["cdn.example.test".to_string()]);
        assert!(validate(&named).is_ok());
    }
    #[test]
    fn expired_cache_preserves_revision_floor() {
        let now = Utc::now() - chrono::Duration::hours(2);
        let (env, key, h) = signed(factory(), 42, now);
        let signing = SigningKey::from_bytes(&[67; 32]);
        let p = json!({"version":3,"revision":1,"issued_at":Utc::now(),"expires_at":Utc::now()+chrono::Duration::minutes(5),"config":{"collection":{"enabled":true},"services":[]}});
        let raw = serde_json::to_vec(&p).unwrap();
        let state = State {
            shadow_policy: Some(Envelope {
                payload: STANDARD.encode(&raw),
                signature: STANDARD.encode(signing.sign(&raw).to_bytes()),
            }),
            shadow_revision: 1,
            public_key: key,
            detection: Cache {
                revision: 42,
                content_hash: h.content_hash,
                envelope: Some(env),
                ..Cache::default()
            },
            ..State::default()
        };
        assert!(crate::shadow::cached(&state).is_ok());
        assert!(
            cached(&state)
                .err()
                .unwrap()
                .to_string()
                .contains("expired")
        );
        let out = browser(&state);
        assert_eq!(out["catalog_state"], "stale");
        assert!(out["catalog"].is_null());
        assert_eq!(state.detection.revision, 42);
    }

    #[test]
    fn health_is_bounded_consent_gated_and_durable_before_ack() {
        let signing = SigningKey::from_bytes(&[67; 32]);
        let now = Utc::now();
        let policy = json!({"version":3,"revision":1,"issued_at":now,"expires_at":now+chrono::Duration::minutes(5),"config":{"collection":{"enabled":true},"services":[],"discovery":{"enabled":false,"ignored_domains":[]}}});
        let raw = serde_json::to_vec(&policy).unwrap();
        let mut state = State {
            server_url: "https://server.test".into(),
            public_key: STANDARD.encode(signing.verifying_key().as_bytes()),
            shadow_policy: Some(Envelope {
                payload: STANDARD.encode(&raw),
                signature: STANDARD.encode(signing.sign(&raw).to_bytes()),
            }),
            shadow_revision: 1,
            ..State::default()
        };
        let batch = json!({"id":uuid::Uuid::new_v4(),"tool":"chrome","extension_version":"0.5.0","catalog_revision":0,"catalog_state":"missing","window_start":now,"window_end":now,"providers":[{"provider":"fixture","navigations":2,"prompts_network":1,"prompts_dom":0,"responses_dom":0,"candidates":0}],"candidates":[]});
        // The answer is the contract native.rs saves on: true queued something, false
        // did not. The extension re-sends a batch until its id comes back acknowledged,
        // so the duplicate below is the ordinary case, not the exception.
        assert!(
            enqueue_health(&mut state, &batch, "chrome").unwrap(),
            "a new batch must report that it queued"
        );
        assert!(
            !enqueue_health(&mut state, &batch, "chrome").unwrap(),
            "a duplicate batch must report that it changed nothing"
        );
        assert_eq!(state.detection.health.len(), 1);
        let mut forbidden = batch.clone();
        forbidden["id"] = json!(uuid::Uuid::new_v4());
        forbidden["candidates"] = json!([{"domain":"candidate.test","signals":["sse"],"count":1}]);
        assert!(enqueue_health(&mut state, &forbidden, "chrome").is_err());
        let directory = tempfile::tempdir().unwrap();
        {
            let store = Store::open(directory.path()).unwrap();
            store.save(&state).unwrap();
        }
        let restored = Store::open(directory.path()).unwrap().load().unwrap();
        assert_eq!(restored.detection.health.len(), 1);
        assert_eq!(restored.detection.health[0]["id"], batch["id"]);
        let bytes = std::fs::read(directory.path().join("state.bin")).unwrap();
        assert!(!bytes.windows(b"fixture".len()).any(|w| w == b"fixture"));
        // What makes the conditional save observable: save draws a fresh nonce every
        // time, so a real write always changes the ciphertext even when the plaintext is
        // identical. Byte-equal files therefore mean no save happened -- and this is the
        // negative control, proving the comparison can tell the two apart at all.
        {
            let store = Store::open(directory.path()).unwrap();
            store.save(&state).unwrap();
        }
        let rewritten = std::fs::read(directory.path().join("state.bin")).unwrap();
        assert_ne!(
            bytes, rewritten,
            "a real save must rewrite the sealed state, or skipping one could not be detected"
        );
    }
}

fn delivery_key(state: &State, request: &Value, event: &Value) -> Result<Option<(String, String)>> {
    let Some(token) = request.get("delivery_id") else {
        return Ok(None);
    };
    uuid::Uuid::parse_str(token.as_str().ok_or("invalid delivery identity")?)?;
    let key = json!([
        state.device_id,
        state.server_url,
        state.public_key,
        request["tool"],
        request["caller"]["user"],
        token
    ]);
    Ok(Some((
        crate::sha256_hex(serde_json::to_vec(&key)?),
        crate::sha256_hex(serde_json::to_vec(event)?),
    )))
}
pub fn delivery_receipt(
    state: &State,
    request: &Value,
    event: &Value,
) -> Result<Option<uuid::Uuid>> {
    let Some((key, hash)) = delivery_key(state, request, event)? else {
        return Ok(None);
    };
    let Some(row) = state.detection.event_receipts.iter().find(|r| r[0] == key) else {
        return Ok(None);
    };
    if row[1] != hash {
        return Err("delivery identity reused for different event".into());
    }
    Ok(Some(uuid::Uuid::parse_str(
        row[2].as_str().ok_or("invalid delivery receipt")?,
    )?))
}
/// The event identity a delivery was given, for a completion that names a send
/// already made durable. Deliberately blind to the payload fingerprint: a completion
/// carries no event to compare, and the refusal `delivery_receipt` raises when a
/// delivery identity is reused for *different* content must stay exactly as it is for
/// `event_v2`. The delivery key binds the installation and the calling account, so an
/// identity belonging to another account simply resolves to nothing.
pub fn completed_delivery(state: &State, request: &Value) -> Result<Option<uuid::Uuid>> {
    let Some((key, _)) = delivery_key(state, request, &json!({}))? else {
        return Ok(None);
    };
    let Some(row) = state.detection.event_receipts.iter().find(|r| r[0] == key) else {
        return Ok(None);
    };
    Ok(Some(uuid::Uuid::parse_str(
        row[2].as_str().ok_or("invalid delivery receipt")?,
    )?))
}
pub fn remember_delivery(
    state: &mut State,
    request: &Value,
    event: &Value,
    id: uuid::Uuid,
) -> Result<()> {
    if let Some((key, hash)) = delivery_key(state, request, event)? {
        state.detection.event_receipts.push(json!([key, hash, id]));
        let excess = state.detection.event_receipts.len().saturating_sub(4096);
        state.detection.event_receipts.drain(..excess);
    }
    Ok(())
}

#[cfg(test)]
mod delivery_tests {
    use super::*;
    #[test]
    fn receipts_bind_payload_and_installation_without_requeueing() {
        let mut state = State {
            device_id: uuid::Uuid::new_v4().to_string(),
            server_url: "https://instance.test".into(),
            public_key: "fixture-anchor".into(),
            ..State::default()
        };
        let request = json!({"delivery_id":uuid::Uuid::new_v4(),"tool":"chrome","caller":{"user":"synthetic-account"}});
        let event = json!({"provider":"fixture.test","characters":12});
        let id = uuid::Uuid::new_v4();
        remember_delivery(&mut state, &request, &event, id).unwrap();
        assert_eq!(
            delivery_receipt(&state, &request, &event).unwrap(),
            Some(id)
        );
        assert!(
            delivery_receipt(
                &state,
                &request,
                &json!({"provider":"other.test","characters":12})
            )
            .is_err()
        );
        let mut other = request.clone();
        other["caller"]["user"] = json!("other-account");
        assert!(delivery_receipt(&state, &other, &event).unwrap().is_none());
        state.server_url = "https://other-instance.test".into();
        assert!(
            delivery_receipt(&state, &request, &event)
                .unwrap()
                .is_none()
        );
    }
}

// Replays the shared detection-catalogue corpus (endpoint/extension/fixtures/catalog,
// one JSON document per file) that the Go server validator, this Rust engine
// validator and the JS extension validator must all judge identically for
// publishability ("server") and applicability ("engine"). Content-only: this
// exercises validate(), never verify()/the signature check. A fixture's optional
// top-level min_engine sibling (outside "content", which carries no such field in
// any of the three schemas) additionally gates the same version floor verify()
// enforces, so the two min_engine corpus cases are covered here too.
#[cfg(test)]
mod corpus_tests {
    use super::*;
    use std::fs;

    #[derive(Deserialize)]
    struct Fixture {
        case: String,
        reason: String,
        server: String,
        engine: String,
        content: Value,
        #[serde(default)]
        min_engine: Option<Engines>,
    }

    fn engine_version_ok(min: &Engines) -> bool {
        let engine = version(ENGINE_VERSION).unwrap();
        [&min.bridge, &min.extension]
            .into_iter()
            .all(|v| version(v).is_some_and(|v| v <= engine))
    }

    #[test]
    fn corpus_matches_engine_verdict() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/extension/fixtures/catalog");
        let entries = fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("cannot read corpus directory {dir}: {e}"));
        let mut seen = 0u32;
        for entry in entries {
            let path = entry.expect("unreadable corpus directory entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            seen += 1;
            let raw = fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
            let fixture: Fixture = serde_json::from_str(&raw)
                .unwrap_or_else(|e| panic!("cannot parse {}: {e}", path.display()));
            assert!(
                matches!(fixture.engine.as_str(), "accept" | "reject"),
                "{}: fixture missing an engine verdict",
                path.display()
            );
            // Both verdicts are read, not only the one this validator can settle. The
            // engine judges applicability and has nothing to say about publishability,
            // which belongs to the server validator -- but a fixture whose `server`
            // verdict is misspelt would otherwise deserialize, sit in the shared corpus
            // and be judged by nobody. Checking the vocabulary is what makes the field
            // load-bearing here rather than decorative.
            for (name, verdict) in [("server", &fixture.server), ("engine", &fixture.engine)] {
                assert!(
                    verdict == "accept" || verdict == "reject",
                    "{}: case {:?}: {name} verdict {verdict:?} is neither accept nor reject",
                    path.display(),
                    fixture.case
                );
            }
            let content: std::result::Result<Content, _> = serde_json::from_value(fixture.content);
            let accepted = content.as_ref().is_ok_and(|c| validate(c).is_ok())
                && fixture.min_engine.as_ref().map_or(true, engine_version_ok);
            let want = fixture.engine == "accept";
            assert_eq!(
                accepted,
                want,
                "{}: case {:?} ({}): engine verdict = {}, want {}",
                path.display(),
                fixture.case,
                fixture.reason,
                if accepted { "accept" } else { "reject" },
                fixture.engine
            );
        }
        assert!(
            seen > 0,
            "no corpus fixtures found in {dir}: an empty corpus must not read as a pass"
        );
    }
}
