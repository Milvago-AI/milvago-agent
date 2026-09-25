//! Exact model policy, independent of collection and content storage.
use crate::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ModelRule {
    pub platform_id: String,
    pub channel: String,
    pub mode: String,
    pub models: Vec<String>,
}
pub fn valid_model(id: &str) -> bool {
    !id.is_empty() && id.len() <= 200 && id.as_bytes()[0].is_ascii_alphanumeric()
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b"._:/+-".contains(&b))
}
// Community covers ChatGPT and Claude, Enterprise all nine: the other seven are removed
// from the build rather than refused at runtime, so the Community binary does not carry
// the names of sites it does not observe (product decision of 2026-09-15).
pub fn browser_platform(domain: &str) -> Option<&'static str> {
    match domain {
        "chatgpt.com" | "chat.openai.com" | "api.openai.com" => Some("chatgpt"),
        "claude.ai" | "api.anthropic.com" => Some("claude"),
        #[cfg(feature = "enterprise-extension")]
        "chat.mistral.ai" => Some("lechat"),
        #[cfg(feature = "enterprise-extension")]
        "copilot.microsoft.com" | "copilot.cloud.microsoft" => Some("copilot"),
        #[cfg(feature = "enterprise-extension")]
        "gemini.google.com" => Some("gemini"),
        #[cfg(feature = "enterprise-extension")]
        "notebooklm.google.com" | "notebook.google.com" => Some("notebooklm"),
        #[cfg(feature = "enterprise-extension")]
        "chat.deepseek.com" => Some("deepseek"),
        #[cfg(feature = "enterprise-extension")]
        "perplexity.ai" | "www.perplexity.ai" => Some("perplexity"),
        #[cfg(feature = "enterprise-extension")]
        "grok.com" => Some("grok"), _ => None,
    }
}
pub fn valid_platform(platform: &str, channel: &str) -> bool {
    match channel {
        "browser" => match platform {
            "chatgpt" | "claude" => true,
            #[cfg(feature = "enterprise-extension")]
            "lechat" | "copilot" | "gemini" | "notebooklm" | "deepseek" | "perplexity" | "grok" => true,
            _ => false,
        },
        "native" => matches!(platform, "codex"|"claude-code"|"claude-desktop"|"claude-desktop-agent"), _ => false,
    }
}
pub fn rules(config: &Value) -> Result<Vec<ModelRule>> {
    let Some(raw) = config.get("model_access") else { return Ok(vec![]); };
    let rules: Vec<ModelRule> = serde_json::from_value(raw.clone())?;
    if rules.len() > 160 { return Err("too many model rules".into()); }
    let mut seen = BTreeSet::new();
    for rule in &rules {
        if !(valid_platform(&rule.platform_id, &rule.channel)
            || (rule.channel == "browser" && !rule.platform_id.is_empty() && rule.platform_id.len()<=64
                && rule.platform_id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))))
            || !seen.insert((&rule.platform_id, &rule.channel))
            || !matches!(rule.mode.as_str(), "off"|"allowlist"|"denylist")
            || rule.models.len() > 100 || rule.models.iter().any(|id| !valid_model(id))
            || rule.models.iter().collect::<BTreeSet<_>>().len() != rule.models.len()
        { return Err("invalid model rule".into()); }
    }
    Ok(rules)
}
// Per-model control is an Enterprise capability. The decision itself is compiled
// only for the binaries that may enforce it (the Enterprise bridge and filter), from a
// file of its own; the Community agent keeps the validation helpers above, which the
// signed-policy check needs, but carries no model decision at all.
#[cfg(feature = "model-control")]
#[path = "model_access_enterprise.rs"]
mod enterprise;
#[cfg(feature = "model-control")]
pub use enterprise::{Decision, decide};
#[cfg(feature = "model-control")]
pub(crate) use enterprise::decide_authorized;

#[cfg(test)]
mod trusted_provider_tests {
    use super::*;
    #[test]
    fn notebook_alias_maps_to_the_trusted_platform() {
        // An alias's fallback stays exact: it is the whole domain that decides, never a
        // suffix. The alias itself only exists in the edition that covers the site.
        let expected = if cfg!(feature = "enterprise-extension") { Some("notebooklm") } else { None };
        assert_eq!(browser_platform("notebook.google.com"), expected);
        assert_eq!(browser_platform("notebook.google.com.attacker.test"), None);
    }
    #[test]
    fn this_edition_knows_only_the_platforms_it_covers() {
        for platform in ["chatgpt", "claude"] {
            assert!(valid_platform(platform, "browser"), "{platform} must be covered");
        }
        for domain in ["chat.mistral.ai", "gemini.google.com", "www.perplexity.ai", "grok.com"] {
            assert_eq!(browser_platform(domain).is_some(), cfg!(feature = "enterprise-extension"), "{domain}");
        }
        assert_eq!(valid_platform("grok", "browser"), cfg!(feature = "enterprise-extension"));
    }
}
