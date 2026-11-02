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
// Community covers ChatGPT and Claude only: the Community source and binary carry no other
// site name (product decisions of 2026-09-15 and 2026-10-15).
pub fn browser_platform(domain: &str) -> Option<&'static str> {
    match domain {
        "chatgpt.com" | "chat.openai.com" | "api.openai.com" => Some("chatgpt"),
        "claude.ai" | "api.anthropic.com" => Some("claude"),
        _ => None,
    }
}
pub fn valid_platform(platform: &str, channel: &str) -> bool {
    match channel {
        "browser" => match platform {
            "chatgpt" | "claude" => true,
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
    fn a_domain_maps_exactly_never_by_suffix() {
        assert_eq!(browser_platform("chat.openai.com"), Some("chatgpt"));
        assert_eq!(browser_platform("chat.openai.com.attacker.test"), None);
    }
    #[test]
    fn this_edition_knows_only_the_platforms_it_covers() {
        for platform in ["chatgpt", "claude"] {
            assert!(valid_platform(platform, "browser"), "{platform} must be covered");
        }
        // Any other assistant is reached and reported by presence, never mapped to a
        // platform whose prompts, responses or model this edition would take.
        for domain in ["gemini.google.com", "www.perplexity.ai", "notebook.google.com"] {
            assert_eq!(browser_platform(domain), None, "{domain}");
        }
        assert!(!valid_platform("gemini", "browser"));
    }
}
