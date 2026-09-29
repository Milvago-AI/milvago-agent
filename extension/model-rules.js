// Community substitute for model-rules.js: this edition has no per-model control,
// so the package carries no model decision at all. It does report which model
// answered — that is inventory, see modelObservation below. Everything else — service
// block/redirect, content control, upload restriction — is unchanged, because it
// lives in model-access.js and is shared by both editions.
//
// These four exports are required when this module replaces model-rules.js in the
// Community package.

/**
 * A Community policy never carries model rules: the server strips model_access from
 * the signed policy. A policy that claims restrictions this build cannot enforce is
 * therefore rejected rather than silently ignored, and the extension fails closed.
 */
export function modelRulesValid(policy){
 const rules=policy.config?.model_access;
 return rules===undefined||(Array.isArray(rules)&&rules.length===0);
}
/** No rule is ever active, so no request is ever gated on a model. */
export function ruleFor(){return undefined;}
export function modelDecision(){return null;}
export function requestModel(){return null;}
/**
 * Observing which model answered is inventory, not control: the name is read from a
 * request this build already watches, and nothing is ever gated on it. Community
 * reports it so an administrator can see what is actually used - the decision code
 * above stays absent from this package.
 */
export const modelObservation=true;
/** Blocking a known platform is Enterprise: this build never installs such a rule. */
export function blockedPlatform(){return false;}
export function platformBlockRules(){return [];}
export function keptWhenSealed(){return false;}
export function blockedTab(){return false;}