// Community substitute for model-rules.js: this edition has no per-model control,
// so the package carries no model decision at all. It does report which model
// answered — that is inventory, see modelObservation below. Everything else — service
// block/redirect, content control, upload restriction — is unchanged, because it
// lives in model-access.js and is shared by both editions.
//
// The exports below are a CONTRACT, not this file's own call graph: build-editions.js
// copies this file over model-rules.js in the Community package, and model-access.js
// imports modelDecision, modelRulesValid, requestBodyJSON, requestModel and ruleFor
// from that name. An export unused *here* may still be required *there* -- removing
// requestBodyJSON on 2026-09-21 because nothing in this file called it broke module
// linking in the assembled Community package. Keep the five in step with
// model-rules.js.
import { strictJSON } from './model-access.js';

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
export function requestBodyJSON(details){ try{
  let length=0;for(const part of details.requestBody.raw){if(!part.bytes||part.file){return null;}length+=part.bytes.byteLength;if(length>131072){return null;}}
  const bytes=new Uint8Array(length);let offset=0;for(const part of details.requestBody.raw){bytes.set(new Uint8Array(part.bytes),offset);offset+=part.bytes.byteLength;}
  return strictJSON(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
 }catch{return null;}
}

/**
 * Observing which model answered is inventory, not control: the name is read from a
 * request this build already watches, and nothing is ever gated on it. Community
 * reports it so an administrator can see what is actually used - the decision code
 * above stays absent from this package.
 */
export const modelObservation=true;