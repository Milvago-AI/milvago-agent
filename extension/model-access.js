import './adapters.js';
// The per-model decision lives in model-rules.js so the Community package can swap
// it for a stub. Everything below is shared by both editions and must stay here.
import { modelDecision, modelRulesValid, requestModel, ruleFor } from './model-rules.js';
export { modelDecision, modelRulesValid, requestModel, ruleFor };
export const apiHosts={'api.openai.com':'chatgpt','api.anthropic.com':'claude'};
// The hostname without its trailing dot: `api.anthropic.com.` reaches the same server, and an
// exact comparison let it slip past every guard.
export function hostOf(u){return u.hostname.replace(/\.+$/,'');}
// Reject duplicate keys including escaped spellings, at every depth, before JSON.parse.
// Default `limit` unchanged. Only the asynchronous observation in `detection.js` raises it,
// for a decompressed body whose size no longer matches the one on the wire. The Enterprise
// control in `model-rules.js` decides, for its part, inside a BLOCKING webRequest handler:
// it must stay synchronous and tight, and never calls with another value.
export function strictJSON(text,limit=131072){
 if(text.length>limit){throw Error('body too large');}let at=0,depth=0;
 function ws(){while(/[ \t\r\n]/.test(text[at]||'\0')){at++;}}
 function string(){const start=at++;while(at<text.length){const c=text[at++];if(c==='"'){return JSON.parse(text.slice(start,at));}if(c==='\\'){at++;}}throw Error('string');}
 function value(){ws();if(++depth>40){throw Error('depth');}const c=text[at];
  if(c==='{'){at++;ws();const keys=new Set();if(text[at]!=='}'){for(;;){ws();if(text[at]!=='"'){throw Error('key');}const key=string();if(keys.has(key)){throw Error('duplicate');}keys.add(key);ws();if(text[at++]!==':'){throw Error('colon');}value();ws();if(text[at]!==','){break;}at++;}}if(text[at++]!=='}'){throw Error('object');}}
  else if(c==='['){at++;ws();if(text[at]!==']'){for(;;){value();ws();if(text[at]!==','){break;}at++;}}if(text[at++]!==']'){throw Error('array');}}
  else if(c==='"'){string();}else {const start=at;while(at<text.length&&!/[,\]}\s]/.test(text[at])){at++;}if(start===at){throw Error('value');}}
  depth--;
 }
 value();ws();if(at!==text.length){throw Error('trailing');}return JSON.parse(text);
}
export function requestBodyJSON(details){ try{
  let length=0;for(const part of details.requestBody.raw){if(!part.bytes||part.file){return null;}length+=part.bytes.byteLength;if(length>131072){return null;}}
  const bytes=new Uint8Array(length);let offset=0;for(const part of details.requestBody.raw){bytes.set(new Uint8Array(part.bytes),offset);offset+=part.bytes.byteLength;}
  return strictJSON(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
 }catch{return null;}
}
function urlOf(value){try{const u=new URL(value);return ['https:','wss:'].includes(u.protocol)&&!u.username&&!u.password&&!u.port?u:null;}catch{return null;}}
export function networkPlatform(value){let u;try{u=new URL(value);if(!['https:','http:','wss:','ws:'].includes(u.protocol)){return null;}}catch{return null;}if(apiHosts[hostOf(u)]){return globalThis.MilvagoAdapters.adapters.find(a=>a.id===apiHosts[hostOf(u)]);}u.protocol='https:';u.username='';u.password='';u.port='';return globalThis.MilvagoAdapters.resolve(u.href);}
export function contentControl(policy){const protection=policy?.config?.protection;return !!(policy?.config?.privacy?.enabled||protection?.block_uploads||(protection?.keywords?.length&&['exact','unicode','fuzzy'].some(k=>protection[k]==='block')));}
// The "direct API" (`api.openai.com`, `api.anthropic.com`) has no composer to inspect.
// Under masking it stays sealed except for a bodyless read; under file-upload blocking
// alone, only a `file` route from the catalog seals (product decision of 2026-09-16), and
// API hosts carry none. The "full text body" qualification that allowed an API request
// under file-upload blocking therefore disappeared along with the rule it served.
// What a request can carry, under content control. Masking used to seal ALL of the
// provider's traffic, document included: the site would no longer open, no content
// script was there to explain it, and the request rewritten by inspection was cancelled
// like the others — masking therefore never actually masked. Measured on 2026-09-15.
//
// The guard is not lifted, it is moved to where the data actually flows:
//  - a `GET` with no parameters, to the root or from the provider itself, passes,
//    with `Referer` stripped by `background.js` (a path or query carrying data is
//    still refused: `/CONFIDENTIAL`, `?text=…`);
//  - anything carrying a prompt — a catalog route, or a body shaped like a prompt —
//    only goes out if its text is exactly what the agent just approved;
//  - a body this synchronous path cannot read only goes out within its tab's
//    approval window;
//  - the rest of the provider's traffic passes.
// Risk accepted and recorded: a prompt-carrying route unknown to the catalog whose
// body does not look like a prompt would get through.
function promptShaped(body,keys){
 if(!body||Array.isArray(body)||typeof body!=='object'){return false;}
 const names=keys?.length?keys:['messages','prompt','model','input'];
 return names.filter(k=>Object.hasOwn(body,k)).length>=2;
}
function masks(policy){
 const protection=policy?.config?.protection,privacy=policy?.config?.privacy;
 return !!privacy?.enabled||!!(protection?.keywords?.length&&['exact','unicode','fuzzy'].some(k=>protection[k]==='block'));
}
// The provider "at home": its domain or an alias — what `networkPlatform` already
// recognizes —, one of its SUBDOMAINS, or an asset host the catalog names for it.
// Measured on 2026-09-16: `resolve()`'s comparison is on the EXACT hostname, so
// `www.claude.ai`, `cdn.claude.ai` and a provider's CDN were treated as
// exfiltration targets and sealed — the page could not render fully. A
// subdomain shares the registrable domain and the operator; a named host was measured
// on the site. Any OTHER host remains third-party: that is where data would leave, and
// that door does not open. The same URL checks as `urlOf` apply, so that
// a subdomain on a port or carrying credentials does not pass.
// `networkPlatform` answers "which provider IS this host"; this one answers "which
// provider does this host BELONG TO". The two questions are distinct, and conflating them
// cost twice: a page cannot render if something it needs belongs to it without
// carrying its name. Exported because `background.js`'s startup guard must ask the
// same question — forgetting it there used to cancel the provider's assets during the
// whole worker wake-up window, i.e. on every page load (measured on 2026-09-16).
export function ownedPlatform(value){
 const direct=networkPlatform(value);
 if(direct){return direct;}
 let u;try{u=new URL(value);}catch{return null;}
 if(!['https:','wss:'].includes(u.protocol)||u.username||u.password||u.port){return null;}
 const host=hostOf(u);
 return globalThis.MilvagoAdapters.adapters.find(a=>host.endsWith('.'+a.domain)||(a.assets||[]).includes(host))||null;
}
function providerOwned(value,adapter){return ownedPlatform(value)?.id===adapter.id;}
function contentDecision(details,policy,wire,approval,adapter,u,target){
 const protection=policy.config?.protection,masking=masks(policy);
 // `HEAD` and `OPTIONS` follow the `GET` rule because they carry NO payload:
 // a CORS preflight is a metadata request, and sealing it protected nothing
 // while killing the real request that follows it — the browser does not even emit
 // one. This is why the page used to load only halfway, with nothing explaining the
 // refusal (measured on 2026-09-16; a sealed `OPTIONS` request was observed on chatgpt.com).
 // `POST`, `PUT`, `PATCH` and `DELETE` stay outside this branch: they can carry
 // a body, and therefore go through the inspection below.
 if(['GET','HEAD','OPTIONS'].includes(details.method)&&!details.requestBody){
  // A `GET` whose DESTINATION is the covered provider passes, regardless of its
  // path and query, with `Referer` stripped. The previous rule only allowed a
  // navigation to the exact root: it sealed `/login`, `/chat/<id>` and
  // authentication redirects, so the site could no longer be opened at all under
  // content control (measured on 2026-09-16). Product decision of 2026-09-16:
  // widen it. The accepted risk is that a path or query can carry data TO THE
  // PROVIDER, which is in any case the intended recipient of prompts, while the
  // composer itself stays inspected.
  //
  // This branch only decides whether `Referer` is stripped: a read the provider's own
  // page makes at home goes out without the internal URL it came from. A `GET` to a
  // third-party host has no longer been sealed since the product decision of 2026-09-16
  // ("block only what is necessary"): it carries no prompt, and sealing it was showing
  // a banner for the page's telemetry. Risk accepted and recorded: a covered
  // page that called a third party with data in the URL would pass; the
  // `declarativeNetRequest` fallback, which has no blocking handler, keeps its own rules.
  const navigation=['main_frame','sub_frame'].includes(details.type);
  const initiator=details.initiator||details.originUrl||details.documentUrl;
  if(providerOwned(details.url,adapter)&&(navigation||providerOwned(initiator||'',adapter))){return {allow:true,strip:true};}
 }
 // A `file` route from the catalog — a MEASURED upload URL — is sealed under
 // file-upload blocking, before any read of the body.
 if(wire?.file){return {seal:!!protection?.block_uploads};}
 // Product decision of 2026-09-16: without masking, blocking file uploads seals
 // these routes and NOTHING ELSE — not a method (`PATCH` for account settings and the
 // model selector), not a host (third-party `GET`, API host), not the shape of a body.
 // Three releases the same day (0.5.30 to 0.5.32) showed that no heuristic holds:
 // a Cloudflare beacon in `text/plain`, NDJSON telemetry, a protobuf RPC, `fetch` sends
 // with a Blob body that `webRequest` only delivers as `error`, then the model-change
 // `PATCH` requests — each showing "the transport cannot be verified" for a send that
 // was not a file. The file picker is otherwise still intercepted in the page.
 // Under masking, everything that follows stays closed.
 if(!masking){return {seal:false};}
 // Under masking, same principle (product decision of 2026-09-16): only what CARRIES a
 // prompt is held back — a prompt route from the catalog, or a body shaped like a
 // prompt — and nothing else. Measured after a keyword block: compressed Datadog
 // telemetry and a claude.ai protobuf RPC were sealed in turn and showed a
 // second banner. The composer has already stopped or masked the text at the source; the
 // network guard only re-checks the request that carries it. Risk accepted and recorded:
 // a prompt route unknown to the catalog with an unreadable body would pass under masking.
 if(!['POST','PUT'].includes(details.method)){return {seal:false};}
 // A body the synchronous path cannot read only goes out, on a prompt route,
 // within the window opened by an approval, for that tab and that document: this is
 // the case for claude.ai, which compresses its request body. Outside a prompt route, it passes.
 if(!wire?.readable){return wire?.route?(approval?{allow:true,approved:true}:{seal:true}):{seal:false};}
 if(!wire.texts.length&&!promptShaped(wire.body,wire.keys)){return {seal:false};}
 // The text must be PRESENT, not merely equal: without this condition, a body shaped
 // like a prompt but carrying nothing at its rule's path yields an empty string,
 // and an approval for empty text — which an empty submission is enough to obtain —
 // would match it. The payload could then travel in any other field of the body.
 return approval&&wire.texts.length&&approval.text===wire.texts.join('')?{allow:true,approved:true}:{seal:true};
}
export function requestDecision(details,policy,wire,approval,now=Date.now()){
 const target=networkPlatform(details.url),origin=networkPlatform(details.initiator||details.originUrl||details.documentUrl);
 const adapter=(origin&&ruleFor(policy,origin.id)&&origin.id!==target?.id)?origin:target||origin;if(!adapter){return null;}
 const fresh=policy&&Date.parse(policy.expires_at)>now,rule=ruleFor(policy,adapter.id);
 const base={platform_id:adapter.id,provider:adapter.domain,revision:policy?.revision};
 const blocked=[target,origin].filter(Boolean).some(a=>policy?.config?.services?.some(s=>s.enabled&&['block','redirect'].includes(s.mode)&&(s.id===a.id||s.domains?.includes(a.domain))));
 if(blocked){return {...base,reason:'control_unavailable'};}
 // Content restrictions apply to private web transports as well as public APIs.
 if(fresh&&!rule&&!contentControl(policy)){return null;}
 const u=urlOf(details.url);
 if(!fresh){return {...base,reason:'control_unavailable'};}
 if(contentControl(policy)){
  // A direct API has no composer to inspect: under masking, it stays sealed —
  // except for a bodyless read (`GET`/`HEAD`/`OPTIONS`) that the provider's own page makes
  // at home, which `contentDecision` judges like any other: measured on 2026-09-16, claude.ai
  // queries `api.anthropic.com/api/directory/servers` on a model change. Under
  // file-upload blocking alone, the API host has no `file` route: nothing there is sealed.
  const direct=(u&&apiHosts[hostOf(u)])||!u,read=!!u&&['GET','HEAD','OPTIONS'].includes(details.method)&&!details.requestBody;
  if(direct&&masks(policy)&&!read){return {...base,reason:'control_unavailable'};}
  const verdict=contentDecision(details,policy,wire,approval,adapter,u,target);
  if(verdict.seal){return {...base,reason:'control_unavailable'};}
  // An approval carries its own directives and **no** `reason`: the caller seals on
  // `decision.reason`, never merely on an object's presence.
  if(verdict.allow){return {...base,allow:true,strip:!!verdict.strip,approved:!!verdict.approved};}
 }
 // Outside content control, a top-level navigation to the root or to a
 // conversation remains a navigation, not a request to qualify: this is the
 // compatibility that per-model rules have always had. Under content control,
 // the branch above has already decided.
 if(!contentControl(policy)&&target&&u?.protocol==='https:'&&!apiHosts[hostOf(u)]&&details.type==='main_frame'&&details.method==='GET'&&!details.requestBody&&!u.search&&(u.pathname==='/'||target.conversation.test(u.pathname))){return null;}
 const model=requestModel(details,adapter.id),reason=modelDecision(rule,model);
 return reason?{...base,reason,model:model||undefined}:null;
}
