import {broker,challenge,currentAuthority} from './broker.js';
import {detectionRuntime} from './detection-runtime.js';
import {trustedProvider,networkRules,validPolicy,eventForPolicy,detectTool} from './policy.js';
import {apiHosts,hostOf,networkPlatform,ownedPlatform,requestDecision,requestModel,modelDecision,contentControl,ruleFor} from './model-access.js';
import {wireFacts} from './detection.js';
import {modelObservation} from './model-rules.js';
const api=globalThis.browser||chrome,host='app.milvago.browser';
const tool=detectTool(globalThis.navigator);
// Product decision of 2026-09-22: two consecutive refreshes lost to
// slowness (broker delay, full queue) are tolerated — the previous policy stays in
// place as long as `authorized()` accepts it, expiry included — the third one seals. A policy re-read less than REUSE_MS ago serves
// as-is for inspect/submit: they follow each other within under a second and each one
// used to trigger a full refresh (exchange, DNR rules, storage).
const TOLERATED_FAILURES=2,REUSE_MS=3000,SLOW=new Set(['broker response expired','broker queue full']);
let transientFailures=0,refreshedAt=-Infinity;
let refreshing,policy,blocking=false,mode='blocked',managed=false,graceDeadline=0,graceWallDeadline=0,graceWallStart=0,gracePerfStart=0;
// Chrome evicts the idle MV3 worker and WAKES it with the request itself. The
// blocking handler is synchronous: it therefore runs BEFORE `refresh()` — a
// native messaging round trip — could return a policy. `policy` is then
// `undefined`, `authorized()` is false, and the navigation that just woke the worker
// was cancelled: `ERR_BLOCKED_BY_CLIENT`, roughly half the time depending on whether the worker was
// still alive. No cache closes this window — `storage.local` is asynchronous,
// and `mode` is never restored from disk, by the broker's design. The
// policy is in fact no longer written there at all: that plaintext cache was removed
// (2026-09-16), the server signature only travels through the broker.
//
// During this window, only READS pass through: a navigation to a
// covered provider, or a sub-resource the page fetches from its own provider.
// Any send — `POST`, `PUT`, `xmlhttprequest` — stays refused, so no prompt can
// go out uncontrolled. The window is bounded by `BOOT_MS` and closes as soon as the first
// refresh resolves, success or failure.
const BOOT_MS=1500;
let booted=false;
const endBoot=()=>{booted=true;};
setTimeout(endBoot,BOOT_MS);
// `ownedPlatform`, not `networkPlatform`: what the page needs often belongs to the
// provider without carrying its hostname — claude.ai serves its interface from
// `assets-proxy.anthropic.com`. With an exact match, these assets used to get cancelled
// during the entire wake window, so on EVERY page load since the worker
// is evicted when idle: the page loaded half-broken even with everything else fixed.
function bootReadable(details){
 if(details.method!=='GET'||details.requestBody||details.type==='xmlhttprequest'){return false;}
 const target=ownedPlatform(details.url);
 if(['main_frame','sub_frame'].includes(details.type)){return !!target;}
 const from=ownedPlatform(details.initiator||details.originUrl||details.documentUrl);
 return !!from&&from.id===target?.id;
}
const decisions=new Map(),reported=new Set();
// The send the agent has just approved, and only that one. One approval per tab, single-use
// and short-lived: it is set just before the content script replays the send,
// and the first matching request consumes it. Without it, under masking, the send
// rewritten by inspection would be cancelled like any other and masking would
// never mask anything.
const APPROVAL_MS=10000;
const approvals=new Map(),approved=new Map();
function approve(sender,platform,text){
 const tabId=sender?.tab?.id;if(typeof tabId!=='number'||tabId<0){return;}
 approvals.set(tabId,{documentId:sender.documentId,frameId:sender.frameId,platform,text,expires:Date.now()+APPROVAL_MS});
}
// The approval is valid for the tab AND the document that obtained it: another tab, a
// different document, or ten seconds later, do not receive it.
function approvalFor(details,platform){
 const entry=approvals.get(details.tabId);if(!entry){return null;}
 if(entry.expires<=Date.now()){approvals.delete(details.tabId);return null;}
 // A request WITHOUT a `documentId` — frame navigation, form, worker — does
 // not receive a document's approval: absence is not a match.
 if(entry.platform!==platform||(entry.documentId&&entry.documentId!==details.documentId)){return null;}
 return entry;
}
const detection=detectionRuntime(api,brokerBridge,tool,()=>policy);
// Only the local service may authorize this worker. Server connectivity is
// reported separately by the service, which applies its encrypted signed cache.
async function bridge(message){const answer=await api.runtime.sendNativeMessage(host,message);if(!answer?.ok){throw Object.assign(new Error('Agent unavailable'),{code:answer?.error});}return answer;}
// A failure here (quota exceeded, malformed rule) made the fail-closed seal
// invisible and silently inert. The signal stays minimal and content-free:
// a plain flag, never the error itself (name, message, or any trace of the
// rules) that could reveal the policy's content. The popup reads it;
// a successful seal clears it, and so does a successful refresh — it replaces the
// dynamic rules with the policy's own, so the fallback seal's failure
// no longer describes anything. Otherwise a single failure would stay displayed forever, agent restored or not.
// Writing the flag must not make its caller fail: the failure path of
// `refresh()` still has to write the "blocked" state after a failed seal.
// `sealFlagged` is the last value THIS worker wrote; `undefined` as long as it has
// written nothing, so that a flag inherited from a previous lifetime gets cleared on the first
// successful refresh. After that, a refresh every thirty seconds no longer
// rewrites a `false` already set. A write that throws memorizes nothing: the next one
// retries.
let sealFlagged;
async function flagSeal(failed){if(sealFlagged===failed){return;}try{await api.storage.local.set({seal_failed:failed});sealFlagged=failed;}catch{}}
// Every write of the dynamic rules goes through here, one after another. Sealing and
// refresh used to each read their own snapshot of the rules: the second one re-added
// ids the first had just set without naming them in its `removeRuleIds`, DNR
// refused, and `seal_failed:true` was written right after the first one's `false` — a false alarm,
// replayed on every refresh. The removal names both the rules already in place AND the ones being
// set: a set replayed against itself has nothing to contest. A failure does not block the queue.
let dnrQueue=Promise.resolve();
function replaceDynamicRules(rules){
 const run=dnrQueue.then(async()=>{const previous=await api.declarativeNetRequest.getDynamicRules();await api.declarativeNetRequest.updateDynamicRules({removeRuleIds:[...new Set([...previous.map(r=>r.id),...rules.map(r=>r.id)])],addRules:rules});});
 dnrQueue=run.catch(()=>{});
 return run;
}
// Only one seal at a time: `adopt()` starts one without waiting for it, and the failure path
// of `refresh()` waits for another one in the same pass; the second joins the first.
let sealing=null;
function sealDnr(){
 if(sealing){return sealing;}
 sealing=replaceDynamicRules(closedRules()).then(()=>flagSeal(false),()=>flagSeal(true)).finally(()=>{sealing=null;});
 return sealing;
}
// `managed` follows the last adopted response: the managed pin is the only proof that
// the agent responding is indeed the organization's install. Without it, the
// degraded mode (inspect/submit) lets no text leave.
function adopt(answer){managed=!answer.legacy;mode=answer.legacy?'connected':answer.mode;gracePerfStart=performance.now();graceWallStart=Date.now();graceDeadline=mode==='grace'?gracePerfStart+answer.remaining_ms:0;graceWallDeadline=mode==='grace'?graceWallStart+answer.remaining_ms:0;if(mode==='grace'&&!blocking){mode='blocked';graceDeadline=graceWallDeadline=0;void sealDnr();}}
function remaining(){return Math.max(0,Math.min(graceDeadline-performance.now(),graceWallDeadline-Date.now()));}
function authorized(){if(!validPolicy(policy)||mode==='blocked'||(mode==='grace'&&!blocking)){return false;}if(mode!=='grace'){return true;}const wallElapsed=Date.now()-graceWallStart,perfElapsed=performance.now()-gracePerfStart;return performance.now()<graceDeadline&&Date.now()>=graceWallStart&&Date.now()<graceWallDeadline&&Math.abs(wallElapsed-perfElapsed)<=1000;}
async function brokerBridge(message){
 const legacy={...message};delete legacy.authority;
 if(message.op==='catalog') {const a=await guarded('browser_catalog',{tool},legacy,message.authority);adopt(a);return a.reply;}
 if(message.op==='event_v2') {const fields={tool,event:message.event,delivery_id:message.delivery_id};const a=await guarded('browser_event',fields,legacy,message.authority);adopt(a);const reply=a.reply;if(!a.legacy&&(!reply?.durable||reply.delivery_id!==message.delivery_id||typeof reply.id!=='string'||!globalThis.MilvagoAdapters.RECEIPT_ID.test(reply.id))){throw new Error('event not durable');}return reply;}
 if(message.op==='event_receipt') {const a=await guarded('browser_receipt',{tool,delivery_id:message.delivery_id},{op:'event_receipt',tool,delivery_id:message.delivery_id},message.authority);adopt(a);if(a.legacy){throw new Error('Managed receipt lookup unavailable');}const reply=a.reply;if(reply?.ok!==true||reply.delivery_id!==message.delivery_id||typeof reply.durable!=='boolean'){throw new Error('Invalid receipt lookup');}return reply;}
 // What the request said about an exchange already made durable. It names that send
 // by its delivery identity and carries nothing else: no event, no text, no decision.
 // The service translates the identity, so a completion can never designate a send
 // this browser account did not make, nor create an event.
 if(message.op==='event_complete') {const fields={tool,delivery_id:message.delivery_id,completion:message.completion};const a=await guarded('browser_complete',fields,{op:'event_complete',tool,delivery_id:message.delivery_id,completion:message.completion},message.authority);adopt(a);const reply=a.reply;if(reply?.ok!==true){throw new Error('Invalid completion reply');}return reply;}
 if(message.op==='detector_health') {const a=await guarded('browser_health',{tool,batch:message.batch},legacy,message.authority);adopt(a);const reply=a.reply;if(!a.legacy&&(!reply?.durable||!Array.isArray(reply.accepted_health_ids))){throw new Error('health not durable');}return reply;}
 return bridge(legacy);
}
async function guarded(op,fields,legacy,expectedAuthority){
 const managed=await api.storage.managed?.get('milvago_pin')||{};
 if(!managed.milvago_pin){if(expectedAuthority!==undefined&&expectedAuthority!==null){throw new Error('browser authority changed');}const reply=await bridge(legacy);if(await currentAuthority(api)!==null){throw new Error('browser authority changed');}return {legacy:true,authority:null,reply};}
 return broker(api,bridge,{protocol:2,op,challenge:challenge(),...fields},expectedAuthority);
}
function notifyBlock(details,decision){
 if(reported.has(details.requestId)){return;}reported.add(details.requestId);
 if(reported.size>2048){reported.delete(reported.values().next().value);}
 if(details.tabId>=0){void api.tabs?.sendMessage(details.tabId,{type:'model-blocked',model:decision.model,reason:decision.reason,revision:decision.revision}).catch(()=>{});}
 if(!policy||!validPolicy(policy)||!policy.config.collection.enabled){return;}
 const event={provider:decision.provider,url:'https://'+decision.provider,source:'browser',tool,kind:'prompt',action:'blocked',characters:0,labels:[],policy_revision:policy.revision,platform_id:decision.platform_id,decision_reason:decision.reason};
 if(decision.model){event.model=decision.model;}
 void brokerBridge({op:'event_v2',tool,event,delivery_id:crypto.randomUUID()}).catch(()=>{});
}
function cancel(details,decision){notifyBlock(details,decision);return {cancel:true};}
try{
 api.webRequest.onBeforeRequest.addListener(details=>{
  if(!authorized()){
   // Worker startup: the policy hasn't come back yet. See `BOOT_MS`.
   if(!booted&&bootReadable(details)){return {};}
   // Fail-closed: agent/service unreachable or policy not yet loaded — block the
   // covered AI surface (platform sites and provider API hosts), nothing else.
   let apiHit=false;try{apiHit=!!apiHosts[hostOf(new URL(details.url))];}catch{}
   const covered=networkPlatform(details.url)||networkPlatform(details.initiator||details.originUrl||details.documentUrl);
   if(covered||apiHit){return cancel(details,{platform_id:covered?.id,provider:covered?.domain||'agent-unavailable',reason:'control_unavailable',revision:policy?.revision});}
   return {};
  }
  const platform=networkPlatform(details.url)||networkPlatform(details.initiator||details.originUrl||details.documentUrl);
  // What the catalog can tell about the body, read only once and only when
  // content control applies: the read is synchronous, the handler is too.
  let wire=null,approval=null;
  if(platform&&contentControl(policy)){
   let u=null;try{u=new URL(details.url);}catch{}
   if(u){wire=wireFacts(details,detection.catalog(),u);wire.keys=detection.catalog()?.heuristics?.keys;}
   approval=approvalFor(details,platform.id);
  }
  const decision=requestDecision(details,policy,wire,approval);
  if(decision?.reason){return cancel(details,decision);}
  if(decision?.allow){
   // An approval only serves once: it is removed as soon as a request
   // consumes it, and the request is flagged so the headers guard lets it through.
   // The revision that approved it travels with it: the text was only ever inspected under
   // that one. The `Referer` removal, on the other hand, is not memorized: it is RECOMPUTED on
   // send, so that no queue saturation can make it forgotten.
   if(decision.approved){approvals.delete(details.tabId);if(approved.size>=64){approved.delete(approved.keys().next().value);}approved.set(details.requestId,policy?.revision);}
   return {};
  }
  // The second guard recomputes the decision when nothing is pending, and it does
  // so WITHOUT the body — which it does not receive. A send that is not an `xmlhttprequest`
  // (`ping`, `beacon`, `other`: what `sendBeacon` produces, and ChatGPT uses it for
  // its events) used to pass the first guard and then get sealed by the second.
  // Fail-closed, but the two guards must say the same thing about the same request:
  // every covered POST/PUT now leaves its verdict pending.
  if(platform&&(ruleFor(policy,platform.id)||contentControl(policy))&&(details.type==='xmlhttprequest'||['POST','PUT'].includes(details.method))){
   if(decisions.size>=64){return cancel(details,{platform_id:platform.id,provider:platform.domain,reason:'control_unavailable',revision:policy?.revision});}
   decisions.set(details.requestId,{platform,model:requestModel(details,platform.id),revision:policy?.revision});
  }
  return {};
 },{urls:['<all_urls>']},['blocking','requestBody']);
 api.webRequest.onBeforeSendHeaders.addListener(details=>{
  // The approved request was authorized on its text, not its transport: the
  // type and encoding checks that follow serve the model decision. Its
  // authorization, however, survives neither the loss of the policy nor a change of
  // revision: the text was only ever inspected under the revision that approved it.
  if(approved.has(details.requestId)){
   const revision=approved.get(details.requestId);approved.delete(details.requestId);
   if(authorized()&&revision===policy?.revision){return {};}
   const covered=networkPlatform(details.url)||networkPlatform(details.initiator||details.originUrl||details.documentUrl);
   return cancel(details,{platform_id:covered?.id,provider:covered?.domain||'agent-unavailable',reason:'control_unavailable',revision:policy?.revision});
  }
  const pending=decisions.get(details.requestId);
  if(!pending){
   // Recheck the clock for every send. A request without its body decision is never
   // allowed to inherit authority across a worker wake or grace expiry.
   if(!authorized()){if(!booted&&bootReadable(details)){return {};}let apiHit=false;try{apiHit=!!apiHosts[hostOf(new URL(details.url))];}catch{};const covered=networkPlatform(details.url)||networkPlatform(details.initiator||details.originUrl||details.documentUrl);if(covered||apiHit){return cancel(details,{platform_id:covered?.id,provider:covered?.domain||'agent-unavailable',reason:'control_unavailable',revision:policy?.revision});}return {};}
   // Without a body, this guard only knows the request's route: `wireFacts` tells it whether
   // it is a catalog prompt route, the only kind masking retains (2026-09-16).
   let wire=null;
   if(contentControl(policy)&&(networkPlatform(details.url)||networkPlatform(details.initiator||details.originUrl||details.documentUrl))){let u=null;try{u=new URL(details.url);}catch{}if(u){wire=wireFacts(details,detection.catalog(),u);}}
   const decision=requestDecision(details,policy,wire);
   if(decision?.reason){return cancel(details,decision);}
   // An authorized `GET` under content control goes out without `Referer`: this
   // header is how an internal page would leak its URL to the provider, and that is the reason
   // these navigations used to be blocked outright until now. The instruction is re-read
   // from the decision — it is not kept in a bounded set that saturation
   // could empty. The `Cookie` stays: it belongs to the provider's domain, and removing it
   // would cut the session.
   return decision?.strip?{requestHeaders:(details.requestHeaders||[]).filter(h=>h.name.toLowerCase()!=='referer')}:{};
  }
  const headers=details.requestHeaders||[],types=headers.filter(h=>h.name.toLowerCase()==='content-type'),enc=headers.filter(h=>h.name.toLowerCase()==='content-encoding');
  const rule=ruleFor(policy,pending.platform.id);
  const reason=!authorized()?'control_unavailable':modelDecision(rule,pending.model);
  if(reason){return cancel(details,{platform_id:pending.platform.id,provider:pending.platform.domain,reason,model:pending.model,revision:policy?.revision});}
  // The uncompressed JSON body is only required here to protect a decision that
  // assumed this shape: a MODEL rule (`requestModel` reads JSON). Without a rule,
  // this entry only exists because content control already decided it
  // synchronously in `requestDecision`, on the request's actual body — not on its
  // headers. A catalog route covered by content control (binary file,
  // plain-text side traffic...) was never JSON and must not be re-sealed here
  // for that reason alone; nor should the API host, since "direct API" no longer decides
  // anything under upload blocking alone (product decision of 2026-09-16).
  if(pending.revision!==policy?.revision||(rule&&(types.length!==1||!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(types[0].value||'')||enc.some(h=>(h.value||'').toLowerCase()!=='identity')))){
   const platform=pending.platform;return cancel(details,{platform_id:platform.id,provider:platform.domain,reason:rule?'model_unknown':'control_unavailable',revision:policy?.revision});
  }
  return {};
 },{urls:['<all_urls>']},['blocking','requestHeaders']);
 const finish=details=>{decisions.delete(details.requestId);reported.delete(details.requestId);approved.delete(details.requestId);};
 api.webRequest.onCompleted.addListener(finish,{urls:['<all_urls>']});
 api.webRequest.onErrorOccurred.addListener(finish,{urls:['<all_urls>']});
 blocking=true;
}catch{/* An unmanaged Chromium install cannot grant blocking permission. DNR below seals restricted platforms. */}
function fallbackRules(active){
 if(blocking){return [];}
 let id=10000;
 // Without synchronous inspection no covered private transport is qualified.
 // Seal destinations AND initiators, including uploads/pings/images/other types.
 const domains=coveredDomains();
 const contentFallback=contentControl(active)?[
  {id:id++,priority:100,action:{type:'block'},condition:{requestDomains:domains}},
  {id:id++,priority:100,action:{type:'block'},condition:{initiatorDomains:domains}}
 ]:[];
 return [...contentFallback,...(active.config.model_access||[]).filter(r=>r.channel==='browser'&&r.mode!=='off').flatMap(r=>{
  const a=globalThis.MilvagoAdapters.adapters.find(a=>a.id===r.platform_id);
  if(!a){return (active.config.services||[]).filter(s=>s.id===r.platform_id).flatMap(s=>[{id:id++,priority:100,action:{type:'block'},condition:{requestDomains:s.domains}},{id:id++,priority:100,action:{type:'block'},condition:{initiatorDomains:s.domains}}]);}
  const domains=[a.domain,...Object.entries(globalThis.MilvagoAdapters.aliases).filter(([,v])=>v===a.domain).map(([k])=>k),...Object.entries(apiHosts).filter(([,v])=>v===a.id).map(([k])=>k)];
  return [
   {id:id++,priority:100,action:{type:'block'},condition:{requestDomains:domains,resourceTypes:['xmlhttprequest','websocket','other','ping','sub_frame']}},
   {id:id++,priority:100,action:{type:'block'},condition:{initiatorDomains:domains,resourceTypes:['xmlhttprequest','websocket','other','ping']}}
  ];
 })];
}
// Rules that seal the entire covered AI surface, installed when no valid policy
// is available so DNR-only installs also fail closed until the agent returns.
function coveredDomains(){return [...new Set([...Object.keys(apiHosts),...globalThis.MilvagoAdapters.adapters.map(a=>a.domain),...Object.keys(globalThis.MilvagoAdapters.aliases)])];}
function closedRules(){
 let id=20000;
 const domains=coveredDomains();
 return [
  {id:id++,priority:200,action:{type:'block'},condition:{requestDomains:domains}},
  {id:id++,priority:200,action:{type:'block'},condition:{initiatorDomains:domains}}
 ];
}
async function report(active){
 for(const rule of active.config.model_access||[]){
  if(rule.channel!=='browser'||rule.mode==='off'){continue;}
  // API contracts are implemented; private web routes and existing service-worker
  // transports have not been qualified. Never claim full platform coverage.
  await bridge({op:'enforcement',revision:active.revision,platform_id:rule.platform_id,channel:'browser',status:'unavailable',reason:blocking?'unverified_web_transport':'managed_extension_required',mechanism:'browser-request'});
 }
}
// Reload the covered AI tabs matching `match`. Used when a model rule appears or
// changes, and after an extension update: a content script injected by the previous
// version loses its channel to this worker, so capture stops silently while the
// page keeps looking supervised.
async function reloadCovered(match){
 if(!api.tabs){return;}
 for(const tab of await api.tabs.query({})){const platform=networkPlatform(tab.url);if(platform&&match(platform)){await api.tabs.reload(tab.id,{bypassCache:true}).catch(()=>{});}}
}
async function refresh(){if(refreshing){return refreshing;}refreshing=(async()=>{try{
 // The browser travels with the poll so the agent knows which extensions are still
 // running: a user who disables one must not simply vanish from the console.
 const guardedAnswer=await guarded('browser_policy',{tool},{op:'policy_v3',tool});adopt(guardedAnswer);if(!guardedAnswer.legacy&&(mode==='blocked'||guardedAnswer.mode==='blocked')){throw new Error('Broker blocked');}const answer=guardedAnswer.legacy?guardedAnswer.reply:{ok:true,online:guardedAnswer.reply.online,policy:guardedAnswer.reply.policy};if(![2,3].includes(answer.policy?.version)||!validPolicy(answer.policy)){throw new Error('Invalid policy');}
 const previousPolicy=policy;policy=answer.policy;transientFailures=0;
 await detection.refresh().catch(()=>{});
 // The catalog or an event delivery processed during this refresh may have
 // made "blocked" get adopted (grace refused without the blocking API) and triggered a seal:
 // installing the policy's rules would remove it, while the written state would still say "blocked".
 // The failure path seals and writes that state. Nothing is awaited between this check and
 // queuing the write: a seal started later runs after it.
 if(mode==='blocked'){throw new Error('Broker blocked');}
 await replaceDynamicRules([...networkRules(policy),...fallbackRules(policy)]);
 await flagSeal(false);
 const changed=JSON.stringify(previousPolicy?.config?.model_access)!==JSON.stringify(policy.config.model_access);
 const contentChanged=contentControl(policy)&&JSON.stringify([previousPolicy?.config?.privacy,previousPolicy?.config?.protection])!==JSON.stringify([policy.config.privacy,policy.config.protection]);
 // Reload closes page-owned streams; service-worker/persistent transports are
 // still unqualified, so content_control must never report complete coverage.
 if(contentChanged){await reloadCovered(()=>true);}
 else if(changed&&(policy.config.model_access||[]).some(r=>r.channel==='browser'&&r.mode!=='off')){await reloadCovered(a=>!!ruleFor(policy,a.id));}
  await report(policy).catch(()=>{});
  await api.storage.local.set({status:{connected:mode!=='blocked',mode,remaining_ms:mode==='grace'?Math.floor(remaining()):0,online:answer.online,managed,revision:policy.revision,expires_at:policy.expires_at,content_control:contentControl(policy)?'unavailable':'off',content_control_reason:contentControl(policy)?(blocking?'unverified_web_transport':'managed_extension_required'):null,model_control:(policy.config.model_access||[]).some(r=>r.channel==='browser'&&r.mode!=='off')?'unavailable':'off',updated_at:new Date().toISOString()}});
  refreshedAt=performance.now();
  }catch(error){
  // Only slowness is tolerated: broker delay exceeded or full queue. Agent absent,
  // refusal, signature, replay, pin or authority changed, invalid policy: seal.
  if(SLOW.has(error?.message)&&mode!=='blocked'&&authorized()&&++transientFailures<=TOLERATED_FAILURES){return;}
  transientFailures=0;refreshedAt=-Infinity;
  // The cause is not read: any failure of this refresh means the same
  // thing — no valid policy — and the extension returns no diagnostic to
  // the page. The response is therefore identical regardless of the error.
  policy=undefined;mode='blocked';graceDeadline=graceWallDeadline=graceWallStart=gracePerfStart=0;
 // Fail-closed: with no valid policy, seal the covered AI surface via DNR too
 // (covers installs without synchronous blocking) until the agent is restored.
 await sealDnr();
 // `connected:false` and nothing else: the popup derives its text from this one field, in the
 // browser's own language. No label is written here. A write that throws does not escape
 // `refresh()`: the popup waits for its response, and every alarm would replay an unhandled
 // rejection.
 try{await api.storage.local.set({status:{connected:false}});}catch{}
 }})().finally(()=>{refreshing=null;endBoot();});return refreshing;}
async function currentPolicy(){if(!(performance.now()-refreshedAt<REUSE_MS&&authorized())){await refresh();}if(!authorized()){throw new Error('Policy unavailable');}return policy;}
api.runtime.onInstalled.addListener(details=>{api.alarms.create('policy',{periodInMinutes:0.5});void (async()=>{await refresh();if(details?.reason==='update'){await reloadCovered(()=>true);}})();});
api.runtime.onStartup.addListener(()=>{api.alarms.create('policy',{periodInMinutes:0.5});void refresh();});
api.alarms.onAlarm.addListener(alarm=>{if(alarm.name==='policy'){void refresh();}});
api.runtime.onMessage.addListener((message,sender,respond)=>{
 // The content script receives the catalog already filtered by this edition
 // (detection-runtime `cover`), never the broker's raw payload.
 if(message?.type==='catalog'&&sender.frameId===0&&sender.tab){respond({ok:true,catalog:detection.catalog()});return false;}
 if(message?.type==='refresh'&&!sender.tab){refresh().then(()=>respond({ok:authorized()}));return true;}
 const provider=sender.frameId===0&&sender.tab?trustedProvider(sender.url):null;if(!provider){respond({ok:false});return false;}
 (async()=>{const active=await currentPolicy();
   if(message?.type==='policy'){return {ok:true,policy:active,tool};}
   if(message?.type==='inspect'){
    if(typeof message.text!=='string'||new TextEncoder().encode(message.text).length>32768||typeof message.upload!=='boolean'){return {ok:false};}
    // Without a managed pin, NEVER send text to the agent: nothing proves it is
    // the organization's install. Under content control, refuse — the network
    // guard seals the send (fail-closed); in observation-only mode, the local response
    // observes without any RPC.
    if(!(await api.storage.managed?.get('milvago_pin'))?.milvago_pin){
     if(contentControl(active)){return {ok:false,reason:'Installation non gérée : le contrôle de contenu exige une installation administrée.'};}
     return {ok:true,action:'observe',text:message.text};
    }
    // DOM inspection cannot authorize a model. Under restrictions, network control
    // remains the authority; the native result keeps other content controls active.
    const modelCheck=modelObservation===true&&message.check_model===true;const fields={text:message.text,provider,upload:message.upload,tool,...(modelCheck?{platform_id:globalThis.MilvagoAdapters.resolve(sender.url).id,check_model:true,...(typeof message.model==='string'?{model:message.model}:{})}:{})};const legacy={op:'inspect',text:message.text,provider,tool,upload:message.upload,...(modelCheck?{platform_id:globalThis.MilvagoAdapters.resolve(sender.url).id,check_model:true,...(typeof message.model==='string'?{model:message.model}:{})}:{})};const response=await guarded('browser_inspect',fields,legacy);adopt(response);if(!authorized()){throw new Error('inspection authorization expired');}return response.reply;
   }
   if(message?.type==='submit'){
    if(typeof message.text!=='string'||new TextEncoder().encode(message.text).length>32768||typeof message.upload!=='boolean'||!message.event||typeof message.event!=='object'){return {ok:false};}
    const input={...message.event,kind:'prompt',action:'observed',characters:Array.from(message.text).length,prompt:message.text};
    const recording=active.config.collection.enabled===true;
    const event=recording?eventForPolicy(input,sender.url,tool,active):{tool,provider,source:'browser'};
    if(!event){return {ok:false};}
    const managed=await api.storage.managed?.get('milvago_pin')||{};
    if(!managed.milvago_pin){
     // Degraded mode without content: metadata only to the agent, never the text —
     // even when the policy asks for it to be kept. And without a pin, no authenticated
     // inspection is possible: under content control, refuse — the network guard
     // seals the send (fail-closed). Both legacy `inspect` calls are skipped in
     // either case.
     delete event.prompt;delete event.response;
     if(contentControl(active)){return {ok:false,reason:'Installation non gérée : le contrôle de contenu exige une installation administrée.'};}
    }
    const authority=await currentAuthority(api);
    const delivery_id=recording?await detection.prepareSubmit(event,sender,authority):crypto.randomUUID();
    try{
    const fields={text:message.text,provider,upload:message.upload,tool,event,delivery_id};
    let result;
    if(managed.milvago_pin){result=await guarded('browser_submit',fields,{},authority);if(result.legacy){throw new Error('managed authority changed');}}
    else{
     if(authority!==null){throw new Error('browser authority changed');}
     // Historical event_v2 acknowledges only after Store.save. Its UUID, not an
     // invented durable field, is the compatibility receipt.
     let saved;
     if(recording){saved=(await guarded('browser_event',{},{op:'event_v2',tool,event,delivery_id:fields.delivery_id},null)).reply;if(typeof saved.id!=='string'||!globalThis.MilvagoAdapters.RECEIPT_ID.test(saved.id)){throw new Error('legacy receipt absent');}}
     const reread=await api.storage.managed?.get('milvago_pin')||{};
     if(reread.milvago_pin){throw new Error('managed authority changed');}
     result={legacy:true,authority:null,reply:{ok:true,action:'observe',text:message.text,recording_required:recording,durable:recording,delivery_id:fields.delivery_id,id:saved?.id}};
    }
   adopt(result);const reply=result.reply;
   if(!authorized()||!reply?.ok||reply.action!=='observe'||reply.text!==message.text){return {ok:false,reason:reply?.reason||'Le texte doit être contrôlé de nouveau.'};}
   if(reply.recording_required!==false&&(reply.durable!==true||reply.delivery_id!==fields.delivery_id||typeof reply.id!=='string')){return {ok:false,reason:'Événement non conservé.'};}
   if(recording){await detection.confirmSubmit(delivery_id,sender,message.text);}
   // The text here is guaranteed equal to what was submitted and inspected (check
   // above). The approval is set right before the content script replays the
   // send, and not before: nothing must pass on the strength of a refused inspection.
   if(contentControl(policy)){approve(sender,provider&&networkPlatform(sender.url)?.id,message.text);}
   return {ok:true,authority:result.authority,mode,remaining_ms:mode==='grace'?Math.floor(remaining()):0,action:reply.action,text:reply.text,durable:reply.durable,recording_required:reply.recording_required,delivery_id:reply.delivery_id};
   }finally{if(recording){detection.releaseSubmit(delivery_id);}}
  }
   if(message?.type==='event'){
    const event=eventForPolicy(message.event,sender.url,tool,active);if(!event){return {ok:false};}
    // Same rule as on submit: without a managed pin, the text (prompt or response)
    // does not leave the browser, even if the policy asks for it to be kept.
    if(!(await api.storage.managed?.get('milvago_pin'))?.milvago_pin){delete event.prompt;delete event.response;}
    return detection.dom(event,sender,message.event);
   }return {ok:false};
 })().then(respond).catch(()=>respond({ok:false,reason:'Contrôle local indisponible. Réessayez après avoir connecté l’agent.'}));return true;
});

// Always re-establish service liveness on worker startup, including DNR-only browsers.
api.alarms.create('policy',{periodInMinutes:0.5});
void refresh();
