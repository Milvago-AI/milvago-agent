import {broker,challenge,currentAuthority} from './broker.js';
import {detectionRuntime} from './detection-runtime.js';
import {trustedProvider,networkRules,validPolicy,eventForPolicy,detectTool} from './policy.js';
import {apiHosts,hostOf,networkPlatform,ownedPlatform,requestDecision,requestModel,modelDecision,contentControl,ruleFor,exactTextDigest,textDigest,lineParts,PART_LINES,bytesDigest,promptShaped} from './model-access.js';
import {wireFacts,headerModel,headerModelScope,headerModelProvider,sessionBeacon,beaconHeaders} from './detection.js';
import {modelObservation,keptWhenSealed,blockedTab} from './model-rules.js';
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
// A paste the agent masked is approved too (`paste`), for longer, once the person has confirmed it
// in the page: it may ride with the send minutes later (a chip) or leave at once as an upload. A text
// file the person picked and the agent let through is approved by the fingerprint of its name and its size (`file`). Each
// approval serves once, under the policy revision that inspected it; a tab holds a bounded few, and
// a new send approval replaces the previous one. An entry keeps the fingerprint and UTF-8 size of
// its text, never the text (`textDigest`).
// A picked file lives as long as a paste: a provider may send it inline with the message, minutes later.
const APPROVAL_MS=10000,FILE_APPROVAL_MS=30*60*1000,PASTE_APPROVAL_MS=30*60*1000,REVIEW_MS=10*60*1000,APPROVALS_PER_TAB=32,APPROVAL_TABS=64;
const LIFETIME={send:APPROVAL_MS,file:FILE_APPROVAL_MS,paste:PASTE_APPROVAL_MS};
const approvals=new Map(),approved=new Map();
const textFields=text=>({exact:exactTextDigest(text),digest:textDigest(text),bytes:new TextEncoder().encode(text).length});
function originOf(value){try{const origin=new URL(value).origin;return origin==='null'?null:origin;}catch{return null;}}
// The document an approval belongs to: its `documentId`, or, where the browser gives none (Firefox
// before 153), its frame and origin, the document itself being retired on `webNavigation.onCommitted`.
// The origin and not the URL: the providers move between conversations with `pushState`.
function documentOf(sender){return sender.documentId?{documentId:sender.documentId}:{frameId:sender.frameId,origin:originOf(sender.url)};}
function sameDocument(entry,documentId,frameId,url){return entry.documentId?entry.documentId===documentId:!!entry.origin&&entry.frameId===frameId&&entry.origin===originOf(url);}
// The worker sleeps when idle and wakes on the next message or request: approvals are kept in
// `storage.session` (browser memory, never disk, out of reach of content scripts) and restored at
// start. Without it, they live as long as the worker.
const session=api.storage?.session;
let restoring=session?Promise.resolve().then(()=>session.get('approvals')).then(restoreApprovals,()=>{}):Promise.resolve();
function persist(){if(!session){return;}restoring=restoring.then(()=>session.set({approvals:[...approvals].flatMap(([tabId,list])=>list.map(e=>({...e,tabId})))})).catch(()=>{});}
function store(tabId,list){if(list.length){approvals.set(tabId,list);}else{approvals.delete(tabId);}persist();}
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-58][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,DIGEST=/^[0-9a-f]{64}$/;
const confirmedReceipts=new Map(),pendingConfirmations=new Map();
function confirmationContext(entry,sender){return entry&&entry.expires>Date.now()&&entry.tabId===sender.tab.id&&entry.revision===policy.revision&&sameDocument(entry,sender.documentId,sender.frameId,sender.url);}
function rememberPendingConfirmation(reply,sender){
 if(reply?.confirmation!==true)return;
 if(!UUID.test(reply.dlp_receipt||''))throw new Error('confirmation receipt absent');
 const now=Date.now();for(const [id,value] of pendingConfirmations){if(value.expires<=now)pendingConfirmations.delete(id);}
 if(pendingConfirmations.size>=256)pendingConfirmations.delete(pendingConfirmations.keys().next().value);
 pendingConfirmations.set(reply.dlp_receipt,{tabId:sender.tab.id,...documentOf(sender),revision:policy.revision,expires:now+REVIEW_MS});
}
function rememberConfirmation(receipt,sender){
 const now=Date.now();for(const [id,value] of confirmedReceipts){if(value.expires<=now)confirmedReceipts.delete(id);}
 if(confirmedReceipts.size>=256)confirmedReceipts.delete(confirmedReceipts.keys().next().value);
 confirmedReceipts.set(receipt,{tabId:sender.tab.id,...documentOf(sender),revision:policy.revision,expires:now+REVIEW_MS});
}
// A picked file: the SHA-256 of its name, computed in the page, and its size.
const validFile=f=>!!f&&typeof f.name==='string'&&DIGEST.test(f.name)&&Number.isSafeInteger(f.size)&&f.size>=0;
// A stored entry is read back field by field: anything malformed, or living longer than its kind allows, is dropped.
function storedApproval(e,now){
 if(!e||typeof e!=='object'||!Number.isSafeInteger(e.tabId)||e.tabId<0||!Object.hasOwn(LIFETIME,e.kind)){return null;}
 const pending=e.pending;
 if(pending!==undefined&&(e.kind!=='paste'||typeof pending!=='string'||!UUID.test(pending))){return null;}
 if(!Number.isFinite(e.expires)||e.expires<=now||e.expires>now+(pending?REVIEW_MS:LIFETIME[e.kind])){return null;}
 if(typeof e.platform!=='string'||e.platform.length>64||!Number.isSafeInteger(e.revision)){return null;}
 let place=null;
 if(typeof e.documentId==='string'&&e.documentId.length<=128){place={documentId:e.documentId};}
 else if(Number.isSafeInteger(e.frameId)&&e.frameId>=0&&typeof e.origin==='string'&&e.origin.length<=2048){place={frameId:e.frameId,origin:e.origin};}
 if(!place){return null;}
 const confirmations=e.confirmations;if(confirmations!==undefined&&(e.kind!=='paste'||!pending||!Array.isArray(confirmations)||confirmations.length>32||!confirmations.every(id=>typeof id==='string'&&UUID.test(id))))return null;
 let body=null;
 if(e.kind==='file'){body=validFile(e)?{name:e.name,size:e.size}:null;}
 else if((e.digest===null||DIGEST.test(e.digest))&&Number.isSafeInteger(e.bytes)&&e.bytes>=0){
  const parts=e.parts;
  if(parts!==undefined&&(e.kind!=='send'||!Array.isArray(parts)||parts.length>2*PART_LINES||!parts.every(p=>typeof p==='string'&&DIGEST.test(p)))){return null;}
  const labels=e.labels;
  if(labels!==undefined&&(e.kind!=='paste'||!validLabels(labels))){return null;}
  body={...(DIGEST.test(e.exact||'')?{exact:e.exact}:{}),digest:e.digest,bytes:e.bytes,...(parts?{parts}:{}),...(labels?{labels:[...labels]}:{})};
 }
 return body?{tabId:e.tabId,entry:{...body,kind:e.kind,platform:e.platform,revision:e.revision,...place,expires:e.expires,...(pending?{pending}:{}),...(confirmations?{confirmations:[...confirmations]}:{})}}:null;
}
function restoreApprovals(stored){
 const list=stored?.approvals,now=Date.now();if(!Array.isArray(list)){return;}
 for(const raw of list.slice(0,APPROVAL_TABS*APPROVALS_PER_TAB)){
  const read=storedApproval(raw,now);if(!read||(!approvals.has(read.tabId)&&approvals.size>=APPROVAL_TABS)){continue;}
  approvals.set(read.tabId,[read.entry,...(approvals.get(read.tabId)||[])].slice(-APPROVALS_PER_TAB));
 }
}
function samePolicyIdentity(left,right){return !!left&&!!right&&left.version===right.version&&left.revision===right.revision&&left.config?.dlp_control?.fingerprint===right.config?.dlp_control?.fingerprint;}
function policyUnchanged(expected){return authorized()&&samePolicyIdentity(expected,policy);}
function approve(sender,platform,fields,kind='send',expected=policy){
 if(!policyUnchanged(expected))return false;
 const tabId=sender?.tab?.id;if(typeof tabId!=='number'||tabId<0||typeof platform!=='string'||!Number.isSafeInteger(expected?.revision)){return false;}
 if(!approvals.has(tabId)&&approvals.size>=APPROVAL_TABS){approvals.delete(approvals.keys().next().value);}
 const now=Date.now(),kept=(approvals.get(tabId)||[]).filter(e=>e.expires>now&&(kind!=='send'||e.kind!=='send'));
 kept.push({...fields,kind,platform,revision:expected.revision,...documentOf(sender),expires:now+(fields.pending?REVIEW_MS:LIFETIME[kind])});
 store(tabId,kept.slice(-APPROVALS_PER_TAB));return true;
}
// An approval is valid for the tab, the document and the revision that obtained it: another tab, a
// different document, another policy, or past its time, do not receive it.
function approvalFor(details,platform){
 const list=approvals.get(details.tabId);if(!list){return [];}
 const now=Date.now(),live=list.filter(e=>e.expires>now);
 if(live.length!==list.length){store(details.tabId,live);}
 // A request WITHOUT a `documentId` — frame navigation, form, worker — does
 // not receive a document's approval: absence is not a match.
 return live.filter(e=>!e.pending&&e.platform===platform&&e.revision===policy?.revision&&sameDocument(e,details.documentId,details.frameId,details.documentUrl));
}
function consume(tabId,used){store(tabId,(approvals.get(tabId)||[]).filter(e=>!used?.includes(e)));}
// What a reviewed paste was found to hold (its labels, never its text), handed to the next network prompt
// of the tab that carried it out: a chip or an attachment never reaches the draft the agent records with
// its labels (real campaign 0.7.10: `labels=[]`). Once, within LENT_MS.
const LENT_MS=120000,lent=new Map(),LABEL=/^[a-z0-9_-]{1,64}$/i;
const validLabels=list=>Array.isArray(list)&&list.length<=16&&list.every(label=>typeof label==='string'&&LABEL.test(label));
// Kept to the document and service that carried the paste out: a tab navigated elsewhere borrows nothing.
function lend(details,platform,used){
 const tabId=details.tabId,labels=[...new Set((used||[]).filter(e=>e.kind==='paste'&&validLabels(e.labels)).flatMap(e=>e.labels))];if(!labels.length){return;}
 if(!lent.has(tabId)&&lent.size>=64){lent.delete(lent.keys().next().value);}
 lent.set(tabId,{labels:labels.slice(0,16),expires:Date.now()+LENT_MS,documentId:details.documentId,platform});
}
function takeLabels(details,platform){
 const entry=lent.get(details.tabId);lent.delete(details.tabId);
 return entry&&entry.expires>Date.now()&&entry.platform===platform&&entry.documentId===details.documentId?entry.labels:[];
}
// The paste the person confirmed after its review becomes an approval; one cancelled never does.
function confirmPaste(message,sender){
 const tabId=sender?.tab?.id,now=Date.now();
 if(typeof message.token!=='string'||!UUID.test(message.token)||typeof tabId!=='number'){return {ok:false};}
 const list=approvals.get(tabId)||[],entry=list.find(e=>e.pending===message.token&&e.expires>now&&sameDocument(e,sender.documentId,sender.frameId,sender.url));
 if(!entry){return {ok:false};}
 if(entry.confirmations?.some(id=>{const ack=confirmedReceipts.get(id);return !ack||ack.expires<=now||ack.tabId!==tabId||ack.revision!==policy.revision||!sameDocument(ack,sender.documentId,sender.frameId,sender.url);})){return {ok:false};}
 for(const id of entry.confirmations||[])confirmedReceipts.delete(id);delete entry.confirmations;
 delete entry.pending;entry.expires=now+PASTE_APPROVAL_MS;store(tabId,list);
 return {ok:true};
}
api.tabs?.onRemoved?.addListener(tabId=>{if(approvals.has(tabId)){store(tabId,[]);}});
// A new document in a frame retires the approvals of the one it replaces.
api.webNavigation?.onCommitted?.addListener(details=>{
 const list=approvals.get(details.tabId);if(!list){return;}
 const left=list.filter(e=>(e.documentId?!(details.frameId===0&&details.documentId&&e.documentId!==details.documentId):e.frameId!==details.frameId));
 if(left.length!==list.length){store(details.tabId,left);}
});
const detection=detectionRuntime(api,brokerBridge,tool,()=>policy,async()=>{try{return await currentPolicy();}catch{return null;}},(details,platform)=>takeLabels(details,platform));
// Only the local service may authorize this worker. Server connectivity is
// reported separately by the service, which applies its encrypted signed cache.
// A browser call that never settles (a native host that hangs, a DNR update that never returns)
// used to hold the single-flight `refresh()` forever: every alarm got the same pending promise
// back, so the worker never retried and stayed sealed until the extension was reloaded.
// Suspected cause of the 2026-10-15 20:59 incident (policy lost for 9 minutes on one profile).
const NATIVE_MS=8000,DNR_MS=10000,CATALOG_MS=15000,REFRESH_MS=45000;
function within(promise,ms){let timer;return Promise.race([promise,new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('operation stalled')),ms);})]).finally(()=>clearTimeout(timer));}
async function bridge(message){const answer=await within(api.runtime.sendNativeMessage(host,message),NATIVE_MS);if(!answer?.ok){throw Object.assign(new Error('Agent unavailable'),{code:answer?.error});}return answer;}
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
function replaceDynamicRules(rules,keep=()=>false){
 const run=dnrQueue.then(()=>within((async()=>{const previous=await api.declarativeNetRequest.getDynamicRules();const kept=previous.filter(keep).filter(r=>!rules.some(x=>x.id===r.id));await api.declarativeNetRequest.updateDynamicRules({removeRuleIds:[...new Set([...previous.map(r=>r.id),...rules.map(r=>r.id)])],addRules:[...rules,...kept]});})(),DNR_MS));
 dnrQueue=run.catch(()=>{});
 return run;
}
// Only one seal at a time: `adopt()` starts one without waiting for it, and the failure path
// of `refresh()` waits for another one in the same pass; the second joins the first.
let sealing=null;
function sealDnr(){
 if(sealing){return sealing;}
 sealing=replaceDynamicRules(closedRules(),keptWhenSealed).then(()=>flagSeal(false),()=>flagSeal(true)).finally(()=>{sealing=null;});
 return sealing;
}
// `managed` follows the last adopted response: the managed pin is the only proof that
// the agent responding is indeed the organization's install. Without it, the
// degraded mode (inspect/submit) lets no text leave.
function adopt(answer){managed=!answer.legacy;mode=answer.legacy?'connected':answer.mode;gracePerfStart=performance.now();graceWallStart=Date.now();graceDeadline=mode==='grace'?gracePerfStart+answer.remaining_ms:0;graceWallDeadline=mode==='grace'?graceWallStart+answer.remaining_ms:0;if(mode==='grace'&&!blocking){mode='blocked';graceDeadline=graceWallDeadline=0;void sealDnr();}}
// A broker that refuses one event signs "blocked" as it does for an absent agent (`cache_service`):
// adopting it sealed every covered page for a refused record (real campaign 0.7.8: an idle page of
// another service sealed 0.8 s after a refusal). Whether the agent is still there is asked again instead,
// after any policy request already on its way: that one may have left before the agent turned blocked.
function adoptDelivery(answer){if(!answer.legacy&&answer.mode==='blocked'){const asked=refreshing;void (asked?asked.then(()=>refresh()):refresh());return;}adopt(answer);}
function remaining(){return Math.max(0,Math.min(graceDeadline-performance.now(),graceWallDeadline-Date.now()));}
function authorized(){if(!validPolicy(policy)||mode==='blocked'||(mode==='grace'&&!blocking)){return false;}if(mode!=='grace'){return true;}const wallElapsed=Date.now()-graceWallStart,perfElapsed=performance.now()-gracePerfStart;return performance.now()<graceDeadline&&Date.now()>=graceWallStart&&Date.now()<graceWallDeadline&&Math.abs(wallElapsed-perfElapsed)<=1000;}
// Completion names an existing durable delivery and carries no new event or text.
async function completeBrowserEvent(message){
 const fields={tool,delivery_id:message.delivery_id,completion:message.completion};
 const answer=await guarded('browser_complete',fields,{op:'event_complete',tool,delivery_id:message.delivery_id,completion:message.completion},message.authority);
 adoptDelivery(answer);
 const reply=answer.reply;
 if(reply?.ok!==true){throw new Error('Invalid completion reply');}
 return reply;
}
async function brokerBridge(message){
 const legacy={...message};delete legacy.authority;
 if(message.op==='catalog') {const a=await guarded('browser_catalog',{tool},legacy,message.authority);adopt(a);return a.reply;}
 if(message.op==='event_v2') {const fields={tool,event:message.event,delivery_id:message.delivery_id};const a=await guarded('browser_event',fields,legacy,message.authority);adoptDelivery(a);const reply=a.reply;if(!a.legacy&&(!reply?.durable||reply.delivery_id!==message.delivery_id||typeof reply.id!=='string'||!globalThis.MilvagoAdapters.RECEIPT_ID.test(reply.id))){throw new Error('event not durable');}return reply;}
 if(message.op==='event_receipt') {const a=await guarded('browser_receipt',{tool,delivery_id:message.delivery_id},{op:'event_receipt',tool,delivery_id:message.delivery_id},message.authority);adoptDelivery(a);if(a.legacy){throw new Error('Managed receipt lookup unavailable');}const reply=a.reply;if(reply?.ok!==true||reply.delivery_id!==message.delivery_id||typeof reply.durable!=='boolean'){throw new Error('Invalid receipt lookup');}return reply;}
 if(message.op==='event_complete') {return completeBrowserEvent(message);}
 if(message.op==='detector_health') {const a=await guarded('browser_health',{tool,batch:message.batch},legacy,message.authority);adoptDelivery(a);const reply=a.reply;if(!a.legacy&&(!reply?.durable||!Array.isArray(reply.accepted_health_ids))){throw new Error('health not durable');}return reply;}
 return bridge(legacy);
}
async function guarded(op,fields,legacy,expectedAuthority){
 const managed=await api.storage.managed?.get('milvago_pin')||{};
 if(!managed.milvago_pin){if(expectedAuthority!==undefined&&expectedAuthority!==null){throw new Error('browser authority changed');}const reply=await bridge(legacy);if(await currentAuthority(api)!==null){throw new Error('browser authority changed');}return {legacy:true,authority:null,reply};}
 return broker(api,bridge,{protocol:2,op,challenge:challenge(),...fields},expectedAuthority);
}
// The send each tab just made durable through the DOM, for the network guard that may
// still cancel it on its model: that event then becomes the blocked one, rather than
// standing as observed beside a second, blocked record of the same send.
const SUBMITTED_MS=10000,PROMPT_REASONS=['model_denied','model_unknown','control_unavailable'];
const submitted=new Map();
// Only where the network guard decides that platform's sends: elsewhere nothing binds the record to the
// request that carried it, which has already gone out when a refusal comes (a broker that answers
// "blocked" for a moment would otherwise turn a send that left into a blocked one).
function rememberSubmit(sender,platform,delivery_id,authority){
 const tabId=sender?.tab?.id;if(typeof tabId!=='number'||tabId<0||!platform||!(contentControl(policy)||ruleFor(policy,platform))){return;}
 if(!submitted.has(tabId)&&submitted.size>=64){submitted.delete(submitted.keys().next().value);}
 submitted.set(tabId,{documentId:sender.documentId,platform,delivery_id,authority,expires:Date.now()+SUBMITTED_MS});
}
// Same binding as an approval: this tab, this document, this platform, once.
function submitFor(details,platform){
 const entry=submitted.get(details.tabId);if(!entry){return null;}
 if(entry.expires<=Date.now()){submitted.delete(details.tabId);return null;}
 if(entry.platform!==platform||(entry.documentId&&entry.documentId!==details.documentId)){return null;}
 return entry;
}
// The DOM record belongs to the FIRST send the network sees after it: a send that went out
// must not be rewritten as blocked by a regeneration refused a few seconds later. Only the
// catalogue route itself binds it: a variant (`near`) is decided like the route, never paired.
// And only a request that carries the send (its approved text or a model): a session handshake
// on the same route passed first and kept the record from the refused send behind it.
function bindSubmit(details,platform){const entry=submitFor(details,platform);if(entry&&entry.requestId===undefined){entry.requestId=details.requestId;}}
function takeSubmit(details,platform){
 const entry=submitFor(details,platform);
 if(!entry||(entry.requestId!==undefined&&entry.requestId!==details.requestId)){return null;}
 submitted.delete(details.tabId);return entry;
}
// A page that retries a refused request on its own (claude.ai resent the same body about every 4 s, real
// campaign 0.7.6: 20 events in 90 s) is told and recorded once per REPEAT_MS for the same body, tab, document, reason and model.
// A refusal decided on the headers is keyed on the body its request carried (`queueDecision`): a page that resent a
// refused session opening three times, byte for byte, was told and recorded three times (real campaign 0.7.10).
const REPEAT_MS=120000,repeats=new Map(),beacons=new Map();
function repeated(details,decision,own=false){
 const request=details.requestBody;if(decision.page||!request||request.error){return false;}
 let material;
 if(Array.isArray(request.raw)){let size=0;for(const part of request.raw){if(!part?.bytes||part.file){return false;}size+=part.bytes.byteLength;}if(size>1024*1024){return false;}material=new Uint8Array(size);let at=0;for(const part of request.raw){material.set(new Uint8Array(part.bytes),at);at+=part.bytes.byteLength;}}
 else if(request.formData){material=new TextEncoder().encode(JSON.stringify(request.formData));}
 else{return false;}
 const place=[details.tabId,details.documentId||'',decision.platform_id,details.method,details.url.split('?')[0]],digest=bytesDigest(material),now=Date.now();
 // Real campaign 0.7.11 (a denied model): the page resent the refused opening 20 ms later, its send approval
 // already spent, so the copy was refused `control_unavailable` and told over the model notice; 7 s later it opened a
 // new session without the text, another body. A copy of the same bytes refused for want of an approval, and a
 // text-less request refused on the same model after a send of the person was refused on it, are that one send.
 const keys=[[...place,decision.reason,decision.model||'',digest],[...place,'copy',digest],...(decision.model?[[...place,'open',decision.reason,decision.model]]:[])].map(k=>k.join('|'));
 const recent=key=>{const last=repeats.get(key);return last!==undefined&&now-last<REPEAT_MS;};
 const hit=recent(keys[0])||decision.reason==='control_unavailable'&&recent(keys[1])||!!decision.textless&&!!decision.model&&recent(keys[2]);
 // Only a send of the person opens the text-less window: a page's own refusals stay apart.
 if(keys[2]&&!own){keys.pop();}
 for(const key of keys){if(repeats.size>=256){repeats.delete(repeats.keys().next().value);}repeats.delete(key);repeats.set(key,now);}
 return hit;
}
function notifyBlock(details,decision){
 if(reported.has(details.requestId)){return;}reported.add(details.requestId);
 if(reported.size>2048){reported.delete(reported.values().next().value);}
 if(decision.quiet){return;}
 // A DOM record still waiting for this request is a new send of the person, never the page's retry: folding it
 // left that record "observed" for a send that was refused.
 const own=PROMPT_REASONS.includes(decision.reason)&&details.tabId>=0&&(entry=>!!entry&&(entry.requestId===undefined||entry.requestId===details.requestId))(submitFor(details,decision.platform_id));
 if(repeated(details,decision,own)&&!own){return;}
 // A held page is replaced by its destination or the notice page: no notice in a page that is gone.
 if(details.tabId>=0&&!decision.page){void api.tabs?.sendMessage(details.tabId,{type:'model-blocked',model:decision.model,reason:decision.reason,revision:decision.revision}).catch(()=>{});}
 // Taken even with collection off: the record only marks a send of the person, whose next refusal must not be folded.
 const sent=PROMPT_REASONS.includes(decision.reason)&&details.tabId>=0?takeSubmit(details,decision.platform_id):null;
 if(!policy||!validPolicy(policy)||!policy.config.collection.enabled){return;}
 // A held service is a visit, blocked or redirected, never a prompt nobody sent.
 const visit=!!decision.page,action=decision.reason==='service_redirected'?'redirected':'blocked';
 // Under its service's own domain: an alias host names no service to the agent, which refused the
 // record (real campaign 0.7.8: a refusal on an alias host left no event).
 const provider=globalThis.MilvagoAdapters.adapters.find(a=>a.id===decision.platform_id)?.domain||decision.provider;
 const event={provider,url:'https://'+provider,source:'browser',tool,kind:visit?'navigation':'prompt',action:visit?action:'blocked',characters:0,labels:[],policy_revision:policy.revision,platform_id:decision.platform_id,decision_reason:decision.reason};
 if(decision.model){event.model=decision.model;}
 const record=()=>brokerBridge({op:'event_v2',tool,event,delivery_id:crypto.randomUUID()}).catch(()=>{});
 if(!sent){void record();return;}
 // Wherever that event now is (browser queue, agent, server), the agent completes it;
 // if it cannot, the blocked send is still recorded on its own.
 const completion={decision_reason:decision.reason,platform_id:decision.platform_id,...(typeof decision.model==='string'&&/^[A-Za-z0-9._:/-]{1,200}$/.test(decision.model)?{model:decision.model}:{})};
 void brokerBridge({op:'event_complete',delivery_id:sent.delivery_id,completion,authority:sent.authority}).then(reply=>reply?.applied===true?null:record(),record);
}
function cancel(details,decision){notifyBlock(details,decision);return {cancel:true};}
// A held service's page: sent to its destination, or to the extension's notice page (`blocked`).
function replacePage(details,decision){notifyBlock(details,decision);return {redirectUrl:decision.page==='blocked'?api.runtime.getURL('/blocked.html?service='+encodeURIComponent(decision.service_host)):decision.page};}
function blockedWithoutPolicy(details){
 if(!booted&&bootReadable(details)){return {};}
 let apiHit=false;
 try{apiHit=!!apiHosts[hostOf(new URL(details.url))];}catch{}
 const covered=networkPlatform(details.url)||networkPlatform(details.initiator||details.originUrl||details.documentUrl);
 // Cut whatever it is, but told and recorded only when it may carry a send: a catalogue route (prompt, draft,
 // file, paste) or a direct API host. The broker signs "blocked" for any agent error, and a policy still in
 // memory then recorded every read of the page as a refused prompt (real campaign 0.7.10: 7 on a reloaded page).
 let send=apiHit;
 // A body shaped like a prompt off those routes is announced too, as masking announces it.
 if(covered&&!send){try{const w=wireFacts(details,detection.catalog(),new URL(details.url));send=!!(w.route||w.file||w.paste||w.draft)||['POST','PUT'].includes(details.method)&&promptShaped(w.body,detection.catalog()?.heuristics?.keys);}catch{}}
 if(covered||apiHit){return cancel(details,{platform_id:covered?.id,provider:covered?.domain||'agent-unavailable',reason:'control_unavailable',revision:policy?.revision,...(send?{}:{quiet:true})});}
 return {};
}
function untrackedHeaders(details){
   // Recheck the clock for every send. A request without its body decision is never
   // allowed to inherit authority across a worker wake or grace expiry.
   if(!authorized()){return blockedWithoutPolicy(details);}
   // Without a body, this guard only knows the request's route: `wireFacts` tells it whether
   // it is a catalog prompt route, the only kind masking retains (2026-09-16).
   let wire=null;
   if(contentControl(policy)&&(networkPlatform(details.url)||networkPlatform(details.initiator||details.originUrl||details.documentUrl))){let u=null;try{u=new URL(details.url);}catch{}if(u){wire=wireFacts(details,detection.catalog(),u);}}
   const decision=requestDecision(details,policy,wire,undefined,Date.now(),scopeFor(details));
   if(decision?.reason){return cancel(details,decision);}
   const routed=decision?.route?routeVerdict(decision.platform_id,decision.route,details.requestHeaders):null;
   if(decision?.route&&!decision.route.near&&!routed.absent){bindSubmit(details,decision.platform_id);}
   if(routed?.reason){return cancel(details,{...decision,...routed});}
   // An authorized `GET` under content control goes out without `Referer`: this
   // header is how an internal page would leak its URL to the provider, and that is the reason
   // these navigations used to be blocked outright until now. The instruction is re-read
   // from the decision — it is not kept in a bounded set that saturation
   // could empty. The `Cookie` stays: it belongs to the provider's domain, and removing it
   // would cut the session.
   return decision?.strip?{requestHeaders:(details.requestHeaders||[]).filter(h=>h.name.toLowerCase()!=='referer')}:{};
}
// The model of a catalogue prompt route that names it in a header, decided on that header:
// an id the rule's `model_map` does not translate is unknown, not merely unlisted.
// A route that names its model in its body was read in the body handler (`route.body`); a message of a
// session that names none is not decided on a model.
function routeVerdict(platformId,route,headers){
 const {model,known,absent}=route.rule.model_header?headerModel(route,headers):route.body||{absent:true};
 if(absent){return {reason:null,absent:true};}
 return {reason:modelDecision(ruleFor(policy,platformId),known?model:undefined),model};
}
function heldNow(platformId){return !!policy?.config?.services?.some(s=>s.enabled&&['block','redirect'].includes(s.mode)&&s.id===platformId);}
function scopeFor(details){return (id,u)=>headerModelScope(detection.catalog(),id,details,u);}
function pendingHeaders(details,pending,approvedSend=false){
  const headers=details.requestHeaders||[],types=headers.filter(h=>h.name.toLowerCase()==='content-type'),enc=headers.filter(h=>h.name.toLowerCase()==='content-encoding');
  const rule=ruleFor(policy,pending.platform.id);
  // A scoped request is decided on its catalogue route's header, or not on a model at all.
  let verdict={reason:null,model:pending.model};
  if(pending.route){verdict=routeVerdict(pending.platform.id,pending.route,details.requestHeaders);}
  else if(!pending.scoped){verdict.reason=modelDecision(rule,pending.model);}
  if(pending.model||(pending.route&&!pending.route.near&&(!verdict.absent||approvedSend))){bindSubmit(details,pending.platform.id);}
  // The body was read in `onBeforeRequest`; the headers stage has none, and a page's identical retry is told once.
  if(pending.body&&!details.requestBody){details={...details,requestBody:pending.body};}
  // Turned unauthorized since its body passed: cut like any other request then, a page read unannounced.
  if(!authorized()){return blockedWithoutPolicy(details);}
  const reason=verdict.reason;
  if(reason){return cancel(details,{platform_id:pending.platform.id,provider:pending.platform.domain,reason,model:verdict.model,revision:policy?.revision,textless:pending.textless});}
  // The uncompressed JSON body is only required here to protect a decision that
  // assumed this shape: a MODEL rule (`requestModel` reads JSON). Without a rule,
  // this entry only exists because content control already decided it
  // synchronously in `requestDecision`, on the request's actual body — not on its
  // headers. A catalog route covered by content control (binary file,
  // plain-text side traffic...) was never JSON and must not be re-sealed here
  // for that reason alone; nor should the API host, since "direct API" no longer decides
  // anything under upload blocking alone (product decision of 2026-09-16).
  if(pending.revision!==policy?.revision||(rule&&!pending.scoped&&(types.length!==1||!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(types[0].value||'')||enc.some(h=>(h.value||'').toLowerCase()!=='identity')))){
   // Caught by a revision change, a request that is neither a catalogue prompt route nor
   // names a model is page traffic in flight, not a send: still cancelled, but neither
   // recorded nor announced as a blocked prompt (about 40 in one redirect loop, 2026-10-15).
   // A send caught by the revision that blocks or redirects its service is the visit's business, not a refusal.
   const platform=pending.platform,quiet=pending.revision!==policy?.revision&&(!pending.route&&!pending.model||heldNow(platform.id));
   return cancel(details,{platform_id:platform.id,provider:platform.domain,reason:rule?'model_unknown':'control_unavailable',revision:policy?.revision,quiet});
  }
  return {};
}
function requestInputs(details,platform){
 if(!platform||!contentControl(policy)){return {wire:null,approval:null};}
 let u=null;
 try{u=new URL(details.url);}catch{}
 let wire=null;
 if(u){wire=wireFacts(details,detection.catalog(),u);wire.keys=detection.catalog()?.heuristics?.keys;}
 return {wire,approval:approvalFor(details,platform.id)};
}
// Keep the body verdict until the headers guard checks the same request.
function queueDecision(details,platform,decision){
 if(platform&&(ruleFor(policy,platform.id)||contentControl(policy))&&(details.type==='xmlhttprequest'||['POST','PUT'].includes(details.method))){
  if(decisions.size>=64){return cancel(details,{platform_id:platform.id,provider:platform.domain,reason:'control_unavailable',revision:policy?.revision});}
  const model=requestModel(details,platform.id),route=decision?.platform_id===platform.id?decision.route||null:null;
  // A route body read whole with no text at its paths (a session opening): only the repeat check uses it.
  let textless=false;
  if(route){try{const w=wireFacts(details,detection.catalog(),new URL(details.url));textless=!!w.readable&&!w.malformed&&!w.prose&&!w.groups?.length&&!(w.texts||[]).some(t=>typeof t!=='string'||globalThis.MilvagoAdapters.layout(t)!=='');}catch{}}
  decisions.set(details.requestId,{platform,model,revision:policy?.revision,scoped:!!decision?.scoped&&decision.platform_id===platform.id,route,body:details.requestBody,textless});
 }
 return {};
}
try{
 api.webRequest.onBeforeRequest.addListener(details=>{
  if(!authorized()){return blockedWithoutPolicy(details);}
  const platform=networkPlatform(details.url)||networkPlatform(details.initiator||details.originUrl||details.documentUrl);
  const {wire,approval}=requestInputs(details,platform);
  const decision=requestDecision(details,policy,wire,approval,Date.now(),scopeFor(details));
  // A session's empty terminate beacon passed on its body; its headers must still show an empty string.
  if(platform&&(contentControl(policy)||ruleFor(policy,platform.id))&&sessionBeacon(details,detection.catalog())){if(beacons.size>=64){return cancel(details,{platform_id:platform.id,provider:platform.domain,reason:'control_unavailable',revision:policy?.revision});}beacons.set(details.requestId,platform);}
  if(decision?.page){return replacePage(details,decision);}
  if(decision?.reason){return cancel(details,decision);}
  // An approved prompt route still has its model decided on its headers.
  if(decision?.allow&&decision.route){const held=queueDecision(details,platform,decision);if(held.cancel){return held;}}
  if(decision?.allow){
   // An approval only serves once: it is removed as soon as a request
   // consumes it, and the request is flagged so the headers guard lets it through.
   // The revision that approved it travels with it: the text was only ever inspected under
   // that one. The `Referer` removal, on the other hand, is not memorized: it is RECOMPUTED on
   // send, so that no queue saturation can make it forgotten.
   if(decision.approved){consume(details.tabId,decision.consumed);lend(details,platform.id,decision.consumed);if(approved.size>=64){approved.delete(approved.keys().next().value);}approved.set(details.requestId,policy?.revision);}
   return {};
  }
  return queueDecision(details,platform,decision);
 },{urls:['<all_urls>']},['blocking','requestBody']);
 api.webRequest.onBeforeSendHeaders.addListener(details=>{
  const beacon=beacons.get(details.requestId);
  if(beacon){beacons.delete(details.requestId);if(!beaconHeaders(details.requestHeaders)){return cancel(details,{platform_id:beacon.id,provider:beacon.domain,reason:'control_unavailable',revision:policy?.revision});}}
  // The approved request was authorized on its text, not its transport: the
  // type and encoding checks that follow serve the model decision. Its
  // authorization, however, survives neither the loss of the policy nor a change of
  // revision: the text was only ever inspected under the revision that approved it.
  if(approved.has(details.requestId)){
   const revision=approved.get(details.requestId);approved.delete(details.requestId);
   if(authorized()&&revision===policy?.revision){return decisions.has(details.requestId)?pendingHeaders(details,decisions.get(details.requestId),true):{};}
   const covered=networkPlatform(details.url)||networkPlatform(details.initiator||details.originUrl||details.documentUrl);
   return cancel(details,{platform_id:covered?.id,provider:covered?.domain||'agent-unavailable',reason:'control_unavailable',revision:policy?.revision,quiet:!!covered&&heldNow(covered.id)});
  }
  const pending=decisions.get(details.requestId);
  if(!pending){return untrackedHeaders(details);}
  return pendingHeaders(details,pending);
 },{urls:['<all_urls>']},['blocking','requestHeaders']);
 const finish=details=>{decisions.delete(details.requestId);beacons.delete(details.requestId);reported.delete(details.requestId);approved.delete(details.requestId);};
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
 if(!policyUnchanged(active)){return;}
 if(active.version>=4&&active.config.dlp_control){
  await bridge({op:'dlp_enforcement',fingerprint:active.config.dlp_control.fingerprint,tool,channel:'browser',mechanism:'browser-request',status:'unavailable'}).catch(()=>{});
 }
 for(const rule of active.config.model_access||[]){
  if(!policyUnchanged(active)){return;}
  if(rule.channel!=='browser'||rule.mode==='off'){continue;}
  // API contracts are implemented. A web provider is `applied` only when every prompt
  // route of its catalogue names the model in a header the blocking handler reads
  // (`headerModelProvider`); other private web routes have not been qualified.
  const applied=blocking&&!!headerModelProvider(detection.catalog(),rule.platform_id);
  await bridge({op:'enforcement',revision:active.revision,platform_id:rule.platform_id,channel:'browser',status:applied?'applied':'unavailable',reason:applied?'':(blocking?'unverified_web_transport':'managed_extension_required'),mechanism:'browser-request',tool});
 }
}
// Remote supervision must not consume the local authorization deadline. Keep
// one bounded reporting pass in flight, so renewals cannot build a backlog.
let reporting;
function reportLater(active){
 if(reporting){return;}
 reporting=report(active).catch(()=>{}).finally(()=>{reporting=null;});
}
// Reload the covered AI tabs matching `match`. Used when a model rule appears or
// changes, and after an extension update: a content script injected by the previous
// version loses its channel to this worker, so capture stops silently while the
// page keeps looking supervised.
async function reloadCovered(match,skip=new Set()){
 if(!api.tabs){return;}
 for(const tab of await api.tabs.query({})){const platform=networkPlatform(tab.url);if(platform&&match(platform)&&!skip.has(tab.id)){await api.tabs.reload(tab.id,{bypassCache:true}).catch(()=>{});}}
}
// A tab already open on a service the new revision blocks or redirects is sent straight to its destination
// or the notice page. Reloaded, it relied on the redirect of its own navigation, which a page's service
// worker takes over (a reload or a navigation it answers is no `main_frame` request): tabs reloaded at the
// switch to `block` stayed blank on Chrome and Edge (real campaign 0.7.7; reproduced with a service worker).
async function replaceHeldTabs(active){
 const moved=new Set();
 if(!api.tabs){return moved;}
 let notice=null;try{notice=api.runtime.getURL('/blocked.html');}catch{/* no notice page to follow */}
 for(const tab of await api.tabs.query({})){
  // A tab already on the notice page follows the new revision too (real campaign 0.7.11: it stayed there after the
  // switch to `redirect`): to the destination, or back to its service once that is no longer held.
  const service=!!notice&&typeof tab.url==='string'&&tab.url.startsWith(notice+'?')?noticeService(tab.url,active):null;
  const url=service?'https://'+service+'/':tab.url;
  const details={requestId:'held-'+active.revision+'-'+tab.id,tabId:tab.id,url,method:'GET',type:'main_frame'};
  const decision=typeof url==='string'?requestDecision(details,active,null,null):null;
  const target=decision?.page?(decision.page==='blocked'?api.runtime.getURL('/blocked.html?service='+encodeURIComponent(decision.service_host)):decision.page):service&&url;
  if(!target||target===tab.url){continue;}
  // The visit was recorded when the notice replaced it: following the policy is not another one.
  moved.add(tab.id);if(!service){notifyBlock(details,decision);}
  await api.tabs.update(tab.id,{url:target}).catch(()=>{});
 }
 return moved;
}
// The service a notice page names, only when the policy knows it: the page is reachable by any site, and its
// parameter must not send a tab anywhere else.
function noticeService(url,active){
 let host;try{host=new URL(url).searchParams.get('service')?.toLowerCase();}catch{return null;}
 if(!host||!/^[a-z0-9](?:[a-z0-9-]{0,62}\.)+[a-z0-9-]{1,63}$/.test(host)||host.length>253){return null;}
 const known=(active.config.services||[]).some(s=>(s.domains||[]).some(d=>host===d||host.endsWith('.'+d)))||!!networkPlatform('https://'+host+'/');
 return known?host:null;
}
async function reconcileOpenTabs(previousPolicy,active){
 const held=JSON.stringify(previousPolicy?.config?.services)!==JSON.stringify(active.config.services)?await replaceHeldTabs(active):new Set();
 // A tab already open on a newly blocked platform keeps its page until reloaded.
 if(JSON.stringify(previousPolicy?.config?.blocked_platforms)!==JSON.stringify(active.config.blocked_platforms)&&api.tabs){
  for(const tab of await api.tabs.query({})){if(blockedTab(active,tab.url)){await closeBlockedTab(tab.id);}}
 }
 const changed=JSON.stringify(previousPolicy?.config?.model_access)!==JSON.stringify(active.config.model_access);
 const contentChanged=contentControl(active)&&JSON.stringify([previousPolicy?.config?.privacy,previousPolicy?.config?.protection,previousPolicy?.config?.dlp_control])!==JSON.stringify([active.config.privacy,active.config.protection,active.config.dlp_control]);
 // Reload closes page-owned streams; service-worker/persistent transports are
 // still unqualified, so content_control must never report complete coverage.
 if(contentChanged){await reloadCovered(()=>true,held);}
 else if(changed&&(active.config.model_access||[]).some(r=>r.channel==='browser'&&r.mode!=='off')){await reloadCovered(a=>!!ruleFor(active,a.id),held);}
}
function policyStatus(active,online){
 return {status:{connected:mode!=='blocked',mode,remaining_ms:mode==='grace'?Math.floor(remaining()):0,online,managed,revision:active.revision,expires_at:active.expires_at,content_control:contentControl(active)?'unavailable':'off',content_control_reason:(()=>{if(!contentControl(active)){return null;}if(blocking){return 'unverified_web_transport';}return 'managed_extension_required';})(),model_control:(active.config.model_access||[]).some(r=>r.channel==='browser'&&r.mode!=='off')?'unavailable':'off',updated_at:new Date().toISOString()}};
}
// Each refresh carries its generation: one abandoned on its deadline (or overtaken) keeps
// running, and must not write mode, policy, rules or status once its stalled call returns.
let generation=0;
async function updatePolicy(run){
 const live=()=>{if(run!==generation){throw new Error('refresh superseded');}};
 // The browser travels with the poll so the agent knows which extensions are still
 // running: a user who disables one must not simply vanish from the console.
 const guardedAnswer=await guarded('browser_policy',{tool},{op:'policy_v3',tool});live();adopt(guardedAnswer);if(!guardedAnswer.legacy&&(mode==='blocked'||guardedAnswer.mode==='blocked')){throw new Error('Broker blocked');}const answer=guardedAnswer.legacy?guardedAnswer.reply:{ok:true,online:guardedAnswer.reply.online,policy:guardedAnswer.reply.policy};if(![2,3,4].includes(answer.policy?.version)||!validPolicy(answer.policy)){throw new Error('Invalid policy');}
 const previousPolicy=policy;policy=answer.policy;transientFailures=0;
 // Every approval was inspected under the revision it names: none survives a new one.
 if(previousPolicy&&!samePolicyIdentity(previousPolicy,policy)){approvals.clear();pendingConfirmations.clear();confirmedReceipts.clear();persist();}
 await within(detection.refresh(),CATALOG_MS).catch(()=>{});live();
 // The catalog or an event delivery processed during this refresh may have
 // made "blocked" get adopted (grace refused without the blocking API) and triggered a seal:
 // installing the policy's rules would remove it, while the written state would still say "blocked".
 // The failure path seals and writes that state. Nothing is awaited between this check and
 // queuing the write: a seal started later runs after it.
 if(mode==='blocked'){throw new Error('Broker blocked');}
 await replaceDynamicRules([...networkRules(policy),...fallbackRules(policy)]);live();
 await flagSeal(false);live();
 await reconcileOpenTabs(previousPolicy,policy);live();
 await api.storage.local.set(policyStatus(policy,answer.online));
 refreshedAt=performance.now();
 reportLater(policy);
  }
async function handleRefreshFailure(error){
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
 }
// Bounded: a refresh that stalls counts as failed (sealed), and the next alarm retries.
async function refresh(){if(refreshing){return refreshing;}const run=++generation;const current=within(updatePolicy(run),REFRESH_MS).catch(error=>{if(run===generation){generation++;}return within(handleRefreshFailure(error),REFRESH_MS).catch(()=>{});}).finally(()=>{if(refreshing===current){refreshing=null;}endBoot();});refreshing=current;return current;}
async function currentPolicy(){if(!(performance.now()-refreshedAt<REUSE_MS&&authorized())){await refresh();}if(!authorized()){throw new Error('Policy unavailable');}return policy;}
api.runtime.onInstalled.addListener(details=>{api.alarms.create('policy',{periodInMinutes:0.5});void (async()=>{await refresh();if(details?.reason==='update'){await reloadCovered(()=>true);}})();});
api.runtime.onStartup.addListener(()=>{api.alarms.create('policy',{periodInMinutes:0.5});void refresh();});
api.alarms.onAlarm.addListener(alarm=>{if(alarm.name==='policy'){void refresh();}});
// A single-page app moves to a blocked path with pushState, which no request rule sees.
// Chrome replaces the page with its error page when the reload is blocked. Firefox
// treats a blocked navigation as cancelled and keeps the page on screen, so the tab is
// sent to about:blank, which is what Firefox shows for any blocked navigation (measured).
// Neither keeps a blocked URL that would fire this again.
function closeBlockedTab(tabId){return (tool==='firefox'?api.tabs.update(tabId,{url:'about:blank'}):api.tabs.reload(tabId)).catch(()=>{});}
api.tabs?.onUpdated?.addListener((tabId,change)=>{if(change.url&&policy&&blockedTab(policy,change.url)){void closeBlockedTab(tabId);}});
async function inspectMessage(message,sender,provider,active){
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
    const modelCheck=modelObservation===true&&message.check_model===true;const fields={text:message.text,provider,upload:message.upload,tool,...(message.observation===true?{observation:true}:{}),...(modelCheck?{platform_id:globalThis.MilvagoAdapters.resolve(sender.url).id,check_model:true,...(typeof message.model==='string'?{model:message.model}:{})}:{})};const legacy={op:'inspect',text:message.text,provider,tool,upload:message.upload,...(modelCheck?{platform_id:globalThis.MilvagoAdapters.resolve(sender.url).id,check_model:true,...(typeof message.model==='string'?{model:message.model}:{})}:{})};const response=await guarded('browser_inspect',fields,legacy);adopt(response);if(!policyUnchanged(active)){throw new Error('inspection policy changed');}if(message.observation!==true)rememberPendingConfirmation(response.reply,sender);return response.reply;
}
// A paste is inspected before the page receives it. Longer than one inspection, it is cut into pieces
// the agent accepts (32 KiB each): at line breaks, and a line longer than one piece after a blank, or
// between two characters when it has none. The pieces are inspected in order, then each seam is
// inspected again on the masked text around it (SEAM characters each side), so a value cut in two
// (an IBAN over two lines) is seen whole; the masked seam replaces that stretch exactly. A paste
// beyond PASTE_LIMIT is refused (fail-closed).
const PASTE_LIMIT=192*1024,PIECE=32768,SEAM=256;
const utf8=text=>new TextEncoder().encode(text).length;
function cutLine(line){
 const out=[];let start=0,bytes=0,blank=-1;
 for(let i=0;i<line.length;){
  const cp=line.codePointAt(i),width=cp<0x80?1:cp<0x800?2:cp<0x10000?3:4,units=cp>0xffff?2:1;
  if(bytes+width>PIECE){const end=blank>start?blank:i;out.push(line.slice(start,end));start=end;bytes=utf8(line.slice(start,i));blank=-1;}
  bytes+=width;i+=units;if(/\s/u.test(String.fromCodePoint(cp))){blank=i;}
 }
 out.push(line.slice(start));return out;
}
// Each piece with the separator that joins it to the previous one: a line break, or nothing.
function pieces(text){
 const out=[];let current=null;
 text.split('\n').forEach((line,index)=>cutLine(line).forEach((segment,at)=>{
  const sep=index&&!at?'\n':'';
  if(current&&utf8(current.text)+utf8(sep)+utf8(segment)<=PIECE){current.text+=sep+segment;}
  else{current={text:segment,sep:out.length?sep:''};out.push(current);}
 }));
 return out;
}
// A stretch boundary that never splits a surrogate pair.
const low=(text,at)=>at>0&&at<text.length&&/[\uDC00-\uDFFF]/.test(text[at]);
async function inspectPiece(text,sender,provider,active,state){
 const answer=await inspectMessage({text,upload:false},sender,provider,active);
 if(!answer?.ok||!['observe','review','block','redirect'].includes(answer.action)||typeof answer.text!=='string'){return {stop:{ok:false,...(typeof answer?.reason==='string'?{reason:answer.reason}:{})}};}
 if(['block','redirect'].includes(answer.action)){return {stop:answer};}
 if(answer.action==='review'){state.action='review';}
 if(answer.confirmation===true){if(!UUID.test(answer.dlp_receipt||''))return {stop:{ok:false}};state.receipts.add(answer.dlp_receipt);if(state.receipts.size>32)return {stop:{ok:false}};if(typeof answer.reason==='string')state.reasons.add(answer.reason);}
 for(const label of Array.isArray(answer.labels)?answer.labels:[]){state.labels.add(label);}
 return {text:answer.text};
}
async function pasteMessage(message,sender,provider,active){
 const refused={ok:false,reason:'Le texte collé dépasse la limite du contrôle local. Collez-le en plusieurs fois.'};
 if(typeof message.text!=='string'||utf8(message.text)>PASTE_LIMIT){return refused;}
 if(active.version>=4&&active.config.dlp_control?.enabled===true&&utf8(message.text)>PIECE){return refused;}
 const parts=pieces(message.text.replaceAll(/\r\n?/g,'\n')),state={action:'observe',labels:new Set(),receipts:new Set(),reasons:new Set()},outputs=[];
 for(const part of parts){const read=await inspectPiece(part.text,sender,provider,active,state);if(read.stop){return read.stop;}outputs.push(read.text);}
 let text=outputs[0];
 for(let i=1;i<outputs.length;i++){
  let from=Math.max(0,text.length-SEAM),to=Math.min(outputs[i].length,SEAM);
  if(low(text,from)){from--;}if(low(outputs[i],to)){to++;}
  const read=await inspectPiece(text.slice(from)+parts[i].sep+outputs[i].slice(0,to),sender,provider,active,state);if(read.stop){return read.stop;}
  text=text.slice(0,from)+read.text+outputs[i].slice(to);
 }
 if(!policyUnchanged(active))return {ok:false};
 // Approved only once the person confirms the paste in the page (`paste-confirm`), with this token.
 let token;
 if(contentControl(policy)){token=crypto.randomUUID();approve(sender,networkPlatform(sender.url)?.id,{...textFields(text),pending:token,...(state.receipts.size?{confirmations:[...state.receipts]}:{}),...(state.labels.size?{labels:[...state.labels].filter(label=>typeof label==='string'&&LABEL.test(label)).slice(0,16)}:{})},'paste',active);}
 const reason=[...state.reasons].join('\n\n');if(utf8(reason)>32768)return refused;
 return {ok:true,action:state.action,text,labels:[...state.labels],...(state.receipts.size?{confirmation:true,dlp_receipts:[...state.receipts],reason}:{}),...(token?{token}:{})};
}
async function submitDelivery(fields,managed,authority,recording){
 if(managed.milvago_pin){
  const result=await guarded('browser_submit',fields,{},authority);
  if(result.legacy){throw new Error('managed authority changed');}
  return result;
 }
 if(authority!==null){throw new Error('browser authority changed');}
 // Historical event_v2 acknowledges only after Store.save. Its UUID is the receipt.
 let saved;
 if(recording){
  saved=(await guarded('browser_event',{},{op:'event_v2',tool,event:fields.event,delivery_id:fields.delivery_id},null)).reply;
  if(typeof saved.id!=='string'||!globalThis.MilvagoAdapters.RECEIPT_ID.test(saved.id)){throw new Error('legacy receipt absent');}
 }
 const reread=await api.storage.managed?.get('milvago_pin')||{};
 if(reread.milvago_pin){throw new Error('managed authority changed');}
 return {legacy:true,authority:null,reply:{ok:true,action:'observe',text:fields.text,recording_required:recording,durable:recording,delivery_id:fields.delivery_id,id:saved?.id}};
}
async function submitMessage(message,sender,provider,active){
    if(typeof message.text!=='string'||new TextEncoder().encode(message.text).length>32768||typeof message.upload!=='boolean'||!message.event||typeof message.event!=='object'){return {ok:false};}
    if(message.files!==undefined&&(!Array.isArray(message.files)||message.files.length>20||!message.files.every(validFile))){return {ok:false};}
    const input={...message.event,kind:'prompt',action:'observed',characters:Array.from(message.text).length,prompt:message.text};
    const recording=active.config.collection.enabled===true||active.config.dlp_control?.journal===true;
    const event=recording?eventForPolicy(input,sender.url,tool,active,true):{tool,provider,source:'browser'};
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
    if(message.approval_id!==undefined){
     const ack=confirmedReceipts.get(message.approval_id);
     if(!UUID.test(message.approval_id)||!ack||ack.expires<=Date.now()||ack.tabId!==sender.tab.id||ack.revision!==active.revision||!sameDocument(ack,sender.documentId,sender.frameId,sender.url))return {ok:false};
     confirmedReceipts.delete(message.approval_id);
    }
    const authority=await currentAuthority(api);
    const delivery_id=recording?await detection.prepareSubmit(event,sender,authority):crypto.randomUUID();
    try{
    if(message.approval_id!==undefined&&!UUID.test(message.approval_id))return {ok:false};
    const fields={text:message.text,provider,upload:message.upload,tool,event,delivery_id,...(message.approval_id?{approval_id:message.approval_id}:{})};
    const result=await submitDelivery(fields,managed,authority,recording);
   adopt(result);const reply=result.reply;
   if(!authorized()||!reply?.ok||reply.action!=='observe'||reply.text!==message.text){return {ok:false,reason:reply?.reason||'Le texte doit être contrôlé de nouveau.'};}
   if(reply.recording_required!==false&&(reply.durable!==true||reply.delivery_id!==fields.delivery_id||typeof reply.id!=='string')){return {ok:false,reason:'Événement non conservé.'};}
   // The broker either kept the event or explicitly required none. Retire the
   // local intent in both cases; otherwise a metadata-only non-match retries forever.
   // This only clears Fusion's pending intent and creates no persistence receipt.
   if(recording){await detection.confirmSubmit(delivery_id,sender,message.text);}rememberSubmit(sender,networkPlatform(sender.url)?.id,delivery_id,result.authority);
   // The text here is guaranteed equal to what was submitted and inspected (check
   // above). The approval is set right before the content script replays the
   // send, and not before: nothing must pass on the strength of a refused inspection.
   if(!policyUnchanged(active))return {ok:false,reason:'Policy changed; inspect this submission again.'};
   if(contentControl(policy)){
    const platform=provider&&networkPlatform(sender.url)?.id;if(!approve(sender,platform,{...textFields(message.text),parts:lineParts(message.text)},'send',active))return {ok:false};
    // The text files of a validated selection, by name and size: the provider declares them so when it uploads them.
    if(message.upload){for(const file of message.files||[]){if(!approve(sender,platform,{name:file.name,size:file.size},'file',active))return {ok:false};}}
   }
   return {ok:true,authority:result.authority,mode,remaining_ms:mode==='grace'?Math.floor(remaining()):0,action:reply.action,text:reply.text,durable:reply.durable,recording_required:reply.recording_required,delivery_id:reply.delivery_id};
   }finally{if(recording){detection.releaseSubmit(delivery_id);}}
}
async function eventMessage(message,sender,active){
    const event=eventForPolicy(message.event,sender.url,tool,active);if(!event){return {ok:false};}
    // Same rule as on submit: without a managed pin, the text (prompt or response)
    // does not leave the browser, even if the policy asks for it to be kept.
    if(!(await api.storage.managed?.get('milvago_pin'))?.milvago_pin){delete event.prompt;delete event.response;}
    return detection.dom(event,sender,message.event);
}
api.runtime.onMessage.addListener((message,sender,respond)=>{
 // The content script receives the catalog already filtered by this edition
 // (detection-runtime `cover`), never the broker's raw payload.
 if(message?.type==='catalog'&&sender.frameId===0&&sender.tab){respond({ok:true,catalog:detection.catalog()});return false;}
 if(message?.type==='refresh'&&!sender.tab){refresh().then(()=>respond({ok:authorized()}));return true;}
 const provider=sender.frameId===0&&sender.tab?trustedProvider(sender.url):null;if(!provider){respond({ok:false});return false;}
 (async()=>{const active=await currentPolicy();
  if(message?.type==='policy'){return {ok:true,policy:active,tool};}
  if(message?.type==='inspect'){return inspectMessage(message,sender,provider,active);}
  if(message?.type==='dlp-confirmed'&&globalThis.MilvagoAdapters.RECEIPT_ID.test(message.receipt||'')){
   const pending=pendingConfirmations.get(message.receipt);if(!confirmationContext(pending,sender))return {ok:false};
   pendingConfirmations.delete(message.receipt);
   const result=await guarded('browser_confirm',{tool,delivery_id:message.receipt},null);adopt(result);
   if(!policyUnchanged(active)||result.reply?.ok!==true||result.reply?.applied!==true)return {ok:false};
   rememberConfirmation(message.receipt,sender);return result.reply;
  }
  if(message?.type==='dlp-cancelled'&&globalThis.MilvagoAdapters.RECEIPT_ID.test(message.receipt||'')){pendingConfirmations.delete(message.receipt);confirmedReceipts.delete(message.receipt);return (await guarded('browser_cancelled',{tool,delivery_id:message.receipt},null)).reply;}
  if(message?.type==='submit'){return submitMessage(message,sender,provider,active);}
  if(message?.type==='paste'){return pasteMessage(message,sender,provider,active);}
  if(message?.type==='paste-confirm'){return confirmPaste(message,sender);}
  if(message?.type==='event'){return eventMessage(message,sender,active);}
  return {ok:false};
 })().then(respond).catch(()=>respond({ok:false,reason:'Contrôle local indisponible. Réessayez après avoir connecté l’agent.'}));return true;
});

// Always re-establish service liveness on worker startup, including DNR-only browsers.
api.alarms.create('policy',{periodInMinutes:0.5});
void refresh();
