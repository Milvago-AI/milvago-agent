import {currentAuthority} from './broker.js';
import {factoryCatalog,coveredProviders} from './detection-factory.js';
import {observeRequest,candidateSignals,glob,Fusion} from './detection.js';
import {modelObservation} from './model-rules.js';
function appendMeasurement(event,output,key){
  if(event[key]===undefined){return;}
  if(!Number.isSafeInteger(event[key])||event[key]<0||(key==='body_bytes'&&event[key]>16*1024*1024)){throw new Error('Invalid detection measurement');}
  output[key]=event[key];
 }
function enrichResponse(event,observed){
  if(!observed||event.kind!=='response'){return;}
   // Only the response: it is the one event guaranteed to be emitted after its own
   // request was seen. A prompt is recorded before the request leaves, so attaching
   // what the tab last said would attribute it to the previous exchange. The
   // conversation identifier obeys the same rule for the same reason: the prompt that
   // opens a thread is emitted while the page still shows `/new`, and the tab still
   // remembers the PREVIOUS conversation -- attaching it there is precisely the
   // cross-conversation mix-up this chain exists to avoid. That prompt keeps its link
   // through the correlation it shares with the navigation that follows, which does
   // carry the identifier because the document reports its live URL.
  if(observed.model){event.model=observed.model;}
  if(observed.effort){event.effort=observed.effort;}
  if(!event.conversation_id&&observed.conversation_id){event.conversation_id=observed.conversation_id;}
 }
function metricFor(kind){
  if(kind==='navigation'){return 'navigations';}
  if(kind==='response'){return 'responses_dom';}
  return 'prompts_dom';
 }
function completionOf(event){
  const out={};
  if(modelObservation&&typeof event.model==='string'&&/^[A-Za-z0-9._:/-]{1,200}$/.test(event.model)){out.model=event.model;}
  if(modelObservation&&typeof event.effort==='string'&&/^[a-z0-9_-]{1,40}$/.test(event.effort)){out.effort=event.effort;}
  if(typeof event.conversation_id==='string'&&/^[A-Za-z0-9_-]{1,200}$/.test(event.conversation_id)){out.conversation_id=event.conversation_id;}
  if(Number.isSafeInteger(event.body_bytes)&&event.body_bytes>=0&&event.body_bytes<=16*1024*1024){out.body_bytes=event.body_bytes;}
  return Object.keys(out).length?out:null;
 }
function identity(details,provider){return [details.tabId,details.documentId||details.frameId||0,provider].join('|');}
// A served catalog cannot extend the providers or hosts packaged in Community.
function narrowCatalogProvider(provider) {
 if(!coveredProviders.includes(provider.id)){return null;}
 const factory=factoryCatalog.providers.find(entry=>entry.id===provider.id);
 if(!factory){return null;}
 const servedDomains=new Set(Array.isArray(provider.domains)?provider.domains:[]);
 const domains=factory.domains.filter(domain=>servedDomains.has(domain));
 if(!domains.length){return null;}
 const servedAliases=new Set(Array.isArray(provider.aliases)?provider.aliases:[]);
 const aliases=(factory.aliases||[]).filter(domain=>servedAliases.has(domain));
 const servedAssets=new Set(Array.isArray(provider.asset_hosts)?provider.asset_hosts:[]);
 const asset_hosts=(factory.asset_hosts||[]).filter(host=>servedAssets.has(host));
 const perimeter=new Set([...factory.domains,...(factory.aliases||[]),...(factory.asset_hosts||[])]);
 const network=(Array.isArray(provider.network)?provider.network:[]).filter(rule=>rule&&perimeter.has(rule.host));
 return {...provider,domains,aliases,asset_hosts,network};
}
function narrowCatalog(content) {
 if(!content||!coveredProviders){return content;}
 const providers=[];
 for(const provider of content.providers||[]){
  const narrowed=narrowCatalogProvider(provider);
  if(narrowed){providers.push(narrowed);}
 }
 return {...content,providers};
}
function validDetectionMetadata(event){
 return !!event&&typeof event.provider==='string'&&/^[a-z0-9.-]{1,253}$/.test(event.provider)&&
  ['navigation','prompt','response'].includes(event.kind)&&
  ['observed','blocked','redirected'].includes(event.action)&&
  Number.isInteger(event.characters)&&event.characters>=0&&event.characters<=1000000;
}
function platformCandidates(index, hostname){
 const candidates=[];
 const own=index.get(hostname);
 if(own){candidates.push(...own);}
 for(let i=0;i<hostname.length;i++){
  if(hostname[i]!=='.'){continue;}
  const suffix=hostname.slice(i+1);
  if(!suffix){continue;}
  const entries=index.get(suffix);
  if(entries){candidates.push(...entries);}
 }
 return candidates;
}
export function detectionRuntime(api,bridge,tool,getPolicy){
 const A=globalThis.MilvagoAdapters;
 let catalog=factoryCatalog,revision=0,catalogState='missing',expires=0,registeredRevision=-1,excludedDomains=[];
 const DAY=86400000,validAuthority=value=>typeof value==='string'&&/^[0-9a-f]{64}$/.test(value);
 async function requireAuthority(expected){if(expected!==await currentAuthority(api)){await change(()=>{diagnostics.last_error='authority_changed';});throw new Error('browser authority changed');}}
 const emptyHealth=()=>({providers:{},candidates:{},start:null,end:null,revision:null,state:null});
 let health=emptyHealth(),outbox=[],diagnostics={dropped_batches:0,dropped_observations:0,last_error:null},catalogIdentity=null,serial=Promise.resolve();
 const requests=new Map();let ready=(async()=>{const s=await api.storage.local.get('detectorHealth');if(s.detectorHealth){
  health=s.detectorHealth.health;outbox=s.detectorHealth.outbox||[];diagnostics=s.detectorHealth.diagnostics||diagnostics;catalogIdentity=s.detectorHealth.catalogIdentity||null;
  if(health.revision==null||!validAuthority(health.authority)){if(Object.keys(health.providers||{}).length||Object.keys(health.candidates||{}).length){drop('legacy_unattributed',health);}health=emptyHealth();}
  const valid=[];for(const batch of outbox){const duration=Date.parse(batch.window_end)-Date.parse(batch.window_start);if(!Number.isFinite(duration)||duration<0||duration>DAY){drop('invalid_window',batch);}else if(!validAuthority(batch.authority)){drop('unbound_authority',batch);}else {valid.push(batch);}}outbox=valid;
 }})();
 void ready.catch(()=>{});
 function drop(reason,value){diagnostics.dropped_batches=Math.min(Number.MAX_SAFE_INTEGER,diagnostics.dropped_batches+1);const rows=[...Object.values(value.providers||{}),...Object.values(value.candidates||{})];const count=rows.reduce((sum,row)=>sum+['navigations','prompts_network','prompts_dom','responses_dom','candidates','count'].reduce((n,key)=>n+(Number.isFinite(row[key])?row[key]:0),0),0);diagnostics.dropped_observations=Math.min(Number.MAX_SAFE_INTEGER,diagnostics.dropped_observations+count);diagnostics.last_error=reason;}
 const save=(extra={})=>api.storage.local.set({detectorHealth:{health,outbox,diagnostics,catalogIdentity},...extra});
 const change=(fn,extra)=>{const operation=serial.then(()=>ready).then(async()=>{const before=structuredClone({health,outbox,diagnostics,catalogIdentity});try{fn();await save(extra);}catch(error){({health,outbox,diagnostics,catalogIdentity}=before);throw error;}});serial=operation.catch(()=>{});return operation;};
 function seal(){
  if(!health.start){return;}
  if(outbox.length>=64){throw new Error('detector health queue full');}
  outbox.push({id:crypto.randomUUID(),tool,extension_version:api.runtime.getManifest().version,authority:health.authority,catalog_revision:health.revision,catalog_state:health.state,window_start:health.start,window_end:health.end,providers:Object.values(health.providers),candidates:Object.values(health.candidates)});health=emptyHealth();
 }
 function observe(at,observedRevision,observedState,authority){
  if(health.start&&(health.authority!==authority||health.revision!==observedRevision||health.state!==observedState||at-Date.parse(health.start)>DAY||at<Date.parse(health.end))){seal();}
  const time=new Date(at).toISOString();if(!health.start){health.start=time;health.authority=authority;health.revision=observedRevision;health.state=observedState;}health.end=time;
 }
 async function count(id,key,observedRevision,observedState,authority){if(observedRevision===undefined){observedRevision=revision;}if(observedState===undefined){observedState=catalogState;}const at=Date.now();if(authority===undefined){authority=await currentAuthority(api);}return change(()=>{observe(at,observedRevision,observedState,authority);if(!health.providers[id]&&Object.keys(health.providers).length>=128){throw new Error('detector health providers full');}const row=health.providers[id]||={provider:id,navigations:0,prompts_network:0,prompts_dom:0,responses_dom:0,candidates:0};row[key]=Math.min(1e6,row[key]+1);});}
 const receiptID=value=>typeof value==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-[1-58][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);

 function metadata(event){
  // This is the only persistent event projection in the browser. Neither content,
  // filenames, conversation identifiers nor their fingerprints enter storage.
  if(!validDetectionMetadata(event)){throw new Error('Invalid detection metadata');}
  const output={provider:event.provider,source:'browser',tool,kind:event.kind,action:event.action,characters:event.characters,characters_known:event.characters_known!==false,labels:(event.labels||[]).filter(label=>['email','phone','iban','card','social_id','ip','source_code','medical','keyword','ssn_us','custom'].includes(label)).slice(0,16)};
  for(const key of ['policy_revision','catalog_revision','body_bytes']){appendMeasurement(event,output,key);}
  if(modelObservation&&event.model!==undefined){if(typeof event.model!=='string'||!/^[A-Za-z0-9._:/-]{1,200}$/.test(event.model)){throw new Error('Invalid detection model');}output.model=event.model;}
  // The reasoning effort the request asked for, in its own field: the provider names
  // it separately, and the page only ever shows it fused into a translated label.
  if(modelObservation&&event.effort!==undefined){if(typeof event.effort!=='string'||!/^[a-z0-9_-]{1,40}$/.test(event.effort)){throw new Error('Invalid detection effort');}output.effort=event.effort;}
  return output;
 }
 // What an outgoing request said about an exchange that is already durable. The
 // prompt is recorded BEFORE it is sent, so that nothing leaves without a trace; the
 // conversation identifier, the model and the effort only exist once the request is
 // on the wire. They are handed over here, against the event the agent already holds,
 // and never as a second event: the anti-duplicate rule of the fusion is untouched.

 async function replayReceipt(delivery_id,submission,authority,observed){
  const receipt=await bridge({op:'event_receipt',tool,delivery_id,authority});
  if(receipt?.ok!==true||receipt.delivery_id!==delivery_id){throw new Error('Receipt lookup rejected');}
  if(receipt.durable===true){
   if(!receiptID(receipt.id)){throw new Error('Receipt identity absent');}
   // Completion is attempted once and is never queued: browser storage only holds
   // the content-free event projection, not the conversation identifier.
   const completion=observed?completionOf(observed):null;
   if(completion){try{await bridge({op:'event_complete',tool,delivery_id,completion,authority});}catch{}}
   return receipt;
  }
  if(receipt.durable!==false){throw new Error('Receipt state absent');}
  return submission?receipt:null;
 }
 async function deliver(event,delivery_id,retry,submission,authority,observed){
  await requireAuthority(authority);
  if(retry&&authority===null){throw new Error('Legacy replay unavailable');}
  if(retry){const receipt=await replayReceipt(delivery_id,submission,authority,observed);if(receipt){return receipt;}}
  const result=await bridge({op:'event_v2',tool,event,delivery_id,authority});
  if(result?.ok!==true||!receiptID(result.id)){throw new Error('Event delivery receipt absent');}
  return result;
 }
 const fusion=new Fusion(deliver,()=>Date.now(),async entries=>{
  const pending=entries.map(entry=>({...entry,event:metadata(entry.event)}));
  if(new TextEncoder().encode(JSON.stringify(pending)).length>1024*1024){throw new Error('Pending detection metadata full');}
  await api.storage.local.set({detectorPending:pending});
 });
 const pendingReady=(async()=>{const stored=await api.storage.local.get('detectorPending');let entries=stored.detectorPending||[];
  const unbound=entries.filter(entry=>!validAuthority(entry?.authority));if(unbound.length){entries=entries.filter(entry=>validAuthority(entry?.authority));await change(()=>{diagnostics.pending_dropped=(diagnostics.pending_dropped||0)+unbound.length;diagnostics.last_error='unbound_pending_authority';},{detectorPending:entries});}
  for(const entry of entries){if(Object.keys(entry).some(key=>!['id','event','identity','source','at','attempted','submission','authority'].includes(key))){throw new Error('Unexpected pending detection field');}const clean=metadata(entry.event);if(Object.keys(entry.event).length!==Object.keys(clean).length||Object.keys(clean).some(key=>JSON.stringify(clean[key])!==JSON.stringify(entry.event[key]))){throw new Error('Pending detection contains undeclared data');}}
  fusion.restore(entries);
 })();
 // Keep a read failure observable by every operation without an unhandled task.
 void pendingReady.catch(()=>{});

 function senderIdentity(sender){const id=A.resolve(sender.url)?.id;if(!id){throw new Error('Detection provider unavailable');}return identity({tabId:sender.tab.id,documentId:sender.documentId,frameId:sender.frameId},id);}
 // A presence entry names a platform the catalogue does NOT cover: it is
 // therefore never an enabled service, and the filter below would silently drop
 // it on the first replay — precisely the silent failure this project spends its
 // time hunting.
 async function replay(){await pendingReady;const policy=getPolicy();if(!policy){return;}if(!policy.config.collection?.enabled){await fusion.clear();return;}await fusion.retain(entry=>entry.source==='presence'||policy.config.services?.some(service=>service.enabled&&service.domains.includes(entry.event.provider)));await fusion.flush();}
 function schedule(){setTimeout(()=>{void replay().catch(()=>{});},3100);}
 async function prepareSubmit(event,sender,authority){if(authority===undefined){authority=await currentAuthority(api);}await requireAuthority(authority);await ready;await pendingReady;const id=A.resolve(sender.url)?.id;if(!id){throw new Error('Detection provider unavailable');}await count(id,'prompts_dom',revision,catalogState,authority);event.catalog_revision=revision;event.detector='dom';return fusion.prepare(event,senderIdentity(sender),authority);}
 async function confirmSubmit(delivery_id){await fusion.acknowledge(delivery_id);}
 function releaseSubmit(delivery_id){fusion.release(delivery_id);schedule();}
 async function candidate(domain,signals,authority){
  const policy=getPolicy();if(!policy?.config.discovery?.enabled||policy.config.discovery.ignored_domains?.includes(domain)||excludedDomains.includes(domain)){return;}
  if(!/^[a-z0-9.-]{1,253}$/.test(domain)||!domain.includes('.')||domain.endsWith('.local')||domain.endsWith('.internal')||/^[0-9.]+$/.test(domain)){return;}
  const at=Date.now(),observedRevision=revision,observedState=catalogState;if(authority===undefined){authority=await currentAuthority(api);}return change(()=>{observe(at,observedRevision,observedState,authority);if(!health.candidates[domain]&&Object.keys(health.candidates).length>=128){return;}const row=health.candidates[domain]||={domain,signals:[],count:0};row.count=Math.min(1e6,row.count+1);row.signals=[...new Set([...row.signals,...signals])];});
 }
 async function syncContentScripts(){
  if(api.scripting&&registeredRevision!==revision){
   const ids=(await api.scripting.getRegisteredContentScripts()).filter(s=>s.id.startsWith('milvago-detection-')).map(s=>s.id);
   if(ids.length){await api.scripting.unregisterContentScripts({ids});}
   const builtins=new Set(api.runtime.getManifest().content_scripts.flatMap(s=>s.matches));
   const matches=catalog?.providers.flatMap(p=>[...p.domains,...p.aliases].map(d=>'https://'+d+'/*')).filter(m=>!builtins.has(m))||[];
   if(matches.length){await api.scripting.registerContentScripts([{id:'milvago-detection-catalog',matches,js:['adapters.js','capture.js'],runAt:'document_start',allFrames:false,persistAcrossSessions:false}]);}
   registeredRevision=revision;for(const tab of await api.tabs.query({})){if(A.resolve(tab.url)){await api.scripting.executeScript({target:{tabId:tab.id},files:['adapters.js','capture.js']}).catch(()=>{});}}
  }
 }
 async function refresh(){
  const authority=await currentAuthority(api),answer=await bridge({op:'catalog',tool,authority});await ready;await requireAuthority(authority);
  // This package only looks at the providers it bundles: a larger catalogue
  // — published on the instance or imported from the publisher — loses what it
  // adds here, otherwise `registerContentScripts` would inject capture on sites
  // this edition has neither selectors nor qualification for.
  const served=narrowCatalog(answer.catalog),nextCatalog=served||factoryCatalog,nextRevision=answer.revision||0;
  const hash=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(JSON.stringify(nextCatalog))))).map(v=>v.toString(16).padStart(2,'0')).join('');
  await change(()=>{if(catalogIdentity?.authority===authority&&catalogIdentity.revision===nextRevision&&catalogIdentity.hash!==hash){throw new Error('catalog changed at identical revision');}catalogIdentity={revision:nextRevision,hash,authority};});
  catalog=nextCatalog;revision=nextRevision;catalogState=answer.catalog_state||'missing';excludedDomains=answer.excluded_domains||[];expires=Date.parse(answer.expires_at)||0;A.applyCatalog(served);
  await syncContentScripts();
  await change(()=>{
   if(!getPolicy()?.config.discovery?.enabled){health.candidates={};outbox=outbox.filter(batch=>{if(batch.candidates?.length){drop('candidate_consent_withdrawn',batch);return false;}return true;});}
   const now=Date.now();if(health.start&&(Date.parse(health.start)<now-30*DAY||Date.parse(health.end)>now+60000)){drop('invalid_observation_window',health);health=emptyHealth();}outbox=outbox.filter(batch=>{if(Date.parse(batch.window_start)<now-30*DAY||Date.parse(batch.window_end)>now+60000){drop('invalid_observation_window',batch);return false;}return true;});
   if(!health.start){observe(now,revision,catalogState,authority);}
   if(outbox.length<64){seal();}
  });
  await replay();
  for(const stored of outbox){if(stored.authority!==await currentAuthority(api)){await change(()=>{diagnostics.last_error='health_authority_changed';});continue;}const {authority,...batch}=stored;const result=await bridge({op:'detector_health',tool,batch,authority});if(result.accepted_health_ids?.includes(batch.id)){await change(()=>{outbox=outbox.filter(b=>b.id!==batch.id);});}else {break;}}
 }
 // What the last observed request of a tab said about itself. Model, effort and
 // conversation identifier are attributes of the exchange, not content: attaching them
 // needs no fingerprint pairing and no time window, only the tab they were seen in.
 // Kept here rather than read from the page, so a compromised document cannot name the
 // model its own traffic is attributed to.
 const TAB_TTL=30*60*1000,TABS=64;
 const seenByTab=new Map();
 function remember(tabId,provider,hit){
  if(typeof tabId!=='number'||tabId<0){return;}
  if(!hit.model&&!hit.effort&&!hit.conversation_id){return;}
  const held=seenByTab.get(tabId);
  const entry=held&&held.provider===provider?held:{provider};
  // Model and effort describe the same request and are replaced together, never
  // merged: a mode change can name a model without naming an effort, and keeping the
  // previous one would attribute it to an exchange that never asked for it.
  if(hit.model||hit.effort){entry.model=hit.model;entry.effort=hit.effort;}
  // The conversation identifier belongs to the thread rather than to one request, and
  // a provider may only state it from the second message onwards, so it persists.
  if(hit.conversation_id){entry.conversation_id=hit.conversation_id;}
  entry.at=Date.now();
  seenByTab.delete(tabId);seenByTab.set(tabId,entry);
  while(seenByTab.size>TABS){seenByTab.delete(seenByTab.keys().next().value);}
 }
 function recall(tabId,provider){
  const entry=seenByTab.get(tabId);
  if(!entry||entry.provider!==provider){return null;}
  if(Date.now()-entry.at>TAB_TTL){seenByTab.delete(tabId);return null;}
  return entry;
 }


 async function dom(event,sender,input){
  await ready;await pendingReady;const id=A.resolve(sender.url)?.id;if(!id){return {ok:false};}
  enrichResponse(event,recall(sender.tab?.id,event.provider));
  const authority=await currentAuthority(api);
  await count(id,metricFor(event.kind),revision,catalogState,authority);
  event.catalog_revision=revision;
  const digest=typeof input?.fingerprint==='string'&&/^[0-9a-f]{64}$/.test(input.fingerprint)?input.fingerprint:null;
  const paired=event.kind==='prompt'&&event.action==='observed'&&digest&&catalog?.providers.some(p=>p.id===id&&p.network.length);
  const captureId=input?.capture_id;
  if(captureId!==undefined&&!receiptID(captureId)){throw new Error('Invalid capture identity');}
  const delivery_id=await fusion.add(event,senderIdentity(sender),digest,'dom',!paired,authority,captureId);
  schedule();return {ok:true,delivery_id};
 }
 async function resumeNetworkReceipt(event,hit,entry,provider){
  if(!hit.fingerprint){return false;}
  const options={frameId:entry.details.frameId||0};
  if(entry.details.documentId){options.documentId=entry.details.documentId;}
  const receipt=await api.tabs.sendMessage(entry.details.tabId,{type:'detection-receipt',fingerprint:hit.fingerprint},options);
  if(receipt?.ok!==true||!(receipt.delivery_id===null||receiptID(receipt.delivery_id))){throw new Error('Document receipt unavailable');}
  if(!receipt.delivery_id){return false;}
  if(!validAuthority(receipt.authority)){throw new Error('Document receipt authority unavailable');}
  await fusion.resume(event,identity(entry.details,provider.id),receipt.delivery_id,receipt.authority);
  return true;
 }
 function networkEvent(hit,provider,policy,entry){
  const event={provider:provider.domains[0],url:'https://'+provider.domains[0]+'/',source:'browser',tool,kind:'prompt',action:'observed',characters:hit.characters,characters_known:hit.characters_known,labels:[],policy_revision:policy.revision,catalog_revision:entry.catalogRevision};
  if(hit.body_bytes!==null){event.body_bytes=hit.body_bytes;}
  if(hit.model){event.model=hit.model;}
  if(hit.effort){event.effort=hit.effort;}
  if(hit.conversation_id){event.conversation_id=hit.conversation_id;}
  // Attached file names only travel when the signed policy asks for them.
  if(hit.files?.length&&policy.config.collection.store_file_names){event.files=hit.files;}
  return event;
 }
 async function deliverNetworkHit(hit,entry,authority){
  const policy=getPolicy(),provider=hit.provider;
  if(policy?.revision!==entry.policyRevision||!policy.config.collection.enabled||!policy.config.services.some(s=>s.enabled&&s.domains.includes(provider.domains[0]))){return;}
  await count(provider.id,'prompts_network',entry.catalogRevision,entry.catalogState,authority);
  const event=networkEvent(hit,provider,policy,entry);
  // The exchange named itself; the response of this tab will carry it too.
  remember(entry.details.tabId,provider.domains[0],hit);
  if(await resumeNetworkReceipt(event,hit,entry,provider)){return;}
  await fusion.add(event,identity(entry.details,provider.id),hit.fingerprint,'network',false,authority);
  schedule();
 }
 async function deliverObserved(hit,entry,mime){
  await ready;await pendingReady;
  if(!hit){return;}
  const bound=await entry.authority;
  if(bound.failed){throw new Error('Observation authority unavailable');}
  const authority=bound.value;await requireAuthority(authority);
  if(hit.candidate){
   const signals=[...hit.signals];
   if(mime==='text/event-stream'){signals.push('sse');}
   if(signals.length){await candidate(hit.candidate,signals,authority);}
   return;
  }
  await deliverNetworkHit(hit,entry,authority);
 }
 try{api.webRequest?.onBeforeRequest?.addListener(details=>{
  const policy=getPolicy();if(!policy||Date.parse(policy.expires_at)<=Date.now()||!policy.config.collection.enabled||details.tabId<0){return;}
  // A single `onBeforeRequest` registration for both paths: presence does not
  // need the body and reads none, but a second listener would make the network
  // path depend on registration order.
  if(details.type==='main_frame'){presence(details,policy);}
  if(!['POST','PUT'].includes(details.method)){return;}
  if(expires&&expires<=Date.now()){catalog=factoryCatalog;revision=0;catalogState='stale';A.applyCatalog(null);}
  const work=(async()=>{
   const hit=await observeRequest(details,catalog,modelObservation);if(hit){return hit;}
   if(!policy.config.discovery?.enabled){return null;}
   let u;try{u=new URL(details.url);if(u.protocol!=='https:'||A.resolve(details.url)){return null;}}catch{return null;}
   return {candidate:u.hostname,signals:await candidateSignals(details,catalog)};
  })();
  if(requests.size<128){requests.set(details.requestId,{work,details:{tabId:details.tabId,documentId:details.documentId,frameId:details.frameId},policyRevision:policy.revision,catalogRevision:revision,catalogState,authority:currentAuthority(api).then(value=>({value}),()=>({failed:true}))});}
 },{urls:['<all_urls>']},['requestBody']);
 api.webRequest?.onHeadersReceived?.addListener(details=>{
  const entry=requests.get(details.requestId);if(!entry){return;}
  if(details.statusCode<200||details.statusCode>=300){requests.delete(details.requestId);return;}
  const mime=(details.responseHeaders||[]).find(h=>h.name.toLowerCase()==='content-type')?.value?.split(';')[0]?.trim().toLowerCase();
  void entry.work.then(hit=>deliverObserved(hit,entry,mime)).catch(()=>{});
  requests.delete(details.requestId);
 },{urls:['<all_urls>']},['responseHeaders']);
 // Presence: a platform the catalogue NAMES without covering it. The worker compares
 // the hostname of the top-level navigation, and never enters the page — no
 // content script registered, no selector, no body read. `known_platforms` never
 // crosses `applyCatalog` or `registerContentScripts`: this separation is what
 // guarantees that adding a platform does not reopen capture on a site the edition
 // does not qualify.
 //
 // A covered provider wins: where the catalogue carries selectors and rules,
 // full capture is worth more than a visit counter, and the same host must not
 // be counted twice.
 const PRESENCE_WINDOW=30*60*1000,PRESENCE_KEYS=256;
 // Index built once per catalogue instance and memoized on object identity: `catalog`
 // is only ever replaced wholesale (init, refresh(), expiry), never mutated in place, so
 // comparing the reference is enough to self-invalidate at all three assignment sites
 // without a call to remember any of them.
 let indexSource=null,hostIndex=null;
 function buildPlatformIndex(source){
  const index=new Map();
  const platforms=source?.known_platforms||[];
  for(let order=0;order<platforms.length;order++){
   const platform=platforms[order];
   const domains=Array.isArray(platform?.domains)?platform.domains:[];
   for(const d of domains){
    if(typeof d!=='string'||!d){continue;}
    // A platform declaring domains:[''] would match every trailing-dot hostname today
    // via endsWith('.'+'') and no longer will, since empty keys are skipped here. No
    // shipped catalogue has one.
    if(!index.has(d)){index.set(d,[]);}
    index.get(d).push({order,platform});
   }
  }
  return index;
 }
 function platformIndex(){if(indexSource!==catalog){indexSource=catalog;hostIndex=buildPlatformIndex(catalog);}return hostIndex;}
 function knownPlatform(url){
  let u;try{u=new URL(url);}catch{return null;}
  if(u.protocol!=='https:'||u.port||A.resolve(url)){return null;}
  const candidates=platformCandidates(platformIndex(),u.hostname);
  candidates.sort((a,b)=>a.order-b.order);
  for(const {platform} of candidates){
   // A shared host is only named under its path prefixes: without them, all of
   // github.com would flag every in-house developer as an AI user.
   const paths=Array.isArray(platform.paths)?platform.paths:[];
   if(paths.length&&!paths.some(p=>glob(p,u.pathname))){continue;}
   return {id:platform.id,provider:platform.domains[0]};
  }
  return null;
 }
 // One visit per platform per half-hour, shared across the whole profile: a
 // reload, a redirect and a restored tab are not three visits. An unavailable
 // storage costs one extra record, never a lost one.
 // Named apart from the unrelated tab-bookkeeping `remember()` above (model/effort/
 // conversation_id recall): both live in `detectionRuntime`'s scope and this one is
 // declared inside the surrounding try block, so reusing the name would shadow that
 // other function for every call site below it, including the one inside the
 // `onHeadersReceived` listener.
 const rememberPresence=async(kept,provider,now)=>{
  kept[provider]=now;
  const keys=Object.keys(kept);
  for(const key of keys.slice(0,Math.max(0,keys.length-PRESENCE_KEYS))){delete kept[key];}
  try{await api.storage.local.set({presence:kept});}catch{}
 };
 let presenceSerial=Promise.resolve();
 function presence(details,policy){
  const match=knownPlatform(details.url);if(!match){return;}
  const operation=presenceSerial.then(async()=>{
   await ready;await pendingReady;
   const eventIdentity=identity({tabId:details.tabId,documentId:details.documentId,frameId:details.frameId},match.id);
   const now=Date.now();
   let held={};try{held=(await api.storage.local.get('presence'))?.presence||{};}catch{}
   const kept={};for(const [key,at] of Object.entries(held)){if(typeof at==='number'&&now-at<PRESENCE_WINDOW){kept[key]=at;}}
   if(match.provider in kept){return;}
   if(fusion.has(eventIdentity,'presence')){
    await rememberPresence(kept,match.provider,now);
    schedule();return;
   }
   // The hostname and nothing else: no address, no conversation, no model, no
   // character count. The agent refuses a presence record that would carry any of
   // that, and the server reduces it anyway.
   // `detector` is set on the event itself, as `prepareSubmit` also does: delivery
   // will rewrite it with the same value, but the pending row must describe
   // itself — that is what `replay` re-reads so it does not discard it.
   // Authority is only read here, for admission: a reload within the half-hour
   // is filtered out earlier without paying for the managed-storage read.
   const authority=await currentAuthority(api);
   const event={provider:match.provider,source:'browser',tool,kind:'navigation',action:'observed',characters:0,characters_known:true,labels:[],detector:'presence',policy_revision:policy.revision,catalog_revision:revision};
   await fusion.add(event,eventIdentity,null,'presence',false,authority);
   await rememberPresence(kept,match.provider,now);
   schedule();
  });presenceSerial=operation.catch(()=>{});
 }
 api.webRequest?.onErrorOccurred?.addListener(d=>requests.delete(d.requestId),{urls:['<all_urls>']});}catch{catalogState='missing';}
 return {refresh,dom,prepareSubmit,confirmSubmit,releaseSubmit,replay,catalog:()=>catalog};
}
