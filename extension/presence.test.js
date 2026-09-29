import test from 'node:test';
import assert from 'node:assert/strict';
import {pinAuthority} from './broker.js';
import {detectionRuntime} from './detection-runtime.js';

const pin={installation:'00000000-0000-4000-8000-000000000001',edition:'community',origin:'https://instance.example.invalid',organization_anchor:'synthetic-anchor',signing_key:'synthetic-key'};
await pinAuthority(pin);
const tick=()=>new Promise(resolve=>setTimeout(resolve,0));
const policy={revision:1,expires_at:'2099-01-01T00:00:00Z',config:{collection:{enabled:true},discovery:{enabled:false},services:[{enabled:true,domains:['ai.example.invalid']}]}};
// One covered provider and three platforms the catalogue names without covering: a
// dedicated host, a host also reached through a subdomain, and a shared host that only
// counts under its prefix.
const catalog={
 providers:[{id:'synthetic',label:'Synthetic',domains:['ai.example.invalid'],aliases:[],network:[]}],
 known_platforms:[
  {id:'aggregator',label:'Aggregator',domains:['aggregator.example.invalid']},
  {id:'studio',label:'Studio',domains:['studio.example.invalid']},
  {id:'forge',label:'Forge',domains:['forge.example.invalid'],paths:['/assistant*']},
 ],
};
// A second, separate host shared by two platforms in catalogue order: the first
// path-restricted, the second not. Kept apart from `catalog` above so the ordering
// test below cannot be affected by the other fixtures' host names.
const orderedCatalog={
 providers:[{id:'synthetic',label:'Synthetic',domains:['ai.example.invalid'],aliases:[],network:[]}],
 known_platforms:[
  {id:'forge-ai',label:'Forge AI',domains:['forge.example.invalid'],paths:['/assistant*']},
  {id:'forge-all',label:'Forge',domains:['forge.example.invalid']},
 ],
};

function fixture({storage={},failPresenceWrites=false,served=catalog,current=()=>policy,wait}={}){
 const listeners={},calls=[];
 // resolve() is how the adapters recognize a covered provider; only the covered domain
 // answers, exactly as in the packaged extension.
 globalThis.MilvagoAdapters={resolve:url=>String(url).includes('ai.example.invalid')?{id:'synthetic'}:null,applyCatalog:()=>{}};
 const api={
  runtime:{getManifest:()=>({version:'0.5.8',content_scripts:[]})},
  storage:{managed:{async get(){return {milvago_pin:JSON.stringify(pin)}}},local:{async get(){return structuredClone(storage);},async set(value){if(failPresenceWrites&&Object.hasOwn(value,'presence')){throw new Error('synthetic presence write failure');}Object.assign(storage,structuredClone(value));}}},
  tabs:{async sendMessage(){return {ok:true,delivery_id:null};}},
  webRequest:{
   onBeforeRequest:{addListener(listener){listeners.before=listener;}},
   onHeadersReceived:{addListener(listener){listeners.headers=listener;}},
   onErrorOccurred:{addListener(listener){listeners.error=listener;}},
  },
 };
 const bridge=async request=>{
  calls.push(structuredClone(request));
  if(request.op==='catalog'){return {revision:1,catalog_state:'ok',catalog:served,expires_at:'2099-01-01T00:00:00Z'};}
  if(request.op==='event_v2'){return {ok:true,durable:true,delivery_id:request.delivery_id,id:'00000000-0000-4000-8000-000000000012'};}
  if(request.op==='detector_health'){return {accepted_health_ids:[request.batch.id]};}
  throw new Error('unexpected bridge operation '+request.op);
 };
 return {runtime:detectionRuntime(api,bridge,'firefox',current,wait),listeners,calls,storage};
}

// A top-level navigation, then long enough for the queue to settle. The queue is what the
// negative cases read: Fusion only delivers three seconds after a row is recorded, so
// proving that nothing was RECORDED costs no wall clock and says the same thing.
async function visit(f,url,requestId='nav-1'){
 f.listeners.before({requestId,tabId:7,documentId:'document-a',frameId:0,method:'GET',type:'main_frame',url});
 for(let n=0;n<50;n++){await tick();}
}
const queued=f=>f.storage.detectorPending?.length??0;

test('a known platform is reported as reached, and nothing of the page is', async()=>{
 const f=fixture();await f.runtime.refresh();
 await visit(f,'https://aggregator.example.invalid/chat/123?q=secret');
 assert.equal(queued(f),1);
 await new Promise(resolve=>setTimeout(resolve,3100));
 await f.runtime.replay();
 const events=f.calls.filter(call=>call.op==='event_v2').map(call=>call.event);
 assert.equal(events.length,1);
 const event=events[0];
 assert.equal(event.provider,'aggregator.example.invalid');
 assert.equal(event.detector,'presence');
 assert.equal(event.kind,'navigation');
 assert.equal(event.characters,0);
 // The address carried a conversation and a query string; neither may survive, in the
 // delivered record or in browser storage.
 assert.equal(event.url,undefined);
 assert.equal(event.conversation_id,undefined);
 assert.equal(JSON.stringify(f.storage).includes('secret'),false);
});

// Measured on 2026-09-29: a visit 38 s after an extension restart left no trace while
// the same visit later was reported. The worker had no policy yet when it navigated.
test('a visit made before the first policy is recorded once the policy arrives', async()=>{
 let loaded,waits=0;
 const f=fixture({current:()=>loaded,wait:async()=>{waits++;await new Promise(resolve=>setTimeout(resolve,20));loaded=policy;return loaded;}});
 await f.runtime.refresh();
 await visit(f,'https://aggregator.example.invalid/');
 for(let n=0;n<20&&!queued(f);n++){await new Promise(resolve=>setTimeout(resolve,10));}
 assert.equal(waits,1);
 assert.equal(queued(f),1);
});

// Community ignores supplied platform blocks and reports an observed visit.
test('a supplied platform block cannot mark a Community visit as blocked', async()=>{
 const blocked={...policy,revision:2,config:{...policy.config,blocked_platforms:[{id:'aggregator',domains:['aggregator.example.invalid']}]}};
 const f=fixture({current:()=>blocked,storage:{}});await f.runtime.refresh();
 await visit(f,'https://aggregator.example.invalid/');
 assert.equal(queued(f),1);
 assert.equal(f.storage.detectorPending[0].event.action,'observed');
});

test('a visit is dropped when no policy can be obtained', async()=>{
 const f=fixture({current:()=>undefined,wait:async()=>null});
 await f.runtime.refresh();
 await visit(f,'https://aggregator.example.invalid/');
 assert.equal(queued(f),0);
 assert.equal(f.storage.presence,undefined,'no half-hour window is spent on a visit that was not recorded');
});

test('a subdomain of a named platform counts, and one visit per half hour', async()=>{
 const f=fixture();await f.runtime.refresh();
 await visit(f,'https://eu.studio.example.invalid/','nav-a');
 assert.equal(queued(f),1);
 const first=f.storage.presence['studio.example.invalid'];
 await visit(f,'https://studio.example.invalid/other','nav-b');
 assert.equal(queued(f),1);
 assert.equal(f.storage.presence['studio.example.invalid'],first,'a duplicate does not move the window');
});

test('a persisted presence restores by its source without a detector field',async()=>{
 const first=fixture();await first.runtime.refresh();await visit(first,'https://aggregator.example.invalid/');
 const storage=structuredClone(first.storage);assert.equal(storage.detectorPending[0].event.detector,undefined);
 storage.detectorPending[0].at=Date.now()-4000;
 const reopened=fixture({storage});await reopened.runtime.refresh();await reopened.runtime.replay();
 const events=reopened.calls.filter(call=>call.op==='event_v2');assert.equal(events.length,1);assert.equal(events[0].event.detector,'presence');
});

test('concurrent tabs serialize presence admission',async()=>{
 const f=fixture();await f.runtime.refresh();
 f.listeners.before({requestId:'one',tabId:7,documentId:'one',frameId:0,method:'GET',type:'main_frame',url:'https://aggregator.example.invalid/'});
 f.listeners.before({requestId:'two',tabId:8,documentId:'two',frameId:0,method:'GET',type:'main_frame',url:'https://aggregator.example.invalid/'});
 for(let n=0;n<100;n++){await tick();}
 assert.equal(queued(f),1);
});

test('a failed dedupe write finds the equivalent durable presence before retrying',async()=>{
 const f=fixture({failPresenceWrites:true});await f.runtime.refresh();
 await visit(f,'https://aggregator.example.invalid/','first');assert.equal(queued(f),1);
 await visit(f,'https://aggregator.example.invalid/','second');assert.equal(queued(f),1);
});

test('a covered provider silences presence: capture already says more', async()=>{
 const f=fixture();await f.runtime.refresh();
 await visit(f,'https://ai.example.invalid/chat');
 assert.equal(queued(f),0);
});

test('a shared host counts only under its declared prefix', async()=>{
 const f=fixture();await f.runtime.refresh();
 await visit(f,'https://forge.example.invalid/teams/repo','nav-out');
 assert.equal(queued(f),0);
 await visit(f,'https://forge.example.invalid/assistant/session','nav-in');
 assert.equal(queued(f),1);
});

// Two platforms sharing one host, the first carrying paths, the second not. Today's
// catalogue-order loop tries `forge-ai` first: its path matches `/assistant/x`, so it
// wins outright; its path does NOT match `/teams`, and that mismatch is a skip, not a
// rejection, so the broader `forge-all` right behind it still matches. An index that
// grouped candidates by host and stopped at the first path mismatch, instead of
// preserving catalogue order across the whole group, would turn the second case into
// "no match" -- exactly what these two fixtures, run in isolation so neither's presence
// write can shadow the other's, would catch. Both platforms declare the same single
// domain, so the delivered `provider` cannot tell them apart; whether a report was
// produced at all is what distinguishes a match from "no match" here.
test('a path mismatch on a shared host is a skip, not a rejection: catalogue order still lets a later platform match',async()=>{
 const withPath=fixture({served:orderedCatalog});await withPath.runtime.refresh();
 await visit(withPath,'https://forge.example.invalid/assistant/x','nav-forge-ai');
 assert.equal(queued(withPath),1,'forge-ai matches: its path covers /assistant/x');
 const withoutPath=fixture({served:orderedCatalog});await withoutPath.runtime.refresh();
 await visit(withoutPath,'https://forge.example.invalid/teams','nav-forge-all');
 assert.equal(queued(withoutPath),1,'forge-all matches: forge-ai\'s path mismatch is skipped, not terminal');
});

test('an unnamed host stays unknown to presence', async()=>{
 const f=fixture();await f.runtime.refresh();
 await visit(f,'https://unlisted.example.invalid/chat');
 assert.equal(queued(f),0);
});

test('a subframe is not a visit, and neither is a port or a plain-text host', async()=>{
 const f=fixture();await f.runtime.refresh();
 f.listeners.before({requestId:'sub',tabId:7,documentId:'document-a',frameId:1,method:'GET',type:'sub_frame',url:'https://aggregator.example.invalid/'});
 for(let n=0;n<50;n++){await tick();}
 assert.equal(queued(f),0);
 await visit(f,'https://aggregator.example.invalid:8443/','nav-port');
 assert.equal(queued(f),0);
 await visit(f,'http://aggregator.example.invalid/','nav-plain');
 assert.equal(queued(f),0);
});
