import {pinAuthority} from './broker.js';
const pin={installation:'00000000-0000-4000-8000-000000000010',edition:'community',origin:'https://instance.example.invalid',organization_anchor:'synthetic-anchor',signing_key:'synthetic-key'};
const authority=await pinAuthority(pin);
import test from 'node:test';
import assert from 'node:assert/strict';
import {detectionRuntime} from './detection-runtime.js';
const DAY=86400000,base=Date.parse('2026-09-12T10:00:00Z');
function fixture(t,saved){
 let now=base,revision=1,label='Synthetic',refuse=false,readRefused=false;
 const stored={value:saved,pending:undefined},sent=[],applied=[],catalogRequests=[];let catalogGate;t.mock.method(Date,'now',()=>now);
 globalThis.MilvagoAdapters={resolve:()=>({id:'synthetic'}),applyCatalog:v=>applied.push(v)};
 const api={runtime:{getManifest:()=>({version:'0.5.8',content_scripts:[]})},storage:{managed:{async get(){return {milvago_pin:JSON.stringify(pin)}}},local:{async get(){if(readRefused){throw Error('storage read refused');}return {detectorHealth:structuredClone(stored.value),detectorPending:structuredClone(stored.pending)}},async set(v){if(refuse){throw Error('storage write refused');}if(Object.hasOwn(v,'detectorHealth')){stored.value=structuredClone(v.detectorHealth);}if(Object.hasOwn(v,'detectorPending')){stored.pending=structuredClone(v.detectorPending)}}}}};
 const policy={config:{discovery:{enabled:true},collection:{enabled:true}}};
 const bridge=async q=>{if(q.op==='catalog'){const value={revision,catalog_state:'ok',catalog:{providers:[{id:'synthetic',label,domains:['ai.example.invalid'],aliases:[],network:[]}]}};catalogRequests.push(value);if(catalogGate){await catalogGate;}return value;}if(q.op==='detector_health'){sent.push(structuredClone(q.batch));return {accepted_health_ids:[q.batch.id]}};if(q.op==='event_receipt'){return {ok:true,durable:false,delivery_id:q.delivery_id};}if(q.op==='event_v2'){return {ok:true,durable:true,delivery_id:q.delivery_id,id:'00000000-0000-4000-8000-000000000001'};}return {ok:true,durable:true}};
 return {runtime:()=>detectionRuntime(api,bridge,'firefox',()=>policy),sent,stored,policy,applied,catalogRequests,setCatalogGate:v=>catalogGate=v,setNow:v=>now=v,setRevision:v=>revision=v,setLabel:v=>label=v,setRefused:v=>refuse=v,setReadRefused:v=>readRefused=v};
}
const navigation=r=>r.dom({provider:'ai.example.invalid',source:'browser',tool:'firefox',kind:'navigation',action:'observed',characters:0,labels:[]},{url:'https://ai.example.invalid/',tab:{id:1}},{});
const observed=sent=>sent.filter(b=>b.providers.some(p=>p.navigations));
test('health keeps observed revision through refresh and cache restart',async t=>{
 const f=fixture(t),r=f.runtime();await r.refresh();await navigation(r);f.setRevision(2);await r.refresh();
 assert.equal(observed(f.sent).length,1);assert.equal(observed(f.sent)[0].catalog_revision,1);
 await navigation(r);await new Promise(resolve=>setImmediate(resolve));assert.equal(f.stored.value.health.revision,2);
 f.setRevision(3);await f.runtime().refresh();assert.equal(observed(f.sent).at(-1).catalog_revision,2);
});
test('wake after 24 hours seals actual observations and continues delivery',async t=>{
 const f=fixture(t),r=f.runtime();await r.refresh();await navigation(r);f.setNow(base+DAY+1);await navigation(r);await r.refresh();
 const batches=observed(f.sent);assert.equal(batches.length,2);assert.equal(batches.reduce((sum,b)=>sum+b.providers[0].navigations,0),2);
 for(const b of batches){assert.ok(Date.parse(b.window_end)-Date.parse(b.window_start)<=DAY);}
 assert.equal(batches[0].window_end,new Date(base).toISOString());assert.equal(f.stored.value.outbox.length,0);
});
test('same revision with modified content refused also after restart',async t=>{
 const f=fixture(t),r=f.runtime();await r.refresh();const before=f.applied.length;f.setLabel('Changed synthetic');
 await assert.rejects(r.refresh(),/identical revision/);await assert.rejects(f.runtime().refresh(),/identical revision/);assert.equal(f.applied.length,before);
});
test('legacy unattributed counters and invalid long head dropped with persisted counts',async t=>{
 const prior={health:{start:new Date(base-DAY*2).toISOString(),providers:{synthetic:{provider:'synthetic',navigations:3}},candidates:{}},outbox:[{id:'synthetic-invalid',catalog_revision:1,window_start:new Date(base-DAY*2).toISOString(),window_end:new Date(base).toISOString(),providers:[{provider:'synthetic',navigations:4}],candidates:[]}]};
 const f=fixture(t,prior),r=f.runtime();await r.refresh();assert.equal(f.sent.some(b=>b.id==='synthetic-invalid'),false);assert.equal(observed(f.sent).length,0);
 assert.deepEqual(f.stored.value.diagnostics,{dropped_batches:2,dropped_observations:7,last_error:'invalid_window'});
 await navigation(r);await r.refresh();assert.equal(observed(f.sent).length,1);
});
test('storage read/write refusals reject refresh without sending unsaved batch',async t=>{
 const f=fixture(t);f.setReadRefused(true);await assert.rejects(f.runtime().refresh(),/storage read refused/);assert.equal(f.sent.length,0);
 f.setReadRefused(false);const r=f.runtime();await r.refresh();const count=f.sent.length;f.setRefused(true);await assert.rejects(r.refresh(),/storage write refused/);assert.equal(f.sent.length,count);
 f.setRefused(false);await r.refresh();assert.equal(f.sent.length,count+1);
});
test('consent withdrawal purges pending candidate metadata before delivery',async t=>{
 const time=new Date(base).toISOString(),candidate={domain:'ai.example.invalid',signals:['sse'],count:2};
 const f=fixture(t,{health:{authority,start:time,end:time,revision:1,state:'ok',providers:{},candidates:{'ai.example.invalid':candidate}},outbox:[{authority,id:'synthetic-pending',tool:'firefox',extension_version:'0.5.8',catalog_revision:1,catalog_state:'ok',window_start:time,window_end:time,providers:[],candidates:[candidate]}]});
 f.policy.config.discovery.enabled=false;const r=f.runtime();await r.refresh();assert.equal(f.sent.length,1);assert.ok(f.sent.every(b=>b.candidates.length===0));assert.deepEqual(f.stored.value.health.candidates,{});assert.equal(f.stored.value.diagnostics.dropped_batches,1);assert.equal(f.stored.value.diagnostics.dropped_observations,2);assert.equal(f.stored.value.diagnostics.last_error,'candidate_consent_withdrawn');
});

test('exactly 24 hours is accepted, backward clock does not poison delivery',async t=>{
 const f=fixture(t),r=f.runtime();await r.refresh();await navigation(r);f.setNow(base+DAY);await navigation(r);await r.refresh();
 const b=observed(f.sent);assert.equal(b.length,1);assert.equal(Date.parse(b[0].window_end)-Date.parse(b[0].window_start),DAY);
 await navigation(r);f.setNow(base);await r.refresh();assert.equal(f.stored.value.diagnostics.dropped_observations,1);assert.equal(f.stored.value.outbox.length,0);
});
test('full persisted outbox drains before a pending observation is sealed next refresh',async t=>{
 const time=new Date(base).toISOString();const outbox=Array.from({length:64},(_,i)=>({authority,id:'synthetic-'+i,tool:'firefox',extension_version:'0.5.8',catalog_revision:1,catalog_state:'ok',window_start:time,window_end:time,providers:[],candidates:[]}));
 const f=fixture(t,{health:{authority,start:time,end:time,revision:1,state:'ok',providers:{synthetic:{provider:'synthetic',navigations:1}},candidates:{}},outbox});const r=f.runtime();
 await r.refresh();assert.equal(f.sent.length,64);assert.equal(f.stored.value.outbox.length,0);assert.equal(f.stored.value.health.providers.synthetic.navigations,1);
 await r.refresh();assert.equal(observed(f.sent).length,1);
});
test('concurrent differing contents at one revision cannot both apply',async t=>{
 const f=fixture(t),r=f.runtime();let release;f.setCatalogGate(new Promise(resolve=>release=resolve));const first=r.refresh();while(f.catalogRequests.length<1){await new Promise(resolve=>setImmediate(resolve));}f.setLabel('Changed concurrent synthetic');const second=r.refresh();while(f.catalogRequests.length<2){await new Promise(resolve=>setImmediate(resolve));}assert.notDeepEqual(f.catalogRequests[0],f.catalogRequests[1]);release();const results=await Promise.allSettled([first,second]);
 assert.equal(results.filter(v=>v.status==='fulfilled').length,1);assert.equal(results.filter(v=>v.status==='rejected').length,1);assert.equal(f.applied.length,1);
});
