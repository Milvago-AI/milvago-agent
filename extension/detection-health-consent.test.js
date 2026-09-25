import assert from 'node:assert/strict';import {createHash} from 'node:crypto';
import test from 'node:test';
import {detectionRuntime} from './detection-runtime.js';import {pinAuthority} from './broker.js';
test('lost health acknowledgement then candidate consent withdrawal never rewrites a delivery identity',async()=>{
const pin={installation:'00000000-0000-4000-8000-000000000001',edition:'community',origin:'https://instance.example.invalid',organization_anchor:'synthetic-anchor',signing_key:'synthetic-key'},authority=await pinAuthority(pin),time=new Date().toISOString(),id='00000000-0000-4000-8000-000000000002';
const storage={detectorHealth:{health:{providers:{},candidates:{}},outbox:[{authority,id,tool:'firefox',extension_version:'0.5.8',catalog_revision:1,catalog_state:'ok',window_start:time,window_end:time,providers:[{provider:'synthetic',navigations:2,prompts_network:0,prompts_dom:0,responses_dom:0,candidates:0}],candidates:[{domain:'ai.example.invalid',signals:['json_keys'],count:1}]}]}},seen=new Map(),attempts=[];let collision=0;
globalThis.MilvagoAdapters={resolve:()=>null,applyCatalog:()=>{}};
const api={runtime:{getManifest:()=>({version:'0.5.8',content_scripts:[]})},storage:{managed:{async get(){return {milvago_pin:JSON.stringify(pin)}}},local:{async get(){return structuredClone(storage)},async set(v){Object.assign(storage,structuredClone(v))}}}};
const policy={config:{collection:{enabled:true},discovery:{enabled:true},services:[]}};
const r=detectionRuntime(api,async q=>{if(q.op==='catalog'){return {revision:1,catalog_state:'ok',catalog:{providers:[]}};}if(q.op==='detector_health'){attempts.push(q.batch.id);const hash=createHash('sha256').update(JSON.stringify(q.batch)).digest('hex');if(seen.has(q.batch.id)&&seen.get(q.batch.id)!==hash){collision++;throw Error('health identity collision')}seen.set(q.batch.id,hash);return {accepted_health_ids:[]}};throw Error('unexpected op')},'firefox',()=>policy);
await r.refresh();assert.ok(seen.has(id));assert.equal(storage.detectorHealth.outbox.find(b=>b.id===id).candidates.length,1);
policy.config.discovery.enabled=false;await r.refresh();assert.equal(collision,0);assert.equal(storage.detectorHealth.outbox.some(b=>b.id===id),false);
assert.equal(storage.detectorHealth.diagnostics.dropped_batches,1);assert.equal(storage.detectorHealth.diagnostics.dropped_observations,3);assert.equal(storage.detectorHealth.diagnostics.last_error,'candidate_consent_withdrawn');
policy.config.discovery.enabled=true;await r.refresh();assert.equal(attempts.filter(value=>value===id).length,1);assert.equal(collision,0);
});
