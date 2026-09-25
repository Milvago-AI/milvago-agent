import test from 'node:test';import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,createHash} from 'node:crypto';
import {broker,pinAuthority} from './broker.js';import {detectionRuntime} from './detection-runtime.js';
const pinA={installation:'00000000-0000-4000-8000-000000000001',edition:'community',origin:'https://a.example.invalid',organization_anchor:'anchor-a',signing_key:'key-a'},pinB={...pinA,installation:'00000000-0000-4000-8000-000000000002',origin:'https://b.example.invalid',organization_anchor:'anchor-b'};
const authorityA=await pinAuthority(pinA),authorityB=await pinAuthority(pinB),receiptID='00000000-0000-4000-8000-000000000003';
const event={provider:'ai.example.invalid',source:'browser',tool:'firefox',kind:'response',action:'observed',characters:7,labels:[]},sender={url:'https://ai.example.invalid/',tab:{id:7},documentId:'synthetic-document'};
function fixture(){
 let pin=pinA,lose=false,healthAck=true;const storage={},calls=[],hooks={};
 globalThis.MilvagoAdapters={resolve:()=>({id:'synthetic'}),applyCatalog:()=>{}};
 const policy={revision:1,expires_at:'2099-01-01T00:00:00Z',config:{collection:{enabled:true},discovery:{enabled:false},services:[{enabled:true,domains:['ai.example.invalid']}]}};
 const api={runtime:{getManifest:()=>({version:'0.5.8',content_scripts:[]})},storage:{managed:{async get(){return {milvago_pin:pin===null?undefined:JSON.stringify(pin)}}},local:{async get(){return structuredClone(storage)},async set(v){Object.assign(storage,structuredClone(v))}}},webRequest:Object.fromEntries(['onBeforeRequest','onHeadersReceived','onErrorOccurred'].map(k=>[k,{addListener:f=>hooks[k]=f}])),tabs:{async sendMessage(){return {ok:true,delivery_id:receiptID,authority:authorityA}}}};
 const bridge=async q=>{const authority=pin===null?null:await pinAuthority(pin);calls.push({authority,q:structuredClone(q)});
  if(q.op==='catalog'){return {revision:1,catalog_state:'ok',catalog:{providers:[{id:'synthetic',label:'Synthetic',domains:['ai.example.invalid'],aliases:[],network:[{host:'ai.example.invalid',path:'/send',method:'POST',text_path:'message'}]}]}};}
  if(q.op==='detector_health'){return {accepted_health_ids:healthAck?[q.batch.id]:[]};}
  if(q.op==='event_receipt'){return {ok:true,durable:authority===authorityA,delivery_id:q.delivery_id,id:receiptID};}
  if(q.op==='event_v2'){if(lose){throw Error('lost ack after synthetic custody');}return {ok:true,id:receiptID}}throw Error('unexpected op');};
 return {api,storage,calls,hooks,policy,runtime:()=>detectionRuntime(api,bridge,'firefox',()=>policy),pin:v=>pin=v,lose:v=>lose=v,healthAck:v=>healthAck=v};
}
test('lost acknowledgement metadata stays held across destination replacement and recovers at original pin',async()=>{
 const f=fixture(),r=f.runtime();await r.refresh();f.lose(true);await assert.rejects(r.dom({...event},sender,{}),/lost ack/);
 assert.equal(f.storage.detectorPending.length,1);assert.equal(f.storage.detectorPending[0].authority,authorityA);const id=f.storage.detectorPending[0].id;
 f.pin(pinB);f.lose(false);const next=f.runtime();await assert.rejects(next.refresh(),/authority changed/);
 assert.equal(f.calls.filter(c=>c.authority===authorityB&&['event_v2','event_receipt'].includes(c.q.op)).length,0);assert.equal(f.storage.detectorPending[0].id,id);assert.equal(f.storage.detectorHealth.diagnostics.last_error,'authority_changed');
 f.pin(pinA);await next.refresh();assert.equal(f.storage.detectorPending.length,0);assert.equal(f.calls.filter(c=>c.q.op==='event_v2').length,1);
});
test('health sidecars stay held for A while B receives only newly created B batches',async()=>{
 const f=fixture(),r=f.runtime();f.healthAck(false);await r.refresh();assert.equal(f.storage.detectorHealth.outbox.length,1);const id=f.storage.detectorHealth.outbox[0].id;
 f.pin(pinB);f.healthAck(true);const next=f.runtime();await next.refresh();assert.equal(f.storage.detectorHealth.outbox[0].id,id);assert.equal(f.storage.detectorHealth.diagnostics.last_error,'health_authority_changed');
 const sentB=f.calls.filter(c=>c.authority===authorityB&&c.q.op==='detector_health');assert.equal(sentB.length,1);assert.equal(sentB[0].q.authority,authorityB);assert.equal(Object.hasOwn(sentB[0].q.batch,'authority'),false);assert.notEqual(sentB[0].q.batch.id,id);
 f.pin(pinA);await next.refresh();assert.equal(f.storage.detectorHealth.outbox.length,0);
});
test('legacy unbound persisted entries are counted and never adopted under a new managed pin',async()=>{
 const f=fixture();f.storage.detectorPending=[{id:receiptID,event,identity:'7|doc|synthetic',source:'dom',attempted:true,at:0}];
 const r=f.runtime();await r.refresh();assert.equal(f.storage.detectorHealth.diagnostics.pending_dropped,1);assert.deepEqual(f.storage.detectorPending,[]);assert.equal(f.calls.some(c=>['event_v2','event_receipt'].includes(c.q.op)),false);
});
test('collection withdrawal clears a held pending entry without sending it to B',async()=>{
 const f=fixture(),r=f.runtime();await r.refresh();f.lose(true);await assert.rejects(r.dom({...event},sender,{}));f.pin(pinB);f.policy.config.collection.enabled=false;await f.runtime().refresh();assert.deepEqual(f.storage.detectorPending,[]);assert.equal(f.calls.filter(c=>c.authority===authorityB&&c.q.op==='event_v2').length,0);
});
test('content receipt carrying authority A cannot create a fresh network event under B',async()=>{
 const f=fixture();f.pin(pinB);const r=f.runtime();await r.refresh();f.hooks.onBeforeRequest({requestId:'synthetic-request',tabId:7,frameId:0,documentId:'synthetic-document',method:'POST',url:'https://ai.example.invalid/send',requestBody:{raw:[{bytes:new TextEncoder().encode(JSON.stringify({message:'synthetic'})).buffer}]}});
 f.hooks.onHeadersReceived({requestId:'synthetic-request',statusCode:200,responseHeaders:[]});
 for(let n=0;n<100&&f.storage.detectorHealth.diagnostics.last_error!=='authority_changed';n++){await new Promise(resolve=>setTimeout(resolve,10));}
 assert.equal(f.storage.detectorHealth.diagnostics.last_error,'authority_changed');assert.equal(f.calls.filter(c=>['event_v2','event_receipt'].includes(c.q.op)).length,0);assert.equal(f.storage.detectorPending[0].authority,authorityA);
});
test('managed pin replacement before native exchange sends no request',async()=>{
 let reads=0,sends=0;const api={storage:{managed:{async get(){return {milvago_pin:JSON.stringify(++reads===1?pinA:pinB)}}}}};
 await assert.rejects(broker(api,async()=>{sends++;return{}},{protocol:2,op:'browser_policy',challenge:'synthetic',tool:'firefox'},authorityA),/pin changed/);assert.equal(sends,0);
});
test('every managed inner operation carries the exact authority hash bound into its signed request',async()=>{
 const {publicKey,privateKey}=generateKeyPairSync('ed25519'),pin={...pinA,signing_key:publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64')};
 const authority=await pinAuthority(pin),expected=createHash('sha256').update(JSON.stringify([pin.installation,pin.edition,pin.origin,pin.organization_anchor,pin.signing_key])).digest('hex');assert.equal(authority,expected);
 const api={storage:{managed:{async get(){return {milvago_pin:JSON.stringify(pin)}}}}};let count=0;
 for(const op of ['browser_policy','browser_catalog','browser_receipt','browser_event','browser_submit','browser_health','browser_inspect']){
  const inner={protocol:2,op,tool:'firefox',challenge:'synthetic-'+op};
  const answer=await broker(api,async request=>{count++;const raw=Buffer.from(request.body,'base64'),parsed=JSON.parse(raw);assert.equal(parsed.expected_authority,expected);
   const body=Buffer.from(JSON.stringify({kind:'milvago.browser-response.v2',protocol:2,pin,challenge:inner.challenge,request_hash:createHash('sha256').update(raw).digest('hex'),generation:1,mode:'connected',reply:{ok:true}}));return {ok:true,protocol:2,signed:{payload:body.toString('base64'),signature:sign(null,body,privateKey).toString('base64')}};
  },inner,expected);assert.equal(answer.authority,expected);
 }assert.equal(count,7);
 let sends=0;await assert.rejects(broker(api,async()=>{sends++},{protocol:2,op:'browser_event'},authorityB),/authority changed/);assert.equal(sends,0);
});
