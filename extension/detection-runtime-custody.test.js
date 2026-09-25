import {pinAuthority} from './broker.js';
const pin={installation:'00000000-0000-4000-8000-000000000010',edition:'community',origin:'https://instance.example.invalid',organization_anchor:'synthetic-anchor',signing_key:'synthetic-key'};
const authority=await pinAuthority(pin);
import test from 'node:test';
import assert from 'node:assert/strict';
import {detectionRuntime} from './detection-runtime.js';

const deliveryID='00000000-0000-4000-8000-000000000001';
const receiptID='00000000-0000-4000-8000-000000000002';
const sender={url:'https://ai.example.invalid/',tab:{id:7},documentId:'document-a'};
const metadata={provider:'ai.example.invalid',source:'browser',tool:'firefox',kind:'prompt',action:'observed',characters:7,characters_known:true,labels:[],catalog_revision:1};
const pending={authority,id:deliveryID,event:metadata,identity:'7|document-a|synthetic',source:'dom',at:0,attempted:true};

function fixture({storedPending=[],collection=true,storageFailure=false,failRemoval=false,receipt=false}={}){
 const storage={detectorPending:structuredClone(storedPending)},calls=[];
 globalThis.MilvagoAdapters={resolve:()=>({id:'synthetic'}),applyCatalog:()=>{}};
 const api={runtime:{getManifest:()=>({version:'0.5.8',content_scripts:[]})},storage:{managed:{async get(){return {milvago_pin:JSON.stringify(pin)}}},local:{async get(){return structuredClone(storage);},async set(value){if(storageFailure||(failRemoval&&Array.isArray(value.detectorPending)&&value.detectorPending.length===0)){throw new Error('storage refused');}Object.assign(storage,structuredClone(value));}}}};
 const policy={config:{collection:{enabled:collection},discovery:{enabled:false},services:[{enabled:true,domains:['ai.example.invalid']}]}};
 const bridge=async request=>{
  calls.push(structuredClone(request));
  if(request.op==='catalog'){return {revision:1,catalog_state:'ok',catalog:{providers:[{id:'synthetic',label:'Synthetic',domains:['ai.example.invalid'],aliases:[],network:[]}]}};}
  if(request.op==='event_receipt'){return {ok:true,durable:receipt,delivery_id:request.delivery_id,...(receipt?{id:receiptID}:{})};}
  if(request.op==='event_v2'){return {ok:true,durable:true,delivery_id:request.delivery_id,id:receiptID};}
  if(request.op==='detector_health'){return {accepted_health_ids:[request.batch.id]};}
  throw new Error('unexpected bridge operation '+request.op);
 };
 return {runtime:detectionRuntime(api,bridge,'firefox',()=>policy),storage,calls};
}

test('prepareSubmit persists only the whitelist, never content sentinels',async()=>{
 const f=fixture();
 const id=await f.runtime.prepareSubmit({...metadata,prompt:'sentinel-prompt',response:'sentinel-response',files:['sentinel-file'],conversation_id:'sentinel-conversation',correlation_id:'sentinel-correlation',fingerprint:'f'.repeat(64)},sender);
 assert.equal(f.storage.detectorPending.length,1);assert.equal(f.storage.detectorPending[0].id,id);assert.equal(f.storage.detectorPending[0].submission,true);
 const durable=JSON.stringify(f.storage.detectorPending);
 for(const sentinel of ['sentinel-prompt','sentinel-response','sentinel-file','sentinel-conversation','sentinel-correlation','f'.repeat(64)]){assert.equal(durable.includes(sentinel),false);}
 assert.deepEqual(f.storage.detectorPending[0].event,{...metadata,catalog_revision:0});
});

test('an unknown submission receipt is removed without inventing an event',async()=>{
 const submission={...pending,submission:true};const f=fixture({storedPending:[submission],receipt:false});
 await f.runtime.refresh();
 assert.equal(f.calls.filter(call=>call.op==='event_receipt').length,1);assert.equal(f.calls.filter(call=>call.op==='event_v2').length,0);assert.deepEqual(f.storage.detectorPending,[]);
});

test('an observed event with a lost acknowledgement replays exact metadata after restart',async()=>{
 const initial=fixture({failRemoval:true});
 await assert.rejects(initial.runtime.dom(metadata,sender),/storage refused/);
 const saved=structuredClone(initial.storage.detectorPending),first=initial.calls.find(call=>call.op==='event_v2');
 assert.equal(saved.length,1);assert.equal(saved[0].submission,undefined);assert.equal(first.delivery_id,saved[0].id);
 const restarted=fixture({storedPending:saved,receipt:false});await restarted.runtime.refresh();
 const lookup=restarted.calls.find(call=>call.op==='event_receipt'),delivery=restarted.calls.find(call=>call.op==='event_v2');
 assert.equal(lookup.delivery_id,saved[0].id);assert.equal(delivery.delivery_id,saved[0].id);assert.deepEqual(delivery.event,{...metadata,catalog_revision:0,detector:'dom'});assert.deepEqual(restarted.storage.detectorPending,[]);
});

test('a durable receipt prevents a repeated event after restart',async()=>{
 const f=fixture({storedPending:[pending],receipt:true});
 await f.runtime.refresh();
 assert.equal(f.calls.filter(call=>call.op==='event_receipt').length,1);assert.equal(f.calls.filter(call=>call.op==='event_v2').length,0);assert.equal(f.storage.detectorPending.length,0);
});

test('a pending storage refusal stops prepareSubmit before any event service call',async()=>{
 const f=fixture({storageFailure:true});
 await assert.rejects(f.runtime.prepareSubmit(metadata,sender),/storage refused/);
 assert.equal(f.calls.some(call=>call.op==='event_v2'||call.op==='event_receipt'),false);
});

test('withdrawn collection consent purges pending entries without delivery',async()=>{
 const f=fixture({storedPending:[pending],collection:false});
 await f.runtime.refresh();
 assert.deepEqual(f.storage.detectorPending,[]);assert.equal(f.calls.some(call=>call.op==='event_v2'||call.op==='event_receipt'),false);
});
