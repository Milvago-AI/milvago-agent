import test from 'node:test';
import {pinAuthority} from './broker.js';
const pin={installation:'00000000-0000-4000-8000-000000000001',edition:'community',origin:'https://instance.example.invalid',organization_anchor:'synthetic-anchor',signing_key:'synthetic-key'};
const authority=await pinAuthority(pin);
import assert from 'node:assert/strict';
import {detectionRuntime} from './detection-runtime.js';

const deliveryID='00000000-0000-4000-8000-000000000011';
const receiptID='00000000-0000-4000-8000-000000000012';
const sender={url:'https://ai.example.invalid/chat',tab:{id:7},documentId:'document-a'};
const policy={revision:1,expires_at:'2099-01-01T00:00:00Z',config:{collection:{enabled:true},discovery:{enabled:false},services:[{enabled:true,domains:['ai.example.invalid']}]}};
const catalog={providers:[{id:'synthetic',label:'Synthetic',domains:['ai.example.invalid'],aliases:[],network:[{host:'ai.example.invalid',path:'/v1/chat',method:'POST',text_path:'prompt',model_path:'model',effort_path:'effort',conversation_path:'conversation_id'}]}]};
const bytes=value=>new TextEncoder().encode(JSON.stringify(value)).buffer;
const tick=()=>new Promise(resolve=>setTimeout(resolve,0));

function fixture({storage={},receipt=null,durableReceipt=false,failCompletion=false}={}){
 const listeners={},calls=[];let currentReceipt=receipt;
 globalThis.MilvagoAdapters={resolve:()=>({id:'synthetic'}),applyCatalog:()=>{}};
 const api={
  runtime:{getManifest:()=>({version:'0.5.8',content_scripts:[]})},
  storage:{managed:{async get(){return {milvago_pin:JSON.stringify(pin)}}},local:{async get(){return structuredClone(storage);},async set(value){Object.assign(storage,structuredClone(value));}}},
  tabs:{async sendMessage(){return {ok:true,delivery_id:currentReceipt,authority};}},
  webRequest:{
   onBeforeRequest:{addListener(listener){listeners.before=listener;}},
   onHeadersReceived:{addListener(listener){listeners.headers=listener;}},
   onErrorOccurred:{addListener(listener){listeners.error=listener;}},
  },
 };
 const bridge=async request=>{
  calls.push(structuredClone(request));
  if(request.op==='catalog'){return {revision:1,catalog_state:'ok',catalog,expires_at:'2099-01-01T00:00:00Z'};}
  if(request.op==='event_receipt'){return {ok:true,durable:durableReceipt,delivery_id:request.delivery_id,...(durableReceipt?{id:receiptID}:{})};}
  if(request.op==='event_v2'){return {ok:true,durable:true,delivery_id:request.delivery_id,id:receiptID};}
  if(request.op==='event_complete'){if(failCompletion){throw new Error('completion refused');}return {ok:true,applied:true};}
  if(request.op==='detector_health'){return {accepted_health_ids:[request.batch.id]};}
  throw new Error('unexpected bridge operation '+request.op);
 };
 return {runtime:detectionRuntime(api,bridge,'firefox',()=>policy),listeners,calls,storage,setReceipt(value){currentReceipt=value;}};
}

// `expect` names the bridge operation the request must produce -- that one is awaited,
// not the first call to land, since a receipt lookup can precede the completion it leads
// to -- or `null` when the request must produce none: a few ticks then suffice instead of
// burning the whole bound on every run.
async function network(f,expect,requestId='network-1',body={prompt:'network prompt'},statusCode=200){
 const before=f.calls.length;
 f.listeners.before({requestId,tabId:7,documentId:'document-a',frameId:0,method:'POST',url:'https://ai.example.invalid/v1/chat',requestBody:{raw:[{bytes:bytes(body)}]}});
 f.listeners.headers({requestId,statusCode,responseHeaders:[{name:'content-type',value:'application/json'}]});
 // The lookup, delivery or completion this request causes sits several awaits away; two
 // bare ticks were not always enough when the whole suite runs in parallel, and the
 // assertions then read the bridge before it had been called.
 if(expect===null){for(let n=0;n<20;n++){await tick();}return;}
 for(let n=0;n<100&&!f.calls.slice(before).some(call=>call.op===expect);n++){await tick();}
 await tick();await tick();
}

test('a DOM-empty receipt creates one network event',async()=>{
 const f=fixture({receipt:null});await f.runtime.refresh();await network(f,null);
 for(let n=0;n<100&&!f.storage.detectorPending?.length;n++){await tick();}assert.equal(f.storage.detectorPending?.length,1);
 await new Promise(resolve=>setTimeout(resolve,3100));await f.runtime.replay();
 assert.equal(f.calls.filter(call=>call.op==='event_v2').length,1);
 assert.equal(f.calls.filter(call=>call.op==='event_receipt').length,0);
});

test('a document receipt uses the signed lookup without a duplicate event',async()=>{
 const f=fixture({receipt:deliveryID,durableReceipt:true});await f.runtime.refresh();
 const id=await f.runtime.prepareSubmit({provider:'ai.example.invalid',kind:'prompt',action:'observed',characters:7,labels:[]},sender);
 f.setReceipt(id);f.runtime.releaseSubmit(id);await network(f,'event_receipt');
 const lookups=f.calls.filter(call=>call.op==='event_receipt');
 assert.equal(lookups.length,1);assert.equal(lookups[0].delivery_id,id);assert.equal(f.calls.filter(call=>call.op==='event_v2').length,0);
});

test('a restarted runtime accepts the persistent document receipt identity',async()=>{
 const storage={};const first=fixture({storage});await first.runtime.refresh();
 const id=await first.runtime.prepareSubmit({provider:'ai.example.invalid',kind:'prompt',action:'observed',characters:7,labels:[]},sender);
 await first.runtime.confirmSubmit(id);assert.deepEqual(storage.detectorPending,[]);
 const restarted=fixture({storage,receipt:id,durableReceipt:true});await restarted.runtime.refresh();await network(restarted,'event_receipt');
 assert.equal(restarted.calls.filter(call=>call.op==='event_receipt').at(-1).delivery_id,id);
 assert.equal(restarted.calls.filter(call=>call.op==='event_v2').length,0);
});

test('an ambiguous content response creates no new event identity',async()=>{
 const f=fixture();await f.runtime.refresh();await network(f,null,'ambiguous',{prompt:'ignored'},500);
 await tick();assert.equal(f.calls.some(call=>call.op==='event_v2'||call.op==='event_receipt'),false);
});

// What the request said about an exchange already made durable. The prompt is recorded
// BEFORE it is sent, so the conversation it created, the model and the effort only
// exist afterwards. They must reach the event as a completion -- exactly one, and never
// as a second prompt.
test('a durable submission is completed by its request, never duplicated',async()=>{
 const f=fixture({receipt:deliveryID,durableReceipt:true});await f.runtime.refresh();
 const id=await f.runtime.prepareSubmit({provider:'ai.example.invalid',kind:'prompt',action:'observed',characters:7,labels:[]},sender);
 f.setReceipt(id);f.runtime.releaseSubmit(id);
 await network(f,'event_complete','network-complete',{prompt:'network prompt',model:'synthetic-model',effort:'high',conversation_id:'synthetic-conversation'});
 assert.equal(f.calls.filter(call=>call.op==='event_v2').length,0,'a second prompt was delivered');
 const completions=f.calls.filter(call=>call.op==='event_complete');
 assert.equal(completions.length,1);
 assert.equal(completions[0].delivery_id,id);
 assert.deepEqual(completions[0].completion,{model:'synthetic-model',effort:'high',conversation_id:'synthetic-conversation',body_bytes:completions[0].completion.body_bytes});
 assert.ok(Number.isSafeInteger(completions[0].completion.body_bytes));
 // Nothing of the exchange is written to browser storage, completion included.
 assert.equal(JSON.stringify(f.storage).includes('synthetic-conversation'),false);
});

// A request that names neither model nor conversation still measured its own body,
// which a send recorded before it left could not know. It says that and nothing else.
test('a request says only what it observed',async()=>{
 const f=fixture({receipt:deliveryID,durableReceipt:true});await f.runtime.refresh();
 const id=await f.runtime.prepareSubmit({provider:'ai.example.invalid',kind:'prompt',action:'observed',characters:7,labels:[]},sender);
 f.setReceipt(id);f.runtime.releaseSubmit(id);
 await network(f,'event_complete','network-bare',{prompt:'network prompt'});
 const completions=f.calls.filter(call=>call.op==='event_complete');
 assert.equal(completions.length,1);
 assert.deepEqual(Object.keys(completions[0].completion),['body_bytes']);
});

test('an unplaceable completion never costs the event its receipt',async()=>{
 const f=fixture({receipt:deliveryID,durableReceipt:true,failCompletion:true});await f.runtime.refresh();
 const id=await f.runtime.prepareSubmit({provider:'ai.example.invalid',kind:'prompt',action:'observed',characters:7,labels:[]},sender);
 f.setReceipt(id);f.runtime.releaseSubmit(id);
 await network(f,'event_complete','network-refused',{prompt:'network prompt',model:'synthetic-model'});
 assert.equal(f.calls.filter(call=>call.op==='event_complete').length,1);
 assert.equal(f.calls.filter(call=>call.op==='event_v2').length,0,'a refused completion produced a second prompt');
 assert.equal(f.storage.detectorPending?.length??0,0,'a refused completion kept the delivery pending');
});
