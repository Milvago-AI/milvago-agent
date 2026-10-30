// Real campaign 0.7.12 (2026-10-17): after the browser stopped the idle worker (about 30 s) and started it
// again, the prompts and answers of an open conversation had no model, the next messages too. A provider may
// name its model only on a conversation's first message (claude.ai); what a tab's exchange named was kept in
// the worker's memory only. The session now keeps it: attribution only, bounded, dropped with its tab.
import test from 'node:test';
import assert from 'node:assert/strict';
import './adapters.js';
import {detectionRuntime} from './detection-runtime.js';
import {pinAuthority} from './broker.js';

const enc=new TextEncoder();
const pin={installation:'00000000-0000-4000-8000-000000000031',edition:'community',origin:'https://instance.example.invalid',organization_anchor:'synthetic-anchor',signing_key:'synthetic-key'};
const authority=await pinAuthority(pin);
const policy={revision:1,expires_at:'2099-01-01T00:00:00Z',config:{collection:{enabled:true},discovery:{enabled:false},services:[{enabled:true,domains:['ai.example.invalid']}]}};
const synthetic={providers:[{id:'synthetic',label:'Synthetic',domains:['ai.example.invalid'],aliases:[],network:[{host:'ai.example.invalid',path:'/v1/chat',method:'POST',text_path:'prompt',model_path:'model',effort_path:'effort',conversation_path:'conversation_id'}]}]};

// One browser: its session storage outlives each worker started on it.
function browser({session=true,sessionGet}={}){
 const store={},calls=[];
 return {store,calls,worker(){
  const listeners={removed:[]};
  globalThis.MilvagoAdapters.applyCatalog=()=>{};
  const api={
   runtime:{getManifest:()=>({version:'0.7.12',content_scripts:[]})},
   storage:{managed:{async get(){return {milvago_pin:JSON.stringify(pin)};}},local:{async get(){return {};},async set(){}},
    ...(session?{session:{get:sessionGet||(async key=>structuredClone({[key]:store[key]})),async set(value){Object.assign(store,structuredClone(value));}}}:{})},
   tabs:{async sendMessage(){return {ok:true,delivery_id:null,authority};},onRemoved:{addListener(l){listeners.removed.push(l);}}},
   webRequest:{onBeforeRequest:{addListener(l){listeners.before=l;}},onHeadersReceived:{addListener(l){listeners.headers=l;}},onErrorOccurred:{addListener(l){listeners.error=l;}}},
  };
  const bridge=async request=>{
   calls.push(structuredClone(request));
   if(request.op==='catalog'){return {revision:1,catalog_state:'ok',catalog:synthetic,expires_at:'2099-01-01T00:00:00Z'};}
   if(request.op==='event_v2'){return {ok:true,durable:true,delivery_id:request.delivery_id,id:'00000000-0000-4000-8000-000000000032'};}
   if(request.op==='event_receipt'){return {ok:true,durable:false,delivery_id:request.delivery_id};}
   if(request.op==='detector_health'){return {accepted_health_ids:[request.batch.id]};}
   throw new Error('unexpected bridge operation '+request.op);
  };
  return {runtime:detectionRuntime(api,bridge,'chrome',()=>policy),listeners};
 }};
}
let serial=0;
const prompts=b=>b.calls.filter(c=>c.op==='event_v2'&&c.event.kind==='prompt').map(c=>c.event);
async function send(b,w,body,tabId=7){
 const before=prompts(b).length,id='r'+serial++;
 w.listeners.before({requestId:id,tabId,documentId:'document-'+tabId,frameId:0,method:'POST',url:'https://ai.example.invalid/v1/chat',requestBody:{raw:[{bytes:enc.encode(JSON.stringify(body)).buffer}]}});
 w.listeners.headers({requestId:id,statusCode:200,responseHeaders:[{name:'content-type',value:'application/json'}]});
 for(let n=0;n<400&&prompts(b).length===before;n++){await new Promise(resolve=>setTimeout(resolve,20));}
 return prompts(b).at(-1);
}
async function answer(b,w,conversation_id,tabId=7){
 const resolve=globalThis.MilvagoAdapters.resolve;globalThis.MilvagoAdapters.resolve=()=>({id:'synthetic'});
 try{await w.runtime.dom({provider:'ai.example.invalid',url:'https://ai.example.invalid/',source:'browser',tool:'chrome',kind:'response',action:'observed',characters:4,labels:[],policy_revision:1,...(conversation_id?{conversation_id}:{})},{tab:{id:tabId},documentId:'document-'+tabId,frameId:0,url:'https://ai.example.invalid/c/x'});}
 finally{globalThis.MilvagoAdapters.resolve=resolve;}
 for(let n=0;n<400;n++){const r=b.calls.filter(c=>c.op==='event_v2'&&c.event.kind==='response');if(r.length){return r.at(-1).event;}await new Promise(r=>setTimeout(r,20));}
 return null;
}
async function started(b){const w=b.worker();await w.runtime.refresh();return w;}

test('a restarted worker keeps the model its tab\'s conversation named, never another conversation\'s or tab\'s',{timeout:60000},async()=>{
 const b=browser();
 let w=await started(b);
 assert.equal((await send(b,w,{prompt:'first',model:'fixture-model-4',effort:'high',conversation_id:'thread-1'})).model,'fixture-model-4');
 w=await started(b);
 const next=await send(b,w,{prompt:'second',conversation_id:'thread-1'});
 assert.equal(next.model,'fixture-model-4','follow-up after a restart');assert.equal(next.effort,'high');
 assert.equal((await answer(b,w,'thread-1')).model,'fixture-model-4','its answer too');
 assert.equal((await send(b,w,{prompt:'session opening'})).model,'fixture-model-4','confirmed by this worker: the same-exchange window holds again');
 w=await started(b);
 assert.equal((await send(b,w,{prompt:'other tab',conversation_id:'thread-1'},8)).model,undefined,'another tab');
 assert.equal((await send(b,w,{prompt:'unnamed'})).model,undefined,'no conversation named after a restart: not the same exchange');
 w=await started(b);
 assert.equal((await send(b,w,{prompt:'elsewhere',conversation_id:'thread-2'})).model,undefined,'another conversation');
 w=await started(b);
 assert.equal((await send(b,w,{prompt:'its follow-up',conversation_id:'thread-2'})).model,undefined,'nor its follow-up');
 // A browser may refuse to store an undefined value: none is written (the model cleared above).
 assert.ok(b.store.detectionSeen.every(e=>Object.values(e).every(v=>v!==undefined)&&!('restored' in e)));
});

test('a restored model reaches an answer only of its own conversation',{timeout:60000},async()=>{
 const b=browser();
 let w=await started(b);
 await send(b,w,{prompt:'first',model:'fixture-model-4',conversation_id:'thread-1'});
 w=await started(b);
 assert.equal((await answer(b,w,'thread-1')).model,'fixture-model-4','an answer is the first thing the woken worker sees');
 w=await started(b);
 assert.equal((await answer(b,w,'thread-9')).model,undefined,'the tab moved to another conversation');
 w=await started(b);
 assert.equal((await answer(b,w,undefined)).model,undefined,'a page naming no conversation');
});

test('a closed tab, a stale entry and foreign session contents leave nothing',{timeout:60000},async()=>{
 const b=browser();
 let w=await started(b);
 await send(b,w,{prompt:'first',model:'fixture-model-4',conversation_id:'thread-1'});
 w=await started(b);
 for(const l of w.listeners.removed){l(7);}
 await new Promise(r=>setTimeout(r,50));
 assert.equal(b.store.detectionSeen.some(e=>e.tab===7),false,'dropped from the session with its tab');
 w=await started(b);
 assert.equal((await send(b,w,{prompt:'again',conversation_id:'thread-1'})).model,undefined,'closed tab');
 const at=Date.now();
 const base={tab:7,provider:'ai.example.invalid',model:'fixture-model-4',conversation_id:'thread-1'};
 for(const [label,value] of [['stale',[{...base,at:at-31*60*1000}]],['future',[{...base,at:at+10*60*1000}]],['not a list',{7:{...base,at}}],
  ['long model',[{...base,model:'m'.repeat(513),at}]],['extra field',[{...base,at,decision:'allow'}]],['negative tab',[{...base,tab:-1,at}]],
  ['model object',[{...base,model:{toString:()=>'x'},at}]],['unknown session',[{...base,session:'admin',at}]],['other provider',[{...base,provider:'elsewhere.invalid',at}]]]){
  b.store.detectionSeen=value;w=await started(b);
  assert.equal((await send(b,w,{prompt:'again',conversation_id:'thread-1'})).model,undefined,label);
 }
 b.store.detectionSeen=Array.from({length:5000},(_,n)=>({...base,tab:1000+n,at}));
 w=await started(b);
 await send(b,w,{prompt:'bounded',model:'fixture-model-4',conversation_id:'thread-1'});
 assert.ok(b.store.detectionSeen.length<=64,'at most 64 tabs kept');
});

test('a follow-up processed while the session is still being read waits for it; no session: memory only',{timeout:60000},async()=>{
 let release;const gate=new Promise(r=>{release=r;});
 const b=browser();
 let w=await started(b);
 await send(b,w,{prompt:'first',model:'fixture-model-4',conversation_id:'thread-1'});
 const kept=structuredClone(b.store);
 const slow=browser({sessionGet:async key=>{await gate;return {[key]:kept[key]};}});
 const w2=slow.worker();
 const pending=w2.runtime.refresh().then(()=>send(slow,w2,{prompt:'second',conversation_id:'thread-1'}));
 await new Promise(r=>setTimeout(r,100));release();
 assert.equal((await pending).model,'fixture-model-4');
 const none=browser({session:false});
 w=await started(none);
 await send(none,w,{prompt:'first',model:'fixture-model-4',conversation_id:'thread-1'});
 assert.equal((await send(none,w,{prompt:'second',conversation_id:'thread-1'})).model,'fixture-model-4','same worker');
 w=await started(none);
 assert.equal((await send(none,w,{prompt:'third',conversation_id:'thread-1'})).model,undefined,'restarted without session storage');
});
