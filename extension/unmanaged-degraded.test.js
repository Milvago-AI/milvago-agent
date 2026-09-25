// Unmanaged mode (no `milvago_pin`): the agent that answers is not proven to be the
// organization's own installation. Degraded mode is then CONTENT-FREE — metadata
// only, never a prompt's or a response's text going to the agent — and masking is
// disabled fail-closed: the send is sealed by the network guard, with no inspection.
import test from 'node:test';
import assert from 'node:assert/strict';

const base=config=>({version:3,revision:4,expires_at:'2099-01-01T00:00:00Z',config:{collection:{enabled:true,store_content:true},services:[{id:'chatgpt',domains:['chatgpt.com'],enabled:true,mode:'observe'}],model_access:[],...config}});
const masking=base({privacy:{enabled:true}});
const observe=base({});

let serial=0;
async function unmanagedWorker(policy,{catalog=null}={}){
 const calls=[],storage={},listeners={},state={rules:[]};
 const bridge={failCatalog:false};
 let message;
 const noop={addListener(){}};
 globalThis.chrome={
  runtime:{getManifest:()=>({version:'0.5.37',content_scripts:[]}),onInstalled:noop,onStartup:noop,onMessage:{addListener(fn){message=fn;}},async sendNativeMessage(host,msg){
   calls.push(msg);
   if(msg.op==='policy_v3'){return {ok:true,online:true,policy};}
   if(msg.op==='event_v2'){return {ok:true,id:crypto.randomUUID()};}
   if(msg.op==='catalog'){if(bridge.failCatalog){throw new Error('broker down');}return {ok:true,catalog,revision:9,catalog_state:'ok',expires_at:'2099-01-01T00:00:00Z'};}
   return {ok:true};
  }},
  alarms:{create(){},onAlarm:noop},
  // storage.managed answers with no pin: the installation is unmanaged.
  storage:{managed:{async get(){return{};}},local:{async get(){return{};},async set(v){Object.assign(storage,v);}}},
  declarativeNetRequest:{async getDynamicRules(){return state.rules;},async updateDynamicRules({addRules}){state.rules=addRules;}},
  tabs:{async query(){return[];},async sendMessage(){},async reload(){}},
  webRequest:Object.fromEntries(['onBeforeRequest','onBeforeSendHeaders','onCompleted','onErrorOccurred','onHeadersReceived'].map(k=>[k,{addListener(fn){(listeners[k]??=[]).push(fn);}}])),
 };
 await import('./background.js?unmanaged='+serial++);
 for(let n=0;n<500&&storage.status?.connected!==true;n++){await new Promise(r=>setTimeout(r,1));}
 assert.equal(storage.status?.connected,true,'the fixture policy must have been adopted');
 return {calls,storage,listeners,bridge,send:(msg,sender)=>new Promise(resolve=>message(msg,sender,resolve)),close(){delete globalThis.chrome;}};
}
const sender={frameId:0,tab:{id:1},documentId:'document-1',url:'https://chatgpt.com/c/abcdefgh'};

test('unmanaged under masking: no text to the bridge, the send stays sealed',async()=>{
 const state=await unmanagedWorker(masking);
 try{
  const inspect=await state.send({type:'inspect',text:'synthetic secret',upload:false},sender);
  assert.equal(inspect.ok,false,'le masquage sans pin géré est refusé (fail-closed)');
  const submit=await state.send({type:'submit',text:'synthetic secret',upload:false,event:{kind:'prompt',action:'observed',characters:16,labels:[],url:'https://chatgpt.com/c/abcdefgh'}},sender);
  assert.equal(submit.ok,false,'la soumission sous masquage est refusée sans pin');
  // Zero bytes of text going to the bridge: no inspect, no submit, no event.
  assert.ok(!JSON.stringify(state.calls).includes('synthetic secret'),'le texte a fuité vers l’agent');
  for(const op of ['inspect','browser_inspect','browser_submit','event_v2','browser_event']){assert.ok(!state.calls.some(c=>c.op===op),op+' ne doit pas partir');}
  // The network send stays sealed by the guard: under masking, no approval exists
  // without inspection, and the prompt route is cancelled.
  const body={messages:[{content:{parts:['synthetic secret text']}}],model:'gpt-synthetic'};
  const details={requestId:'seal-1',tabId:1,documentId:'document-1',frameId:0,method:'POST',type:'xmlhttprequest',url:'https://chatgpt.com/backend-api/f/conversation',initiator:'https://chatgpt.com/c/abcdefgh',requestBody:{raw:[{bytes:new TextEncoder().encode(JSON.stringify(body)).buffer}]}};
  const verdicts=state.listeners.onBeforeRequest.map(fn=>fn(details));
  assert.ok(verdicts.some(v=>v?.cancel===true),'la garde réseau doit sceller l’envoi non inspecté');
  assert.ok(!('policy' in state.storage),'la politique ne doit plus être écrite en clair');
 }finally{state.close();}
});

test('unmanaged observation: local answer, metadata-only durable event, no inspect RPC',async()=>{
 const state=await unmanagedWorker(observe);
 try{
  const inspect=await state.send({type:'inspect',text:'synthetic secret',upload:false},sender);
  assert.deepEqual(inspect,{ok:true,action:'observe',text:'synthetic secret'},'l’observation répond localement');
  const before=state.calls.length;
  const submit=await state.send({type:'submit',text:'synthetic secret',upload:false,event:{kind:'prompt',action:'observed',characters:16,labels:[],url:'https://chatgpt.com/c/abcdefgh'}},sender);
  assert.equal(submit.ok,true);
  assert.equal(submit.action,'observe');
  assert.equal(submit.text,'synthetic secret');
  assert.equal(submit.durable,true,'le reçu durable legacy est conservé');
  const sent=state.calls.slice(before);
  const events=sent.filter(c=>c.op==='event_v2');
  assert.equal(events.length,1,'un seul événement durable');
  assert.ok(!sent.some(c=>['inspect','browser_inspect','browser_submit'].includes(c.op)),'aucun inspect n’est émis');
  assert.ok(!('prompt' in events[0].event)&&!('response' in events[0].event),'métadonnées seules malgré store_content');
  assert.equal(events[0].event.provider,'chatgpt.com');
  assert.equal(events[0].event.characters,16);
  // The DOM event path follows the same rule: an observed response does not carry
  // its text either.
  const beforeEvent=state.calls.length;
  const recorded=await state.send({type:'event',event:{kind:'response',action:'observed',characters:16,labels:[],url:'https://chatgpt.com/c/abcdefgh',response:'synthetic answer'}},sender);
  assert.equal(recorded.ok,true);
  const responses=state.calls.slice(beforeEvent).filter(c=>c.op==='event_v2');
  assert.equal(responses.length,1);
  assert.ok(!('response' in responses[0].event)&&!('prompt' in responses[0].event),'une réponse non gérée ne porte pas son texte');
  assert.equal(state.storage.status.managed,false,'la popup doit voir l’installation non gérée');
 }finally{state.close();}
});

test('the catalog message answers the runtime catalog, never the raw broker packet',async()=>{
 const served={providers:[{id:'chatgpt',label:'chatgpt',domains:['chatgpt.com'],aliases:[],conversation_path:'/c/*',conversation_segment:1,dom:{editor:'#prompt-textarea',send:'button',response:'[data-message-author-role="assistant"]'},network:[],qualified_at:'2026-09-11T00:00:00Z'}],heuristics:{keys:['messages']}};
 const state=await unmanagedWorker(observe,{catalog:served});
 try{
  // The broker goes down: if the handler still queried it, the reply would be
  // {ok:false}. It comes from the runtime instead — the catalogue already filtered by edition.
  state.bridge.failCatalog=true;
  const before=state.calls.length;
  const reply=await state.send({type:'catalog'},sender);
  assert.equal(reply.ok,true);
  assert.ok(!state.calls.slice(before).some(c=>c.op==='catalog'),'le broker ne doit plus être consulté par le script de contenu');
  assert.equal(reply.revision,undefined,'le paquet brut portait la révision au premier niveau');
  assert.deepEqual(reply.catalog,served);
 }finally{state.close();}
});
