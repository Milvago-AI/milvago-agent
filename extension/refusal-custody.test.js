// Real campaign 0.7.8 under policy (2026-10-17): a send refused on an alias host left no event (the agent
// names no service by that host and refused the record), and that refusal, answered by the broker as it
// answers an absent agent, sealed an idle page of another service 0.8 s later. Every refusal must leave
// exactly one durable event. Synthetic policies, bodies and tabs.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {managedBridge} from './managed-fixture.js';

const catalog=JSON.parse(await readFile(new URL('./detection-factory.json',import.meta.url),'utf8'));
const policy={version:3,revision:1,expires_at:'2099-01-01T00:00:00Z',config:{services:[{id:'chatgpt',enabled:true,mode:'observe',domains:['chatgpt.com','chat.openai.com']},{id:'claude',enabled:true,mode:'observe',domains:['claude.ai']}],collection:{enabled:true,store_content:false},model_access:[],privacy:{enabled:true}}};
let serial=0,id=0;
async function worker({event=req=>({ok:true,id:crypto.randomUUID(),durable:true,delivery_id:req.delivery_id}),complete=()=>({ok:true,applied:true}),policyAnswer=()=>({online:true,policy}),submit=req=>({ok:true,action:'observe',text:req.text,recording_required:true,durable:true,delivery_id:req.delivery_id,id:crypto.randomUUID()})}={}){
 let message;const handlers={},stored={},noop={addListener(){}};
 const bridge=managedBridge({
  browser_policy:policyAnswer,
  browser_inspect:req=>({ok:true,action:'observe',text:req.text,labels:[]}),
  browser_submit:submit,
  browser_event:event,
  browser_complete:complete,
  browser_catalog:()=>({catalog,revision:1,catalog_state:'ok',expires_at:'2099-01-01T00:00:00Z'}),
  browser_health:req=>({accepted_health_ids:[req.batch.id]}),
 });
 globalThis.chrome={
  runtime:{onInstalled:noop,onStartup:noop,onMessage:{addListener(fn){message=fn;}},sendNativeMessage:bridge.sendNativeMessage,getURL:path=>'chrome-extension://synthetic'+path,getManifest:()=>({version:'0.7.8',content_scripts:[]})},
  storage:{managed:{async get(){return {milvago_pin:JSON.stringify(bridge.pin)};}},local:{async get(k){return k?{[k]:stored[k]}:{...stored};},async set(v){Object.assign(stored,v);}}},
  alarms:{create(){},onAlarm:noop},
  tabs:{async query(){return [];},async reload(){},async sendMessage(){}},
  declarativeNetRequest:{async getDynamicRules(){return [];},async updateDynamicRules(){}},
  webRequest:Object.fromEntries(['onBeforeRequest','onBeforeSendHeaders','onHeadersReceived','onCompleted','onErrorOccurred'].map(k=>[k,{addListener(fn){handlers[k]=fn;}}])),
 };
 await import('./background.js?custody='+serial++);
 const ask=(msg,sender={})=>new Promise(resolve=>message(msg,sender,resolve));
 assert.deepEqual(await ask({type:'refresh'}),{ok:true});
 const ops=op=>bridge.calls.filter(c=>c.op===op).map(c=>c.message);
 return {handlers,ask,ops,close(){delete globalThis.chrome;}};
}
const settle=async()=>{for(let i=0;i<60;i++){await new Promise(r=>setTimeout(r,0));}};
const body=value=>({raw:[{bytes:new TextEncoder().encode(JSON.stringify(value)).buffer}]});
const chatgpt=(text,over={})=>({requestId:'q'+id++,tabId:1,documentId:'document-1',frameId:0,method:'POST',type:'xmlhttprequest',url:'https://chatgpt.com/backend-api/f/conversation',initiator:'https://chatgpt.com',requestBody:body({messages:[{id:'6aa99383-dd04-43ea-88fb-50a164a3820d',content:{content_type:'text',parts:[text]}}],model:'auto'}),...over});
const blockedPrompts=state=>state.ops('browser_event').map(m=>m.event).filter(e=>e.kind==='prompt'&&e.action==='blocked');

test('a refusal on an alias host is recorded under its service\'s own domain',async()=>{
 const state=await worker();
 try{
  const send=chatgpt('Texte non approuve synthetique',{url:'https://chat.openai.com/backend-api/f/conversation',initiator:'https://chat.openai.com'});
  assert.equal(state.handlers.onBeforeRequest(send).cancel,true);
  await settle();
  const [event]=blockedPrompts(state);
  assert.deepEqual([event?.provider,event?.url,event?.platform_id,event?.decision_reason],['chatgpt.com','https://chatgpt.com','chatgpt','control_unavailable']);
 }finally{state.close();}
});

test('a record the broker refuses does not seal every other page',async()=>{
 const state=await worker({event:()=>({brokerMode:'blocked',reply:{ok:false,error:'control_unavailable'}})});
 try{
  assert.equal(state.handlers.onBeforeRequest(chatgpt('Texte non approuve synthetique')).cancel,true);
  await settle();
  assert.equal(state.ops('browser_event').length,1,'the refusal was put to the broker');
  // An idle page of another service, a few hundred milliseconds later: page traffic without a prompt.
  const telemetry={requestId:'q'+id++,tabId:2,documentId:'document-2',frameId:0,method:'POST',type:'xmlhttprequest',url:'https://claude.ai/api/event_logging/batch',initiator:'https://claude.ai',requestBody:body({events:[{event_name:'page_view',ts:1}]})};
  assert.deepEqual(state.handlers.onBeforeRequest(telemetry),{});
  assert.deepEqual(state.handlers.onBeforeSendHeaders({...telemetry,requestBody:undefined,requestHeaders:[]}),{});
 }finally{state.close();}
});

const PAGE='https://claude.ai/chat/0b5b8a7e-4a49-4b2a-9c3e-6d6b1d1c2a10';
const sender={frameId:0,documentId:'document-1',tab:{id:1},url:PAGE};
const claude=(prompt,over={})=>({requestId:'q'+id++,tabId:1,documentId:'document-1',frameId:0,method:'POST',type:'xmlhttprequest',url:'https://claude.ai/api/organizations/0b5b8a7e-4a49-4b2a-9c3e-6d6b1d1c2a11/chat_conversations/0b5b8a7e-4a49-4b2a-9c3e-6d6b1d1c2a10/completion',initiator:'https://claude.ai',requestBody:body({prompt,timezone:'Europe/Paris'}),...over});
async function submitted(state,text){
 const answer=await state.ask({type:'submit',text,upload:false,event:{kind:'prompt',action:'observed',characters:text.length,labels:[],url:PAGE}},sender);
 assert.equal(answer.ok,true,JSON.stringify(answer));
}

test('a send sealed after its DOM record completes that record: one event, blocked',async()=>{
 const state=await worker();
 try{
  await submitted(state,'Bonjour');
  assert.equal(state.handlers.onBeforeRequest(claude('Autre texte non approuve synthetique')).cancel,true);
  await settle();
  const [completion]=state.ops('browser_complete');
  assert.deepEqual(completion?.completion,{decision_reason:'control_unavailable',platform_id:'claude'});
  assert.equal(blockedPrompts(state).length,0,'no second record of the same send');
 }finally{state.close();}
});

test('a completion the agent cannot place leaves the refusal recorded on its own, once',async()=>{
 for(const complete of [()=>({ok:true,applied:false}),()=>({brokerMode:'blocked',reply:{ok:false,error:'control_unavailable'}})]){
  const state=await worker({complete});
  try{
   await submitted(state,'Bonjour');
   assert.equal(state.handlers.onBeforeRequest(claude('Autre texte non approuve synthetique')).cancel,true);
   await settle();
   assert.equal(state.ops('browser_complete').length,1);
   assert.equal(blockedPrompts(state).length,1);
  }finally{state.close();}
 }
});

// Attacks on the record of a refusal: the refused text never travels, a refusal in another tab never takes
// this tab's record, and a broker that is really gone still seals once the policy is asked again.
test('a refusal record carries none of the refused text, wherever it goes',async()=>{
 const state=await worker();
 try{
  await submitted(state,'Bonjour');
  const secret='Texte refuse synthetique 4970101234567894';
  assert.equal(state.handlers.onBeforeRequest(claude(secret)).cancel,true);
  assert.equal(state.handlers.onBeforeRequest(chatgpt(secret,{tabId:2,documentId:'document-2'})).cancel,true);
  await settle();
  const sent=JSON.stringify([...state.ops('browser_event'),...state.ops('browser_complete')]);
  assert.ok(!sent.includes('4970101234567894')&&!sent.includes('refuse synthetique'),sent);
 }finally{state.close();}
});

test('a refusal in another tab does not take the record of this tab',async()=>{
 const state=await worker();
 try{
  await submitted(state,'Bonjour');
  assert.equal(state.handlers.onBeforeRequest(claude('Autre texte non approuve',{tabId:2,documentId:'document-2'})).cancel,true);
  await settle();
  assert.equal(state.ops('browser_complete').length,0);assert.equal(blockedPrompts(state).length,1);
 }finally{state.close();}
});

test('a broker refusing the record and then the policy still seals the covered pages',async()=>{
 let gone=false;
 const state=await worker({event:()=>{gone=true;return {brokerMode:'blocked',reply:{ok:false,error:'control_unavailable'}};}});
 try{
  // The agent disappears with the refused record: the policy asked again is refused too.
  globalThis.chrome.runtime.sendNativeMessage=(original=>async(host,message)=>{if(gone){throw new Error('Offline');}return original(host,message);})(globalThis.chrome.runtime.sendNativeMessage);
  assert.equal(state.handlers.onBeforeRequest(chatgpt('Texte non approuve synthetique')).cancel,true);
  for(let i=0;i<20;i++){await settle();}
  const telemetry={requestId:'q'+id++,tabId:2,documentId:'document-2',frameId:0,method:'POST',type:'xmlhttprequest',url:'https://claude.ai/api/event_logging/batch',initiator:'https://claude.ai',requestBody:body({events:[{event_name:'page_view',ts:1}]})};
  assert.equal(state.handlers.onBeforeRequest(telemetry).cancel,true,'fail-closed once the agent is gone');
 }finally{state.close();}
});

// Review of round 5: a refusal that lands while a policy request is already on its way must not be
// answered by that request, which may have left before the agent turned blocked.
test('a record refused during a policy request asks again, and a signed blocked policy then seals',async()=>{
 let calls=0,release,refused=false;const gate=new Promise(r=>{release=r;});
 const state=await worker({
  event:()=>{refused=true;return {brokerMode:'blocked',reply:{ok:false,error:'control_unavailable'}};},
  policyAnswer:async()=>{calls++;if(calls===2){await gate;}return refused&&calls>2?{brokerMode:'blocked',reply:{ok:false,error:'control_unavailable'}}:{online:true,policy};},
 });
 try{
  const asked=state.ask({type:'refresh'});await settle();
  assert.equal(state.handlers.onBeforeRequest(chatgpt('Texte non approuve synthetique')).cancel,true);
  // The broker answers in order: the refusal comes back while that policy request is still being applied.
  release();await asked;
  for(let i=0;i<20;i++){await settle();}
  assert.equal(refused,true);
  assert.equal(calls,3,'the policy was asked again after the refusal');
  const telemetry={requestId:'q'+id++,tabId:2,documentId:'document-2',frameId:0,method:'POST',type:'xmlhttprequest',url:'https://claude.ai/api/event_logging/batch',initiator:'https://claude.ai',requestBody:body({events:[{event_name:'page_view',ts:1}]})};
  assert.equal(state.handlers.onBeforeRequest(telemetry).cancel,true,'fail-closed');
 }finally{state.close();}
});

// Review of round 5: without content control nothing binds a DOM record to the request that carried it, so
// the send has already gone out when a refusal arrives. A broker that answers "blocked" for a moment after a
// send (here on another tab's send) must not have the record of that send rewritten as blocked.
test('without content control, a refusal after a broker drop-out leaves the passed send observed',async()=>{
 const observe={...policy,config:{...policy.config,privacy:{enabled:false}}};
 let down=false;const ok=req=>({ok:true,action:'observe',text:req.text,recording_required:true,durable:true,delivery_id:req.delivery_id,id:crypto.randomUUID()});
 const state=await worker({policyAnswer:()=>({online:true,policy:observe}),submit:req=>down?{brokerMode:'blocked',reply:{ok:false,error:'control_unavailable'}}:ok(req)});
 try{
  await submitted(state,'Bonjour');
  assert.deepEqual(state.handlers.onBeforeRequest(claude('Bonjour')),{},'the send goes out');
  down=true;
  const other=await state.ask({type:'submit',text:'Salut',upload:false,event:{kind:'prompt',action:'observed',characters:5,labels:[],url:PAGE}},{...sender,documentId:'document-2',tab:{id:2}});
  assert.equal(other.ok,false);down=false;
  // Tour 8: page telemetry cut while the broker answers "blocked" is not a refused prompt; a send is.
  assert.equal(state.handlers.onBeforeRequest(claude('Bonjour',{url:'https://claude.ai/api/event_logging/batch'})).cancel,true,'fail-closed');
  assert.equal(state.handlers.onBeforeRequest(claude('Salut')).cancel,true,'fail-closed');
  await settle();
  assert.equal(state.ops('browser_complete').length,0,'the passed send is not completed as blocked');
  assert.equal(blockedPrompts(state).length,1,'the refusal of the send is recorded on its own');
 }finally{state.close();}
});
