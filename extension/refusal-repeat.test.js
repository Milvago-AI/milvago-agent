// Real campaign 0.7.6: claude.ai resent a refused send on its own about every 4 s (20 refusals recorded in
// 90 s), and switching services to `block` recorded 8 `control_unavailable` prompts for page traffic caught
// in flight. Synthetic policies, bodies and tabs.
import test from 'node:test';
import assert from 'node:assert/strict';
import {managedBridge} from './managed-fixture.js';

const policyFor=(revision,config)=>({version:3,revision,expires_at:'2099-01-01T00:00:00Z',config:{services:[{id:'chatgpt',enabled:true,mode:'observe',domains:['chatgpt.com']}],collection:{enabled:true,store_content:false},model_access:[],privacy:{enabled:true},...config}});
let serial=0;
async function worker(initial){
 let message,policy=initial;const handlers={},stored={},noop={addListener(){}},notices=[];
 const bridge=managedBridge({
  browser_policy:()=>({online:true,policy}),
  browser_inspect:req=>({ok:true,action:'observe',text:req.text,labels:[]}),
  browser_submit:req=>({ok:true,action:'observe',text:req.text,recording_required:false}),
  browser_event:req=>({ok:true,id:crypto.randomUUID(),durable:true,delivery_id:req.delivery_id}),
  browser_catalog:()=>({catalog:null,revision:0,catalog_state:'missing'}),
  browser_health:req=>({accepted_health_ids:[req.batch.id]}),
 });
 globalThis.chrome={
  runtime:{onInstalled:noop,onStartup:noop,onMessage:{addListener(fn){message=fn;}},sendNativeMessage:bridge.sendNativeMessage,getURL:path=>'chrome-extension://synthetic'+path},
  storage:{managed:{async get(){return {milvago_pin:JSON.stringify(bridge.pin)};}},local:{async get(k){return {[k]:stored[k]};},async set(v){Object.assign(stored,v);}}},
  alarms:{create(){},onAlarm:noop},
  tabs:{async query(){return [];},async reload(){},async sendMessage(tab,msg){notices.push(msg);}},
  declarativeNetRequest:{async getDynamicRules(){return [];},async updateDynamicRules(){}},
  webRequest:Object.fromEntries(['onBeforeRequest','onBeforeSendHeaders','onCompleted','onErrorOccurred'].map(k=>[k,{addListener(fn){handlers[k]=fn;}}])),
 };
 await import('./background.js?repeat='+serial++);
 const ask=(msg,sender={})=>new Promise(resolve=>message(msg,sender,resolve));
 assert.deepEqual(await ask({type:'refresh'}),{ok:true});
 const prompts=()=>bridge.calls.filter(c=>c.op==='browser_event').map(c=>c.message.event).filter(e=>e.kind==='prompt');
 return {handlers,notices,prompts,ask,setPolicy(next){policy=next;},close(){delete globalThis.chrome;}};
}
const settle=async()=>{for(let i=0;i<30;i++){await new Promise(r=>setTimeout(r,0));}};
const PAGE='https://chatgpt.com/c/abcdefgh';
let id=0;
const conversation=(text,over={})=>({requestId:'q'+id++,tabId:1,documentId:'document-1',frameId:0,method:'POST',type:'xmlhttprequest',url:'https://chatgpt.com/backend-api/f/conversation',initiator:'https://chatgpt.com',requestBody:{raw:[{bytes:new TextEncoder().encode(JSON.stringify({messages:[{id:'6aa99383-dd04-43ea-88fb-50a164a3820d',content:{content_type:'text',parts:[text]}}],model:'auto'})).buffer}]},...over});

test('a page resending the same refused body is told and recorded once',async()=>{
 const state=await worker(policyFor(1));
 try{
  for(let i=0;i<5;i++){assert.equal(state.handlers.onBeforeRequest(conversation('Texte non approuve synthetique')).cancel,true,'each retry stays refused');}
  await settle();
  assert.equal(state.prompts().length,1);assert.equal(state.notices.length,1);
  // Another body, or the same body from another tab, is another refusal.
  state.handlers.onBeforeRequest(conversation('Un autre texte non approuve'));
  state.handlers.onBeforeRequest(conversation('Texte non approuve synthetique',{tabId:2}));
  await settle();
  assert.equal(state.prompts().length,3);assert.equal(state.notices.length,3);
 }finally{state.close();}
});

test('a send caught in flight by the revision that blocks its service is not a refused prompt',async()=>{
 const state=await worker(policyFor(1));
 try{
  const sender={frameId:0,documentId:'document-1',tab:{id:1},url:PAGE};
  assert.equal((await state.ask({type:'submit',text:'Bonjour',upload:false,event:{kind:'prompt',action:'observed',characters:7,labels:[],url:PAGE}},sender)).ok,true);
  const send=conversation('Bonjour');
  assert.deepEqual(state.handlers.onBeforeRequest(send),{},'approved');
  state.setPolicy(policyFor(2,{services:[{id:'chatgpt',enabled:true,mode:'block',domains:['chatgpt.com']}]}));
  assert.deepEqual(await state.ask({type:'refresh'}),{ok:true});
  assert.equal(state.handlers.onBeforeSendHeaders({...send,requestBody:undefined,requestHeaders:[]}).cancel,true,'still cancelled');
  await settle();
  assert.equal(state.prompts().length,0);assert.equal(state.notices.length,0);
 }finally{state.close();}
});

test('a send caught by a revision that does not hold its service is still announced',async()=>{
 const state=await worker(policyFor(1));
 try{
  const sender={frameId:0,documentId:'document-1',tab:{id:1},url:PAGE};
  await state.ask({type:'submit',text:'Bonjour',upload:false,event:{kind:'prompt',action:'observed',characters:7,labels:[],url:PAGE}},sender);
  const send=conversation('Bonjour');
  assert.deepEqual(state.handlers.onBeforeRequest(send),{});
  state.setPolicy(policyFor(2));
  assert.deepEqual(await state.ask({type:'refresh'}),{ok:true});
  assert.equal(state.handlers.onBeforeSendHeaders({...send,requestBody:undefined,requestHeaders:[]}).cancel,true);
  await settle();
  assert.equal(state.notices.length,1);
 }finally{state.close();}
});
