// Real campaign 0.7.3: a service in `redirect` mode behaved as a block. Every request of the
// service, the page itself included, was cancelled: the browser showed its own error page and
// the redirection offered on send could never be reached. The visit was recorded as a blocked
// prompt `control_unavailable`. Synthetic policies and hosts.
import test from 'node:test';
import assert from 'node:assert/strict';
import {managedBridge} from './managed-fixture.js';
import {networkRules} from './policy.js';

const policyFor=services=>({version:3,revision:1,expires_at:'2099-01-01T00:00:00Z',config:{services,collection:{enabled:true,store_content:false,store_file_names:true},model_access:[]}});
const redirecting=policyFor([{id:'chatgpt',enabled:true,mode:'redirect',redirect_url:'https://ai.example.test/approved',domains:['chatgpt.com']}]);
const blocking=policyFor([{id:'chatgpt',enabled:true,mode:'block',domains:['chatgpt.com']}]);
let serial=0;
async function worker(policy){
 let message;const handlers={},stored={},noop={addListener(){}},notices=[];
 const bridge=managedBridge({
  browser_policy:()=>({online:true,policy}),
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
 await import('./background.js?service='+serial++);
 const ask=msg=>new Promise(resolve=>message(msg,{},resolve));
 assert.deepEqual(await ask({type:'refresh'}),{ok:true});
 const events=()=>bridge.calls.filter(c=>c.op==='browser_event').map(c=>c.message.event);
 return {handlers,notices,events,close(){delete globalThis.chrome;}};
}
const page={requestId:'nav',tabId:1,method:'GET',type:'main_frame',url:'https://chatgpt.com/'};
const xhr={requestId:'x',tabId:1,method:'POST',type:'xmlhttprequest',url:'https://chatgpt.com/backend-api/f/conversation',initiator:'https://chatgpt.com',requestBody:{raw:[{bytes:new TextEncoder().encode('{}').buffer}]}};
const settle=async()=>{for(let i=0;i<30;i++){await new Promise(r=>setTimeout(r,0));}};

test('a redirected service sends its page to the destination and records a redirected visit',async()=>{
 const state=await worker(redirecting);
 try{
  assert.deepEqual(state.handlers.onBeforeRequest(page),{redirectUrl:'https://ai.example.test/approved'});
  assert.equal(state.handlers.onBeforeRequest(xhr).cancel,true,'its other traffic stays cut');
  await settle();
  const recorded=state.events();
  assert.equal(recorded.length,1);
  assert.deepEqual([recorded[0].kind,recorded[0].action,recorded[0].decision_reason],['navigation','redirected','service_redirected']);
 }finally{state.close();}
});

test('a destination that is not plain https, or is itself held back, is a block',async()=>{
 // Fourth review, M5: a port, even the default one the URL parser drops, is refused like the
 // server refuses it, and a subdomain of a held service is held too.
 for(const redirect_url of ['http://ai.example.test/','https://user:secret@ai.example.test/','https://claude.ai/','javascript:alert(1)','https://ai.example.test:8443/','https://ai.example.test:443/','https://ai.example.test:/','https://www.claude.ai/']){
  const state=await worker(policyFor([{id:'chatgpt',enabled:true,mode:'redirect',redirect_url,domains:['chatgpt.com']},{id:'claude',enabled:true,mode:'block',domains:['claude.ai']}]));
  try{assert.deepEqual(state.handlers.onBeforeRequest(page),{redirectUrl:'chrome-extension://synthetic/blocked.html?service=chatgpt.com'},redirect_url);}finally{state.close();}
 }
});

test('a blocked service shows the extension notice page and records a blocked visit',async()=>{
 const state=await worker(blocking);
 try{
  assert.deepEqual(state.handlers.onBeforeRequest(page),{redirectUrl:'chrome-extension://synthetic/blocked.html?service=chatgpt.com'});
  assert.equal(state.handlers.onBeforeRequest(xhr).cancel,true);
  await settle();
  const recorded=state.events();
  assert.equal(recorded.length,1,'page traffic of a blocked service is not a blocked prompt');
  assert.deepEqual([recorded[0].kind,recorded[0].action,recorded[0].decision_reason],['navigation','blocked','service_blocked']);
 }finally{state.close();}
});

test('the declarative fallback shows the notice page for a blocked service',()=>{
 const rules=networkRules(blocking);
 const pageRule=rules.find(r=>r.condition.requestDomains?.includes('chatgpt.com')&&r.condition.resourceTypes?.includes('main_frame'));
 assert.deepEqual(pageRule.action,{type:'redirect',redirect:{extensionPath:'/blocked.html?service=chatgpt.com'}});
 assert.ok(rules.some(r=>r.action.type==='block'&&r.condition.requestDomains?.includes('chatgpt.com')&&r.condition.resourceTypes.includes('xmlhttprequest')&&!r.condition.resourceTypes.includes('main_frame')));
});
