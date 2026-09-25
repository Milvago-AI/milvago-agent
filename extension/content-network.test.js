import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {managedBridge} from './managed-fixture.js';

const policyFor = config => ({
 version:3,revision:1,expires_at:'2099-01-01T00:00:00Z',
 config:{services:[],collection:{enabled:false},model_access:[],...config},
});
let serial=0;
// DOM inspection under masking is a managed channel: without a pin it is refused
// (fail-closed). This bench therefore pins the install — the object under test remains the
// network guard, against a real loopback receiver.
async function worker(initial,{blocking=true}={}){
 let policy=initial,message;const handlers={},stored={},reloaded=[],rules=[];
 const noop={addListener(){}};
 const bridge=managedBridge({
  browser_policy:()=>({online:true,policy}),
  browser_inspect:req=>({ok:true,action:'observe',text:req.text,labels:[]}),
  browser_event:req=>({ok:true,id:crypto.randomUUID(),durable:true,delivery_id:req.delivery_id}),
  browser_catalog:()=>({catalog:null,revision:0,catalog_state:'missing'}),
  browser_health:req=>({accepted_health_ids:[req.batch.id]}),
 });
 globalThis.chrome={
  runtime:{onInstalled:noop,onStartup:noop,onMessage:{addListener(fn){message=fn;}},sendNativeMessage:bridge.sendNativeMessage},
  storage:{managed:{async get(){return{milvago_pin:JSON.stringify(bridge.pin)};}},local:{async get(k){return {[k]:stored[k]};},async set(value){Object.assign(stored,value);}}},
  alarms:{create(){},onAlarm:noop},
  tabs:{async query(){return [{id:1,url:'https://chatgpt.com/'},{id:2,url:'https://unrelated.test/'}];},async reload(id){reloaded.push(id);},async sendMessage(){}},
  declarativeNetRequest:{async getDynamicRules(){return rules;},async updateDynamicRules({addRules}){rules.splice(0,rules.length,...addRules);}},
  webRequest:Object.fromEntries(['onBeforeRequest','onBeforeSendHeaders','onCompleted','onErrorOccurred'].map(k=>[k,{addListener(fn){if(!blocking){throw Error('Permission not granted');}handlers[k]=fn;}}])),
 };
 await import('./background.js?content-test='+serial++);
 const send=(msg,sender={})=>new Promise(resolve=>message(msg,sender,resolve));
 assert.deepEqual(await send({type:'refresh'}),{ok:true});
 assert.equal(stored.status.connected,true,'worker must have installed the fixture policy');
 return {handlers,stored,rules,reloaded,send,async refresh(next){policy=next;assert.deepEqual(await send({type:'refresh'}),{ok:true});assert.equal(stored.status.revision,next.revision);}};
}
const body='{"model":"synthetic-model","input":"synthetic text"}';
const request=(overrides={})=>({
 requestId:'request-'+serial++,tabId:1,url:'https://api.openai.com/v1/responses',method:'POST',type:'xmlhttprequest',
 requestBody:{raw:[{bytes:new TextEncoder().encode(body).buffer}]},...overrides,
});
const withHeaders=(details,values=[{name:'Content-Type',value:'application/json'}])=>({...details,requestBody:undefined,requestHeaders:values});

test('real registered callbacks reject private sends and only forward the exact qualified text body',async()=>{
 const state=await worker(policyFor({privacy:{enabled:true}}));
 const received=[];
 const server=http.createServer(async(req,res)=>{const parts=[];for await(const part of req){parts.push(part);}received.push(Buffer.concat(parts).toString('utf8'));res.end('ok');});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 async function send(details,headers){
  if(state.handlers.onBeforeRequest(details).cancel){state.handlers.onErrorOccurred(details);return false;}
  if(state.handlers.onBeforeSendHeaders(withHeaders(details,headers)).cancel){state.handlers.onErrorOccurred(details);return false;}
  // The loopback receiver gets exactly the bytes inspected by the real callbacks.
  const bytes=Buffer.concat(details.requestBody.raw.map(part=>Buffer.from(part.bytes)));
  await fetch('http://127.0.0.1:'+server.address().port,{method:details.method,body:bytes});
  state.handlers.onCompleted(details);return true;
 }
 try{
  assert.equal(state.stored.status.content_control,'unavailable');
  assert.deepEqual(state.reloaded,[1]);
  // Even a successful DOM inspection cannot authorize a different outbound body.
  const inspected=await state.send({type:'inspect',text:'harmless',upload:false},{frameId:0,tab:{id:1},url:'https://chatgpt.com/'});
  assert.equal(inspected.action,'observe');
  assert.equal(await send(request({url:'https://chatgpt.com/backend-api/conversation'})),false);
  assert.equal(await send(request()),false,'no synchronous content scanner exists');
  assert.deepEqual(received,[]);

  await state.refresh({...policyFor({protection:{block_uploads:true}}),revision:2});
  assert.equal(await send(request()),true);
  assert.deepEqual(received,[body],'a real transmission must have occurred');
  // File upload blocking now seals the catalog's FILE ROUTES only,
  // not all of the provider's traffic: the promise kept is "no
  // file leaves", not "the service is cut off". Intercepting the file
  // picker remains the first-line guard; this one is its safety net.
  assert.equal(await send(request({url:'https://chatgpt.com/unauth-mweb/image-uploads'})),false);
  assert.equal(await send(request({url:'https://chatgpt.com/file-synthetic',method:'PUT'})),false);
  assert.equal(await send(request({url:'https://chatgpt.com/backend-api/conversation'})),true);
  // Product decision of 2026-09-16: under file blocking alone, NOTHING other than the
  // file routes is sealed — not even the "direct API" either, whatever the shape
  // of its body or headers. API hosts have no `file` route.
  assert.equal(await send(request({url:'https://api.openai.com/v1/unknown'})),true);
  assert.equal(await send(request(),[{name:'Content-Type',value:'text/plain'}]),true);
  assert.equal(await send(request(),[{name:'Content-Type',value:'application/json'},{name:'Content-Encoding',value:'gzip'}]),true);
  // Five real transmissions; only the two file routes emitted nothing.
  assert.deepEqual(received,[body,body,body,body,body]);

  // No pending entry existed when the request began without restrictions.
  await state.refresh({...policyFor({}),revision:3});
  // The catalog's PROMPT route: with no body, the second guard knows nothing about the
  // request but its route, and that is the only thing masking retains (product decision of 2026-09-16).
  const inFlight=request({url:'https://chatgpt.com/backend-api/f/conversation'});
  assert.deepEqual(state.handlers.onBeforeRequest(inFlight),{});
  await state.refresh({...policyFor({protection:{keywords:['restricted'],exact:'block'}}),revision:4});
  assert.equal(state.handlers.onBeforeSendHeaders(withHeaders(inFlight)).cancel,true);
  // Off the prompt route, the same in-flight request passes: nothing indicates it carries a prompt.
  const offRoute=request({url:'https://chatgpt.com/backend-api/settings'});
  assert.equal(state.handlers.onBeforeSendHeaders(withHeaders(offRoute)).cancel,undefined);
  // Nothing more went out: the count is the same as before this section.
  assert.deepEqual(received,[body,body,body,body,body]);
 }finally{
  await new Promise(resolve=>server.close(resolve));
  delete globalThis.chrome;
 }
});

test('DNR fallback covers private destinations and foreign destinations initiated by covered pages',async()=>{
 const state=await worker(policyFor({protection:{block_uploads:true}}),{blocking:false});
 try{
  assert.equal(state.stored.status.content_control,'unavailable');
  assert.ok(state.rules.length>=2,'fallback rules must actually have been installed');
  const matches=(host,domains)=>domains?.some(domain=>host===domain||host.endsWith('.'+domain));
  const blocked=(url,origin,type)=>state.rules.some(rule=>
   rule.action.type==='block'&&(!rule.condition.resourceTypes||rule.condition.resourceTypes.includes(type))&&
   (!rule.condition.requestDomains||matches(new URL(url).hostname,rule.condition.requestDomains))&&
   (!rule.condition.initiatorDomains||matches(new URL(origin).hostname,rule.condition.initiatorDomains)));
  for(const type of ['xmlhttprequest','websocket','other','ping','image','sub_frame']){
   assert.equal(blocked('https://chatgpt.com/backend-api/conversation','https://unrelated.test',type),true,type);
   assert.equal(blocked('https://unrelated.test/transfer','https://chatgpt.com',type),true,type);
  }
  assert.equal(blocked('https://chat.openai.com/transfer','https://unrelated.test','xmlhttprequest'),true,'aliases remain covered');
  assert.equal(blocked('https://unrelated.test/transfer','https://another.test','xmlhttprequest'),false);
 }finally{delete globalThis.chrome;}
});
