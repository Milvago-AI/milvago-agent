// Real campaign 0.7.11 under policy (2026-10-17). Synthetic policies and hosts.
//  1. Tabs already on the notice page (`blocked.html`) stayed there after their service was switched from `block`
//     to `redirect`; a new tab was redirected.
import test from 'node:test';
import assert from 'node:assert/strict';
import {managedBridge} from './managed-fixture.js';

const NOTICE='chrome-extension://synthetic/blocked.html';
const policyFor=(revision,mode,extra={})=>({version:3,revision,expires_at:'2099-01-01T00:00:00Z',config:{services:[{id:'chatgpt',enabled:true,mode,domains:['chatgpt.com'],...extra}],collection:{enabled:true,store_content:false},model_access:[]}});
let serial=0;
async function worker(initial,tabs){
 let message,policy=initial;const stored={},noop={addListener(){}},updates=[];
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
  tabs:{async query(){return tabs.map(t=>({...t}));},async reload(){},async update(id,change){updates.push([id,change.url]);const tab=tabs.find(t=>t.id===id);if(tab){tab.url=change.url;}},async sendMessage(){}},
  declarativeNetRequest:{async getDynamicRules(){return [];},async updateDynamicRules(){}},
  webRequest:Object.fromEntries(['onBeforeRequest','onBeforeSendHeaders','onCompleted','onErrorOccurred'].map(k=>[k,{addListener(){}}])),
 };
 await import('./background.js?campaign0711='+serial++);
 const ask=msg=>new Promise(resolve=>message(msg,{},resolve));
 assert.deepEqual(await ask({type:'refresh'}),{ok:true});
 const visits=()=>bridge.calls.filter(c=>c.op==='browser_event').map(c=>c.message.event).filter(e=>e.kind==='navigation');
 return {updates,visits,async move(next){policy=next;assert.deepEqual(await ask({type:'refresh'}),{ok:true});},close(){delete globalThis.chrome;}};
}

test('a tab on the notice page follows its service to the redirect, then back once it is free',async()=>{
 const tabs=[{id:1,url:NOTICE+'?service=chatgpt.com'},{id:2,url:'https://example.test/'}];
 const state=await worker(policyFor(1,'block'),tabs);
 try{
  assert.deepEqual(state.updates,[],'already on the notice of the block');
  await state.move(policyFor(2,'redirect',{redirect_url:'https://ai.example.test/approved'}));
  assert.deepEqual(state.updates,[[1,'https://ai.example.test/approved']]);
  // Back on the notice (a destination that is not plain https is a block), then free: back to the service.
  tabs[0].url=NOTICE+'?service=chatgpt.com';
  await state.move(policyFor(3,'redirect',{redirect_url:'http://ai.example.test/'}));
  assert.equal(state.updates.length,1,'still a block: left on its notice');
  await state.move(policyFor(4,'observe'));
  assert.deepEqual(state.updates.at(-1),[1,'https://chatgpt.com/']);
  assert.equal(state.visits().length,0,'following the policy records no visit');
 }finally{state.close();}
});

test('a notice page naming a host the policy does not know sends the tab nowhere',async()=>{
 const forged=['example.test','evil.example','chatgpt.com.evil.example','chatgpt.com/../x','','%2F%2Fevil.example','chatgpt.com@evil.example','a'.repeat(300)+'.com'];
 const tabs=forged.map((service,i)=>({id:10+i,url:NOTICE+'?service='+encodeURIComponent(service)}));
 const state=await worker(policyFor(1,'block'),tabs);
 try{
  await state.move(policyFor(2,'observe'));
  assert.deepEqual(state.updates,[]);
 }finally{state.close();}
});
