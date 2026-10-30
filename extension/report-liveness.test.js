import test from 'node:test';
import assert from 'node:assert/strict';
import {managedBridge} from './managed-fixture.js';

const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function until(check){
 const deadline=Date.now()+2000;
 while(!check()&&Date.now()<deadline){await pause(5);}
 assert.ok(check(),'the local operation waited for remote enforcement reporting');
}

test('pending enforcement reporting neither delays local authorization nor queues reports on renewal',async t=>{
 t.mock.method(globalThis,'fetch',()=>{assert.fail('the extension must communicate through the native bridge');});
 let release;
 const pending=new Promise(resolve=>{release=resolve;});
 let reports=0,listener,refused=false;
 const policy={version:4,revision:4,expires_at:'2099-01-01T00:00:00Z',config:{
  collection:{enabled:true,store_content:false},
  services:[{id:'chatgpt',domains:['chatgpt.com'],enabled:true,mode:'observe'}],
  model_access:[],dlp_control:{enabled:true,journal:true,fingerprint:'a'.repeat(64)},
 }};
 const bridge=managedBridge({
  browser_policy:()=>refused?{brokerMode:'blocked',reply:{ok:false}}:{online:false,policy},
  browser_catalog:()=>({catalog:null,revision:0,catalog_state:'missing'}),
  browser_health:req=>({accepted_health_ids:[req.batch.id]}),
  dlp_enforcement:async()=>{reports++;await pending;return {ok:true};},
 });
 const stored={},rules=[],noop={addListener(){}};
 globalThis.chrome={
  runtime:{getManifest:()=>({version:'0.7.0',content_scripts:[]}),onInstalled:noop,onStartup:noop,
   onMessage:{addListener(fn){listener=fn;}},sendNativeMessage:bridge.sendNativeMessage},
  alarms:{create(){},onAlarm:noop},
  storage:{managed:{async get(){return {milvago_pin:JSON.stringify(bridge.pin)};}},local:{async get(){return {};},async set(value){Object.assign(stored,value);}}},
  tabs:{async query(){return [];},async sendMessage(){}},
  declarativeNetRequest:{async getDynamicRules(){return rules;},async updateDynamicRules({addRules}){rules.splice(0,rules.length,...addRules);}},
  webRequest:Object.fromEntries(['onBeforeRequest','onBeforeSendHeaders','onCompleted','onErrorOccurred','onHeadersReceived'].map(k=>[k,noop])),
 };
 let refresh;
 t.after(async()=>{release();await refresh;await pause(30);delete globalThis.chrome;});
 await import('./background.js?case=report-liveness');
 const ask=()=>new Promise(resolve=>listener({type:'refresh'},{},resolve));
 refresh=ask();
 await until(()=>reports===1);
 await until(()=>stored.status?.connected===true);
 assert.deepEqual(await refresh,{ok:true});
 assert.equal(stored.status.online,false,'server reachability is independent of local control');
 assert.ok(!rules.some(rule=>rule.id>=20000),'an optional report must not seal the surface');
 for(let n=0;n<3;n++){assert.deepEqual(await ask(),{ok:true});}
 assert.equal(reports,1,'renewals must not accumulate pending reports');
 refused=true;
 assert.deepEqual(await ask(),{ok:false});
 assert.equal(stored.status.connected,false,'a real local refusal must still seal');
 assert.deepEqual(rules.map(rule=>rule.id),[20000,20001]);
 release();await pause(30);
 assert.equal(stored.status.connected,false,'a late report must not restore authorization');
 refused=false;
 assert.deepEqual(await ask(),{ok:true},'local recovery must require no console login');
 assert.equal(stored.status.connected,true);
 await until(()=>reports===2);
 assert.ok(!rules.some(rule=>rule.id>=20000));
});
