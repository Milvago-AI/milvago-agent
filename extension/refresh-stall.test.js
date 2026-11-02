// A browser call that never settles must not freeze the policy refresh for the worker's
// lifetime. Here the first DNR update hangs forever, as a wedged browser call would: the
// refresh has to give up, seal, and the next refresh has to restore the policy.
import test from 'node:test';
import assert from 'node:assert/strict';
import {managedBridge} from './managed-fixture.js';

const policy={version:2,revision:4,expires_at:'2099-01-01T00:00:00Z',config:{collection:{enabled:true,store_content:false},services:[{id:'chatgpt',domains:['chatgpt.com'],enabled:true,mode:'observe'}]}};

test('a DNR update that never settles is abandoned, sealed, and the next refresh recovers',{timeout:60000},async t=>{
 t.after(()=>{delete globalThis.chrome;});
 const bridge=managedBridge({browser_policy:()=>({online:true,policy}),browser_catalog:()=>({catalog:null,revision:0,catalog_state:'missing'}),browser_health:req=>({accepted_health_ids:[req.batch.id]})});
 const noop={addListener(){}},storage={};let listener,updates=0;
 globalThis.chrome={
  runtime:{getManifest:()=>({version:'0.5.37',content_scripts:[]}),onInstalled:noop,onStartup:noop,onMessage:{addListener(fn){listener=fn;}},sendNativeMessage:bridge.sendNativeMessage},
  alarms:{create(){},onAlarm:noop},
  declarativeNetRequest:{async getDynamicRules(){return [];},updateDynamicRules(){updates++;return updates===1?new Promise(()=>{}):Promise.resolve();}},
  storage:{managed:{async get(){return {milvago_pin:JSON.stringify(bridge.pin)};}},local:{async get(){return {};},async set(value){Object.assign(storage,value);}}},
  tabs:{async query(){return [];},async sendMessage(){}},
  webRequest:Object.fromEntries(['onBeforeRequest','onBeforeSendHeaders','onCompleted','onErrorOccurred','onHeadersReceived'].map(k=>[k,noop])),
 };
 await import('./background.js?case=refresh-stall');
 const send=message=>new Promise(resolve=>listener(message,{},resolve));
 // The startup refresh is stuck on the hanging update; this request joins it, and must come
 // back (sealed) instead of waiting forever.
 assert.deepEqual(await send({type:'refresh'}),{ok:false});
 assert.equal(storage.status?.connected,false);
 // The single-flight slot was released: a new refresh runs and restores the policy.
 assert.deepEqual(await send({type:'refresh'}),{ok:true});
 assert.equal(storage.status?.connected,true);
 assert.equal(storage.status?.revision,4);
});

// Review 2026-10-16, finding 4: a refresh abandoned on its deadline must not keep writing
// the worker's state when its stalled call finally returns. Here a tab query hangs past the
// deadline, a later refresh restores the policy, then the stalled one wakes up: its status
// (written with its own, older `online`) must not replace the current one.
function harness(bridge,api){
 const noop={addListener(){}},storage={},writes=[];let listener;
 globalThis.chrome={
  runtime:{getManifest:()=>({version:'0.5.37',content_scripts:[]}),onInstalled:noop,onStartup:noop,onMessage:{addListener(fn){listener=fn;}},sendNativeMessage:bridge.sendNativeMessage},
  alarms:{create(){},onAlarm:noop},
  declarativeNetRequest:{async getDynamicRules(){return [];},async updateDynamicRules(){}},
  storage:{managed:{async get(){return {milvago_pin:JSON.stringify(bridge.pin)};}},local:{async get(){return {};},async set(value){writes.push(value);Object.assign(storage,value);}}},
  tabs:{async query(){return [];},async reload(){},async sendMessage(){}},
  webRequest:Object.fromEntries(['onBeforeRequest','onBeforeSendHeaders','onCompleted','onErrorOccurred','onHeadersReceived'].map(k=>[k,noop])),
  ...api,
 };
 return {storage,writes,send:message=>new Promise(resolve=>listener(message,{},resolve))};
}
test('a refresh past its deadline writes nothing when its stalled call returns',{timeout:120000},async t=>{
 t.after(()=>{delete globalThis.chrome;});
 const masking={...policy,config:{...policy.config,privacy:{enabled:true}}};
 let online=false,release,queries=0;
 const bridge=managedBridge({browser_policy:()=>({online,policy:masking}),browser_catalog:()=>({catalog:null,revision:0,catalog_state:'missing'}),browser_health:req=>({accepted_health_ids:[req.batch.id]})});
 const h=harness(bridge,{tabs:{async query(){return ++queries===1?new Promise(r=>{release=r;}):[];},async reload(){},async sendMessage(){}}});
 await import('./background.js?case=refresh-stale');
 assert.deepEqual(await h.send({type:'refresh'}),{ok:false});
 assert.equal(h.storage.status?.connected,false);
 online=true;
 assert.deepEqual(await h.send({type:'refresh'}),{ok:true});
 assert.equal(h.storage.status?.online,true);
 const before=h.writes.length;
 release([]);
 for(let n=0;n<50;n++){await new Promise(r=>setTimeout(r,0));}
 assert.equal(h.storage.status?.online,true,'the stale refresh rewrote the status');
 assert.equal(h.writes.length,before,'the stale refresh wrote again');
});
// The catalogue refresh is bounded too: a content-script registration that never settles
// must not cost the policy refresh its whole deadline (and seal the worker).
test('a catalogue refresh that never settles does not take the policy refresh down',{timeout:120000},async t=>{
 t.after(()=>{delete globalThis.chrome;});
 const bridge=managedBridge({browser_policy:()=>({online:true,policy}),browser_catalog:()=>({catalog:null,revision:0,catalog_state:'missing'}),browser_health:req=>({accepted_health_ids:[req.batch.id]})});
 const h=harness(bridge,{scripting:{getRegisteredContentScripts:()=>new Promise(()=>{}),async unregisterContentScripts(){},async registerContentScripts(){},async executeScript(){}}});
 await import('./background.js?case=catalog-stall');
 const started=Date.now();
 assert.deepEqual(await h.send({type:'refresh'}),{ok:true});
 assert.ok(Date.now()-started<30000,'bounded well under the refresh deadline');
 assert.equal(h.storage.status?.connected,true);
});
