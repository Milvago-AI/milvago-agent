import test from 'node:test';
import assert from 'node:assert/strict';
import {managedBridge} from './managed-fixture.js';

// Minimal `chrome` bridge shared by this file's test benches: `storage` receives
// local writes; `dnr` replaces `updateDynamicRules`, `rules` feeds `getDynamicRules`, `set`
// replaces `storage.local.set`, `onMessage` receives the worker's message handler, and
// `webRequest:false` removes the blocking API — an install where only DNR seals.
function fakeChrome(bridge,storage,{dnr,rules,set,onMessage,webRequest=true}={}){
 const noop={addListener(){}};
 const listener=webRequest?noop:{addListener(){throw new Error('webRequestBlocking unavailable');}};
 return {runtime:{getManifest:()=>({version:"0.5.37",content_scripts:[]}),onInstalled:noop,onStartup:noop,onMessage:{addListener(fn){onMessage?.(fn);}},sendNativeMessage:bridge.sendNativeMessage},alarms:{create(){},onAlarm:noop},declarativeNetRequest:{async getDynamicRules(){return rules?rules.map(r=>({...r})):[];},updateDynamicRules:dnr||(async()=>{})},storage:{managed:{async get(){return{milvago_pin:JSON.stringify(bridge.pin)};}},local:{async get(){return{};},set:set||(async v=>{Object.assign(storage,v);})}},tabs:{async query(){return[];},async sendMessage(){}},webRequest:Object.fromEntries(['onBeforeRequest','onBeforeSendHeaders','onCompleted','onErrorOccurred','onHeadersReceived'].map(k=>[k,listener]))};
}
// Waits for the state written by the first refresh. Bounded by wall-clock time, not by a
// number of ticks: under the parallel suite, the managed bridge's key generation and
// signatures sometimes took more than two hundred one-millisecond ticks, and the
// following assertion would then wrongly blame the refresh.
async function settled(storage,timeoutMs=10000){const deadline=Date.now()+timeoutMs;while(!storage.status&&Date.now()<deadline){await new Promise(r=>setTimeout(r,5));}}
const policy={version:2,revision:4,expires_at:'2099-01-01T00:00:00Z',config:{collection:{enabled:true,store_content:false},services:[{id:'chatgpt',domains:['chatgpt.com'],enabled:true,mode:'observe'}]}};
const policyHandlers={browser_policy:()=>({online:true,policy}),browser_catalog:()=>({catalog:null,revision:0,catalog_state:'missing'}),browser_health:req=>({accepted_health_ids:[req.batch.id]})};
// A DNR that keeps its rules and rejects an already-present id, like the real one: this
// is the rejection that two simultaneous seals used to trigger.
function dnrStore(rules){
 return async({removeRuleIds=[],addRules=[]})=>{
  const kept=rules.filter(r=>!removeRuleIds.includes(r.id));
  for(const rule of addRules){if(kept.some(k=>k.id===rule.id)){throw new Error('Rule with id '+rule.id+' already exists');}kept.push(rule);}
  rules.splice(0,rules.length,...kept);
 };
}

// The managed path: pin present, every exchange signed by the broker. The degraded
// mode without a pin has its own bench (unmanaged-degraded.test.js).
test('managed native bridge authenticates sender scope, derives tool/provider, strips raw event bodies and fails closed',async t=>{
 t.after(()=>{delete globalThis.chrome;});
 const bridge=managedBridge({
  ...policyHandlers,
  browser_inspect:req=>({ok:true,action:'observe',text:req.text,labels:[]}),
  browser_event:req=>({ok:true,id:crypto.randomUUID(),durable:true,delivery_id:req.delivery_id}),
 });
 let listener;const storage={};
 globalThis.chrome=fakeChrome(bridge,storage,{onMessage:fn=>{listener=fn;}});
 await import('./background.js?case=managed-bridge');
 await settled(storage);
 assert.equal(storage.status?.managed,true,'adopt() must record the managed installation');
 const startupCalls=bridge.calls.length;
 const send=(message,sender)=>new Promise(resolve=>listener(message,sender,resolve));
 const sender={frameId:0,tab:{id:1},url:'https://chatgpt.com/c/abcdefgh?token=private'};
 assert.deepEqual(await send({type:'inspect',text:'synthetic',upload:false},{...sender,frameId:1}),{ok:false});
 assert.equal(bridge.calls.length,startupCalls);
 assert.deepEqual(await send({type:'inspect',text:'synthetic',upload:false},{...sender,url:'https://chatgpt.com.attacker.test'}),{ok:false});
 assert.equal(bridge.calls.length,startupCalls);
 assert.equal((await send({type:'inspect',text:'synthetic',upload:false,provider:'other.test',tool:'native'},sender)).ok,true);
 const inspection=bridge.calls.find(c=>c.op==='browser_inspect');
 assert.equal(inspection.host,'app.milvago.browser');
 assert.equal(inspection.message.provider,'chatgpt.com');
 assert.equal(inspection.message.tool,'chrome');
 const recorded=await send({type:'event',event:{kind:'prompt',characters:9,action:'observed',prompt:'synthetic',organization_id:'forged',provider:'other.test'}},sender);
 assert.equal(recorded.ok,true);
 const event=bridge.calls.find(c=>c.op==='browser_event').message.event;
 assert.equal(event.prompt,undefined);
 assert.equal(event.organization_id,undefined);
 assert.equal(event.provider,'chatgpt.com');
 assert.equal(event.url,'https://chatgpt.com/c/abcdefgh');
 bridge.setUnavailable(true);
 assert.equal((await send({type:'inspect',text:'synthetic',upload:false},sender)).ok,false);
});

// A `seal_failed` inherited from an outage (failed fallback DNR seal) does not survive a
// successful refresh: it replaces the dynamic rules with the policy's, protection is
// restored, and the popup must no longer report a failed seal as long as the agent
// stays reachable. Once cleared, the flag is no longer rewritten on every
// refresh: a `false` over a `false` every thirty seconds teaches nobody
// anything and wakes every `storage.onChanged` listener.
test('a successful refresh clears a stale seal_failed flag, once',async t=>{
 t.after(()=>{delete globalThis.chrome;});
 const bridge=managedBridge(policyHandlers);
 const storage={seal_failed:true};let listener,sealWrites=0;
 globalThis.chrome=fakeChrome(bridge,storage,{onMessage:fn=>{listener=fn;},set:async v=>{if('seal_failed' in v){sealWrites++;}Object.assign(storage,v);}});
 await import('./background.js?case=seal-cleared');
 await settled(storage);
 assert.equal(storage.status?.connected,true,'the refresh must have succeeded for this test to prove anything');
 assert.equal(storage.seal_failed,false,'a successful refresh replaces the dynamic rules and must clear the fallback seal flag');
 assert.equal(sealWrites,1);
 const again=await new Promise(resolve=>listener({type:'refresh'},{},resolve));
 assert.equal(again.ok,true,'the second refresh must have succeeded too');
 assert.equal(sealWrites,1,'a flag already cleared is not written again');
});

// The fallback seal fails AND writing the flag throws (storage unavailable,
// callback-based API): nothing must escape sealDnr, otherwise `refresh()` would stop before
// writing the "blocked" state and the popup would keep showing the old "connected" while
// traffic is actually blocked.
test('a seal failure whose flag cannot be written still records the blocked status',async t=>{
 t.after(()=>{delete globalThis.chrome;});
 const bridge=managedBridge();bridge.setUnavailable(true);
 const storage={};
 globalThis.chrome=fakeChrome(bridge,storage,{dnr:async()=>{throw new Error('rule quota');},set(v){if('seal_failed' in v){throw new TypeError('storage unavailable');}Object.assign(storage,v);return Promise.resolve();}});
 await import('./background.js?case=seal-flag-throws');
 await settled(storage);
 assert.equal(storage.status?.connected,false,'the blocked status must be written even when the seal flag cannot be');
 assert.equal(storage.seal_failed,undefined);
});

// An install with no blocking API (DNR only) whose agent responds "grace": `adopt()`
// refuses it — without synchronous inspection, the tolerance is worthless — and kicks off a
// seal without awaiting it; `refresh()` then finds it blocked and awaits another one in the
// same pass. Two simultaneous seals used to read the same snapshot, the second one would
// re-add ids the first had just set, DNR would reject it, and `seal_failed:true` would be
// written after the first one's `false`: the popup would report a failed seal even though
// it held, and every alarm would replay the alert. Only one seal must fire, and it must
// succeed.
test('concurrent seals share one DNR update and never flag a seal that holds',async t=>{
 t.after(()=>{delete globalThis.chrome;});
 const bridge=managedBridge(policyHandlers,{mode:'grace',remaining_ms:60000});
 const storage={},rules=[];
 globalThis.chrome=fakeChrome(bridge,storage,{webRequest:false,rules,dnr:dnrStore(rules)});
 await import('./background.js?case=seal-race');
 await settled(storage);
 assert.equal(storage.status?.connected,false,'grace without blocking is refused: the status must read blocked');
 assert.equal(storage.seal_failed,false,'the seal holds, so no failure may be flagged');
 assert.deepEqual(rules.map(r=>r.id).sort(),[20000,20001],'the covered surface is sealed exactly once');
});

// Community seals covered services without retaining Enterprise platform rules.
test('a Community seal drops platform blocks and still seals covered services',async t=>{
 t.after(()=>{delete globalThis.chrome;});
 const bridge=managedBridge();bridge.setUnavailable(true);
 const storage={},rules=[{id:1,priority:1,action:{type:'block'},condition:{requestDomains:['chatgpt.com']}},{id:40000,priority:150,action:{type:'block'},condition:{requestDomains:['mammouth.ai','mammouth.ai.']}}];
 globalThis.chrome=fakeChrome(bridge,storage,{rules,dnr:dnrStore(rules)});
 await import('./background.js?case=seal-keeps-platforms');
 await settled(storage);
 assert.equal(storage.status?.connected,false);
 assert.equal(storage.seal_failed,false,'the seal holds');
 assert.deepEqual(rules.map(r=>r.id).sort((a,b)=>a-b),[20000,20001]);
});
