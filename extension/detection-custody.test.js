import test from 'node:test';
import assert from 'node:assert/strict';
import {Fusion} from './detection.js';

const clone=value=>JSON.parse(JSON.stringify(value));
const deferred=()=>{let resolve,reject;const promise=new Promise((ok,fail)=>{resolve=ok;reject=fail;});return {promise,resolve,reject};};
const event=label=>({provider:'fixture.test',kind:'prompt',action:'observed',characters:label.length,label});
const identity='7|document-a|fixture',otherDocument='7|document-b|fixture';
const digestA='a'.repeat(64),digestB='b'.repeat(64);

test('a failed first persistence never accepts an event',async()=>{
 let now=0,calls=0;const gate=deferred();
 const fusion=new Fusion(async()=>{calls++;},()=>now,()=>gate.promise);
 const adding=fusion.add(event('first'),identity,digestA,'dom');
 await Promise.resolve();assert.equal(fusion.pending.length,0);assert.equal(calls,0);
 gate.reject(new Error('storage rejected'));
 await assert.rejects(adding,/storage rejected/);
 assert.equal(fusion.pending.length,0);assert.equal(calls,0);
});

test('a refused delivery retains the pending event and its stable identity',async()=>{
 let now=0;const writes=[];let fail=true;
 const fusion=new Fusion(async()=>{if(fail){throw new Error('delivery refused');}},()=>now,async rows=>{writes.push(clone(rows));});
 await fusion.add(event('refused'),identity,digestA,'dom');const id=fusion.pending[0].id;
 now=3001;await assert.rejects(fusion.flush(),/delivery refused/);
 assert.equal(fusion.pending.length,1);assert.equal(fusion.pending[0].id,id);assert.equal(fusion.pending[0].attempted,true);
 assert.ok(writes.every(rows=>rows.every(row=>!Object.hasOwn(row,'digest'))));
 fail=false;await fusion.flush();assert.equal(fusion.pending.length,0);
});

test('a lost acknowledgement survives reopening with the exact payload and stable identity',async()=>{
 let now=0,removeFails=true;let durable=[],first;
 const persist=async rows=>{if(removeFails&&rows.length===0){throw new Error('remove failed');}durable=clone(rows);};
 const original=new Fusion(async(value,id)=>{first={value:clone(value),id};},()=>now,persist);
 await original.add(event('reopen'),identity,digestA,'network');
 now=3001;await assert.rejects(original.flush(),/remove failed/);
 assert.equal(durable.length,1);assert.equal(durable[0].id,first.id);assert.equal(durable[0].attempted,true);assert.ok(!Object.hasOwn(durable[0],'digest'));
 removeFails=false;let retry;
 const reopened=new Fusion(async(value,id)=>{retry={value:clone(value),id};},()=>now,persist);
 reopened.restore(durable);await reopened.flush();
 assert.deepEqual(retry,first);assert.equal(reopened.pending.length,0);
});

test('a removal persistence failure retries the same payload identity',async()=>{
 let now=0,failRemoval=true;const calls=[];
 const fusion=new Fusion(async(value,id)=>calls.push({value:clone(value),id}),()=>now,async rows=>{if(failRemoval&&rows.length===0){throw new Error('remove failed');}});
 await fusion.add(event('retry'),identity,digestA,'network');now=3001;
 await assert.rejects(fusion.flush(),/remove failed/);failRemoval=false;await fusion.flush();
 assert.equal(calls.length,2);assert.deepEqual(calls[1],calls[0]);assert.equal(fusion.pending.length,0);
});

test('a later fusion cannot alter an event whose delivery was attempted',async()=>{
 let now=100;const calls=[];let reject=true;
 const fusion=new Fusion(async(value,id)=>{calls.push({value:clone(value),id});if(reject){throw new Error('temporary refusal');}},()=>now,async()=>{});
 await fusion.add(event('dom'),identity,digestA,'dom');now=3100;await assert.rejects(fusion.flush(),/temporary refusal/);
 await assert.rejects(fusion.add(event('network'),identity,digestA,'network'),/temporary refusal/);
 assert.equal(fusion.pending.length,1);assert.equal(fusion.pending[0].event.label,'dom');
 reject=false;await fusion.flush();assert.equal(calls.at(-1).value.label,'dom');
});

test('the durable queue caps at 128 entries',async()=>{
 let now=0;const fusion=new Fusion(async()=>{},()=>now,async()=>{});
 for(let index=0;index<128;index++){await fusion.add(event(String(index)),index+'|document|fixture',String(index).padStart(64,'0'),'dom');}
 await assert.rejects(fusion.add(event('overflow'),'overflow|document|fixture',digestA,'dom'),/queue full/);
 assert.equal(fusion.pending.length,128);
});

test('concurrent additions and a flush retain one fused delivery',async()=>{
 let now=3001;const calls=[];const gate=deferred();let firstWrite=true;
 const fusion=new Fusion(async(value,id)=>calls.push({value:clone(value),id}),()=>now,async()=>{if(firstWrite){firstWrite=false;await gate.promise;}});
 const dom=fusion.add({...event('dom'),correlation_id:'dom'},identity,digestA,'dom');
 await Promise.resolve();const network=fusion.add({...event('network'),correlation_id:'network'},identity,digestA,'network');const flushing=fusion.flush();
 gate.resolve();await Promise.all([dom,network,flushing]);
 assert.equal(calls.length,1);assert.equal(calls[0].value.detector,'both');assert.equal(calls[0].value.correlation_id,'dom');assert.equal(fusion.pending.length,0);
});

test('a received delivery receipt persists its identity and resumes custody safely',async()=>{
 let now=0;const writes=[],calls=[],order=[];let refuse=true;
 const receipt='00000000-0000-4000-8000-000000000001';
 const fusion=new Fusion(async(value,id,retry)=>{
  order.push('emit');calls.push({value:clone(value),id,retry});if(refuse){throw new Error('enqueue refused');}
 },()=>now,async rows=>{order.push('persist');writes.push(clone(rows));});
 const received=event('received');
 await assert.rejects(fusion.resume(received,identity,receipt),/enqueue refused/);
 assert.deepEqual(order.slice(0,2),['persist','emit']);
 assert.equal(fusion.pending.length,1);assert.equal(fusion.pending[0].id,receipt);
 assert.equal(calls[0].id,receipt);assert.equal(calls[0].retry,true);
 assert.deepEqual(writes[0][0].event,received);
 await assert.rejects(fusion.resume(event('bad'),identity,'not-a-receipt'),/Invalid delivery receipt/);
 assert.throws(()=>fusion.restore([writes[0][0],writes[0][0]]),/Duplicate pending delivery identity/);

 const restoredCalls=[];const restored=new Fusion(async(value,id,retry)=>restoredCalls.push({value:clone(value),id,retry}),()=>now,async()=>{});
 restored.restore(writes[0]);await restored.flush();
 assert.equal(restoredCalls.length,1);assert.equal(restoredCalls[0].id,receipt);assert.equal(restoredCalls[0].retry,true);

 refuse=false;await fusion.resume(received,identity,receipt);
 assert.equal(calls.length,2);assert.equal(calls[1].id,receipt);assert.equal(calls[1].retry,true);
 assert.equal(fusion.pending.some(row=>row.id===receipt),false);

 const prepared=event('before-mutation');prepared.nested={value:'original'};
 const preparation=await fusion.prepare(prepared,identity);prepared.label='mutated';prepared.nested.value='mutated';
 await fusion.flush();assert.equal(calls.length,2,'inflight preparation must not deliver during flush');
 fusion.release(preparation);await fusion.flush();
 assert.equal(calls.length,3);
 assert.equal(calls.at(-1).id,preparation);assert.equal(calls.at(-1).retry,true);
 assert.equal(calls.at(-1).value.label,'before-mutation');assert.equal(calls.at(-1).value.nested.value,'original');
});
