import test from 'node:test';
import assert from 'node:assert/strict';
import {Fusion} from './detection.js';
const id='12345678-1234-4234-8234-123456789012';
const event={kind:'response',provider:'chatgpt.com',action:'observed',characters:9,response:'synthetic'};
test('a response retry preserves its delivery identity after a lost acknowledgement',async()=>{
 const received=new Map(),calls=[];let lose=true;
 const fusion=new Fusion(async(value,delivery,retry)=>{calls.push({delivery,retry});received.set(delivery,value);if(lose){lose=false;throw Error('lost acknowledgement');}return {ok:true,id:delivery};});
 await assert.rejects(fusion.add(event,'document',null,'dom',true,'authority',id),/lost acknowledgement/);
 assert.equal(fusion.pending.length,1);
 await fusion.add(event,'document',null,'dom',true,'authority',id);
 assert.equal(fusion.pending.length,0);assert.equal(received.size,1);
 assert.deepEqual(calls,[{delivery:id,retry:false},{delivery:id,retry:true}]);
});
test('a reused capture identity cannot replace another document or payload',async()=>{
 const fusion=new Fusion(async()=>{throw Error('offline');});
 await fusion.add(event,'document',null,'dom',false,'authority',id);
 for(const [value,document,authority] of [[{...event,response:'changed'},'document','authority'],[event,'other','authority'],[event,'document','other']]){
  await assert.rejects(fusion.add(value,document,null,'dom',true,authority,id),/collision/);
 }
 assert.equal(fusion.pending.length,1);assert.equal(fusion.pending[0].event.response,'synthetic');
 await assert.rejects(fusion.add(event,'document',null,'dom',true,'authority','invalid'),/identity/);
});
