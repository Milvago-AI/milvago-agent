import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto,createHash} from 'node:crypto';
import {JSDOM} from 'jsdom';
const listeners=new Set(),storageWrites=[];
globalThis.browser={runtime:{id:'synthetic-extension',onMessage:{addListener:f=>listeners.add(f),removeListener:f=>listeners.delete(f)}},storage:{local:{get:async()=>({}),set:async v=>storageWrites.push(v)}}};
await import('./adapters.js');await import('./capture.js');
const A=globalThis.MilvagoAdapters,text='Synthetic prompt',hash=createHash('sha256').update(text).digest('hex');
const ids=['00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000002'];
function query(fingerprint=hash,sender={id:'synthetic-extension'}){let response;for(const listener of listeners){listener({type:'detection-receipt',fingerprint},sender,value=>{response=value});}return response;}
const click=target=>({type:'click',target,isTrusted:true,preventDefault(){},stopImmediatePropagation(){}});
async function fixture(reply,policyReply){
 const dom=new JSDOM('<form><textarea id="prompt-textarea"></textarea><button data-testid="send-button">Send</button></form>',{url:'https://chatgpt.com/'}),doc=dom.window.document;
 Object.defineProperty(dom.window.crypto,'subtle',{value:webcrypto.subtle});let submissions=0,count=0;
 doc.querySelector('form').addEventListener('submit',e=>{e.preventDefault();submissions++});
 const policy={config:{collection:{enabled:true,store_content:false},services:[{enabled:true,domains:['chatgpt.com']}]}};
 const controller=globalThis.MilvagoCapture.start(doc,dom.window.location,async msg=>{
  if(msg.type==='policy'){return policyReply?.()||{ok:true,policy};}if(msg.type==='inspect'){return {ok:true,action:'observe',text:msg.text};}if(msg.type==='submit'){return reply?reply(msg):{ok:true,action:'observe',text:msg.text,durable:true,recording_required:true,authority:'a'.repeat(64),delivery_id:ids[count++]};}return {ok:true};
 });await new Promise(r=>setImmediate(r));
 const editor=doc.querySelector('textarea'),button=doc.querySelector('button');A.write(editor,text);
 return {dom,controller,submissions:()=>submissions,submit:async()=>{await controller.handle(click(button));},close(){controller.dispose();dom.window.close()}};
}
test('two identical submits survive worker queries and consume receipt FIFO only once',async()=>{
 const f=await fixture();try{await f.submit();await f.submit();assert.equal(f.submissions(),2);assert.deepEqual(query(),{ok:true,delivery_id:ids[0],authority:'a'.repeat(64)});assert.deepEqual(query(),{ok:true,delivery_id:ids[1],authority:'a'.repeat(64)});assert.deepEqual(query(),{ok:true,delivery_id:null});assert.equal(JSON.stringify(storageWrites).includes(hash),false);assert.equal(JSON.stringify(storageWrites).includes(ids[0]),false);}finally{f.close()}
});
test('queries reject malformed digests and foreign senders without consuming the marker',async()=>{
 const f=await fixture();try{await f.submit();assert.deepEqual(query('bad'),{ok:false});assert.deepEqual(query(hash,{id:'foreign-extension'}),{ok:false});assert.deepEqual(query(hash,{id:'synthetic-extension',tab:{id:1}}),{ok:false});assert.deepEqual(query('b'.repeat(64)),{ok:true,delivery_id:null});assert.deepEqual(query(),{ok:true,delivery_id:ids[0],authority:'a'.repeat(64)});}finally{f.close()}
});
test('no receipt marker before durable submit acknowledgement or after refused submit',async()=>{
 let finish;const gate=new Promise(resolve=>finish=resolve);const f=await fixture(()=>gate);
 try{const sending=f.submit();await new Promise(r=>setImmediate(r));assert.deepEqual(query(),{ok:true,delivery_id:null});assert.equal(f.submissions(),0);finish({ok:true,action:'observe',text,durable:false,recording_required:true,delivery_id:ids[0]});await sending;assert.deepEqual(query(),{ok:true,delivery_id:null});assert.equal(f.submissions(),0);}finally{f.close()}
});
// Slow network: the periodic policy refresh (30 s) used to fail during a
// pending submission, `policy` became `undefined`, the submission's snapshot no longer
// matched, and the page displayed "Final validation or durable recording failed."
test('a failed policy refresh during a pending submit does not abort it',async()=>{
 let finish,refreshFails=false;const gate=new Promise(resolve=>finish=resolve);
 const f=await fixture(msg=>gate.then(()=>({ok:true,action:'observe',text:msg.text,durable:true,recording_required:true,authority:'a'.repeat(64),delivery_id:ids[0]})),()=>refreshFails?{ok:false}:null);
 try{const sending=f.submit();await new Promise(r=>setImmediate(r));refreshFails=true;await f.controller.refresh();finish();await sending;assert.equal(f.submissions(),1);}finally{f.close()}
});
test('automatically assigned conversation preserves just-submitted receipt, later navigation clears it',async()=>{
 const f=await fixture();try{await f.submit();f.dom.window.history.pushState({},'', '/c/00000000-0000-4000-8000-000000000001');f.controller.navigation();assert.deepEqual(query(),{ok:true,delivery_id:ids[0],authority:'a'.repeat(64)});await f.submit();f.dom.window.history.pushState({},'', '/c/00000000-0000-4000-8000-000000000002');f.controller.navigation();assert.deepEqual(query(),{ok:true,delivery_id:null});}finally{f.close()}
});

test('receipt listener exists on a supported page with an empty DOM',async()=>{
 const dom=new JSDOM('<main></main>',{url:'https://chatgpt.com/'});const controller=globalThis.MilvagoCapture.start(dom.window.document,dom.window.location,async()=>({ok:false}));
 try{assert.ok(controller);assert.deepEqual(query(),{ok:true,delivery_id:null});}finally{controller.dispose();dom.window.close()}
});
test('invalid durable receipt never replays or creates a marker',async()=>{
 const f=await fixture(msg=>({ok:true,action:'observe',text:msg.text,durable:true,recording_required:true,authority:'a'.repeat(64),delivery_id:'malformed'}));try{await f.submit();assert.equal(f.submissions(),0);assert.deepEqual(query(),{ok:true,delivery_id:null});}finally{f.close()}
});
test('the document marker queue retains at most 128 receipt identities',async()=>{
 let count=0;const id=n=>'00000000-0000-4000-8000-'+String(n).padStart(12,'0');
 const f=await fixture(msg=>({ok:true,action:'observe',text:msg.text,durable:true,recording_required:true,authority:'a'.repeat(64),delivery_id:id(++count)}));try{for(let n=0;n<129;n++){await f.submit();}assert.equal(f.submissions(),129);for(let n=2;n<=129;n++){assert.deepEqual(query(),{ok:true,delivery_id:id(n),authority:'a'.repeat(64)});}assert.deepEqual(query(),{ok:true,delivery_id:null});}finally{f.close()}
});
