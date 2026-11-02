// Real campaign 0.7.3: signed-out ChatGPT recorded two answers for one prompt. Its answer can
// match the response selector twice, an outer message and its inner text (the catalogue names
// both shapes): one answer must be one response. The conversation of `/uc/<id>` is the thread.
import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {JSDOM} from 'jsdom';
import {readFile} from 'node:fs/promises';
globalThis.browser={runtime:{id:'synthetic-extension',onMessage:{addListener(){},removeListener(){}}},storage:{local:{get:async()=>({}),set:async()=>{}}}};
await import('./adapters.js');await import('./capture.js');
const A=globalThis.MilvagoAdapters;

test('an answer matched twice by the response selector is one response',async()=>{
 const dom=new JSDOM('<form><textarea id="mobile-composer-prompt"></textarea><button type="submit">Send</button></form><ul id="thread"></ul>',{url:'https://chatgpt.com/'}),doc=dom.window.document;
 Object.defineProperty(dom.window.crypto,'subtle',{value:webcrypto.subtle});
 doc.querySelector('form').addEventListener('submit',e=>e.preventDefault());
 const events=[],policy={config:{collection:{enabled:true,store_content:false},services:[{enabled:true,domains:['chatgpt.com']}]}};
 const controller=globalThis.MilvagoCapture.start(doc,dom.window.location,async msg=>{
  if(msg.type==='policy'){return {ok:true,policy};}if(msg.type==='inspect'){return {ok:true,action:'observe',text:msg.text};}
  if(msg.type==='submit'){return {ok:true,action:'observe',text:msg.text,durable:true,recording_required:true,authority:'a'.repeat(64),delivery_id:'00000000-0000-4000-8000-000000000001'};}
  if(msg.type==='event'){events.push(msg.event);return {ok:true};}return {ok:true};
 });
 try{
  await new Promise(r=>setImmediate(r));
  const editor=doc.querySelector('textarea');await A.write(editor,'Synthetic prompt');
  await controller.handle({type:'click',target:doc.querySelector('button'),isTrusted:true,preventDefault(){},stopImmediatePropagation(){}});
  doc.getElementById('thread').innerHTML='<li data-message-role="assistant"><div data-message-author-role="assistant">Synthetic answer</div></li>';
  await new Promise(r=>setTimeout(r,3000));
  assert.equal(events.filter(e=>e.kind==='response').length,1);
 }finally{controller.dispose();dom.window.close();}
});

test('the signed-out thread /uc/<id> names its conversation',async()=>{
 const factory=JSON.parse(await readFile(new URL('./detection-factory.json',import.meta.url)));
 const id='6aa99383-dd04-83ea-88fb-50a164a3820d';
 try{
  for(const catalog of [null,factory]){A.applyCatalog(catalog);assert.equal(A.context(`https://chatgpt.com/uc/${id}`)?.conversation_id,id,catalog?'catalogue':'adapters');}
 }finally{A.applyCatalog(null);}
});
