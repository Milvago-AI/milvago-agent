// Real campaign 0.7.3: a file the policy refused left no event at all, and a prompt blocked on a
// protected word did not say why. Synthetic page, policy and file.
import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {JSDOM} from 'jsdom';
import {eventForPolicy} from './policy.js';
globalThis.browser={runtime:{id:'synthetic-extension',onMessage:{addListener(){},removeListener(){}}},storage:{local:{get:async()=>({}),set:async()=>{}}}};
await import('./adapters.js');await import('./capture.js');
const A=globalThis.MilvagoAdapters;
const policy={version:3,revision:4,expires_at:'2099-01-01T00:00:00Z',config:{collection:{enabled:true,store_content:false,store_file_names:true},services:[{id:'chatgpt',enabled:true,mode:'observe',domains:['chatgpt.com']}],model_access:[]}};

function page(inspect){
 const dom=new JSDOM('<form><textarea id="mobile-composer-prompt"></textarea><button type="submit">Send</button><input type="file"></form>',{url:'https://chatgpt.com/'}),doc=dom.window.document;
 Object.defineProperty(dom.window.crypto,'subtle',{value:webcrypto.subtle});
 doc.documentElement.lang='fr';
 const events=[],shadows=[],attach=dom.window.Element.prototype.attachShadow;
 // The notice lives in a closed shadow root: opened here so the test can read it.
 dom.window.Element.prototype.attachShadow=function(init){const root=attach.call(this,{...init,mode:'open'});shadows.push(root);return root;};
 const controller=globalThis.MilvagoCapture.start(doc,dom.window.location,async msg=>{
  if(msg.type==='policy'){return {ok:true,policy};}if(msg.type==='inspect'){return inspect(msg);}
  if(msg.type==='event'){events.push(msg.event);return {ok:true};}return {ok:true};
 });
 return {dom,doc,controller,events,get notices(){return shadows.map(s=>s.textContent);},close(){controller.dispose();dom.window.close();}};
}

test('a refused file is recorded as blocked, with its name, and the notice says it is refused',async()=>{
 const p=page(msg=>msg.upload?{ok:true,action:'block',text:'',labels:[],reason:'Les fichiers sont interdits.'}:{ok:true,action:'observe',text:msg.text,labels:[]});
 try{
  await new Promise(r=>setImmediate(r));
  const input=p.doc.querySelector('input[type="file"]'),file=new p.dom.window.File(['x'],'synthetic-report.pdf');
  Object.defineProperty(input,'files',{value:[file]});
  await p.controller.upload({type:'change',target:input,isTrusted:true,preventDefault(){},stopImmediatePropagation(){}});
  for(let i=0;i<20;i++){await new Promise(r=>setTimeout(r,0));}
  const blocked=p.events.filter(e=>e.action==='blocked');
  assert.equal(blocked.length,1);
  assert.deepEqual([blocked[0].kind,blocked[0].decision_reason,blocked[0].files],['prompt','upload_blocked',['synthetic-report.pdf']]);
  assert.ok(p.notices.some(text=>text.includes('Fichier refusé')),p.notices.join(' | '));
 }finally{p.close();}
});

test('a prompt blocked on a protected word says so',async()=>{
 const p=page(()=>({ok:true,action:'block',text:'x',labels:['keyword'],reason:'Mot protégé.'}));
 try{
  await new Promise(r=>setImmediate(r));
  await A.write(p.doc.querySelector('textarea'),'Synthetic PRJ-0000');
  await p.controller.handle({type:'click',target:p.doc.querySelector('button'),isTrusted:true,preventDefault(){},stopImmediatePropagation(){}});
  for(let i=0;i<20;i++){await new Promise(r=>setTimeout(r,0));}
  const blocked=p.events.filter(e=>e.action==='blocked');
  assert.equal(blocked.length,1);
  assert.equal(blocked[0].decision_reason,'keyword');
 }finally{p.close();}
});

test('the worker keeps only the reasons a page may state, on a blocked prompt',()=>{
 const base={kind:'prompt',action:'blocked',characters:0,labels:[],url:'https://chatgpt.com/'};
 for(const [input,expected] of [
  [{...base,decision_reason:'keyword'},'keyword'],
  [{...base,decision_reason:'upload_blocked',files:['synthetic-report.pdf']},'upload_blocked'],
  [{...base,decision_reason:'model_denied'},undefined],
  [{...base,action:'observed',decision_reason:'keyword'},undefined],
 ]){assert.equal(eventForPolicy(input,'https://chatgpt.com/',"chrome",policy)?.decision_reason,expected,JSON.stringify(input));}
 assert.deepEqual(eventForPolicy({...base,decision_reason:'upload_blocked',files:['synthetic-report.pdf']},'https://chatgpt.com/','chrome',policy).files,['synthetic-report.pdf']);
});

test('a DLP upload refusal already journaled by the broker is not duplicated by the page',async()=>{
 const p=page(()=>({ok:true,action:'block',text:'',labels:[],dlp_recorded:true,reason:'Synthetic DLP rule'}));
 try{
  await new Promise(r=>setImmediate(r));
  const input=p.doc.querySelector('input[type="file"]');Object.defineProperty(input,'files',{value:[new p.dom.window.File(['x'],'synthetic.pdf')]});
  await p.controller.upload({type:'change',target:input,isTrusted:true,preventDefault(){},stopImmediatePropagation(){}});
  await new Promise(r=>setImmediate(r));assert.equal(p.events.filter(e=>e.action==='blocked').length,0);
  assert.ok(p.notices.some(text=>text.includes('Fichier refusé')));
 }finally{p.close();}
});
