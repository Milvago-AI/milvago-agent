// What a send inspects must be what the person typed, and a send the extension cannot handle
// must say so. Synthetic pages only.
import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {JSDOM} from 'jsdom';
import './adapters.js';
import './capture.js';
const A=globalThis.MilvagoAdapters;
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const SEND='<button type="button" data-testid="chat-input-send">Envoyer</button>';
const box=(text,extra='')=>`<div contenteditable="true" role="textbox" ${extra}>${text}</div>`;
function trusted(type,target,extra={}){return {type,target,isTrusted:true,prevented:false,preventDefault(){this.prevented=true;},stopImmediatePropagation(){},...extra};}
function page(html,send=async()=>({ok:true,action:'observe',text:'',labels:[]})){
 const dom=new JSDOM(html,{url:'https://claude.ai/chat/00000000-0000-4000-8000-000000000000'});
 Object.defineProperty(dom.window.crypto,'subtle',{value:webcrypto.subtle});
 const attach=dom.window.Element.prototype.attachShadow;dom.window.Element.prototype.attachShadow=function(options){const root=attach.call(this,options);this.testShadow=root;return root;};
 const messages=[];
 const controller=globalThis.MilvagoCapture.start(dom.window.document,dom.window.location,msg=>{messages.push(msg);if(msg.type==='policy'){return Promise.resolve({ok:true,policy:{version:2,revision:1,expires_at:'2099-01-01T00:00:00Z',config:{collection:{enabled:false},services:[]}}});}return send(msg);});
 const doc=dom.window.document;
 return {dom,doc,controller,messages,adapter:A.resolve(dom.window.location.href),button:doc.querySelector('[data-testid="chat-input-send"]'),
  inspected(){return messages.filter(m=>m.type==='inspect').map(m=>m.text);},
  dialog(){return [...doc.querySelectorAll('div')].find(x=>x.testShadow)?.testShadow?.textContent||'';},
  close(){controller.dispose();dom.window.close();}};
}
const approve=async msg=>msg.type==='submit'?{ok:true,action:'observe',text:msg.text,durable:true,recording_required:true,authority:null,delivery_id:'00000000-0000-4000-8000-000000000001'}:{ok:true,action:'observe',text:msg.text,labels:[]};

test('a click inspects the visible composer, never a hidden field holding other text',async()=>{
 for(const hidden of ['aria-hidden="true"','hidden','style="display:none"','style="visibility:hidden"']){
  const p=page(`${box('x',hidden)}${box('Synthetic visible draft')}${SEND}`,approve);
  try{await delay(0);const click=trusted('click',p.button);await p.controller.handle(click);assert.equal(click.prevented,true,hidden);assert.deepEqual(p.inspected(),['Synthetic visible draft'],hidden);}finally{p.close();}
 }
});
test('text only in one hidden field is inspected like any send, never let through unread',async()=>{
 for(const [shape,text] of [[box('x','aria-hidden="true"'),'x'],[`<div inert>${box('x')}</div>`,'x'],[`<div hidden>${box('secret draft')}</div>`,'secret draft']]){
  const p=page(shape+SEND,approve);
  try{await delay(0);const click=trusted('click',p.button);await p.controller.handle(click);
   assert.equal(click.prevented,true,shape);assert.deepEqual(p.inspected(),[text],shape);
  }finally{p.close();}
 }
});
test('text in two hidden fields refuses the send with a notice instead of letting it pass',async()=>{
 const p=page(`${box('x','aria-hidden="true"')}<div hidden>${box('secret draft')}</div>${SEND}`,approve);
 try{await delay(0);const click=trusted('click',p.button);await p.controller.handle(click);
  assert.equal(click.prevented,true);assert.deepEqual(p.inspected(),[]);assert.match(p.dialog(),/missing or ambiguous/);
 }finally{p.close();}
});
test('an element the browser reports as not rendered is not the composer',async()=>{
 const p=page(`${box('x','id="ghost"')}${box('Real draft')}${SEND}`,approve);
 try{await delay(0);p.doc.getElementById('ghost').checkVisibility=()=>false;await p.controller.handle(trusted('click',p.button));assert.deepEqual(p.inspected(),['Real draft']);}finally{p.close();}
});
test('two visible drafts are ambiguous and refused; one filled among empty ones is the composer',async()=>{
 let p=page(`${box('first draft')}${box('second draft')}${SEND}`,approve);
 try{await delay(0);const click=trusted('click',p.button);await p.controller.handle(click);assert.equal(click.prevented,true);assert.deepEqual(p.inspected(),[]);assert.match(p.dialog(),/missing or ambiguous/);}finally{p.close();}
 p=page(`${box('')}${box('only draft')}${box('')}${SEND}`,approve);
 try{await delay(0);await p.controller.handle(trusted('click',p.button));assert.deepEqual(p.inspected(),['only draft']);}finally{p.close();}
});
test('the composer nearest to the clicked button wins over a draft elsewhere on the page',async()=>{
 const p=page(`<aside>${box('other panel draft')}</aside><main><section>${box('composer draft')}${SEND}</section></main>`,approve);
 try{await delay(0);await p.controller.handle(trusted('click',p.button));assert.deepEqual(p.inspected(),['composer draft']);}finally{p.close();}
});
test('an image alone in the composer is not a text send and is not swallowed',async()=>{
 const p=page(`${box('<img alt="" src="data:image/png;base64,iVBORw0KGgo=">')}${SEND}`,approve);
 try{await delay(0);const click=trusted('click',p.button);await p.controller.handle(click);assert.equal(click.prevented,false);assert.deepEqual(p.inspected(),[]);}finally{p.close();}
});
test('control characters and binary-looking text reach inspection unchanged',async()=>{
 const odd='a\u0000b‮c�😀';
 const p=page(`${box('')}${SEND}`,approve);
 try{await delay(0);p.doc.querySelector('[role="textbox"]').textContent=odd;await p.controller.handle(trusted('click',p.button));assert.deepEqual(p.inspected(),[odd]);}finally{p.close();}
});
test('an orphaned script (extension reloaded) refuses every send with a reload notice',async()=>{
 for(const failure of [()=>{throw new Error('Extension context invalidated.');},()=>Promise.reject(new Error('Extension context invalidated.'))]){
  const p=page(`${box('Synthetic draft')}${SEND}`,msg=>msg.type==='inspect'?failure():approve(msg));
  try{
   await delay(0);
   for(let attempt=0;attempt<2;attempt++){
    const click=trusted('click',p.button);await p.controller.handle(click);
    assert.equal(click.prevented,true);assert.match(p.dialog(),/Extension updated: reload the page to send/);
   }
   // The second attempt was inspected again: nothing stayed pending.
   assert.equal(p.messages.filter(m=>m.type==='inspect').length,2);
  }finally{p.close();}
 }
});
test('a send button disabled for a moment is clicked once it is enabled again',async()=>{
 const p=page(`${box('Synthetic draft')}${SEND}`,approve);
 try{
  await delay(0);let clicks=0;p.button.addEventListener('click',()=>clicks++);
  p.button.disabled=true;setTimeout(()=>{p.button.disabled=false;},300);
  await p.controller.handle(trusted('click',p.button));
  assert.equal(clicks,1);assert.equal(p.messages.filter(m=>m.type==='submit').length,1);assert.equal(p.dialog(),'');
 }finally{p.close();}
});
test('a send button greyed for seconds while an attachment uploads is still clicked',async()=>{
 const p=page(`${box('Synthetic draft')}${SEND}`,approve);
 try{
  await delay(0);let clicks=0;p.button.addEventListener('click',()=>clicks++);
  // Measured 2026-10-17: an image or a long paste turned attachment keeps the button greyed during its upload.
  p.button.disabled=true;setTimeout(()=>{p.button.disabled=false;},3000);
  await p.controller.handle(trusted('click',p.button));
  assert.equal(clicks,1);assert.equal(p.messages.filter(m=>m.type==='submit').length,1);assert.equal(p.dialog(),'');
 }finally{p.close();}
});
test('a send button that stays disabled is never clicked and is reported, before any recording',async()=>{
 const p=page(`${box('Synthetic draft')}${SEND}`,approve);
 try{
  await delay(0);let clicks=0;p.button.addEventListener('click',()=>clicks++);p.button.setAttribute('aria-disabled','true');
  await p.controller.handle(trusted('click',p.button));
  assert.equal(clicks,0);assert.equal(p.messages.filter(m=>m.type==='submit').length,0);assert.match(p.dialog(),/send button is unavailable/);
 }finally{p.close();}
});
test('spoofed hosts never resolve to a covered provider, and a trailing dot is normalized',()=>{
 for(const url of ['https://claude.ai.attacker.test/','https://attacker.test/claude.ai','https://claude.ai@attacker.test/','http://claude.ai/','https://claude.ai:8443/','https://xn--claude-.ai/','https://claude.ai。attacker.test/']){assert.equal(A.resolve(url),null,url);}
 assert.equal(A.context('https://claude.ai./chat/00000000-0000-4000-8000-000000000000').url,'https://claude.ai/chat/00000000-0000-4000-8000-000000000000');
 assert.equal(A.context('https://claude.ai../').url,'https://claude.ai');
});
test('Enter with no recognized button and no form is replayed on the editor, and an ignored replay is reported',async()=>{
 for(const taken of [true,false]){
  const p=page(box('Synthetic draft'),approve);
  try{
   await delay(0);const editor=p.doc.querySelector('[role="textbox"]'),replayed=[];
   editor.addEventListener('keydown',event=>{if(!event.isTrusted){replayed.push(event.key);if(taken){editor.textContent='';}}});
   const enter=trusted('keydown',editor,{key:'Enter'});await p.controller.handle(enter);
   assert.equal(enter.prevented,true);assert.deepEqual(replayed,['Enter']);assert.equal(p.messages.filter(m=>m.type==='submit').length,1);
   await delay(1600);
   if(taken){assert.equal(p.dialog(),'');}else{assert.match(p.dialog(),/Click the service’s send button/);}
  }finally{p.close();}
 }
});
test('an editor nested in another matching editor is one composer, not an ambiguity',async()=>{
 const p=page(`<div class="ProseMirror" contenteditable="true"><p>Nested draft</p><div contenteditable="true" role="textbox">Nested draft</div></div>${SEND}`,approve);
 try{await delay(0);await p.controller.handle(trusted('click',p.button));assert.equal(p.inspected().length,1);assert.match(p.inspected()[0],/Nested draft/);}finally{p.close();}
});
// Second review, I2: a provider may keep a hidden field worth "x" beside its composer and send
// a file alone with the visible editor empty. That one field is inspected and approved like any
// send; two filled hidden fields leave no field that can be trusted.
test('an empty visible composer beside one hidden field holding text inspects that field',async()=>{
 for(const hidden of ['aria-hidden="true"','style="display:none"']){
  const p=page(`${box('hidden secret draft',hidden)}${box('')}${SEND}`,approve);
  try{await delay(0);const click=trusted('click',p.button);await p.controller.handle(click);
   assert.equal(click.prevented,true,hidden);assert.deepEqual(p.inspected(),['hidden secret draft'],hidden);assert.equal(p.dialog(),'',hidden);
  }finally{p.close();}
 }
});
test('an empty visible composer beside two hidden fields holding text refuses the send',async()=>{
 const p=page(`${box('x','aria-hidden="true"')}${box('hidden secret draft','style="display:none"')}${box('')}${SEND}`,approve);
 try{await delay(0);const click=trusted('click',p.button);await p.controller.handle(click);
  assert.equal(click.prevented,true);assert.deepEqual(p.inspected(),[]);assert.match(p.dialog(),/missing or ambiguous/);
 }finally{p.close();}
});
// Fourth review, M3: while the confirmed masked text is being written into the draft, a second
// send must not start its own inspection of the half-written draft.
test('a send during the write of the confirmed masked text is ignored',async()=>{
 const p=page(`${box('Bonjour 4111 1111 1111 1111')}${SEND}`,async msg=>msg.type==='inspect'?{ok:true,action:'review',text:'Bonjour [CARD]',labels:['card']}:approve(msg));
 const write=A.write;let release;A.write=(editor,text)=>new Promise(resolve=>{release=()=>{editor.textContent=text;resolve(text);};});
 try{await delay(0);await p.controller.handle(trusted('click',p.button));
  [...p.doc.querySelector('div[contenteditable]').ownerDocument.querySelectorAll('div')].find(x=>x.testShadow).testShadow.querySelector('button').click();
  await delay(0);assert.equal(typeof release,'function','the write is under way');
  const again=trusted('click',p.button);await p.controller.handle(again);
  assert.equal(again.prevented,true);assert.equal(p.inspected().length,1,'no second inspection during the write');
  release();await delay(0);
 }finally{A.write=write;p.close();}
});
