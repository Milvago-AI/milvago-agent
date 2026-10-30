// An editor may keep a long paste as a chip: it shows `text.trim().replace(/\s+/g,' ').slice(0,100)`, its
// `innerText` reads that preview, a line break, then the space the editor puts after the chip and the draft, while
// the request carries the whole paste then the draft less that one space (measured by CDP on 2026-10-17). The
// receipt of the send names that request from the paste the document saw: one record, not two. Synthetic texts.
import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto,createHash} from 'node:crypto';
import {JSDOM} from 'jsdom';
const listeners=new Set();
globalThis.browser={runtime:{id:'synthetic-extension',onMessage:{addListener:f=>listeners.add(f),removeListener:f=>listeners.delete(f)}},storage:{local:{get:async()=>({}),set:async()=>{}}}};
await import('./adapters.js');await import('./capture.js');
const delay=ms=>new Promise(r=>setTimeout(r,ms));
const CHIP='Synthetic first line of a long paste.    \r\n'+'Synthetic filler sentence, no real data. '.repeat(40)+'\r\nEnd.';
const preview=text=>text.trim().replace(/\s+/g,' ').slice(0,100);
const ids=['00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000002','00000000-0000-4000-8000-000000000003'];
// Named through the chip: flagged with the send's correlation, so a request carrying more than the record is not lost.
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
function chipNamed(response,id,label){const {correlation_id,...rest}=response||{};assert.match(correlation_id||'',UUID,label);assert.deepEqual(rest,{ok:true,delivery_id:id,authority:'a'.repeat(64),chip:true},label);}
const sha=text=>createHash('sha256').update(text).digest('hex');
function query(fingerprint){let response;for(const listener of listeners){listener({type:'detection-receipt',fingerprint},{id:'synthetic-extension'},value=>{response=value;});}return response;}
const clipboard=text=>({files:[],types:['text/plain'],getData:type=>type==='text/plain'?text:''});
function page(){
 const dom=new JSDOM('<form><div id="prompt-textarea" class="ProseMirror" contenteditable="true"><p></p></div><button data-testid="send-button">Send</button></form>',{url:'https://chatgpt.com/'}),doc=dom.window.document;
 Object.defineProperty(dom.window.crypto,'subtle',{value:webcrypto.subtle});
 doc.querySelector('form').addEventListener('submit',e=>e.preventDefault());
 const editor=doc.querySelector('#prompt-textarea');let chip=null;
 const show=draft=>{editor.innerHTML=`<p><span contenteditable="false"><button type="button">${preview(chip)}</button></span>\n ${draft}</p>`;};
 let n=0;const policy={version:2,revision:1,expires_at:'2099-01-01T00:00:00Z',config:{collection:{enabled:true,store_content:false},services:[{enabled:true,domains:['chatgpt.com']}]}};
 const controller=globalThis.MilvagoCapture.start(doc,dom.window.location,async msg=>{
  if(msg.type==='policy'){return {ok:true,policy};}if(msg.type==='inspect'){return {ok:true,action:'observe',text:msg.text};}
  if(msg.type==='submit'){return {ok:true,action:'observe',text:msg.text,durable:true,recording_required:true,authority:'a'.repeat(64),delivery_id:ids[n++]};}
  return {ok:true};
 });
 return {editor,show,controller,
  async paste(text,isTrusted=true){await controller.paste({type:'paste',target:editor,isTrusted,clipboardData:clipboard(text),preventDefault(){},stopImmediatePropagation(){}});chip=text;show('');},
  send:()=>controller.handle({type:'click',target:doc.querySelector('[data-testid="send-button"]'),isTrusted:true,preventDefault(){},stopImmediatePropagation(){}}),
  close(){controller.dispose();dom.window.close();}};
}

test('a chip and the draft typed after it: the request is named by the receipt of the send',async()=>{
 const p=page();
 try{
  await delay(0);await p.paste(CHIP);p.show(' Synthetic question');await p.send();
  chipNamed(query(sha(CHIP+' Synthetic question')),ids[0]);
  p.show('');await p.send();
  chipNamed(query(sha(CHIP)),ids[1],'the chip alone');
  // The text the DOM read names the send without the flag.
  p.show(' Other');const read=globalThis.MilvagoAdapters.read(p.editor);await p.send();
  assert.deepEqual(query(sha(read)),{ok:true,delivery_id:ids[2],authority:'a'.repeat(64)},'the draft as read');
 }finally{p.close();}
});

test('another text, another draft, or a paste that was not trusted is not named',async()=>{
 const p=page();
 try{
  await delay(0);await p.paste(CHIP);p.show('Synthetic question');await p.send();
  for(const text of [CHIP.replace('End.','Fin.')+'Synthetic question',CHIP+'Other question',preview(CHIP)+'Synthetic question']){assert.deepEqual(query(sha(text)),{ok:true,delivery_id:null});}
 }finally{p.close();}
 const q=page();
 try{await delay(0);await q.paste(CHIP,false);q.show('Synthetic question');await q.send();assert.deepEqual(query(sha(CHIP+'Synthetic question')),{ok:true,delivery_id:null});}finally{q.close();}
});
