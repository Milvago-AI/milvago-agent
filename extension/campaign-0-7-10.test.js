// Real campaign 0.7.10 (observation, 2026-10-17). Synthetic pages and texts; shapes measured on the
// real pages: an empty claude.ai composer reads "\n" in Chrome (ProseMirror's trailing break), the
// paste goes as a protobuf `PerformAction` with an empty 2.3 and its content at 2.15.4, and the
// claude.ai bundle renders one answer turn as several rows sharing `data-turn-key`, the streaming
// flag on the first row only, the stop button `chat-input-stop` labelled in the interface language.
import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {JSDOM} from 'jsdom';
let receipt=null;
globalThis.browser={runtime:{id:'synthetic-extension',onMessage:{addListener(fn){if(fn.length===3){receipt=fn;}},removeListener(){}}}};
await import('./adapters.js');await import('./capture.js');
const {observeRequest}=await import('./detection.js');
const {factoryCatalog}=await import('./detection-factory.js');
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const observe={version:2,revision:1,expires_at:'2099-01-01T00:00:00Z',config:{collection:{enabled:true,store_content:false},services:[{id:'claude',enabled:true,mode:'observe',domains:['claude.ai']}]}};
function trusted(type,target,extra={}){return {type,target,isTrusted:true,prevented:false,get defaultPrevented(){return this.prevented;},preventDefault(){this.prevented=true;},stopImmediatePropagation(){},...extra};}
function page(){
 const dom=new JSDOM('<main id="thread"></main><div class="ProseMirror" role="textbox" contenteditable="true"><p><br class="ProseMirror-trailingBreak"></p></div><button type="button" data-testid="chat-input-send">Envoyer</button>',{url:'https://claude.ai/chat/6ad30bf2-0000-4000-8000-000000000001'});
 Object.defineProperty(dom.window.crypto,'subtle',{value:webcrypto.subtle});
 const doc=dom.window.document,field=doc.querySelector('[contenteditable]'),button=doc.querySelector('button');
 // Chrome's innerText of a ProseMirror editor (scratchpad r094/innertext.mjs): an empty paragraph reads "\n".
 Object.defineProperty(field,'innerText',{configurable:true,get(){const blocks=[...field.querySelectorAll('p')];return blocks.length?blocks.map(p=>p.textContent||'\n').join('\n\n'):field.textContent;}});
 const messages=[];let serial=0;
 const controller=globalThis.MilvagoCapture.start(doc,dom.window.location,async msg=>{
  messages.push(msg);
  if(msg.type==='policy'){return {ok:true,policy:observe};}
  if(msg.type==='submit'){serial++;return {ok:true,action:'observe',text:msg.text,durable:true,recording_required:true,authority:null,delivery_id:'00000000-0000-4000-8000-00000000000'+serial};}
  return {ok:true,action:'observe',text:msg.text||'',labels:[]};
 });
 const set=text=>{field.innerHTML=text?`<p>${text}</p>`:'<p><br class="ProseMirror-trailingBreak"></p>';};
 return {dom,doc,controller,messages,field,button,set,close(){controller.dispose();dom.window.close();}};
}
const ask=fingerprint=>new Promise(resolve=>receipt({type:'detection-receipt',fingerprint},{id:'synthetic-extension'},resolve));
const sends=p=>p.messages.filter(m=>m.type==='submit'&&!m.upload);
const answers=p=>p.messages.filter(m=>m.type==='event'&&m.event.kind==='response').map(m=>m.event);

// The protobuf body of `PerformAction` (protobuf-guard.test.js), synthetic values. proto3 leaves an empty
// draft out (no 2.3): the campaign's network prompt held the chip's 15 215 characters alone.
const varint=n=>{const out=[];let v=BigInt(n);do{let b=Number(v&127n);v>>=7n;if(v){b|=128;}out.push(b);}while(v);return out;};
const f=(field,value)=>typeof value==='number'?[...varint(field*8),...varint(value)]:(bytes=>[...varint(field*8+2),...varint(bytes.length),...bytes])(typeof value==='string'?[...new TextEncoder().encode(value)]:value);
const msg=(...parts)=>parts.flat();
const CONV='00000000-0000-4000-8000-000000000000';
const performSend=(text,content)=>msg(f(1,msg(f(2,CONV),f(3,3),f(14,'fr-FR'))),f(2,msg(f(1,'11111111-1111-4111-8111-111111111111'),...(text?[f(3,text)]:[]),f(15,msg(f(2,content.length),f(3,'txt'),f(4,content))),f(18,1))));
const PERFORM='https://claude.ai/claudeai-rpc/anthropic.bard.api.v1alpha.ConversationService/PerformAction';
// 15 215 characters, as in the campaign: synthetic lines.
const pasted=('Ligne synthetique sans valeur, numero '.padEnd(60,'.')+'\n').repeat(250).slice(0,15215);

test('claude, observation: the network prompt of a chip sent from an empty composer ("\\n") gets its correlation',async()=>{
 const p=page();
 try{
  await delay(0);
  const clip={files:[],types:['text/plain'],getData:type=>type==='text/plain'?pasted:''};
  await p.controller.paste(trusted('paste',p.field,{clipboardData:clip}));
  const enter=trusted('keydown',p.field,{key:'Enter'});await p.controller.handle(enter);await delay(20);
  const [send]=sends(p);assert.equal(send?.text,'\n','the composer as Chrome reads it');
  const hit=await observeRequest({url:PERFORM,method:'POST',requestBody:{raw:[{bytes:Uint8Array.from(performSend('',pasted)).buffer}]}},factoryCatalog,true);
  assert.equal(hit.characters,15215);assert.match(hit.fingerprint,/^[0-9a-f]{64}$/);
  assert.deepEqual(await ask(hit.fingerprint),{ok:true,delivery_id:null,correlation_id:send.event.correlation_id});
  assert.deepEqual(await ask(hit.fingerprint),{ok:true,delivery_id:null},'once');
 }finally{p.close();}
});

test('claude, observation: a draft with text does not lend its correlation to another network prompt',async()=>{
 const p=page();
 try{
  await delay(0);p.set('Synthetic question');
  await p.controller.handle(trusted('keydown',p.field,{key:'Enter'}));await delay(20);
  assert.equal(sends(p).length,1);
  assert.deepEqual(await ask('b'.repeat(64)),{ok:true,delivery_id:null});
 }finally{p.close();}
});

test('claude: an answer turn split in rows, the first one no longer flagged while the stop button is up, is one response',async()=>{
 const p=page();
 try{
  await delay(0);p.set('Synthetic question');
  await p.controller.handle(trusted('keydown',p.field,{key:'Enter'}));await delay(20);
  const thread=p.doc.getElementById('thread');
  p.doc.body.insertAdjacentHTML('beforeend','<button type="button" data-testid="chat-input-stop" aria-label="Arrêter la réponse"></button>');
  // A row read for the file, shown before the text, without `data-is-streaming` while the turn waits.
  thread.insertAdjacentHTML('beforeend','<div data-testid="assistant-message" data-turn-key="turn-1"><h2 class="sr-only">Claude a répondu :</h2><p>Lecture du fichier note-synthetique.txt</p></div>');
  await delay(2700);
  assert.deepEqual(answers(p),[],'nothing while the turn runs');
  thread.insertAdjacentHTML('beforeend','<div data-testid="assistant-message" data-turn-key="turn-1"><p>OK 200</p></div>');
  thread.firstElementChild.setAttribute('data-is-streaming','false');p.doc.querySelector('[data-testid="chat-input-stop"]').remove();
  await delay(2700);
  const got=answers(p);
  assert.equal(got.length,1,'one response for one send');
  assert.equal(got[0].correlation_id,sends(p)[0].event.correlation_id);
  assert.equal(got[0].characters,Array.from('Lecture du fichier note-synthetique.txt\n\nOK 200').length);
 }finally{p.close();}
});

test('claude: two turns keep two responses, rows of another turn are not merged',async()=>{
 const p=page();
 try{
  await delay(0);
  const thread=p.doc.getElementById('thread');
  thread.insertAdjacentHTML('beforeend','<div data-testid="assistant-message" data-turn-key="turn-0" data-is-streaming="false"><p>Ancienne reponse</p></div>');
  await delay(20);p.set('Synthetic question');
  await p.controller.handle(trusted('keydown',p.field,{key:'Enter'}));await delay(20);
  thread.insertAdjacentHTML('beforeend','<div data-testid="assistant-message" data-turn-key="turn-1" data-is-streaming="false"><p>OK</p></div>');
  await delay(1500);
  const got=answers(p);
  assert.equal(got.length,1);assert.equal(got[0].characters,2,'the earlier turn is neither sent again nor joined');
 }finally{p.close();}
});

test('claude: a thousand rows under one turn key are read once per turn, not once per row',async()=>{
 const p=page();
 try{
  await delay(0);p.set('Synthetic question');
  await p.controller.handle(trusted('keydown',p.field,{key:'Enter'}));await delay(20);
  p.doc.getElementById('thread').insertAdjacentHTML('beforeend',Array.from({length:1000},(_,i)=>`<div data-testid="assistant-message" data-turn-key="turn-1"><p>Ligne synthetique ${i}</p></div>`).join(''));
  await delay(100);
  const started=performance.now();p.controller.navigation();p.dom.window.history.pushState({},'','/chat/6ad30bf2-0000-4000-8000-000000000002');p.controller.navigation();
  assert.ok(performance.now()-started<1000,'a page cannot stall the reset with one key');
 }finally{p.close();}
});

test('claude: a later row of the turn still streaming holds the whole turn, never a partial answer',async()=>{
 const p=page();
 try{
  await delay(0);p.set('Synthetic question');
  await p.controller.handle(trusted('keydown',p.field,{key:'Enter'}));await delay(20);
  const thread=p.doc.getElementById('thread');
  thread.insertAdjacentHTML('beforeend','<div data-testid="assistant-message" data-turn-key="turn-1" data-is-streaming="false"><p>Debut</p></div><div data-testid="assistant-message" data-turn-key="turn-1" data-is-streaming="true"><p>Suite</p></div>');
  await delay(2700);
  assert.deepEqual(answers(p),[],'nothing while a row of the turn streams');
  thread.lastElementChild.setAttribute('data-is-streaming','false');
  await delay(1500);
  const got=answers(p);
  assert.equal(got.length,1);assert.equal(got[0].characters,Array.from('Debut\n\nSuite').length);
 }finally{p.close();}
});

test('claude: answers pending under many turn keys do not each rescan every row',async()=>{
 const p=page();
 try{
  await delay(0);p.set('Synthetic question');
  await p.controller.handle(trusted('keydown',p.field,{key:'Enter'}));await delay(20);
  const proto=p.dom.window.Element.prototype,original=proto.querySelector;let walks=0;
  proto.querySelector=function(...args){walks++;return original.apply(this,args);};
  try{
   p.doc.getElementById('thread').insertAdjacentHTML('beforeend',Array.from({length:300},(_,i)=>`<div data-testid="assistant-message" data-turn-key="turn-${i}" data-is-streaming="false"><p>Ligne synthetique ${i}</p></div>`).join(''));
   await delay(1500);
  }finally{proto.querySelector=original;}
  assert.equal(answers(p).length,300);
  // One pass reads each row once; each of the 300 checks then reads its own turn, not the 300 rows.
  assert.ok(walks<20000,`row walks: ${walks}`);
 }finally{p.close();}
});
