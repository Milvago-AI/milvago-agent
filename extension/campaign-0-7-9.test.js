// Real campaign 0.7.9 (observation, 2026-10-17). Synthetic pages and texts.
import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto,createHash} from 'node:crypto';
import {JSDOM} from 'jsdom';
import fileListUtils from 'jsdom/lib/generated/idl/utils.js';
let receipt=null;
globalThis.browser={runtime:{id:'synthetic-extension',onMessage:{addListener(fn){if(fn.length===3){receipt=fn;}},removeListener(){}}}};
await import('./adapters.js');await import('./capture.js');
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const sha=text=>createHash('sha256').update(text).digest('hex');
const observe={version:2,revision:1,expires_at:'2099-01-01T00:00:00Z',config:{collection:{enabled:true,store_content:false},services:[{id:'claude',enabled:true,mode:'observe',domains:['claude.ai']},{id:'chatgpt',enabled:true,mode:'observe',domains:['chatgpt.com']}]}};
const shapes={
 claude:['<div role="textbox" contenteditable="true"></div><button type="button" data-testid="chat-input-send">Envoyer</button>','https://claude.ai/chat/6ad30bf2-0000-4000-8000-000000000001'],
 chatgpt:['<form><textarea id="prompt-textarea"></textarea><button type="button" data-testid="send-button">Send</button></form>','https://chatgpt.com/c/6ad30bf2-0000-4000-8000-000000000001'],
};
function trusted(type,target,extra={}){return {type,target,isTrusted:true,prevented:false,get defaultPrevented(){return this.prevented;},preventDefault(){this.prevented=true;},stopImmediatePropagation(){},...extra};}
// `uploadMs`: the agent's answer to the file check, about 1 s in the campaign. `uploadAction`: its decision.
function page(id,{uploadMs=0,uploadAction='observe'}={}){
 const [html,url]=shapes[id],dom=new JSDOM(html,{url});
 Object.defineProperty(dom.window.crypto,'subtle',{value:webcrypto.subtle});
 const messages=[];let serial=0;
 const controller=globalThis.MilvagoCapture.start(dom.window.document,dom.window.location,async msg=>{
  messages.push(msg);
  if(msg.type==='policy'){return {ok:true,policy:observe};}
  if(msg.type==='inspect'&&msg.upload){await delay(uploadMs);return {ok:true,action:uploadAction,text:'',labels:[]};}
  if(msg.type==='submit'){serial++;return {ok:true,action:'observe',text:msg.text,durable:true,recording_required:true,authority:null,delivery_id:'00000000-0000-4000-8000-00000000000'+serial};}
  return {ok:true,action:'observe',text:msg.text||'',labels:[]};
 });
 const doc=dom.window.document,field=doc.querySelector('[contenteditable],textarea'),button=doc.querySelector('button');
 const set=text=>{if('value' in field&&field.tagName==='TEXTAREA'){field.value=text;}else{field.textContent=text;}};
 let clicks=0;button.addEventListener('click',()=>clicks++);
 return {dom,doc,controller,messages,field,button,set,clicks:()=>clicks,close(){controller.dispose();dom.window.close();}};
}
function picker(p){
 const input=p.doc.createElement('input');input.type='file';p.doc.body.append(input);
 const file=new p.dom.window.File(['Synthetic file body'],'note.txt',{type:'text/plain'});
 fileListUtils.implForWrapper(input.files).push(fileListUtils.implForWrapper(file));
 return input;
}
const ask=fingerprint=>new Promise(resolve=>receipt({type:'detection-receipt',fingerprint},{id:'synthetic-extension'},resolve));
const sends=p=>p.messages.filter(m=>m.type==='submit'&&!m.upload);

for(const id of ['claude','chatgpt']){
 test(`${id}: Enter pressed while the file just chosen is checked is sent once the file is through, inspected again`,async()=>{
  const p=page(id,{uploadMs:300});
  try{
   await delay(0);p.set('Synthetic question');
   const choosing=p.controller.upload(trusted('change',picker(p)));
   await delay(50);
   const enter=trusted('keydown',p.field,{key:'Enter'});const held=p.controller.handle(enter);
   assert.equal(enter.prevented,true,'held, not given to the page during the check');
   await choosing;await held;await delay(20);
   const order=p.messages.map(m=>`${m.type}${m.upload?'-file':''}`).filter(t=>!['policy','event'].includes(t));
   assert.deepEqual(order,['inspect-file','submit-file','inspect','submit'],'the text is inspected after the file, never before');
   assert.equal(sends(p)[0].text,'Synthetic question');assert.equal(p.clicks(),1);
   const file=p.messages.find(m=>m.type==='submit'&&m.upload);
   assert.equal(sends(p)[0].event.correlation_id,file.event.correlation_id,'one exchange for the file and its text');
  }finally{p.close();}
 });
}

test('claude: a refused file drops the Enter pressed while it was checked',async()=>{
 const p=page('claude',{uploadMs:200,uploadAction:'block'});
 try{
  await delay(0);p.set('Synthetic question');
  const choosing=p.controller.upload(trusted('change',picker(p)));await delay(20);
  const held=p.controller.handle(trusted('keydown',p.field,{key:'Enter'}));
  await choosing;await held;await delay(20);
  assert.equal(sends(p).length,0);assert.equal(p.messages.filter(m=>m.type==='inspect'&&!m.upload).length,0);assert.equal(p.clicks(),0);
 }finally{p.close();}
});

test('claude: a draft changed during the file check is not sent by the earlier Enter',async()=>{
 const p=page('claude',{uploadMs:200});
 try{
  await delay(0);p.set('Synthetic question');
  const choosing=p.controller.upload(trusted('change',picker(p)));await delay(20);
  const held=p.controller.handle(trusted('keydown',p.field,{key:'Enter'}));
  await delay(50);p.set('Synthetic question, edited');
  await choosing;await held;await delay(20);
  assert.equal(sends(p).length,0);assert.equal(p.messages.filter(m=>m.type==='inspect'&&!m.upload).length,0,'the stale draft is not even inspected');assert.equal(p.clicks(),0);
 }finally{p.close();}
});

test('claude: two Enters during the file check make one send',async()=>{
 const p=page('claude',{uploadMs:200});
 try{
  await delay(0);p.set('Synthetic question');
  const choosing=p.controller.upload(trusted('change',picker(p)));await delay(20);
  const a=p.controller.handle(trusted('keydown',p.field,{key:'Enter'})),b=p.controller.handle(trusted('keydown',p.field,{key:'Enter'}));
  await choosing;await a;await b;await delay(20);
  assert.equal(sends(p).length,1);assert.equal(p.clicks(),1);
 }finally{p.close();}
});

const long='Synthetic long pasted line, nothing private.\n'.repeat(300);
const clip=text=>({files:[],types:['text/plain'],getData:type=>type==='text/plain'?text:''});
test('claude, observation: a paste kept as a chip and sent with an empty draft names its exchange, the paste untouched',async()=>{
 const p=page('claude');
 try{
  await delay(0);
  const pasted=trusted('paste',p.field,{clipboardData:clip(long)});await p.controller.paste(pasted);
  assert.equal(pasted.prevented,false,'without masking the page gets the paste itself');
  p.set('');
  const enter=trusted('keydown',p.field,{key:'Enter'});await p.controller.handle(enter);await delay(20);
  assert.equal(enter.prevented,true);
  const [send]=sends(p);assert.equal(send?.text,'');assert.equal(p.clicks(),1);
  assert.match(send.event.correlation_id,/^[0-9a-f-]{36}$/);
  assert.deepEqual(await ask('a'.repeat(64)),{ok:true,delivery_id:null,correlation_id:send.event.correlation_id});
  assert.deepEqual(await ask('a'.repeat(64)),{ok:true,delivery_id:null},'once');
 }finally{p.close();}
});

test('claude, observation: a paste the page made, or one outside the composer, opens no exchange',async()=>{
 const p=page('claude');
 try{
  await delay(0);
  await p.controller.paste({...trusted('paste',p.field,{clipboardData:clip(long)}),isTrusted:false});
  const other=p.doc.createElement('textarea');p.doc.body.append(other);
  await p.controller.paste(trusted('paste',other,{clipboardData:clip(long)}));
  const enter=trusted('keydown',p.field,{key:'Enter'});await p.controller.handle(enter);await delay(20);
  assert.equal(enter.prevented,false,'an empty draft is left to the page as before');
  assert.equal(sends(p).length,0);
  assert.deepEqual(await ask('a'.repeat(64)),{ok:true,delivery_id:null});
 }finally{p.close();}
});

test('chatgpt: the network prompt the page trimmed joins the send of the draft with a trailing space, once',async()=>{
 const p=page('chatgpt');
 try{
  await delay(0);const draft='Synthetic question ';p.set(draft);
  await p.controller.handle(trusted('keydown',p.field,{key:'Enter'}));await delay(20);
  assert.equal(sends(p).length,1);
  assert.deepEqual(await ask(sha(draft.trim())),{ok:true,delivery_id:'00000000-0000-4000-8000-000000000001',authority:null});
  assert.deepEqual(await ask(sha(draft)),{ok:true,delivery_id:null},'the receipt is spent by either form');
  assert.deepEqual(await ask(sha('Synthetic question  ')),{ok:true,delivery_id:null},'nothing but the trim');
 }finally{p.close();}
});
