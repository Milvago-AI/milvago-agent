// Real campaign 0.7.8 under masking: a long paste the page kept out of the draft (a chip, an attachment)
// was sent with an empty draft. That send was never held, its network prompt carried no exchange, and the
// answer was filed under the conversation's first prompt. Synthetic page and texts.
import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {JSDOM} from 'jsdom';
let receipt=null;
globalThis.browser={runtime:{id:'synthetic-extension',onMessage:{addListener(fn){receipt=fn;},removeListener(){}}}};
await import('./adapters.js');await import('./capture.js');
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const policy={version:2,revision:1,expires_at:'2099-01-01T00:00:00Z',config:{collection:{enabled:true,store_content:false},services:[{id:'chatgpt',enabled:true,mode:'observe',domains:['chatgpt.com']}],privacy:{enabled:true}}};
function trusted(type,target,extra={}){return {type,target,isTrusted:true,prevented:false,get defaultPrevented(){return this.prevented;},preventDefault(){this.prevented=true;},stopImmediatePropagation(){},...extra};}
function page(){
 const dom=new JSDOM('<form><textarea id="prompt-textarea"></textarea><button type="button" data-testid="send-button">Send</button></form>',{url:'https://chatgpt.com/c/6ad30bf2-0000-4000-8000-000000000001'});
 Object.defineProperty(dom.window.crypto,'subtle',{value:webcrypto.subtle});
 const messages=[];let serial=0;
 const controller=globalThis.MilvagoCapture.start(dom.window.document,dom.window.location,async msg=>{
  messages.push(msg);
  if(msg.type==='policy'){return {ok:true,policy};}
  if(msg.type==='paste'){return {ok:true,action:'observe',text:msg.text,labels:[]};}
  if(msg.type==='submit'){serial++;return {ok:true,action:'observe',text:msg.text,durable:true,recording_required:true,authority:null,delivery_id:'00000000-0000-4000-8000-00000000000'+serial};}
  return {ok:true,action:'observe',text:msg.text||'',labels:[]};
 });
 const doc=dom.window.document;
 return {doc,controller,messages,field:doc.querySelector('textarea'),button:doc.querySelector('button'),close(){controller.dispose();dom.window.close();}};
}
const ask=message=>new Promise(resolve=>receipt(message,{id:'synthetic-extension'},resolve));

test('an empty draft sent after a paste the page kept aside is held, and names its exchange to the network',async()=>{
 const p=page();
 try{
  await delay(0);let clicks=0;p.button.addEventListener('click',()=>clicks++);
  const long='Synthetic long pasted line, nothing private.\n'.repeat(400);
  await p.controller.paste(trusted('paste',p.field,{clipboardData:{files:[],types:['text/plain'],getData:type=>type==='text/plain'?long:''}}));
  // The page turns the long paste into a chip: the draft is empty again.
  p.field.value='';
  const enter=trusted('keydown',p.field,{key:'Enter'});
  await p.controller.handle(enter);await delay(20);
  assert.equal(enter.prevented,true,'the send is held');
  const submit=p.messages.find(m=>m.type==='submit'&&!m.upload);
  assert.equal(submit?.text,'');assert.equal(clicks,1,'and replayed once approved');
  const correlation=submit.event.correlation_id;
  assert.match(correlation,/^[0-9a-f-]{36}$/);
  // The network request carries the chip, which the DOM record never saw: it joins the same exchange, once.
  assert.deepEqual(await ask({type:'detection-receipt',fingerprint:'a'.repeat(64)}),{ok:true,delivery_id:null,correlation_id:correlation});
  assert.deepEqual(await ask({type:'detection-receipt',fingerprint:'a'.repeat(64)}),{ok:true,delivery_id:null});
 }finally{p.close();}
});

test('a send with text names no exchange to a network record it does not match',async()=>{
 const p=page();
 try{
  await delay(0);p.field.value='Bonjour';
  await p.controller.handle(trusted('keydown',p.field,{key:'Enter'}));await delay(20);
  assert.equal(p.messages.filter(m=>m.type==='submit').length,1);
  assert.deepEqual(await ask({type:'detection-receipt',fingerprint:'a'.repeat(64)}),{ok:true,delivery_id:null});
 }finally{p.close();}
});
