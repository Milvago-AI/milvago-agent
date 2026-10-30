// Real campaign 0.7.10 under policy (2026-10-17). Synthetic policies, texts and bodies; the shapes are the
// measured ones (scratchpad r093/, r096/).
//  1. A refusal decided on the headers has no body there: a page that resent the same refused request byte for
//     byte was told and recorded once per retry.
//  2. The broker signs "blocked" for any agent error while the policy stays in memory: every read of a page
//     reloaded with no action was recorded as a refused prompt.
//  3. A rich editor's `innerText` doubles the break between two paragraphs while the page sends one: a masked
//     paste of three lines was read 65 characters, sent 63, recorded as two prompts.
//  4. A reviewed paste carried out as an attachment never reaches the draft the agent records: its labels were lost.
import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto,createHash} from 'node:crypto';
import {JSDOM} from 'jsdom';
import {managedBridge} from './managed-fixture.js';

const json=value=>({raw:[{bytes:new TextEncoder().encode(JSON.stringify(value)).buffer}]});
const conversation=(...parts)=>json({action:'next',messages:[{id:'6aa99383-dd04-43ea-88fb-50a164a3820d',author:{role:'user'},content:{content_type:'text',parts}}],model:'auto'});
const CONVERSATION='https://chatgpt.com/backend-api/f/conversation',FILES='https://chatgpt.com/backend-api/files',PAGE='https://chatgpt.com/c/6aa99383-dd04-43ea-88fb-50a164a3820d';
const policyFor=(revision,config={})=>({version:3,revision,expires_at:'2099-01-01T00:00:00Z',config:{services:[{id:'chatgpt',enabled:true,mode:'observe',domains:['chatgpt.com']}],collection:{enabled:true,store_content:false},model_access:[],privacy:{enabled:true},...config}});

let worker=0;
async function background(initial,handlers={},receipt=()=>({ok:true,delivery_id:null})){
 let message,policy=initial;const listeners={},stored={},noop={addListener(){}},notices=[];
 const bridge=managedBridge({
  browser_policy:()=>({online:true,policy}),
  browser_inspect:req=>({ok:true,action:'observe',text:req.text,labels:[]}),
  browser_submit:req=>({ok:true,action:'observe',text:req.text,recording_required:false}),
  browser_event:req=>({ok:true,id:crypto.randomUUID(),durable:true,delivery_id:req.delivery_id}),
  browser_catalog:()=>({catalog:null,revision:0,catalog_state:'missing'}),
  browser_health:req=>({accepted_health_ids:[req.batch.id]}),
  ...handlers,
 });
 // Every listener, in registration order: the detection runtime observes beside the blocking guard.
 const on=k=>({addListener(fn){(listeners[k]??=[]).push(fn);}});
 globalThis.chrome={
  runtime:{onInstalled:noop,onStartup:noop,onMessage:{addListener(fn){message=fn;}},sendNativeMessage:bridge.sendNativeMessage,getURL:path=>'chrome-extension://synthetic'+path,getManifest:()=>({version:'0.7.10',content_scripts:[]})},
  storage:{managed:{async get(){return {milvago_pin:JSON.stringify(bridge.pin)};}},local:{async get(k){return k?{[k]:stored[k]}:{...stored};},async set(value){Object.assign(stored,value);}}},
  alarms:{create(){},onAlarm:noop},
  tabs:{async query(){return [];},async reload(){},async update(){},async sendMessage(tab,msg){if(msg.type==='detection-receipt'){return receipt(msg);}notices.push(msg);}},
  declarativeNetRequest:{async getDynamicRules(){return [];},async updateDynamicRules(){}},
  webRequest:Object.fromEntries(['onBeforeRequest','onBeforeSendHeaders','onHeadersReceived','onCompleted','onErrorOccurred'].map(k=>[k,on(k)])),
 };
 await import('./background.js?campaign0710p='+worker++);
 const ask=(msg,sender={})=>new Promise(resolve=>message(msg,sender,resolve));
 assert.deepEqual(await ask({type:'refresh'}),{ok:true});
 const fire=(k,details)=>{let result={};for(const fn of listeners[k]||[]){const r=fn(details);if(r&&typeof r==='object'&&!(r instanceof Promise)){result={...result,...r};}}return result;};
 const prompts=()=>bridge.calls.filter(c=>c.op==='browser_event').map(c=>c.message.event).filter(e=>e.kind==='prompt');
 return {fire,notices,ask,prompts,setPolicy(next){policy=next;},close(){delete globalThis.chrome;}};
}
const settled=async()=>{for(let i=0;i<80;i++){await new Promise(r=>setTimeout(r,0));}await new Promise(r=>setTimeout(r,30));};
const sender={frameId:0,documentId:'document-1',tab:{id:1},url:PAGE};
let id=0;
const request=(url,body,over={})=>({requestId:'c'+id++,tabId:1,documentId:'document-1',frameId:0,method:'POST',type:'xmlhttprequest',url,initiator:'https://chatgpt.com',...(body?{requestBody:body}:{}),...over});
const headers=(state,details)=>state.fire('onBeforeSendHeaders',{...details,requestBody:undefined,requestHeaders:[{name:'Content-Type',value:'application/json'}]});
// The network record leaves once the response starts (`onHeadersReceived`).
const answered=(state,details)=>state.fire('onHeadersReceived',{...details,requestBody:undefined,statusCode:200,responseHeaders:[{name:'Content-Type',value:'text/event-stream'}]});

test('a request refused on its headers and resent byte for byte is told and recorded once',async()=>{
 let refuse=false;
 const state=await background(policyFor(1),{browser_inspect:req=>refuse?{brokerMode:'blocked',reply:{ok:false,error:'control_unavailable'}}:{ok:true,action:'observe',text:req.text,labels:[]}});
 try{
  // Nothing at the text path: the body passes; the agent then turns "blocked" before the headers.
  const retries=[0,1,2].map(()=>request(CONVERSATION,conversation()));
  const other=request(CONVERSATION,json({action:'next',messages:[],model:'auto'}));
  for(const details of [...retries,other]){assert.deepEqual(state.fire('onBeforeRequest',details),{},'the body passes');}
  refuse=true;assert.equal((await state.ask({type:'inspect',text:'Bonjour',upload:false},sender)).ok,false);
  // Synchronously, as the browser hands them: the agent's next answer may say "connected" again.
  for(const details of [...retries,other]){assert.equal(headers(state,details).cancel,true,'each retry stays cut');}
  await settled();
  assert.equal(state.prompts().filter(e=>e.action==='blocked').length,2,'the three retries once, the other body once');
  assert.equal(state.notices.length,2);
 }finally{state.close();}
});

test('while the broker answers "blocked" with a policy in memory, page reads are cut, sends cut and recorded',async()=>{
 let refuse=false;
 const state=await background(policyFor(1),{browser_inspect:req=>refuse?{brokerMode:'blocked',reply:{ok:false,error:'control_unavailable'}}:{ok:true,action:'observe',text:req.text,labels:[]}});
 try{
  refuse=true;
  assert.equal((await state.ask({type:'inspect',text:'Bonjour',upload:false},sender)).ok,false);
  const reads=[request('https://chatgpt.com/backend-api/conversations?offset=0&limit=28',undefined,{method:'GET'}),request('https://chatgpt.com/backend-api/sentinel/chat-requirements',json({p:'synthetic'})),request('https://chatgpt.com/ces/v1/t',json({event:'synthetic',n:1})),request(PAGE,undefined,{method:'GET',type:'main_frame'})];
  for(const details of reads){assert.equal(state.fire('onBeforeRequest',details).cancel,true,'still cut: '+details.url);}
  await settled();
  assert.equal(state.prompts().length,0,'no read recorded as a refused prompt');assert.equal(state.notices.length,0);
  for(const details of [request(CONVERSATION,conversation('Bonjour')),request(FILES,json({file_name:'Texte collé.txt',file_size:12,mime_type:'text/plain'})),request('https://api.openai.com/v1/responses',json({input:'Bonjour'}))]){
   assert.equal(state.fire('onBeforeRequest',details).cancel,true,details.url);
  }
  await settled();
  assert.equal(state.prompts().length,3,'a send, a paste upload and a direct API call stay recorded');
  assert.ok(state.prompts().every(e=>e.action==='blocked'&&e.decision_reason==='control_unavailable'));
 }finally{state.close();}
});

test('a reviewed paste carried out as an attachment lends its labels to the network prompt, once',async()=>{
 const PASTED='Ligne un carte [CARD]\nLigne deux mail [EMAIL]\nReponds juste OK.';
 const state=await background(policyFor(1),{browser_inspect:req=>req.text.includes('4970')?{ok:true,action:'review',text:PASTED,labels:['card','email']}:{ok:true,action:'observe',text:req.text,labels:[]}});
 try{
  const pasted=await state.ask({type:'paste',text:'Ligne un carte 4970 1012 3456 7894\nLigne deux mail synthetic@example.invalid\nReponds juste OK.'},sender);
  assert.equal(pasted.text,PASTED);assert.equal(JSON.stringify(pasted).includes('4970'),false);
  assert.deepEqual(await state.ask({type:'paste-confirm',token:pasted.token},sender),{ok:true});
  const upload=request(FILES,json({file_name:'Texte collé.txt',file_size:new TextEncoder().encode(PASTED).length,mime_type:'text/plain',use_case:'my_files'}));
  assert.deepEqual(state.fire('onBeforeRequest',upload),{},'the approved paste goes out as a file');
  // Two sends of the tab, each approved: the first network prompt takes the labels, the second none.
  for(const text of ['Resume ce fichier','Et ensuite']){
   const submitted=await state.ask({type:'submit',text,upload:false,event:{kind:'prompt',action:'observed',characters:text.length,labels:[],url:PAGE}},sender);
   assert.equal(submitted.ok,true,JSON.stringify(submitted));
   const send=request(CONVERSATION,conversation(text));
   assert.notEqual(state.fire('onBeforeRequest',send).cancel,true);assert.notEqual(headers(state,send).cancel,true);answered(state,send);
   await settled();
  }
  await new Promise(r=>setTimeout(r,3500));// the network record leaves with the next replay (3.1 s)
  const network=state.prompts().filter(e=>e.action==='observed');
  assert.deepEqual(network.map(e=>[e.characters,e.labels]),[[17,['card','email']],[10,[]]]);
  assert.equal(JSON.stringify(state.prompts()).includes('4970'),false);
 }finally{state.close();}
});

test('labels lent by a paste do not reach another tab, and expire',async()=>{
 const PASTED='Note [IBAN] synthetique';
 const state=await background(policyFor(1),{browser_inspect:req=>req.text.includes('FR76')?{ok:true,action:'review',text:PASTED,labels:['iban']}:{ok:true,action:'observe',text:req.text,labels:[]}});
 try{
  const pasted=await state.ask({type:'paste',text:'Note FR76 3000 6000 0112 3456 7890 189 synthetique'},sender);
  await state.ask({type:'paste-confirm',token:pasted.token},sender);
  state.fire('onBeforeRequest',request(FILES,json({file_name:'Texte collé.txt',file_size:new TextEncoder().encode(PASTED).length,mime_type:'text/plain'})));
  const other={...sender,tab:{id:2},documentId:'document-2'};
  await state.ask({type:'submit',text:'Autre onglet',upload:false,event:{kind:'prompt',action:'observed',characters:12,labels:[],url:PAGE}},other);
  const send=request(CONVERSATION,conversation('Autre onglet'),{tabId:2,documentId:'document-2'});state.fire('onBeforeRequest',send);headers(state,send);answered(state,send);
  // Past LENT_MS, the tab that carried the paste out borrows nothing either.
  const now=Date.now;Date.now=()=>now()+121000;
  try{
   await state.ask({type:'submit',text:'Plus tard',upload:false,event:{kind:'prompt',action:'observed',characters:9,labels:[],url:PAGE}},sender);
   const late=request(CONVERSATION,conversation('Plus tard'));state.fire('onBeforeRequest',late);headers(state,late);answered(state,late);
   await new Promise(r=>setTimeout(r,3500));
  }finally{Date.now=now;}
  assert.deepEqual(state.prompts().map(e=>[e.characters,e.labels]),[[12,[]],[9,[]]],'another tab, then too late: nothing borrowed');
 }finally{state.close();}
});

// --- Adversarial review of tour 8 -------------------------------------------------------------------------
const recorded=()=>{let completions=0;return {handlers:{browser_submit:req=>({ok:true,action:'observe',text:req.text,recording_required:true,durable:true,delivery_id:req.delivery_id,id:crypto.randomUUID()}),browser_complete:()=>{completions++;return {ok:true,applied:true};}},get completions(){return completions;}};};
test('a second send of the person refused with the same body completes its own DOM record; a page retry is folded',async()=>{
 const counter=recorded(),state=await background(policyFor(1),counter.handlers);
 try{
  // The page sends a body the approval does not cover, the same bytes on each click.
  for(let i=0;i<2;i++){
   const answer=await state.ask({type:'submit',text:'Bonjour',upload:false,event:{kind:'prompt',action:'observed',characters:7,labels:[],url:PAGE}},sender);
   assert.equal(answer.ok,true,JSON.stringify(answer));
   for(let retry=0;retry<2;retry++){assert.equal(state.fire('onBeforeRequest',request(CONVERSATION,conversation('Bonjour autre texte'))).cancel,true);}
   await settled();
  }
  assert.equal(counter.completions,2,'each DOM record of a refused send is completed as blocked');
  assert.equal(state.prompts().filter(e=>e.action==='blocked').length,0,'the page retries are folded');
 }finally{state.close();}
});
// Adversarial review of tour 9: the same guarantee with collection off, where nothing is recorded.
test('collection off, two refused sends of the person with the same body are each told; a page retry is folded',async()=>{
 const state=await background(policyFor(1,{collection:{enabled:false}}));
 try{
  for(let i=0;i<2;i++){
   const answer=await state.ask({type:'submit',text:'Bonjour',upload:false,event:{kind:'prompt',action:'observed',characters:7,labels:[],url:PAGE}},sender);
   assert.equal(answer.ok,true,JSON.stringify(answer));
   for(let retry=0;retry<2;retry++){assert.equal(state.fire('onBeforeRequest',request(CONVERSATION,conversation('Bonjour autre texte'))).cancel,true);}
   await settled();
  }
  assert.equal(state.notices.filter(m=>m.type==='model-blocked').length,2,'one notice per send of the person');
  assert.equal(state.prompts().length,0,'collection off: nothing recorded');
 }finally{state.close();}
});
test('while the broker answers "blocked", a prompt-shaped body off the catalogue routes is recorded; a read queued before is not',async()=>{
 let refuse=false;
 const state=await background(policyFor(1),{browser_inspect:req=>refuse?{brokerMode:'blocked',reply:{ok:false,error:'control_unavailable'}}:{ok:true,action:'observe',text:req.text,labels:[]}});
 try{
  // Queued while authorized, cut at the headers once the broker turned: the read silently, the send recorded.
  const read=request('https://chatgpt.com/backend-api/sentinel/chat-requirements',json({p:'synthetic'})),send=request(CONVERSATION,conversation());
  assert.deepEqual(state.fire('onBeforeRequest',read),{});assert.deepEqual(state.fire('onBeforeRequest',send),{});
  refuse=true;assert.equal((await state.ask({type:'inspect',text:'Bonjour',upload:false},sender)).ok,false);
  assert.equal(headers(state,read).cancel,true);assert.equal(headers(state,send).cancel,true);
  await settled();
  assert.equal(state.prompts().length,1,'the queued send only');
  // Recording the send made the broker answer again: turned "blocked" once more.
  assert.equal((await state.ask({type:'inspect',text:'Bonjour',upload:false},sender)).ok,false);
  const shaped=json({model:'synthetic-model',messages:[{role:'user',content:'Texte synthetique'}]});
  for(const details of [request('https://chatgpt.com/backend-api/conversation-next',shaped),request('https://collector.example.invalid/v1/chat',shaped)]){assert.equal(state.fire('onBeforeRequest',details).cancel,true,details.url);}
  await settled();
  assert.equal(state.prompts().length,3,'a prompt-shaped body on another path or a third-party host is recorded, as masking announces it');
 }finally{state.close();}
});
test('labels lent by a paste stay with the document that carried it out',async()=>{
 const PASTED='Note [IBAN] synthetique';
 const state=await background(policyFor(1),{browser_inspect:req=>req.text.includes('FR76')?{ok:true,action:'review',text:PASTED,labels:['iban']}:{ok:true,action:'observe',text:req.text,labels:[]}});
 try{
  const pasted=await state.ask({type:'paste',text:'Note FR76 3000 6000 0112 3456 7890 189 synthetique'},sender);
  await state.ask({type:'paste-confirm',token:pasted.token},sender);
  assert.deepEqual(state.fire('onBeforeRequest',request(FILES,json({file_name:'Texte collé.txt',file_size:new TextEncoder().encode(PASTED).length,mime_type:'text/plain'}))),{});
  // The same tab, navigated to another document (another account, conversation or service).
  const next={...sender,documentId:'document-9'};
  await state.ask({type:'submit',text:'Autre page',upload:false,event:{kind:'prompt',action:'observed',characters:10,labels:[],url:PAGE}},next);
  const send=request(CONVERSATION,conversation('Autre page'),{documentId:'document-9'});state.fire('onBeforeRequest',send);headers(state,send);answered(state,send);
  await new Promise(r=>setTimeout(r,3500));
  assert.deepEqual(state.prompts().map(e=>e.labels),[[]],'nothing borrowed by another document');
 }finally{state.close();}
});

test('a send named through a chip keeps the labels of its reviewed paste, on its own prompt of the exchange',async()=>{
 // The DOM record holds the chip's preview only (real campaign 0.7.11): absorbing the request lost its labels.
 const CHIP='Note [IBAN] synthetique\n'+'Ligne de remplissage synthetique. '.repeat(40),DRAFT='Reponds juste OK';
 const CORRELATION='00000000-0000-4000-8000-0000000000c1',DELIVERY='00000000-0000-4000-8000-0000000000d1';
 for(const reviewed of [true,false]){
  const state=await background(policyFor(1),{browser_inspect:req=>req.text.includes('FR76')?{ok:true,action:'review',text:CHIP,labels:['iban']}:{ok:true,action:'observe',text:req.text,labels:[]}},
   ()=>({ok:true,delivery_id:DELIVERY,authority:'a'.repeat(64),chip:true,correlation_id:CORRELATION}));
  try{
   const pasted=await state.ask({type:'paste',text:reviewed?CHIP.replace('[IBAN]','FR76 3000 6000 0112 3456 7890 189'):CHIP},sender);
   assert.deepEqual(await state.ask({type:'paste-confirm',token:pasted.token},sender),{ok:true});
   assert.equal((await state.ask({type:'submit',text:DRAFT,upload:false,event:{kind:'prompt',action:'observed',characters:DRAFT.length,labels:[],url:PAGE}},sender)).ok,true);
   const send=request(CONVERSATION,conversation(CHIP,DRAFT));
   assert.notEqual(state.fire('onBeforeRequest',send).cancel,true,'chip and draft reviewed: the send passes');assert.notEqual(headers(state,send).cancel,true);answered(state,send);
   await new Promise(r=>setTimeout(r,3500));
   const network=state.prompts().filter(e=>e.detector==='network');
   if(reviewed){assert.deepEqual(network.map(e=>[e.characters,e.labels,e.correlation_id]),[[CHIP.length+DRAFT.length,['iban'],CORRELATION]]);}
   else {assert.deepEqual(network,[],'nothing lent: the request is absorbed by the record of the send');}
   assert.equal(JSON.stringify(state.prompts()).includes('FR76'),false);
  }finally{state.close();}
 }
});

// --- 3. The receipt of a draft whose paragraphs the editor reads with a doubled break ----------------------
const listeners=new Set();
const setupCapture=async()=>{
 globalThis.browser={runtime:{id:'synthetic-extension',onMessage:{addListener:f=>listeners.add(f),removeListener:f=>listeners.delete(f)}},storage:{local:{get:async()=>({}),set:async()=>{}}}};
 await import('./adapters.js');await import('./capture.js?campaign0710p');
};
const sha=text=>createHash('sha256').update(text).digest('hex');
function query(fingerprint){let response;for(const listener of listeners){listener({type:'detection-receipt',fingerprint},{id:'synthetic-extension'},value=>{response=value;});}return response;}
async function composer(read){
 const dom=new JSDOM('<form><textarea id="prompt-textarea"></textarea><button data-testid="send-button">Send</button></form>',{url:'https://chatgpt.com/'}),doc=dom.window.document;
 Object.defineProperty(dom.window.crypto,'subtle',{value:webcrypto.subtle});
 doc.querySelector('form').addEventListener('submit',e=>e.preventDefault());
 const policy={config:{collection:{enabled:true,store_content:false},services:[{enabled:true,domains:['chatgpt.com']}]}};
 const controller=globalThis.MilvagoCapture.start(doc,dom.window.location,async msg=>{
  if(msg.type==='policy'){return {ok:true,policy};}if(msg.type==='inspect'){return {ok:true,action:'observe',text:msg.text};}
  if(msg.type==='submit'){return {ok:true,action:'observe',text:msg.text,durable:true,recording_required:true,authority:'a'.repeat(64),delivery_id:'00000000-0000-4000-8000-000000000001'};}return {ok:true};
 });await new Promise(r=>setImmediate(r));
 globalThis.MilvagoAdapters.write(doc.querySelector('textarea'),read);
 await controller.handle({type:'click',target:doc.querySelector('button'),isTrusted:true,preventDefault(){},stopImmediatePropagation(){}});
 return {close(){controller.dispose();dom.window.close();}};
}
test('a draft read with doubled paragraph breaks is one send with the body that carries single ones',async()=>{
 await setupCapture();
 const sent='Ligne un carte [CARD]\nLigne deux mail [EMAIL]\nReponds juste OK.',read=sent.replaceAll('\n','\n\n');
 assert.deepEqual([read.length,sent.length],[65,63],'the measured lengths');
 let c=await composer(read);
 try{
  assert.deepEqual(query(sha(sent)),{ok:true,delivery_id:'00000000-0000-4000-8000-000000000001',authority:'a'.repeat(64)});
  assert.deepEqual(query(sha(sent)),{ok:true,delivery_id:null},'once');
 }finally{c.close();}
 // Other layouts of the same words are other texts: no receipt.
 c=await composer(read);
 try{
  for(const other of [sent.replaceAll('\n',' '),sent.replaceAll('\n',''),read.replaceAll('\n\n','\n\n\n'),sent+'\nAjout']){assert.deepEqual(query(sha(other)),{ok:true,delivery_id:null},JSON.stringify(other));}
  assert.equal(query(sha(read)).delivery_id,'00000000-0000-4000-8000-000000000001','the text as read still names it');
 }finally{c.close();}
});
