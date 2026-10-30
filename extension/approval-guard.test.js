// Approvals the network guard accepts under masking: a text file the person picked (by name and
// size, once), a paste confirmed after its review, each bound to the policy revision and to the
// document that obtained it (by `documentId`, or by frame and origin where the browser gives none),
// and kept across a worker restart as fingerprints only. Synthetic texts and bodies.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import './adapters.js';
import {wireFacts} from './detection.js';
import {requestDecision,textDigest,nameDigest} from './model-access.js';
import {factoryCatalog} from './detection-factory.js';
import {managedBridge} from './managed-fixture.js';

const policyFor=(config,revision=1)=>({version:3,revision,expires_at:'2099-01-01T00:00:00Z',config:{services:[],collection:{enabled:false},model_access:[],...config}});
const masking=policyFor({privacy:{enabled:true}});
const json=value=>({raw:[{bytes:new TextEncoder().encode(JSON.stringify(value)).buffer}]});
const bytes=text=>new TextEncoder().encode(text).length;
const PASTED='Synthetic pasted notes, account [EMAIL] removed.\nSecond line é.';
const meta=over=>({entry_surface:'chat_composer',file_name:'Texte collé.txt',file_size:bytes(PASTED),mime_type:'text/plain',use_case:'my_files',...over});
let serial=0;
function decide(body,approvals,catalog=factoryCatalog,path='/backend-api/files'){
 const url='https://chatgpt.com'+path,details={requestId:'g'+serial++,tabId:1,documentId:'document-1',url,method:'POST',type:'xmlhttprequest',initiator:'https://chatgpt.com',requestBody:body};
 return requestDecision(details,masking,wireFacts(details,catalog,new URL(url)),approvals,Date.now());
}
const sealed=decision=>decision?.reason==='control_unavailable';
const passes=decision=>!decision||(decision.allow===true&&!decision.reason);
const picked=(name,size)=>({kind:'file',name:nameDigest(name),size});
const sha=text=>createHash('sha256').update(text).digest('hex');

test('the digest is SHA-256 of the text as the composer lays it out, and empty text has none',()=>{
 for(const text of ['abc','',' a\r\n\r\nb ','é'.repeat(1000),'x'.repeat(200000)]){
  const laid=globalThis.MilvagoAdapters.layout(text);
  assert.equal(textDigest(text),laid?createHash('sha256').update(laid).digest('hex'):null);
 }
});
test('a text file the person picked passes on its name and size, once',()=>{
 for(const [name,type] of [['report.csv','text/csv'],['notes.md','text/markdown'],['main.py','text/x-python'],['notes.txt','text/plain']]){
  const approval=picked(name,1234),decision=decide(json(meta({file_name:name,file_size:1234,mime_type:type})),[approval]);
  assert.equal(decision.allow,true,name);assert.deepEqual(decision.consumed,[approval]);
 }
});
test('a picked file approval holds the fingerprint of the name, never the name',()=>{
 assert.equal(nameDigest('report é.csv'),sha('report é.csv'));
 assert.ok(sealed(decide(json(meta({file_name:'report.csv',file_size:1234,mime_type:'text/csv'})),[{kind:'file',name:'report.csv',size:1234}])),'a clear name is no approval');
});
test('a picked file approval covers only that file',()=>{
 assert.ok(sealed(decide(json(meta({file_name:'report.csv',file_size:1234,mime_type:'text/csv'})),[picked('report.csv',1235)])),'size');
 assert.ok(sealed(decide(json(meta({file_name:'other.csv',file_size:1234,mime_type:'text/csv'})),[picked('report.csv',1234)])),'name');
 // Real campaign 0.7.6: an upload that states no size is matched on the name alone (the size is only the page's word).
 assert.ok(passes(decide(json(meta({file_name:'report.csv',file_size:undefined,mime_type:'text/csv'})),[picked('report.csv',1234)])),'no declared size');
 assert.ok(sealed(decide(json(meta({file_name:'report.csv',file_size:1234,mime_type:'text/csv'})),[])),'no approval');
});
test('a paste approval covers only a plain-text upload named as a paste',()=>{
 assert.ok(passes(decide(json(meta()),[{text:PASTED,kind:'paste'}])));
 assert.ok(sealed(decide(json(meta({file_name:'report.csv',mime_type:'text/csv'})),[{text:PASTED,kind:'paste'}])),'a CSV of the same size');
 assert.ok(sealed(decide(json(meta({mime_type:'text/markdown'})),[{text:PASTED,kind:'paste'}])),'a Markdown type');
 assert.ok(sealed(decide(json(meta()),[])),'an unapproved paste stays sealed');
});
test('approvals given as fingerprints decide like the text they stand for',()=>{
 assert.ok(passes(decide(json(meta()),[{kind:'paste',digest:textDigest(PASTED),bytes:bytes(PASTED)}])));
 const route={providers:[{id:'chatgpt',domains:['chatgpt.com'],network:[{method:'POST',host:'chatgpt.com',path:'/fixture/route',text_path:'msg'}]}]};
 assert.ok(passes(decide(json({msg:'Draft text\n'}),[{digest:textDigest('Draft text'),bytes:10}],route,'/fixture/route')));
 assert.ok(sealed(decide(json({msg:'Other text'}),[{digest:textDigest('Draft text'),bytes:10}],route,'/fixture/route')));
});
test('a file approval never opens the window of an unreadable send',()=>{
 const route={providers:[{id:'chatgpt',domains:['chatgpt.com'],network:[{method:'POST',host:'chatgpt.com',path:'/fixture/route',text_path:'msg'}]}]};
 const gzipped={raw:[{bytes:new Uint8Array([0x1f,0x8b,8,0,0,0,0,0,0,3,1,2,3]).buffer}]};
 assert.ok(sealed(decide(gzipped,[picked('report.csv',1234)],route,'/fixture/route')));
});

// The worker.
function worker({policy=masking,session={},responses={}}={}){
 let message,current=policy;const handlers={},listeners={},stored={},noop={addListener(){}};
 const on=name=>({addListener(fn){listeners[name]=fn;}});
 const bridge=managedBridge({browser_policy:()=>({online:true,policy:current}),browser_inspect:req=>({ok:true,action:'observe',text:req.text,labels:[]}),browser_submit:req=>({ok:true,action:'observe',text:req.text,recording_required:false}),browser_catalog:()=>({catalog:null,revision:0,catalog_state:'missing'}),browser_health:req=>({accepted_health_ids:[req.batch.id]}),...responses});
 globalThis.chrome={runtime:{onInstalled:noop,onStartup:noop,onMessage:{addListener(fn){message=fn;}},sendNativeMessage:bridge.sendNativeMessage},
  storage:{managed:{async get(){return {milvago_pin:JSON.stringify(bridge.pin)};}},local:{async get(k){return {[k]:stored[k]};},async set(v){Object.assign(stored,v);}},
   ...(session?{session:{async get(k){return {[k]:structuredClone(session[k])};},async set(v){Object.assign(session,structuredClone(v));}}}:{})},
  alarms:{create(){},onAlarm:noop},tabs:{async query(){return [];},async reload(){},async sendMessage(){},onRemoved:{addListener(fn){const held=listeners.tabRemoved;listeners.tabRemoved=held?(...args)=>{held(...args);fn(...args);}:fn;}},onUpdated:noop},
  webNavigation:{onCommitted:on('committed')},
  declarativeNetRequest:{async getDynamicRules(){return [];},async updateDynamicRules(){}},
  webRequest:Object.fromEntries(['onBeforeRequest','onBeforeSendHeaders','onCompleted','onErrorOccurred'].map(k=>[k,{addListener(fn){handlers[k]=fn;}}]))};
 const sender={frameId:0,documentId:'document-1',tab:{id:1},url:'https://chatgpt.com/'};
 const send=(msg,from=sender)=>new Promise(resolve=>message(msg,from,resolve));
 const metadata=(over={},request={})=>({requestId:'w'+serial++,tabId:1,frameId:0,documentId:'document-1',method:'POST',type:'xmlhttprequest',url:'https://chatgpt.com/backend-api/files',initiator:'https://chatgpt.com',requestBody:json(meta(over)),...request});
 return {
  async start(){await import('./background.js?approval-guard='+serial++);assert.deepEqual(await send({type:'refresh'},{}),{ok:true});},
  send,sender,metadata,listeners,session,
  setPolicy(next){current=next;},
  allowed:details=>!handlers.onBeforeRequest(details).cancel,
  async paste(text,from){const reply=await send({type:'paste',text},from);assert.equal(reply.ok,true);return reply;},
  close(){delete globalThis.chrome;}
 };
}
const uploadSubmit=files=>({type:'submit',text:'',upload:true,files,event:{kind:'prompt',action:'observed',characters:0,labels:[],url:'https://chatgpt.com/'}});

test('a file picked and validated is approved by name and size, once',async()=>{
 const state=worker();
 try{await state.start();
  assert.equal(state.allowed(state.metadata({file_name:'report.csv',file_size:1234,mime_type:'text/csv'})),false,'nothing approved yet');
  const reply=await state.send(uploadSubmit([{name:sha('report.csv'),size:1234},{name:sha('notes.txt'),size:99}]));
  assert.equal(reply.ok,true);
  assert.equal(state.allowed(state.metadata({file_name:'report.csv',file_size:1234,mime_type:'text/csv'})),true);
  assert.equal(state.allowed(state.metadata({file_name:'report.csv',file_size:1234,mime_type:'text/csv'})),false,'single use');
  assert.equal(state.allowed(state.metadata({file_name:'notes.txt',file_size:99,mime_type:'text/plain'})),true);
  for(const files of [[{name:sha('a.csv'),size:-1}],[{name:'a.csv',size:1}],[{name:sha('a.csv').toUpperCase(),size:1}],[null],'a.csv',Array.from({length:21},(_,i)=>({name:sha(i+'.csv'),size:1})),[{name:sha('a.csv'),size:'1'}]]){
   const bad=await state.send(uploadSubmit(files));assert.equal(bad.ok,false,JSON.stringify(files).slice(0,40));
  }
  assert.equal(state.allowed(state.metadata({file_name:'a.csv',file_size:1,mime_type:'text/csv'})),false,'a refused selection approves nothing');
  const text=await state.send({type:'submit',text:'Draft',upload:false,files:[{name:sha('b.csv'),size:5}],event:{kind:'prompt',action:'observed',characters:5,labels:[],url:'https://chatgpt.com/'}});
  assert.equal(text.ok,true);assert.equal(state.allowed(state.metadata({file_name:'b.csv',file_size:5,mime_type:'text/csv'})),false,'a text send approves no file');
 }finally{state.close();}
});
test('a paste is approved only once the person confirms it, and the confirmation serves once',async()=>{
 const state=worker();
 try{await state.start();
  const reply=await state.paste(PASTED);
  assert.match(reply.token,/^[0-9a-f-]{36}$/);
  assert.equal(state.allowed(state.metadata()),false,'not before the confirmation');
  assert.deepEqual(await state.send({type:'paste-confirm',token:'00000000-0000-4000-8000-000000000000'}),{ok:false});
  assert.deepEqual(await state.send({type:'paste-confirm',token:42}),{ok:false});
  assert.deepEqual(await state.send({type:'paste-confirm',token:reply.token},{...state.sender,documentId:'document-2'}),{ok:false},'another document cannot confirm it');
  assert.deepEqual(await state.send({type:'paste-confirm',token:reply.token}),{ok:true});
  assert.deepEqual(await state.send({type:'paste-confirm',token:reply.token}),{ok:false},'confirmed once');
  assert.equal(state.allowed(state.metadata()),true);
  assert.equal(state.allowed(state.metadata()),false);
  await state.paste(PASTED);
  assert.equal(state.allowed(state.metadata()),false,'a paste cancelled at review is never approved');
 }finally{state.close();}
});
test('approvals are bound to the revision that inspected them and emptied when it changes',async()=>{
 const state=worker();
 try{await state.start();
  const reply=await state.paste(PASTED);await state.send({type:'paste-confirm',token:reply.token});
  state.setPolicy(policyFor({privacy:{enabled:true}},2));assert.deepEqual(await state.send({type:'refresh'},{}),{ok:true});
  assert.equal(state.allowed(state.metadata()),false);
  assert.ok(!JSON.stringify(state.session).includes('"kind"'),'the stored approvals are emptied too');
 }finally{state.close();}
});
test('a closed tab loses its approvals',async()=>{
 const state=worker();
 try{await state.start();
  const reply=await state.paste(PASTED);await state.send({type:'paste-confirm',token:reply.token});
  state.listeners.tabRemoved(1,{});
  assert.equal(state.allowed(state.metadata()),false);
 }finally{state.close();}
});
test('without documentId the approval is bound to the frame and the document origin, and purged on commit',async()=>{
 const state=worker();
 try{await state.start();
  const firefox={frameId:0,tab:{id:1},url:'https://chatgpt.com/'};
  const confirm=async()=>{const reply=await state.paste(PASTED,firefox);assert.deepEqual(await state.send({type:'paste-confirm',token:reply.token},firefox),{ok:true});};
  const request=over=>state.metadata({},{documentId:undefined,documentUrl:'https://chatgpt.com/c/abcdefgh',...over});
  await confirm();
  assert.equal(state.allowed(request({frameId:1})),false,'another frame');
  assert.equal(state.allowed(request({documentUrl:'https://evil.example/'})),false,'another document origin');
  assert.equal(state.allowed(request({documentUrl:undefined})),false,'no document at all');
  assert.equal(state.allowed(request({documentId:'document-9'})),true,'the same frame and origin, after the page moved with pushState');
  await confirm();
  state.listeners.committed({tabId:1,frameId:1,url:'https://chatgpt.com/'});
  assert.equal(state.allowed(request()),true,'a subframe commit leaves the top document approvals');
  await confirm();
  state.listeners.committed({tabId:1,frameId:0,url:'https://chatgpt.com/'});
  assert.equal(state.allowed(request()),false,'a new top document');
 }finally{state.close();}
});
test('a Chrome commit purges the previous document approvals, not those of the committed one',async()=>{
 const state=worker();
 try{await state.start();
  const reply=await state.paste(PASTED);await state.send({type:'paste-confirm',token:reply.token});
  state.listeners.committed({tabId:1,frameId:0,documentId:'document-1',url:'https://chatgpt.com/'});
  assert.equal(state.allowed(state.metadata()),true);
  const again=await state.paste(PASTED);await state.send({type:'paste-confirm',token:again.token});
  state.listeners.committed({tabId:1,frameId:0,documentId:'document-2',url:'https://chatgpt.com/'});
  assert.equal(state.allowed(state.metadata()),false);
 }finally{state.close();}
});
test('approvals survive a worker restart, stored as fingerprints without their text',async()=>{
 const session={};
 const first=worker({session});
 try{await first.start();
  const reply=await first.paste(PASTED);
  assert.deepEqual(await first.send({type:'paste-confirm',token:reply.token}),{ok:true});
  await first.send(uploadSubmit([{name:sha('report.csv'),size:1234}]));
 }finally{first.close();}
 await new Promise(resolve=>setTimeout(resolve,10));
 const dump=JSON.stringify(session);
 assert.ok(dump.length>2&&!dump.includes('Synthetic')&&!dump.includes('Second line')&&!dump.includes('report'),'no text nor file name is stored');
 assert.ok(dump.length<4096,'entries stay small');
 const second=worker({session});
 try{await second.start();
  assert.equal(second.allowed(second.metadata()),true,'the paste approved before the restart');
  assert.equal(second.allowed(second.metadata({file_name:'report.csv',file_size:1234,mime_type:'text/csv'})),true,'the file approved before the restart');
 }finally{second.close();}
 const hostile=worker({session:{approvals:[{tabId:1,kind:'paste',digest:'zz',bytes:1,expires:Date.now()+1000,revision:1,platform:'chatgpt',frameId:0,documentId:'document-1'},{tabId:1,kind:'send',digest:null,bytes:0,expires:Date.now()+10**12,revision:1,platform:'chatgpt',frameId:0,documentId:'document-1'},'junk',null]}});
 try{await hostile.start();
  assert.equal(hostile.allowed(hostile.metadata({file_size:1})),false,'malformed stored entries are dropped');
 }finally{hostile.close();}
});
test('without session storage the worker keeps its approvals in memory',async()=>{
 const state=worker({session:null});
 try{await state.start();
  const reply=await state.paste(PASTED);await state.send({type:'paste-confirm',token:reply.token});
  assert.equal(state.allowed(state.metadata()),true);
 }finally{state.close();}
});

// Review of round 5: an empty send is now held after a paste (a chip), and a picked file already sent an
// empty draft. Its approval names no text, so a body the guard cannot read must not ride on it.
test('an empty draft approval opens no window for an unreadable body on a prompt route',()=>{
 const empty={kind:'send',digest:textDigest(''),bytes:0,parts:[]};
 assert.equal(sealed(decide({error:'Unknown error.'},[empty],factoryCatalog,'/backend-api/f/conversation')),true);
 const typed={kind:'send',digest:textDigest('Bonjour'),bytes:bytes('Bonjour'),parts:[]};
 assert.equal(decide({error:'Unknown error.'},[typed],factoryCatalog,'/backend-api/f/conversation').allow,true,'an inspected draft still covers it');
});

test('warning requires issued confirmation in the same document before one submission',async()=>{
 const receipt='11000000-0000-4000-8000-000000000001';let confirms=0,submits=0;
 const state=worker({responses:{
  browser_inspect:req=>({ok:true,action:'review',text:req.text,confirmation:true,dlp_receipt:receipt,reason:'Check this submission',labels:[]}),
  browser_confirm:req=>{assert.equal(req.tool,'chrome');confirms++;return {ok:true,applied:true};},
  browser_submit:req=>{submits++;return {ok:true,action:'observe',text:req.text,recording_required:false};}
 }});
 try{await state.start();
  const confirm={type:'dlp-confirmed',receipt},submit={...uploadSubmit([]),approval_id:receipt};
  assert.equal((await state.send(confirm)).ok,false,'no issuance');assert.equal(confirms,0);
  const checked=await state.send({type:'inspect',text:'',upload:true});assert.equal(checked.confirmation,true);
  const foreign={...state.sender,documentId:'other-document'};
  assert.equal((await state.send(confirm,foreign)).ok,false);assert.equal(confirms,0);
  assert.equal((await state.send(submit)).ok,false,'not confirmed');assert.equal(submits,0);
  assert.equal((await state.send(confirm)).ok,true);assert.equal(confirms,1);
  assert.equal((await state.send(confirm)).ok,false,'single confirmation');
  assert.equal((await state.send(submit,foreign)).ok,false);assert.equal(submits,0);
  assert.equal((await state.send(submit)).ok,true);assert.equal(submits,1);
  assert.equal((await state.send(submit)).ok,false,'single submission');assert.equal(submits,1);
 }finally{state.close();}
});

test('warning paste cannot approve a transfer before every native acknowledgement',async()=>{
 const receipt='11000000-0000-4000-8000-000000000002';
 const state=worker({responses:{
  browser_inspect:req=>({ok:true,action:'review',text:req.text,confirmation:true,dlp_receipt:receipt,reason:'Check',labels:[]}),
  browser_confirm:()=>({ok:true,applied:true})
 }});
 try{await state.start();const reply=await state.paste(PASTED);assert.equal(reply.confirmation,true);
  assert.equal((await state.send({type:'paste-confirm',token:reply.token})).ok,false);
  assert.equal(state.allowed(state.metadata()),false);
  assert.equal((await state.send({type:'dlp-confirmed',receipt})).ok,true);
  assert.equal((await state.send({type:'paste-confirm',token:reply.token})).ok,true);
  assert.equal(state.allowed(state.metadata()),true);assert.equal(state.allowed(state.metadata()),false);
 }finally{state.close();}
});

test('DLP never approves a paste whose complete logical condition was only checked in fragments',async()=>{
 const policy=policyFor({services:[{id:'chatgpt',domains:['chatgpt.com'],enabled:true,mode:'observe'}],privacy:{enabled:false},dlp_control:{enabled:true,journal:false,fingerprint:'a'.repeat(64)}});policy.version=4;
 let inspected=0;const state=worker({policy,responses:{browser_inspect:req=>{inspected++;return {ok:true,action:'observe',text:req.text};}}});
 try{await state.start();const answer=await state.send({type:'paste',text:'Tomate'+'.'.repeat(32768)+'Carotte'});
  assert.equal(answer.ok,false);assert.equal(inspected,0);assert.equal(state.allowed(state.metadata()),false);
 }finally{state.close();}
});

test('a durable acknowledgement cannot publish an old inspection as a new policy approval',async()=>{
 const policy=policyFor({services:[{id:'chatgpt',domains:['chatgpt.com'],enabled:true,mode:'observe'}],collection:{enabled:true,store_content:false},privacy:{enabled:false},dlp_control:{enabled:true,journal:true,fingerprint:'a'.repeat(64)}});policy.version=4;
 const state=worker({policy,responses:{browser_submit:req=>({ok:true,action:'observe',text:req.text,recording_required:true,durable:true,delivery_id:req.delivery_id,id:'b3000000-0000-4000-8000-000000000001'})}});
 let release;const paused=new Promise(resolve=>{release=resolve;});let entered;const stopped=new Promise(resolve=>{entered=resolve;});let armed=true,send,refresh;
 try{await state.start();const original=chrome.storage.local.set;
  chrome.storage.local.set=async value=>{await original(value);if(armed&&Array.isArray(value.detectorPending)&&value.detectorPending.length===0){armed=false;entered();await paused;}};
  const text='Allowed under policy A';
  send=state.send({type:'submit',text,upload:false,event:{kind:'prompt',action:'observed',characters:text.length,labels:[],url:state.sender.url}});
  await Promise.race([stopped,new Promise((_,reject)=>setTimeout(()=>reject(new Error('acknowledgement was not reached')),1000))]);
  const next=structuredClone(policy);next.revision=2;next.config.dlp_control.fingerprint='b'.repeat(64);state.setPolicy(next);
  refresh=state.send({type:'refresh'},{});
  let adopted=false;for(let i=0;i<100;i++){const current=await state.send({type:'policy'});if(current.policy.revision===2){adopted=true;break;}await new Promise(resolve=>setTimeout(resolve,1));}
  assert.equal(adopted,true,'the new policy is installed while the old acknowledgement waits');
  release();assert.equal((await send).ok,false,'old authorization cannot become a new-revision approval');await refresh;
  const details=state.metadata({},{url:'https://chatgpt.com/backend-api/f/conversation',requestBody:json({messages:[{content:{parts:[text]}}]})});
  assert.equal(state.allowed(details),false,'no network proof survives under the stronger policy');
 }finally{release?.();if(send)await send;if(refresh)await refresh;state.close();}
});

test('warning cancellation sends the authenticated browser identity to the broker',async()=>{
 const receipt='11000000-0000-4000-8000-000000000003';let cancelled=0;
 const state=worker({responses:{
  browser_inspect:req=>({ok:true,action:'review',text:req.text,confirmation:true,dlp_receipt:receipt,labels:[]}),
  browser_cancelled:req=>{assert.equal(req.tool,'chrome');assert.equal(req.delivery_id,receipt);cancelled++;return {ok:true,applied:true};}
 }});
 try{await state.start();assert.equal((await state.send({type:'inspect',text:'Synthetic warning',upload:false})).confirmation,true);
  assert.equal((await state.send({type:'dlp-cancelled',receipt})).applied,true);assert.equal(cancelled,1);
 }finally{state.close();}
});
