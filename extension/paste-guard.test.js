// Pasted text under masking (chantier B). A long paste may leave the page as an upload at paste
// time, before any send: the network guard holds a text upload to a paste the agent approved, and
// a send carrying a pasted chip beside its draft to both approvals. Synthetic texts and bodies,
// shaped like the measured ChatGPT metadata request (2026-10-16).
import test from 'node:test';
import assert from 'node:assert/strict';
import './adapters.js';
import {wireFacts} from './detection.js';
import {requestDecision} from './model-access.js';
import {factoryCatalog} from './detection-factory.js';
import {managedBridge} from './managed-fixture.js';

const policyFor=config=>({version:3,revision:1,expires_at:'2099-01-01T00:00:00Z',config:{services:[],collection:{enabled:false},model_access:[],...config}});
const masking=policyFor({privacy:{enabled:true}}),keyword=policyFor({protection:{keywords:['orion'],exact:'block'}}),uploads=policyFor({protection:{block_uploads:true}}),observe=policyFor({});
const json=value=>({raw:[{bytes:new TextEncoder().encode(JSON.stringify(value)).buffer}]});
const bytes=text=>new TextEncoder().encode(text).length;
const PASTED='Synthetic pasted notes, account [EMAIL] removed.\nSecond line é.';
const meta=over=>({entry_surface:'chat_composer',file_name:'Texte collé.txt',file_size:bytes(PASTED),client_resolved_mime_type:'text/plain',mime_type:'text/plain',use_case:'my_files',...over});
let serial=0;
function files(body,approvals,policy=masking,catalog=factoryCatalog,path='/backend-api/files'){
 const url='https://chatgpt.com'+path,details={requestId:'p'+serial++,tabId:1,documentId:'document-1',url,method:'POST',type:'xmlhttprequest',initiator:'https://chatgpt.com',requestBody:body};
 return requestDecision(details,policy,wireFacts(details,catalog,new URL(url)),approvals,Date.now());
}
const sealed=decision=>decision?.reason==='control_unavailable';
const passes=decision=>!decision||(decision.allow===true&&!decision.reason);
const paste=(text=PASTED)=>({text,kind:'paste'});

test('a pasted text upload is sealed under masking without an approved paste',()=>{
 assert.ok(sealed(files(json(meta()),[])));
 assert.ok(sealed(files(json(meta()),undefined)));
 assert.ok(sealed(files(json(meta()),[],keyword)),'keyword protection holds it too');
});
test('the upload of an approved paste of the same size passes and consumes that approval',()=>{
 const approval=paste(),decision=files(json(meta()),[approval]);
 assert.equal(decision.allow,true);assert.equal(decision.approved,true);
 assert.deepEqual(decision.consumed,[approval]);
});
test('a size that differs from every approved paste is sealed',()=>{
 assert.ok(sealed(files(json(meta({file_size:bytes(PASTED)+1})),[paste()])));
 assert.ok(sealed(files(json(meta({file_size:String(bytes(PASTED))})),[paste()])),'a size that is not a number');
 assert.ok(sealed(files(json(meta({file_size:undefined})),[paste()])),'no size at all');
});
test('the size compared is the UTF-8 byte length, not the character count',()=>{
 const text='é'.repeat(10);
 assert.ok(passes(files(json(meta({file_size:20})),[paste(text)])));
 assert.ok(sealed(files(json(meta({file_size:10})),[paste(text)])));
});
test('a send approval never covers a paste upload',()=>{
 assert.ok(sealed(files(json(meta()),[{text:PASTED}])));
 assert.ok(sealed(files(json(meta()),[{text:PASTED,kind:'send'}])));
});
test('a text file is recognised by its type or its name',()=>{
 assert.ok(sealed(files(json(meta({file_name:'notes.TXT',mime_type:'application/octet-stream',client_resolved_mime_type:undefined})),[])));
 assert.ok(sealed(files(json(meta({file_name:'clip',mime_type:'text/plain'})),[])));
 assert.ok(sealed(files(json({files:{a:{filename:'paste.txt'}}}),[])),'nested in a list of files');
});
test('a non-text upload keeps today’s behaviour',()=>{
 assert.ok(passes(files(json(meta({file_name:'photo.png',mime_type:'image/png',client_resolved_mime_type:'image/png'})),[])));
 assert.ok(passes(files(json({use_case:'my_files'}),[])),'no file named at all');
});
test('outside masking the paste route is not held',()=>{
 assert.ok(passes(files(json(meta()),[],uploads)),'file blocking alone does not seal pasted text');
 assert.equal(files(json(meta()),[],observe),null);
});
test('an unreadable body on the paste route is sealed under masking, approved or not',()=>{
 const gzipped={raw:[{bytes:new Uint8Array([0x1f,0x8b,8,0,0,0,0,0,0,3,1,2,3]).buffer}]};
 assert.ok(sealed(files(gzipped,[paste()])));
 assert.ok(sealed(files({error:'Unknown error.'},[paste()])),'a Blob body, as webRequest reports it');
});

// A multipart upload: Chrome gives the part headers, never the file content (measured 2026-10-16).
const multipartCatalog={providers:[{id:'chatgpt',domains:['chatgpt.com'],network:[{method:'POST',host:'chatgpt.com',path:'/fixture/upload',kind:'paste'}]}]};
const multipart=parts=>({raw:[{bytes:new TextEncoder().encode(parts.map(p=>`------B\r\nContent-Disposition: form-data; ${p}`).join('')+'\r\n------B--\r\n').buffer}]});
const upload=(body,approvals)=>files(body,approvals,masking,multipartCatalog,'/fixture/upload');
test('a multipart text file is sealed under masking: its content cannot be compared',()=>{
 assert.ok(sealed(upload(multipart(['name="file"; filename="Synthetic first words.txt"\r\nContent-Type: text/plain\r\n\r\n']),[paste()])));
 assert.ok(sealed(upload(multipart(['name="file"; filename="clip"\r\nContent-Type: text/plain\r\n\r\n']),[])));
 assert.ok(sealed(upload({formData:{file:['Synthetic first words.txt']}},[paste()])),'the file name Chrome puts in formData');
});
test('a multipart text field carrying the paste must match an approved paste',()=>{
 assert.ok(passes(upload(multipart([`name="text"\r\n\r\n${PASTED}`]),[paste()])));
 assert.ok(sealed(upload(multipart(['name="text"\r\n\r\nClear words jean.exemple@example.com']),[paste()])));
 assert.ok(sealed(upload({formData:{text:['Clear words jean.exemple@example.com']}},[paste()])));
});
test('a multipart image keeps passing, and so do identifiers beside it',()=>{
 assert.ok(passes(upload(multipart(['name="file"; filename="photo.png"\r\nContent-Type: image/png\r\n\r\n','name="purpose"\r\n\r\nupload']),[])));
 assert.ok(passes(upload({formData:{file:['photo.png'],purpose:['upload']}},[])));
});

// A send carrying a pasted chip beside its draft (claude.ai `2.15.4`, a list path).
const twoPaths={providers:[{id:'chatgpt',domains:['chatgpt.com'],network:[{method:'POST',host:'chatgpt.com',path:'/fixture/route',text_path:'',text_paths:['msg.body','chip.text'],attachment_paths:['chip.text']}]}]};
const listPath={providers:[{id:'chatgpt',domains:['chatgpt.com'],network:[{method:'POST',host:'chatgpt.com',path:'/fixture/route',text_path:'',text_paths:['content[*].text']}]}]};
const send=(catalog,body,approvals)=>files(json(body),approvals,masking,catalog,'/fixture/route');
const DRAFT='Summarise the pasted notes';
test('a draft and a pasted chip pass when each was approved',()=>{
 const draft={text:DRAFT,kind:'send'},chip=paste(),decision=send(twoPaths,{msg:{body:DRAFT},chip:{text:PASTED}},[draft,chip]);
 assert.equal(decision.allow,true);assert.deepEqual(new Set(decision.consumed),new Set([draft,chip]));
 assert.ok(passes(send(listPath,{content:[{type:'text',text:DRAFT},{type:'text',text:PASTED}]},[draft,chip])));
});
test('a chip that was never approved keeps the send sealed',()=>{
 assert.ok(sealed(send(twoPaths,{msg:{body:DRAFT},chip:{text:'Clear jean.exemple@example.com'}},[{text:DRAFT,kind:'send'},paste()])));
 assert.ok(sealed(send(listPath,{content:[{type:'text',text:DRAFT},{type:'text',text:'Clear jean.exemple@example.com'}]},[{text:DRAFT,kind:'send'},paste()])));
 assert.ok(sealed(send(twoPaths,{msg:{body:DRAFT},chip:{text:PASTED}},[{text:DRAFT,kind:'send'}])),'the draft approval alone');
});
test('a paste approval never stands for the draft',()=>{
 assert.ok(sealed(send(twoPaths,{msg:{body:PASTED}},[paste()])),'the draft path');
 assert.ok(sealed(send(listPath,{content:[{type:'text',text:PASTED}]},[paste()])),'a list holding the paste alone');
 assert.ok(sealed(send(listPath,{content:[{type:'text',text:PASTED},{type:'text',text:'Second synthetic paste'}]},[paste(),paste('Second synthetic paste')])),'a list of pastes without a draft');
 assert.ok(sealed(send(twoPaths,{msg:{body:DRAFT},chip:{text:PASTED}},[{text:DRAFT,kind:'send'},{text:PASTED,kind:'send'}])),'an attachment path covered by a send approval');
 assert.ok(passes(send(twoPaths,{chip:{text:PASTED}},[paste()])),'a pasted block sent alone');
});
test('an unreadable send rides only on a send approval, never on a lingering paste',()=>{
 const gzipped={raw:[{bytes:new Uint8Array([0x1f,0x8b,8,0,0,0,0,0,0,3,1,2,3]).buffer}]};
 assert.ok(sealed(files(gzipped,[paste()],masking,twoPaths,'/fixture/route')));
 assert.equal(files(gzipped,[{text:DRAFT,kind:'send'}],masking,twoPaths,'/fixture/route').allow,true);
});

// The worker: a paste is inspected in pieces the agent accepts, approved as one text, once.
async function worker(policy,inspect=req=>({ok:true,action:'observe',text:req.text,labels:[]})){
 let message;const handlers={},stored={},noop={addListener(){}};const inspected=[];
 const bridge=managedBridge({browser_policy:()=>({online:true,policy}),browser_inspect:req=>{inspected.push(req.text);return inspect(req);},browser_submit:req=>({ok:true,action:'observe',text:req.text,recording_required:false}),browser_event:req=>({ok:true,id:crypto.randomUUID(),durable:true,delivery_id:req.delivery_id}),browser_catalog:()=>({catalog:null,revision:0,catalog_state:'missing'}),browser_health:req=>({accepted_health_ids:[req.batch.id]})});
 globalThis.chrome={runtime:{onInstalled:noop,onStartup:noop,onMessage:{addListener(fn){message=fn;}},sendNativeMessage:bridge.sendNativeMessage},
  storage:{managed:{async get(){return {milvago_pin:JSON.stringify(bridge.pin)};}},local:{async get(k){return {[k]:stored[k]};},async set(v){Object.assign(stored,v);}}},
  alarms:{create(){},onAlarm:noop},tabs:{async query(){return [];},async reload(){},async sendMessage(){}},
  declarativeNetRequest:{async getDynamicRules(){return [];},async updateDynamicRules(){}},
  webRequest:Object.fromEntries(['onBeforeRequest','onBeforeSendHeaders','onCompleted','onErrorOccurred'].map(k=>[k,{addListener(fn){handlers[k]=fn;}}]))};
 await import('./background.js?paste-guard='+serial++);
 const sender={frameId:0,documentId:'document-1',tab:{id:1},url:'https://chatgpt.com/'};
 const send=(msg,from=sender)=>new Promise(resolve=>message(msg,from,resolve));
 assert.deepEqual(await send({type:'refresh'},{}),{ok:true});
 const metadata=size=>({requestId:'w'+serial++,tabId:1,documentId:'document-1',method:'POST',type:'xmlhttprequest',url:'https://chatgpt.com/backend-api/files',initiator:'https://chatgpt.com',requestBody:json(meta({file_size:size}))});
 return {send,inspected,allowed:details=>!handlers.onBeforeRequest(details).cancel,metadata,close(){delete globalThis.chrome;}};
}
const lines=(count,width=70)=>Array.from({length:count},(_,i)=>`Synthetic line ${i} `.padEnd(width,'x')).join('\n');

test('the worker inspects a long paste in pieces under the agent limit and approves the whole text once',async()=>{
 const state=await worker(masking);
 try{
  const text=lines(600);assert.ok(bytes(text)>32768);
  const reply=await state.send({type:'paste',text});
  assert.equal(reply.ok,true);assert.equal(reply.action,'observe');assert.equal(reply.text,text);
  assert.ok(state.inspected.length>=2&&state.inspected.every(chunk=>bytes(chunk)<=32768));
  const pieces=state.inspected.slice(0,(state.inspected.length+1)/2);
  assert.equal(pieces.join('\n'),text,'the pieces cover the paste exactly, then each seam is inspected');
  assert.equal(state.allowed(state.metadata(bytes(text))),false,'not before the person confirms it');
  assert.deepEqual(await state.send({type:'paste-confirm',token:reply.token}),{ok:true});
  assert.equal(state.allowed(state.metadata(bytes(text))),true);
  assert.equal(state.allowed(state.metadata(bytes(text))),false,'single use');
 }finally{state.close();}
});
test('the worker approves the masked text, never the original',async()=>{
 const state=await worker(masking,req=>({ok:true,action:'review',text:req.text.replaceAll('jean.exemple@example.com','[EMAIL]'),labels:['email']}));
 try{
  const text='Notes\nContact jean.exemple@example.com\r\nEnd';
  const reply=await state.send({type:'paste',text});
  assert.equal(reply.action,'review');assert.equal(reply.text,'Notes\nContact [EMAIL]\nEnd');assert.deepEqual(reply.labels,['email']);
  await state.send({type:'paste-confirm',token:reply.token});
  assert.equal(state.allowed(state.metadata(bytes(text))),false);
  assert.equal(state.allowed(state.metadata(bytes(reply.text))),true);
 }finally{state.close();}
});
test('a paste the agent blocks, or cannot inspect, is not approved',async()=>{
 let calls=0;
 const state=await worker(masking,req=>(++calls===2?{ok:true,action:'block',text:req.text,labels:['keyword'],reason:'Mot protégé.'}:{ok:true,action:'observe',text:req.text,labels:[]}));
 try{
  const text=lines(600);
  const reply=await state.send({type:'paste',text});
  assert.equal(reply.action,'block');assert.equal(state.allowed(state.metadata(bytes(text))),false);
  for(const bad of [{type:'paste',text:'x'.repeat(200*1024)},{type:'paste',text:lines(3000)},{type:'paste',text:42},{type:'paste'}]){
   const answer=await state.send(bad);assert.equal(answer.ok,false,JSON.stringify(bad).slice(0,60));
  }
 }finally{state.close();}
});
test('a later draft approval does not discard an earlier paste approval',async()=>{
 const state=await worker(masking);
 try{
  const pasted=await state.send({type:'paste',text:PASTED});await state.send({type:'paste-confirm',token:pasted.token});
  const reply=await state.send({type:'submit',text:DRAFT,upload:false,event:{kind:'prompt',action:'observed',characters:DRAFT.length,labels:[],url:'https://chatgpt.com/'}});
  assert.equal(reply.ok,true);
  assert.equal(state.allowed(state.metadata(bytes(PASTED))),true);
  const other={frameId:0,documentId:'document-2',tab:{id:1},url:'https://chatgpt.com/'};
  const elsewhere=await state.send({type:'paste',text:PASTED},other);await state.send({type:'paste-confirm',token:elsewhere.token},other);
  assert.equal(state.allowed(state.metadata(bytes(PASTED))),false,'another document of the tab does not lend its approval');
 }finally{state.close();}
});
test('outside masking a paste is answered without approval or inspection of pieces',async()=>{
 const state=await worker(observe);
 try{const reply=await state.send({type:'paste',text:PASTED});assert.equal(reply.ok,true);assert.equal(reply.text,PASTED);assert.equal(reply.token,undefined);}finally{state.close();}
});
// A value cut by the pieces is inspected whole at the seam, and the masked seam is put back exactly.
const IBAN='FR76 3000 6000\n0112 3456 7890 189';
const maskIban=req=>{const text=req.text.replaceAll(IBAN,'[IBAN]');return {ok:true,action:text===req.text?'observe':'review',text,labels:text===req.text?[]:['iban']};};
test('a value across the cut between two pieces is masked at their seam',async()=>{
 const state=await worker(masking,maskIban);
 try{
  const head='x'.repeat(32768-1-14),text=head+'\n'+IBAN+'\nSynthetic tail line.\n'+lines(20);
  const reply=await state.send({type:'paste',text});
  assert.ok(state.inspected.some(chunk=>chunk.endsWith('FR76 3000 6000'))&&state.inspected.some(chunk=>chunk.startsWith('0112')),'the pieces did cut the value');
  assert.equal(reply.action,'review');assert.deepEqual(reply.labels,['iban']);
  assert.equal(reply.text,text.replace(IBAN,'[IBAN]'),'the rest of the text is reassembled exactly');
 }finally{state.close();}
});
test('a line longer than one piece is cut after a blank, or between characters, and reassembled exactly',async()=>{
 const state=await worker(masking);
 try{
  for(const text of [Array.from({length:6000},(_,i)=>'word'+i).join(' '),'é'.repeat(40000),'a😀'.repeat(15000),'start\n'+'z'.repeat(70000)+'\nend']){
   state.inspected.length=0;
   const reply=await state.send({type:'paste',text});
   assert.equal(reply.ok,true);assert.equal(reply.text,text,text.slice(0,12));
   assert.ok(state.inspected.length>=2&&state.inspected.every(chunk=>bytes(chunk)<=32768&&!/^[\uDC00-\uDFFF]|[\uD800-\uDBFF]$/.test(chunk)));
  }
  state.inspected.length=0;
  await state.send({type:'paste',text:Array.from({length:6000},(_,i)=>'word'+i).join(' ')});
  assert.ok(state.inspected[0].endsWith(' '),'the first piece ends at a blank');
 }finally{state.close();}
});
