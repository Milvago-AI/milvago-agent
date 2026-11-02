// Real campaign 0.7.6 (2026-10-16), shared engine. Bodies follow the shape of the requests measured on
// the real sites (CDP, every non-GET request failed, nothing sent), with synthetic values only.
//  1. A WebChannel batch (base64 protobuf messages in `req<n>___data__` form fields) carried the text
//     past the guard: no rule could read it.
//  2. A provider page posted the draft to a third-party suggestion host while the person typed.
//  5. claude.ai sends a picked `.txt` inline in `PerformAction` (`2.15`: name, size, type, content): sealed
//     under masking, then resent by the page about every 4 s, one event each time.
//  6. A multipart upload stating no size: the picked text file was sealed.
//  7. A sub-route body with no draft field but prose elsewhere (an answer to a question the model asked)
//     was sealed without a notice.
//  8. Thinking placeholders ("Réflexion…") were recorded as answers.
//  10. claude.ai: a `PerformAction` without text recorded a 0-character prompt, its model
//     (`2.7.2`) was not read, and its answers began with a screen-reader heading.
//  4. The notice page of a blocked service did not open under Chrome installed by policy.
import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {JSDOM} from 'jsdom';
globalThis.browser={runtime:{id:'synthetic-extension',onMessage:{addListener(){},removeListener(){}}},storage:{local:{get:async()=>({}),set:async()=>{}}}};
await import('./adapters.js');await import('./capture.js');
const {wireFacts,headerModelScope,headerModelProvider,observeRequest,decodeProtobuf}=await import('./detection.js');
const {requestDecision,nameDigest}=await import('./model-access.js');
const {factoryCatalog}=await import('./detection-factory.js');
const {networkRules}=await import('./policy.js');
const A=globalThis.MilvagoAdapters;

const policyFor=config=>({version:3,revision:7,expires_at:'2099-01-01T00:00:00Z',config:{services:[],model_access:[],collection:{enabled:false},...config}});
const masking=policyFor({privacy:{enabled:true}});
const keyword=policyFor({protection:{keywords:['orion'],exact:'block'}});
const open=policyFor({});
const bytes=u8=>({raw:[{bytes:u8.buffer.slice(u8.byteOffset,u8.byteOffset+u8.byteLength)}]});
const raw=text=>bytes(new TextEncoder().encode(text));
const json=value=>raw(JSON.stringify(value));
let serial=0;
function decide(url,requestBody,{policy=masking,approvals,method='POST',catalog=factoryCatalog,initiator}={}){
 const details={requestId:'r'+serial++,tabId:1,documentId:'document-1',url,method,type:'xmlhttprequest',initiator:initiator||new URL(url).origin,...(requestBody===undefined?{}:{requestBody})};
 return requestDecision(details,policy,wireFacts(details,catalog,new URL(url)),approvals,Date.now(),(id,u)=>headerModelScope(catalog,id,details,u));
}
const passes=decision=>!decision||(decision.allow===true&&!decision.reason);
const sealed=decision=>decision?.reason==='control_unavailable';
const send=text=>({kind:'send',text});
const fileApproval=(name,size)=>({kind:'file',name:nameDigest(name),size});
const SECRET='Le projet Orion rachete la societe Exemple, IBAN FR7630006000011234567890189';

// A minimal protobuf writer: `ld` a length-delimited field, `vi` a varint field.
const enc=new TextEncoder();
function varint(n){const out=[];while(n>127){out.push((n&127)|128);n=Math.floor(n/128);}out.push(n);return out;}
const ld=(field,payload)=>[...varint(field*8+2),...varint(payload.length),...payload];
const vi=(field,n)=>[...varint(field*8),...varint(n)];
const str=(field,text)=>ld(field,[...enc.encode(text)]);
const u8=list=>new Uint8Array(list);

// --- 5. claude.ai, a picked `.txt` sent inline -------------------------------------------------
const PERFORM='https://claude.ai/claudeai-rpc/anthropic.bard.api.v1alpha.ConversationService/PerformAction';
const CONVERSATION_ID='4bd34c3e-ebd6-45de-8868-650ccf424d37';
function perform({text='Dis OK',files=[],model='claude-sonnet-5-5'}={}){
 const message=[...str(1,'eeab9e26-0f7b-4e8d-8bcf-20145d4e098f'),...str(2,'f4256f17-116b-48c3-923d-1308d44b340a'),...(text?str(3,text):[]),...(model?ld(7,str(2,model)):[]),...str(12,'Asia/Dubai'),...str(13,'fr-RE'),
  ...files.flatMap(f=>ld(15,[...(f.name!==undefined?str(1,f.name):[]),...vi(2,f.size??enc.encode(f.content).length),...str(3,f.type||'text/plain'),...str(4,f.content)])),...vi(18,1)];
 return bytes(u8([...ld(1,[...ld(1,[...str(1,'sess_80176c3842acfc63'),...vi(2,3)]),...str(2,CONVERSATION_ID),...vi(3,3),...str(14,'fr-FR')]),...ld(2,message)]));
}
const NOTE='Note de test synthetique, aucune donnee reelle.\n';

test('a picked text file sent inline passes on its name and size, once',()=>{
 const file=fileApproval('note-test.txt',enc.encode(NOTE).length);
 const decision=decide(PERFORM,perform({files:[{name:'note-test.txt',content:NOTE}]}),{approvals:[send('Dis OK'),file]});
 assert.equal(decision?.allow,true);assert.equal(decision.consumed.length,2);assert.ok(decision.consumed.includes(file));
 assert.ok(sealed(decide(PERFORM,perform({files:[{name:'note-test.txt',content:NOTE}]}),{approvals:[send('Dis OK')]})),'never without the picked file');
 // A byte-order mark the provider dropped still counts.
 assert.equal(decide(PERFORM,perform({files:[{name:'note-test.txt',content:NOTE}]}),{approvals:[send('Dis OK'),fileApproval('note-test.txt',enc.encode(NOTE).length+3)]})?.allow,true);
});

test('an inline file is sealed on another name, another size, a second use or a pasted chip',()=>{
 const file=fileApproval('note-test.txt',enc.encode(NOTE).length);
 for(const [label,files,approvals] of [
  ['another name',[{name:'other.txt',content:NOTE}],[file]],
  ['no name',[{content:NOTE}],[file]],
  ['another size',[{name:'note-test.txt',content:NOTE+'x'}],[file]],
  ['a secret instead of the content, same name',[{name:'note-test.txt',content:SECRET}],[file]],
  ['two files, one approval',[{name:'note-test.txt',content:NOTE},{name:'note-test.txt',content:NOTE}],[file]],
  ['the name written in the content only',[{name:'note-test.txt',content:'note-test.txt'}],[fileApproval('other.txt',13)]],
 ]){assert.ok(sealed(decide(PERFORM,perform({files}),{approvals:[send('Dis OK'),...approvals]})),label);}
 // Two picked files, each with its own approval.
 const second=fileApproval('b.txt',2);
 assert.equal(decide(PERFORM,perform({files:[{name:'note-test.txt',content:NOTE},{name:'b.txt',content:'ab'}]}),{approvals:[send('Dis OK'),file,second]})?.allow,true);
 // An empty file carries no text: nothing to compare.
 assert.equal(decide(PERFORM,perform({files:[{name:'empty.txt',content:''}]}),{approvals:[send('Dis OK')]})?.allow,true);
 // A paste approval still covers a pasted chip, and a file approval never stands for the draft.
 assert.equal(decide(PERFORM,perform({files:[{content:NOTE,type:'text/plain'}]}),{approvals:[send('Dis OK'),{kind:'paste',text:NOTE}]})?.allow,true);
 assert.ok(sealed(decide(PERFORM,perform({text:NOTE}),{approvals:[fileApproval('note-test.txt',enc.encode(NOTE).length)]})));
});

test('a send without text at its paths stays sealed when prose hides in an opaque value or a plain form field',()=>{
 // Security loop, 2026-10-17: the text-less branch recomputed prose on the decoded strings only, and dropped
 // what the protobuf read had found in opaque values.
 const hidden=bytes(u8([...ld(1,str(2,CONVERSATION_ID)),...ld(2,[...str(1,'eeab9e26-0f7b-4e8d-8bcf-20145d4e098f'),...ld(20,[0xff,...enc.encode(SECRET)])])]));
 assert.ok(sealed(decide(PERFORM,hidden,{approvals:[]})));
 assert.ok(passes(decide(PERFORM,perform({text:''}),{approvals:[]})),'a plain action without text passes');
});

test('claude.ai: a send without text records no prompt, its model is read, its answer loses the screen-reader heading',async()=>{
 const observe=async body=>observeRequest({url:PERFORM,method:'POST',requestBody:body},factoryCatalog,true);
 const empty=await observe(perform({text:''}));
 assert.equal(empty.silent,true);assert.equal(empty.model,'claude-sonnet-5-5');assert.equal(empty.conversation_id,CONVERSATION_ID);assert.equal(empty.characters,undefined);
 const sent=await observe(perform({text:'Dis OK'}));
 assert.equal(sent.silent,undefined);assert.equal(sent.characters,6);assert.equal(sent.model,'claude-sonnet-5-5');
 // A compressed or unreadable body keeps its event, characters unknown.
 const unreadable=await observe(bytes(u8([0x1f,0x8b,1,2,3])));
 assert.equal(unreadable.silent,undefined);assert.equal(unreadable.characters_known,false);
 const dom=new JSDOM('<div data-is-streaming="false"><h2 class="sr-only select-none">Claude a répondu : OK.</h2><p>OK. Code bien noté.</p><time>il y a 29 minutes</time></div>');
 assert.equal(A.answer(dom.window.document.querySelector('[data-is-streaming]')),'OK. Code bien noté.');
});

// --- 1. WebChannel batch, protobuf messages in form fields (synthetic catalogue rule) ------------
const BATCH='https://claude.ai/synthetic/v1/session';
const batchCatalog={providers:factoryCatalog.providers.map(p=>p.id!=='claude'?p:{...p,network:[...p.network,{method:'POST',host:'claude.ai',path:'/synthetic/v1/session',form_field:'___data__',body_format:'protobuf',text_path:'',text_paths:['2[*].9[*].1[*]','1[*].8[*].5[*].1[*].1[*].1[*]'],model_path:'1[*].1[*].2[*]',model_map:{'56fdd199312815e2':'model-a','cf41b0e0dd7d53e5':'model-auto'},effort_path:'',conversation_path:''}]}),native_tools:[],heuristics:factoryCatalog.heuristics};
const b64=list=>Buffer.from(u8(list)).toString('base64');
const opener=(text,model='56fdd199312815e2')=>[...ld(1,[...ld(1,[...vi(1,1),...str(2,model),...str(3,'fr'),...str(4,'B48F9456-8206-41AD-8837-A91E8CB5CFBC')]),...vi(2,0),...ld(8,ld(5,[...ld(1,ld(1,[...str(1,text),...vi(2,0)])),...str(5,'c49fa06aa49fa991c69268a5ca60ee0b')]))])];
const message=text=>[...ld(2,[...vi(1,1),...ld(9,str(1,text))])];
const form=fields=>({formData:Object.fromEntries(Object.entries(fields).map(([k,v])=>[k,[v]]))});

test('a WebChannel batch is read field by field, its text compared like a send',()=>{
 const approval=send(SECRET);
 for(const [label,body] of [
  ['the text sent into an open session',form({count:'1',ofs:'1',req0___data__:b64(message(SECRET))})],
  ['a session opened with the text',form({count:'2',ofs:'0',req0___data__:b64(opener(SECRET)),req1___data__:b64(message(SECRET))})],
  ['the same batch as raw bytes',raw(new URLSearchParams({count:'1',ofs:'1',req0___data__:b64(message(SECRET))}).toString())],
 ]){
  assert.ok(sealed(decide(BATCH,body,{catalog:batchCatalog,approvals:[]})),label+' unapproved');
  assert.ok(sealed(decide(BATCH,body,{catalog:batchCatalog,policy:keyword,approvals:[]})),label+' blocking keyword');
  const decision=decide(BATCH,body,{catalog:batchCatalog,approvals:[approval]});
  assert.equal(decision?.allow,true,label+' approved');
 }
 // The session's own calls carry no text: handshake, empty opener, acknowledgement, terminate.
 for(const body of [form({count:'0'}),form({count:'1',ofs:'0',req0___data__:b64(opener(''))}),form({count:'1',ofs:'2',req0___data__:b64([...ld(4,vi(1,1))])}),undefined]){
  assert.ok(passes(decide(BATCH,body,{catalog:batchCatalog,approvals:[]})),JSON.stringify(body));
 }
 assert.ok(passes(decide(BATCH,form({count:'1',ofs:'1',req0___data__:b64(message(SECRET))}),{catalog:batchCatalog,policy:open,approvals:[]})),'no content control');
});

test('a text one message down is found at its path whatever its length, even when its message is printable',()=>{
 for(const length of [1,20,31,32,33,76,126,127,128,300,5000]){
  const text=('Bonjour synthetique '.repeat(300)).slice(0,length);
  const body=form({count:'1',ofs:'1',req0___data__:b64(message(text))});
  assert.equal(decide(BATCH,body,{catalog:batchCatalog,approvals:[send(text)]})?.allow,true,'length '+length);
  assert.ok(sealed(decide(BATCH,body,{catalog:batchCatalog,approvals:[send(text+'x')]})),'length '+length+' unapproved');
 }
});

test('a WebChannel batch is sealed when a field cannot be read or text travels beside it',()=>{
 const approval=send('Bonjour');
 for(const [label,body] of [
  ['not base64',form({count:'1',ofs:'1',req0___data__:'%%%not base64'})],
  ['base64 of a truncated message',form({count:'1',ofs:'1',req0___data__:b64(message('Bonjour')).slice(0,-8)})],
  ['a second message with other text',form({count:'2',ofs:'1',req0___data__:b64(message('Bonjour')),req1___data__:b64(message(SECRET))})],
  ['prose in another form field',form({count:'1',ofs:'1',req0___data__:b64(message('Bonjour')),note:SECRET})],
  ['prose elsewhere in the message',form({count:'1',ofs:'1',req0___data__:b64([...message('Bonjour'),...str(7,SECRET)])})],
  ['a batch past the body limit',form({count:'1',ofs:'1',req0___data__:b64(message('a'.repeat(140*1024)))})],
  ['a Blob body',{error:'Unable to read'}],
  ['a data field given twice',{formData:{count:['1'],req0___data__:[b64(message('Bonjour')),b64(message(SECRET))]}}],
  ['more fields than the guard reads',form(Object.fromEntries([['req0___data__',b64(message('Bonjour'))],...Array.from({length:300},(_,i)=>['f'+i,'1'])]))],
  ['a JSON body',json({req0___data__:b64(message('Bonjour')),text:SECRET})],
  ['plain text body',raw(SECRET)],
 ]){assert.ok(sealed(decide(BATCH,body,{catalog:batchCatalog,approvals:[approval]})),label);}
});

test('a sibling of a batch route carrying text in a plain form field is sealed',()=>{
 const SIBLING='https://claude.ai/synthetic/v1/other';
 assert.ok(sealed(decide(SIBLING,form({count:'1',q:SECRET}),{catalog:batchCatalog,approvals:[]})));
 assert.ok(passes(decide(SIBLING,form({count:'1',ofs:'0'}),{catalog:batchCatalog,approvals:[]})),'its own calls pass');
 assert.ok(passes(decide(SIBLING,form({count:'1',req0___data__:b64([...ld(4,vi(1,1))])}),{catalog:batchCatalog,approvals:[]})),'a message without text');
});

test('a hostile WebChannel batch is decided quickly',()=>{
 const deep=[];let inner=str(1,'x');for(let i=0;i<40;i++){inner=ld(1,inner);}deep.push(...inner);
 const wide=[];for(let i=0;i<20000;i++){wide.push(...vi(3,1));}
 for(const list of [deep,wide,new Array(90*1024).fill(0x0a)]){
  const started=performance.now();
  assert.ok(sealed(decide(BATCH,form({count:'1',ofs:'1',req0___data__:b64(list)}),{catalog:batchCatalog,approvals:[]}))||true);
  assert.ok(performance.now()-started<500,'decided in '+(performance.now()-started)+' ms');
 }
});

test('a batch names its model in the message that opens the session; others are not decided on one',()=>{
 assert.ok(headerModelProvider(batchCatalog,'claude')===null,'a JSON route without a header still disqualifies the provider');
 const only={...batchCatalog,providers:batchCatalog.providers.map(p=>p.id!=='claude'?p:{...p,network:p.network.filter(n=>n.path==='/synthetic/v1/session')})};
 assert.ok(headerModelProvider(only,'claude'));
 const scope=body=>headerModelScope(only,'claude',{method:'POST',url:BATCH,...(body?{requestBody:body}:{})},new URL(BATCH)).route.body;
 assert.deepEqual(scope(form({count:'1',ofs:'0',req0___data__:b64(opener(''))})),{model:'model-a',known:true});
 assert.deepEqual(scope(form({count:'1',ofs:'0',req0___data__:b64(opener('','0123456789abcdef'))})),{model:'claude:0123456789abcdef',known:false});
 assert.deepEqual(scope(form({count:'1',ofs:'1',req0___data__:b64(message('Bonjour'))})),{absent:true});
 assert.deepEqual(scope(undefined),{absent:true});
 assert.equal(scope(form({count:'1',ofs:'0',req0___data__:'%%%'})).known,false,'unreadable: unknown, never absent');
 assert.equal(scope(form({count:'2',ofs:'0',req0___data__:b64(opener('')),req1___data__:b64(opener('','e6fa609c3fa255c0'))})).known,false,'two models: unknown');
 // An opening message without its model (forged, or a shape the catalogue missed) names no model.
 const bare=[...ld(1,[...ld(1,[...vi(1,1),...str(3,'fr')]),...vi(2,0)])];
 assert.deepEqual(scope(form({count:'1',ofs:'0',req0___data__:b64(bare)})),{model:undefined,known:false});
 // Review of the 0.7.6 fixes: each message of a batch opens its own session, so a second opening without a
 // model was let through on the first one's model.
 assert.deepEqual(scope(form({count:'2',ofs:'0',req0___data__:b64(opener('')),req1___data__:b64(bare)})),{model:undefined,known:false},'a second opening without its model');
});

test('a batch message is read on its own: a length left open cannot swallow the next one',()=>{
 // Review of the 0.7.6 fixes: the messages were joined before reading, and an open length at the end of the
 // first read the second, text and all, as one opaque field outside the paths. The server reads each alone.
 const word='PRJ-1234-PRJ-1234-PRJ-1234',next=message(word);
 const dangling=[...message('Bonjour'),...varint(15*8+2),...varint(next.length)];
 assert.ok(sealed(decide(BATCH,form({count:'2',ofs:'1',req0___data__:b64(dangling),req1___data__:b64(next)}),{catalog:batchCatalog,approvals:[send('Bonjour')]})));
 assert.equal(decide(BATCH,form({count:'2',ofs:'1',req0___data__:b64(message('Bonjour')),req1___data__:b64(message('Bonjour'))}),{catalog:batchCatalog,approvals:[send('Bonjour')]})?.allow,true,'two whole messages');
});

test('a string met on a path is read again as a message, a prompt at the end of a path never is',()=>{
 // Review of the 0.7.6 fixes. (1) A message whose bytes are all printable and whose first field is not a
 // length-delimited one (a varint ` `) was read as a string: text inside it, one message down, was out of
 // the path's reach. (2) A prompt that parses whole as a message (a sentence said twice, `B` opening a
 // field 8 of 111 bytes) was read as one and sealed even approved; so was a prompt whose trial length cut
 // an accent in two, the piece left among the opaque values.
 const word='PRJ-1234-PRJ-1234-PRJ-1234-PRJ-1234-PRJ-1234',inner=str(1,word),nine=[0x4a,inner.length,...inner],two=[0x20,0x20,...nine];
 assert.ok(two.every(b=>b===10||b>=0x20&&b<0x7f));
 assert.ok(sealed(decide(BATCH,form({count:'1',ofs:'1',req0___data__:b64([0x12,two.length,...two])}),{catalog:batchCatalog,approvals:[]})),'hidden one message down');
 let cut='Bonjour, voici ma question ';while(enc.encode(cut).length<112){cut+='a';}cut+='été fin de la question.';
 assert.equal(enc.encode(cut)[112],0xc3);
 const twice='Bonjour, je voudrais savoir comment configurer le serveur. '.repeat(2);
 // A vertical tab makes the prompt unprintable: it is then tried as a message, and that trial fails.
 for(const text of [cut,twice,cut+'']){
  assert.equal(decide(BATCH,form({count:'1',ofs:'1',req0___data__:b64(message(text))}),{catalog:batchCatalog,approvals:[send(text)]})?.allow,true,'approved: '+text.slice(0,20));
  assert.equal(decide(PERFORM,perform({text}),{approvals:[send(text)]})?.allow,true,'approved, claude.ai: '+text.slice(0,20));
 }
});

test('a WebChannel batch is observed like any route',async()=>{
 const hit=await observeRequest({url:BATCH,method:'POST',requestBody:form({count:'2',ofs:'0',req0___data__:b64(opener('Bonjour')),req1___data__:b64(message('Bonjour'))})},batchCatalog,true);
 assert.equal(hit.characters,7);assert.equal(hit.model,'model-a');
 const quiet=await observeRequest({url:BATCH,method:'POST',requestBody:form({count:'1',ofs:'0',req0___data__:b64(opener(''))})},batchCatalog,true);
 assert.equal(quiet.silent,true);assert.equal(quiet.model,'model-a');
 assert.deepEqual(Object.keys(decodeProtobuf(u8(message('x')))),['2']);
});

// --- 2. a draft posted to a third-party host --------------------------------------------------
test('a draft posted to a third-party host the page names is sealed quietly unless approved',()=>{
 const claude=A.adapters.find(a=>a.id==='claude'),saved=claude.drafts;
 claude.drafts=[{host:'suggest.example.test',path:'/api/v1/suggestions',field:'QueryString'}];
 try{
  const URL_='https://suggest.example.test/api/v1/suggestions?setflight=1',initiator='https://claude.ai';
  const body=text=>json({Scenario:{Name:'Web.Synthetic_QF'},EntityRequests:['Prompt','People','File'].map(EntityType=>({EntityType,Query:{QueryString:text},Size:10})),LogicalId:'18c13a1f-a55b-444e-a0ef-00290b619125'});
  for(const policy of [masking,keyword]){const d=decide(URL_,body(SECRET),{policy,approvals:[],initiator});assert.ok(sealed(d));assert.equal(d.quiet,true);}
  assert.ok(passes(decide(URL_,body(SECRET),{approvals:[send(SECRET)],initiator})),'the draft just approved');
  assert.ok(passes(decide(URL_,body(''),{approvals:[],initiator})),'an empty query');
  assert.ok(passes(decide(URL_,body(SECRET),{policy:open,approvals:[],initiator})),'no masking');
  assert.ok(sealed(decide(URL_,body('x'.repeat(140*1024)),{approvals:[],initiator})),'too large to read');
  assert.ok(sealed(decide('https://suggest.example.test/API/v1/Suggestions/',body(SECRET),{approvals:[],initiator})),'spelling variant');
  assert.ok(passes(decide(URL_,body(SECRET),{approvals:[],initiator:'https://other.example.test'})),'only from the page that names it');
  // Prose in another field of the same body is sealed too, quietly.
  const d=decide(URL_,json({EntityRequests:[{Query:{QueryString:''}}],Note:SECRET}),{approvals:[],initiator});assert.ok(sealed(d));assert.equal(d.quiet,true);
 }finally{claude.drafts=saved;}
});

// --- 7. a sub-route body with prose outside the draft field -----------------------------------
const RESUME='https://chatgpt.com/backend-api/f/conversation/resume';
test('prose sent to a sub-route without a draft field is a send: approved it passes, refused it is announced',()=>{
 const answer='Je choisis la deuxieme option, merci';
 const body=json({conversation_id:'6aa99383-dd04-43ea-88fb-50a164a3820d',callbackResults:[{toolCallId:'call_1',result:{answer}}]});
 const refused=decide(RESUME,body,{approvals:[]});
 assert.ok(sealed(refused));assert.notEqual(refused.quiet,true,'announced');
 const ok=decide(RESUME,body,{approvals:[send(answer)]});
 assert.ok(passes(ok));assert.equal(ok.consumed,undefined,'not spent');
 assert.ok(sealed(decide(RESUME,json({callbackResults:[{result:{answer}},{result:{other:SECRET}}]}),{approvals:[send(answer)]})),'unapproved prose beside it');
 assert.ok(sealed(decide(RESUME,json({callbackResults:[{result:{answer}}],tags:['alpha','bravo','charlie']}),{approvals:[send(answer)]})),'a list of words beside it');
 // A draft-shaped body keeps the quiet seal.
 const draft=decide('https://chatgpt.com/backend-api/f/conversation/prepare',json({partial_query:{content:{parts:[SECRET]}}}),{approvals:[]});
 assert.ok(sealed(draft));assert.equal(draft.quiet,true);
 const empty=decide('https://chatgpt.com/backend-api/f/conversation/prepare',json({partial_query:{content:{parts:[]}},note:SECRET}),{approvals:[]});
 assert.ok(sealed(empty));assert.equal(empty.quiet,true,'an empty draft field is still a draft');
});

// --- 6. a multipart upload stating no size ------------------------------------------------------
test('a paste-route upload stating only a name passes as the file picked under that name',()=>{
 const FILES='https://chatgpt.com/backend-api/files',body={formData:{file:['notes.txt'],purpose:['assistants']}};
 assert.ok(sealed(decide(FILES,body,{approvals:[]})));
 const approval=fileApproval('notes.txt',1234);
 const decision=decide(FILES,body,{approvals:[approval]});
 assert.equal(decision?.allow,true);assert.deepEqual(decision.consumed,[approval]);
 assert.ok(sealed(decide(FILES,{formData:{file:['other.txt']}},{approvals:[approval]})),'another name');
 assert.ok(sealed(decide(FILES,{formData:{file:['notes.txt'],text:[SECRET]}},{approvals:[approval]})),'pasted text riding as a field');
 assert.ok(sealed(decide(FILES,{formData:{file:['notes.txt','notes.txt']}},{approvals:[approval]})),'two files, one approval');
});

// --- 8. thinking placeholders --------------------------------------------------------------------
test('a thinking placeholder is not recorded as the answer',async()=>{
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
  await A.write(doc.querySelector('textarea'),'Synthetic prompt');
  await controller.handle({type:'click',target:doc.querySelector('button'),isTrusted:true,preventDefault(){},stopImmediatePropagation(){}});
  doc.getElementById('thread').innerHTML='<li data-message-role="assistant">Réflexion…</li>';
  await new Promise(r=>setTimeout(r,3000));
  assert.equal(events.filter(e=>e.kind==='response').length,0,'still thinking');
  doc.querySelector('[data-message-role]').textContent='Voici la reponse finale synthetique.';
  await new Promise(r=>setTimeout(r,3000));
  assert.deepEqual(events.filter(e=>e.kind==='response').map(e=>e.characters),[36]);
 }finally{controller.dispose();dom.window.close();}
});

test('a short answer ending in an ellipsis is still recorded when the next prompt is sent within the wait',async()=>{
 // Review of the 0.7.6 fixes: the 60 s wait made a short real answer ("Je ne sais pas...") lost when the
 // person sent again before its end, the next send clearing every pending answer.
 const dom=new JSDOM('<form><textarea id="mobile-composer-prompt"></textarea><button type="submit">Send</button></form><ul id="thread"></ul>',{url:'https://chatgpt.com/'}),doc=dom.window.document;
 Object.defineProperty(dom.window.crypto,'subtle',{value:webcrypto.subtle});
 doc.querySelector('form').addEventListener('submit',e=>e.preventDefault());
 const events=[],sends=[],policy={config:{collection:{enabled:true,store_content:false},services:[{enabled:true,domains:['chatgpt.com']}]}};
 let receipt=0;
 const controller=globalThis.MilvagoCapture.start(doc,dom.window.location,async msg=>{
  if(msg.type==='policy'){return {ok:true,policy};}if(msg.type==='inspect'){return {ok:true,action:'observe',text:msg.text};}
  if(msg.type==='submit'){receipt++;sends.push(msg.event.correlation_id);return {ok:true,action:'observe',text:msg.text,durable:true,recording_required:true,authority:'a'.repeat(64),delivery_id:'00000000-0000-4000-8000-00000000000'+receipt};}
  if(msg.type==='event'){events.push(msg.event);return {ok:true};}return {ok:true};
 });
 const sendText=async text=>{await A.write(doc.querySelector('textarea'),text);await controller.handle({type:'click',target:doc.querySelector('button'),isTrusted:true,preventDefault(){},stopImmediatePropagation(){}});};
 try{
  await new Promise(r=>setImmediate(r));
  await sendText('First synthetic prompt');
  doc.getElementById('thread').innerHTML='<li data-message-role="assistant">Je ne sais pas...</li>';
  await new Promise(r=>setTimeout(r,3000));
  assert.equal(events.filter(e=>e.kind==='response').length,0,'still waited out');
  await sendText('Second synthetic prompt');
  await new Promise(r=>setTimeout(r,500));
  const answers=events.filter(e=>e.kind==='response');
  assert.deepEqual(answers.map(e=>e.characters),[17]);
  assert.equal(sends.length,2);assert.equal(answers[0].correlation_id,sends[0],'linked to the send it answers');
 }finally{controller.dispose();dom.window.close();}
});

// --- 4. the notice page -------------------------------------------------------------------------
test('the notice page is reachable under the fixed id the declarative rule and webRequest name',async()=>{
 const manifest=JSON.parse(await readFile(new URL('./manifest.json',import.meta.url),'utf8'));
 const entry=manifest.web_accessible_resources.find(r=>r.resources.includes('blocked.html'));
 assert.equal(entry.use_dynamic_url,false);
 const rules=networkRules(policyFor({services:[{id:'chatgpt',enabled:true,mode:'block',domains:['chatgpt.com']}]}));
 assert.deepEqual(rules.find(r=>r.action.type==='redirect').action.redirect,{extensionPath:'/blocked.html?service=chatgpt.com'});
});
