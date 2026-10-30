// Real campaign 0.7.4 (2026-10-16), shared engine. Bodies follow the shape of the requests measured on
// the real sites, with synthetic values only.
//  1. Signed-in ChatGPT posts the draft being typed to `/backend-api/f/conversation/prepare`
//     (`partial_query.content.parts`): under masking it must not leave in clear.
//  3. Signed-out ChatGPT, an image sent alone: a challenge token decoding to ASCII control
//     characters was read as prose and sealed the send.
//  4. Signed-in ChatGPT answers sit in `[data-markdown-text-style="assistant-message"]`.
//  5. claude.ai: an answer's relative time ("il y a 35 minutes") re-delivered it every minute, and
//     `GetNewConversationDefaults` (an empty protobuf body, `error` for webRequest) was sealed.
//  6. The notice page of a blocked service: see campaign-0-7-6.test.js (served under the fixed id again).
import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {JSDOM} from 'jsdom';
globalThis.browser={runtime:{id:'synthetic-extension',onMessage:{addListener(){},removeListener(){}}},storage:{local:{get:async()=>({}),set:async()=>{}}}};
await import('./adapters.js');await import('./capture.js');
const {wireFacts,headerModelScope}=await import('./detection.js');
const {requestDecision,textDigest,lineParts}=await import('./model-access.js');
const {factoryCatalog}=await import('./detection-factory.js');
const {networkRules}=await import('./policy.js');
const A=globalThis.MilvagoAdapters;

const policyFor=config=>({version:3,revision:7,expires_at:'2099-01-01T00:00:00Z',config:{services:[],model_access:[],collection:{enabled:false},...config}});
const masking=policyFor({privacy:{enabled:true}});
const keyword=policyFor({protection:{keywords:['orion'],exact:'block'}});
const open=policyFor({});
const raw=text=>({raw:[{bytes:new TextEncoder().encode(text).buffer}]});
const json=value=>raw(JSON.stringify(value));
let serial=0;
function decide(url,requestBody,{policy=masking,approvals,method='POST'}={}){
 const details={requestId:'r'+serial++,tabId:1,documentId:'document-1',url,method,type:'xmlhttprequest',initiator:new URL(url).origin,...(requestBody===undefined?{}:{requestBody})};
 const u=new URL(url);
 return requestDecision(details,policy,wireFacts(details,factoryCatalog,u),approvals,Date.now(),(id,uu)=>headerModelScope(factoryCatalog,id,details,uu));
}
const passes=decision=>!decision||(decision.allow===true&&!decision.reason);
const sealed=decision=>decision?.reason==='control_unavailable';
const send=text=>({kind:'send',text});

// --- 1. `/backend-api/f/conversation/prepare` ---------------------------------------------------
const PREPARE='https://chatgpt.com/backend-api/f/conversation/prepare';
const CONVERSATION='https://chatgpt.com/backend-api/f/conversation';
const DRAFT='Le projet Orion rachete la societe Exemple, IBAN FR7630006000011234567890189';
const prepare=(parts,extra={})=>({action:'next',fork_from_shared_post:false,parent_message_id:'client-created-root',model:'auto',client_prepare_state:'success',timezone_offset_min:-240,timezone:'Asia/Dubai',conversation_mode:{kind:'primary_assistant'},system_hints:[],partial_query:{id:'6aa99383-dd04-43ea-88fb-50a164a3820d',author:{role:'user'},content:{content_type:'text',parts}},supports_buffering:true,supported_encodings:['v1'],client_contextual_info:{app_name:'chatgpt.com'},...extra});
const conversation=parts=>({action:'next',messages:[{id:'6aa99383-dd04-43ea-88fb-50a164a3820d',author:{role:'user'},content:{content_type:'text',parts}}],parent_message_id:'client-created-root',model:'auto',timezone_offset_min:-240});

test('a draft posted to prepare is sealed quietly under masking or a blocking keyword',()=>{
 for(const policy of [masking,keyword]){
  const decision=decide(PREPARE,json(prepare([DRAFT])),{policy,approvals:[]});
  assert.ok(sealed(decision),'sealed');assert.equal(decision.quiet,true,'no notice, no event while typing');
 }
 for(const variant of ['https://chatgpt.com/backend-api/f/conversation/Prepare','https://chatgpt.com/backend-api/f/Conversation/prepare/','https://chatgpt.com/backend-api/f/conversation/%70repare','https://chatgpt.com/backend-api//f/conversation/prepare','https://chatgpt.com/backend-api/f/conversation/x/y']){
  assert.ok(sealed(decide(variant,json(prepare([DRAFT])),{approvals:[]})),variant);
 }
 assert.ok(sealed(decide(PREPARE,json(prepare([DRAFT])),{method:'PATCH',approvals:[]})),'any method with a body');
});

test('prepare passes with an empty draft, without content control, and on its headers alone',()=>{
 assert.ok(passes(decide(PREPARE,json(prepare([])),{approvals:[]})));
 assert.ok(passes(decide(PREPARE,json(prepare([''])),{approvals:[]})));
 assert.ok(passes(decide(PREPARE,json(prepare([DRAFT])),{policy:open,approvals:[]})));
 assert.ok(passes(decide(PREPARE,undefined,{approvals:[]})),'the header handler sees no body');
});

test('an approved draft passes prepare without spending the approval of the send',()=>{
 const approval=send(DRAFT);
 const early=decide(PREPARE,json(prepare([DRAFT])),{approvals:[approval]});
 assert.ok(passes(early));assert.equal(early.consumed,undefined);assert.notEqual(early.approved,true);
 const real=decide(CONVERSATION,json(conversation([DRAFT])),{approvals:[approval]});
 assert.equal(real.allow,true);assert.deepEqual(real.consumed,[approval]);
 assert.ok(sealed(decide(CONVERSATION,json(conversation([DRAFT])),{approvals:[]})),'the send still needs its approval');
});

test('prepare is sealed for text elsewhere, an unreadable body or a body too large to read',()=>{
 const approval=send('Bonjour');
 for(const [label,body] of [
  ['an unapproved draft beside an approved one',json(prepare(['Bonjour',DRAFT]))],
  ['prose outside the parts',json(prepare(['Bonjour'],{metadata:{note:DRAFT}}))],
  ['the draft in base64 elsewhere',json(prepare(['Bonjour'],{blob:Buffer.from(DRAFT).toString('base64')}))],
  ['the draft as a part object',json(prepare([{text:DRAFT}]))],
  ['a body that is not JSON',raw(DRAFT)],
  ['a JSON string',json(DRAFT)],
  ['duplicate keys',raw('{"partial_query":{"content":{"parts":["Bonjour"]}},"partial_query":{"content":{"parts":["'+DRAFT+'"]}}}')],
  ['a body over 128 KiB',json(prepare([('Bonjour '+DRAFT+' ').repeat(2000)]))],
  ['a body too deep to walk',raw('['.repeat(39)+JSON.stringify(prepare([DRAFT]))+']'.repeat(39))],
  ['a Blob body',{error:'Unknown error.'}],
  ['a compressed body',{raw:[{bytes:Uint8Array.from([0x1f,0x8b,8,0,0,0,0,0]).buffer}]}],
 ]){assert.ok(sealed(decide(PREPARE,body,{approvals:[approval]})),label);}
});

test('a draft in another call of the send directory is sealed with a notice; spellings do not step around it',()=>{
 for(const url of ['https://chatgpt.com/backend-api/f/other','https://chatgpt.com/backend-api/f/conversation;prepare','https://chatgpt.com/backend-api/f/conversation/prepare?x=1','https://chatgpt.com/backend-api/f/conversation/prepare#x']){
  const decision=decide(url,json(prepare([DRAFT])),{approvals:[]});
  assert.ok(sealed(decision),url);
 }
 const loud=decide('https://chatgpt.com/backend-api/f/other',json(prepare([DRAFT])),{approvals:[]});
 assert.notEqual(loud.quiet,true,'an unmeasured call fails visibly');
 assert.ok(passes(decide('https://chatgpt.com/backend-api/f/other',json({action:'x',ids:['6aa99383-dd04-43ea-88fb-50a164a3820d']}),{approvals:[]})),'a call without text passes');
 assert.ok(passes(decide('https://chatgpt.com/backend-api/f/other',json(prepare([DRAFT])),{approvals:[send(DRAFT)]})),'approved text passes');
});

// --- send approvals cover line-aligned parts of the inspected text ---------------------------------
test('a send approval covers a line-aligned part of the text it approved, nothing else',()=>{
 const inspected='Apercu d un texte colle\n  Reponds juste OK';
 assert.ok(passes(decide(CONVERSATION,json(conversation([' Reponds juste OK'])),{approvals:[send(inspected)]})));
 assert.ok(passes(decide(CONVERSATION,json(conversation(['Apercu d un texte colle'])),{approvals:[send(inspected)]})));
 for(const text of ['Reponds juste','juste OK','Apercu d un texte colle\nReponds juste OK et '+DRAFT,DRAFT,'colle\n  Reponds']){
  assert.ok(sealed(decide(CONVERSATION,json(conversation([text])),{approvals:[send(inspected)]})),text);
 }
 // The worker keeps fingerprints only: the parts travel the same way.
 const stored={kind:'send',digest:textDigest(inspected),bytes:new TextEncoder().encode(inspected).length,parts:lineParts(inspected)};
 assert.ok(passes(decide(CONVERSATION,json(conversation(['Reponds juste OK'])),{approvals:[stored]})));
 assert.ok(sealed(decide(CONVERSATION,json(conversation(['Reponds juste OK'])),{approvals:[{...stored,parts:['not-a-digest']}]})));
 assert.ok(sealed(decide(CONVERSATION,json(conversation(['Reponds juste OK'])),{approvals:[{...stored,kind:'paste'}]})),'a paste approval has no parts');
});

test('line parts are bounded and leave out blank lines',()=>{
 const many=Array.from({length:500},(_,i)=>'ligne '+i).join('\n');
 assert.ok(lineParts(many).length<=32);
 assert.deepEqual(lineParts('une seule ligne'),[]);
 assert.deepEqual(lineParts('\n\n  \n'),[]);
});

// --- 3. base64 values that decode to control characters ------------------------------------------
const UNAUTH='https://chatgpt.com/unauth-mweb/conversation/updates';
// Synthetic challenge token: ASCII bytes, a third of them control characters, an `@` and a form feed among them.
const challenge=Buffer.from(Array.from({length:1050},(_,i)=>i%3===0?(i*7)%26+1:i===500?64:i===800?12:0x41+(i*13)%58).map(b=>b===0x5c?0x5d:b)).toString('base64');
const proof='gAAAAAB'+Buffer.from(JSON.stringify([2774,'Fri Oct 16 2026 20:46:38 GMT+0400 (heure normale)',null,47,'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:158.0) Gecko/20100101 Firefox/158.0'])).toString('base64')+'~S';
const imageForm=extra=>({formData:{conversationState:[JSON.stringify({messages:[],parentMessageId:'client-created-root',userMessageCount:0})],messageMetadata:['{}'],imageAttachments:[JSON.stringify([{fileId:'file-0123456789abcdef0123',height:32,mimeType:'image/png',name:'carre-bleu.png',size:99,width:32}])],prompt:[''],timezone:['Asia/Dubai'],chatRequirementsToken:['gAAAAABq0lTv-Bk397gPGrNp8zLKYbgQPzUhcfjT_TORb'],proofToken:[proof],turnstileToken:[challenge],...extra}});

test('an image sent alone passes beside a challenge token that decodes to control characters',()=>{
 assert.ok(passes(decide(UNAUTH,imageForm({}),{approvals:[]})));
 assert.ok(passes(decide(UNAUTH,imageForm({proofToken:[proof.slice(0,-2)]}),{approvals:[]})),'the proof token without its suffix');
});

test('text hidden in base64 keeps the image send sealed, controls and all',()=>{
 const b64=text=>Buffer.from(text).toString('base64');
 for(const [label,value] of [
  ['a sentence',b64(DRAFT)],
  ['a sentence split by a form feed',b64(DRAFT.replaceAll(' ','\f'))],
  ['a sentence with a few controls',b64(DRAFT.replaceAll(' Exemple',' \x01Exemple'))],
  ['an e-mail with a control',b64('jean.exemple@example.com\x02')],
  ['base64url of an IBAN',Buffer.from('FR7630006000011234567890189').toString('base64url')],
  ['double base64',b64(b64(DRAFT))],
  // Adversarial review: half the bytes of UTF-16 are zero, which the control threshold dropped.
  ['UTF-16LE',Buffer.from(DRAFT,'utf16le').toString('base64')],
  ['UTF-16BE',Buffer.from(DRAFT,'utf16le').swap16().toString('base64')],
 ]){assert.ok(sealed(decide(UNAUTH,imageForm({turnstileToken:[value]}),{approvals:[]})),label);}
});

// --- adversarial review of the fixes above ----------------------------------------------------------
test('a form field under a key no path can name is still read by the guard',()=>{
 for(const key of ['partial_query[content][parts][]','messages.0.content','__proto__']){
  const body={formData:{[key]:[DRAFT]}};
  assert.ok(sealed(decide(PREPARE,body,{approvals:[]})),'prepare '+key);
  assert.ok(sealed(decide(CONVERSATION,body,{approvals:[]})),'send '+key);
  assert.ok(sealed(decide(UNAUTH,imageForm({[key]:[DRAFT]}),{approvals:[]})),'signed-out send '+key);
 }
 assert.ok(passes(decide(UNAUTH,imageForm({'meta[app]':['chatgpt.com']}),{approvals:[]})),'a form key without text passes');
});

test('the prose check stays linear on a long run of letters',()=>{
 // 128 KiB of hex took 24 s in the blocking handler while `\p{L}{2,}\s+` backtracked.
 const started=Date.now();
 decide(CONVERSATION,json({...conversation([]),blob:'0123456789abcdef'.repeat(7800)}),{approvals:[]});
 decide(PREPARE,json(prepare([],{blob:'a'.repeat(120000)})),{approvals:[]});
 assert.ok(Date.now()-started<2000,Date.now()-started+' ms');
});

// --- 5b. claude.ai sibling RPC with an empty body ---------------------------------------------------
const RPC='https://claude.ai/claudeai-rpc/anthropic.bard.api.v1alpha.ConversationService/';
test('a protobuf read RPC whose body webRequest cannot give passes, a send stays sealed',()=>{
 const empty={error:'Unknown error.'};
 assert.ok(passes(decide(RPC+'GetNewConversationDefaults',empty,{approvals:[]})));
 assert.ok(passes(decide(RPC+'ListConversationThings',empty,{approvals:[]})));
 assert.ok(passes(decide(RPC+'GetNewConversationDefaults',{raw:[{bytes:new ArrayBuffer(0)}]},{approvals:[]})),'an empty body read as bytes');
 for(const rpc of ['PerformAction','StreamTimeline','getNewConversationDefaults','Get','GetNewConversationDefaults/','Getter','GetX%2FPerformAction']){
  assert.ok(sealed(decide(RPC+rpc,empty,{approvals:[]})),rpc);
 }
 assert.ok(sealed(decide(RPC+'GetNewConversationDefaults',{raw:[{bytes:Uint8Array.from([0x7b,0x7d,0x00]).buffer}]},{approvals:[]})),'a body that is not protobuf');
});

// --- 4 and 5a. answers ----------------------------------------------------------------------------
test('an answer is read without the relative time it shows',()=>{
 const dom=new JSDOM('<div id="a"><h2>Claude a répondu : OK</h2><div><p>Réponse synthétique</p></div><div role="toolbar"><button>Copier</button><time datetime="2026-10-16T16:21:31Z">il y a 35 minutes</time></div></div>');
 const node=dom.window.document.getElementById('a'),time=node.querySelector('time');
 const first=A.answer(node);assert.doesNotMatch(first,/minutes/);assert.match(first,/Réponse synthétique/);
 for(const label of ['maintenant','il y a 1 min','now','35 minutes ago','hace 35 minutos','ahora','há 35 minutos','agora','Réponse synthétique']){time.textContent=label;assert.equal(A.answer(node),first,label);}
 const plain=new JSDOM('<div id="a"><p>Sans heure</p></div>').window.document.getElementById('a');
 assert.equal(A.answer(plain),'Sans heure');
});

test('signed-in ChatGPT answers are captured, once, through the catalogue and the adapters',async()=>{
 const factory=JSON.parse(await readFile(new URL('./detection-factory.json',import.meta.url)));
 assert.match(factory.providers.find(p=>p.id==='chatgpt').dom.response,/^\[data-markdown-text-style="assistant-message"\],\[data-message-author-role="assistant"\]/);
 for(const catalog of [null,factory]){
  A.applyCatalog(catalog);
  const dom=new JSDOM('<form><textarea id="mobile-composer-prompt"></textarea><button type="submit">Send</button></form><section id="thread"></section>',{url:'https://chatgpt.com/'}),doc=dom.window.document;
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
   doc.getElementById('thread').innerHTML='<div data-markdown-text-style="assistant-message"><p>Synthetic answer</p><time>maintenant</time></div>';
   await new Promise(r=>setTimeout(r,3000));
   doc.querySelector('time').textContent='il y a 1 min';
   await new Promise(r=>setTimeout(r,3000));
   assert.equal(events.filter(e=>e.kind==='response').length,1,catalog?'catalogue':'adapters');
  }finally{controller.dispose();dom.window.close();}
 }
 A.applyCatalog(null);
});
