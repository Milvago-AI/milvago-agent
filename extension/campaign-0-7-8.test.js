// Real campaign 0.7.8 (2026-10-17), shared engine. Structures measured on the real pages, values synthetic.
//  - Signed-out ChatGPT labels each answer with an `h4` "ChatGPT a dit :" hidden by atomic classes (no
//    `.sr-only`): the label was captured with the answer, and alone as a partial answer.
//  - A WebChannel session's terminate beacon produced an empty prompt; Firefox names its type `beacon` and
//    gives its empty body as `{raw:[]}` (measured in Firefox 158 with a probe add-on).
//  - A follow-up message naming no model was recorded without the model its conversation named.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import './adapters.js';
import {wireFacts,observeRequest,emptyBeacon,sessionBeacon,beaconHeaders} from './detection.js';
import {requestDecision} from './model-access.js';
import {detectionRuntime} from './detection-runtime.js';
import {pinAuthority} from './broker.js';

const catalog=JSON.parse(await readFile(new URL('./detection-factory.json',import.meta.url),'utf8'));
const masking={version:3,revision:1,expires_at:'2099-01-01T00:00:00Z',config:{services:[],collection:{enabled:false},model_access:[],privacy:{enabled:true}}};
const enc=new TextEncoder();
const sealed=decision=>decision?.reason==='control_unavailable';
const passes=decision=>!decision||(decision.allow===true&&!decision.reason);
let serial=0;

// The label's classes and their rules, as served by chatgpt.com to a signed-out visitor (2026-10-17).
const STYLEX='<style>.x1717udv{padding:0}.xu82sp8{border-width:0}.xb3r6kr{overflow:hidden}.x1hyvwdk{clip-path:inset(50%)}.x10l6tqk{position:absolute}.xuxw1ft{white-space:nowrap}.xjm9jq1{height:1px}.x1i1rx1s{width:1px}</style>';
const LABEL='<h4 class="xjm9jq1 xu82sp8 x1hyvwdk x1i1rx1s xb3r6kr x1717udv x10l6tqk xuxw1ft">ChatGPT a dit&nbsp;:</h4>';
const message=content=>STYLEX+'<ul><li class="x10ukxgv xrvj5dj" data-message-role="assistant">'+LABEL+'<div class="xjbqb8w xbs2zpe"><div data-assistant-markdown="">'+content+'</div></div></li></ul>';

test('a heading hidden from view is no answer, whatever its classes; a visible one is',async()=>{
 const {JSDOM}=await import('jsdom');const A=globalThis.MilvagoAdapters;
 const at=html=>A.answer(new JSDOM(html).window.document.querySelector('li[data-message-role="assistant"]'));
 assert.equal(at(message('<p>Bleu</p>')),'Bleu');
 assert.equal(at(message('')),'','the label alone is no answer: nothing is recorded before the answer');
 assert.equal(at(message('<h4>ChatGPT a dit :</h4><p>Bleu</p>')),'ChatGPT a dit :Bleu','a visible heading is part of the answer');
 for(const hidden of ['clip:rect(0px,0px,0px,0px)','clip:rect(0,0,0,0)','position:absolute;width:1px;height:1px']){
  assert.equal(at('<ul><li data-message-role="assistant"><h6 style="'+hidden+'">Said:</h6><p>Bleu</p></li></ul>'),'Bleu',hidden);
 }
 assert.equal(at('<ul><li data-message-role="assistant"><h6 style="position:absolute;width:2px;height:1px">Said:</h6><p>Bleu</p></li></ul>'),'Said:Bleu','2 px wide is drawn');
 // Hiding the answer itself in such a heading only loses its capture: it is not what any control reads.
 assert.equal(at(STYLEX+'<ul><li data-message-role="assistant">'+LABEL.replace('ChatGPT a dit&nbsp;:','Bleu')+'</li></ul>'),'');
});

// A WebChannel batch route (synthetic catalogue rule in the measured shape), as in campaign-0-7-7.test.js.
const batchCatalog={providers:catalog.providers.map(p=>p.id!=='claude'?p:{...p,network:[...p.network,{method:'POST',host:'claude.ai',path:'/synthetic/v1/session',form_field:'___data__',body_format:'protobuf',text_path:'',text_paths:['2[*].9[*].1[*]'],model_path:'1[*].1[*].2[*]',effort_path:'',conversation_path:''}]}),native_tools:[],heuristics:catalog.heuristics};
const URL_='https://claude.ai/synthetic/v1/session?VER=8&SID=synthetic&RID=9&TYPE=terminate&zx=synthetic';
const details=(body,type,url=URL_)=>({requestId:'t'+serial++,tabId:1,documentId:'document-1',url,method:'POST',type,initiator:'https://claude.ai',requestBody:body});
const CHROME={error:'Unknown error.'},FIREFOX={raw:[],lenientFormData:null};

test('the terminate beacon, as Chrome and as Firefox give it, passes on its headers and makes no prompt',async()=>{
 for(const [label,d] of [['chrome',details(CHROME,'ping')],['firefox',details(FIREFOX,'beacon')]]){
  assert.equal(emptyBeacon(d),true,label);assert.equal(sessionBeacon(d,batchCatalog),true,label);
  assert.ok(passes(requestDecision(d,masking,wireFacts(d,batchCatalog,new URL(d.url)),[],Date.now(),null)),label);
  assert.equal(await observeRequest(d,batchCatalog,true),null,label+': no prompt');
 }
 // Only the string's header: Firefox lower-cases a Blob's type as Chrome does (measured), a Blob of text
 // arrives with its bytes, a FormData or URLSearchParams as `formData`.
 assert.equal(beaconHeaders([{name:'Content-Type',value:'text/plain;charset=UTF-8'}]),true);
 assert.equal(beaconHeaders([{name:'Content-Type',value:'text/plain;charset=utf-8'}]),false,'an empty Blob');
 const prose=enc.encode('Le projet Orion rachete la societe Exemple').buffer;
 for(const [label,body,type] of [['firefox blob of text',{raw:[{bytes:prose}],lenientFormData:null},'beacon'],['firefox form',{formData:{a:['Le projet Orion rachete la societe Exemple']}},'beacon'],['error beside bytes',{error:'x',raw:[{bytes:prose}]},'ping'],['raw beside a form',{raw:[],formData:{a:['x']}},'beacon'],['no body',undefined,'beacon'],['fetch',FIREFOX,'xmlhttprequest'],['other type',FIREFOX,'other']]){
  assert.equal(emptyBeacon(details(body,type)),false,label);
 }
 const d=details({raw:[{bytes:prose}],lenientFormData:null},'beacon');
 assert.ok(sealed(requestDecision(d,masking,wireFacts(d,batchCatalog,new URL(d.url)),[],Date.now(),null)),'prose in a Firefox beacon is read and sealed');
 assert.equal(emptyBeacon(details(FIREFOX,'beacon',URL_.replace('TYPE=terminate','TYPE=xmlhttp'))),false,'not a terminate');
});

// Adversarial review: a variant of the route passed its empty beacon on the body alone, so a Chrome Blob of
// any content (`{error}` as well) rode on it without the header check that refuses a Blob's type.
test('a beacon on a variant of the batch route has its headers checked like the route',()=>{
 for(const path of ['/synthetic/v1/session/','/Synthetic/v1/Session','/synthetic/v1/other']){
  const d=details(CHROME,'ping',URL_.replace('/synthetic/v1/session',path));
  assert.ok(passes(requestDecision(d,masking,wireFacts(d,batchCatalog,new URL(d.url)),[],Date.now(),null)),path+': passes on its body');
  assert.equal(sessionBeacon(d,batchCatalog),true,path+': so its headers are checked');
 }
 assert.equal(sessionBeacon(details(CHROME,'ping','https://claude.ai/elsewhere?TYPE=terminate'),batchCatalog),false,'not a route');
});

// --- A follow-up message without its model ------------------------------------------------------------
const pin={installation:'00000000-0000-4000-8000-000000000021',edition:'community',origin:'https://instance.example.invalid',organization_anchor:'synthetic-anchor',signing_key:'synthetic-key'};
const authority=await pinAuthority(pin);
const policy={revision:1,expires_at:'2099-01-01T00:00:00Z',config:{collection:{enabled:true},discovery:{enabled:false},services:[{enabled:true,domains:['ai.example.invalid']}]}};
const synthetic={providers:[{id:'synthetic',label:'Synthetic',domains:['ai.example.invalid'],aliases:[],network:[{host:'ai.example.invalid',path:'/v1/chat',method:'POST',text_path:'prompt',model_path:'model',effort_path:'effort',conversation_path:'conversation_id'}]}]};
function fixture(){
 const listeners={},calls=[],storage={};
 globalThis.MilvagoAdapters.applyCatalog=()=>{};
 const resolve=globalThis.MilvagoAdapters.resolve;globalThis.MilvagoAdapters.resolve=()=>({id:'synthetic'});
 const api={
  runtime:{getManifest:()=>({version:'0.7.8',content_scripts:[]})},
  storage:{managed:{async get(){return {milvago_pin:JSON.stringify(pin)};}},local:{async get(){return structuredClone(storage);},async set(value){Object.assign(storage,structuredClone(value));}}},
  tabs:{async sendMessage(){return {ok:true,delivery_id:null,authority};}},
  webRequest:{onBeforeRequest:{addListener(l){listeners.before=l;}},onHeadersReceived:{addListener(l){listeners.headers=l;}},onErrorOccurred:{addListener(l){listeners.error=l;}}},
 };
 const bridge=async request=>{
  calls.push(structuredClone(request));
  if(request.op==='catalog'){return {revision:1,catalog_state:'ok',catalog:synthetic,expires_at:'2099-01-01T00:00:00Z'};}
  if(request.op==='event_v2'){return {ok:true,durable:true,delivery_id:request.delivery_id,id:'00000000-0000-4000-8000-000000000022'};}
  if(request.op==='event_receipt'){return {ok:true,durable:false,delivery_id:request.delivery_id};}
  if(request.op==='detector_health'){return {accepted_health_ids:[request.batch.id]};}
  throw new Error('unexpected bridge operation '+request.op);
 };
 return {runtime:detectionRuntime(api,bridge,'firefox',()=>policy),listeners,calls,restore(){globalThis.MilvagoAdapters.resolve=resolve;}};
}
const prompts=f=>f.calls.filter(c=>c.op==='event_v2'&&c.event.kind==='prompt').map(c=>c.event);
async function send(f,body,id){
 const before=prompts(f).length;
 f.listeners.before({requestId:id,tabId:7,documentId:'document-a',frameId:0,method:'POST',url:'https://ai.example.invalid/v1/chat',requestBody:{raw:[{bytes:enc.encode(JSON.stringify(body)).buffer}]}});
 f.listeners.headers({requestId:id,statusCode:200,responseHeaders:[{name:'content-type',value:'application/json'}]});
 for(let n=0;n<400&&prompts(f).length===before;n++){await new Promise(resolve=>setTimeout(resolve,20));}
 return prompts(f).at(-1);
}

test('a follow-up message takes the model its own conversation named, never another one',{timeout:60000},async()=>{
 const f=fixture();
 try{
  await f.runtime.refresh();
  assert.equal((await send(f,{prompt:'first',model:'fixture-model-4',effort:'high',conversation_id:'thread-1'},'r1')).model,'fixture-model-4');
  const next=await send(f,{prompt:'second',conversation_id:'thread-1'},'r2');
  assert.equal(next.model,'fixture-model-4');assert.equal(next.effort,'high');
  assert.equal((await send(f,{prompt:'elsewhere',conversation_id:'thread-2'},'r3')).model,undefined,'another conversation');
  assert.equal((await send(f,{prompt:'and its follow-up',conversation_id:'thread-2'},'r3b')).model,undefined,'nor its follow-up');
  assert.equal((await send(f,{prompt:'again',model:'fixture-model-5',conversation_id:'thread-1'},'r4')).model,'fixture-model-5','a named model wins');
  // No conversation named: only a model named just before, by the same exchange (a session opening).
  assert.equal((await send(f,{prompt:'unnamed'},'r5')).model,'fixture-model-5');
  const now=Date.now;Date.now=()=>now()+61000;
  try{assert.equal((await send(f,{prompt:'later'},'r6')).model,undefined,'stale');}finally{Date.now=now;}
 }finally{f.restore();}
});
