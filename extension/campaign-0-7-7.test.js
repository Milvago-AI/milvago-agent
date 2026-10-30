// Real campaign 0.7.7 (2026-10-16), shared engine. Synthetic values in measured shapes.
//  - A page's own constants (`ask_retry_or_continue_rate_limit`) and flags (`beta-imagegen`) read as prose
//    sealed sends with nothing to compare.
//  - A file picked from disk reaches `webRequest` as a `{file:<path>}` element of a multipart body (measured
//    in an isolated Chrome, 2026-10-17): the upload was sealed although the file was approved.
//  - Tabs open on a service switched to `block` were reloaded and stayed blank: the page's service worker
//    answers a reload, so no `main_frame` request is redirected (reproduced in an isolated Chrome).
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {managedBridge} from './managed-fixture.js';
import './adapters.js';
import {wireFacts,headerModelScope} from './detection.js';
import {requestDecision,nameDigest} from './model-access.js';

const catalog=JSON.parse(await readFile(new URL('./detection-factory.json',import.meta.url),'utf8'));
const policyFor=(config,revision=1)=>({version:3,revision,expires_at:'2099-01-01T00:00:00Z',config:{services:[],collection:{enabled:false},model_access:[],...config}});
const masking=policyFor({privacy:{enabled:true}});
const enc=new TextEncoder();
const json=value=>({raw:[{bytes:enc.encode(JSON.stringify(value)).buffer}]});
const sealed=decision=>decision?.reason==='control_unavailable';
const passes=decision=>!decision||(decision.allow===true&&!decision.reason);
let serial=0;
function decide(url,requestBody,{approvals=[]}={}){
 const details={requestId:'d'+serial++,tabId:1,documentId:'document-1',url,method:'POST',type:'xmlhttprequest',initiator:new URL(url).origin,requestBody};
 return requestDecision(details,masking,wireFacts(details,catalog,new URL(url)),approvals,Date.now(),(id,u)=>headerModelScope(catalog,id,details,u));
}

test('a page constant or flag is not prose; a sensitive value inside one still is',()=>{
 const URL_='https://chatgpt.com/backend-api/f/conversation';
 const send=extra=>json({action:'next',messages:[{id:'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',author:{role:'user'},content:{content_type:'text',parts:[]}}],model:'gpt-6-thinking',...extra});
 assert.ok(passes(decide(URL_,send({supported:['ask_user_question','ask_retry_or_continue_rate_limit','delegate_workflow_execution']}))),'snake_case constants');
 assert.ok(passes(decide(URL_,send({features:['beta-code-interpreter','beta-imagegen','beta-websearch','agentic-harness']}))),'kebab-case flags');
 // Words joined by a run of `_` or by another connector are joined words all the same.
 for(const value of ['LE__CLIENT__DUPONT__DOIT__PAYER','le__client__dupont__doit__payer__la__somme__avant__lundi','Jean\uFF3FDupont\uFF3Fhabite\uFF3FParis','carte\u203F4970\u203F1012\u203F3456\u203F7894']){
  assert.ok(sealed(decide(URL_,send({note:value}))),JSON.stringify(value));
 }
 assert.ok(passes(decide(URL_,send({supported:['ask__user__question'],note:'__typename'}))),'a lower-case identifier with doubled underscores');
 for(const value of ['iban_FR7630006000011234567890189','carte_4970101234567894','mail_jean@example.com','dossier_numero_123456789','le_client_jean_dupont_habite_au_douze_rue_des_lilas','4970_1012_3456_7894','IBAN_FR76_3000_6000_0112_3456_7890_189',['Le','projet','Orion'],'Le projet Orion',['beta-flag','Jean','Paul','Marie']]){
  assert.ok(sealed(decide(URL_,send({note:value}))),JSON.stringify(value));
 }
});

test('a picked file from disk in a multipart upload passes on its own name, once',()=>{
 const URL_='https://chatgpt.com/backend-api/files',boundary='----WebKitFormBoundary7DQ0j8UL7q869Buw';
 const head=(name,type='text/plain')=>({bytes:enc.encode('--'+boundary+'\r\nContent-Disposition: form-data; name="file"; filename="'+name+'"\r\nContent-Type: '+type+'\r\n\r\n').buffer});
 const tail={bytes:enc.encode('\r\n--'+boundary+'--\r\n').buffer};
 const approval={kind:'file',name:nameDigest('notes.txt'),size:40};
 const body=(name,path)=>({raw:[head(name),{file:path},tail]});
 assert.ok(sealed(decide(URL_,body('notes.txt','C:\\Users\\synthetic\\notes.txt'))),'not picked');
 const ok=decide(URL_,body('notes.txt','C:\\Users\\synthetic\\notes.txt'),{approvals:[approval]});
 assert.equal(ok?.allow,true);assert.deepEqual(ok.consumed,[approval]);
 assert.ok(sealed(decide(URL_,body('notes.txt','/home/synthetic/other.txt'),{approvals:[approval]})),'another file under the approved name');
 assert.ok(sealed(decide(URL_,{raw:[head('notes.txt'),{file:42},tail]},{approvals:[approval]})),'a file element that is not a path');
 assert.ok(sealed(decide(URL_,{raw:[head('notes.txt"; filename*=UTF-8\'\'secret.txt'),{file:'C:\\Users\\synthetic\\notes.txt'},tail]},{approvals:[approval]})),'filename* names it otherwise');
 assert.ok(sealed(decide(URL_,{raw:[head('notes.txt'),{file:'C:\\notes.txt'},{bytes:new Uint8Array([0xff,0xfe]).buffer},tail]},{approvals:[approval]})),'bytes that are not text');
 // On a POSIX disk `\` belongs to the file name: `evil\notes.txt` is not the approved `notes.txt`.
 assert.ok(sealed(decide(URL_,body('notes.txt','/home/synthetic/evil\\notes.txt'),{approvals:[approval]})),'a POSIX name holding a backslash');
});

let worker=0;
async function background(first){
 let message,policy=first;const handlers={},stored={},noop={addListener(){}},updates=[],reloads=[];
 const bridge=managedBridge({
  browser_policy:()=>({online:true,policy}),
  browser_inspect:req=>({ok:true,action:'observe',text:req.text,labels:[]}),
  browser_submit:req=>({ok:true,action:'observe',text:req.text,recording_required:false}),
  browser_event:req=>({ok:true,id:crypto.randomUUID(),durable:true,delivery_id:req.delivery_id}),
  browser_catalog:()=>({catalog:null,revision:0,catalog_state:'missing'}),
  browser_health:req=>({accepted_health_ids:[req.batch.id]}),
 });
 const tabs=[{id:7,url:'https://chatgpt.com/c/6ad28e6f-fcd4-83e9-9b2f-15f89e6d9957'},{id:8,url:'https://claude.ai/new'},{id:9,url:'https://example.org/'}];
 globalThis.chrome={
  runtime:{onInstalled:noop,onStartup:noop,onMessage:{addListener(fn){message=fn;}},sendNativeMessage:bridge.sendNativeMessage,getURL:path=>'chrome-extension://synthetic'+path},
  storage:{managed:{async get(){return {milvago_pin:JSON.stringify(bridge.pin)};}},local:{async get(k){return {[k]:stored[k]};},async set(value){Object.assign(stored,value);}}},
  alarms:{create(){},onAlarm:noop},
  tabs:{async query(){return tabs;},async reload(id){reloads.push(id);},async update(id,change){updates.push([id,change.url]);},async sendMessage(){},onUpdated:noop},
  declarativeNetRequest:{async getDynamicRules(){return [];},async updateDynamicRules(){}},
  webRequest:Object.fromEntries(['onBeforeRequest','onBeforeSendHeaders','onCompleted','onErrorOccurred'].map(k=>[k,{addListener(fn){handlers[k]=fn;}}])),
 };
 await import('./background.js?campaign077shared='+worker++);
 const refresh=async next=>{if(next){policy=next;}assert.deepEqual(await new Promise(resolve=>message({type:'refresh'},{},resolve)),{ok:true});};
 await refresh();
 return {updates,reloads,refresh,close(){delete globalThis.chrome;}};
}

test('tabs open on a service switched to block or redirect are sent to the notice or the destination',async()=>{
 const services=(chatgpt,claude)=>[{id:'chatgpt',enabled:true,mode:chatgpt,domains:['chatgpt.com']},{id:'claude',enabled:true,mode:claude,domains:['claude.ai'],...(claude==='redirect'?{redirect_url:'https://example.com/ia'}:{})}];
 const state=await background(policyFor({services:services('observe','observe'),privacy:{enabled:true}}));
 try{
  state.updates.length=0;state.reloads.length=0;
  await state.refresh(policyFor({services:services('block','redirect'),privacy:{enabled:false}},2));
  assert.deepEqual(state.updates,[[7,'chrome-extension://synthetic/blocked.html?service=chatgpt.com'],[8,'https://example.com/ia']]);
  assert.deepEqual(state.reloads,[],'a held tab is not reloaded as well');
  state.updates.length=0;
  await state.refresh(policyFor({services:services('block','redirect'),privacy:{enabled:true}},3));
  assert.deepEqual(state.updates,[],'services unchanged: nothing moves');
 }finally{state.close();}
});

test('an answer is read without icon glyphs, a hidden label or a reasoning block',async()=>{
 const {JSDOM}=await import('jsdom');const A=globalThis.MilvagoAdapters;
 const at=(html,selector)=>A.answer(new JSDOM(html).window.document.querySelector(selector));
 // claude.ai's action bar draws its icons with private-use glyphs (U+E056…, measured 2026-10-17).
 const bar=['\uE056','\uE0E4','\uE0FB'].map(g=>'<button type="button" data-cds="Button"><span class="inline-flex"><span data-cds="Icon" aria-hidden="true">'+g+'</span></span></button>').join('');
 assert.equal(at('<div data-is-streaming="false"><div class="prose"><p dir="ltr">OK</p></div>'+bar+'</div>','[data-is-streaming]'),'OK');
 assert.equal(at('<div data-message-author-role="assistant"><h5 class="sr-only">ChatGPT a dit :</h5><p>Synthétique.</p></div>','[data-message-author-role]'),'Synthétique.');
 assert.equal(at('<div data-message-author-role="assistant"><div class="thinking-container"><button>Thinking for 4 s</button></div></div>','[data-message-author-role]'),'','a reasoning block alone is no answer');
 assert.equal(at('<div data-message-author-role="assistant"><p>Le code \uE000 reste.</p></div>','[data-message-author-role]'),'Le code  reste.','private-use glyphs only');
});

// A WebChannel batch route (synthetic catalogue rule in the measured shape): the session's terminate
// beacon and batch fields placed in the query.
test('a batch route: the empty terminate beacon passes on its headers, a batch field in the query is sealed',async()=>{
 const {sessionBeacon,beaconHeaders,emptyBeacon}=await import('./detection.js');
 const batchCatalog={providers:catalog.providers.map(p=>p.id!=='claude'?p:{...p,network:[...p.network,{method:'POST',host:'claude.ai',path:'/synthetic/v1/session',form_field:'___data__',body_format:'protobuf',text_path:'',text_paths:['2[*].9[*].1[*]'],model_path:'1[*].1[*].2[*]',effort_path:'',conversation_path:''}]}),native_tools:[],heuristics:catalog.heuristics};
 const URL_='https://claude.ai/synthetic/v1/session?VER=8&SID=synthetic&RID=9&TYPE=terminate&zx=synthetic';
 const details=(url,body,type='ping')=>({requestId:'t'+serial++,tabId:1,documentId:'document-1',url,method:'POST',type,initiator:'https://claude.ai',requestBody:body});
 const run=d=>requestDecision(d,masking,wireFacts(d,batchCatalog,new URL(d.url)),[],Date.now(),null);
 const beacon=details(URL_,{error:'Unknown error.'});
 assert.ok(passes(run(beacon)));assert.equal(sessionBeacon(beacon,batchCatalog),true);
 assert.equal(beaconHeaders([{name:'Content-Type',value:'text/plain;charset=UTF-8'}]),true);
 for(const headers of [[],[{name:'content-type',value:'text/plain;charset=utf-8'}],[{name:'Content-Type',value:'text/plain;charset=UTF-8'},{name:'Content-Type',value:'text/plain;charset=UTF-8'}],null]){assert.equal(beaconHeaders(headers),false,JSON.stringify(headers));}
 for(const [label,d] of [['not a beacon',details(URL_,{error:'Unknown error.'},'xmlhttprequest')],['not a terminate',details(URL_.replace('&TYPE=terminate',''),{error:'Unknown error.'})],['TYPE twice',details(URL_+'&TYPE=terminate',{error:'Unknown error.'})],['a field in the query',details(URL_+'&req0___data__=AA',{error:'Unknown error.'})]]){
  assert.equal(sessionBeacon(d,batchCatalog),false,label);assert.ok(sealed(run(d)),label);
 }
 assert.equal(emptyBeacon(details(URL_,{raw:[{bytes:enc.encode('count=0').buffer}]})),false,'a readable body is read as usual');
 assert.ok(sealed(run(details(URL_,{formData:{count:['1'],note:['Le projet Orion rachete la societe Exemple']}}))),'prose with a terminate');
 assert.ok(sealed(run(details(URL_.replace('&TYPE=terminate','&REQ7___DATA__=AA'),{formData:{count:['0']}},'xmlhttprequest'))),'batch field in the query, any case');
 // The body as well: a batch field in another case, or its name hidden in another field, is read or sealed.
 const short=Buffer.from([0x12,0x0c,0x4a,0x0a,0x0a,0x08,...Buffer.from('PRJ-1234')]).toString('base64');
 const SEND=URL_.replace('&TYPE=terminate','');
 assert.ok(passes(run(details(SEND,{formData:{count:['1'],ofs:['0'],req0___data__:[Buffer.from([0x08,0x01]).toString('base64')]}},'xmlhttprequest'))),'a batch without text');
 for(const key of ['REQ0___DATA__','req0___Data__','req0___data__x']){assert.ok(sealed(run(details(SEND,{formData:{count:['1'],ofs:['0'],[key]:[short]}},'xmlhttprequest'))),key);}
 assert.ok(sealed(run(details(SEND,{raw:[{bytes:enc.encode('count=1&ofs=0;req0___data__='+encodeURIComponent(short)).buffer}]},'xmlhttprequest'))),'its name inside another field');
});
