// A rule can read its prompt from one JSON form field and its model from a JSON request
// header, mapped to a canonical name. Gemini needs both (measured on 2026-10-15): the
// prompt travels in `f.req=<json>`, the model as an opaque id in a `x-goog-ext-*-jspb`
// header. Synthetic hosts and values only.
import test from 'node:test';
import assert from 'node:assert/strict';
import {pinAuthority} from './broker.js';
import {observeRequest,decodeFormField,headerJSON,canonicalModel,unwrapFields,wireFacts,fingerprint,BODY_LIMIT,HEADER_LIMIT} from './detection.js';
import {detectionRuntime} from './detection-runtime.js';

const HEADER='x-synthetic-ext-jspb';
const rule={method:'POST',host:'ai.example.invalid',path:'/*_/rpc/Generate',form_field:'f.req',json_fields:['1'],text_path:'1.0.0',model_header:HEADER,model_path:'4',model_map:{'0123456789abcdef':'synthetic-fast','fedcba9876543210':'synthetic-deep'}};
const catalog={providers:[{id:'synthetic',label:'Synthetic',domains:['ai.example.invalid'],aliases:[],network:[rule]}]};
const freq=(prompt='bonjour')=>JSON.stringify([null,JSON.stringify([[prompt,0,null,null,null,null,0],['fr'],null,'synthetic-token'])]);
const modelHeader=(id='0123456789abcdef')=>({name:HEADER,value:JSON.stringify([1,null,null,null,id,null,null,0,[4,6],null])});
const request=(requestBody={formData:{'f.req':[freq()],at:['synthetic-at']}},url='https://ai.example.invalid/_/rpc/Generate?rt=c')=>({requestId:'r1',tabId:7,documentId:'document-a',frameId:0,method:'POST',url,requestBody});
const raw=text=>({raw:[{bytes:new TextEncoder().encode(text).buffer}]});

test('the form field becomes the body, from formData or from raw bytes',()=>{
 assert.deepEqual(decodeFormField(request(),'f.req').body,JSON.parse(freq()));
 assert.equal(decodeFormField(request(),'f.req').body_bytes,null,'Chrome hands decoded fields, not the transmitted bytes');
 const encoded='f.req='+encodeURIComponent(freq())+'&at=synthetic-at';
 const fromRaw=decodeFormField(request(raw(encoded)),'f.req');
 assert.deepEqual(fromRaw.body,JSON.parse(freq()));
 assert.equal(fromRaw.body_bytes,encoded.length);
});

test('a form field that is absent, repeated, unreadable or hostile yields nothing',()=>{
 const none=details=>decodeFormField(details,'f.req').body;
 assert.equal(none(request({formData:{}})),null);
 assert.equal(none(request({formData:{'f.req':[freq(),freq()]}})),null,'two values are ambiguous');
 assert.equal(none(request({formData:{'f.req':['not json']}})),null);
 assert.equal(none(request({formData:{'f.req':[{image:new Uint8Array(8)}]}})),null,'a binary value in a text field');
 assert.equal(none(request({formData:{'f.req':'['+'1,'.repeat(10)+'1]'}})),null,'a value that is not a list');
 assert.equal(none(request({formData:{'f.req':['"'+'x'.repeat(BODY_LIMIT)+'"']}})),null,'oversized');
 assert.equal(none(request({formData:{'f.req':['['.repeat(5000)+']'.repeat(5000)]}})),null,'nested beyond the parser bound');
 assert.equal(none(request({formData:{'f.req':['{"a":1,"a":2}']}})),null,'duplicate keys are refused as everywhere else');
 assert.equal(none(request({error:'unreadable',formData:{'f.req':[freq()]}})),null);
 assert.equal(none(request({formData:[['f.req',freq()]]})),null);
 assert.equal(none(request(null)),null);
 assert.equal(none(request({raw:[{file:'C:/synthetic.bin'}]})),null);
 assert.equal(none(request({raw:[{bytes:new Uint8Array([0x1f,0x8b,8,0]).buffer}]})),null,'compressed bytes are not read here');
 assert.equal(none(request({raw:[{bytes:new Uint8Array([0x66,0xff,0xfe]).buffer}]})),null,'invalid UTF-8');
 assert.equal(none(request({raw:[null]})),null);
 for(const field of ['__proto__','constructor','f req','',7,null,'x'.repeat(65)]){
  assert.deepEqual(decodeFormField(request({formData:{[String(field)]:[freq()]}}),field),{body:null,body_bytes:null},String(field));
 }
 // A field inherited from the prototype is not a field of the form.
 assert.equal(decodeFormField(request({formData:Object.create({'f.req':[freq()]})}),'f.req').body,null);
});

test('an array root is unwrapped by position, and only where the rule says so',()=>{
 const body=JSON.parse(freq());
 assert.equal(typeof unwrapFields(body,[])[1],'string');
 const out=unwrapFields(body,['1']);
 assert.equal(out[0],null);assert.equal(out[1][0][0],'bonjour');
 assert.equal(typeof body[1],'string','the decoded body itself is not mutated');
 assert.ok(Array.isArray(unwrapFields(body,['__proto__'])));
 assert.equal([].polluted,undefined);
 assert.deepEqual(unwrapFields(['{"a":'],['0']),['{"a":'],'a field that is not JSON stays the string it is');
});

test('a header holding JSON is read once, case-insensitively, within bounds',()=>{
 assert.deepEqual(headerJSON([{name:'X-Synthetic-Ext-JSPB',value:'[1,2]'}],HEADER),[1,2]);
 assert.equal(headerJSON([modelHeader(),modelHeader()],HEADER),undefined,'a repeated header is ambiguous');
 assert.equal(headerJSON([{name:HEADER,value:'[1,'}],HEADER),undefined);
 assert.equal(headerJSON([{name:HEADER,value:'['+'0,'.repeat(HEADER_LIMIT)+'0]'}],HEADER),undefined);
 assert.equal(headerJSON([{name:HEADER,binaryValue:[91,93]}],HEADER),undefined);
 assert.equal(headerJSON([{name:HEADER,value:{toString:()=>'[1]'}}],HEADER),undefined);
 assert.equal(headerJSON([null,7,'x',{name:5}],HEADER),undefined);
 assert.equal(headerJSON(null,HEADER),undefined);
 assert.equal(headerJSON('[1]',HEADER),undefined);
 assert.equal(headerJSON([modelHeader()],'X-Upper'),undefined,'rule names are lower case');
 assert.equal(headerJSON([modelHeader()],'__proto__'),undefined);
});

test('a mapped id is named, an unknown one stays visible under its provider',()=>{
 assert.equal(canonicalModel('0123456789abcdef',rule,'synthetic'),'synthetic-fast');
 assert.equal(canonicalModel('aaaaaaaaaaaaaaaa',rule,'synthetic'),'synthetic:aaaaaaaaaaaaaaaa');
 assert.equal(canonicalModel('a'.repeat(65),rule,'synthetic'),undefined,'the fallback stays bounded');
 assert.equal(canonicalModel('model-x',{},'synthetic'),'model-x','no map: the request names the model itself');
 assert.equal(canonicalModel('model x',{},'synthetic'),undefined);
 assert.equal(canonicalModel(42,rule,'synthetic'),undefined);
 assert.equal(canonicalModel('toString',rule,'synthetic'),'synthetic:toString','an inherited name is not an entry');
 assert.equal(canonicalModel('__proto__',{model_map:JSON.parse('{"__proto__":"x"}')},'synthetic'),'x');
 assert.equal(canonicalModel('k',{model_map:{k:'bad:value'}},'synthetic'),undefined,'a mapped name never takes the fallback form');
 assert.equal(canonicalModel('k',{model_map:{k:7}},'synthetic'),undefined);
 assert.equal(canonicalModel('k',{model_map:['k']},'synthetic'),'k');
 assert.equal(canonicalModel('k',rule,'Bad Provider'),undefined);
});

test('the request yields its prompt and the header its model',async()=>{
 const hit=await observeRequest(request(),catalog,true,Promise.resolve([{name:'Content-Type',value:'application/x-www-form-urlencoded'},modelHeader()]));
 assert.equal(hit.provider.id,'synthetic');
 assert.equal(hit.characters,7);assert.equal(hit.characters_known,true);
 assert.equal(hit.fingerprint,await fingerprint('bonjour'),'the DOM capture pairs on the same digest');
 assert.equal(hit.model,'synthetic-fast');
 assert.equal((await observeRequest(request(),catalog,true,[modelHeader('fedcba9876543210')])).model,'synthetic-deep');
 assert.equal((await observeRequest(request(),catalog,true,[modelHeader('1111222233334444')])).model,'synthetic:1111222233334444');
 assert.equal((await observeRequest(request(),catalog,false,[modelHeader()])).model,undefined,'model observation off reads no header');
 // Path variant with an account prefix, and a route that is not the send.
 assert.ok(await observeRequest(request(undefined,'https://ai.example.invalid/u/1/_/rpc/Generate'),catalog,true,[]));
 assert.equal(await observeRequest(request(undefined,'https://ai.example.invalid/_/rpc/Other'),catalog,true,[]),null);
});

test('a missing, hostile or failed header keeps the prompt and drops only the model',async()=>{
 for(const headers of [()=>null,()=>[],()=>Promise.resolve(null),()=>Promise.reject(new Error('gone')),()=>[{name:HEADER,value:'[1,null,null,null,{"id":"x"}]'}],()=>[{name:HEADER,value:'[1,null,null,null,"has space"]'}],()=>[{name:HEADER,value:'[1,null,null,null,1234567890]'}]]){
  const hit=await observeRequest(request(),catalog,true,headers());
  assert.equal(hit.characters,7);assert.equal(hit.model,undefined);
 }
 // A body that cannot be read is still a request of the route, with nothing known.
 const blind=await observeRequest(request({formData:{'f.req':['[']}}),catalog,true,[modelHeader()]);
 assert.equal(blind.characters_known,false);assert.equal(blind.model,'synthetic-fast');
 // A rule without a header keeps reading its model from the body.
 const json={providers:[{id:'synthetic',domains:['ai.example.invalid'],network:[{method:'POST',host:'ai.example.invalid',path:'/v1/chat',text_path:'prompt',model_path:'model',model_map:{'opaque-1':'synthetic-fast'}}]}]};
 const hit=await observeRequest({method:'POST',url:'https://ai.example.invalid/v1/chat',requestBody:raw(JSON.stringify({prompt:'x',model:'opaque-1'}))},json,true);
 assert.equal(hit.model,'synthetic-fast');
});

test('the blocking guard treats a form-field route as it did before the rule existed',()=>{
 const details=request();
 const facts=wireFacts(details,catalog,new URL(details.url));
 assert.equal(facts.route,false);assert.deepEqual(facts.texts,[]);
 const unreadable=request(raw('f.req=%FF'));
 assert.equal(wireFacts(unreadable,catalog,new URL(unreadable.url)).route,false);
});

const pin={installation:'00000000-0000-4000-8000-000000000001',edition:'community',origin:'https://instance.example.invalid',organization_anchor:'synthetic-anchor',signing_key:'synthetic-key'};
const authority=await pinAuthority(pin);
const policy={revision:1,expires_at:'2099-01-01T00:00:00Z',config:{collection:{enabled:true},discovery:{enabled:false},services:[{enabled:true,domains:['ai.example.invalid']}]}};
const tick=()=>new Promise(resolve=>setTimeout(resolve,0));
function fixture({refuseHeaders=false}={}){
 const listeners={},calls=[],storage={},options={};
 globalThis.MilvagoAdapters={resolve:()=>({id:'synthetic'}),applyCatalog:()=>{}};
 const listen=name=>({addListener(listener,filter,extra){if(name==='sendHeaders'&&refuseHeaders){throw new Error('unsupported');}listeners[name]=listener;options[name]=extra;}});
 const api={
  runtime:{getManifest:()=>({version:'0.5.8',content_scripts:[]})},
  storage:{managed:{async get(){return {milvago_pin:JSON.stringify(pin)};}},local:{async get(){return structuredClone(storage);},async set(value){Object.assign(storage,structuredClone(value));}}},
  tabs:{async sendMessage(){return {ok:true,delivery_id:null,authority};}},
  webRequest:{onBeforeRequest:listen('before'),onBeforeSendHeaders:listen('sendHeaders'),onHeadersReceived:listen('headers'),onErrorOccurred:listen('error')},
 };
 const bridge=async message=>{
  calls.push(structuredClone(message));
  if(message.op==='catalog'){return {revision:1,catalog_state:'ok',catalog,expires_at:'2099-01-01T00:00:00Z'};}
  if(message.op==='event_v2'){return {ok:true,durable:true,delivery_id:message.delivery_id,id:'00000000-0000-4000-8000-000000000012'};}
  if(message.op==='event_complete'){return {ok:true,applied:true};}
  if(message.op==='detector_health'){return {accepted_health_ids:[message.batch.id]};}
  throw new Error('unexpected bridge operation '+message.op);
 };
 return {runtime:detectionRuntime(api,bridge,'firefox',()=>policy),listeners,calls,storage,options};
}
async function pending(f){for(let n=0;n<200&&!f.storage.detectorPending?.length;n++){await tick();}return f.storage.detectorPending||[];}

test('the runtime reads headers without blocking and without extraHeaders (Firefox refuses it)',async()=>{
 const f=fixture();await f.runtime.refresh();
 assert.deepEqual(f.options.sendHeaders,['requestHeaders']);
 assert.equal(f.listeners.sendHeaders({requestId:'unknown',requestHeaders:[modelHeader()]}),undefined,'a request it does not track is ignored');
 f.listeners.before(request());
 f.listeners.sendHeaders({requestId:'r1',requestHeaders:[modelHeader('fedcba9876543210')]});
 f.listeners.headers({requestId:'r1',statusCode:200,responseHeaders:[]});
 const [entry]=await pending(f);
 assert.equal(entry.source,'network');assert.equal(entry.event.model,'synthetic-deep');assert.equal(entry.event.characters,7);
});

test('headers are correlated by request id, never across requests',async()=>{
 const f=fixture();await f.runtime.refresh();
 f.listeners.before({...request(),requestId:'a'});f.listeners.before({...request(),requestId:'b',tabId:8});
 f.listeners.sendHeaders({requestId:'b',requestHeaders:[modelHeader('fedcba9876543210')]});
 f.listeners.sendHeaders({requestId:'a',requestHeaders:[modelHeader('0123456789abcdef')]});
 f.listeners.headers({requestId:'b',statusCode:200,responseHeaders:[]});
 f.listeners.headers({requestId:'a',statusCode:200,responseHeaders:[]});
 for(let n=0;n<200&&(f.storage.detectorPending?.length||0)<2;n++){await tick();}
 const byTab=Object.fromEntries(f.storage.detectorPending.map(p=>[p.identity.split('|')[0],p.event.model]));
 assert.deepEqual(byTab,{7:'synthetic-fast',8:'synthetic-deep'});
});

test('a request whose headers never show is still observed, without a model, and never hangs',async()=>{
 const f=fixture();await f.runtime.refresh();
 f.listeners.before(request());
 f.listeners.headers({requestId:'r1',statusCode:200,responseHeaders:[]});
 const [entry]=await pending(f);
 assert.equal(entry.event.characters,7);assert.equal(entry.event.model,undefined);
 // A failed request is forgotten, its pending header read settled.
 f.listeners.before({...request(),requestId:'r2'});f.listeners.error({requestId:'r2'});
 f.listeners.sendHeaders({requestId:'r2',requestHeaders:[modelHeader()]});
 for(let n=0;n<20;n++){await tick();}
 assert.equal(f.storage.detectorPending.length,1);
});

test('a browser refusing the header listener keeps every other observation',async()=>{
 const f=fixture({refuseHeaders:true});await f.runtime.refresh();
 assert.equal(f.listeners.sendHeaders,undefined);
 f.listeners.before(request());
 f.listeners.headers({requestId:'r1',statusCode:200,responseHeaders:[]});
 const [entry]=await pending(f);
 assert.equal(entry.event.characters,7);assert.equal(entry.event.model,undefined);
});

test('the DOM prompt and the network request still pair, the model carried by the request',async()=>{
 const f=fixture();await f.runtime.refresh();
 const sender={url:'https://ai.example.invalid/app',tab:{id:7},documentId:'document-a',frameId:0};
 await f.runtime.dom({provider:'ai.example.invalid',kind:'prompt',action:'observed',characters:7,labels:[]},sender,{fingerprint:await fingerprint('bonjour')});
 f.listeners.before(request());
 f.listeners.sendHeaders({requestId:'r1',requestHeaders:[modelHeader()]});
 f.listeners.headers({requestId:'r1',statusCode:200,responseHeaders:[]});
 for(let n=0;n<200&&!f.calls.some(c=>c.op==='event_v2');n++){await tick();}
 const sent=f.calls.filter(c=>c.op==='event_v2');
 assert.equal(sent.length,1,'one exchange, one event');
 assert.equal(sent[0].event.detector,'both');assert.equal(sent[0].event.model,'synthetic-fast');
});
