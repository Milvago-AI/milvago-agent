// claude.ai sends through `ConversationService/PerformAction`, a binary protobuf body, not the
// JSON `/completion` any more (measured by CDP 2026-10-16, every request paused and failed, nothing
// sent). The bodies below follow the shape of that capture, with synthetic values: the context
// (field 1: session, conversation id, locale, a 32-byte opaque value), the message (field 2: ids,
// text at 2.3, locale, and a pasted text block at 2.15 holding its content at 2.15.4). The call
// made at paste time carries no field 2. A sibling RPC (`StreamTimeline`) uses a Connect envelope.
import test from 'node:test';
import assert from 'node:assert/strict';
import {gzipSync} from 'node:zlib';
import {randomBytes} from 'node:crypto';
import './adapters.js';
import {wireFacts,headerModelScope,observeRequest,decodeProtobuf} from './detection.js';
import {requestDecision} from './model-access.js';
import {factoryCatalog} from './detection-factory.js';

const policy={version:3,revision:7,expires_at:'2099-01-01T00:00:00Z',config:{services:[],model_access:[],collection:{enabled:false},privacy:{enabled:true}}};
const RPC='https://claude.ai/claudeai-rpc/anthropic.bard.api.v1alpha.ConversationService/';
const CONV='00000000-0000-4000-8000-000000000000';
const varint=n=>{const out=[];let v=BigInt(n);do{let b=Number(v&127n);v>>=7n;if(v){b|=128;}out.push(b);}while(v);return out;};
const f=(field,value)=>typeof value==='number'?[...varint(field*8),...varint(value)]:(bytes=>[...varint(field*8+2),...varint(bytes.length),...bytes])(typeof value==='string'?[...new TextEncoder().encode(value)]:value);
const msg=(...parts)=>parts.flat();
const OPAQUE=Array.from({length:32},(_,i)=>0x80+i);
const context=msg(f(1,msg(f(1,'sess_0a1b2c3d4e5f6a7b'),f(2,3))),f(2,CONV),f(3,3),f(7,msg(f(1,1),f(2,1),f(3,1),f(6,1),f(7,1),f(8,1),f(10,1),f(22,1))),f(14,'fr-FR'),f(15,OPAQUE));
const pasted=content=>f(15,msg(f(2,content.length),f(3,'txt'),f(4,content)));
const message=(text,...extra)=>f(2,msg(f(1,'11111111-1111-4111-8111-111111111111'),f(2,'22222222-2222-4222-8222-222222222222'),f(3,text),f(12,'Europe/Paris'),f(13,'fr-FR'),...extra,f(18,1)));
const performSend=(text,...extra)=>msg(f(1,context),message(text,...extra));
const pasteCall=msg(f(1,msg(f(2,CONV),f(3,3),f(14,'fr-FR'))),f(15,msg(f(1,msg(f(12,'Europe/Paris'),f(13,'fr-FR'),f(18,1))))));
const envelope=(bytes,flag=0)=>[flag,(bytes.length>>>24)&255,(bytes.length>>>16)&255,(bytes.length>>>8)&255,bytes.length&255,...bytes];
const timeline=envelope(msg(f(1,CONV),f(2,msg(f(1,'1792154665164-0'))),f(3,1),f(4,msg(f(6,1),f(22,1))),f(5,'fr-FR'),f(6,1),f(8,'Europe/Paris')));
const SECRET='Le projet Orion rachete la societe Exemple, IBAN FR7630006000011234567890189';

function details(bytes,rpc='PerformAction',requestBody){
 const u8=Uint8Array.from(bytes);
 return {requestId:'a',tabId:1,url:RPC+rpc,method:'POST',type:'xmlhttprequest',requestBody:requestBody||{raw:[{bytes:u8.buffer}]},initiator:'https://claude.ai'};
}
function decide(d,approval){
 const u=new URL(d.url);
 return requestDecision(d,policy,wireFacts(d,factoryCatalog,u),approval,Date.now(),(id,uu)=>headerModelScope(factoryCatalog,id,d,uu));
}
const passes=decision=>!decision||decision.allow===true;
const approved=decision=>decision?.allow===true&&decision.approved===true;

test('the catalogue names the protobuf send route and keeps /completion',()=>{
 const claude=factoryCatalog.providers.find(p=>p.id==='claude');
 const rule=claude.network.find(n=>n.body_format==='protobuf');
 assert.ok(rule,'a protobuf rule');
 assert.deepEqual(rule.text_paths,['2[*].3[*]','2[*].15[*].4[*]']);
 assert.ok(claude.network.some(n=>n.path.endsWith('/completion')),'the JSON route stays');
 const facts=wireFacts(details(performSend('Dis OK')),factoryCatalog,new URL(RPC+'PerformAction'));
 assert.equal(facts.route,true);assert.deepEqual(facts.texts,['Dis OK']);
});

test('under masking the send passes only with its approved text, attachments compared too',()=>{
 assert.ok(approved(decide(details(performSend('Dis OK')),{text:'Dis OK'})),'the approved text');
 assert.equal(passes(decide(details(performSend('Dis OK')),null)),false,'no approval');
 assert.equal(passes(decide(details(performSend(SECRET)),{text:'Dis OK'})),false,'other text');
 assert.equal(passes(decide(details(performSend('Dis OK',pasted(SECRET))),{text:'Dis OK'})),false,'a pasted text block nobody approved');
 assert.equal(passes(decide(details(performSend('',pasted(SECRET))),{text:''})),false,'a pasted text block sent alone');
});

test('the paste-time call and the sibling RPCs without text pass',()=>{
 assert.ok(passes(decide(details(pasteCall),null)),'paste-time call');
 assert.ok(passes(decide(details(timeline,'StreamTimeline'),null)),'StreamTimeline in its Connect envelope');
 assert.ok(passes(decide(details(msg(f(1,CONV)),'ListMessages'),null)),'a sibling read');
 assert.equal(passes(decide(details(performSend(SECRET),'EditMessage'),null)),false,'a sibling carrying text at the send path');
 assert.equal(passes(decide(details(gzipSync(Uint8Array.from(performSend(SECRET))),'EditMessage'),null)),false,'a sibling the guard cannot read');
});

test('a hostile body is sealed, even within an approval',()=>{
 const ok={text:'Dis OK'},good=performSend('Dis OK');
 let deep=f(3,'Dis OK');for(let i=0;i<100;i++){deep=f(1,deep);}
 for(const [label,body] of [
  ['truncated',good.slice(0,good.length-3)],
  ['a length past the end',[...good,0x12,0x7f,0x41]],
  ['a giant varint',[...good,0x08,...Array(11).fill(0xff),0x01]],
  ['a field number of zero',[...good,0x02,0x01,0x41]],
  ['a group wire type',[...good,0x0b]],
  ['excessive depth',msg(f(1,context),f(2,deep))],
  ['text hidden in a nested field',performSend('Dis OK',f(99,msg(f(1,SECRET))))],
  ['text hidden in the context',msg(f(1,msg(...context,f(50,msg(f(7,SECRET))))),message('Dis OK'))],
  ['a lone IBAN hidden in the context',msg(f(1,msg(...context,f(50,'FR7630006000011234567890189'))),message('Dis OK'))],
  ['a message where the text belongs',performSend(msg(f(1,0x01),f(2,SECRET)))],
  ['a large opaque value',performSend('Dis OK',f(98,Array.from({length:2048},(_,i)=>0x80+(i%64))))],
  ['gzip',[...gzipSync(Uint8Array.from(good))]],
  ['a compressed Connect envelope',envelope(good,1)],
 ]){assert.equal(passes(decide(details(body),ok)),false,label);}
 assert.equal(passes(decide(details([],'PerformAction',{error:'Unknown error.'}),ok)),false,'a body the browser could not read');
});

test('the bounded reader returns every field as a list, and null on a hostile body',()=>{
 const body=decodeProtobuf(Uint8Array.from(performSend('Dis OK',pasted('ab'))));
 assert.equal(body['2'][0]['3'][0],'Dis OK');
 assert.equal(body['2'][0]['15'][0]['4'][0],'ab');
 assert.equal(body['1'][0]['2'][0],CONV);
 assert.equal(decodeProtobuf(Uint8Array.from([0x08,...Array(11).fill(0xff),0x01])),null);
 assert.equal(Object.getPrototypeOf(body),null,'no prototype to pollute');
});

test('observation reads the text and the conversation, and leaves the model empty',async()=>{
 const seen=await observeRequest(details(performSend('Dis OK',pasted('ab'))),factoryCatalog,true);
 assert.equal(seen.provider.id,'claude');
 assert.equal(seen.characters,6);
 assert.equal(seen.conversation_id,CONV);
 assert.equal(seen.model,undefined);
});

test('a control character in the approved text does not seal it',()=>{
 for(const text of ['\x1b[31mred\x1b[0m done','one\x0btwo','page\x0cnext','a\tb','bell\x07 and nul\x00 too']){
  assert.ok(approved(decide(details(performSend(text)),{text})),JSON.stringify(text));
  assert.equal(passes(decide(details(performSend(text)),{text:'Dis OK'})),false,'still compared: '+JSON.stringify(text));
 }
});
test('prose kept out of sight as a non-text value off the path is read and seals the send',()=>{
 const ok={text:'Dis OK'},bytes=[...new TextEncoder().encode(SECRET)];
 for(const [label,value] of [['a control character',SECRET+'\x01'],['an invalid UTF-8 byte',[...bytes,0xff]],['interleaved control bytes',[...new TextEncoder().encode('Projet Orion\x02 rachat\x03 de la societe Exemple')]]]){
  assert.equal(passes(decide(details(performSend('Dis OK',f(40,value))),ok)),false,label);
 }
 assert.ok(approved(decide(details(performSend('Dis OK',f(40,Array.from({length:32},(_,i)=>0x80+i)))),ok)),'a binary value is not prose');
 for(let i=0;i<200;i++){const key=[...randomBytes(32)];assert.ok(approved(decide(details(performSend('Dis OK',f(40,key))),ok)),'a random key is not prose: '+Buffer.from(key).toString('hex'));}
});
// Prose cut into fixed-width fields (`fixed64`, `fixed32`) or wide varints never reaches a string:
// the bytes of a message's numeric fields are read back together, in order.
test('prose cut into fixed-width or wide numeric fields seals the send',()=>{
 const ok={text:'Dis OK'},enc=new TextEncoder();
 const fixed=(wire,size,text)=>{const bytes=[...enc.encode(text)];const out=[];for(let at=0;at<bytes.length;at+=size){out.push(...varint(41*8+wire),...Array.from({length:size},(_,i)=>bytes[at+i]??0x20));}return out;};
 const wide=text=>{const bytes=[...enc.encode(text)];const out=[];for(let at=0;at<bytes.length;at+=7){let v=0n;for(let i=6;i>=0;i--){v=(v<<8n)|BigInt(bytes[at+i]??0x20);}out.push(...varint(42*8),...varint(v));}return out;};
 for(const [label,extra] of [['fixed64',fixed(1,8,SECRET)],['fixed32',fixed(5,4,SECRET)],['varints',wide(SECRET)],['fixed64 in a nested message',f(43,fixed(1,8,SECRET))]]){
  assert.equal(passes(decide(details(performSend('Dis OK',extra)),ok)),false,label);
 }
 const noise=count=>Array.from({length:count},()=>[...varint(41*8+1),...randomBytes(8)]).flat();
 assert.equal(passes(decide(details(performSend('Dis OK',noise(8))),ok)),false,'many fixed fields the guard cannot read');
 const stamp=new Uint8Array(new Float64Array([1792154665.164]).buffer);
 assert.ok(approved(decide(details(performSend('Dis OK',[...varint(41*8+1),...stamp],f(42,1792154665164))),ok)),'a timestamp is not prose');
 for(let i=0;i<200;i++){assert.ok(approved(decide(details(performSend('Dis OK',noise(2))),ok)),'two random fixed fields are not prose');}
});
// A paste approval covers the pasted block (`2.15.4`), never the typed draft (`2.3`): that one is
// the send just approved.
test('a paste approval covers the pasted block, never the draft',()=>{
 const claude=factoryCatalog.providers.find(p=>p.id==='claude'),rule=claude.network.find(n=>n.body_format==='protobuf');
 assert.deepEqual(rule.attachment_paths,['2[*].15[*].4[*]']);
 const draft={text:'Resume ce texte',kind:'send'},chip={text:SECRET,kind:'paste'};
 assert.ok(approved(decide(details(performSend('Resume ce texte',pasted(SECRET))),[draft,chip])),'the real send: draft and pasted block, each approved');
 assert.ok(approved(decide(details(performSend('',pasted(SECRET))),[chip])),'a pasted block sent alone');
 assert.equal(passes(decide(details(performSend(SECRET)),[chip])),false,'a draft covered by a paste approval only');
 assert.equal(passes(decide(details(performSend(SECRET)),[{text:'Autre chose',kind:'send'},chip])),false,'a draft that is the paste, beside another approved draft');
 assert.equal(passes(decide(details(performSend('Resume ce texte',pasted(SECRET))),[draft,{text:SECRET,kind:'send'}])),false,'a pasted block covered by a send approval');
});
