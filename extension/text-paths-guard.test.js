// A prompt route may carry the same text in several fields. Under masking the network guard
// must compare EVERY field it knows against the approved text: comparing only the first let a
// masked copy cover a clear copy travelling beside it. Synthetic route and fields.
import test from 'node:test';
import assert from 'node:assert/strict';
import './adapters.js';
import {wireFacts} from './detection.js';
import {requestDecision} from './model-access.js';
import {gzipSync} from 'node:zlib';

const catalog={providers:[{id:'chatgpt',domains:['chatgpt.com'],network:[{method:'POST',host:'chatgpt.com',path:'/fixture/route',text_path:'',text_paths:['msg.body','meta.copy']}]}]};
const policy={version:3,revision:1,expires_at:'2099-01-01T00:00:00Z',config:{services:[{id:'chatgpt',domains:['chatgpt.com'],enabled:true,mode:'observe'}],collection:{enabled:false},model_access:[],privacy:{enabled:true}}};
const approved='Hello [EMAIL]';
function decide(body,text=approved){
 const details={requestId:'fixture',tabId:1,url:'https://chatgpt.com/fixture/route',method:'POST',type:'xmlhttprequest',requestBody:{raw:[{bytes:new TextEncoder().encode(typeof body==='string'?body:JSON.stringify(body)).buffer}]}};
 return requestDecision(details,policy,wireFacts(details,catalog,new URL(details.url)),{text},Date.now());
}
const sealed=decision=>decision?.reason==='control_unavailable';
const allowed=decision=>decision?.allow===true&&decision.approved===true;

test('both copies equal to the approved text pass',()=>{
 assert.ok(allowed(decide({msg:{body:approved},meta:{copy:approved}})));
});
test('a masked first copy does not cover a clear second copy',()=>{
 assert.ok(sealed(decide({msg:{body:approved},meta:{copy:'Hello jean.exemple@example.com'}})));
});
test('a clear first copy is sealed whatever the second holds',()=>{
 assert.ok(sealed(decide({msg:{body:'Hello jean.exemple@example.com'},meta:{copy:approved}})));
});
test('an absent or empty second field carries nothing and is not compared',()=>{
 assert.ok(allowed(decide({msg:{body:approved}})));
 assert.ok(allowed(decide({msg:{body:approved},meta:{copy:''}})));
});
test('blanks in a text field are sealed, and so is any value there that is not text',()=>{
 assert.ok(sealed(decide({msg:{body:approved},meta:{copy:'   '}})));
 // A text path holding something else is a shape the guard cannot compare: it fails closed.
 for(const copy of [42,true,null,{nested:'Hello jean.exemple@example.com'},['Hello jean.exemple@example.com']]){
  assert.ok(sealed(decide({msg:{body:approved},meta:{copy}})),JSON.stringify(copy));
  assert.ok(sealed(decide({msg:{body:copy},meta:{copy:approved}})),JSON.stringify(copy));
 }
});
test('a list path keeps its non-text elements out of the comparison',()=>{
 const list={providers:[{id:'chatgpt',domains:['chatgpt.com'],network:[{method:'POST',host:'chatgpt.com',path:'/fixture/route',text_path:'',text_paths:['parts[*]']}]}]};
 const details={requestId:'fixture',tabId:1,url:'https://chatgpt.com/fixture/route',method:'POST',type:'xmlhttprequest',requestBody:{raw:[{bytes:new TextEncoder().encode(JSON.stringify({parts:[{content_type:'image_asset_pointer',asset_pointer:'file-service://synthetic'},approved]})).buffer}]}};
 // A multimodal message lists an attachment pointer beside its text: sealing it would block every image send.
 assert.ok(allowed(requestDecision(details,policy,wireFacts(details,list,new URL(details.url)),{text:approved},Date.now())));
});
test('the text only in the second field must still match',()=>{
 assert.ok(allowed(decide({meta:{copy:approved}})));
 assert.ok(sealed(decide({meta:{copy:'other text'}})));
});
test('a request without an approval is sealed even when both copies agree',()=>{
 const details={requestId:'fixture',tabId:1,url:'https://chatgpt.com/fixture/route',method:'POST',type:'xmlhttprequest',requestBody:{raw:[{bytes:new TextEncoder().encode(JSON.stringify({msg:{body:approved},meta:{copy:approved}})).buffer}]}};
 assert.ok(sealed(requestDecision(details,policy,wireFacts(details,catalog,new URL(details.url)),null,Date.now())));
});
// Second review, M1: a list path admits beside its text only attachment pointers. Text riding
// in a part object, a nested list, or a segment that is not an object is sealed.
test('a list path seals text hidden in parts it cannot compare',()=>{
 const list={providers:[{id:'chatgpt',domains:['chatgpt.com'],network:[{method:'POST',host:'chatgpt.com',path:'/fixture/route',text_path:'',text_paths:['messages[*].content.parts[*]']}]}]};
 const send=body=>{const details={requestId:'fixture',tabId:1,url:'https://chatgpt.com/fixture/route',method:'POST',type:'xmlhttprequest',requestBody:{raw:[{bytes:new TextEncoder().encode(JSON.stringify(body)).buffer}]}};return requestDecision(details,policy,wireFacts(details,list,new URL(details.url)),{text:approved},Date.now());};
 const message=parts=>({content:{content_type:'multimodal_text',parts}});
 assert.ok(allowed(send({model:'auto',messages:[{content:{content_type:'text',parts:[approved]}}]})));
 assert.ok(allowed(send({model:'auto',messages:[message([{content_type:'image_asset_pointer',asset_pointer:'file-service://synthetic',size_bytes:42,width:8,height:8},approved])]})),'an image beside the text');
 const secret='Hello jean.exemple@example.com';
 for(const [label,body] of [
  ['a text part object',{messages:[message([approved,{content_type:'text',text:secret}])]}],
  ['a pointer carrying text',{messages:[message([approved,{content_type:'image_asset_pointer',text:secret}])]}],
  ['a nested list',{messages:[message([approved,[secret]])]}],
  ['a null part',{messages:[message([approved,null])]}],
  ['content as a string',{messages:[{content:{content_type:'text',parts:[approved]}},{content:secret}]}],
  ['a message as a string',{messages:[{content:{content_type:'text',parts:[approved]}},secret]}],
  ['parts as a string',{messages:[{content:{content_type:'text',parts:[approved]}},{content:{parts:secret}}]}],
  ['messages as an object',{messages:{content:{parts:[secret]}}}],
 ]){assert.ok(sealed(send(body)),label);}
});
// Second review, I1: a variant the server may route to the prompt route (trailing slash, letter
// case, a sibling of the same directory, another method that carries a body) is guarded like it.
test('under masking a variant of the prompt route is guarded like the route',()=>{
 for(const [path,method] of [['/fixture/route/','POST'],['/FIXTURE/Route','POST'],['/fixture/sibling','POST'],['/fixture/route','PUT']]){
  const details={requestId:'fixture',tabId:1,url:'https://chatgpt.com'+path,method,type:'xmlhttprequest',requestBody:{raw:[{bytes:new TextEncoder().encode(JSON.stringify({msg:{body:'Hello jean.exemple@example.com'}})).buffer}]}};
  const wire=wireFacts(details,catalog,new URL(details.url));
  assert.equal(wire.route,true,path+' '+method);
  assert.ok(sealed(requestDecision(details,policy,wire,null,Date.now())),path+' '+method+' without approval');
  assert.ok(sealed(requestDecision(details,policy,wire,{text:approved},Date.now())),path+' '+method+' other text');
 }
 // A read of the provider is not a send.
 const read={requestId:'fixture',tabId:1,url:'https://chatgpt.com/fixture/route/',method:'GET',type:'xmlhttprequest'};
 assert.equal(wireFacts(read,catalog,new URL(read.url)).route,false);
});
// Third review, I3: a sibling of a form route is guarded like the route when it carries the
// route's field or a body the guard cannot read; a sibling without the field is page traffic.
test('under masking a sibling of a form route is sealed when it may carry the field',()=>{
 const form={providers:[{id:'chatgpt',domains:['chatgpt.com'],network:[{method:'POST',host:'chatgpt.com',path:'/fixture/form/send',form_field:'msg.body',text_path:'text'}]}]};
 const bytes=u8=>({raw:[{bytes:u8.buffer.slice(u8.byteOffset,u8.byteOffset+u8.byteLength)}]});
 const field=text=>JSON.stringify({text});
 const decide=(requestBody,approval)=>{const details={requestId:'fixture',tabId:1,url:'https://chatgpt.com/fixture/form/other',method:'POST',type:'xmlhttprequest',requestBody};return requestDecision(details,policy,wireFacts(details,form,new URL(details.url)),approval,Date.now());};
 for(const [label,body] of [
  ['a compressed body',bytes(gzipSync(new TextEncoder().encode('msg.body='+encodeURIComponent(field('Hello jean.exemple@example.com')))))],
  ['a body the browser could not read',{error:'Unknown error.'}],
  ['the field twice',{formData:{'msg.body':[field(approved),field('Hello jean.exemple@example.com')]}}],
  ['the field in a JSON body',bytes(new TextEncoder().encode(JSON.stringify({'msg.body':field('Hello jean.exemple@example.com')})))],
 ]){assert.ok(sealed(decide(body,null)),label);}
 const page=decide({formData:{token:['synthetic-token']}},null);
 assert.ok(!page||page.allow,'a sibling without the field passes');
});
// Third review, I4: a prompt route under another method that carries a body is a send.
test('under masking PATCH and DELETE on the prompt route are guarded like POST',()=>{
 const call=(path,method,requestBody)=>{const details={requestId:'fixture',tabId:1,url:'https://chatgpt.com'+path,method,type:'xmlhttprequest',requestBody};return requestDecision(details,policy,wireFacts(details,catalog,new URL(details.url)),{text:approved},Date.now());};
 const json=o=>({raw:[{bytes:new TextEncoder().encode(JSON.stringify(o)).buffer}]});
 for(const method of ['PATCH','DELETE']){assert.ok(sealed(call('/fixture/route',method,json({msg:{body:'Hello jean.exemple@example.com'}}))),method);}
 const sibling=call('/fixture/sibling','PATCH',json({title:'synthetic'}));
 assert.ok(!sibling||sibling.allow,'a sibling PATCH without text passes');
 const bare=call('/fixture/route','PATCH',undefined);
 assert.ok(!bare||bare.allow,'a PATCH without a body passes');
});
// Third review, m1: a list path holding more values than `valuesAt` reads is sealed, even
// when no single list exceeds the limit.
test('a list path with more values than the guard reads is sealed',()=>{
 const list={providers:[{id:'chatgpt',domains:['chatgpt.com'],network:[{method:'POST',host:'chatgpt.com',path:'/fixture/route',text_path:'',text_paths:['messages[*].content.parts[*]']}]}]};
 const H=n=>Array(n).fill('H');
 const details={requestId:'fixture',tabId:1,url:'https://chatgpt.com/fixture/route',method:'POST',type:'xmlhttprequest',requestBody:{raw:[{bytes:new TextEncoder().encode(JSON.stringify({messages:[{content:{parts:H(600)}},{content:{parts:[...H(500),'Hello jean.exemple@example.com']}}]})).buffer}]}};
 assert.ok(sealed(requestDecision(details,policy,wireFacts(details,list,new URL(details.url)),{text:'H'.repeat(1024)},Date.now())));
});
