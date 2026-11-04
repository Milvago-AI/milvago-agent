import test from 'node:test';
import assert from 'node:assert/strict';
import {validPolicy,eventForPolicy} from './policy.js';
import './adapters.js';
import {contentControl,requestDecision,nameDigest} from './model-access.js';

const policy=()=>({version:4,revision:20,expires_at:'2099-01-01T00:00:00Z',config:{
 services:[{id:'chatgpt',domains:['chatgpt.com'],enabled:true,mode:'observe'}],model_access:[],
 collection:{enabled:false,store_content:false},protection:{keywords:[],block_uploads:false},privacy:{enabled:false},
 dlp_control:{enabled:true,journal:true,fingerprint:'a'.repeat(64)}
}});
test('v4 seals controlled transports independently of legacy Shadow masking',()=>{
 const p=policy();assert.equal(validPolicy(p),true);assert.equal(contentControl(p),true);
 p.config.dlp_control.enabled=false;assert.equal(contentControl(p),false);
 p.expires_at='2000-01-01T00:00:00Z';assert.equal(validPolicy(p),false);
});
test('DLP metadata journaling does not authorize content retention or page-nominated attribution',()=>{
 const p=policy();
 const event=eventForPolicy({kind:'prompt',action:'observed',characters:7,labels:[],prompt:'Tomates',dlp:{rule_id:'forged'}},'https://chatgpt.com/','chrome',p,true);
 assert.ok(event);assert.equal(event.prompt,undefined);assert.equal(event.dlp,undefined);
 assert.equal(eventForPolicy({kind:'prompt',action:'observed',characters:7},'https://chatgpt.com/','chrome',p),null);
 p.config.dlp_control.journal=false;assert.equal(eventForPolicy({kind:'prompt',action:'observed',characters:7},'https://chatgpt.com/','chrome',p),null);
});

test('dedicated DLP seals opaque upload routes until an exact private transport proof exists',()=>{
 const p=policy();const details={tabId:1,documentId:'fixture-document',url:'https://chatgpt.com/fixture/upload',initiator:'https://chatgpt.com',method:'POST',type:'xmlhttprequest',requestBody:{raw:[{bytes:new Uint8Array([1,2,3]).buffer}]}};
 for(const approval of [[],[{kind:'file',name:nameDigest('fixture.bin'),size:3}],[{digest:'a'.repeat(64),bytes:3}]]){
  const result=requestDecision(details,p,{file:true},approval);assert.equal(result?.reason,'control_unavailable');
 }
 p.config.dlp_control.enabled=false;assert.equal(requestDecision(details,p,{file:true},[])?.reason,undefined,'legacy-only behavior remains compatible');
});

test('dedicated DLP does not lend an inspected text approval to unreadable prompt bytes',()=>{
 const p=policy(),details={tabId:1,documentId:'fixture-document',url:'https://chatgpt.com/fixture/prompt',initiator:'https://chatgpt.com',method:'POST',type:'xmlhttprequest',requestBody:{raw:[{bytes:new Uint8Array([0x1f,0x8b,1,2]).buffer}]}};
 const wire={route:{method:'POST'},readable:false,texts:[],body:null};
 assert.equal(requestDecision(details,p,wire,[{text:'Previously inspected text'}])?.reason,'control_unavailable');
 p.config.dlp_control.enabled=false;p.config.privacy.enabled=true;
 assert.equal(requestDecision(details,p,wire,[{text:'Previously inspected text'}])?.allow,true,'the explicitly legacy window stays compatible');
});

test('contextual DLP requires the complete exact text, including whitespace',()=>{
 const p=policy(),details={url:'https://chatgpt.com/fixture/prompt',initiator:'https://chatgpt.com',method:'POST',type:'xmlhttprequest',requestBody:{}};
 const decision=(texts,proofs,groups=[texts])=>requestDecision(details,p,{route:{method:'POST'},readable:true,texts,groups,body:{}},proofs);
 const approved={text:'SECRET\nPUBLIC'};
 assert.equal(decision(['SECRET\nPUBLIC'],[approved])?.allow,true);
 for(const text of ['SECRET','PUBLIC','SECRET\n\nPUBLIC',' SECRET\nPUBLIC','SECRET\r\nPUBLIC'])assert.equal(decision([text],[approved])?.reason,'control_unavailable',text);
 assert.equal(decision(['SECRET','PUBLIC'],[{text:'SECRET'},{text:'PUBLIC'}])?.reason,'control_unavailable','separate approvals do not authorize their combination');
 assert.equal(decision(['SECRET','PUBLIC'],[approved],[['SECRET'],['PUBLIC']])?.reason,'control_unavailable','separate groups have no qualified whole-text binding');
 const attachment=['SECRET\nPUBLIC'];attachment.attachment=true;
 assert.equal(decision(attachment,[approved],[attachment])?.reason,'control_unavailable');
});

test('dedicated DLP refuses paste upload proofs based only on name, size or pasted text',()=>{
 const p=policy(),details={url:'https://chatgpt.com/backend-api/files',initiator:'https://chatgpt.com',method:'POST',type:'xmlhttprequest',requestBody:{}};
 for(const upload of [{text:true,name:'paste.txt',size:6},{text:true,content:'PUBLIC'},{text:false,name:'fixture.png',size:6}]){
  const result=requestDecision(details,p,{paste:true,readable:true,uploads:[upload]},[{kind:'paste',text:'PUBLIC'},{kind:'file',name:nameDigest('paste.txt'),size:6}]);
  assert.equal(result?.reason,'control_unavailable','paste inspection does not authorize an upload context');
 }
});

test('a recognized DLP send without inspectable text never borrows an empty-text exception',()=>{
 const p=policy(),details={url:'https://chatgpt.com/fixture/prompt',initiator:'https://chatgpt.com',method:'POST',type:'xmlhttprequest',requestBody:{}};
 for(const extras of [{prose:false},{},{prose:false,draft:true}]){
  const wire={route:{method:'POST'},readable:true,texts:[],groups:[],body:{},...extras};
  for(const approvals of [[],[{text:''}],[{text:'Previously approved'}]])assert.equal(requestDecision(details,p,wire,approvals)?.reason,'control_unavailable');
 }
 p.config.dlp_control.enabled=false;p.config.privacy.enabled=true;
 assert.equal(requestDecision(details,p,{route:{method:'POST'},readable:true,texts:[],groups:[],body:{},prose:false},[])?.reason,undefined,'legacy empty-route behavior remains unchanged');
});
