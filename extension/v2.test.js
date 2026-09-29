import test from 'node:test';
import {webcrypto} from 'node:crypto';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {JSDOM} from 'jsdom';
import fileListUtils from 'jsdom/lib/generated/idl/utils.js';
import './adapters.js';
import './capture.js';
import {eventForPolicy,networkRules,providers} from './policy.js';
const A=globalThis.MilvagoAdapters;
const policy=(store=false)=>({version:2,revision:9,expires_at:'2099-01-01T00:00:00Z',config:{collection:{enabled:true,store_content:store},services:A.adapters.map(a=>({id:a.id,domains:[a.domain],enabled:true,mode:'observe'}))}});
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const pages={
 chatgpt:['<textarea id="prompt-textarea"></textarea><button data-testid="send-button">Send</button>','<div data-message-author-role="assistant">Answer</div>','/c/00000000-0000-4000-8000-000000000000'],
 claude:['<div role="textbox" contenteditable="true" data-testid="chat-input"></div><button type="button" aria-label="Envoyer le message" data-testid="chat-input-send">Envoyer</button>','<div data-testid="assistant-message">Answer</div>','/chat/00000000-0000-4000-8000-000000000000'],
 // Measured on 2026-09-14: TWO submit buttons coexist on the page, and only
 // the composer's carries `aria-busy`. The second one is reproduced here, otherwise the fixture
 // would validate a disambiguation it never actually exercised.
 lechat:['<textarea></textarea><button type="submit">Autre</button><button type="submit" aria-busy="false" aria-label="Envoyer">Envoyer</button>','<div data-message-role="assistant">Answer</div>','/chat/00000000-0000-4000-8000-000000000000'],
 copilot:['<textarea></textarea><button data-testid="submit-button">Send</button>','<div data-content="ai-message">Answer</div>','/chats/00000000-0000-4000-8000-000000000000'],
 // The real page nests the button inside a wrapper that carries the class, and its
 // label is in the interface language. A fixture that put the class on the button
 // itself made a dead selector look alive: the markup here mirrors what was measured.
 gemini:['<rich-textarea><div contenteditable="true"></div></rich-textarea><gem-icon-button class="send-button"><button aria-label="Envoyer un message">Envoyer</button></gem-icon-button>','<model-response>Answer</model-response>','/app/abcdefgh12345678'],
 // The Send/Envoyer labels matched TWO buttons on the real page — an
 // ambiguous selector, not just a language-dependent one. The neighbors are reproduced.
 notebooklm:['<textarea></textarea><button aria-label="Web">Web</button><button type="submit" aria-label="Envoyer">Envoyer</button>','<div class="to-user-message">Answer</div>','/notebook/00000000-0000-4000-8000-000000000000'],
 // DeepSeek exposes NO <button> around its composer at all: its send control is a
 // div[role=button] from its in-house library, with its variant class.
 deepseek:['<textarea></textarea><div role="button" class="ds-button ds-button--secondary">Autre</div><div role="button" class="ds-button ds-button--primary ds-button--filled ds-button--circle" tabindex="0">Envoyer</div>','<div data-message-role="assistant">Answer</div>','/a/chat/s/00000000-0000-4000-8000-000000000000'],
 // Perplexity has no structural handle at all and its three selectors are neutralized:
 // it has no DOM path left to exercise. The fixture stays here for URL resolution.
 perplexity:['<textarea></textarea><button aria-label="Envoyer">Send</button>','<div data-testid="answer">Answer</div>','/search/private-question-00000000-0000-4000-8000-000000000000'],
 grok:['<textarea></textarea><button type="submit" data-testid="chat-submit" aria-label="Envoyer">Envoyer</button>','<div data-message-role="assistant">Answer</div>','/c/00000000-0000-4000-8000-000000000000'],
};
function trusted(type,target,extra={}){return {type,target,isTrusted:true,prevented:false,preventDefault(){this.prevented=true;},stopImmediatePropagation(){},...extra};}
async function fixture(id='chatgpt',answer,store=false,submitAnswer,eventAnswer){
 const adapter=A.adapters.find(a=>a.id===id),[html,old,path]=pages[id];const dom=new JSDOM(`<form>${html}</form>${old}`,{url:`https://${adapter.domain}${path}`});const doc=dom.window.document;Object.defineProperty(dom.window.crypto,'subtle',{value:webcrypto.subtle});
 const form=doc.querySelector('form');let submissions=0;const geste={parClic:false};
 // Count the resumed GESTURE, not the form submission. Measured on 2026-09-14:
 // claude.ai has no form and its send button is `type="button"`;
 // chat.deepseek.com has no <button> at all. Their resume therefore goes through
 // `control.click()` and produces no `submit` event. Counting submits alone
 // would have required a page shape these two providers don't have.
 // The wrapping form remains a fixture simplification: `submissionTarget()`
 // keeps the control when it exists, so its presence doesn't change the path exercised.
 form.addEventListener('submit',event=>{event.preventDefault();if(!geste.parClic){submissions+=1;}});
 // Expose the closed shadow only in this synthetic fixture for behavior assertions.
 const attach=dom.window.Element.prototype.attachShadow;dom.window.Element.prototype.attachShadow=function(options){const root=attach.call(this,options);this.testShadow=root;return root;};
 const messages=[];const config=policy(store);const controller=globalThis.MilvagoCapture.start(doc,dom.window.location,async msg=>{messages.push(msg);if(msg.type==='policy'){return {ok:true,policy:config};}if(msg.type==='inspect'){return typeof answer==='function'?answer(msg):answer||{ok:true,action:'observe',text:msg.text,labels:['email']};}if(msg.type==='submit'){return submitAnswer?submitAnswer(msg):{ok:true,action:'observe',text:msg.text,durable:true,recording_required:true,authority:null,delivery_id:'00000000-0000-4000-8000-000000000001'};}if(msg.type==='event'&&eventAnswer){return eventAnswer(msg);}return {ok:true};});await delay(0);
 const editor=doc.querySelector(adapter.editor),button=doc.querySelector(adapter.send);A.write(editor,'Synthetic prompt');
 geste.parClic=!!button;if(button){button.addEventListener('click',()=>{submissions+=1;});}
 return {dom,doc,controller,messages,editor,button,config,adapter,submissionCount(){return submissions;},close(){controller.dispose();dom.window.close();},dialog(){return [...doc.querySelectorAll('div')].find(x=>x.testShadow)?.testShadow;}};
}
// Perplexity is deliberately without a DOM path: its three selectors are neutralized
// for lack of any structural handle, and its interface language follows the browser across
// dozens of languages. It is exercised by its own test below, which verifies
// the opposite: that it intercepts NOTHING, so it cannot block a send.
for(const adapter of A.adapters.filter(a=>a.id!=='perplexity')){test(`${adapter.id}: trusted submission, navigation, correlated response without retrospective capture`,async()=>{
 const f=await fixture(adapter.id);try{
  const first=trusted('click',f.button);await f.controller.handle(first);assert.equal(first.prevented,true);
  assert.equal(f.messages.filter(m=>m.type==='submit').length,1);
  assert.equal(f.dialog(),undefined);const prompts=f.messages.filter(m=>m.type==='submit');assert.equal(prompts.length,1);assert.equal(f.submissionCount(),1);assert.equal(prompts[0].event.prompt,undefined);
  const holder=f.doc.createElement('section');holder.innerHTML=pages[adapter.id][1];f.doc.body.append(holder);await delay(1350);
  const responses=f.messages.filter(m=>m.type==='event'&&m.event.kind==='response');assert.equal(responses.length,1);assert.equal(responses[0].event.correlation_id,prompts[0].event?.correlation_id);assert.equal(responses[0].event.response,undefined);
  assert.equal(f.messages.filter(m=>m.type==='event'&&m.event.kind==='navigation').length,1);
 }finally{f.close();}
});}
test('synthetic events, shift-enter, IME and unrelated clicks do not inspect or emit prompts',async()=>{const f=await fixture();try{for(const e of [trusted('click',f.button,{isTrusted:false}),trusted('keydown',f.editor,{key:'Enter',shiftKey:true}),trusted('keydown',f.editor,{key:'Enter',isComposing:true}),trusted('click',f.doc.body)]){await f.controller.handle(e);}assert.equal(f.messages.filter(m=>m.type==='inspect').length,0);}finally{f.close();}});
test('review approval validates and sends the transformed draft once',async()=>{
 const f=await fixture('chatgpt',msg=>({ok:true,action:'review',text:msg.text.replace('Synthetic','[MASKED]'),labels:['email']}),true);try{
  await f.controller.handle(trusted('click',f.button));assert.equal(A.read(f.editor),'Synthetic prompt');assert.equal(f.dialog().querySelector('textarea').value,'[MASKED] prompt');
  f.dialog().querySelector('button').click();await delay(20);assert.equal(A.read(f.editor),'[MASKED] prompt');assert.equal(f.messages.filter(m=>m.type==='submit').length,1);
  const prompt=f.messages.find(m=>m.type==='submit');assert.equal(prompt.text,'[MASKED] prompt');assert.equal(f.submissionCount(),1);
 }finally{f.close();}
});
test('cancel review preserves draft and never emits an observed prompt',async()=>{const f=await fixture('chatgpt',{ok:true,action:'review',text:'[MASKED]',labels:[]});try{await f.controller.handle(trusted('click',f.button));[...f.dialog().querySelectorAll('button')].at(-1).click();assert.equal(A.read(f.editor),'Synthetic prompt');assert.equal(f.messages.some(m=>m.event?.kind==='prompt'),false);}finally{f.close();}});
test('changing the draft invalidates previous local approval',async()=>{const f=await fixture();try{await f.controller.handle(trusted('click',f.button));A.write(f.editor,'Changed draft');const event=trusted('click',f.button);await f.controller.handle(event);assert.equal(event.prevented,true);assert.equal(f.messages.filter(m=>m.type==='inspect').length,2);assert.equal(f.messages.filter(m=>m.type==='submit').length,2);}finally{f.close();}});
test('navigation to another conversation clears pending response correlation',async()=>{const f=await fixture();try{await f.controller.handle(trusted('click',f.button));assert.equal(f.submissionCount(),1);f.dom.window.history.pushState({},'', '/c/anotherconversation');f.controller.navigation();f.doc.body.insertAdjacentHTML('beforeend',pages.chatgpt[1]);await delay(1350);assert.equal(f.messages.some(m=>m.event?.kind==='response'),false);assert.equal(f.messages.filter(m=>m.event?.kind==='navigation').length,2);}finally{f.close();}});
test('a new conversation URL keeps the just-submitted prompt correlation',async()=>{const f=await fixture();try{f.dom.window.history.replaceState({},'', '/');f.controller.navigation();await f.controller.handle(trusted('click',f.button));assert.equal(f.submissionCount(),1);f.dom.window.history.pushState({},'', '/c/newconversation');f.controller.navigation();f.doc.body.insertAdjacentHTML('beforeend',pages.chatgpt[1]);await delay(1350);const prompt=f.messages.find(m=>m.type==='submit');const response=f.messages.find(m=>m.event?.kind==='response');assert.equal(response.event.correlation_id,prompt.event?.correlation_id);}finally{f.close();}});
test('native failure blocks attempt and does not erase draft',async()=>{const f=await fixture('chatgpt',{ok:false});try{const e=trusted('submit',f.doc.querySelector('form'));await f.controller.handle(e);assert.equal(e.prevented,true);assert.equal(A.read(f.editor),'Synthetic prompt');assert.ok(f.dialog());assert.equal(f.messages.some(m=>m.event?.kind==='prompt'),false);}finally{f.close();}});
test('UTF-8 prompt above 32 KiB never crosses the native boundary',async()=>{const f=await fixture();try{A.write(f.editor,'é'.repeat(16385));const e=trusted('click',f.button);await f.controller.handle(e);assert.equal(e.prevented,true);assert.equal(f.messages.some(m=>m.type==='inspect'),false);}finally{f.close();}});
test('responses are classified and masked locally even when inspect says block',async()=>{const f=await fixture('chatgpt',msg=>({ok:true,action:msg.text==='Answer'?'block':'observe',text:msg.text==='Answer'?'[MASKED]':msg.text,labels:['custom']}),true);try{await f.controller.handle(trusted('click',f.button));assert.equal(f.submissionCount(),1);f.doc.body.insertAdjacentHTML('beforeend',pages.chatgpt[1]);await delay(1350);const response=f.messages.find(m=>m.event?.kind==='response').event;assert.equal(response.action,'observed');assert.equal(response.response,'[MASKED]');assert.deepEqual(response.labels,['custom']);}finally{f.close();}});
test('blocked upload does not read filenames or contents',async()=>{const f=await fixture('chatgpt',{ok:true,action:'block',text:'',reason:'Uploads blocked'});try{const {input,file}=selectedFile(f);Object.defineProperty(file,'name',{get(){throw Error('Filename read');}});file.text=()=>{throw Error('File contents read');};let delivered=0;input.addEventListener('change',()=>delivered++);const e=trusted('change',input);await f.controller.upload(e);assert.equal(e.prevented,true);assert.equal(delivered,0);const message=f.messages.find(m=>m.type==='inspect');assert.equal(message.upload,true);assert.equal(message.text,'');assert.equal(f.messages.filter(m=>m.type==='submit').length,0);}finally{f.close();}});
test('URL normalization removes query/hash and descriptive search slug',()=>{for(const a of A.adapters){const c=A.context(`https://${a.domain}${pages[a.id][2]}?token=secret#fragment`);assert.ok(c.conversation_id);assert.ok(!/[?#]/.test(c.url));assert.ok(!c.url.includes('private-question'));}assert.equal(A.context('https://chatgpt.com/private-sensitive-title').url,'https://chatgpt.com');});
test('worker whitelist derives sender, drops unknown fields and gates raw content',()=>{const input={kind:'prompt',action:'observed',characters:5,prompt:'hello',response:'secret',provider:'other.test',source:'native',organization_id:'fake',labels:['email','bad space']};const out=eventForPolicy(input,'https://chatgpt.com/c/abcdefgh?secret=x','edge',policy());assert.equal(out.provider,'chatgpt.com');assert.equal(out.source,'browser');assert.equal(out.prompt,undefined);assert.equal(out.organization_id,undefined);assert.deepEqual(out.labels,['email']);assert.equal(eventForPolicy(input,'https://chatgpt.com','edge',policy(true)).prompt,'hello');const off=policy(true);off.config.collection.enabled=false;assert.equal(eventForPolicy(input,'https://chatgpt.com','edge',off),null);});
test('v2 network block stays scoped and malformed expiration is rejected',()=>{const p=policy();p.config.services[0].mode='block';assert.equal(networkRules(p).length,2);p.expires_at='invalid';assert.throws(()=>networkRules(p));});
test('manifest grants exactly supported domains and retains stable extension identity',async()=>{const m=JSON.parse(await readFile(new URL('./manifest.json',import.meta.url)));assert.deepEqual(m.host_permissions,['<all_urls>']);assert.ok(m.permissions.includes('webRequestBlocking'));assert.ok(m.key);assert.deepEqual(m.content_scripts[0].js,['adapters.js','capture.js']);});

// A provider with no structural handle must intercept NOTHING. The worst possible
// state would be a live `editor` with a dead `send`: `submission()` would then swallow the
// Enter key, `submissionTarget()` would fail for lack of a button or a form, and the
// person's send would be blocked by an overlay. Measured on gemini, deepseek and perplexity on
// 2026-09-14. The three selectors are therefore neutralized together, never separately.
test('a provider with no structural handle intercepts nothing and cannot block a send',()=>{
 const perplexity=A.adapters.find(a=>a.id==='perplexity');
 assert.deepEqual([perplexity.editor,perplexity.send,perplexity.response],[':not(*)',':not(*)',':not(*)']);
 const dom=new JSDOM('<textarea>Synthetic</textarea><button aria-label="Envoyer">Send</button>',{url:'https://www.perplexity.ai/'});
 try{
  const doc=dom.window.document,editor=doc.querySelector('textarea'),bouton=doc.querySelector('button');
  const adapter=A.resolve(dom.window.location.href);
  assert.equal(adapter.id,'perplexity');
  assert.equal(A.submission(adapter,trusted('keydown',editor,{key:'Enter'}),doc),null);
  assert.equal(A.submission(adapter,trusted('click',bouton),doc),null);
 }finally{dom.window.close();}
});

test('Enter without a form resumes the unique provider button in one gesture',async()=>{
 const f=await fixture('deepseek');try{
  const form=f.doc.querySelector('form');form.replaceWith(...form.childNodes);let clicks=0;
  f.button.addEventListener('click',()=>clicks++);
  await f.controller.handle(trusted('keydown',f.editor,{key:'Enter'}));
  assert.equal(clicks,1);assert.equal(f.messages.filter(m=>m.type==='inspect').length,1);assert.equal(f.messages.filter(m=>m.type==='submit').length,1);assert.equal(f.dialog(),undefined);
 }finally{f.close();}
});
// Measured on the real pages on 2026-09-14: gemini, copilot, notebooklm and grok
// expose TWO elements for their editor selector and have no form. The fallback
// required a unique editor, so the Enter key was intercepted there — the send blocked —
// then abandoned with "This control cannot resume sending automatically",
// whether the send button was live or not. What must be unique is the button, not the editor.
test('Enter resumes even when the editor selector matches several elements',async()=>{
 const f=await fixture('gemini');try{
  const form=f.doc.querySelector('form');form.replaceWith(...form.childNodes);
  // A second element matching the editor selector, as on the real page.
  const autre=f.doc.createElement('textarea');f.doc.body.append(autre);
  assert.ok(f.doc.querySelectorAll(f.adapter.editor).length>1,'la fixture doit exposer plusieurs éditeurs');
  assert.equal(f.doc.querySelectorAll(f.adapter.send).length,1,'le bouton d\'envoi doit rester unique');
  let clicks=0;f.button.addEventListener('click',()=>clicks++);
  await f.controller.handle(trusted('keydown',f.editor,{key:'Enter'}));
  assert.equal(clicks,1);assert.equal(f.messages.filter(m=>m.type==='submit').length,1);
  assert.equal(f.dialog(),undefined,'aucune incrustation ne doit s\'afficher pour un envoi autorisé');
 }finally{f.close();}
});
// The ambiguity that matters is still refused: two send buttons, no resume possible.
test('Enter refuses to resume when the send control is ambiguous',async()=>{
 const f=await fixture('gemini');try{
  const form=f.doc.querySelector('form');form.replaceWith(...form.childNodes);
  // Gemini's selector targets the button VIA ITS CONTAINER: cloning the button alone
  // creates no ambiguity. It's the wrapper that must be duplicated.
  const enveloppe=f.button.closest('.send-button');
  f.doc.body.append(enveloppe.cloneNode(true));
  assert.equal(f.doc.querySelectorAll(f.adapter.send).length,2);
  let clicks=0;for(const b of f.doc.querySelectorAll(f.adapter.send)){b.addEventListener('click',()=>clicks++);}
  await f.controller.handle(trusted('keydown',f.editor,{key:'Enter'}));
  assert.equal(clicks,0);assert.equal(f.messages.filter(m=>m.type==='submit').length,0);
  assert.ok(f.dialog(),'un envoi non reprenable doit être signalé, pas parti en silence');
 }finally{f.close();}
});
// Measured on chatgpt.com signed out, Chrome and Firefox, 2026-09-29: the mobile composer
// page cancels the first submit, fetches its sentinel tokens, then calls
// form.requestSubmit() itself 32 ms later. That second, trusted submit was taken for a
// new send, so every first message of a conversation was recorded twice.
test('a page that resubmits the approved form itself records one prompt',async()=>{
 const dom=new JSDOM('<form><textarea id="mobile-composer-prompt"></textarea><button type="submit">Send</button></form>',{url:'https://chatgpt.com/'});
 const doc=dom.window.document;Object.defineProperty(dom.window.crypto,'subtle',{value:webcrypto.subtle});
 const form=doc.querySelector('form');let sent=0,deferred=false;
 form.addEventListener('submit',event=>{event.preventDefault();if(!deferred){deferred=true;setTimeout(()=>form.requestSubmit(),30);return;}sent++;});
 const messages=[];const config=policy();
 const controller=globalThis.MilvagoCapture.start(doc,dom.window.location,async msg=>{messages.push(msg);if(msg.type==='policy'){return {ok:true,policy:config};}if(msg.type==='inspect'){return {ok:true,action:'observe',text:msg.text,labels:[]};}if(msg.type==='submit'){return {ok:true,action:'observe',text:msg.text,durable:true,recording_required:true,authority:null,delivery_id:'00000000-0000-4000-8000-000000000001'};}return {ok:true};});
 try{
  await delay(0);
  const editor=doc.querySelector('#mobile-composer-prompt');A.write(editor,'Salut');
  await controller.handle(trusted('keydown',editor,{key:'Enter'}));
  await delay(120);
  assert.equal(messages.filter(m=>m.type==='submit').length,1);
  assert.equal(sent,1,'the page send goes through once');
 }finally{controller.dispose();dom.window.close();}
});
// Measured on signed-out chatgpt.com, 2026-09-29: the answer is `li[data-message-role="assistant"]`,
// never `[data-message-author-role]`, and it carries `data-message-streaming` while it is
// generated, then `data-message-complete`. No response was recorded at all before.
test('a signed-out ChatGPT answer is recorded once, after it finished streaming',async()=>{
 const dom=new JSDOM('<form><textarea id="mobile-composer-prompt"></textarea><button type="submit">Send</button></form><ol id="thread"></ol>',{url:'https://chatgpt.com/'});
 const doc=dom.window.document;Object.defineProperty(dom.window.crypto,'subtle',{value:webcrypto.subtle});
 doc.querySelector('form').addEventListener('submit',event=>event.preventDefault());
 const messages=[];const config=policy();
 const controller=globalThis.MilvagoCapture.start(doc,dom.window.location,async msg=>{messages.push(msg);if(msg.type==='policy'){return {ok:true,policy:config};}if(msg.type==='inspect'){return {ok:true,action:'observe',text:msg.text,labels:[]};}if(msg.type==='submit'){return {ok:true,action:'observe',text:msg.text,durable:true,recording_required:true,authority:null,delivery_id:'00000000-0000-4000-8000-000000000001'};}return {ok:true};});
 try{
  await delay(0);
  const editor=doc.querySelector('#mobile-composer-prompt');A.write(editor,'Donne trois fruits');
  await controller.handle(trusted('keydown',editor,{key:'Enter'}));
  const answer=doc.createElement('li');answer.setAttribute('data-message-role','assistant');answer.setAttribute('data-message-streaming','');answer.textContent='Pomme';
  doc.querySelector('#thread').append(answer);
  await delay(1350);
  assert.equal(messages.filter(m=>m.event?.kind==='response').length,0,'a streaming answer is not recorded yet');
  answer.textContent='Pomme, poire, banane';answer.removeAttribute('data-message-streaming');answer.setAttribute('data-message-complete','');
  await delay(2700);
  const responses=messages.filter(m=>m.event?.kind==='response');
  assert.equal(responses.length,1);
  assert.equal(responses[0].event.correlation_id,messages.find(m=>m.type==='submit').event.correlation_id,'the answer belongs to the prompt it follows');
 }finally{controller.dispose();dom.window.close();}
});
test('a later submit of the same text is a new send once the window has passed',async()=>{
 const dom=new JSDOM('<form><textarea id="mobile-composer-prompt"></textarea><button type="submit">Send</button></form>',{url:'https://chatgpt.com/'});
 const doc=dom.window.document;Object.defineProperty(dom.window.crypto,'subtle',{value:webcrypto.subtle});
 const form=doc.querySelector('form');form.addEventListener('submit',event=>event.preventDefault());
 const messages=[];const config=policy();
 const controller=globalThis.MilvagoCapture.start(doc,dom.window.location,async msg=>{messages.push(msg);if(msg.type==='policy'){return {ok:true,policy:config};}if(msg.type==='inspect'){return {ok:true,action:'observe',text:msg.text,labels:[]};}if(msg.type==='submit'){return {ok:true,action:'observe',text:msg.text,durable:true,recording_required:true,authority:null,delivery_id:'00000000-0000-4000-8000-000000000001'};}return {ok:true};});
 const realNow=Date.now;
 try{
  await delay(0);
  const editor=doc.querySelector('#mobile-composer-prompt');A.write(editor,'Salut');
  await controller.handle(trusted('keydown',editor,{key:'Enter'}));
  Date.now=()=>realNow()+2500;
  await controller.handle(trusted('submit',form));
  assert.equal(messages.filter(m=>m.type==='submit').length,2);
 }finally{Date.now=realNow;controller.dispose();dom.window.close();}
});
test('concurrent clicks cannot start a second inspection or replay',async()=>{
 let finish;const gate=new Promise(resolve=>finish=resolve);const f=await fixture('chatgpt',()=>gate);try{
  const first=f.controller.handle(trusted('click',f.button));await f.controller.handle(trusted('click',f.button));
  assert.equal(f.messages.filter(m=>m.type==='inspect').length,1);
  finish({ok:true,action:'observe',text:'Synthetic prompt'});await first;
  assert.equal(f.submissionCount(),1);assert.equal(f.messages.filter(m=>m.type==='submit').length,1);
 }finally{f.close();}
});
test('changing then restoring a draft while inspection runs invalidates the attempt',async()=>{
 let finish;const gate=new Promise(resolve=>finish=resolve);const f=await fixture('chatgpt',()=>gate);try{
  const first=f.controller.handle(trusted('click',f.button));A.write(f.editor,'Changed');A.write(f.editor,'Synthetic prompt');
  finish({ok:true,action:'observe',text:'Synthetic prompt'});await first;
  assert.equal(f.messages.filter(m=>m.type==='submit').length,0);assert.equal(f.submissionCount(),0);
 }finally{f.close();}
});
test('policy revision changed during review prevents submit and preserves the draft',async()=>{
 const f=await fixture('chatgpt',{ok:true,action:'review',text:'[MASKED]'});try{
  await f.controller.handle(trusted('click',f.button));f.config.revision++;await f.controller.refresh();
  f.dialog().querySelector('button').click();await delay(10);
  assert.equal(A.read(f.editor),'Synthetic prompt');assert.equal(f.submissionCount(),0);assert.equal(f.messages.filter(m=>m.type==='submit').length,0);
 }finally{f.close();}
});
test('same policy revision with renewed lease permits review approval',async()=>{
 const f=await fixture('chatgpt',{ok:true,action:'review',text:'[MASKED]'});try{
  await f.controller.handle(trusted('click',f.button));f.config.expires_at='2099-02-01T00:00:00Z';f.config.issued_at='2099-01-01T00:00:00Z';await f.controller.refresh();
  f.dialog().querySelector('button').click();await delay(20);
  assert.equal(A.read(f.editor),'[MASKED]');assert.equal(f.submissionCount(),1);
 }finally{f.close();}
});
test('a streaming response is not captured during an idle pause and is retried at completion',async()=>{
 const f=await fixture('chatgpt',undefined,true);try{
  await f.controller.handle(trusted('click',f.button));f.doc.body.insertAdjacentHTML('beforeend','<div data-message-author-role="assistant" data-is-streaming="true">Partial</div>');
  const node=f.doc.body.lastElementChild;await delay(1350);assert.equal(f.messages.filter(m=>m.event?.kind==='response').length,0);
  node.textContent='Complete\nresponse';node.setAttribute('data-is-streaming','false');await delay(1350);
  const responses=f.messages.filter(m=>m.event?.kind==='response');assert.equal(responses.length,1);assert.equal(responses[0].event.response,'Complete\nresponse');
 }finally{f.close();}
});
test('text response mutations share one non-renewing 50 ms batch and capture the final text',async()=>{
 const f=await fixture('chatgpt',undefined,true);try{
  await f.controller.handle(trusted('click',f.button));const node=f.doc.querySelector('[data-message-author-role="assistant"]');
  const setTimeout=f.dom.window.setTimeout.bind(f.dom.window);let batches=0,flush;f.dom.window.setTimeout=(fn,ms,...args)=>{if(ms===50){batches++;flush=()=>fn(...args);return 1;}return setTimeout(fn,ms,...args);};
  node.firstChild.data='First';await delay(0);node.firstChild.data='Second';await delay(0);node.firstChild.data='Final response';await delay(0);
  assert.equal(batches,1,'the first mutation starts a bounded batch window');assert.equal(f.messages.filter(m=>m.type==='inspect'&&m.text==='Final response').length,0);flush();
  await delay(1250);const responses=f.messages.filter(m=>m.event?.kind==='response');assert.equal(responses.length,1);assert.equal(responses[0].event.response,'Final response');
 }finally{f.close();}
});
test('a structural response replacement uses the conservative global rescan',async()=>{
 const f=await fixture('chatgpt',undefined,true);try{
  await f.controller.handle(trusted('click',f.button));const previous=f.doc.querySelector('[data-message-author-role="assistant"]'),replacement=f.doc.createElement('div');replacement.setAttribute('data-message-author-role','assistant');replacement.textContent='Replacement response';previous.replaceWith(replacement);
  await delay(1350);const responses=f.messages.filter(m=>m.event?.kind==='response');assert.equal(responses.length,1);assert.equal(responses[0].event.response,'Replacement response');
 }finally{f.close();}
});
test('failed response inspection is retried without needing another DOM mutation',async()=>{
 let responses=0;const f=await fixture('chatgpt',msg=>msg.text==='Answer'&&responses++===0?{ok:false}:{ok:true,action:'observe',text:msg.text},true);try{
  await f.controller.handle(trusted('click',f.button));f.doc.body.insertAdjacentHTML('beforeend',pages.chatgpt[1]);await delay(2600);
  assert.equal(responses,2);assert.equal(f.messages.filter(m=>m.event?.kind==='response').length,1);
 }finally{f.close();}
});
test('Le Chat roleless editor and Notebook current hostname resolve',()=>{
 const dom=new JSDOM('<div contenteditable="true">Synthetic</div><button type="submit" aria-busy="false" aria-label="Envoyer">Envoyer</button>',{url:'https://chat.mistral.ai/'});
 try{const adapter=A.resolve(dom.window.location.href);assert.equal(A.submission(adapter,trusted('click',dom.window.document.querySelector('button')),dom.window.document),dom.window.document.querySelector('[contenteditable]'));assert.equal(A.resolve('https://notebook.google.com/').id,'notebooklm');}finally{dom.window.close();}
});

function selectedFile(f,name='synthetic.txt'){
 const input=f.doc.createElement('input');input.type='file';f.doc.body.append(input);
 const file=new f.dom.window.File(['Synthetic file body'],name,{type:'text/plain'});
 // Populate jsdom's actual, branded FileList; the product sees no array stand-in.
 fileListUtils.implForWrapper(input.files).push(fileListUtils.implForWrapper(file));
 assert.ok(input.files instanceof f.dom.window.FileList);assert.equal(input.files[0],file);
 return {input,file};
}
test('picker change delivers the same actual FileList once after durable validation',async()=>{
 const f=await fixture();try{
  const {input,file}=selectedFile(f);let delivered=0;
  input.addEventListener('change',e=>{assert.ok(e.target.files instanceof f.dom.window.FileList);assert.equal(e.target.files.length,1);assert.equal(e.target.files[0],file);delivered++;});
  await f.controller.upload(trusted('click',input));assert.equal(f.messages.filter(m=>m.type==='inspect').length,0);
  const original=trusted('change',input);await f.controller.upload(original);
  assert.equal(original.prevented,true);assert.equal(delivered,1);
  const checks=f.messages.filter(m=>m.type==='inspect'||m.type==='submit');assert.deepEqual(checks.map(m=>[m.type,m.upload]),[['inspect',true],['submit',true]]);
  assert.equal(JSON.stringify(checks).includes('Synthetic file body'),false);assert.equal(JSON.stringify(checks).includes('synthetic.txt'),false);
 }finally{f.close();}
});
test('refused final upload never dispatches the selected FileList',async()=>{
 const f=await fixture('chatgpt',undefined,false,()=>({ok:false,reason:'Unavailable'}));try{
  const {input}=selectedFile(f);let delivered=0;input.addEventListener('change',()=>delivered++);
  await f.controller.upload(trusted('change',input));assert.equal(delivered,0);assert.ok(f.dialog());
 }finally{f.close();}
});
test('policy changed while durable prompt is pending never replays',async()=>{
 let finish;const gate=new Promise(resolve=>finish=resolve);
 const f=await fixture('chatgpt',undefined,false,()=>gate);try{
  const sending=f.controller.handle(trusted('click',f.button));
  for(const deadline=Date.now()+5000;Date.now()<deadline&&!f.messages.some(m=>m.type==='submit');){await delay(10);}
  assert.equal(f.messages.filter(m=>m.type==='submit').length,1);f.config.revision++;
  finish({ok:true,action:'observe',text:'Synthetic prompt',durable:true,recording_required:true,authority:null,delivery_id:'00000000-0000-4000-8000-000000000001'});await sending;
  assert.equal(f.submissionCount(),0);assert.equal(A.read(f.editor),'Synthetic prompt');
 }finally{f.close();}
});
test('successive prompts receive distinct correlation identities',async()=>{
 const f=await fixture();try{
  await f.controller.handle(trusted('click',f.button));A.write(f.editor,'Next synthetic prompt');await f.controller.handle(trusted('click',f.button));
  const prompts=f.messages.filter(m=>m.type==='submit');assert.equal(prompts.length,2);assert.notEqual(prompts[0].event.correlation_id,prompts[1].event.correlation_id);
 }finally{f.close();}
});

test('file input is held before change and both replay once only after validation',async()=>{
 let finish;const gate=new Promise(resolve=>finish=resolve);const f=await fixture('chatgpt',()=>gate);try{
  const {input,file}=selectedFile(f);const delivered=[];
  for(const type of ['input','change']){input.addEventListener(type,e=>{assert.ok(e.target.files instanceof f.dom.window.FileList);assert.equal(e.target.files[0],file);delivered.push(e.type);});}
  const first=trusted('input',input);const sending=f.controller.upload(first);const second=trusted('change',input);await f.controller.upload(second);
  assert.equal(first.prevented,true);assert.equal(second.prevented,true);assert.deepEqual(delivered,[]);assert.equal(f.messages.filter(m=>m.type==='inspect').length,1);
  finish({ok:true,action:'observe',text:''});await sending;
  assert.deepEqual(delivered,['input','change']);assert.equal(f.messages.filter(m=>m.type==='submit').length,1);
 }finally{f.close();}
});
for(const [language,title,confirm,cancel]of [['fr','Informations confidentielles','Valider et envoyer','Annuler'],['en','Confidential information','Confirm and send','Cancel'],['es','Información confidencial','Confirmar y enviar','Cancelar'],['pt-BR','Informações confidenciais','Confirmar e enviar','Cancelar']]){test('review dialog renders '+language+' and Escape restores the draft focus',async()=>{
 const f=await fixture('chatgpt',{ok:true,action:'review',text:'[MASKED]'});try{
  f.doc.documentElement.lang=language;f.editor.focus();await f.controller.handle(trusted('click',f.button));
  assert.equal(f.doc.documentElement.lang,language);const dialog=f.dialog();
  assert.equal(dialog.querySelector('h2').textContent,title);const sentence={fr:'Les informations que vous avez fournies contiennent des informations confidentielles, merci de vérifier les éléments que nous avons masqués ci-dessous avant envoi.',en:'The information you provided contains confidential information. Please review the elements we masked below before sending.',es:'La información que has proporcionado contiene información confidencial. Revisa los elementos que hemos enmascarado a continuación antes de enviar.','pt-BR':'As informações que você forneceu contêm informações confidenciais. Verifique os elementos que mascaramos abaixo antes de enviar.'}[language];assert.equal(dialog.querySelector('p').textContent,sentence);// Product decision of 2026-09-16: the buttons are aligned right and the close button is last, hence rightmost.
  const actions=dialog.querySelector('.actions');assert.ok(actions);assert.equal(actions.lastElementChild.textContent,cancel);assert.deepEqual([...dialog.querySelectorAll('button')].map(x=>x.textContent),[confirm,cancel]);
  dialog.dispatchEvent(new f.dom.window.KeyboardEvent('keydown',{key:'Escape',bubbles:true,cancelable:true}));
  assert.equal(f.dialog(),undefined);assert.equal(f.doc.activeElement,f.editor);assert.equal(A.read(f.editor),'Synthetic prompt');assert.equal(f.submissionCount(),0);
 }finally{f.close();}
});}
test('response delivery retry retains the same capture identity and exact text',async()=>{
 let responses=0;const f=await fixture('chatgpt',undefined,true,undefined,msg=>msg.event.kind==='response'?{ok:++responses>1}:{ok:true});try{
  await f.controller.handle(trusted('click',f.button));f.doc.body.insertAdjacentHTML('beforeend',pages.chatgpt[1]);await delay(2600);
  const sent=f.messages.filter(m=>m.event?.kind==='response');assert.equal(sent.length,2);
  assert.match(sent[0].event.capture_id,/^[0-9a-f-]{36}$/);assert.equal(sent[0].event.capture_id,sent[1].event.capture_id);
  assert.equal(sent[0].event.response,'Answer');assert.deepEqual(sent[0].event,sent[1].event);
 }finally{f.close();}
});

// A controlled file then sent without text used to go out without passing through
// inspection, hence without approval: under masking, the network guard sealed claude.ai's send.
test('claude: a send carrying only a controlled file goes through inspection and keeps its correlation',async()=>{
 const f=await fixture('claude');try{
  f.editor.textContent='';
  const bare=trusted('click',f.button);await f.controller.handle(bare);
  assert.equal(bare.prevented,false,'an empty composer without a file is not a send');assert.equal(f.messages.some(m=>m.type==='inspect'&&!m.upload),false);
  const {input}=selectedFile(f);await f.controller.upload(trusted('change',input));
  const upload=f.messages.find(m=>m.type==='submit'&&m.upload);assert.ok(upload);
  const send=trusted('click',f.button);await f.controller.handle(send);
  assert.equal(send.prevented,true);
  const prompt=f.messages.find(m=>m.type==='submit'&&!m.upload);assert.ok(prompt,'the file-only send is submitted');
  assert.equal(prompt.text,'');assert.equal(prompt.event.correlation_id,upload.event.correlation_id);assert.equal(f.submissionCount(),1);
 }finally{f.close();}
});

// ProseMirror (claude.ai) stores each line in a paragraph: `innerText` reads back `\n\n`
// between two lines. The applied masked text must be accepted and submitted exactly as read back.
function proseMirror(f){
 const editor=f.editor;
 Object.defineProperty(editor,'innerText',{configurable:true,get(){const blocks=[...editor.querySelectorAll('p')];return blocks.length?blocks.map(p=>p.textContent).join('\n\n'):editor.textContent;}});
 f.doc.execCommand=(command,ui,text)=>{if(command!=='insertText'){return false;}editor.innerHTML='';for(const line of text.split('\n')){const p=f.doc.createElement('p');p.textContent=line;editor.append(p);}return true;};
 editor.innerHTML='<p>Bonjour</p><p>Synthetic prompt</p>';
}
test('claude: a masked multi-line draft is applied and submitted as the editor reads it back',async()=>{
 const f=await fixture('claude',msg=>({ok:true,action:'review',text:msg.text.replace('Synthetic','[MASKED]').replace('\n\n','\n'),labels:['email']}));try{
  proseMirror(f);
  await f.controller.handle(trusted('click',f.button));f.dialog().querySelector('button').click();await delay(20);
  const prompt=f.messages.find(m=>m.type==='submit');assert.ok(prompt,'the masked draft is sent');
  assert.equal(prompt.text,'Bonjour\n\n[MASKED] prompt');assert.equal(f.submissionCount(),1);
 }finally{f.close();}
});
test('claude: an editor that does not hold the masked text stops the send',async()=>{
 const f=await fixture('claude',msg=>({ok:true,action:'review',text:msg.text.replace('Synthetic','[MASKED]'),labels:['email']}));try{
  proseMirror(f);f.doc.execCommand=()=>true;
  await f.controller.handle(trusted('click',f.button));f.dialog().querySelector('button').click();await delay(20);
  assert.equal(f.messages.some(m=>m.type==='submit'),false);assert.equal(f.submissionCount(),0);
 }finally{f.close();}
});
