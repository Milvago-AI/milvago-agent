// Pasted or dropped text under masking (chantier B): the page never receives it before the agent
// has inspected it, and receives only the masked plain text. Synthetic pages and texts only.
import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto,createHash} from 'node:crypto';
import {JSDOM} from 'jsdom';
import './adapters.js';
import './capture.js';
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const SECRET='jean.exemple@example.com',MASKED='[EMAIL]';
const masking={version:2,revision:1,expires_at:'2099-01-01T00:00:00Z',config:{collection:{enabled:false},services:[],privacy:{enabled:true}}};
const observing={version:2,revision:1,expires_at:'2099-01-01T00:00:00Z',config:{collection:{enabled:false},services:[]}};
const mask=async msg=>msg.type==='paste'?{ok:true,action:msg.text.includes(SECRET)?'review':'observe',text:msg.text.replaceAll(SECRET,MASKED).replaceAll(/\r\n?/g,'\n'),labels:[]}:{ok:true,action:'observe',text:msg.text||'',labels:[]};
function clipboard(data={},files=[]){return {files,types:Object.keys(data),getData:type=>data[type]||''};}
function trusted(type,target,extra={}){return {type,target,isTrusted:true,prevented:false,stopped:false,get defaultPrevented(){return this.prevented;},preventDefault(){this.prevented=true;},stopImmediatePropagation(){this.stopped=true;},...extra};}
function page(html,{policy=masking,reply=mask}={}){
 const dom=new JSDOM(html,{url:'https://chatgpt.com/'});
 Object.defineProperty(dom.window.crypto,'subtle',{value:webcrypto.subtle});
 const attach=dom.window.Element.prototype.attachShadow;dom.window.Element.prototype.attachShadow=function(options){const root=attach.call(this,options);this.testShadow=root;return root;};
 // jsdom has neither: the minimum a page reads from a paste.
 dom.window.DataTransfer=class{constructor(){this.data={};this.files=[];}setData(t,v){this.data[t]=v;}getData(t){return this.data[t]||'';}get types(){return Object.keys(this.data);}};
 dom.window.ClipboardEvent=class extends dom.window.Event{constructor(type,init){super(type,init);this.clipboardData=init.clipboardData;}};
 const messages=[];
 const controller=globalThis.MilvagoCapture.start(dom.window.document,dom.window.location,msg=>{messages.push(msg);if(msg.type==='policy'){return Promise.resolve({ok:true,policy});}return reply(msg);});
 const doc=dom.window.document;
 return {dom,doc,controller,messages,
  pasted(){return messages.filter(m=>m.type==='paste').map(m=>m.text);},
  dialog(){return [...doc.querySelectorAll('div')].find(x=>x.testShadow)?.testShadow||null;},
  close(){controller.dispose();dom.window.close();}};
}
const field=p=>p.doc.querySelector('textarea');

test('a paste into a field under masking reaches it only masked, at the caret',async()=>{
 const p=page('<textarea id="prompt-textarea">before  after</textarea>');
 try{await delay(0);const box=field(p);box.setSelectionRange(7,7);
  const event=trusted('paste',box,{clipboardData:clipboard({'text/plain':'mail '+SECRET,'text/html':'<b>mail '+SECRET+'</b>'})});
  await p.controller.paste(event);
  assert.equal(event.prevented,true);assert.equal(event.stopped,true);
  assert.deepEqual(p.pasted(),['mail '+SECRET]);
  assert.ok(p.dialog(),'the masked text is shown for review');
  assert.equal(box.value,'before  after','nothing reaches the page before the person confirms');
  [...p.dialog().querySelectorAll('button')].find(b=>/paste|coller/i.test(b.textContent)).click();await delay(10);
  assert.equal(box.value,'before mail '+MASKED+' after');
 }finally{p.close();}
});
test('a clean paste is inserted at once, line breaks kept, without any dialog',async()=>{
 const p=page('<textarea id="prompt-textarea"></textarea>');
 try{await delay(0);const event=trusted('paste',field(p),{clipboardData:clipboard({'text/plain':'line one\r\nline two'})});
  await p.controller.paste(event);
  assert.equal(event.prevented,true);assert.equal(field(p).value,'line one\nline two');assert.equal(p.dialog(),null);
 }finally{p.close();}
});
test('an HTML-only clipboard is inspected as its text and reinjected as plain text',async()=>{
 const p=page('<textarea id="prompt-textarea"></textarea>');
 try{await delay(0);
  const html=`<p>Note</p><script>steal()</script><style>p{}</style><span style="display:none">${SECRET}</span>`;
  await p.controller.paste(trusted('paste',field(p),{clipboardData:clipboard({'text/html':html})}));
  assert.deepEqual(p.pasted(),['Note'+SECRET]);
  [...p.dialog().querySelectorAll('button')].find(b=>/paste|coller/i.test(b.textContent)).click();await delay(10);
  assert.equal(field(p).value,'Note'+MASKED);assert.ok(!field(p).value.includes('<'));
 }finally{p.close();}
});
test('a paste carrying files is left to the file path, untouched by the text path',async()=>{
 const p=page('<textarea id="prompt-textarea"></textarea>');
 try{await delay(0);
  const event=trusted('paste',field(p),{clipboardData:clipboard({'text/plain':'caption','image/png':''},[{name:'photo.png'}])});
  await p.controller.paste(event);
  assert.equal(event.prevented,false);assert.deepEqual(p.pasted(),[]);
 }finally{p.close();}
});
test('outside masking, and for an untrusted or empty paste, nothing is held',async()=>{
 const o=page('<textarea id="prompt-textarea"></textarea>',{policy:observing});
 try{await delay(0);const event=trusted('paste',field(o),{clipboardData:clipboard({'text/plain':SECRET})});await o.controller.paste(event);
  assert.equal(event.prevented,false);assert.deepEqual(o.pasted(),[]);}finally{o.close();}
 const p=page('<textarea id="prompt-textarea"></textarea>');
 try{await delay(0);
  for(const event of [trusted('paste',field(p),{isTrusted:false,clipboardData:clipboard({'text/plain':SECRET})}),trusted('paste',field(p),{clipboardData:clipboard({})}),trusted('paste',field(p),{clipboardData:null})]){
   await p.controller.paste(event);assert.equal(event.prevented,false);
  }
  assert.deepEqual(p.pasted(),[]);
 }finally{p.close();}
 const w=page('<input type="password">');
 try{await delay(0);const event=trusted('paste',w.doc.querySelector('input'),{clipboardData:clipboard({'text/plain':'synthetic-value'})});await w.controller.paste(event);
  assert.equal(event.prevented,false);assert.deepEqual(w.pasted(),[]);}finally{w.close();}
});
test('a paste the agent blocks or cannot inspect never reaches the page',async()=>{
 for(const [reply,shown] of [[async()=>({ok:true,action:'block',text:'x',labels:['keyword'],reason:'Mot protégé.'}),/Mot protégé/],[async()=>({ok:false}),/agent/i],[async()=>({ok:true,action:'observe'}),/invalid|non valide/i],[async()=>{throw new Error('down');},/./]]){
  const p=page('<textarea id="prompt-textarea">draft</textarea>',{reply:async msg=>msg.type==='paste'?reply(msg):mask(msg)});
  try{await delay(0);const event=trusted('paste',field(p),{clipboardData:clipboard({'text/plain':'Orion '+SECRET})});
   await p.controller.paste(event);
   assert.equal(event.prevented,true);assert.equal(field(p).value,'draft');assert.match(p.dialog()?.textContent||'',shown);
  }finally{p.close();}
 }
});
test('a paste beyond the local limit is refused before anything is sent',async()=>{
 for(const data of [{'text/plain':'x'.repeat(200*1024)},{'text/html':'<p>'+'x'.repeat(1024*1024)+'</p>'}]){
  const p=page('<textarea id="prompt-textarea"></textarea>');
  try{await delay(0);const event=trusted('paste',field(p),{clipboardData:clipboard(data)});
   await p.controller.paste(event);
   assert.equal(event.prevented,true);assert.deepEqual(p.pasted(),[]);assert.equal(field(p).value,'');assert.match(p.dialog().textContent,/limit/i);
  }finally{p.close();}
 }
});
test('a paste aimed at the review dialog itself does not replace it',async()=>{
 const p=page('<textarea id="prompt-textarea"></textarea>');
 try{await delay(0);
  await p.controller.paste(trusted('paste',field(p),{clipboardData:clipboard({'text/plain':SECRET})}));
  const host=p.dialog().host,event=trusted('paste',host,{clipboardData:clipboard({'text/plain':'other '+SECRET})});
  await p.controller.paste(event);
  assert.equal(event.prevented,true,'no page handler gets it');assert.equal(p.dialog().host,host);assert.deepEqual(p.pasted(),[SECRET]);
 }finally{p.close();}
});
test('a rich editor receives a synthetic plain-text paste, which the capture lets through',async()=>{
 const p=page('<div contenteditable="true" class="ProseMirror" data-composer-markdown><p>x</p></div>');
 try{await delay(0);const editor=p.doc.querySelector('[contenteditable]'),seen=[];
  editor.addEventListener('paste',e=>{seen.push({types:e.clipboardData.types,text:e.clipboardData.getData('text/plain'),trusted:e.isTrusted});e.preventDefault();});
  await p.controller.paste(trusted('paste',editor.firstChild,{clipboardData:clipboard({'text/plain':'clean words','text/html':'<i>clean words</i>'})}));
  assert.deepEqual(seen,[{types:['text/plain'],text:'clean words',trusted:false}],'plain text only, never the original HTML');
  assert.deepEqual(p.pasted(),['clean words'],'the reinjected paste is not inspected again');
 }finally{p.close();}
});
test('dropped text, and a paste seen only as beforeinput, are held the same way',async()=>{
 const p=page('<textarea id="prompt-textarea"></textarea>');
 try{await delay(0);
  const drop=trusted('drop',field(p),{dataTransfer:clipboard({'text/plain':'dropped '+SECRET})});
  await p.controller.paste(drop);assert.equal(drop.prevented,true);
  const late=trusted('beforeinput',field(p),{inputType:'insertFromPaste',data:'typed '+SECRET,dataTransfer:null});
  await p.controller.paste(late);assert.equal(late.prevented,true);
  const typing=trusted('beforeinput',field(p),{inputType:'insertText',data:'a'});
  await p.controller.paste(typing);assert.equal(typing.prevented,false);
  assert.deepEqual(p.pasted(),['dropped '+SECRET,'typed '+SECRET]);
 }finally{p.close();}
});
test('text dragged inside the page itself is a move, not a paste from outside',async()=>{
 const p=page('<textarea id="prompt-textarea">abc</textarea>');
 try{await delay(0);
  p.controller.paste(trusted('dragstart',field(p)));
  const drop=trusted('drop',field(p),{dataTransfer:clipboard({'text/plain':'abc'})});
  await p.controller.paste(drop);assert.equal(drop.prevented,false);assert.deepEqual(p.pasted(),[]);
  p.controller.paste(trusted('dragend',field(p)));
  const outside=trusted('drop',field(p),{dataTransfer:clipboard({'text/plain':'from elsewhere'})});
  await p.controller.paste(outside);assert.equal(outside.prevented,true);
 }finally{p.close();}
});
test('a paste is held even before the policy has arrived',async()=>{
 const p=page('<textarea id="prompt-textarea"></textarea>');
 try{const event=trusted('paste',field(p),{clipboardData:clipboard({'text/plain':SECRET})});
  await p.controller.paste(event);assert.equal(event.prevented,true);assert.deepEqual(p.pasted(),[SECRET]);
 }finally{p.close();}
});

// Review 5: where a paste is held, what it takes for it to be approved, and the edge cases.
const accept=p=>[...p.dialog().querySelectorAll('button')].find(b=>/paste|coller/i.test(b.textContent)).click();
const dismiss=p=>[...p.dialog().querySelectorAll('button')].find(b=>/annuler|cancel/i.test(b.textContent)).click();
const withToken=async msg=>msg.type==='paste'?{...(await mask(msg)),token:'00000000-0000-4000-8000-0000000000aa'}:mask(msg);
test('only the composer is held: its editor, and a field or rich editor in its form',async()=>{
 const p=page('<form><textarea id="prompt-textarea"></textarea><div contenteditable="true" id="side"><p>x</p></div></form><textarea id="elsewhere"></textarea><input id="search"><div contenteditable="true" id="note"><p>y</p></div>');
 try{await delay(0);
  for(const id of ['prompt-textarea','side']){const event=trusted('paste',p.doc.getElementById(id).firstChild||p.doc.getElementById(id),{clipboardData:clipboard({'text/plain':'held '+id})});await p.controller.paste(event);assert.equal(event.prevented,true,id);}
  for(const id of ['elsewhere','search','note']){const event=trusted('paste',p.doc.getElementById(id),{clipboardData:clipboard({'text/plain':'free '+id})});await p.controller.paste(event);assert.equal(event.prevented,false,id);}
  assert.deepEqual(p.pasted(),['held prompt-textarea','held side']);
 }finally{p.close();}
});
test('a paste another handler already cancelled is still held',async()=>{
 const p=page('<textarea id="prompt-textarea"></textarea>');
 try{await delay(0);const event=trusted('paste',field(p),{clipboardData:clipboard({'text/plain':SECRET})});event.preventDefault();
  await p.controller.paste(event);assert.equal(event.stopped,true);assert.deepEqual(p.pasted(),[SECRET]);
 }finally{p.close();}
});
test('a clipboard with types but no readable text is refused under masking, with a notice',async()=>{
 for(const data of [{'text/rtf':'{\\rtf1 synthetic}'},{'text/uri-list':'https://example.com/a'},{'application/x-synthetic':'blob'}]){
  const p=page('<textarea id="prompt-textarea"></textarea>');
  try{await delay(0);const event=trusted('paste',field(p),{clipboardData:clipboard(data)});
   await p.controller.paste(event);
   assert.equal(event.prevented,true,Object.keys(data)[0]);assert.deepEqual(p.pasted(),[]);assert.match(p.dialog()?.textContent||'',/Collage refusé|Paste refused/);
  }finally{p.close();}
 }
 const o=page('<textarea id="prompt-textarea"></textarea>',{policy:observing});
 try{await delay(0);const event=trusted('paste',field(o),{clipboardData:clipboard({'text/rtf':'{\\rtf1}'})});await o.controller.paste(event);assert.equal(event.prevented,false,'not held outside masking');}finally{o.close();}
});
test('an internal drag that lost its dragend no longer lets an outside drop through',async()=>{
 for(const reset of [p=>p.controller.paste(trusted('pointerup',field(p))),p=>p.controller.paste(trusted('dragleave',field(p),{relatedTarget:null})),p=>p.controller.paste(trusted('drop',field(p),{dataTransfer:clipboard({'text/plain':'abc'})}))]){
  const p=page('<textarea id="prompt-textarea">abc</textarea>');
  try{await delay(0);
   p.controller.paste(trusted('dragstart',field(p)));await reset(p);await delay(0);
   const outside=trusted('drop',field(p),{dataTransfer:clipboard({'text/plain':'from elsewhere'})});
   await p.controller.paste(outside);assert.equal(outside.prevented,true);
  }finally{p.close();}
 }
 const p=page('<textarea id="prompt-textarea">abc</textarea>');
 try{await delay(0);p.controller.paste(trusted('dragstart',field(p)));
  await p.controller.paste(trusted('dragleave',field(p),{relatedTarget:p.doc.body}));
  const inside=trusted('drop',field(p),{dataTransfer:clipboard({'text/plain':'abc'})});await p.controller.paste(inside);assert.equal(inside.prevented,false,'leaving one element for another is still inside');
 }finally{p.close();}
});
test('a reviewed paste is approved only when the person confirms it',async()=>{
 const p=page('<textarea id="prompt-textarea"></textarea>',{reply:withToken});
 try{await delay(0);
  await p.controller.paste(trusted('paste',field(p),{clipboardData:clipboard({'text/plain':SECRET})}));
  assert.deepEqual(p.messages.filter(m=>m.type==='paste-confirm'),[]);
  dismiss(p);await delay(10);
  assert.deepEqual(p.messages.filter(m=>m.type==='paste-confirm'),[],'cancelled: never approved');assert.equal(field(p).value,'');
  await p.controller.paste(trusted('paste',field(p),{clipboardData:clipboard({'text/plain':SECRET})}));
  accept(p);await delay(10);
  assert.deepEqual(p.messages.filter(m=>m.type==='paste-confirm'),[{type:'paste-confirm',token:'00000000-0000-4000-8000-0000000000aa'}]);
  assert.equal(field(p).value,MASKED);
 }finally{p.close();}
 const q=page('<textarea id="prompt-textarea"></textarea>',{reply:async msg=>msg.type==='paste-confirm'?{ok:false}:withToken(msg)});
 try{await delay(0);
  await q.controller.paste(trusted('paste',field(q),{clipboardData:clipboard({'text/plain':'clean words'})}));
  assert.equal(field(q).value,'','a refused confirmation inserts nothing');assert.match(q.dialog()?.textContent||'',/Collage refusé|Paste refused/);
 }finally{q.close();}
});
test('a paste confirmed after the page moved is not inserted',async()=>{
 const p=page('<textarea id="prompt-textarea"></textarea>');
 try{await delay(0);
  await p.controller.paste(trusted('paste',field(p),{clipboardData:clipboard({'text/plain':SECRET})}));
  p.dom.window.history.pushState({},'','/c/other-conversation');
  accept(p);await delay(10);
  assert.equal(field(p).value,'');
 }finally{p.close();}
});
test('a second paste while the first is checked is refused with a notice, and the first still lands',async()=>{
 let release;const gate=new Promise(resolve=>{release=resolve;});
 const p=page('<textarea id="prompt-textarea"></textarea>',{reply:async msg=>{if(msg.type==='paste'){await gate;}return mask(msg);}});
 try{await delay(0);
  const first=p.controller.paste(trusted('paste',field(p),{clipboardData:clipboard({'text/plain':'first words'})}));
  await delay(450);
  const second=trusted('paste',field(p),{clipboardData:clipboard({'text/plain':'second words'})});
  await p.controller.paste(second);
  assert.equal(second.prevented,true);assert.match(p.dialog()?.textContent||'',/Collage refusé|Paste refused/);
  release();await first;await delay(10);
  assert.equal(field(p).value,'first words');assert.deepEqual(p.pasted(),['first words']);
 }finally{p.close();}
});
test('a validated file selection names each file and its size to the worker',async()=>{
 const p=page('<form><textarea id="prompt-textarea"></textarea><input type="file"></form>');
 try{await delay(0);
  const input=p.doc.querySelector('input[type="file"]'),files=[new p.dom.window.File(['a,b\n1,2\n'],'report.csv',{type:'text/csv'}),new p.dom.window.File(['notes'],'notes.txt',{type:'text/plain'})];
  Object.defineProperty(input,'files',{value:files});
  await p.controller.upload({type:'change',target:input,isTrusted:true,preventDefault(){},stopImmediatePropagation(){}});
  const submit=p.messages.find(m=>m.type==='submit');
  const sha=text=>createHash('sha256').update(text).digest('hex');
  assert.deepEqual(submit.files,[{name:sha('report.csv'),size:8},{name:sha('notes.txt'),size:5}]);
  assert.ok(!JSON.stringify(p.messages).includes('report.csv'),'the name stays in the page');
 }finally{p.close();}
});
