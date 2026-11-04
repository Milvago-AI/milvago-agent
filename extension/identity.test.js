import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {webcrypto} from 'node:crypto';
import {JSDOM} from 'jsdom';
import './adapters.js';
import './capture.js';

const source = name => readFile(new URL(name, import.meta.url), 'utf8');

test('the embedded notice and assembled runtime use the same complete identity', async () => {
  const capture = await source('capture.js');
  const embedded = JSON.parse(capture.match(/const NOTICE_STYLES=(".*");/)[1]);
  assert.equal(embedded, (await source('brand.css') + await source('notice.css')).replace(/\r\n/g,'\n'));
  const build = await source('build-editions.js');
  for (const asset of ['brand.css','appearance.js','milvago-logo-horizontal-inverse.svg','milvago-logo-horizontal-mono-black.svg','Inter-latin.woff2','Inter-OFL.txt']) {
    assert.ok(build.includes("'"+asset+"'"), asset+' must reach both browser packages');
    assert.ok((await readFile(new URL(asset,import.meta.url))).length > 0);
  }
  const manifest = JSON.parse(await source('manifest.json'));
  const exposed = manifest.web_accessible_resources.flatMap(item=>item.resources);
  for (const asset of ['Inter-latin.woff2','milvago-logo-horizontal-inverse.svg','milvago-logo-horizontal-mono-black.svg']) { assert.ok(exposed.includes(asset)); }
  assert.ok(!exposed.includes('appearance.js'), 'the page cannot call the preference script as a public resource');
});

test('appearance is restored before rendering and a choice persists only a cosmetic value', async () => {
  const html = await source('popup.html');
  assert.ok(html.indexOf('appearance.js') < html.indexOf('brand.css'));
  const dom = new JSDOM(html,{url:'https://extension.example.invalid/',runScripts:'outside-only'});
  const writes=[];
  dom.window.chrome={storage:{local:{set:async value=>writes.push(value)}}};
  dom.window.localStorage.setItem('milvago.theme','light');
  dom.window.eval(await source('appearance.js'));
  assert.equal(dom.window.document.documentElement.dataset.theme,'light');
  dom.window.document.dispatchEvent(new dom.window.Event('DOMContentLoaded'));
  const select=dom.window.document.getElementById('appearance');
  select.value='dark';select.dispatchEvent(new dom.window.Event('change'));
  assert.equal(dom.window.document.documentElement.dataset.theme,'dark');
  assert.equal(dom.window.localStorage.getItem('milvago.theme'),'dark');
  assert.equal(JSON.stringify(writes),JSON.stringify([{'milvago.theme':'dark'}]));
  select.value='system';select.dispatchEvent(new dom.window.Event('change'));
  assert.equal(dom.window.document.documentElement.dataset.theme,undefined);
  dom.window.close();
});

test('a blocked service name stays inert text in all four languages', async () => {
  const attack='<img src=x onerror=alert(1)>';
  for(const [language,label] of [['fr','Bloqué'],['en','Blocked'],['es','Bloqueado'],['pt-BR','Bloqueado']]){
    const dom=new JSDOM(await source('blocked.html'),{url:'https://extension.example.invalid/blocked.html?service='+encodeURIComponent(attack),runScripts:'outside-only'});
    Object.defineProperty(dom.window.navigator,'language',{value:language});
    dom.window.eval(await source('blocked.js'));
    assert.equal(dom.window.document.getElementById('service').textContent,attack);
    assert.equal(dom.window.document.getElementById('service').children.length,0);
    assert.equal(dom.window.document.getElementById('decision-label').textContent,label);
    dom.window.close();
  }
});

test('the masked review keeps the exact readonly text, cancel action and focus restoration', async () => {
  const dom=new JSDOM('<html lang="en"><form><textarea id="prompt-textarea"></textarea><button data-testid="send-button" type="button">Send</button></form></html>',{url:'https://chatgpt.com/'});
  const {window}=dom,doc=window.document;
  Object.defineProperty(window.crypto,'subtle',{value:webcrypto.subtle});
  const attach=window.Element.prototype.attachShadow;
  let shadow;
  window.Element.prototype.attachShadow=function(options){shadow=attach.call(this,options);return shadow;};
  window.HTMLDialogElement.prototype.showModal=function(){this.setAttribute('open','');};
  window.HTMLDialogElement.prototype.close=function(){this.removeAttribute('open');};
  const masked='Synthetic [MASKED]\n<img src=x onerror=alert(1)>';
  const policy={version:2,revision:9,expires_at:'2099-01-01T00:00:00Z',config:{collection:{enabled:true,store_content:false},services:[{id:'chatgpt',domains:['chatgpt.com'],enabled:true,mode:'observe'}]}};
  const messages=[];
  const controller=globalThis.MilvagoCapture.start(doc,window.location,async message=>{
    messages.push(message);
    if(message.type==='policy'){return {ok:true,policy};}
    if(message.type==='inspect'){return {ok:true,action:'review',text:masked,labels:['synthetic']};}
    return {ok:true};
  });
  try{
    await new Promise(resolve=>setTimeout(resolve,0));
    const editor=doc.querySelector('textarea');editor.value='Synthetic original';editor.focus();
    await controller.handle({type:'click',target:doc.querySelector('button'),isTrusted:true,preventDefault(){},stopImmediatePropagation(){}});
    assert.equal(shadow.querySelector('.card').dataset.decision,'masked');
    const preview=shadow.querySelector('textarea');
    assert.equal(preview.value,masked);assert.equal(preview.readOnly,true);
    assert.equal(shadow.querySelector('.notice-body img'),null);
    const dialog=shadow.querySelector('dialog');
    assert.equal(shadow.getElementById(dialog.getAttribute('aria-labelledby')).tagName,'H2');
    assert.equal(shadow.querySelectorAll('[role=dialog]').length,0,'one native dialog, no duplicate role');
    const buttons=shadow.querySelectorAll('button');
    assert.ok(buttons[0].classList.contains('primary'));assert.equal(buttons[1].textContent,'Cancel');
    assert.equal(shadow.activeElement,buttons[1],'confirm is never automatically focused');
    buttons[1].click();
    assert.equal(doc.activeElement,editor);
    assert.equal(editor.value,'Synthetic original');
    assert.equal(messages.filter(message=>message.type==='submit').length,0);
  }finally{controller.dispose();window.close();}
});
