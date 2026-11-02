// The notice for a request the worker cancelled. `capture.js` binds the runtime API when
// it loads, hence a file of its own with the listener stubbed before the import.
import test from 'node:test';
import assert from 'node:assert/strict';
import {JSDOM} from 'jsdom';

const listeners=[];
globalThis.chrome={runtime:{onMessage:{addListener(fn){listeners.push(fn);},removeListener(){}}}};
await import('./adapters.js');
await import('./capture.js');

async function noticeFor(message,lang){
 const dom=new JSDOM('<textarea></textarea>',{url:'https://chatgpt.com/'});
 dom.window.document.documentElement.lang=lang;
 const attach=dom.window.Element.prototype.attachShadow;dom.window.Element.prototype.attachShadow=function(options){const root=attach.call(this,options);this.testShadow=root;return root;};
 const controller=globalThis.MilvagoCapture.start(dom.window.document,dom.window.location,async()=>({ok:false}));
 try{
  for(const fn of listeners.splice(0)){fn(message);}
  return [...dom.window.document.querySelectorAll('div')].find(x=>x.testShadow)?.testShadow.textContent;
 }finally{controller.dispose();dom.window.close();}
}

test('a send cancelled for want of local validation does not blame a model',async()=>{
 for(const lang of ['fr','en']){
  const text=await noticeFor({type:'model-blocked',reason:'control_unavailable',revision:10},lang);
  assert.ok(text,lang);
  assert.doesNotMatch(text,/Modèle|Model|indéterminé|unknown/,lang);
  assert.match(text,lang==='fr'?/contrôle local/:/local control/,lang);
 }
});

test('a model decision still names the model',async()=>{
 assert.match(await noticeFor({type:'model-blocked',reason:'model_denied',model:'model-x',revision:3},'fr'),/Modèle : model-x\. Politique 3\. Ce modèle est interdit\./);
 assert.match(await noticeFor({type:'model-blocked',reason:'model_unknown',revision:3},'en'),/Model: unknown\. Policy 3\./);
});

test('the local-validation notice speaks all four languages, revision appended',async()=>{
 const expected={fr:/Envoi bloquéCet envoi.*contrôle local.*Politique 10\./,en:/Send blockedThis send.*local control.*Policy 10\./,es:/Envío bloqueadoEste envío.*control local.*Política 10\./,'pt-BR':/Envio bloqueadoEste envio.*verificação local.*Política 10\./};
 for(const [lang,shape] of Object.entries(expected)){
  const text=await noticeFor({type:'model-blocked',reason:'control_unavailable',revision:10},lang);
  assert.match(text,shape,lang);
 }
 assert.match(await noticeFor({type:'model-blocked',reason:'control_unavailable'},'es'),/Política no disponible\./);
});

// Fourth review, M4, then real campaign 0.7.6: the notice page was first served under the per-session id
// only (`use_dynamic_url`). Chrome installed by policy gave the fixed id from `runtime.getURL` and refused
// it for that resource: the page never opened. It is served under the fixed id again; a page can tell the
// extension is installed, which an organization's managed install does not hide anyway. Firefox already
// serves its pages under a random per-install id: the Gecko build leaves the key out.
test('the notice page is served under the fixed id',async()=>{
 const {readFile}=await import('node:fs/promises');
 const manifest=JSON.parse(await readFile(new URL('./manifest.json',import.meta.url),'utf8'));
 const entry=manifest.web_accessible_resources.find(r=>r.resources.includes('blocked.html'));
 assert.equal(entry.use_dynamic_url,false);
 const build=await readFile(new URL('./build-editions.js',import.meta.url),'utf8');
 assert.match(build,/delete resource\.use_dynamic_url/);
});
