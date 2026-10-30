// Real campaign 0.7.11: a page's own modal window opened over the review notice (top layer beats any z-index),
// and the person's click never reached "Validate and send". The notice is now a modal dialog of its own, shown
// again when the page puts one back above it, and still out of the page's reach. Synthetic page.
import test from 'node:test';
import assert from 'node:assert/strict';
import {JSDOM} from 'jsdom';

const listeners=[];
globalThis.chrome={runtime:{onMessage:{addListener(fn){listeners.push(fn);},removeListener(){}}}};
await import('./adapters.js');
await import('./capture.js');

function page(){
 const dom=new JSDOM('<textarea></textarea><div id="modal"></div>',{url:'https://chatgpt.com/'});
 const {window}=dom,shown=[];
 // jsdom has no top layer: the calls are what the browser would act on.
 window.HTMLDialogElement.prototype.showModal=function(){if(!this.isConnected){throw new window.DOMException('not connected','InvalidStateError');}this.setAttribute('open','');shown.push(this);};
 window.HTMLDialogElement.prototype.close=function(){this.removeAttribute('open');};
 const attach=window.Element.prototype.attachShadow;window.Element.prototype.attachShadow=function(options){const root=attach.call(this,options);this.testShadow=root;return root;};
 const controller=globalThis.MilvagoCapture.start(window.document,window.location,async()=>({ok:false}));
 for(const fn of listeners.splice(0)){fn({type:'model-blocked',reason:'control_unavailable',revision:4});}
 const host=[...window.document.querySelectorAll('div')].find(x=>x.testShadow);
 return {window,host,shown,close(){controller.dispose();window.close();}};
}
const wait=ms=>new Promise(r=>setTimeout(r,ms));

test('the notice is a modal dialog in the top layer, its content inside it',()=>{
 const p=page();
 try{
  const box=p.host.testShadow.querySelector('dialog');
  assert.ok(box,'a dialog');assert.equal(p.shown.length,1);assert.equal(p.shown[0],box);
  assert.ok(box.querySelector('.card button'),'the card and its buttons are in the dialog');
 }finally{p.close();}
});

test('a page modal put above the notice is answered by showing the notice again, until it is closed',async()=>{
 const p=page();
 try{
  const theirs=p.window.document.getElementById('modal');
  p.window.document.elementFromPoint=()=>theirs;
  await wait(700);
  assert.ok(p.shown.length>=2,'shown again over the page modal');
  p.window.document.elementFromPoint=()=>p.host;
  const count=p.shown.length;await wait(400);
  assert.equal(p.shown.length,count,'on top: left alone');
  p.window.document.elementFromPoint=()=>theirs;
  p.host.testShadow.querySelector('button').click();
  assert.equal(p.host.isConnected,false,'closed by its own button');
  const after=p.shown.length;await wait(400);
  assert.equal(p.shown.length,after,'nothing shown once closed');
 }finally{p.close();}
});

test('the page cannot close or activate the notice by synthetic events',()=>{
 const p=page();
 try{
  const {window,host}=p;
  host.dispatchEvent(new window.MouseEvent('click',{bubbles:true,composed:true}));
  for(const key of ['Enter',' ','Escape']){
   host.dispatchEvent(new window.KeyboardEvent('keydown',{key,bubbles:true,composed:true}));
   window.document.dispatchEvent(new window.KeyboardEvent('keydown',{key,bubbles:true,composed:true}));
  }
  assert.equal(host.isConnected,true,'still shown');
  assert.equal(host.shadowRoot,null,'closed shadow: the page reaches no button');
 }finally{p.close();}
});
