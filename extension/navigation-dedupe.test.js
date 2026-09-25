import test from 'node:test';
import assert from 'node:assert/strict';
import {JSDOM} from 'jsdom';
// The content script reads its API namespace once, at load: the fake storage must
// exist before capture.js is imported, hence the dynamic imports below.
const held={};let failing=false;
globalThis.chrome={storage:{local:{async get(key){if(failing){throw new Error('storage unavailable');}return {[key]:held[key]};},async set(value){if(failing){throw new Error('storage unavailable');}Object.assign(held,value);}}}};
await import('./adapters.js');await import('./capture.js');
const A=globalThis.MilvagoAdapters;
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const policy={version:2,revision:9,expires_at:'2099-01-01T00:00:00Z',config:{collection:{enabled:true,store_content:false},services:A.adapters.map(a=>({id:a.id,domains:[a.domain],enabled:true,mode:'observe'}))}};
async function open(path){
 const dom=new JSDOM('<form><textarea id="prompt-textarea"></textarea><button data-testid="send-button">Send</button></form>',{url:'https://chatgpt.com'+path});
 const messages=[];const controller=globalThis.MilvagoCapture.start(dom.window.document,dom.window.location,async msg=>{messages.push(msg);return msg.type==='policy'?{ok:true,policy}:{ok:true};});
 await delay(20);
 return {navigations:()=>messages.filter(m=>m.type==='event'&&m.event.kind==='navigation').length,close(){controller.dispose();dom.window.close();}};
}
test('a page reloaded within the window is recorded once, a new conversation always, and a failing storage never loses a record',async()=>{
 const first=await open('/');assert.equal(first.navigations(),1);
 // A refresh, a redirect or a prerendered document: another content script, same page.
 const again=await open('/');assert.equal(again.navigations(),0);
 const conversation=await open('/c/00000000-0000-4000-8000-000000000000');assert.equal(conversation.navigations(),1);
 const sameConversation=await open('/c/00000000-0000-4000-8000-000000000000');assert.equal(sameConversation.navigations(),0);
 // Past the window the page is a new usage again.
 for(const key of Object.keys(held.navigations)){held.navigations[key]-=31*60*1000;}
 const later=await open('/');assert.equal(later.navigations(),1);
 // Storage refusing is the extra record, never the lost one.
 failing=true;const blind=await open('/');assert.equal(blind.navigations(),1);failing=false;
 for(const page of [first,again,conversation,sameConversation,later,blind]){page.close();}
});
